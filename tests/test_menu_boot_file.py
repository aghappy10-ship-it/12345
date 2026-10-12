"""Real local rc copies/rename; OS identities, labels and mounts are models."""
from copy import deepcopy
import os
import queue
import subprocess
import threading
import time

import pytest

from tests.test_release_lifecycle import installer
from tests.test_peer_install import SH
from tools import menu_boot_file as boot_file
from tools import prepare_peer_install as peer
from tools import session_context as session

HOST_BASH = SH.parent.parent / "usr/bin/bash.exe"


def run_rc(installer, *, action="activate", setup=True, hook="", raw=None,
           backup_identity=None, render_changes=None, stable=False, argument_hash=None,
           supervised=False, process_runner=None, dependency_hash=None, source_renderer=None):
    if setup:
        installer.shell_fixture()
    stage = installer.root / "blackbox/x2dii-menu-stage" / installer.manifest["candidate_sha256"][:24]
    data = raw if raw is not None else peer.session_data(installer.manifest, installer.q)
    data_path = stage / (f"session-context-{peer.sha(data)}.data" if supervised else "session-context.data")
    if supervised and data_path.exists():
        assert data_path.read_bytes() == data, "an immutable session must not be replaced by the fixture"
    else:
        data_path.write_bytes(data)
    kwargs = dict(action=action, session_data_sha256=peer.sha(data),
                  original_rc=peer.boot.STOCK.read_bytes(),
                  metadata=installer.q["metadata"][peer.boot.TARGET],
                  init_scan_roots=installer.q["init_scan_roots"], backup_identity=backup_identity)
    kwargs.update(render_changes or {})
    if stable or supervised:
        compiled_or_current_hash = kwargs.pop("session_data_sha256")
        if argument_hash is None:
            argument_hash = compiled_or_current_hash
        kwargs.pop("backup_identity")
        renderer = source_renderer or (boot_file.render_supervised_boot_transaction if supervised else
                                       boot_file.render_stable_boot_transaction)
        source = renderer(installer.manifest, **kwargs)
    else:
        source = boot_file.render_boot_transaction(installer.manifest, **kwargs)
    original_program_sha = peer.sha(source.encode("ascii"))
    head, parser = source.split("# SESSION_DATA_PARSER_BEGIN\n", 1)
    parser, tail = parser.split("# SESSION_DATA_PARSER_END\n", 1)
    source = head + "# PARSER\n" + tail
    for fd in (3, 4, 5):
        source = source.replace(f"/proc/self/fd/{fd}", f"FD_{fd}")
    for prefix in ("/system", "/blackbox", "/proc"):
        source = source.replace(prefix, installer.posix + prefix)
    for fd in (3, 4, 5):
        source = source.replace(f"FD_{fd}", f"/proc/self/fd/{fd}")
    source = source.replace("# PARSER\n", parser)
    source = source.replace("export PATH=" + installer.posix + "/system/bin:" + installer.posix + "/system/xbin:/sbin", "export PATH=/usr/bin:/bin")
    source = source.replace(installer.posix + "/system/bin/toybox", "toybox")
    epoch = int(peer.datetime.fromisoformat(installer.q["observed_utc"]).timestamp())
    wrapper = r'''
fixture=FIXTURE
id() { echo 0; }
date() { echo EPOCH; }
cat() {
 case "$1" in
  /proc/self/fd/[345]|"$fixture/proc/self/attr/current"|"$fixture/proc/sys/kernel/random/boot_id") ;;
  "$fixture/proc/"*|"$fixture/system/bin/"*) echo forbidden-cat >&2; return 90;;
 esac
 /usr/bin/cat "$@"
}
readlink() { [ "$1" = "$fixture/proc/self/ns/mnt" ] || return 90; echo 'mnt:[4026531840]'; }
fixture_stat() {
 if [ "$2" = '%u:%g:%a' ]; then
  if [ -d "$3" ]; then echo 0:0:700; else echo 0:0:600; fi
 elif [ "$2" = '%u %g' ]; then echo '0 0'
 elif [ "$2" = '%u %g %a' ] || [ "$2" = '%d:%i:%f:%h:%s:%u:%g' ]; then
  fixture_path=$3
  native=$(/usr/bin/stat -Lc '%d:%i:%f:%h:%s:%u:%g' "$3") || return
  saved_ifs=$IFS; IFS=:; set -- $native; IFS=$saved_ifs
  fixture_mode=600
  if [ -f "$fixture/mode-$2" ]; then fixture_mode=$(/usr/bin/cat "$fixture/mode-$2")
  else case "$fixture_path" in */.x2dii-boot-*|/proc/self/fd/3) :;; *) fixture_mode=644;; esac; fi
  if [ "$fixture_mode" = 644 ]; then fixture_hex=81a4; else fixture_hex=8180; fi
  if [ "$stat_format" = '%u %g %a' ]; then printf '0 0 %s\n' "$fixture_mode"
  else printf '%s:%s:%s:%s:%s:0:0\n' "$1" "$2" "$fixture_hex" "$4" "$5"; fi
 else /usr/bin/stat "$@"; fi
}
stat() { stat_format=$2; fixture_stat "$@"; }
ls() { printf 'u:object_r:system_file:s0 %s\n' "$2"; }
fixture_toybox() {
 [ "$1" = getfattr ] || return 90
 shift
 if [ "$1" = -d ]; then printf '# file: %s\nsecurity.selinux="u:object_r:system_file:s0"\n\n' "$2"
 else printf '# file: %s\nsecurity.selinux\n\n' "$1"; fi
}
toybox() { fixture_toybox "$@"; }
sync() { echo sync >> "$fixture/rc-operations"; }
boundary() { :; }
mount() {
 printf 'mount:%s\n' "$*" >> "$fixture/rc-operations"
 case "$2" in remount,rw) worker_state=rw;; remount,ro) worker_state=ro;; *) return 90;; esac
 printf '/dev/block/current-attested-slot %s/system ext4 %s,seclabel,relatime 0 0\n' "$fixture" "$worker_state" > "$fixture/proc/mounts"
 boundary remount
}
chmod() {
 printf 'chmod:%s\n' "$*" >> "$fixture/rc-operations"
 /usr/bin/chmod "$@" || return
 inode=$(/usr/bin/stat -c %i "$2") || return
 printf 644 > "$fixture/mode-$inode"
}
mv() { printf 'mv:%s\n' "$*" >> "$fixture/rc-operations"; /usr/bin/mv "$@"; }
touch() { printf 'touch:%s\n' "$*" >> "$fixture/rc-operations"; /usr/bin/touch "$@"; }
mkdir() { echo forbidden-mkdir >&2; return 90; }
chcon() { echo forbidden-chcon >&2; return 90; }
ln() { echo forbidden-link >&2; return 90; }
rm() { echo forbidden-rm >&2; return 90; }
start() { echo forbidden-start >&2; return 90; }
stop() { echo forbidden-stop >&2; return 90; }
'''.replace("FIXTURE", peer.shlex.quote(installer.posix)).replace("EPOCH", str(epoch))
    arguments = [installer.posix + "/" + data_path.relative_to(installer.root).as_posix(),
                 peer.sha(data) if argument_hash is None else argument_hash]
    if (stable or supervised) and action == "restore":
        arguments.append(backup_identity if backup_identity is not None else "")
    if supervised and action == "activate":
        arguments.append(dependency_hash or "f" * 64)
    if process_runner is not None:
        wrapper += r'''
sha256sum() {
 host_hash=$(/usr/bin/sha256sum "$@") || return
 if [ "$#" = 1 ] && [ "$1" = "$0" ] && [ "${host_hash%% *}" = "$X2DII_TEST_HOST_PROGRAM_SHA" ]; then
  printf 'ORIGINAL_PROGRAM_SHA  %s\n' "$1"
 else printf '%s\n' "$host_hash"; fi
}
'''.replace("ORIGINAL_PROGRAM_SHA", original_program_sha)
        return process_runner(wrapper + hook + source, arguments, stage)
    return subprocess.run([str(SH), "-s", "--", *arguments],
                          input=(wrapper + hook + source).encode("ascii"), capture_output=True, timeout=60)


def test_activation_preserves_official_backup_before_atomic_two_line_rc_replacement(installer):
    result = run_rc(installer)
    assert result.returncode == 0, (result.stdout, result.stderr)
    target = installer.root / peer.boot.TARGET.lstrip("/")
    backup = installer.root / "system/etc" / (".x2dii-boot-" + installer.manifest["candidate_sha256"][:24] + ".original")
    assert backup.read_bytes() == peer.boot.STOCK.read_bytes()
    assert target.read_bytes() == peer.boot.activate(peer.boot.STOCK.read_bytes())
    assert backup.stat().st_ino != target.stat().st_ino
    assert target.stat().st_mtime_ns == backup.stat().st_mtime_ns
    assert (installer.root / "proc/mounts").read_text() == installer.mount_line
    assert (installer.root / "gui-service-state").read_text() == "running"
    assert b"maintenance_boundaries=UNCONNECTED" in result.stdout
    assert b"X2DII_RC_FILE_COMMITTED_NOT_LIFECYCLE_VALIDATED" in result.stdout
    assert b"forbidden-" not in result.stderr
    assert sum(line.startswith("mv:") for line in (installer.root / "rc-operations").read_text().splitlines()) == 1


def recovery_data(installer):
    values = peer.session_values(installer.q)
    values.update(kind="recovery", session_nonce="c" * 32, recovery_nonce="c" * 32,
                  gui_state="absent", gui_service_state="stopped",
                  backup_owner_label="u:object_r:system_file:s0",
                  present_library="0", present_bootstrap="0", present_model="0", present_page="0",
                  rc_sha256=installer.manifest["candidate"]["rc"]["after"])
    values.update({key: "-" for key in session.GUI_PROCESS_FIELDS})
    return session.encode_session(values)


def test_independent_recovery_uses_exact_retained_backup_without_proposed_source(installer):
    activated = run_rc(installer)
    assert activated.returncode == 0, (activated.stdout, activated.stderr)
    identity = next(line.split("=", 1)[1] for line in activated.stdout.decode().splitlines()
                    if line.startswith("backup_identity="))
    backup = installer.root / "system/etc" / (".x2dii-boot-" + installer.manifest["candidate_sha256"][:24] + ".original")
    before = backup.stat()
    (installer.root / "blackbox/x2dii-menu-stage" / installer.manifest["candidate_sha256"][:24] / "camera-gui.rc.proposed").unlink()
    restored = run_rc(installer, action="restore", setup=False, raw=recovery_data(installer), backup_identity=identity)
    assert restored.returncode == 0, (restored.stdout, restored.stderr)
    assert b"action=restore\n" in restored.stdout
    assert (installer.root / peer.boot.TARGET.lstrip("/")).read_bytes() == peer.boot.STOCK.read_bytes()
    assert backup.read_bytes() == peer.boot.STOCK.read_bytes()
    assert (backup.stat().st_ino, backup.stat().st_mtime_ns) == (before.st_ino, before.st_mtime_ns)
    assert (installer.root / "proc/mounts").read_text() == installer.mount_line
    assert (installer.root / "gui-service-state").read_text() == "running"


@pytest.mark.parametrize("stable", (False, True))
def test_receipt_does_not_adopt_backup_replaced_during_final_target_hash(installer, stable):
    result = run_rc(installer, stable=stable, hook=r'''
sha256sum() {
 /usr/bin/sha256sum "$@" || return
 if [ "${committed:-0}" = 1 ] && [ "$1" = "$target" ]; then
  count=0
  [ ! -f "$fixture/final-hash-count" ] || count=$(/usr/bin/cat "$fixture/final-hash-count")
  count=$((count+1)); printf '%s\n' "$count" > "$fixture/final-hash-count"
  if [ "$count" = 2 ]; then
   /usr/bin/mv "$backup" "$backup.displaced"
   /usr/bin/cp -p "$backup.displaced" "$backup"
   inode=$(/usr/bin/stat -c %i "$backup"); printf 644 > "$fixture/mode-$inode"
  fi
 fi
}
''')
    assert result.returncode == 73, (result.stdout, result.stderr)
    assert b"schema=x2dii-rc-file-transaction" not in result.stdout
    backups = list((installer.root / "system/etc").glob(".x2dii-boot-*.original*"))
    assert len(backups) == 2 and backups[0].read_bytes() == backups[1].read_bytes()
    assert backups[0].stat().st_ino != backups[1].stat().st_ino


@pytest.mark.parametrize("fault", ("extra_name", "wrong_value", "names_status", "values_status", "wrong_path"))
def test_original_xattrs_must_be_complete_exact_and_successfully_queried_before_writes(installer, fault):
    hook = r'''
toybox() {
 if [ "FAULT" = extra_name ] && [ "$2" != -d ]; then
  fixture_toybox "$@"; printf 'user.unknown\n'; return
 elif [ "FAULT" = wrong_value ] && [ "$2" = -d ]; then
  printf '# file: %s\nsecurity.selinux="u:object_r:wrong:s0"\n\n' "$3"; return
 elif [ "FAULT" = wrong_path ]; then
  printf '# file: /system/etc/unrelated\nsecurity.selinux\n\n'; return
 fi
 fixture_toybox "$@" || return
 if [ "FAULT" = names_status ] && [ "$2" != -d ]; then return 9; fi
 if [ "FAULT" = values_status ] && [ "$2" = -d ]; then return 9; fi
}
'''.replace("FAULT", fault)
    result = run_rc(installer, hook=hook)
    assert result.returncode == 33, (result.stdout, result.stderr)
    assert not (installer.root / "rc-operations").exists()
    assert (installer.root / peer.boot.TARGET.lstrip("/")).read_bytes() == peer.boot.STOCK.read_bytes()


@pytest.mark.parametrize("phase", ("backup", "proposed"))
@pytest.mark.parametrize("stable", (False, True))
def test_partial_copy_keeps_original_rc_and_failed_file_without_deletion(installer, phase, stable):
    installer.shell_fixture()
    target = installer.root / peer.boot.TARGET.lstrip("/")
    before = (target.stat().st_ino, target.read_bytes(), target.stat().st_mtime_ns)
    hook = r'''
cat() {
 case "PHASE:$1" in
  backup:/proc/self/fd/4|proposed:*/camera-gui.rc.proposed) printf partial; return 9;;
  *) /usr/bin/cat "$@";;
 esac
}
'''.replace("PHASE", phase)
    result = run_rc(installer, setup=False, hook=hook, stable=stable)
    assert result.returncode == 9, (result.stdout, result.stderr)
    assert (target.stat().st_ino, target.read_bytes(), target.stat().st_mtime_ns) == before
    files = list((installer.root / "system/etc").glob(".x2dii-boot-*"))
    assert any(path.read_bytes() == b"partial" for path in files)
    assert len(files) == (1 if phase == "backup" else 2)
    assert (installer.root / "proc/mounts").read_text() == installer.mount_line
    assert b"schema=x2dii-rc-file-transaction" not in result.stdout


def test_same_content_rc_replacement_during_backup_is_not_adopted(installer):
    result = run_rc(installer, hook=r'''
cat() {
 /usr/bin/cat "$@" || return
 if [ "$1" = /proc/self/fd/4 ]; then
  /usr/bin/mv "$target" "$target.displaced"
  /usr/bin/cp "$target.displaced" "$target"
 fi
}
''')
    assert result.returncode == 33, (result.stdout, result.stderr)
    target = installer.root / peer.boot.TARGET.lstrip("/")
    displaced = target.with_name(target.name + ".displaced")
    assert target.read_bytes() == displaced.read_bytes() == peer.boot.STOCK.read_bytes()
    assert target.stat().st_ino != displaced.stat().st_ino
    assert "chmod:" not in (installer.root / "rc-operations").read_text()
    assert (installer.root / "proc/mounts").read_text() == installer.mount_line


def test_original_hardlink_cannot_pass_single_owner_gate(installer):
    installer.shell_fixture()
    original = installer.root / peer.boot.TARGET.lstrip("/")
    original.with_name("unrelated-rc-link").hardlink_to(original)
    result = run_rc(installer, setup=False)
    assert result.returncode == 33, (result.stdout, result.stderr)
    assert not (installer.root / "rc-operations").exists()
    assert original.stat().st_nlink == 2


def test_existing_unknown_backup_is_never_overwritten(installer):
    installer.shell_fixture()
    backup = installer.root / "system/etc" / (".x2dii-boot-" + installer.manifest["candidate_sha256"][:24] + ".original")
    backup.write_bytes(b"unknown retained backup")
    before = backup.stat().st_ino
    result = run_rc(installer, setup=False)
    assert result.returncode == 33, (result.stdout, result.stderr)
    assert backup.stat().st_ino == before and backup.read_bytes() == b"unknown retained backup"
    assert not (installer.root / "rc-operations").exists()


@pytest.mark.parametrize("field,value", (("xattr_names", ["security.selinux", "user.extra"]),
                                        ("uid", 1000), ("mode", "600")))
def test_unsupported_observed_metadata_does_not_render(installer, field, value):
    metadata = deepcopy(installer.q["metadata"][peer.boot.TARGET])
    metadata[field] = value
    with pytest.raises(ValueError):
        run_rc(installer, render_changes={"metadata": metadata})


def test_init_scan_root_cannot_include_backup_or_staging_files(installer):
    with pytest.raises(ValueError):
        run_rc(installer, render_changes={"init_scan_roots": ["/system/etc/init", "/system/etc"]})


@pytest.mark.parametrize("stable", (False, True))
def test_readonly_remount_error_retains_failure_even_if_readback_is_readonly(installer, stable):
    result = run_rc(installer, stable=stable, hook='boundary() { [ "$worker_state" != ro ] || return 9; }\n')
    assert result.returncode == 72, (result.stdout, result.stderr)
    assert (installer.root / "proc/mounts").read_text() == installer.mount_line
    assert b"schema=x2dii-rc-file-transaction" not in result.stdout


@pytest.mark.parametrize("fault", ("other_session_hash", "temporary_v3", "wrong_uid", "wrong_domain", "expired"))
@pytest.mark.parametrize("stable", (False, True))
def test_unbound_temporary_wrong_role_and_expired_contexts_make_no_writes(installer, fault, stable):
    kwargs = {}
    if fault == "other_session_hash":
        kwargs["render_changes"] = {"session_data_sha256": "f" * 64}
    elif fault == "temporary_v3":
        from tests.test_temporary_menu_session import temporary_values
        kwargs["raw"] = session.encode_session(temporary_values(installer), schema=session.MENU_VALIDATION_SCHEMA)
    elif fault == "wrong_uid":
        kwargs["hook"] = "id() { echo 1000; }\n"
    elif fault == "wrong_domain":
        kwargs["hook"] = 'printf "u:r:hbl_camera_service:s0\\n" > "$fixture/proc/self/attr/current"\n'
    else:
        epoch = int(peer.datetime.fromisoformat(installer.q["observed_utc"]).timestamp())
        kwargs["hook"] = f"date() {{ echo {epoch + 601}; }}\n"
    result = run_rc(installer, stable=stable, **kwargs)
    assert result.returncode in (31, 32, 33), (result.stdout, result.stderr)
    assert not (installer.root / "rc-operations").exists()
    assert (installer.root / peer.boot.TARGET.lstrip("/")).read_bytes() == peer.boot.STOCK.read_bytes()


@pytest.mark.parametrize("stable", (False, True))
def test_recovery_does_not_adopt_same_bytes_and_metadata_at_new_backup_inode(installer, stable):
    activated = run_rc(installer, stable=stable)
    assert activated.returncode == 0, (activated.stdout, activated.stderr)
    identity = next(line.split("=", 1)[1] for line in activated.stdout.decode().splitlines()
                    if line.startswith("backup_identity="))
    backup = installer.root / "system/etc" / (".x2dii-boot-" + installer.manifest["candidate_sha256"][:24] + ".original")
    original_identity = backup.stat()
    displaced = backup.with_name(backup.name + ".displaced")
    backup.rename(displaced)
    subprocess.run([str(SH), "-c", '/usr/bin/cp -p "$1" "$2"', "fixture",
                    installer.posix + "/" + displaced.relative_to(installer.root).as_posix(),
                    installer.posix + "/" + backup.relative_to(installer.root).as_posix()], check=True)
    (installer.root / f"mode-{backup.stat().st_ino}").write_text("644")
    assert backup.stat().st_ino != original_identity.st_ino
    assert backup.stat().st_mtime_ns == original_identity.st_mtime_ns
    operations = (installer.root / "rc-operations").read_bytes()
    target = installer.root / peer.boot.TARGET.lstrip("/")
    target_before = (target.stat().st_ino, target.read_bytes())
    recovered = run_rc(installer, stable=stable, action="restore", setup=False,
                       raw=recovery_data(installer), backup_identity=identity)
    assert recovered.returncode == 33, (recovered.stdout, recovered.stderr)
    assert (installer.root / "rc-operations").read_bytes() == operations
    assert (target.stat().st_ino, target.read_bytes()) == target_before
    assert backup.read_bytes() == displaced.read_bytes() == peer.boot.STOCK.read_bytes()


@pytest.mark.parametrize("damage", ("rc_hash", "rc_path", "source_path", "payload_bound", "action"))
def test_compile_inputs_cannot_expand_the_fixed_rc_transaction(installer, damage):
    manifest = deepcopy(installer.manifest)
    action = "activate"
    if damage == "rc_hash": manifest["candidate"]["rc"]["after"] = "f" * 64
    elif damage == "rc_path": manifest["candidate"]["rc"]["target"] = "/system/etc/init/other.rc"
    elif damage == "source_path": manifest["candidate"]["files"][0]["source"] = "elsewhere.so"
    elif damage == "payload_bound": manifest["candidate"]["files"][0]["bytes"] = 8 * 1024 * 1024
    else: action = "arbitrary"
    manifest["candidate_sha256"] = peer.sha(peer.canonical(manifest["candidate"]))
    with pytest.raises(ValueError):
        boot_file.render_boot_transaction(manifest, action=action, session_data_sha256="f" * 64,
            original_rc=peer.boot.STOCK.read_bytes(), metadata=installer.q["metadata"][peer.boot.TARGET],
            init_scan_roots=installer.q["init_scan_roots"])


def test_stable_activation_uses_runtime_session_hash_and_binds_its_receipt(installer):
    expected_hash = peer.sha(peer.session_data(installer.manifest, installer.q))
    result = run_rc(installer, stable=True)
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert ("session_data_sha256=" + expected_hash + "\n").encode() in result.stdout
    assert (installer.root / peer.boot.TARGET.lstrip("/")).read_bytes() == peer.boot.activate(peer.boot.STOCK.read_bytes())
    assert (installer.root / "proc/mounts").read_text() == installer.mount_line


def test_stable_restore_uses_separate_exact_saved_identity_and_current_session(installer):
    activated = run_rc(installer, stable=True)
    assert activated.returncode == 0, (activated.stdout, activated.stderr)
    identity = next(line.split("=", 1)[1] for line in activated.stdout.decode().splitlines()
                    if line.startswith("backup_identity="))
    raw = recovery_data(installer)
    restored = run_rc(installer, stable=True, action="restore", setup=False,
                      raw=raw, backup_identity=identity)
    assert restored.returncode == 0, (restored.stdout, restored.stderr)
    assert ("session_data_sha256=" + peer.sha(raw) + "\n").encode() in restored.stdout
    assert ("backup_identity=" + identity + "\n").encode() in restored.stdout
    assert (installer.root / peer.boot.TARGET.lstrip("/")).read_bytes() == peer.boot.STOCK.read_bytes()
    assert (installer.root / "proc/mounts").read_text() == installer.mount_line


def test_stable_program_rejects_previous_session_hash_after_session_data_changes(installer):
    old_data = peer.session_data(installer.manifest, installer.q)
    values = session.decode_session(old_data)
    values["session_nonce"] = "d" * 32
    current_data = session.encode_session(values, schema=session.INSTALL_SCHEMA)
    result = run_rc(installer, stable=True, raw=current_data, argument_hash=peer.sha(old_data))
    assert result.returncode == 32, (result.stdout, result.stderr)
    assert not (installer.root / "rc-operations").exists()
    assert (installer.root / peer.boot.TARGET.lstrip("/")).read_bytes() == peer.boot.STOCK.read_bytes()


@pytest.mark.parametrize("argument", ("", "a" * 63, "A" * 64, "a" * 64 + "\n", "$(touch injected)"))
def test_stable_runtime_hash_is_strict_data_never_shell_source(installer, argument):
    result = run_rc(installer, stable=True, argument_hash=argument)
    assert result.returncode == 32, (result.stdout, result.stderr)
    assert not (installer.root / "rc-operations").exists()
    assert not (installer.root / "injected").exists()


@pytest.mark.parametrize("identity", (
    "", "1:2:81a4:1:SIZE:0:0:extra", "01:2:81a4:1:SIZE:0:0",
    "1:02:81a4:1:SIZE:0:0", "1:2:8180:1:SIZE:0:0", "1:2:81a4:2:SIZE:0:0",
    "1:2:81a4:1:SIZE:1000:0", "1:2:81a4:1:1:0:0", "$(touch injected)",
))
def test_stable_restore_rejects_malformed_saved_identity_before_any_write(installer, identity):
    identity = identity.replace("SIZE", str(len(peer.boot.STOCK.read_bytes())))
    result = run_rc(installer, stable=True, action="restore", raw=recovery_data(installer),
                    backup_identity=identity)
    assert result.returncode == 32, (result.stdout, result.stderr)
    assert not (installer.root / "rc-operations").exists()
    assert not (installer.root / "injected").exists()


@pytest.mark.parametrize("action", ("activate", "restore"))
def test_stable_program_bytes_do_not_change_with_new_session_or_saved_identity(installer, action):
    kwargs = dict(action=action, original_rc=peer.boot.STOCK.read_bytes(),
                  metadata=installer.q["metadata"][peer.boot.TARGET],
                  init_scan_roots=installer.q["init_scan_roots"])
    first_session = peer.session_data(installer.manifest, installer.q)
    first = boot_file.render_stable_boot_transaction(installer.manifest, **kwargs)
    old_kwargs = {**kwargs, "session_data_sha256": peer.sha(first_session)}
    if action == "restore":
        old_kwargs["backup_identity"] = "1:2:81a4:1:436:0:0"
    old_first = boot_file.render_boot_transaction(installer.manifest, **old_kwargs)
    installer.q["session_nonce"] = "d" * 32
    second_session = peer.session_data(installer.manifest, installer.q)
    assert peer.sha(first_session) != peer.sha(second_session)
    old_kwargs["session_data_sha256"] = peer.sha(second_session)
    if action == "restore":
        old_kwargs["backup_identity"] = "1:3:81a4:1:436:0:0"
    assert boot_file.render_boot_transaction(installer.manifest, **old_kwargs) != old_first
    assert boot_file.render_stable_boot_transaction(installer.manifest, **kwargs) == first
    assert peer.sha(first_session) not in first and peer.sha(second_session) not in first


def test_payload_identity_data_accepts_only_four_exact_candidate_inodes(installer):
    identities = tuple(f"1:{i+20}:81a4:1:{entry['bytes']}:0:0"
                       for i, entry in enumerate(installer.manifest["candidate"]["files"]))
    raw = boot_file.encode_payload_identities(installer.manifest, identities)
    assert raw == "".join(f"identity_{i}={value}\n" for i, value in enumerate(identities)).encode()
    assert boot_file.decode_payload_identities(installer.manifest, raw) == identities
    for invalid in (identities[:3], identities + identities[:1],
                    (identities[0].replace(":81a4:", ":8180:"), *identities[1:]),
                    (identities[0].replace(":1:", ":2:", 1), *identities[1:])):
        with pytest.raises(ValueError):
            boot_file.encode_payload_identities(installer.manifest, invalid)


def prepare_payload_identities(installer):
    """Actual payload bytes/inodes; root/mode remain explicit OS fixture facts."""
    stage = installer.shell_fixture()
    from tests.test_temporary_menu_session import prepare_maintenance
    prepare_maintenance(installer, preplace=False)
    (installer.root / "proc/self/attr/current").write_text("u:r:su:s0\n")
    (installer.root / "proc/234/environ").write_bytes(b"XDG_RUNTIME_DIR=/tmp\0")
    identities = []
    for entry in installer.manifest["candidate"]["files"]:
        target = installer.root / entry["target"].lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((peer.ROOT / entry["source"]).read_bytes())
        observed = subprocess.run([str(SH), "-c", '/usr/bin/stat -c "%d:%i" "$1"', "fixture",
            installer.posix + entry["target"]], capture_output=True, text=True, check=True).stdout.strip()
        identities.append(observed + f":81a4:1:{entry['bytes']}:0:0")
    raw = boot_file.encode_payload_identities(installer.manifest, identities)
    nonce = session.decode_session(peer.session_data(installer.manifest, installer.q))["session_nonce"]
    (stage / f".payload-identities-{nonce}.data").write_bytes(raw)
    return raw


def test_supervised_boot_eof_before_remount_preserves_official_rc(installer):
    raw = prepare_payload_identities(installer)

    def run(source, arguments, stage):
        path = stage / "activate-boot.sh"
        path.write_text(source, encoding="ascii", newline="\n")
        env = os.environ.copy()
        env["X2DII_TEST_HOST_PROGRAM_SHA"] = peer.sha(source.encode("ascii"))
        return subprocess.run([str(SH), installer.posix + "/" + path.relative_to(installer.root).as_posix(),
                               *arguments], input=b"", capture_output=True, timeout=30, env=env)

    result = run_rc(installer, setup=False, supervised=True, dependency_hash=peer.sha(raw), process_runner=run)
    assert result.returncode == 81, (result.stdout, result.stderr)
    assert b"X2DII_BOOT_BOUNDARY_REQUEST:activate:0:" in result.stdout
    assert not (installer.root / "rc-operations").exists()
    assert (installer.root / peer.boot.TARGET.lstrip("/")).read_bytes() == peer.boot.STOCK.read_bytes()


def test_shell_payload_identity_data_rejects_nul_even_when_its_input_hash_matches(installer):
    raw = prepare_payload_identities(installer)
    changed = raw.replace(b"identity_0=", b"identity_0=\0")
    stage = installer.root / "blackbox/x2dii-menu-stage" / installer.manifest["candidate_sha256"][:24]
    data_path, = stage.glob(".payload-identities-*.data")
    data_path.write_bytes(changed)

    def run(source, arguments, stage):
        path = stage / "activate-boot.sh"
        path.write_text(source, encoding="ascii", newline="\n")
        env = os.environ.copy()
        env["X2DII_TEST_HOST_PROGRAM_SHA"] = peer.sha(source.encode("ascii"))
        return subprocess.run([str(SH), installer.posix + "/" + path.relative_to(installer.root).as_posix(),
                               *arguments], input=b"", capture_output=True, timeout=30, env=env)

    result = run_rc(installer, setup=False, supervised=True, dependency_hash=peer.sha(changed), process_runner=run)
    assert result.returncode == 81, (result.stdout, result.stderr)
    assert b"X2DII_BOOT_BOUNDARY_REQUEST" not in result.stdout
    assert not (installer.root / "rc-operations").exists()


def boot_dialogue(installer, *, action="activate", setup=True, reply=None, raw=None,
                  backup_identity=None, hook="", use_observer=False, staged_program=False, wrap_status=False,
                  host_wait_seconds=None):
    from tools import menu_boot_boundary as boundary
    if setup:
        dependencies = prepare_payload_identities(installer)
    else:
        values = session.decode_session(peer.session_data(installer.manifest, installer.q))
        dependency_path = (installer.root / "blackbox/x2dii-menu-stage" /
            installer.manifest["candidate_sha256"][:24] / f".payload-identities-{values['session_nonce']}.data")
        dependencies = dependency_path.read_bytes() if dependency_path.exists() else b""
    observations = []

    def run(source, arguments, stage):
        if host_wait_seconds is not None:
            assert (staged_program or use_observer) and host_wait_seconds == 30
            assert source.count("IFS= read -r -t 8 boot_ack") == 1
            # Only the host OS timing seam, never the original staged bytes or
            # target's eight-second acknowledgement/USB-window qualification.
            source = source.replace("IFS= read -r -t 8 boot_ack", "IFS= read -r -t 30 boot_ack", 1)
        path = stage / f"{action}-boot.sh"
        original = None
        if staged_program:
            original = (path.stat().st_ino, path.stat().st_mtime_ns, path.read_bytes())
            host_script = installer.root / f".host-{action}-boot.sh"
            host_script.write_text(source, encoding="ascii", newline="\n")
        else:
            path.write_text(source, encoding="ascii", newline="\n")
        env = {key: value for key, value in os.environ.items()
               if key.upper() not in {"BASH_ENV", "ENV"}}
        env["X2DII_TEST_HOST_PROGRAM_SHA"] = peer.sha(source.encode("ascii"))
        command = [str(SH), installer.posix + "/" + path.relative_to(installer.root).as_posix(), *arguments]
        if staged_program:
            command = [str(SH), "-c", 'host_source=$1; shift; . "$host_source"', command[1],
                installer.posix + "/" + host_script.relative_to(installer.root).as_posix(), *arguments]
        if wrap_status:
            marker = f"X2DII_BOOT_WORKER_{arguments[1][:24]}_{action}_RC="
            command = [str(SH), "-c", '("$@"); r=$?; printf "\\n' + marker + '%s\\n" "$r"',
                       "status-wrapper", "/usr/bin/sh", *command[1:]]
        command = [str(HOST_BASH), "--noprofile", "--norc", "-p", *command[1:]]
        process = thread = stderr_thread = None
        primary = None
        forced = retained = False
        stdout_start_attempted = stderr_start_attempted = False
        cleanup_errors = []
        lines = queue.Queue()
        stdout_eof = threading.Event()
        stderr_eof = threading.Event()
        reader_errors = []
        reader_output = bytearray()
        stderr_output = bytearray()
        output = bytearray()

        def retain_fixture():
            nonlocal retained
            if not retained:
                installer.temp._finalizer.detach()
                installer.temp.cleanup = lambda: None
                retained = True

        def attempt(label, operation):
            try:
                return operation()
            except BaseException as error:
                # An auxiliary exception's __str__/__repr__ can also fail.
                cleanup_errors.append((label, type(error).__name__))
                return None

        def reader():
            try:
                for line in iter(process.stdout.readline, b""):
                    reader_output.extend(line)
                    lines.put(line)
                stdout_eof.set()
                lines.put(None)
            except BaseException as error:
                reader_errors.append(error)
                lines.put(error)

        def stderr_reader():
            try:
                for chunk in iter(lambda: process.stderr.read1(65536), b""):
                    stderr_output.extend(chunk)
                stderr_eof.set()
            except BaseException as error:
                reader_errors.append(error)
                lines.put(error)

        try:
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
            thread = threading.Thread(target=reader, daemon=True)
            stdout_start_attempted = True
            thread.start()
            stderr_thread = threading.Thread(target=stderr_reader, daemon=True)
            stderr_start_attempted = True
            stderr_thread.start()
            while True:
                line = lines.get(timeout=30)
                if isinstance(line, BaseException):
                    raise line
                if line is None:
                    break
                output.extend(line)
                if not line.startswith(b"X2DII_BOOT_BOUNDARY_REQUEST:"):
                    continue
                _, request_action, index, digest = line.decode().strip().split(":")
                assert request_action == action
                index = int(index)
                session_file = stage / f"session-context-{arguments[1]}.data"
                nonce = session.decode_session(session_file.read_bytes())["session_nonce"]
                data = (stage / f".boot-{action}-{nonce}-{index}.data").read_bytes()
                assert peer.sha(data) == digest
                values = boundary.decode_request(data)
                observations.append(values)
                answer = f"X2DII_BOOT_BOUNDARY_ACK:{digest}:{values['issued_epoch']}:{values['issued_epoch']}\n".encode()
                observation_started = time.monotonic()
                if use_observer:
                    from tests.test_menu_boot_boundary import execute_boot_observer
                    result = execute_boot_observer(installer, session_file.read_bytes(),
                        data, action=action, index=index)
                    assert result.returncode == 0, (result.stdout, result.stderr)
                    verified = boundary.decode_response(result.stdout, data, received_epoch=values["issued_epoch"])
                    answer = f"X2DII_BOOT_BOUNDARY_ACK:{digest}:{verified['started_epoch']}:{verified['checked_epoch']}\n".encode()
                if reply:
                    answer = reply(index, answer, values)
                if answer is None:
                    process.stdin.close()
                else:
                    try:
                        process.stdin.write(answer)
                        process.stdin.flush()
                    except OSError as error:
                        elapsed = time.monotonic() - observation_started
                        try:
                            status = process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            status = None
                        raise AssertionError((action, index, "observer seconds", elapsed,
                            "outer process status", status, "stderr complete", stderr_eof.is_set(),
                            "observed stderr", bytes(stderr_output), "timely stdout", bytes(output))) from error
            # Preserve the original outer-wait then reader-join phases. A
            # stderr error wakes an active stdout wait; after stdout EOF it
            # remains the exact primary error, even if outer wait expires.
            if reader_errors:
                raise reader_errors[0]
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                if reader_errors:
                    raise reader_errors[0]
                raise
            thread.join(timeout=5)
            stderr_thread.join(timeout=5)
            if reader_errors:
                raise reader_errors[0]
            assert not thread.is_alive() and stdout_eof.is_set(), "stdout stream remains incomplete"
            assert not stderr_thread.is_alive() and stderr_eof.is_set(), "stderr stream remains incomplete"
            if original is not None:
                assert (path.stat().st_ino, path.stat().st_mtime_ns, path.read_bytes()) == original
            # This is the directly owned outer process result. A wrapped inner
            # worker is still independently checked through its exact marker by
            # BootCoordinator; outer returncode zero does not prove that worker.
            return subprocess.CompletedProcess(process.args, process.returncode, bytes(output), bytes(stderr_output))
        except BaseException as error:
            primary = error
            attempt("retain primary-failure fixture", retain_fixture)
            raise
        finally:
            if process is not None:
                status = attempt("poll owned process", lambda: process.poll())
                if status is None:
                    attempt("retain before forced cleanup", retain_fixture)
                    forced = True
                    attempt("kill owned process only", lambda: process.kill())
                    attempt("wait owned process", lambda: process.wait(timeout=10))
            for label, worker, attempted, eof in (
                    ("stdout", thread, stdout_start_attempted, stdout_eof),
                    ("stderr", stderr_thread, stderr_start_attempted, stderr_eof)):
                if worker is not None and attempted:
                    attempt(label + " reader join", lambda worker=worker: worker.join(timeout=5))
                    if not eof.is_set():
                        # start() can fail after native thread creation but
                        # before ident/_started publication. Do not infer that
                        # this reader never ran from ident/is_alive alone.
                        cleanup_errors.append((label + " reader", "IncompleteStream"))
            if cleanup_errors:
                attempt("retain unknown cleanup fixture", retain_fixture)
            if process is not None:
                # Closing BufferedWriter can flush into an inherited pipe even
                # after the outer shell exits. Close its owned raw handle,
                # discarding pending bytes on this completed/failed operation.
                attempt("stdin raw close without flush", lambda: process.stdin.raw.close())
                for label, pipe, attempted, eof in (
                        ("stdout", process.stdout, stdout_start_attempted, stdout_eof),
                        ("stderr", process.stderr, stderr_start_attempted, stderr_eof)):
                    # Never close a buffer potentially held by a reader whose
                    # start failed halfway. Preserve that object on the error.
                    if not attempted or eof.is_set():
                        attempt(label + " close", lambda pipe=pipe: pipe.close())
            if cleanup_errors:
                attempt("retain auxiliary-failure fixture", retain_fixture)
                error = primary if primary is not None else AssertionError("boot host cleanup incomplete")
                attempt("annotate cleanup errors", lambda: error.add_note("Boot cleanup errors: " + repr(cleanup_errors)))
            else:
                error = primary
            if error is not None:
                # Snapshot only this reader's already received bytes. Late
                # lines never enter timely output or turn a timeout into PASS.
                attempt("attach host failure evidence", lambda: setattr(error, "boot_host_evidence", {
                    "fixture": str(installer.root), "fixture_retained": retained,
                    "forced_owned_process_cleanup": forced,
                    "stdout_eof": stdout_eof.is_set(), "stderr_eof": stderr_eof.is_set(),
                    "reader_observed_stdout": bytes(reader_output),
                    "timely_stdout": bytes(output), "observed_stderr": bytes(stderr_output),
                    "reader_errors": tuple(reader_errors),
                    "cleanup_errors": tuple(cleanup_errors),
                    "whole_process_tree_terminal_claimed": False, "installable": False}))
                if forced or not stdout_eof.is_set() or not stderr_eof.is_set():
                    # Retain the pipe objects too; do not trigger buffered-I/O
                    # finalization while a late-starting reader is unresolved.
                    attempt("retain owned pipe objects", lambda: setattr(error, "boot_host_retained_process", process))
                if primary is None:
                    raise error

    renderer = None
    if staged_program:
        def renderer(manifest, **kwargs):
            path = installer.root / "blackbox/x2dii-menu-stage" / manifest["candidate_sha256"][:24] / f"{action}-boot.sh"
            return path.read_bytes().decode("ascii")
    result = run_rc(installer, setup=False, supervised=True, action=action, raw=raw, hook=hook,
        backup_identity=backup_identity, dependency_hash=peer.sha(dependencies), process_runner=run,
        source_renderer=renderer)
    return result, observations


@pytest.mark.parametrize("use_observer,host_wait_seconds,expected_read", (
    (False, None, 8), (True, None, 8), (True, 30, 30),
))
def test_boot_observer_host_wait_is_explicit_and_keeps_exact_host_hash_mapping(
        installer, monkeypatch, use_observer, host_wait_seconds, expected_read):
    stage = installer.shell_fixture()
    original = boot_file.render_supervised_boot_transaction(installer.manifest, action="activate",
        original_rc=peer.boot.STOCK.read_bytes(),
        metadata=installer.q["metadata"][peer.boot.TARGET],
        init_scan_roots=installer.q["init_scan_roots"])
    assert original.count("IFS= read -r -t 8 boot_ack") == 1

    def observe_launch(command, **kwargs):
        # Observe the real external launch seam and actual written adapter;
        # no worker, observer or transaction result is substituted.
        path = stage / "activate-boot.sh"
        adapter = path.read_bytes()
        assert command[:5] == [str(HOST_BASH), "--noprofile", "--norc", "-p",
                               installer.posix + "/" + path.relative_to(installer.root).as_posix()]
        assert SH.as_posix() == "C:/Program Files/Git/bin/sh.exe"
        assert not {key.upper() for key in kwargs["env"]} & {"BASH_ENV", "ENV"}
        assert adapter.count(f"IFS= read -r -t {expected_read} boot_ack".encode()) == 1
        assert b'[ "$((boot_received-boot_issued_epoch))" -le 8 ] || exit 81' in adapter
        assert kwargs["env"]["X2DII_TEST_HOST_PROGRAM_SHA"] == peer.sha(adapter)
        assert ("printf '" + peer.sha(original.encode("ascii")) + "  %s\\n' \"$1\"").encode() in adapter
        assert b'[ "$1" = "$0" ] && [ "${host_hash%% *}" = "$X2DII_TEST_HOST_PROGRAM_SHA" ]' in adapter
        raise RuntimeError("recorded external boot launch")

    monkeypatch.setattr(subprocess, "Popen", observe_launch)
    with pytest.raises(RuntimeError, match="recorded external boot launch"):
        boot_dialogue(installer, setup=False, use_observer=use_observer,
                      host_wait_seconds=host_wait_seconds)


@pytest.mark.parametrize("use_observer,host_wait_seconds", ((False, 30), (True, 8), (True, 31)))
def test_boot_host_wait_rejects_unselected_or_unsupported_adapter_before_launch(
        installer, monkeypatch, use_observer, host_wait_seconds):
    stage = installer.shell_fixture()

    def unexpected_launch(*args, **kwargs):
        pytest.fail("unsupported host wait reached the external process")

    monkeypatch.setattr(subprocess, "Popen", unexpected_launch)
    with pytest.raises(AssertionError):
        boot_dialogue(installer, setup=False, use_observer=use_observer,
                      host_wait_seconds=host_wait_seconds)
    assert not (stage / "activate-boot.sh").exists()


def test_supervised_activation_and_independent_restore_keep_original_backup_and_fixed_boundaries(installer):
    activated, observed = boot_dialogue(installer, use_observer=True, host_wait_seconds=30)
    assert activated.returncode == 0, (activated.stdout, activated.stderr)
    assert [item["boundary_name"] for item in observed] == [
        "remount_rw", "backup_create", "backup_write", "backup_chmod", "backup_timestamp",
        "temporary_create", "temporary_write", "temporary_chmod", "temporary_timestamp", "commit_rename",
        "final_identity", "final_receipt"]
    assert b"maintenance_boundaries=HOST_MEDIATED_FIXED_BOOT_MATCHED" in activated.stdout
    assert (installer.root / peer.boot.TARGET.lstrip("/")).read_bytes() == peer.boot.activate(peer.boot.STOCK.read_bytes())
    identity = next(line.split("=", 1)[1] for line in activated.stdout.decode().splitlines()
                    if line.startswith("backup_identity="))
    for entry in installer.manifest["candidate"]["files"]:
        (installer.root / entry["target"].lstrip("/")).unlink()
    restored, recovery_observed = boot_dialogue(installer, setup=False, action="restore",
        raw=recovery_data(installer), backup_identity=identity, use_observer=True, host_wait_seconds=30)
    assert restored.returncode == 0, (restored.stdout, restored.stderr)
    assert [item["boundary_name"] for item in recovery_observed] == [
        "remount_rw", "temporary_create", "temporary_write", "temporary_chmod", "temporary_timestamp",
        "commit_rename", "final_identity", "final_receipt"]
    assert (installer.root / peer.boot.TARGET.lstrip("/")).read_bytes() == peer.boot.STOCK.read_bytes()
    assert (installer.root / "proc/mounts").read_text() == installer.mount_line


@pytest.mark.parametrize("fault,at", (("payload_inode", 1), ("temporary_inode", 7), ("eof", 1)))
def test_waiting_boot_worker_rechecks_owned_dependencies_before_next_write(installer, fault, at):
    def reply(index, answer, values):
        if index != at:
            return answer
        if fault == "eof":
            return None
        if fault == "payload_inode":
            target = installer.root / installer.manifest["candidate"]["files"][0]["target"].lstrip("/")
        else:
            target, = (installer.root / "system/etc").glob(".x2dii-boot-*-activate.stage")
        old_inode = target.stat().st_ino
        displaced = target.with_name(target.name + ".replaced")
        target.rename(displaced)
        target.write_bytes(displaced.read_bytes())
        assert target.stat().st_ino != old_inode
        return answer

    result, observed = boot_dialogue(installer, reply=reply)
    assert result.returncode == 81, (result.stdout, result.stderr)
    assert len(observed) == at + 1
    assert b"schema=x2dii-rc-file-transaction-v1" not in result.stdout
    assert (installer.root / peer.boot.TARGET.lstrip("/")).read_bytes() == peer.boot.STOCK.read_bytes()
    assert (installer.root / "proc/mounts").read_text() == installer.mount_line
    assert "mv:" not in (installer.root / "rc-operations").read_text()


def test_supervised_restore_already_official_is_readonly_and_needs_no_payloads(installer):
    activated = run_rc(installer, stable=True)
    assert activated.returncode == 0, (activated.stdout, activated.stderr)
    identity = next(line.split("=", 1)[1] for line in activated.stdout.decode().splitlines()
                    if line.startswith("backup_identity="))
    restored = run_rc(installer, stable=True, setup=False, action="restore",
                      raw=recovery_data(installer), backup_identity=identity)
    assert restored.returncode == 0, (restored.stdout, restored.stderr)
    operations = (installer.root / "rc-operations").read_bytes()
    target = installer.root / peer.boot.TARGET.lstrip("/")
    before = (target.stat().st_ino, target.stat().st_mtime_ns)
    values = session.decode_session(recovery_data(installer))
    values["rc_sha256"] = installer.manifest["candidate"]["rc"]["before"]
    result, observed = boot_dialogue(installer, setup=False, action="restore",
        raw=session.encode_session(values), backup_identity=identity)
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert [item["boundary_index"] for item in observed] == [6, 7]
    assert (installer.root / "rc-operations").read_bytes() == operations
    assert (target.stat().st_ino, target.stat().st_mtime_ns) == before
