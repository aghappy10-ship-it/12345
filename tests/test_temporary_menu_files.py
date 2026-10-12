"""Actual generated shell/file operations; OS labels and mounts are fixtures only."""
from copy import deepcopy
from functools import partial
import os
import subprocess

import pytest

from tests.test_release_lifecycle import installer
from tests.test_temporary_menu_session import temporary_values
from tests.test_peer_install import SH
from tools import prepare_peer_install as peer
from tools import session_context as session
from tools import temporary_menu_files as files


def test_temporary_and_formal_workers_have_distinct_fixed_paths(installer):
    for index in range(4):
        temporary = files.worker_path(installer.manifest, index, session_kind="menu_validation")
        formal = files.worker_path(installer.manifest, index, session_kind="install")
        assert temporary.endswith(f"/menu-validation-preplace-{index}.sh")
        assert formal.endswith(f"/preplace-{index}.sh")
        assert temporary != formal
    with pytest.raises(ValueError):
        files.worker_path(installer.manifest, 0, session_kind="recovery")


def run_worker(installer, *, index=0, hook="", values=None, setup=True,
               renderer=files.render_preplacement, process_runner=None,
               schema=session.MENU_VALIDATION_SCHEMA):
    if setup:
        source_dir = installer.shell_fixture()
    else:
        # Reuse actual prior file operations without resetting core/GUI state.
        source_dir = installer.root / "blackbox/x2dii-menu-stage" / installer.manifest["candidate_sha256"][:24]
        assert source_dir.is_dir()
    data = session.encode_session(values or temporary_values(installer), schema=schema)
    session_file = source_dir / (f"session-context-{peer.sha(data)}.data" if process_runner is not None else "session-context.data")
    if not setup and session_file.exists():
        assert session_file.read_bytes() == data, "handoff cannot replace the original session"
    else:
        session_file.write_bytes(data)
    source = renderer(installer.manifest, file_index=index)
    original_program_sha = peer.sha(source.encode("ascii"))
    head, parser = source.split("# SESSION_DATA_PARSER_BEGIN\n", 1)
    parser, tail = parser.split("# SESSION_DATA_PARSER_END\n", 1)
    source = head + "# PARSER_PLACEHOLDER\n" + tail
    source = source.replace("/proc/self/fd/3", "FD_PATH_PLACEHOLDER")
    for prefix in ("/system", "/blackbox", "/proc"):
        source = source.replace(prefix, installer.posix + prefix)
    source = source.replace("FD_PATH_PLACEHOLDER", "/proc/self/fd/3")
    source = source.replace("# PARSER_PLACEHOLDER\n", parser)
    source = source.replace("export PATH=" + installer.posix + "/system/bin:" + installer.posix + "/system/xbin:/sbin", "export PATH=/usr/bin:/bin")
    epoch = int(peer.datetime.fromisoformat(installer.q["observed_utc"]).timestamp())
    wrapper = r'''
fixture=FIXTURE
worker_mode=600
id() { printf '0\n'; }
date() { printf 'EPOCH\n'; }
cat() {
 case "$1" in
  "$fixture/proc/self/attr/current"|"$fixture/proc/sys/kernel/random/boot_id") ;;
  "$fixture/proc/"*|"$fixture/system/bin/"*) printf 'forbidden-cat:%s\n' "$1" >&2; return 90;;
 esac
 /usr/bin/cat "$@"
}
readlink() {
 [ "$1" = "$fixture/proc/self/ns/mnt" ] || { printf 'forbidden-readlink:%s\n' "$1" >&2; return 90; }
 printf 'mnt:[4026531840]\n'
}
fixture_stat() {
 if [ "$2" = '%u:%g:%a' ]; then
  if [ -d "$3" ]; then echo '0:0:700'; else echo '0:0:600'; fi
 elif [ "$2" = '%u %g %a' ]; then
  if [ -d "$3" ]; then echo '0 0 700'
  else
   case "$3" in
    */.boundary-*.data|*/preplace-*.sh|*/menu-validation-preplace-*.sh|*/session-context*.data) echo '0 0 600';;
    *) printf '0 0 %s\n' "$worker_mode";;
   esac
  fi
 elif [ "$2" = '%d:%i:%f:%h:%s:%u:%g' ]; then
  native_identity=$(/usr/bin/stat "$@") || return
  case "$3" in
   */.boundary-*.data|*/preplace-*.sh|*/menu-validation-preplace-*.sh|*/session-context*.data) modeled_mode=8180;;
   *) if [ "$worker_mode" = 644 ]; then modeled_mode=81a4; else modeled_mode=8180; fi;;
  esac
  saved_ifs=$IFS; IFS=:; set -- $native_identity; IFS=$saved_ifs
  # Ownership is the same explicit root fixture as the standalone %u/%g
  # metadata query; keep native inode/link/length, not the Windows account ID.
  printf '%s:%s:%s:%s:%s:0:0\n' "$1" "$2" "$modeled_mode" "$4" "$5"
 else /usr/bin/stat "$@"; fi
}
stat() { fixture_stat "$@"; }
ls() { printf 'u:object_r:system_file:s0 %s\n' "$2"; }
sync() { printf 'sync\n' >> "$fixture/worker-operations"; }
boundary() { :; }
mount() {
 printf 'mount:%s\n' "$*" >> "$fixture/worker-operations"
 case "$2" in remount,rw) worker_state=rw;; remount,ro) worker_state=ro;; *) return 90;; esac
 printf '/dev/block/current-attested-slot %s/system ext4 %s,seclabel,relatime 0 0\n' "$fixture" "$worker_state" > "$fixture/proc/mounts"
 boundary remount
}
mv() { printf 'mv:%s\n' "$*" >> "$fixture/worker-operations"; /usr/bin/mv "$@"; }
# NTFS ACL mode reporting is not target chmod behavior; model only that boundary.
chmod() { printf 'chmod:%s\n' "$*" >> "$fixture/worker-operations"; /usr/bin/chmod "$@" || return; worker_mode=644; }
mkdir() { printf forbidden-mkdir >&2; return 90; }
chcon() { printf forbidden-chcon >&2; return 90; }
start() { printf forbidden-start >&2; return 90; }
stop() { printf forbidden-stop >&2; return 90; }
rm() { printf forbidden-rm >&2; return 90; }
rmdir() { printf forbidden-rmdir >&2; return 90; }
'''.replace("FIXTURE", peer.shlex.quote(installer.posix)).replace("EPOCH", str(epoch))
    if process_runner is not None:
        # Hash mapping models only the fixed host root/OS substitutions. Changed
        # host bytes still return their actual hash, never the original digest.
        wrapper += r'''
sha256sum() {
 host_hash=$(/usr/bin/sha256sum "$@") || return
 if [ "$#" = 1 ] && [ "$1" = "$0" ] && [ "${host_hash%% *}" = "${X2DII_TEST_HOST_PROGRAM_SHA-}" ]; then
  printf 'ORIGINAL_PROGRAM_SHA  %s\n' "$1"
 else printf '%s\n' "$host_hash"; fi
}
'''.replace("ORIGINAL_PROGRAM_SHA", original_program_sha)
    arguments = [installer.posix + "/" + session_file.relative_to(installer.root).as_posix(), peer.sha(data)]
    if process_runner is not None:
        # Only a local OS-process seam: the runner owns stdin/stdout for actual
        # generated worker execution, not a fake internal ready() result.
        return process_runner(wrapper + hook + source, arguments, source_dir)
    result = subprocess.run([str(SH), "-s", "--", *arguments],
                            input=(wrapper + hook + source).encode("ascii"), capture_output=True, timeout=60)
    return result


def test_one_file_preplacement_uses_real_shell_and_leaves_other_payloads_absent(installer):
    result = run_worker(installer)
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert b"X2DII_ONE_FILE_PREPLACED_NOT_RUNTIME_VALIDATED" in result.stdout
    entry = installer.manifest["candidate"]["files"][0]
    assert peer.sha((installer.root / entry["target"].lstrip("/")).read_bytes()) == entry["sha256"]
    assert all(not (installer.root / other["target"].lstrip("/")).exists()
               for other in installer.manifest["candidate"]["files"][1:])
    assert (installer.root / "proc/mounts").read_text() == installer.mount_line
    assert not (installer.root / "tmp/x2dii-menu-install.lock").exists()
    assert (installer.root / "system/etc/init/camera-gui.rc").read_bytes() == peer.boot.STOCK.read_bytes()


@pytest.mark.parametrize("program_kind,schema,expected", (
    ("install", session.INSTALL_SCHEMA, 81),
    ("install", session.MENU_VALIDATION_SCHEMA, 32),
    ("menu_validation", session.INSTALL_SCHEMA, 32),
    ("install", session.SCHEMA, 32),
))
def test_formal_worker_accepts_only_its_fixed_kind_before_requesting_any_write(
        installer, program_kind, schema, expected):
    values = (temporary_values(installer) if schema == session.MENU_VALIDATION_SCHEMA
              else session.decode_session(peer.session_data(installer.manifest, installer.q)))
    values["observer_domain"] = "u:r:hbl_camera_service:s0"
    if schema == session.SCHEMA:
        values = {key: values[key] for key in session.COMMON_FIELDS}

    def run(source, arguments, source_dir):
        script = installer.root / files.worker_path(installer.manifest, 0, session_kind=program_kind).lstrip("/")
        script.write_text(source, encoding="ascii", newline="\n")
        env = os.environ.copy()
        env["X2DII_TEST_HOST_PROGRAM_SHA"] = peer.sha(source.encode("ascii"))
        return subprocess.run([str(SH), installer.posix + "/" + script.relative_to(installer.root).as_posix(),
                               *arguments], input=b"", capture_output=True, env=env, timeout=30)

    result = run_worker(installer, values=values, schema=schema,
        renderer=partial(files.render_supervised_preplacement, session_kind=program_kind), process_runner=run)
    assert result.returncode == expected, (result.stdout, result.stderr)
    assert (b"X2DII_BOUNDARY_REQUEST:0:0:" in result.stdout) == (expected == 81)
    assert not (installer.root / "worker-operations").exists()
    assert not (installer.root / "system/lib64/libx2dii_menu.so").exists()


def test_supervised_worker_rejects_legacy_session_path_even_with_matching_bytes(installer):
    def run(source, arguments, source_dir):
        current = source_dir / f"session-context-{arguments[1]}.data"
        legacy = source_dir / "session-context.data"
        legacy.write_bytes(current.read_bytes())
        script = installer.root / files.worker_path(installer.manifest, 0, session_kind="menu_validation").lstrip("/")
        script.write_text(source, encoding="ascii", newline="\n")
        env = os.environ.copy()
        env["X2DII_TEST_HOST_PROGRAM_SHA"] = peer.sha(source.encode("ascii"))
        return subprocess.run([str(SH), installer.posix + "/" + script.relative_to(installer.root).as_posix(),
            installer.posix + "/" + legacy.relative_to(installer.root).as_posix(), arguments[1]],
            input=b"", capture_output=True, env=env, timeout=30)

    result = run_worker(installer, renderer=files.render_supervised_preplacement, process_runner=run)
    assert result.returncode == 32, (result.stdout, result.stderr)
    assert b"X2DII_BOUNDARY_REQUEST" not in result.stdout
    assert not (installer.root / "worker-operations").exists()


@pytest.mark.parametrize("size", (8 * 1024 * 1024, 8 * 1024 * 1024 + 1, 64 * 1024 * 1024))
def test_existing_strict_eight_mib_member_limit_is_not_weakened(installer, size):
    manifest = deepcopy(installer.manifest)
    manifest["candidate"]["files"][0]["bytes"] = size
    manifest["candidate_sha256"] = peer.sha(peer.canonical(manifest["candidate"]))
    with pytest.raises(ValueError):
        files.render_preplacement(manifest, file_index=0)


def test_label_reply_for_another_path_is_not_this_created_files_metadata(installer):
    result = run_worker(installer, hook=r'''
ls() { printf 'u:object_r:system_file:s0 /system/etc/unrelated\n'; }
''')
    assert result.returncode != 0, (result.stdout, result.stderr)
    assert not (installer.root / "system/lib64/libx2dii_menu.so").exists()


def test_success_receipt_binds_final_inode_not_only_initial_empty_file(installer):
    result = run_worker(installer)
    assert result.returncode == 0, (result.stdout, result.stderr)
    lines = result.stdout.decode().splitlines()
    assert "schema=x2dii-one-file-preplacement-v1" in lines
    assert "candidate_sha256=" + installer.manifest["candidate_sha256"] in lines
    assert "session_nonce=" + "b" * 32 in lines
    assert "file_index=0" in lines
    assert "label=u:object_r:system_file:s0" in lines
    assert "sha256=" + installer.manifest["candidate"]["files"][0]["sha256"] in lines
    identity = next(line[9:] for line in lines if line.startswith("identity="))
    actual = subprocess.run([str(SH), "-c", '/usr/bin/stat -c "%d:%i:%f:%h:%s:%u:%g" "$1"',
                             "fixture", installer.posix + "/system/lib64/libx2dii_menu.so"],
                            capture_output=True, text=True, check=True).stdout.strip()
    # Ownership is explicitly modeled as root at the OS fixture boundary;
    # native Windows UID/GID must not be mistaken for target metadata. Keep
    # the actual inode, mode, link count and length comparison independent.
    assert identity.split(":")[:5] == actual.split(":")[:5]
    assert identity.split(":")[5:] == ["0", "0"]
    assert int(identity.split(":")[4]) == installer.manifest["candidate"]["files"][0]["bytes"]
    assert "maintenance_boundaries=UNCONNECTED" in lines


@pytest.mark.parametrize("hook", (
    "id() { echo 1000; }\n",
    "printf 'u:r:hbl_camera_service:s0\\n' > \"$fixture/proc/self/attr/current\"\n",
))
def test_non_su_roles_are_refused_before_any_file_or_mount_operation(installer, hook):
    result = run_worker(installer, hook=hook)
    assert result.returncode == 31, (result.stdout, result.stderr)
    assert not (installer.root / "worker-operations").exists()


def test_partial_copy_is_retained_without_delete_or_commit_and_mount_returns_ro(installer):
    result = run_worker(installer, hook=r'''
cat() {
 case "$1" in
  */blackbox/x2dii-menu-stage/*/libx2dii_menu.so) printf partial; return 9;;
  *) /usr/bin/cat "$@";;
 esac
}
''')
    assert result.returncode == 9, (result.stdout, result.stderr)
    retained = list((installer.root / "system/lib64").glob(".x2dii-preplace-*"))
    assert len(retained) == 1 and retained[0].read_bytes() == b"partial"
    assert not (installer.root / "system/lib64/libx2dii_menu.so").exists()
    assert (installer.root / "proc/mounts").read_text() == installer.mount_line
    assert b"schema=x2dii-one-file-preplacement" not in result.stdout


@pytest.mark.parametrize("damage", ("label", "owner", "label_status", "metadata_status"))
def test_wrong_created_metadata_or_error_with_expected_output_is_retained(installer, damage):
    if damage.startswith("label"):
        label = "u:object_r:wrong:s0" if damage == "label" else "u:object_r:system_file:s0"
        hook = "ls() { printf '" + label + " %s\\n' \"$2\"; " + ("return 9;" if damage == "label_status" else ":;") + " }\n"
    else:
        hook = r'''
stat() {
 if [ "$2" = '%u %g %a' ] && [ -f "$3" ]; then
  printf 'METADATA\n'
  return STATUS
 fi
 fixture_stat "$@"
}
'''.replace("METADATA", "1000 0 600" if damage == "owner" else "0 0 600").replace(
            "STATUS", "9" if damage == "metadata_status" else "0")
    result = run_worker(installer, hook=hook)
    assert result.returncode == 33, (result.stdout, result.stderr)
    retained = list((installer.root / "system/lib64").glob(".x2dii-preplace-*"))
    assert len(retained) == 1
    assert not (installer.root / "system/lib64/libx2dii_menu.so").exists()
    assert (installer.root / "proc/mounts").read_text() == installer.mount_line
    assert b"schema=x2dii-one-file-preplacement" not in result.stdout


@pytest.mark.parametrize("boundary", ("before_remount", "before_commit"))
def test_original_lease_is_not_renewed_at_later_boundaries(installer, boundary):
    epoch = int(peer.datetime.fromisoformat(installer.q["observed_utc"]).timestamp())
    hook = f'''
date() {{
 if [ "{boundary}" = before_remount ] || [ "$worker_mode" = 644 ]; then echo {epoch + 601}
 else echo {epoch}; fi
}}
'''
    result = run_worker(installer, hook=hook)
    assert result.returncode == 32, (result.stdout, result.stderr)
    assert not (installer.root / "system/lib64/libx2dii_menu.so").exists()
    assert (installer.root / "proc/mounts").read_text() == installer.mount_line
    if boundary == "before_remount":
        assert not (installer.root / "worker-operations").exists()
    else:
        retained = list((installer.root / "system/lib64").glob(".x2dii-preplace-*"))
        assert len(retained) == 1 and retained[0].stat().st_size == installer.manifest["candidate"]["files"][0]["bytes"]


def test_same_content_replacement_is_not_adopted_or_committed(installer):
    result = run_worker(installer, hook=r'''
cat() {
 /usr/bin/cat "$@" || return
 case "$1" in
  */blackbox/x2dii-menu-stage/*/libx2dii_menu.so)
   /usr/bin/mv "$temporary" "$temporary.displaced"
   /usr/bin/cp "$temporary.displaced" "$temporary";;
 esac
}
''')
    assert result.returncode == 33, (result.stdout, result.stderr)
    retained = list((installer.root / "system/lib64").glob(".x2dii-preplace-*"))
    assert len(retained) == 2
    assert retained[0].read_bytes() == retained[1].read_bytes()
    assert retained[0].stat().st_ino != retained[1].stat().st_ino
    assert not (installer.root / "system/lib64/libx2dii_menu.so").exists()
    assert (installer.root / "proc/mounts").read_text() == installer.mount_line
    assert "chmod:" not in (installer.root / "worker-operations").read_text()


def test_readonly_remount_error_never_produces_success_receipt(installer):
    result = run_worker(installer, hook=r'''
boundary() { [ "$worker_state" != ro ] || return 9; }
''')
    assert result.returncode == 72, (result.stdout, result.stderr)
    assert (installer.root / "system/lib64/libx2dii_menu.so").is_file()
    assert (installer.root / "proc/mounts").read_text() == installer.mount_line
    assert b"schema=x2dii-one-file-preplacement" not in result.stdout


@pytest.mark.parametrize("index", (1, 2, 3))
def test_other_compiled_indexes_keep_the_same_one_file_role(installer, index):
    result = run_worker(installer, index=index)
    assert result.returncode == 0, (result.stdout, result.stderr)
    for other_index, entry in enumerate(installer.manifest["candidate"]["files"]):
        assert (installer.root / entry["target"].lstrip("/")).exists() == (other_index == index)
    assert f"file_index={index}\n".encode() in result.stdout
    assert b"forbidden-" not in result.stderr


@pytest.mark.parametrize("index", (-1, 4, True, "0", "/system/etc/custom"))
def test_runtime_paths_or_noncanonical_indexes_cannot_select_a_payload(installer, index):
    with pytest.raises(ValueError):
        files.render_preplacement(installer.manifest, file_index=index)


def test_eight_mib_minus_one_is_still_permitted_by_pure_renderer(installer):
    manifest = deepcopy(installer.manifest)
    manifest["candidate"]["files"][0]["bytes"] = 8 * 1024 * 1024 - 1
    manifest["candidate_sha256"] = peer.sha(peer.canonical(manifest["candidate"]))
    assert "8388607" in files.render_preplacement(manifest, file_index=0)


def test_reused_fixture_keeps_previous_payload_and_observed_state(installer):
    first = run_worker(installer)
    assert first.returncode == 0, (first.stdout, first.stderr)
    library = installer.root / "system/lib64/libx2dii_menu.so"
    first_inode = library.stat().st_ino
    observed_state = installer.root / "gui-service-state"
    observed_state.write_text("do-not-reinitialize-fixture")
    second = run_worker(installer, index=1, setup=False)
    assert second.returncode == 0, (second.stdout, second.stderr)
    assert library.stat().st_ino == first_inode
    assert observed_state.read_text() == "do-not-reinitialize-fixture"
    assert (installer.root / "system/etc/X2d2MenuBootstrap.qml").is_file()


def test_final_hash_query_cannot_substitute_same_content_new_inode_into_receipt(installer):
    result = run_worker(installer, hook=r'''
sha256sum() {
 /usr/bin/sha256sum "$@" || return
 if [ "${committed:-0}" = 1 ] && [ -n "${final_identity:-}" ] && [ "$1" = "$target" ]; then
  /usr/bin/mv "$target" "$target.displaced"
  /usr/bin/cp "$target.displaced" "$target"
 fi
}
''')
    assert result.returncode == 73, (result.stdout, result.stderr)
    target = installer.root / "system/lib64/libx2dii_menu.so"
    displaced = target.with_name(target.name + ".displaced")
    assert target.read_bytes() == displaced.read_bytes()
    assert target.stat().st_ino != displaced.stat().st_ino
    assert (installer.root / "proc/mounts").read_text() == installer.mount_line
    assert b"schema=x2dii-one-file-preplacement" not in result.stdout
