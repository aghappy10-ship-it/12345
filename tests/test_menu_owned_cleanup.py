"""Fixed four-file cleanup: local models never establish target visibility."""
import json
from io import BytesIO
import queue
import subprocess
import threading
import time
from pathlib import Path
from unittest import mock
from types import SimpleNamespace

import pytest

from tests.test_release_lifecycle import installer
from tests.test_menu_stock_boot import fixture_inputs, DeviceBoundary
from tools import prepare_peer_install as peer, session_context as sc
from tests.test_peer_install import SH


def cleanup_inputs(installer):
    from tools import menu_stock_boot as stock
    raw, previous, receipt, fresh, values = fixture_inputs(installer)
    observed = stock.observe_stock_boot(raw, peer.sha(raw), previous, receipt, fresh,
        DeviceBoundary(installer.manifest, values), clock=lambda: values["observed_epoch"])
    identities = tuple(f"1:{100 + index}:81a4:1:{item['bytes']}:0:0"
                       for index, item in enumerate(installer.manifest["candidate"]["files"]))
    return fresh, identities, observed, receipt


def test_cleanup_has_four_fixed_workers_and_one_readonly_observer(installer):
    from tools import menu_owned_cleanup as cleanup
    args = cleanup_inputs(installer)
    programs = cleanup.render_programs(installer.manifest, *args)
    assert len(programs) == 5
    for index in range(4):
        path = cleanup.worker_path(installer.manifest, args[0], index)
        source = programs[path].decode("ascii")
        assert "X2DII_CLEANUP_BOUNDARY_REQUEST:" in source
        assert "schema=x2dii-one-file-cleanup-v1" in source
        assert source.count('rm -- "$target"') == 1
        assert "start camera" not in source and "stop camera" not in source
    observer = programs[cleanup.observer_path(installer.manifest, args[0])].decode("ascii")
    assert "mc_all_maps" in observer and "UNKNOWN_RETAIN_FILES" in observer
    assert "rm --" not in observer and "mount -o" not in observer


def test_cleanup_does_not_depend_on_unavailable_host_only_awk(installer):
    from tools import menu_owned_cleanup as cleanup
    args = cleanup_inputs(installer)
    programs = cleanup.render_programs(installer.manifest, *args)
    # An awk/gawk/busybox applet was not established in the pinned root/toybox.
    # Host availability must not silently become a target prerequisite.
    assert all(b"awk" not in source and b"busybox" not in source for source in programs.values())


@pytest.mark.parametrize("fault", ("old_boot", "old_session", "unknown_stock", "wrong_receipt",
                                  "replacement_identity", "missing_identity"))
def test_cleanup_rejects_missing_or_misattributed_bound_inputs(installer, fault):
    from tools import menu_owned_cleanup as cleanup
    raw, ids, observed, receipt = cleanup_inputs(installer)
    if fault == "old_boot":
        observed["previous_boot_id"] = observed["boot_id"]
    elif fault == "old_session":
        observed["session_data_sha256"] = "e" * 64
    elif fault == "unknown_stock":
        observed["status"] = "UNKNOWN_RETAIN_FILES"
    elif fault == "wrong_receipt":
        receipt["identity"] = "1:9:81a4:1:5:0:0"
    elif fault == "replacement_identity":
        ids = (*ids[:3], ids[3].replace(":81a4:", ":a1ff:"))
    else:
        ids = ids[:3]
    with pytest.raises(ValueError):
        cleanup.CleanupCoordinator(installer.manifest, raw, ids, observed, receipt)


def test_coordinator_uses_cleanup_only_schemas_and_single_use_boundary_ack(installer):
    from tools import menu_owned_cleanup as cleanup
    raw, ids, observed, receipt = cleanup_inputs(installer)
    c = cleanup.CleanupCoordinator(installer.manifest, raw, ids, observed, receipt)
    epoch = sc.decode_session(raw)["observed_epoch"]
    request = c.expected_request(issued_epoch=epoch)
    values = cleanup.decode_request(request)
    assert values["schema"] == cleanup.REQUEST_SCHEMA
    assert values["boundary_name"] == "remount_rw"
    command = c.begin_boundary(f"X2DII_HOST_CLEANUP_BOUNDARY:0:0:{peer.sha(request)}")
    from tools.stage_peer_usb_access import envelope
    envelope(command, "123456abcdef")
    response = dict(values, schema=cleanup.RESPONSE_SCHEMA, request_sha256=peer.sha(request),
        started_epoch=epoch, checked_epoch=epoch, result="OBSERVED_MATCH", scope=cleanup.SCOPE)
    reply = cleanup.encode_response(response)
    assert c.accept_reply(reply, received_epoch=epoch).startswith(b"X2DII_CLEANUP_BOUNDARY_ACK:")
    assert c.next_boundary == (0, 1)
    with pytest.raises(ValueError):
        c.accept_reply(reply, received_epoch=epoch)


def shell_fixture(installer):
    from tools import menu_owned_cleanup as cleanup, menu_maintenance_boundary as boundary
    installer.shell_fixture()
    raw, ids, observed, receipt = cleanup_inputs(installer)
    values = sc.decode_session(raw)
    identities = []

    def identity(path):
        result = subprocess.run([str(SH), "-c", '/usr/bin/stat -c "%d:%i:%f:%h:%s:%u:%g" "$1"',
            "fixture", installer.posix + "/" + path.relative_to(installer.root).as_posix()],
            capture_output=True, text=True, check=True)
        fields = result.stdout.strip().split(":")
        return ":".join((*fields[:2], "81a4", *fields[3:5], "0", "0"))

    for item in installer.manifest["candidate"]["files"]:
        target = installer.root / item["target"].lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((peer.ROOT / item["source"]).read_bytes())
        identities.append(identity(target))
    receipt["identity"] = identity(installer.root / "system/etc/init/camera-gui.rc")
    observed["restore_receipt_sha256"] = peer.sha(json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode())
    ids = tuple(identities)
    (installer.root / "proc/sys/kernel/random/boot_id").write_text(values["boot_id"] + "\n")
    (installer.root / "proc/100/attr/current").write_text("u:r:hbl_camera_service:s0\n")
    (installer.root / "proc/1").mkdir(exist_ok=True)
    for proc in (installer.root / "proc").iterdir():
        if not proc.name.isdigit():
            continue
        if not (proc / "stat").exists():
            (proc / "stat").write_text(proc.name + " (init) S " + "0 " * 18 + "456 0\n")
        (proc / "maps").write_bytes(b"1000-2000 r-xp 00000000 08:01 19 /system/bin/original\n")
    (installer.root / "proc/234/stat").write_text("234 (camera-gui) S " + "0 " * 18 + "4567 0\n")
    (installer.root / "proc/234/environ").write_bytes(b"XDG_RUNTIME_DIR=/tmp\0")
    (installer.root / "proc/mounts").write_text(installer.mount_line + f"proc {installer.posix}/proc proc rw,nosuid,nodev,noexec 0 0\n")
    session_path = installer.root / boundary.session_path(installer.manifest, peer.sha(raw)).lstrip("/")
    session_path.write_bytes(raw)
    programs = cleanup.render_programs(installer.manifest, raw, ids, observed, receipt)
    for path, source in programs.items():
        target = installer.root / path.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source)
    return raw, ids, observed, receipt, programs


def os_hook(installer, values, *, observer, hook=""):
    return r'''
fixture_stat() {
 if [ "$2" = '%u %g %a %h' ]; then echo '0 0 644 1'
 elif [ "$2" = '%u:%g:%a' ] || [ "$2" = '%u %g %a' ]; then
  if [ -d "$3" ]; then observed_meta='0:0:700'
  else case "$3" in */cleanup-*.sh|*/.cleanup-*.data|*/session-context*.data|*/o) observed_meta='0:0:600';;
   *) observed_meta='0:0:644';; esac; fi
  if [ "$2" = '%u %g %a' ]; then printf '%s\n' "$observed_meta" | /usr/bin/tr : ' '
  else printf '%s\n' "$observed_meta"; fi
 elif [ "$2" = '%d:%i:%f:%h:%s:%u:%g' ]; then
  if [ "$#" = 3 ] && [ "$1" = -c ]; then
   case "$3" in
    -*) ;;
    *) /usr/bin/stat -c '%d:%i:81a4:%h:%s:0:0' "$3"
       return $?;;
   esac
  fi
  v=$(/usr/bin/stat "$@") || return
  saved_ifs=$IFS; IFS=:; set -- $v; IFS=$saved_ifs
  printf '%s:%s:81a4:%s:%s:0:0\n' "$1" "$2" "$4" "$5"
 else /usr/bin/stat "$@"; fi
}
stat() { fixture_stat "$@"; }
readlink() {
 case "$1" in
  "$fixture/proc/100/exe") echo /system/bin/camera-test;;
  "$fixture/proc/self/ns/pid"|"$fixture/proc/1/ns/pid") echo 'pid:[4026531836]';;
  *) fixture_readlink "$@";;
 esac
}
cat() {
 if [ "$1" = "$fixture/proc/self/attr/current" ]; then echo TEST_DOMAIN
 else /usr/bin/cat "$@"; fi
}
date() { echo TEST_EPOCH; }
awk() { echo forbidden-host-awk >&2; return 90; }
gawk() { echo forbidden-host-gawk >&2; return 90; }
busybox() { echo forbidden-host-busybox >&2; return 90; }
toybox() {
 case "$1" in
  od|wc) applet=$1; shift; /usr/bin/"$applet" "$@"; return;;
  getfattr) ;; *) return 90;;
 esac
 shift
 if [ "$1" = -d ]; then printf '# file: %s\nsecurity.selinux="u:object_r:system_file:s0"\n' "$2"
 else printf '# file: %s\nsecurity.selinux\n' "$1"; fi
}
mount() {
 printf 'mount:%s\n' "$*" >> "$fixture/cleanup-operations"
 case "$2" in remount,rw) access=rw;; remount,ro) access=ro;; *) return 90;; esac
 printf '/dev/block/current-attested-slot %s/system ext4 %s,seclabel,relatime 0 0\nproc %s/proc proc rw,nosuid,nodev,noexec 0 0\n' "$fixture" "$access" "$fixture" > "$fixture/proc/mounts"
}
rm() { printf 'rm:%s\n' "$*" >> "$fixture/cleanup-operations"; /usr/bin/rm "$@"; }
start() { echo forbidden-start >&2; return 90; }
stop() { echo forbidden-stop >&2; return 90; }
chcon() { echo forbidden-chcon >&2; return 90; }
'''.replace("TEST_DOMAIN", "u:r:hbl_camera_service:s0" if observer else "u:r:su:s0").replace(
        "TEST_EPOCH", str(values["observed_epoch"])) + (
        "\nmount() { echo forbidden-mount >&2; return 90; }\nrm() { echo forbidden-rm >&2; return 90; }\n"
        if observer else "") + hook


def run_staged(installer, raw, path, *, observer, arguments, hook="", runner=None,
               host_wait_seconds=None, observer_wait_seconds=None):
    if host_wait_seconds is not None and (observer is not False or
            type(host_wait_seconds) is not int or host_wait_seconds not in (30, 60)):
        raise ValueError("host cleanup wait requires a worker and an approved budget")
    if observer_wait_seconds is not None and (observer is not True or runner is not None or
            type(observer_wait_seconds) is not int or observer_wait_seconds not in (30, 60)):
        raise ValueError("host cleanup wait requires a synchronous observer and an approved budget")
    source_file = installer.root / path.lstrip("/")
    original = (source_file.stat().st_ino, source_file.stat().st_mtime_ns, source_file.read_bytes())
    installer.scripts["cleanup-test"] = original[2].decode("ascii")

    def execute(source, unused):
        # The target's explicit toybox applet is represented by one OS fixture
        # function, not by changing the generated metadata policy.
        source = source.replace(installer.posix + "/system/bin/toybox", "toybox")
        if host_wait_seconds is not None:
            # Windows launches every modeled tool as a host process. This
            # explicit OS timing adapter exercises logic, NOT the device's
            # unchanged 8-second ACK or 80-second USB-window qualification.
            assert source.count("IFS= read -r -t 8 ack") == 1
            source = source.replace("IFS= read -r -t 8 ack", f"IFS= read -r -t {host_wait_seconds} ack", 1)
        host_path = installer.root / (".host-cleanup-observer.sh" if observer else ".host-cleanup-worker.sh")
        host_path.write_text(source, encoding="ascii", newline="\n")
        command = [str(SH), "-c", 'host_source=$1; shift; . "$host_source"', installer.posix + path,
            installer.posix + "/" + host_path.name, *arguments]
        return runner(command) if runner else subprocess.run(command, capture_output=True,
            timeout=30 if observer_wait_seconds is None else observer_wait_seconds)

    with mock.patch.object(peer, "session_data", return_value=raw):
        result = installer.run_script("cleanup-test", boundary_hook=os_hook(installer, sc.decode_session(raw),
            observer=observer, hook=hook), process_runner=execute)
    assert (source_file.stat().st_ino, source_file.stat().st_mtime_ns, source_file.read_bytes()) == original
    return result


def test_real_observer_complete_maps_and_exact_stock_rc_are_readonly(installer):
    from tools import menu_owned_cleanup as cleanup
    raw, ids, observed, receipt, programs = shell_fixture(installer)
    c = cleanup.CleanupCoordinator(installer.manifest, raw, ids, observed, receipt)
    epoch = c.context["observed_epoch"]
    request = c.expected_request(issued_epoch=epoch)
    request_path = installer.root / cleanup.request_path(installer.manifest, raw, 0, 0).lstrip("/")
    request_path.write_bytes(request)
    c.begin_boundary(f"X2DII_HOST_CLEANUP_BOUNDARY:0:0:{peer.sha(request)}")
    result = run_staged(installer, raw, cleanup.observer_path(installer.manifest, raw), observer=True,
        arguments=[peer.sha(raw), "0", "0", peer.sha(request)])
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert c.accept_reply(result.stdout, received_epoch=epoch).startswith(b"X2DII_CLEANUP_BOUNDARY_ACK:")
    assert not (installer.root / "cleanup-operations").exists()


@pytest.mark.parametrize("fault", ("map_denied", "missing_map", "map_incomplete", "map_bad_row", "map_nul",
    "mapping_present", "renamed_inode_mapping", "pid_change", "rc_replacement", "hidepid",
    "current_extension_env", "current_incomplete_env"))
def test_real_observer_incomplete_or_changed_coverage_never_releases_cleanup(installer, fault):
    from tools import menu_owned_cleanup as cleanup
    raw, ids, observed, receipt, programs = shell_fixture(installer)
    c = cleanup.CleanupCoordinator(installer.manifest, raw, ids, observed, receipt)
    request = c.expected_request(issued_epoch=c.context["observed_epoch"])
    (installer.root / cleanup.request_path(installer.manifest, raw, 0, 0).lstrip("/")).write_bytes(request)
    hook = ""
    maps = installer.root / "proc/100/maps"
    if fault == "map_denied":
        hook = '''cat() { case "$1" in */100/maps) return 13;; */self/attr/current) echo u:r:hbl_camera_service:s0;; *) /usr/bin/cat "$@";; esac; }\n'''
    elif fault == "missing_map":
        maps.rename(maps.with_name("maps-retained"))
    elif fault == "map_incomplete":
        maps.write_bytes(b"1000-2000 r-xp 0 08:01 99 /system/bin/original")
    elif fault == "map_bad_row":
        maps.write_bytes(b"incomplete\n")
    elif fault == "map_nul":
        maps.write_bytes(b"1000-2000 r-xp 00000000 08:01 19 /system/bin/orig\0inal\n")
    elif fault == "mapping_present":
        maps.write_bytes(b"1000-2000 r-xp 0 08:01 99 /system/lib64/libx2dii_menu.so\n")
    elif fault == "renamed_inode_mapping":
        maps.write_bytes(f"1000-2000 r-xp 0 08:01 {ids[0].split(':')[1]} /system/lib64/unknown.so\n".encode())
    elif fault == "pid_change":
        hook = '''cat() { case "$1" in */100/maps) /usr/bin/cat "$@"; printf '100 (reused) S %s 6789 0\\n' '0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0' > "$fixture/proc/100/stat";; */self/attr/current) echo u:r:hbl_camera_service:s0;; *) /usr/bin/cat "$@";; esac; }\n'''
    elif fault == "rc_replacement":
        rc = installer.root / "system/etc/init/camera-gui.rc"
        original = rc.read_bytes()
        rc.rename(rc.with_name("camera-gui.rc-retained"))
        rc.write_bytes(original)
    elif fault == "current_extension_env":
        (installer.root / "proc/234/environ").write_bytes(b"XDG_RUNTIME_DIR=/tmp\0LD_PRELOAD=/system/lib64/libx2dii_menu.so\0")
    elif fault == "current_incomplete_env":
        (installer.root / "proc/234/environ").write_bytes(b"XDG_RUNTIME_DIR=/tmp")
    else:
        mount = installer.root / "proc/mounts"
        mount.write_text(mount.read_text().replace("rw,nosuid", "rw,hidepid=2,nosuid"))
    result = run_staged(installer, raw, cleanup.observer_path(installer.manifest, raw), observer=True,
        arguments=[peer.sha(raw), "0", "0", peer.sha(request)], hook=hook)
    assert result.returncode != 0, (fault, result.stdout, result.stderr)
    assert b"result=OBSERVED_MATCH" not in result.stdout
    assert not (installer.root / "cleanup-operations").exists()


@pytest.mark.parametrize("fault", ("replacement_at_ack", "wrong_mode", "unknown_label", "extra_xattr", "lost_ack", "unresponsive"))
def test_worker_never_unlinks_unknown_metadata_or_replacement_and_recovers_mount(installer, fault):
    from tools import menu_owned_cleanup as cleanup, menu_maintenance_boundary as boundary
    raw, ids, observed, receipt, programs = shell_fixture(installer)
    epoch = sc.decode_session(raw)["observed_epoch"]
    item = installer.manifest["candidate"]["files"][0]
    target = installer.root / item["target"].lstrip("/")
    original = target.read_bytes()
    hook = ""
    if fault == "wrong_mode":
        hook = '''saved_stat=$(declare -f stat); eval "${saved_stat/stat/previous_stat}"; stat() { if [ "$2" = '%d:%i:%f:%h:%s:%u:%g' ] && [ "$3" = "$fixture/system/lib64/libx2dii_menu.so" ]; then previous_stat "$@" | /usr/bin/sed 's/:81a4:/:8180:/' ; else previous_stat "$@"; fi; }\n'''
    elif fault == "unknown_label":
        hook = '''ls() { printf 'u:object_r:unknown:s0 %s\\n' "$2"; }\n'''
    elif fault == "extra_xattr":
        hook = '''toybox() { [ "$1" = getfattr ] || return 90; shift; if [ "$1" = -d ]; then printf '# file: %s\\nsecurity.selinux="u:object_r:system_file:s0"\\n' "$2"; else printf '# file: %s\\nsecurity.selinux\\nuser.unknown\\n' "$1"; fi; }\n'''

    def dialogue(command):
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = bytearray()
        try:
            for line in iter(process.stdout.readline, b""):
                output.extend(line)
                if not line.startswith(b"X2DII_CLEANUP_BOUNDARY_REQUEST:"):
                    continue
                pieces = line.decode().strip().split(":")
                if fault == "lost_ack":
                    process.stdin.close()
                    continue
                if fault == "unresponsive":
                    # Keep the host pipe open: the unchanged production read
                    # must time out after eight seconds without removing data.
                    continue
                if fault == "replacement_at_ack" and pieces[2] == "1":
                    target.rename(target.with_name(target.name + ".retained-original"))
                    target.write_bytes(original)
                # Worker-only fault injection. These synthetic ACKs are not
                # actual maintenance observations or execution qualification.
                process.stdin.write(f"X2DII_CLEANUP_BOUNDARY_ACK:{pieces[3]}:{epoch}:{epoch}\n".encode())
                process.stdin.flush()
            process.wait(timeout=10)
            return subprocess.CompletedProcess(command, process.returncode, bytes(output), process.stderr.read())
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)

    result = run_staged(installer, raw, cleanup.worker_path(installer.manifest, raw, 0), observer=False,
        arguments=[installer.posix + boundary.session_path(installer.manifest, peer.sha(raw)), peer.sha(raw)],
        runner=dialogue, hook=hook)
    assert result.returncode != 0, (fault, result.stdout, result.stderr)
    assert target.read_bytes() == original
    operations = installer.root / "cleanup-operations"
    assert not operations.exists() or "rm:" not in operations.read_text()
    assert " ext4 ro," in (installer.root / "proc/mounts").read_text()


def run_four_file_dialogue(installer, raw, ids, observed, receipt, *, host_wait_seconds=60):
    # Approved host-only normal withdrawal waits. Standalone/fault calls retain
    # run_staged's30-second default and the generated target's8-second ACK.
    if type(host_wait_seconds) is not int or host_wait_seconds not in (30, 60):
        raise ValueError("host cleanup wait requires an approved normal budget")
    from tools import menu_owned_cleanup as cleanup, menu_maintenance_boundary as boundary
    c = cleanup.CleanupCoordinator(installer.manifest, raw, ids, observed, receipt)
    epoch = c.context["observed_epoch"]
    staged = {path: (installer.root / path.lstrip("/")).read_bytes() for path in c.programs}
    assert staged == c.programs, "execute the original staged source, never regenerate it"

    for file_index in range(4):
        def dialogue(command):
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            lines = queue.Queue()
            def receive():
                for line in iter(process.stdout.readline, b""):
                    lines.put(line)
                lines.put(None)
            thread = threading.Thread(target=receive, daemon=True)
            thread.start()
            output = bytearray()
            try:
                while True:
                    line = lines.get(timeout=35)
                    if line is None:
                        break
                    output.extend(line)
                    if not line.startswith(b"X2DII_CLEANUP_BOUNDARY_REQUEST:"):
                        continue
                    pieces = line.decode().strip().split(":")
                    index = int(pieces[2])
                    c.begin_boundary(f"X2DII_HOST_CLEANUP_BOUNDARY:{file_index}:{index}:{pieces[3]}")
                    observation_started = time.monotonic()
                    response = run_staged(installer, raw, cleanup.observer_path(installer.manifest, raw),
                        observer=True, arguments=[peer.sha(raw), str(file_index), str(index), pieces[3]],
                        observer_wait_seconds=host_wait_seconds)
                    assert response.returncode == 0, (response.stdout, response.stderr)
                    try:
                        process.stdin.write(c.accept_reply(response.stdout, received_epoch=epoch))
                        process.stdin.flush()
                    except OSError as error:
                        raise AssertionError((file_index, index, "host observer seconds",
                            time.monotonic() - observation_started, "worker status", process.poll(),
                            process.stderr.read())) from error
                process.wait(timeout=10)
                return subprocess.CompletedProcess(command, process.returncode, bytes(output), process.stderr.read())
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=10)
                thread.join(timeout=5)
        result = run_staged(installer, raw, cleanup.worker_path(installer.manifest, raw, file_index),
            observer=False, arguments=[installer.posix + boundary.session_path(installer.manifest, peer.sha(raw)),
                                       peer.sha(raw)], runner=dialogue, host_wait_seconds=host_wait_seconds)
        assert result.returncode == 0, (result.stdout, result.stderr)
        completed = result.stdout + f"\nX2DII_CLEANUP_WORKER_{peer.sha(raw)[:24]}_{file_index}_RC=0\n".encode()
        c.finish_file(file_index=file_index, decoded_output=completed, stream_completed=True)
    assert len(c.completed_receipts) == 4
    assert all(not (installer.root / item["target"].lstrip("/")).exists() for item in installer.manifest["candidate"]["files"])
    assert (installer.root / "system/etc/init/camera-gui.rc").read_bytes() == peer.boot.STOCK.read_bytes()
    assert all((installer.root / path.lstrip("/")).read_bytes() == source for path, source in staged.items())
    return c.completed_receipts


def test_real_worker_and_observer_remove_only_four_exact_owned_files(installer):
    raw, ids, observed, receipt, programs = shell_fixture(installer)
    run_four_file_dialogue(installer, raw, ids, observed, receipt)


@pytest.fixture
def cleanup_budget_inputs(installer):
    """Real staged bytes; budget controls below do not execute device logic."""
    from tools import menu_owned_cleanup as cleanup
    installer.shell_fixture()
    args = cleanup_inputs(installer)
    for path, source in cleanup.render_programs(installer.manifest, *args).items():
        target = installer.root / path.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source)
    return installer, args


@pytest.mark.parametrize("wait", (None, 30, 60))
@pytest.mark.parametrize("observer", (True, False))
def test_cleanup_host_wait_is_role_scoped_and_preserves_target_bytes(cleanup_budget_inputs, observer, wait):
    from tools import menu_owned_cleanup as cleanup
    fixture, args = cleanup_budget_inputs
    path = (cleanup.observer_path(fixture.manifest, args[0]) if observer else
            cleanup.worker_path(fixture.manifest, args[0], 0))
    staged = fixture.root / path.lstrip("/")
    before = (staged.stat().st_ino, staged.stat().st_mtime_ns, staged.read_bytes())
    options = ({"observer_wait_seconds": wait} if observer else {"host_wait_seconds": wait})
    reply = subprocess.CompletedProcess([], 0, b"budget control only\n", b"")
    with mock.patch.object(subprocess, "run", return_value=reply) as process:
        assert run_staged(fixture, args[0], path, observer=observer, arguments=[], **options) is reply
    process.assert_called_once()
    assert process.call_args.kwargs["timeout"] == ((wait or 30) if observer else 30)
    host = (fixture.root / (".host-cleanup-observer.sh" if observer else ".host-cleanup-worker.sh")).read_bytes()
    if not observer:
        assert host.count(f"IFS= read -r -t {wait or 8} ack".encode()) == 1
        assert b'[ "$((received-issued))" -le 8 ]' in host
    assert (staged.stat().st_ino, staged.stat().st_mtime_ns, staged.read_bytes()) == before


@pytest.mark.parametrize("observer,options", (
    (True, {"host_wait_seconds": 60}), (False, {"observer_wait_seconds": 60}),
    (True, {"host_wait_seconds": 30, "observer_wait_seconds": 60}),
    (True, {"observer_wait_seconds": 60, "runner": lambda unused: None}),
    (True, {"observer_wait_seconds": 8}), (True, {"observer_wait_seconds": 31}),
    (True, {"observer_wait_seconds": 61}), (True, {"observer_wait_seconds": 240}),
    (False, {"host_wait_seconds": 8}), (False, {"host_wait_seconds": 31}),
    (False, {"host_wait_seconds": 61}), (False, {"host_wait_seconds": 240}),
    (False, {"host_wait_seconds": 30.0}),
))
def test_cleanup_invalid_host_wait_refuses_before_copy_or_spawn(cleanup_budget_inputs, observer, options):
    fixture, args = cleanup_budget_inputs
    with mock.patch.object(subprocess, "run") as process:
        with pytest.raises(ValueError, match="host cleanup wait"):
            run_staged(fixture, args[0], "/unused-staged-path", observer=observer, arguments=[], **options)
    process.assert_not_called()
    assert not list(fixture.root.glob(".host-cleanup-*.sh"))


@pytest.mark.parametrize("anchor_count", (0, 2))
def test_cleanup_host_ack_projection_requires_one_anchor(cleanup_budget_inputs, anchor_count):
    from tools import menu_owned_cleanup as cleanup
    fixture, args = cleanup_budget_inputs
    path = cleanup.worker_path(fixture.manifest, args[0], 0)
    staged = fixture.root / path.lstrip("/")
    staged.write_bytes(staged.read_bytes().replace(b"IFS= read -r -t 8 ack", b"IFS= read -r -t 8 ack" * anchor_count))
    before = staged.read_bytes()
    with mock.patch.object(subprocess, "run") as process:
        with pytest.raises(AssertionError):
            run_staged(fixture, args[0], path, observer=False, arguments=[], host_wait_seconds=60)
    process.assert_not_called()
    assert staged.read_bytes() == before and not (fixture.root / ".host-cleanup-worker.sh").exists()


@pytest.mark.parametrize("wait", (None, 30, 60))
def test_cleanup_observer_timeout_is_original_single_attempt(cleanup_budget_inputs, wait):
    from tools import menu_owned_cleanup as cleanup
    fixture, args = cleanup_budget_inputs
    failure = subprocess.TimeoutExpired(["host control"], wait or 30, output=b"partial\n", stderr=b"error\n")
    with mock.patch.object(subprocess, "run", side_effect=failure) as process:
        with pytest.raises(subprocess.TimeoutExpired) as caught:
            run_staged(fixture, args[0], cleanup.observer_path(fixture.manifest, args[0]),
                       observer=True, arguments=[], observer_wait_seconds=wait)
    assert caught.value is failure
    process.assert_called_once()
    assert process.call_args.kwargs["timeout"] == (wait or 30)
    assert (caught.value.output, caught.value.stderr) == (b"partial\n", b"error\n")


@pytest.mark.parametrize("wait,expected", ((None, 60), (30, 30), (60, 60)))
def test_public_four_file_helper_pairs_only_normal_observer_and_ack(cleanup_budget_inputs, wait, expected):
    from tools import menu_owned_cleanup as cleanup
    fixture, args = cleanup_budget_inputs
    c = cleanup.CleanupCoordinator(fixture.manifest, *args)
    request = c.expected_request(issued_epoch=c.context["observed_epoch"])
    process = SimpleNamespace(stdout=BytesIO(f"X2DII_CLEANUP_BOUNDARY_REQUEST:0:0:{peer.sha(request)}\n".encode()),
        stderr=BytesIO(), stdin=BytesIO(), poll=lambda: 0, wait=lambda **unused: 0, returncode=0)
    calls = []
    class BudgetReached(Exception):
        pass
    def capture(installer, raw, path, **options):
        calls.append(options)
        if options["observer"]:
            raise BudgetReached
        return options["runner"](["modeled worker; no process start"])
    options = {} if wait is None else {"host_wait_seconds": wait}
    with mock.patch(__name__ + ".run_staged", side_effect=capture), mock.patch.object(subprocess, "Popen", return_value=process):
        with pytest.raises(BudgetReached):
            run_four_file_dialogue(fixture, *args, **options)
    assert len(calls) == 2
    assert calls[0]["observer"] is False and calls[0]["host_wait_seconds"] == expected
    assert calls[1]["observer"] is True and calls[1].get("observer_wait_seconds") == expected
