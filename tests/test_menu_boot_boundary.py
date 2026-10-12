"""Fixed boot action observations, distinct from payload placement boundaries."""
import os
import subprocess
from unittest import mock
import pytest

from tests.test_release_lifecycle import installer
from tests.test_menu_maintenance_boundary import context
from tests.test_menu_boot_file import recovery_data
from tools import prepare_peer_install as peer
from tools import session_context


@pytest.mark.parametrize("action,index,name", (
    ("activate", 9, "commit_rename"), ("restore", 5, "commit_rename"),
))
def test_boot_request_binds_exact_action_and_original_lease(installer, action, index, name):
    from tools import menu_boot_boundary as boundary
    raw = context(installer, session_kind="install")
    if action == "restore":
        raw = recovery_data(installer)
    values = session_context.decode_session(raw)
    request = boundary.make_request(installer.manifest, raw, action=action,
        worker_session_sha256=peer.sha(raw), worker_program_sha256="a" * 64,
        boundary_index=index, challenge="c" * 64, issued_epoch=values["observed_epoch"])
    result = boundary.decode_request(request)
    assert result["action"] == action
    assert result["boundary_name"] == name
    assert result["mount_access"] == "rw"
    assert "file_index" not in result
    assert result["deadline_epoch"] == values["observed_epoch"] + 600
    assert boundary.paths(installer.manifest, action, index, session_nonce=values["session_nonce"], session_data_sha256=peer.sha(raw))["request"].endswith(
        f"/.boot-{action}-{values['session_nonce']}-{index}.data")


def execute_boot_observer(installer, raw, request, *, action, index, hook="", staged_program=False):
    from tools import menu_boot_boundary as boundary
    values = session_context.decode_session(raw)
    fixed = boundary.paths(installer.manifest, action, index, session_nonce=values["session_nonce"], session_data_sha256=peer.sha(raw))
    program_path = installer.root / fixed["program"].lstrip("/")
    program = (program_path.read_bytes().decode("ascii") if staged_program else
               boundary.render_observer(installer.manifest, action=action))
    if not staged_program:
        program_path.parent.mkdir(parents=True, exist_ok=True)
    installer.scripts["boot_boundary"] = program
    os_hook = r'''
readlink() {
 if [ "$1" = "$fixture/proc/100/exe" ]; then echo /system/bin/camera-test
 else fixture_readlink "$@"; fi
}
cat() {
 if [ "$1" = "$fixture/proc/self/attr/current" ]; then echo u:r:hbl_camera_service:s0
 else /usr/bin/cat "$@"; fi
}
test_base_sha=$(declare -f sha256sum)
eval "${test_base_sha/sha256sum/test_base_sha256sum}"
sha256sum() {
 if [ "$#" = 1 ] && [ "$1" = "$fixtureTEST_PROGRAM" ]; then
  actual=$(/usr/bin/sha256sum "$1") || return
  if [ "${actual%% *}" = "$X2DII_TEST_HOST_PROGRAM_SHA" ]; then printf 'TEST_SHA  %s\n' "$1"
  else printf '%s\n' "$actual"; fi
 else test_base_sha256sum "$@"; fi
}
date() { echo TEST_EPOCH; }
mount() { echo forbidden-mount >&2; return 90; }
start() { echo forbidden-start >&2; return 90; }
stop() { echo forbidden-stop >&2; return 90; }
rm() { echo forbidden-rm >&2; return 90; }
mv() { echo forbidden-mv >&2; return 90; }
cp() { echo forbidden-cp >&2; return 90; }
chmod() { echo forbidden-chmod >&2; return 90; }
'''.replace("TEST_PROGRAM", fixed["program"]).replace("TEST_SHA", peer.sha(program.encode())).replace(
        "TEST_EPOCH", str(values["observed_epoch"]))
    actual_run = subprocess.run

    def run_file(args, **kwargs):
        if args[1] != "-s":
            return actual_run(args, **kwargs)
        source = kwargs.pop("input").decode("ascii").replace(
            'mb_file "$X2DII_SESSION_CORE_CAPTURE_EXE_TARGET"',
            'mb_file "$fixture$X2DII_SESSION_CORE_CAPTURE_EXE_TARGET"')
        expected = source.encode("ascii")
        original = None
        if staged_program:
            original = (program_path.stat().st_ino, program_path.stat().st_mtime_ns, program_path.read_bytes())
            host_path = installer.root / ".host-boot-observer.sh"
            host_path.write_bytes(expected)
        if not program_path.exists():
            program_path.write_bytes(expected)
        env = os.environ.copy()
        env["X2DII_TEST_HOST_PROGRAM_SHA"] = peer.sha(expected)
        command = [args[0], installer.posix + fixed["program"], peer.sha(raw), action, str(index), peer.sha(request)]
        if staged_program:
            command = [command[0], "-c", 'host_source=$1; shift; . "$host_source"', command[1],
                       installer.posix + "/.host-boot-observer.sh", *command[2:]]
        result = actual_run(command, env=env, **kwargs)
        if original is not None:
            assert (program_path.stat().st_ino, program_path.stat().st_mtime_ns, program_path.read_bytes()) == original
        return result

    with mock.patch.object(peer, "session_data", return_value=raw), mock.patch(
            "tests.test_peer_install.subprocess.run", side_effect=run_file):
        return installer.run_script("boot_boundary", boundary_hook=os_hook + hook)


@pytest.mark.parametrize("action", ("activate", "restore"))
@pytest.mark.parametrize("fault", (None, "slot_changed", "observer_changed"))
def test_real_boot_observer_matches_fixed_action_without_writes(installer, action, fault):
    from tools import menu_boot_boundary as boundary
    raw = context(installer, session_kind="install")
    if action == "restore":
        raw = recovery_data(installer)
        # Recovery remains available with a broken capture path and mapped GUI.
        (installer.root / "proc/345/attr/current").write_text("u:r:broken:s0\n")
        (installer.root / "proc/234/environ").write_bytes(b"LD_PRELOAD=broken\0")
    values = session_context.decode_session(raw)
    request = boundary.make_request(installer.manifest, raw, action=action,
        worker_session_sha256=peer.sha(raw), worker_program_sha256="a" * 64,
        boundary_index=0, challenge="c" * 64, issued_epoch=values["observed_epoch"])
    fixed = boundary.paths(installer.manifest, action, 0, session_nonce=values["session_nonce"], session_data_sha256=peer.sha(raw))
    (installer.root / fixed["session"].lstrip("/")).write_bytes(raw)
    (installer.root / fixed["request"].lstrip("/")).write_bytes(request)
    if fault == "slot_changed":
        hook = 'unrd() { echo 0; }\n'
    elif fault == "observer_changed":
        hook = 'printf "u:r:su:s0\\n" > "$fixture/proc/100/attr/current"\n'
    else:
        hook = ""
    result = execute_boot_observer(installer, raw, request, action=action, index=0, hook=hook)
    if fault:
        assert result.returncode == 35, (result.stdout, result.stderr)
        assert b"OBSERVED_MATCH" not in result.stdout
        return
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert boundary.decode_response(result.stdout, request, received_epoch=values["observed_epoch"])["action"] == action
    assert b"forbidden-" not in result.stderr
    assert not (installer.root / "operations").exists()


@pytest.mark.parametrize("action,index", (("activate", 12), ("restore", 8), ("restore", -1), ("other", 0)))
def test_unknown_boot_actions_and_boundaries_have_no_path(installer, action, index):
    from tools import menu_boot_boundary as boundary
    with pytest.raises(ValueError):
        boundary.paths(installer.manifest, action, index, session_nonce="b" * 32, session_data_sha256="a" * 64)


def test_boot_session_cannot_be_used_for_the_other_action(installer):
    from tools import menu_boot_boundary as boundary
    install = context(installer, session_kind="install")
    recovery = recovery_data(installer)
    for action, raw in (("activate", recovery), ("restore", install)):
        with pytest.raises(ValueError):
            boundary.make_request(installer.manifest, raw, action=action,
                worker_session_sha256=peer.sha(raw), worker_program_sha256="a" * 64,
                boundary_index=0, challenge="c" * 64,
                issued_epoch=session_context.decode_session(raw)["observed_epoch"])
