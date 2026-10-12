"""Execute rendered phases against host files with substituted device identity.

The agreed seam is the existing shell/filesystem harness, not camera execution.
Time, credentials, namespaces, services and mount operations are substitutes.
"""
from copy import deepcopy
from datetime import datetime, timedelta

import pytest


PHASES = ("install-files.sh", "activate-boot.sh", "restore-boot.sh")


@pytest.fixture
def phase_fixture(request):
    from tests.test_peer_install import PeerInstallTests
    PeerInstallTests.setUpClass()
    fixture = PeerInstallTests()
    fixture.setUp()
    try:
        fixture.shell_fixture()
        for prior in PHASES:
            if prior == request.param:
                break
            result = fixture.run_script(prior)
            assert result.returncode == 0, result.stderr
        yield fixture, request.param
    finally:
        fixture.tearDown()


def observed_state(fixture):
    operations = fixture.root / "operations"
    files = {str(path.relative_to(fixture.root)): path.read_bytes()
             for directory in ("system", "blackbox")
             for path in (fixture.root / directory).rglob("*") if path.is_file()}
    return files, operations.read_bytes() if operations.exists() else b""


@pytest.mark.parametrize("phase_fixture", PHASES, indirect=True)
def test_rendered_phase_expires_before_stop_mount_or_write(phase_fixture):
    fixture, phase = phase_fixture
    before = observed_state(fixture)
    expired = int(datetime.fromisoformat(fixture.q["observed_utc"]).timestamp()) + 601
    fixture.scripts[phase] = f"date() {{ printf '{expired}\\n'; }}\n" + fixture.scripts[phase]
    result = fixture.run_script(phase)
    assert result.returncode != 0, result.stdout
    assert observed_state(fixture) == before
    assert not (fixture.root / "tmp/x2dii-menu-install.lock").exists()


@pytest.mark.parametrize("phase_fixture", PHASES, indirect=True)
@pytest.mark.parametrize("clock_case", ("future_observation", "malformed_epoch"))
def test_runtime_clock_rejected_before_lock_stop_mount_or_write(phase_fixture, clock_case):
    fixture, phase = phase_fixture
    before = observed_state(fixture)
    observed = int(datetime.fromisoformat(fixture.q["observed_utc"]).timestamp())
    target_now = str(observed - 1) if clock_case == "future_observation" else "not-an-epoch"
    hook = f'''
boundary() {{ [ "$1" != lock ] || printf acquired > "$fixture/identity-lock-created"; }}
date() {{ printf '%s\\n' '{target_now}'; }}
'''
    result = fixture.run_script(phase, boundary_hook=hook)
    assert result.returncode == 32, (result.stdout, result.stderr)
    assert observed_state(fixture) == before
    assert (fixture.root / "proc/mounts").read_text() == fixture.mount_line
    assert not (fixture.root / "identity-lock-created").exists()
    assert not (fixture.root / "tmp/x2dii-menu-install.lock").exists()
    assert b"X2DII_" not in result.stdout


@pytest.mark.parametrize("phase_fixture", PHASES, indirect=True)
@pytest.mark.parametrize("identity_case", ("boot_id", "observer_exe_path", "observer_exe_hash"))
def test_boot_or_observer_executable_drift_rejected_before_lock_stop_mount_or_write(phase_fixture, identity_case):
    fixture, phase = phase_fixture
    before = observed_state(fixture)
    hook = '''
boundary() { [ "$1" != lock ] || printf acquired > "$fixture/identity-lock-created"; }
'''
    if identity_case == "boot_id":
        (fixture.root / "proc/sys/kernel/random/boot_id").write_text(
            "99999999-9999-4999-8999-999999999999\n")
    elif identity_case == "observer_exe_path":
        hook += '''
readlink() {
 case "$1" in
  */ns/mnt) echo 'mnt:[4026531840]';;
  */100/exe) echo "$fixture/system/bin/replaced-adbd";;
  *) fixture_readlink "$@";;
 esac
}
'''
    else:
        (fixture.root / "proc/100/exe").write_bytes(b"changed observer executable")
    result = fixture.run_script(phase, boundary_hook=hook)
    assert result.returncode == 32, (result.stdout, result.stderr)
    assert observed_state(fixture) == before
    assert (fixture.root / "proc/mounts").read_text() == fixture.mount_line
    assert not (fixture.root / "identity-lock-created").exists()
    assert not (fixture.root / "tmp/x2dii-menu-install.lock").exists()
    assert b"X2DII_" not in result.stdout


@pytest.mark.parametrize("phase_fixture", PHASES, indirect=True)
@pytest.mark.parametrize("mode", ("wrong_namespace", "observer_reused_midquery"))
def test_runtime_namespace_or_reused_observer_refused_before_stop_mount_or_write(phase_fixture, mode):
    fixture, phase = phase_fixture
    before = observed_state(fixture)
    result = fixture.run_script(phase, mode=mode)
    assert result.returncode != 0, result.stdout
    assert observed_state(fixture) == before
    assert not (fixture.root / "tmp/x2dii-menu-install.lock").exists()


@pytest.mark.parametrize("phase_fixture", PHASES, indirect=True)
@pytest.mark.parametrize("boundary", ("lock", "stop", "remount"))
def test_expiry_at_phase_boundary_prevents_next_disruptive_operation(phase_fixture, boundary):
    fixture, phase = phase_fixture
    files_before, operations_before = observed_state(fixture)
    observed = int(datetime.fromisoformat(fixture.q["observed_utc"]).timestamp())
    hook = f'''
boundary() {{ [ "$1" != {boundary} ] || printf expired > "$fixture/identity-drift"; }}
date() {{ if [ -f "$fixture/identity-drift" ]; then echo {observed + 601}; else echo {observed}; fi; }}
'''
    result = fixture.run_script(phase, boundary_hook=hook)
    assert result.returncode != 0, result.stdout
    files_after, operations_after = observed_state(fixture)
    assert files_after == files_before
    suffix = operations_after[len(operations_before):].decode().splitlines()
    expected = [] if boundary == "lock" else ["stop:camera-gui"]
    if boundary == "remount":
        expected += ["mount:-o remount,rw " + fixture.posix + "/system",
                     "mount:-o remount,ro " + fixture.posix + "/system"]
    assert suffix == expected
    assert (fixture.root / "proc/mounts").read_text() == fixture.mount_line
    assert not (fixture.root / "tmp/x2dii-menu-install.lock").exists()


@pytest.mark.parametrize("phase_fixture", PHASES, indirect=True)
def test_observer_lifetime_drift_after_lock_prevents_stop(phase_fixture):
    fixture, phase = phase_fixture
    before = observed_state(fixture)
    hook = '''
boundary() {
 if [ "$1" = lock ]; then
  printf '100 (adbd) S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 99999 0\n' > "$fixture/proc/100/stat"
 fi
}
'''
    result = fixture.run_script(phase, boundary_hook=hook)
    assert result.returncode != 0, result.stdout
    assert observed_state(fixture) == before
    assert not (fixture.root / "tmp/x2dii-menu-install.lock").exists()


@pytest.mark.parametrize("phase_fixture", PHASES, indirect=True)
def test_namespace_drift_after_remount_preserves_files_and_does_not_clean_wrong_runtime(phase_fixture):
    fixture, phase = phase_fixture
    files_before, operations_before = observed_state(fixture)
    hook = '''
boundary() { [ "$1" != remount ] || printf changed > "$fixture/identity-drift"; }
readlink() {
 case "$1" in
  */ns/mnt) if [ -f "$fixture/identity-drift" ]; then echo 'mnt:[9]'; else echo 'mnt:[4026531840]'; fi;;
  */100/exe) echo /system/bin/adbd;;
  *) fixture_readlink "$@";;
 esac
}
'''
    result = fixture.run_script(phase, boundary_hook=hook)
    assert result.returncode == 72, result.stderr
    files_after, operations_after = observed_state(fixture)
    assert files_after == files_before
    assert operations_after[len(operations_before):].decode().splitlines() == [
        "stop:camera-gui", "mount:-o remount,rw " + fixture.posix + "/system"]
    assert (fixture.root / "tmp/x2dii-menu-install.lock").is_dir()
    assert b"X2DII_SCRIPT_FAILED:72" in result.stderr
    assert b"INSTALLED" not in result.stdout and b"RESTORED" not in result.stdout


@pytest.mark.parametrize("phase_fixture", PHASES, indirect=True)
def test_mount_drift_after_stop_is_refused_before_remount(phase_fixture):
    fixture, phase = phase_fixture
    files_before, operations_before = observed_state(fixture)
    hook = '''
boundary() {
 if [ "$1" = stop ]; then
  printf '/dev/block/unrelated %s/system ext4 ro,seclabel,relatime 0 0\n' "$fixture" > "$fixture/proc/mounts"
 fi
}
'''
    result = fixture.run_script(phase, boundary_hook=hook)
    assert result.returncode != 0, result.stdout
    files_after, operations_after = observed_state(fixture)
    assert files_after == files_before
    assert operations_after[len(operations_before):].decode().splitlines() == ["stop:camera-gui"]


@pytest.mark.parametrize("phase_fixture", ("activate-boot.sh",), indirect=True)
def test_expiry_during_final_quiescence_query_cannot_commit_rc(phase_fixture):
    fixture, phase = phase_fixture
    files_before, _ = observed_state(fixture)
    observed = int(datetime.fromisoformat(fixture.q["observed_utc"]).timestamp())
    hook = f'''
boundary() {{ [ "$1" != remount ] || printf armed > "$fixture/identity-drift"; }}
getprop() {{
 if [ -f "$fixture/identity-drift" ]; then printf expired > "$fixture/identity-expired"; fi
 fixture_getprop "$@"
}}
date() {{ if [ -f "$fixture/identity-expired" ]; then echo {observed + 601}; else echo {observed}; fi; }}
'''
    result = fixture.run_script(phase, boundary_hook=hook)
    assert result.returncode != 0, result.stdout
    assert (fixture.root / "identity-expired").read_text() == "expired"
    assert observed_state(fixture)[0] == files_before
    assert (fixture.root / "proc/mounts").read_text() == fixture.mount_line


@pytest.mark.parametrize("phase_fixture", ("install-files.sh",), indirect=True)
def test_expiry_between_payload_moves_preserves_partial_owned_state_without_activation(phase_fixture):
    fixture, phase = phase_fixture
    observed = int(datetime.fromisoformat(fixture.q["observed_utc"]).timestamp())
    hook = f'''
boundary() {{ [ "$1" != move ] || printf expired > "$fixture/identity-drift"; }}
date() {{ if [ -f "$fixture/identity-drift" ]; then echo {observed + 601}; else echo {observed}; fi; }}
'''
    result = fixture.run_script(phase, boundary_hook=hook)
    assert result.returncode != 0, result.stdout
    assert b"X2DII_FILES_INSTALLED" not in result.stdout
    entries = fixture.manifest["candidate"]["files"]
    assert (fixture.root / entries[0]["target"].lstrip("/")).is_file()
    assert all(not (fixture.root / entry["target"].lstrip("/")).exists() for entry in entries[1:])
    from tools import prepare_peer_install as peer
    assert (fixture.root / peer.boot.TARGET.lstrip("/")).read_bytes() == peer.boot.STOCK.read_bytes()
    assert (fixture.root / "proc/mounts").read_text() == fixture.mount_line
    assert not (fixture.root / "tmp/x2dii-menu-install.lock").exists()


@pytest.mark.parametrize("phase_fixture", ("install-files.sh",), indirect=True)
def test_session_fields_and_observation_time_are_bound_to_existing_qualification(phase_fixture):
    fixture, _ = phase_fixture
    from tools import prepare_peer_install as peer
    original = fixture.validated_shape_fixture()
    peer.validate_qualification(fixture.manifest, original)
    for field in ("observed_utc", "start_ticks", "exe_sha256", "domain", "namespace"):
        changed = deepcopy(original)
        if field == "observed_utc":
            changed[field] = (datetime.fromisoformat(changed[field]) - timedelta(seconds=1)).isoformat()
        elif field == "namespace":
            changed["mount_namespace"] = changed["init_mount_namespace"] = "mnt:[9]"
            changed["observer"]["mount_namespace"] = "mnt:[9]"
            from tests.test_runtime_observation import synthetic_observation
            changed["runtime_observation"] = synthetic_observation(changed, fixture.manifest["candidate"]["gui_sha256"])
        else:
            changed["observer"][field] = {"start_ticks": "99999", "exe_sha256": "a" * 64,
                                           "domain": "u:r:adbd:s0"}[field]
        with pytest.raises(ValueError, match="execution subject"):
            peer.validate_qualification(fixture.manifest, changed)
