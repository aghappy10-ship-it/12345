"""The real rendered install script must consume observed core identities.

All executions use the existing isolated host fixture: process, service, UID,
SELinux and mount responses are explicit substitutes, never device evidence.
"""
import pytest
from copy import deepcopy

from tests.test_release_lifecycle import installer
from tools import prepare_peer_install as peer
from tools import session_context


def test_install_session_carries_observed_core_processes_and_artifact_sizes(installer):
    values = session_context.decode_session(peer.session_data(installer.manifest, installer.q))
    observation = installer.q["runtime_observation"]
    for component, prefix in (("gui", "core_gui"), ("service", "core_service"),
                              ("capture_owner", "core_capture")):
        for key, value in observation[component]["process"].items():
            assert values[prefix + "_" + key] == value
        assert values[prefix + "_bytes"] == observation[component]["artifact"]["bytes"]
    assert values["core_sensor_sha256"] == observation["sensor"]["sha256"]
    assert values["core_sensor_bytes"] == observation["sensor"]["bytes"]


@pytest.mark.parametrize("component", ("gui", "service"))
def test_replaced_observed_core_process_is_refused_before_stop_or_write(installer, component):
    installer.shell_fixture()
    process = installer.q["runtime_observation"][component]["process"]
    stat = installer.root / "proc" / str(process["pid"]) / "stat"
    stat.parent.mkdir(parents=True, exist_ok=True)
    stat.write_text(str(process["pid"]) + " (synthetic-process) S " + "0 " * 18 + "999999 0\n")
    result = installer.run_script("install-files.sh")
    assert result.returncode != 0, (result.stdout, result.stderr)
    assert not (installer.root / "operations").exists()
    assert not (installer.root / "system/lib64/libx2dii_menu.so").exists()


def test_failed_core_query_cannot_succeed_by_printing_the_expected_path(installer):
    installer.shell_fixture()
    hook = '''
readlink() {
 case "$1" in
  */345/exe) printf reached > "$fixture/core-query-reached"; printf '/system/bin/camera-service\\n'; return 2;;
  *) fixture_readlink "$@";;
 esac
}
'''
    result = installer.run_script("install-files.sh", boundary_hook=hook)
    assert (installer.root / "core-query-reached").read_text() == "reached"
    assert result.returncode != 0, (result.stdout, result.stderr)
    assert not (installer.root / "operations").exists()


def test_failed_core_link_count_query_cannot_be_accepted(installer):
    installer.shell_fixture()
    hook = '''
stat() {
 if [ "$2" = %h ] && [ "$3" = "$fixture/system/bin/camera-service" ]; then
  printf reached > "$fixture/core-query-reached"
  printf '1\\n'
  return 2
 fi
 fixture_stat "$@"
}
'''
    result = installer.run_script("install-files.sh", boundary_hook=hook)
    assert (installer.root / "core-query-reached").read_text() == "reached"
    assert result.returncode != 0, (result.stdout, result.stderr)
    assert not (installer.root / "operations").exists()


@pytest.mark.parametrize("query", ("file_metadata", "file_label", "directory_metadata", "owner"))
def test_failed_metadata_query_with_expected_output_is_rejected_before_operations(installer, query):
    installer.shell_fixture()
    phase = "activate-boot.sh" if query in ("directory_metadata", "owner") else "install-files.sh"
    if phase == "activate-boot.sh":
        prior = installer.run_script("install-files.sh")
        assert prior.returncode == 0, (prior.stdout, prior.stderr)
    operations = installer.root / "operations"
    before = operations.read_bytes() if operations.exists() else b""
    predicate, command = {
        "file_metadata": ('[ "$2" = "%u %g %a" ] && [ "$3" = "$fixture/system/etc/init/camera-gui.rc" ]', "stat"),
        "file_label": ('[ "$2" = "$fixture/system/etc/init/camera-gui.rc" ]', "ls"),
        "directory_metadata": ('[ "$2" = "%u %g %a" ] && [ -d "$3" ] && [ "${3##*/}" = "' + installer.manifest["candidate_sha256"][:24] + '" ]', "stat"),
        "owner": ('[ "${1##*/}" = owner ]', "cat"),
    }[query]
    delegate = {"stat": 'fixture_stat "$@"', "ls": 'fixture_ls "$@"', "cat": '/usr/bin/cat "$@"'}[command]
    hook = '''
QUERY() {
 if PREDICATE; then
  printf reached > "$fixture/metadata-fault-reached"
  DELEGATE
  return 2
 fi
 DELEGATE
}
'''.replace("QUERY", command).replace("PREDICATE", predicate).replace("DELEGATE", delegate)
    result = installer.run_script(phase, boundary_hook=hook)
    assert (installer.root / "metadata-fault-reached").read_text() == "reached"
    assert result.returncode != 0, (result.stdout, result.stderr)
    assert (operations.read_bytes() if operations.exists() else b"") == before


def test_mount_state_read_error_after_expected_text_is_not_treated_as_eof(installer):
    installer.shell_fixture()
    hook = '''
read() {
 if command read "$@"; then test_read_status=0; else test_read_status=$?; fi
 if [ "$#" = 2 ] && [ "${1-}" = -r ] && [ "${2-}" = state_line ] && [ "$test_read_status" != 0 ]; then
  printf observed > "$fixture/mount-read-error-reached"
  return 2
 fi
 return "$test_read_status"
}
'''
    result = installer.run_script("install-files.sh", boundary_hook=hook)
    assert (installer.root / "mount-read-error-reached").read_text() == "observed"
    assert result.returncode != 0, (result.stdout, result.stderr)
    assert not (installer.root / "operations").exists()


@pytest.mark.parametrize("tail", (b"/dev/block/partial /system ext4 ro", b" \t"))
def test_incomplete_mount_record_cannot_be_ignored_after_a_valid_system_line(installer, tail):
    installer.shell_fixture()
    mounts = installer.root / "proc/mounts"
    original = mounts.read_bytes() + tail
    mounts.write_bytes(original)
    result = installer.run_script("install-files.sh")
    assert result.returncode != 0, (result.stdout, result.stderr)
    assert not (installer.root / "operations").exists()
    assert mounts.read_bytes() == original
    assert not (installer.root / "system/lib64/libx2dii_menu.so").exists()


@pytest.mark.parametrize("damage", ("sensor_bytes", "service_bytes", "service_executable", "service_state"))
def test_core_content_or_service_drift_is_refused_before_stop(installer, damage):
    installer.shell_fixture()
    paths = {"sensor_bytes": "system/etc/imx861bqr_hb722.conf",
             "service_bytes": "system/bin/camera-service", "service_executable": "proc/345/exe",
             "service_state": "core-service-state"}
    path = installer.root / paths[damage]
    raw = path.read_bytes()
    path.write_bytes(b"X" + raw[1:])
    result = installer.run_script("install-files.sh")
    assert result.returncode != 0, (result.stdout, result.stderr)
    assert not (installer.root / "operations").exists()


@pytest.mark.parametrize("boundary", ("lock", "stop", "remount", "move"))
def test_service_replacement_at_each_phase_boundary_blocks_the_next_write(installer, boundary):
    installer.shell_fixture()
    hook = '''
boundary() {
 if [ "$1" = BOUNDARY ]; then
  printf '345 (synthetic) S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 999999 0\n' > "$fixture/proc/345/stat"
  printf reached > "$fixture/core-fault-reached"
 fi
}
'''.replace("BOUNDARY", boundary)
    result = installer.run_script("install-files.sh", boundary_hook=hook)
    assert (installer.root / "core-fault-reached").read_text() == "reached"
    assert result.returncode != 0, (result.stdout, result.stderr)
    operations_path = installer.root / "operations"
    operations = operations_path.read_text().splitlines() if operations_path.exists() else []
    moves = [line for line in operations if line.startswith("mv:")]
    assert len(moves) == (1 if boundary == "move" else 0)
    if boundary == "lock":
        assert not operations
    assert (installer.root / "proc/mounts").read_text() == installer.mount_line
    assert (installer.root / "system/etc/init/camera-gui.rc").read_bytes() == peer.boot.STOCK.read_bytes()
    assert b"X2DII_FILES_INSTALLED" not in result.stdout


def distinct_capture_owner(installer):
    observation = installer.q["runtime_observation"]
    owner = observation["capture_owner"]
    owner["process"].update(pid=456, start_ticks="45600", exe_target="/system/bin/capture-owner", exe_sha256="f" * 64)
    owner["artifact"].update(path="/system/bin/capture-owner", sha256="f" * 64)


def test_distinct_capture_owner_normal_install_activate_and_restore(installer):
    distinct_capture_owner(installer)
    installer.shell_fixture()
    for phase in ("install-files.sh", "activate-boot.sh", "restore-boot.sh"):
        result = installer.run_script(phase)
        assert result.returncode == 0, (phase, result.stdout, result.stderr)
    assert (installer.root / "system/etc/init/camera-gui.rc").read_bytes() == peer.boot.STOCK.read_bytes()


def test_distinct_capture_owner_is_checked_without_inventing_a_service_name(installer):
    distinct_capture_owner(installer)
    installer.shell_fixture()
    (installer.root / "proc/456/attr/current").write_text("u:r:changed:s0\n")
    result = installer.run_script("install-files.sh")
    assert result.returncode != 0, (result.stdout, result.stderr)
    assert not (installer.root / "operations").exists()


def test_capture_owner_gui_alias_follows_the_deliberate_stop_transition(installer):
    observation = installer.q["runtime_observation"]
    owner = observation["capture_owner"]
    owner["process"] = deepcopy(observation["gui"]["process"])
    owner["artifact"] = deepcopy(observation["gui"]["artifact"])
    installer.shell_fixture()
    for phase in ("install-files.sh", "activate-boot.sh", "restore-boot.sh"):
        result = installer.run_script(phase)
        assert result.returncode == 0, (phase, result.stdout, result.stderr)
    assert (installer.root / "gui-service-state").read_text() == "stopped"
    assert (installer.root / "system/etc/init/camera-gui.rc").read_bytes() == peer.boot.STOCK.read_bytes()


@pytest.mark.parametrize("phase", ("activate-boot.sh", "restore-boot.sh"))
@pytest.mark.parametrize("component", ("service", "sensor", "capture_owner"))
def test_later_phase_core_drift_after_remount_blocks_configuration_write(installer, phase, component):
    if component == "capture_owner":
        distinct_capture_owner(installer)
    installer.shell_fixture()
    for prior in ("install-files.sh", "activate-boot.sh"):
        if prior == phase:
            break
        result = installer.run_script(prior)
        assert result.returncode == 0, (prior, result.stdout, result.stderr)
    rc = installer.root / "system/etc/init/camera-gui.rc"
    original = rc.read_bytes()
    operations = installer.root / "operations"
    before = operations.read_bytes()
    mutation = {
        "service": 'printf "u:r:changed:s0\\n" > "$fixture/proc/345/attr/current"',
        "sensor": 'printf changed > "$fixture/system/etc/imx861bqr_hb722.conf"',
        "capture_owner": 'printf "u:r:changed:s0\\n" > "$fixture/proc/456/attr/current"',
    }[component]
    hook = '''
boundary() {
 if [ "$1" = remount ]; then
  MUTATE
  printf reached > "$fixture/core-fault-reached"
 fi
}
'''.replace("MUTATE", mutation)
    result = installer.run_script(phase, boundary_hook=hook)
    assert result.returncode == 32, (result.stdout, result.stderr)
    assert (installer.root / "core-fault-reached").read_text() == "reached"
    assert rc.read_bytes() == original
    assert operations.read_bytes()[len(before):].decode().splitlines() == [
        "stop:camera-gui", "mount:-o remount,rw " + installer.posix + "/system",
        "mount:-o remount,ro " + installer.posix + "/system"]
    assert (installer.root / "proc/mounts").read_text() == installer.mount_line
    assert not (installer.root / "tmp/x2dii-menu-install.lock").exists()
    assert b"ACTIVATED" not in result.stdout and b"RESTORED" not in result.stdout
