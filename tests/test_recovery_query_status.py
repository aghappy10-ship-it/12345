"""Query failure faults in the real rendered recovery shell, host files only."""
from pathlib import Path
import shlex

import pytest

from tests.test_release_lifecycle import recovery_fixture


# Fixed query arguments; ROOT is substituted only with the host fixture path.
QUERIES = (
    ("link-count", "stat", ("-c", "%h", "ROOT/system/etc/init/camera-gui.rc"), "initial", False),
    ("file-owner-mode", "stat", ("-c", "%u %g %a", "ROOT/system/etc/init/camera-gui.rc"), "initial", False),
    ("private-directory", "stat", ("-c", "%u %g %a", "ROOT/system/etc/x2dii-menu-backup"), "initial", False),
    ("directory-device", "stat", ("-c", "%d", "ROOT/system/etc/init"), "initial", False),
    ("payload-size", "stat", ("-c", "%s", "ROOT/system/lib64/libx2dii_menu.so"), "initial", False),
    ("work-device", "stat", ("-c", "%d", "ROOT/system/.x2dii-menu-recovery-NONCE"), "initial", False),
    ("init-device-after-work", "stat", ("-c", "%d", "ROOT/system/etc/init"), "work-created", False),
    ("boot", "cat", ("ROOT/proc/sys/kernel/random/boot_id",), "initial", False),
    ("boot-after-lock", "cat", ("ROOT/proc/sys/kernel/random/boot_id",), "lock", False),
    ("self-domain", "cat", ("ROOT/proc/self/attr/current",), "initial", False),
    ("uid", "id", ("-u",), "initial", False),
    ("self-namespace", "readlink", ("ROOT/proc/self/ns/mnt",), "initial", False),
    ("init-namespace", "readlink", ("ROOT/proc/1/ns/mnt",), "initial", False),
    ("observer-executable", "readlink", ("ROOT/proc/100/exe",), "initial", False),
    ("observer-namespace", "readlink", ("ROOT/proc/100/ns/mnt",), "initial", False),
    ("observer-domain", "cat", ("ROOT/proc/100/attr/current",), "initial", False),
    ("gui-executable", "readlink", ("ROOT/proc/234/exe",), "initial", True),
    ("gui-namespace", "readlink", ("ROOT/proc/234/ns/mnt",), "initial", True),
    ("gui-domain", "cat", ("ROOT/proc/234/attr/current",), "initial", True),
    ("observed-service-state", "getprop", ("init.svc.camera-gui",), "initial", False),
    ("quiescent-service-state", "getprop", ("init.svc.camera-gui",), "stop", False),
    *(("slot-" + str(slot) + "-" + flag, "unrd", (f"slot_{slot}.status_{flag}",), "initial", False)
      for slot in (1, 2) for flag in ("active", "bootable", "successful")),
)


def present_gui(fixture):
    """Existing host fixture's present-process form, still synthetic data."""
    from tests.test_runtime_observation import synthetic_observation

    process = {"pid": 234, "start_ticks": "54321", "exe_target": "/system/bin/camera-gui",
               "exe_sha256": fixture.manifest["candidate"]["gui_sha256"], "domain": "u:r:camera_gui:s0",
               "mount_namespace": fixture.q["mount_namespace"]}
    fixture.q["gui"] = {"state": "present", "service_state": "running", "process": process}
    fixture.q["runtime_observation"] = synthetic_observation(fixture.q, process["exe_sha256"], recovery=True)
    fixture.path("/proc/234/attr").mkdir(parents=True)
    fixture.path("/proc/234/attr/current").write_text("u:r:camera_gui:s0\n")
    fixture.path("/proc/234/stat").write_text("234 (camera gui) S " + "0 " * 18 + "54321 0\n")
    fixture.path("/proc/234/exe").write_bytes(b"GUI identity is mocked")


def query_failure_hook(fixture, tool, arguments, stage):
    arguments = tuple(arg.replace("ROOT", fixture.posix).replace("NONCE", fixture.q["recovery_nonce"])
                      for arg in arguments)
    matching = " && ".join('[ "${' + str(index) + '-}" = ' + shlex.quote(arg) + ' ]'
                           for index, arg in enumerate(arguments, 1))
    armed = "true" if stage == "initial" else ('[ -d "$fixture/system/.x2dii-menu-recovery-' +
                                                  fixture.q["recovery_nonce"] + '" ]' if stage == "work-created"
                                                  else '[ -f "$fixture/query-armed" ]')
    delegate = "command " + tool if tool in ("cat", "date") else "fixture_" + tool
    return '''
boundary() { [ "$1" != ''' + shlex.quote(stage) + ''' ] || printf armed > "$fixture/query-armed"; }
''' + tool + '''() {
 ''' + delegate + ''' "$@" || return $?
 if ''' + matching + " && " + armed + '''; then
  printf observed > "$fixture/query-failure-observed"
  return 2
 fi
 return 0
}
'''


@pytest.mark.parametrize("name,tool,arguments,stage,gui_present", QUERIES, ids=[case[0] for case in QUERIES])
def test_recovery_refuses_correct_query_stdout_with_failure_status(
    recovery_fixture, name, tool, arguments, stage, gui_present
):
    fixture = recovery_fixture
    if gui_present:
        present_gui(fixture)
    recovery = fixture.recovery()
    source = recovery.render_recovery(fixture.saved, fixture.saved_sha, fixture.q)
    result = fixture.run_script(source, mode="gui_present" if gui_present else "normal",
                                boundary_hook=query_failure_hook(fixture, tool, arguments, stage))
    assert fixture.path("/query-failure-observed").read_text() == "observed", "fault query was not reached"
    assert result.returncode != 0, (name, result.stdout, result.stderr)
    assert b"X2DII_OFFICIAL_RC_RESTORED_OWNED_FILES_REMOVED" not in result.stdout
    fixture.assert_intact()
    assert fixture.path(fixture.backup + "/camera-gui.rc.original").read_bytes() == fixture.original
    operations = fixture.path("/operations")
    lines = operations.read_text().splitlines() if operations.exists() else []
    assert not any(line.startswith(("cp:", "mv:", "rm:")) for line in lines)
    if stage not in ("stop", "work-created") and name != "work-device":
        assert not any(line.startswith(("stop:", "mount:")) for line in lines)


@pytest.mark.parametrize("tool,arguments", [
    ("ls", ("-Zd", "ROOT/system/etc/init/camera-gui.rc")),
    ("sha256sum", ("ROOT/system/bin/camera-gui",)),
    ("date", ("-u", "+%s")),
    ("cat", ("ROOT/proc/100/stat",)),
    ("stat", ("-c", "%d", "ROOT/system")),
])
def test_already_guarded_recovery_queries_keep_failure_status(recovery_fixture, tool, arguments):
    fixture = recovery_fixture
    recovery = fixture.recovery()
    result = fixture.run_script(recovery.render_recovery(fixture.saved, fixture.saved_sha, fixture.q),
                                boundary_hook=query_failure_hook(fixture, tool, arguments, "initial"))
    assert fixture.path("/query-failure-observed").read_text() == "observed"
    assert result.returncode != 0
    fixture.assert_intact()
    assert not fixture.path("/operations").exists()


def test_two_failed_device_queries_cannot_agree_on_empty_stdout(recovery_fixture):
    fixture = recovery_fixture
    recovery = fixture.recovery()
    work = fixture.posix + "/system/.x2dii-menu-recovery-" + fixture.q["recovery_nonce"]
    hook = '''
stat() {
 if [ "${1-}" = -c ] && [ "${2-}" = %d ] && [ -d ''' + shlex.quote(work) + ''' ]; then
  case "${3-}" in ''' + shlex.quote(work) + '''|"$fixture/system/etc/init")
   printf observed > "$fixture/query-failure-observed"
   return 2;;
  esac
 fi
 fixture_stat "$@"
}
'''
    result = fixture.run_script(recovery.render_recovery(fixture.saved, fixture.saved_sha, fixture.q),
                                boundary_hook=hook)
    assert fixture.path("/query-failure-observed").read_text() == "observed"
    assert result.returncode != 0
    assert b"X2DII_OFFICIAL_RC_RESTORED_OWNED_FILES_REMOVED" not in result.stdout
    fixture.assert_intact()
    assert not any(line.startswith(("cp:", "mv:", "rm:"))
                   for line in fixture.path("/operations").read_text().splitlines())


def test_mount_table_read_error_is_not_accepted_as_normal_eof(recovery_fixture):
    fixture = recovery_fixture
    recovery = fixture.recovery()
    hook = '''
read() {
 if command read "$@"; then test_read_status=0; else test_read_status=$?; fi
 if [ "$#" = 2 ] && [ "${1-}" = -r ] && [ "${2-}" = state_line ] && [ "$test_read_status" != 0 ]; then
  printf observed > "$fixture/query-failure-observed"
  return 2
 fi
 return "$test_read_status"
}
'''
    result = fixture.run_script(recovery.render_recovery(fixture.saved, fixture.saved_sha, fixture.q),
                                boundary_hook=hook)
    assert fixture.path("/query-failure-observed").read_text() == "observed"
    assert result.returncode != 0, (result.stdout, result.stderr)
    assert b"X2DII_OFFICIAL_RC_RESTORED_OWNED_FILES_REMOVED" not in result.stdout
    fixture.assert_intact()
    assert not fixture.path("/operations").exists()


@pytest.mark.parametrize("trailing", [
    "/dev/block/other-slot ROOT/system",
    "/dev/block/other-slot ROOT/other ext4 rw",
    " \t ",
], ids=["partial-system", "partial-other", "partial-whitespace"])
def test_nonempty_unterminated_mount_tail_refuses_recovery_before_writes(recovery_fixture, trailing):
    fixture = recovery_fixture
    recovery = fixture.recovery()
    trailing = trailing.replace("ROOT", fixture.posix)
    mount_bytes = (fixture.mount_line + trailing).encode("ascii")
    fixture.path("/proc/mounts").write_bytes(mount_bytes)
    assert mount_bytes.endswith(trailing.encode("ascii")) and not mount_bytes.endswith(b"\n")

    result = fixture.run_script(recovery.render_recovery(fixture.saved, fixture.saved_sha, fixture.q))
    assert result.returncode != 0, (trailing, result.stdout, result.stderr)
    assert b"X2DII_OFFICIAL_RC_RESTORED_OWNED_FILES_REMOVED" not in result.stdout
    fixture.assert_intact()
    assert fixture.path(fixture.backup + "/camera-gui.rc.original").read_bytes() == fixture.original
    assert not fixture.path("/operations").exists()


@pytest.mark.parametrize("relative", ["tests/test_recovery_query_status.py", "tests/test_output_withdrawal.py"])
def test_recovery_build_identity_binds_query_and_output_withdrawal_tests(recovery_fixture, monkeypatch, relative):
    fixture = recovery_fixture
    recovery = fixture.recovery()
    target = recovery.ROOT / relative
    original_read = Path.read_bytes
    original = original_read(target)
    before = recovery.build_subject_sha256(fixture.saved, fixture.saved_sha)

    def changed_input(path):
        raw = original_read(path)
        return raw + b"\n# changed query status test input\n" if path == target else raw

    monkeypatch.setattr(Path, "read_bytes", changed_input)
    assert recovery.build_subject_sha256(fixture.saved, fixture.saved_sha) != before
    assert original_read(target) == original
