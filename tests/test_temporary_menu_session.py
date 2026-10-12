"""Temporary menu session seams; host execution is not camera qualification."""
from unittest import mock

import pytest

from tests.test_release_lifecycle import installer
from tests.test_session_context import shell_read
from tools import prepare_peer_install as peer
from tools import session_context as session


def temporary_values(installer):
    # Test fixture only. Production has no install-to-validation authority cast.
    values = session.decode_session(peer.session_data(installer.manifest, installer.q))
    values.update(kind="menu_validation", purpose="temporary_menu_validation",
                  action="run_and_restore", candidate_sha256=installer.manifest["candidate_sha256"])
    return values


def test_temporary_session_is_a_separate_canonical_action_not_an_install_flag(installer, tmp_path):
    values = temporary_values(installer)
    raw = session.encode_session(values, schema="x2dii-session-context-v3")
    assert session.decode_session(raw) == values
    result, _ = shell_read(tmp_path, raw, after='''
x2dii_load_session "$1" "$2" || exit 42
printf '%s|%s|%s|%s\\n' "$X2DII_SESSION_KIND" "$X2DII_SESSION_PURPOSE" "$X2DII_SESSION_ACTION" "$X2DII_SESSION_CANDIDATE_SHA256"
''')
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "menu_validation|temporary_menu_validation|run_and_restore|" + installer.manifest["candidate_sha256"]
    for schema in (session.SCHEMA, session.INSTALL_SCHEMA):
        with pytest.raises(session.SessionContextError):
            session.encode_session(values, schema=schema)


def test_install_context_cannot_enter_temporary_operation_or_reverse(installer):
    installer.shell_fixture()
    installer.scripts["temporary"] = peer.render_temporary_menu_session(installer.manifest)
    result = installer.run_script("temporary")
    assert result.returncode == 32
    assert not (installer.root / "operations").exists()
    temporary = session.encode_session(temporary_values(installer), schema=session.MENU_VALIDATION_SCHEMA)
    with mock.patch.object(peer, "session_data", return_value=temporary):
        for action in ("install-files.sh", "activate-boot.sh", "restore-boot.sh"):
            result = installer.run_script(action)
            assert result.returncode == 32
    assert not (installer.root / "operations").exists()


@pytest.mark.parametrize("change", ({"kind": "install"}, {"purpose": "final_camera_installation"},
                                    {"action": "activate_boot"}, {"approved": True}))
def test_temporary_purpose_cannot_be_repurposed_as_persistent_install(installer, change):
    with pytest.raises(session.SessionContextError):
        session.encode_session({**temporary_values(installer), **change}, schema=session.MENU_VALIDATION_SCHEMA)


def test_failed_reload_clears_temporary_action_fields(installer, tmp_path):
    raw = session.encode_session(temporary_values(installer), schema=session.MENU_VALIDATION_SCHEMA)
    result, _ = shell_read(tmp_path, raw, after='''
x2dii_load_session "$1" "$2" || exit 42
if x2dii_load_session "$1" invalid; then exit 43; fi
[ "$X2DII_SESSION_VALID" = 0 ] && [ "${X2DII_SESSION_PURPOSE-unset}" = unset ] &&
[ "${X2DII_SESSION_ACTION-unset}" = unset ] && [ "${X2DII_SESSION_CANDIDATE_SHA256-unset}" = unset ]
''')
    assert result.returncode == 0, result.stderr


def test_wrong_candidate_context_stops_before_any_operation(installer):
    installer.shell_fixture()
    installer.scripts["temporary"] = peer.render_temporary_menu_session(installer.manifest)
    values = temporary_values(installer)
    values["candidate_sha256"] = "f" * 64
    raw = session.encode_session(values, schema=session.MENU_VALIDATION_SCHEMA)
    with mock.patch.object(peer, "session_data", return_value=raw):
        result = installer.run_script("temporary")
    assert result.returncode == 32
    assert not (installer.root / "operations").exists()


def temporary_os_boundary(installer, *, child_domain=None, request_stop=True):
    """Only OS process/service/metadata boundaries; renderer/file work is real."""
    domain = child_domain or installer.q["runtime_observation"]["gui"]["process"]["domain"]
    return r'''
sleep() { /usr/bin/sleep .02; }
env() {
 # A real child runs; its /proc identity is a host fixture, not camera evidence.
 test_child=$BASHPID
 printf '%s\n' "$test_child" > "$fixture/test-child-pid"
 /usr/bin/mkdir -p "$fixture/proc/$test_child/attr"
 printf '%s (camera-gui) S %s 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 77700 0\n' "$test_child" "$$" > "$fixture/proc/$test_child/stat"
 /usr/bin/cp "$fixture/system/bin/camera-gui" "$fixture/proc/$test_child/exe"
 printf '%s\n' 'TEST_DOMAIN' > "$fixture/proc/$test_child/attr/current"
 printf '%s\n' "$fixture/system/lib64/libx2dii_menu.so" > "$fixture/proc/$test_child/maps"
 printf '%s\n' "$*" > "$fixture/launch-args"
 trap '/usr/bin/rm -r "$fixture/proc/$test_child"' EXIT
 trap 'exit 0' TERM INT
 TEST_STOP
 test_lifetime=0
 while builtin kill -0 "$$" 2>/dev/null && [ "$test_lifetime" -lt 1500 ]; do
  /usr/bin/sleep .02
  test_lifetime=$((test_lifetime+1))
 done
}
pidof() {
 case "$1" in
  camera-service) echo 345;;
  camera-gui)
   if [ -f "$fixture/test-child-pid" ] && [ -f "$fixture/proc/$(cat "$fixture/test-child-pid")/stat" ]; then
    cat "$fixture/test-child-pid"
   elif [ "$(cat "$fixture/gui-service-state")" = running ]; then echo 234
   else return 1; fi;;
  *) return 1;;
 esac
}
readlink() {
 if [ "$1" = "$fixture/proc/100/exe" ]; then
  printf '/system/bin/camera-test\n'
  return
 fi
 # Only executable links can refer to the modeled GUI child. Namespace and
 # other queries must not read GUI-only state or start an unrelated helper.
 case "$1" in "$fixture/proc/"*/exe)
  if [ -f "$fixture/test-child-pid" ] && [ "$1" = "$fixture/proc/$(cat "$fixture/test-child-pid")/exe" ]; then
   printf '/system/bin/camera-gui\n'
   return
  fi;;
 esac
 fixture_readlink "$@"
}
test_original_sha=$(declare -f sha256sum)
eval "${test_original_sha/sha256sum/test_original_sha256sum}"
sha256sum() {
 if [ "$#" = 1 ]; then
  case "$1" in "$fixture/proc/"*/exe)
   if [ -f "$fixture/test-child-pid" ] && [ "$1" = "$fixture/proc/$(cat "$fixture/test-child-pid")/exe" ]; then
    test_original_sha256sum "$fixture/system/bin/camera-gui"
    return $?
   fi;;
  esac
 fi
 test_original_sha256sum "$@"
}
kill() {
 printf 'kill:%s\n' "$*" >> "$fixture/operations"
 builtin kill "$@"
}
start() {
 printf 'start:%s\n' "$*" >> "$fixture/operations"
 [ "$1" = camera-gui ] || return 1
 printf running > "$fixture/gui-service-state"
}
'''.replace("TEST_DOMAIN", domain).replace("TEST_STOP", (
        'printf stop > "$fixture/tmp/x2dii-menu-validation-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/stop"'
        if request_stop else ":"))


def run_temporary(installer, hook=""):
    # Existing fixture predates any environment check; this models stock /proc.
    environment = installer.root / "proc/234/environ"
    if not environment.exists():
        environment.write_bytes(b"XDG_RUNTIME_DIR=/tmp\0XDG_CACHE_HOME=/data\0")
    installer.scripts["temporary"] = peer.render_temporary_menu_session(installer.manifest)
    raw = session.encode_session(temporary_values(installer), schema=session.MENU_VALIDATION_SCHEMA)
    with mock.patch.object(peer, "session_data", return_value=raw):
        return installer.run_script("temporary", boundary_hook=hook)


def prepare_maintenance(installer, *, preplace=True):
    """Pre-existing files and maintenance identity, not an installation action."""
    installer.q["observer"].update(exe_target="/system/bin/camera-test",
                                  domain="u:r:hbl_camera_service:s0")
    for relative in ("proc/self/attr/current", "proc/100/attr/current"):
        (installer.root / relative).write_text("u:r:hbl_camera_service:s0\n")
    # Every modelled live PID has a maps file. Omitting a PID's maps must be a
    # failed observation now, not the old glob's silently skipped process.
    for directory in (installer.root / "proc").iterdir():
        if directory.name.isdecimal():
            (directory / "maps").write_text("unrelated-library\n")
    if preplace:
        for entry in installer.manifest["candidate"]["files"]:
            (installer.root / entry["target"].lstrip("/")).write_bytes(
                (peer.ROOT / entry["source"]).read_bytes())


@pytest.mark.parametrize("reply", (
    "u:object_r:system_file:s0 /system/etc/unrelated",
    "u:object_r:system_file:s0",
    "u:object_r:system_file:s0 TARGET unexpected",
))
def test_maintenance_rejects_label_reply_not_bound_to_queried_file(installer, reply):
    installer.shell_fixture()
    prepare_maintenance(installer)
    hook = temporary_os_boundary(installer) + r'''
ls() {
 case "$2" in
  */libx2dii_menu.so) printf '%s\n' 'REPLY';;
  *) printf 'u:object_r:system_file:s0 %s\n' "$2";;
 esac
}
'''.replace("REPLY", reply)
    result = run_temporary(installer, hook)
    assert result.returncode != 0, (result.stdout, result.stderr)
    assert b"CHILD_LOADED" not in result.stdout
    assert not (installer.root / "operations").exists()
    assert (installer.root / "gui-service-state").read_text() == "running"


@pytest.mark.parametrize("domain,expected", (("u:r:su:s0", 31), ("u:r:hbl_camera_service:s0", 0)))
def test_only_maintenance_role_runs_preplaced_menu_without_system_writes(installer, domain, expected):
    installer.shell_fixture()
    prepare_maintenance(installer)
    (installer.root / "proc/self/attr/current").write_text(domain + "\n")
    hook = temporary_os_boundary(installer) + r'''
readlink() {
 if [ "$1" = "$fixture/proc/100/exe" ]; then echo /system/bin/camera-test
 elif [ -f "$fixture/test-child-pid" ] && [ "$1" = "$fixture/proc/$(cat "$fixture/test-child-pid")/exe" ]; then echo /system/bin/camera-gui
 else fixture_readlink "$@"; fi
}
mount() { printf 'forbidden-system-write:mount\n' >> "$fixture/operations"; return 91; }
chcon() { printf 'forbidden-system-write:chcon\n' >> "$fixture/operations"; return 91; }
chown() { printf 'forbidden-system-write:chown\n' >> "$fixture/operations"; return 91; }
cp() { printf 'forbidden-system-write:cp\n' >> "$fixture/operations"; return 91; }
mv() { printf 'forbidden-system-write:mv\n' >> "$fixture/operations"; return 91; }
rm() { printf 'forbidden-system-write:rm\n' >> "$fixture/operations"; return 91; }
'''
    result = run_temporary(installer, hook)
    assert result.returncode == expected, (result.stdout, result.stderr)
    operations = (installer.root / "operations").read_text() if (installer.root / "operations").exists() else ""
    assert "forbidden-system-write:" not in operations
    if domain == "u:r:su:s0":
        assert not operations
    else:
        assert b"X2DII_ORIGINAL_GUI_RESTORED_EXTENSION_FILES_RETAINED_PENDING_SU_REMOVAL" in result.stdout
        assert b"X2DII_VISIBLE_PROCESS_MAPPINGS_OBSERVED_CLEAR_COVERAGE_UNVERIFIED_NOT_REMOVAL_AUTHORITY" in result.stdout
        assert b"X2DII_ALL_PROCESS_MAPPINGS_OBSERVED_CLEAR" not in result.stdout
        assert "start:camera-gui" in operations
        for entry in installer.manifest["candidate"]["files"]:
            assert peer.sha((installer.root / entry["target"].lstrip("/")).read_bytes()) == entry["sha256"]


@pytest.mark.parametrize("failure", ("permission_denied", "disappeared"))
def test_incomplete_global_maps_observation_does_not_prevent_stock_recovery_or_allow_removal(installer, failure):
    installer.shell_fixture()
    prepare_maintenance(installer)
    hook = temporary_os_boundary(installer) + r'''
grep() {
 case "$*" in
  *"$fixture/proc/123/maps"*) printf 'TEST_MAPS_ERROR\n' >&2; return 2;;
  *) /usr/bin/grep "$@";;
 esac
}
'''.replace("TEST_MAPS_ERROR", "Permission denied" if failure == "permission_denied" else "No such file or directory")
    result = run_temporary(installer, hook)
    assert result.returncode == 80, (result.stdout, result.stderr)
    assert (installer.root / "gui-service-state").read_text() == "running"
    assert b"X2DII_ORIGINAL_GUI_RESTORED_EXTENSION_FILES_RETAINED_PENDING_SU_REMOVAL" in result.stdout
    assert b"X2DII_ALL_PROCESS_MAPPINGS_UNVERIFIED_FILES_RETAINED_NO_REMOVAL_AUTHORITY" in result.stderr
    operations = (installer.root / "operations").read_text()
    assert "kill:-TERM " in operations and "start:camera-gui" in operations
    assert "rm:" not in operations
    assert (installer.root / "system/lib64/libx2dii_menu.so").exists()


@pytest.mark.parametrize("expiry", ("before_loaded", "while_loaded"))
def test_original_session_deadline_is_not_extended_by_a_late_child_launch(installer, expiry):
    installer.shell_fixture()
    prepare_maintenance(installer)
    observed = int(peer.datetime.fromisoformat(installer.q["observed_utc"]).timestamp())
    hook = temporary_os_boundary(installer) + f'''
printf() {{
 case "$*" in *X2DII_TEMPORARY_CHILD_LOADED_NOT_FEATURE_VERIFIED*) builtin printf used > "$fixture/loaded-event";; esac
 builtin printf "$@"
}}
date() {{
 if [ -f "$fixture/test-child-pid" ]; then
  if [ "{expiry}" = before_loaded ]; then echo {observed + 601}
  elif [ -f "$fixture/loaded-event" ]; then
   if [ -f "$fixture/validation-started" ]; then echo {observed + 601}
   else printf used > "$fixture/validation-started"; echo {observed + 599}; fi
  else echo {observed + 599}; fi
 else echo {observed + 599}; fi
}}
'''
    result = run_temporary(installer, hook)
    assert result.returncode == 78, (result.stdout, result.stderr)
    assert (installer.root / "gui-service-state").read_text() == "running"
    assert b"X2DII_ORIGINAL_GUI_RESTORED_EXTENSION_FILES_RETAINED_PENDING_SU_REMOVAL" in result.stdout
    if expiry == "before_loaded":
        assert b"X2DII_TEMPORARY_CHILD_LOADED" not in result.stdout
    operations = (installer.root / "operations").read_text()
    assert "kill:-TERM " in operations and "start:camera-gui" in operations
    assert (installer.root / "system/lib64/libx2dii_menu.so").exists()


def test_temporary_child_is_stopped_and_stock_recovers_while_files_remain(installer):
    installer.shell_fixture()
    prepare_maintenance(installer)
    result = run_temporary(installer, temporary_os_boundary(installer))
    assert result.returncode == 0, (result.stdout, result.stderr)
    operations = (installer.root / "operations").read_text().splitlines()
    kill_index = next(i for i, x in enumerate(operations) if x.startswith("kill:-TERM "))
    removed = [i for i, x in enumerate(operations) if x.startswith("rm:") and "/system/" in x]
    started = operations.index("start:camera-gui")
    assert not removed and kill_index < started
    assert (installer.root / "system/etc/init/camera-gui.rc").read_bytes() == peer.boot.STOCK.read_bytes()
    assert (installer.root / "proc/mounts").read_text() == installer.mount_line
    assert (installer.root / "gui-service-state").read_text() == "running"
    assert b"X2DII_ORIGINAL_GUI_RESTORED_EXTENSION_FILES_RETAINED_PENDING_SU_REMOVAL" in result.stdout
    assert (installer.root / "system/lib64/libx2dii_menu.so").exists()
    transaction = installer.root / "tmp/x2dii-menu-validation-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    assert (transaction / "attempt").is_file()
    assert "domain=u:r:hbl_camera_service:s0" in (transaction / "child.identity").read_text()
    launch = (installer.root / "launch-args").read_text()
    assert "X2DII_MENU_EXTENSION=1" in launch and "LD_PRELOAD=" in launch


@pytest.mark.parametrize("fault", ("wrong_domain", "observer_ended", "timeout", "restore_failed"))
def test_temporary_exit_recovers_without_inventing_domain_or_renewing_observer(installer, fault):
    installer.shell_fixture()
    prepare_maintenance(installer)
    hook = temporary_os_boundary(installer, child_domain="u:r:su:s0" if fault == "wrong_domain" else None,
                                 request_stop=fault != "timeout")
    if fault == "observer_ended":
        hook = hook.replace('printf \'%s\\n\' "$*" > "$fixture/launch-args"',
                            'printf \'%s\\n\' "$*" > "$fixture/launch-args"\n /usr/bin/rm "$fixture/proc/100/stat"')
    if fault == "timeout":
        observed = int(peer.datetime.fromisoformat(installer.q["observed_utc"]).timestamp())
        hook += f'''
printf() {{
 case "$*" in *X2DII_TEMPORARY_CHILD_LOADED_NOT_FEATURE_VERIFIED*) builtin printf used > "$fixture/loaded-event";; esac
 builtin printf "$@"
}}
date() {{
 if [ -f "$fixture/loaded-event" ]; then
  if [ -f "$fixture/clock-consumed" ]; then echo {observed + 120}
  else printf used > "$fixture/clock-consumed"; echo {observed}; fi
 else echo {observed}; fi
}}
'''
    if fault == "restore_failed":
        hook += '\nstart() { printf "start-failed:%s\\n" "$*" >> "$fixture/operations"; return 1; }\n'
    result = run_temporary(installer, hook)
    assert result.returncode == {"wrong_domain": 76, "observer_ended": 0, "timeout": 78,
                                 "restore_failed": 79}[fault], (result.stdout, result.stderr)
    operations = (installer.root / "operations").read_text()
    assert "kill:-TERM " in operations
    assert (installer.root / "system/lib64/libx2dii_menu.so").exists()
    assert (installer.root / "system/etc/init/camera-gui.rc").read_bytes() == peer.boot.STOCK.read_bytes()
    assert (installer.root / "proc/mounts").read_text() == installer.mount_line
    if fault != "observer_ended":
        assert b"X2DII_TEMPORARY_MENU_RESTORED" not in result.stdout
    if fault == "wrong_domain":
        assert b"CHILD_LOADED" not in result.stdout
        record = installer.root / "tmp/x2dii-menu-validation-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/child.identity"
        assert "domain=u:r:su:s0" in record.read_text()
    if fault == "observer_ended":
        assert not (installer.root / "proc/100/stat").exists()
    if fault == "restore_failed":
        assert b"RECOVERY_FAILED" in result.stderr
        assert b"X2DII_ORIGINAL_GUI_RESTORED" not in result.stdout
        assert (installer.root / "tmp/x2dii-menu-install.lock").exists()
    else:
        assert b"X2DII_ORIGINAL_GUI_RESTORED_EXTENSION_FILES_RETAINED_PENDING_SU_REMOVAL" in result.stdout


@pytest.mark.parametrize("marker", ("tmp/x2dii-menu.attempt", "blackbox/x2dii-menu.disable"))
def test_existing_attempt_or_disable_marker_prevents_any_menu_stop(installer, marker):
    installer.shell_fixture()
    prepare_maintenance(installer)
    (installer.root / marker).write_text("prior state\n")
    result = run_temporary(installer, temporary_os_boundary(installer))
    assert result.returncode != 0
    assert not (installer.root / "operations").exists()
    assert (installer.root / marker).read_text() == "prior state\n"


@pytest.mark.parametrize("fault", ("incomplete", "missing", "metadata"))
def test_invalid_preplaced_file_is_retained_without_stopping_stock_gui(installer, fault):
    installer.shell_fixture()
    prepare_maintenance(installer)
    residue = installer.root / "system/etc/X2d2MenuPage.qml"
    hook = temporary_os_boundary(installer)
    if fault == "incomplete":
        residue.write_bytes(b"incomplete")
    elif fault == "missing":
        residue.unlink()
    else:
        hook += r'''
ls() {
 if [ "$2" = "$fixture/system/etc/X2d2MenuPage.qml" ]; then
  printf 'u:object_r:unexpected:s0 %s\n' "$2"
 else fixture_ls "$@"; fi
}
'''
    result = run_temporary(installer, hook)
    assert result.returncode == 33, (result.stdout, result.stderr)
    assert (installer.root / "gui-service-state").read_text() == "running"
    assert b"X2DII_ORIGINAL_GUI_RESTORED" not in result.stdout
    if fault == "incomplete":
        assert residue.read_bytes() == b"incomplete"
    elif fault == "missing":
        assert not residue.exists()
    assert not (installer.root / "operations").exists()
    assert not (installer.root / "tmp/x2dii-menu-install.lock").exists()


def test_pid_birth_reuse_during_exec_wait_is_not_adopted_as_our_child(installer):
    installer.shell_fixture()
    prepare_maintenance(installer)
    hook = temporary_os_boundary(installer) + r'''
readlink() {
 if [ "$1" = "$fixture/proc/100/exe" ]; then echo /system/bin/camera-test
 elif [ -f "$fixture/test-child-pid" ] && [ "$1" = "$fixture/proc/$(cat "$fixture/test-child-pid")/exe" ]; then
  if [ ! -f "$fixture/reused-child" ]; then
   printf reused > "$fixture/reused-child"
   test_reused_pid=$(cat "$fixture/test-child-pid")
   printf '%s (camera-gui) S %s 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 99900 0\n' "$test_reused_pid" "$$" > "$fixture/proc/$test_reused_pid/stat"
  fi
  printf '/system/bin/camera-gui\n'
 else fixture_readlink "$@"; fi
}
'''
    result = run_temporary(installer, hook)
    assert result.returncode == 79, (result.stdout, result.stderr)
    operations = (installer.root / "operations").read_text()
    assert "kill:" not in operations and "start:camera-gui" not in operations
    assert (installer.root / "system/lib64/libx2dii_menu.so").exists()
    assert (installer.root / "tmp/x2dii-menu-install.lock").exists()


def test_backend_drift_after_launch_is_not_reported_as_successful_recovery(installer):
    installer.shell_fixture()
    prepare_maintenance(installer)
    hook = temporary_os_boundary(installer).replace(
        'printf \'%s\\n\' "$*" > "$fixture/launch-args"',
        'printf \'%s\\n\' "$*" > "$fixture/launch-args"\n printf "u:r:changed:s0\\n" > "$fixture/proc/345/attr/current"')
    result = run_temporary(installer, hook)
    assert result.returncode == 79, (result.stdout, result.stderr)
    assert (installer.root / "gui-service-state").read_text() == "running"
    assert b"X2DII_ORIGINAL_GUI_RESTORED" not in result.stdout


@pytest.mark.parametrize("signal", ("TERM", "KILL"))
def test_signal_error_with_confirmed_child_exit_still_restores_stock(installer, signal):
    installer.shell_fixture()
    prepare_maintenance(installer)
    hook = temporary_os_boundary(installer)
    if signal == "KILL":
        hook = hook.replace("trap 'exit 0' TERM INT", "trap ':' TERM\n trap 'exit 0' INT")
    hook += r'''
kill() {
 printf 'kill:%s\n' "$*" >> "$fixture/operations"
 builtin kill "$@" || return $?
 if [ "$1" = -TEST_SIGNAL ]; then
  wait "$2" 2>/dev/null || :
  # KILL cannot run the fixture's EXIT trap; model kernel /proc disappearance.
  if [ -d "$fixture/proc/$2" ]; then /usr/bin/rm -r "$fixture/proc/$2"; fi
  printf observed > "$fixture/signal-reported-esrch"
  return 1
 fi
}
'''.replace("TEST_SIGNAL", signal)
    result = run_temporary(installer, hook)
    assert (installer.root / "signal-reported-esrch").exists()
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert (installer.root / "gui-service-state").read_text() == "running"
    assert (installer.root / "system/lib64/libx2dii_menu.so").exists()
    assert not (installer.root / "tmp/x2dii-menu-install.lock").exists()


def test_changed_mount_is_refused_before_stop_without_attempting_a_remount(installer):
    installer.shell_fixture()
    prepare_maintenance(installer)
    hook = temporary_os_boundary(installer) + r'''
mount() {
 printf 'unexpected-remount\n' >> "$fixture/operations"
 return 9
}
'''
    (installer.root / "proc/mounts").write_text(installer.mount_line.replace(" ro,", " rw,"))
    result = run_temporary(installer, hook)
    assert result.returncode == 32, (result.stdout, result.stderr)
    assert (installer.root / "gui-service-state").read_text() == "running"
    assert (installer.root / "proc/mounts").read_text() == installer.mount_line.replace(" ro,", " rw,")
    assert b"X2DII_ORIGINAL_GUI_RESTORED" not in result.stdout
    assert not (installer.root / "operations").exists()
    assert not (installer.root / "tmp/x2dii-menu-install.lock").exists()


@pytest.mark.parametrize("phase", ("install-files.sh", "activate-boot.sh", "restore-boot.sh"))
def test_formal_cleanup_also_retains_readonly_remount_failure(installer, phase):
    installer.shell_fixture()
    for prior in ("install-files.sh", "activate-boot.sh", "restore-boot.sh"):
        if prior == phase:
            break
        result = installer.run_script(prior)
        assert result.returncode == 0, (result.stdout, result.stderr)
    hook = r'''
test_original_mount=$(declare -f mount)
eval "${test_original_mount/mount/test_original_mount}"
mount() {
 test_original_mount "$@" || return $?
 if [ "$2" = remount,ro ]; then
  printf reached > "$fixture/remount-ro-reported-failure"
  return 9
 fi
}
'''
    # A failed move enters the shared EXIT cleanup while /system is still rw.
    result = installer.run_script(phase, fail_move=1, boundary_hook=hook)
    assert (installer.root / "remount-ro-reported-failure").exists()
    assert result.returncode == 72, (result.stdout, result.stderr)
    assert (installer.root / "proc/mounts").read_text() == installer.mount_line
    assert b"X2DII_SCRIPT_FAILED:72" in result.stderr
    assert b"X2DII_FILES_INSTALLED" not in result.stdout
    assert b"X2DII_BOOT_CONFIG_ACTIVATED" not in result.stdout
    assert b"X2DII_OFFICIAL_RC_RESTORED" not in result.stdout
