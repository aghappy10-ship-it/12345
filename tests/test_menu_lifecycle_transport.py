"""Fixed maintenance commands and real background lifecycle, no camera."""
import json
import subprocess
import re
import shutil
import sys
import tempfile
import time
from unittest import mock
from types import SimpleNamespace

import pytest

from tests.test_release_lifecycle import installer
from tests.test_temporary_menu_session import temporary_values, prepare_maintenance, temporary_os_boundary
from tests.test_peer_install import SH
from tools import session_context as sc, prepare_peer_install as peer
from tools import stage_peer_usb_access as maintenance


# Earlier 35/240 s failures stay preserved; the same normal host lifecycle
# later returned its actual final receipt at about 274 s. The user approved
# 360 s for normal receipt polling on 2026-10-10. This is host-only headroom,
# not a camera performance claim. All post-fault callers retain explicit
# 240 s (or their narrower existing allowance), with unchanged assertions.
# As before, this is the deadline to START a read. An in-flight public read
# uses its finite host command allowance below, not a strict 360 s wall cap.
HOST_LIFECYCLE_RECEIPT_WAIT_SECONDS = 360

# These positive pre-injection markers share the same measured startup
# prefix (AR/AS child admission ~131/134 s, launch ~153/157 s). BE preserved
# fixed_stop's real 35 s failure before that prefix reached stop intent. Use
# the approved 360 s host-only headroom through final.pending; do not
# enlarge stage/negative/post-injection waits or the default wait_file budget.
HOST_LIFECYCLE_PREINJECTION_WAIT_SECONDS = 360

# BH preserved the original 8 s failure, then the SAME host stop process
# returned the real NOT_COMPLETED acknowledgement at 11.172 s. This finite
# stop-only host observation allowance adds 4.828 s of engineering headroom;
# launch stays at 8 s; the read allowance is documented below. Target/client/
# receipt contracts are unchanged.
# Above describes the historical16 s choice. Current16 s timeout evidence
# retains incomplete cumulative validation, not proof of a single deadlock.
# On2026-10-11 the user explicitly approved only this normal host stop
# command wait at30 s; target deadlines and240 s fault recovery stay intact.
HOST_LIFECYCLE_STOP_COMMAND_WAIT_SECONDS = 30

# RG509 preserved five original 8 s timeouts; the SAME q processes returned
# real pending receipts at 8.016--8.719 s with continued stat/hash/lifetime
# checks, not an EOF-only stall. The prior 12 s allowance added 3.281 s above
# that measured maximum. RG513 preserved another original 12 s timeout, then
# the SAME q Popen returned actual PENDING WORKER_OBSERVED at 14.828 s.
# On 2026-10-10 the user explicitly approved a 20 s computer-side read wait.
# This current host allowance does not change camera/client deadlines,
# launch 8 s. Overflow propagates the original failure
# without retry; the earlier 8/12 s failures remain historical evidence.
HOST_LIFECYCLE_READ_COMMAND_WAIT_SECONDS = 20

# Full menu snapshots took 40.375 s on the same observed host process. The
# user approved 60 s for this action alone; ordinary read stays at 20 s.
HOST_LIFECYCLE_MENU_COMMAND_WAIT_SECONDS = 60

# BM preserved the disconnected 35 s failure, then first observed the same
# session's exact final78 at 160.390 s with the stock GUI restored and no stop
# request. This host-only wait starts AFTER launch returns, as wait_file always
# has; it is not a strict launch-to-finish cap or a camera performance claim.
HOST_DISCONNECTED_FINAL_WAIT_SECONDS = 240


@pytest.mark.parametrize("mutation", ("missing", "duplicate"))
@pytest.mark.parametrize("section,anchor", (
    pytest.param("temporary", "trap temporary_finish EXIT\n", id="recovery-boundary"),
    pytest.param("prelude", "core_equals() {", id="recovery-start"),
    pytest.param("prelude", '[ "$#" = 1 ] || exit 32\n', id="controller-arguments"),
    pytest.param("prelude", "runtime_identity || exit 32\n", id="runtime-admission"),
    pytest.param("prelude", 'absent "$transaction" || exit 33\n', id="transaction-admission"),
    pytest.param("prelude", " recover_needed=1\n stop camera-gui\n", id="stop-arm"),
    pytest.param("prelude", "rmdir /tmp/x2dii-menu-install.lock || recovered=0", id="unlock"),
    pytest.param("controller", "# A direct child, never an init restart", id="launch-start"),
    pytest.param("controller", 'launch_wait=0\nwhile [ "$launch_wait" -lt 50 ]; do', id="launch-end"),
    pytest.param("controller", "env X2DII_MENU_EXTENSION=1 ", id="launch-command"),
    pytest.param("controller", "\nchild_pid=$!", id="launch-pid"),
    pytest.param("common", 'ml_run="', id="bridge-start"),
    pytest.param("common", "ml_root=", id="bridge-root"),
))
def test_guardian_renderer_rejects_missing_or_duplicate_critical_anchor(installer, section, anchor, mutation):
    from tools import menu_lifecycle_transport as lifecycle
    guarded = lifecycle._guarded_sources

    def altered_template(temporary, common, manifest):
        prelude, controller = temporary.split("trap temporary_finish EXIT\n", 1)
        fragments = dict(temporary=temporary, prelude=prelude, controller=controller, common=common)
        assert fragments[section].count(anchor) == 1, "negative fixture must alter exactly one real anchor"
        fragments[section] = fragments[section].replace(anchor, "" if mutation == "missing" else anchor + anchor, 1)
        if section in ("prelude", "controller"):
            temporary = fragments["prelude"] + "trap temporary_finish EXIT\n" + fragments["controller"]
        else:
            temporary = fragments["temporary"]
        return guarded(temporary, fragments["common"], manifest)

    with mock.patch.object(lifecycle, "_guarded_sources", side_effect=altered_template):
        with pytest.raises(ValueError):
            lifecycle.render_programs(installer.manifest)


def test_fixed_lifecycle_entry_fits_maintenance_while_two_argument_call_does_not(installer):
    from tools import menu_lifecycle_transport as lifecycle
    values = temporary_values(installer)
    values.update(observer_domain="u:r:hbl_camera_service:s0", observer_exe_target="/system/bin/camera-test")
    raw = sc.encode_session(values, schema=sc.MENU_VALIDATION_SCHEMA)
    paths = lifecycle.paths(installer.manifest, raw)
    old = f"sh {paths['t']} {paths['session']} {peer.sha(raw)}"
    with pytest.raises(ValueError, match="capacity"):
        maintenance.envelope(old, "123456abcdef")
    for action in ("launch", "read", "stop"):
        command = lifecycle.command(installer.manifest, raw, action=action)
        framed, _, _ = maintenance.envelope(command, "123456abcdef")
        assert len(framed.encode()) < 232
        assert command.split()[-1] == peer.sha(raw)
        assert len(command.split()) == 3


def _host_sha_capture_pipelines(source):
    """Avoid a host pipeline child inside an already isolated SHA capture."""
    def scoped(match):
        pipeline = match.group()
        # The capture contains one printf-to-hash pipeline and no nested
        # capture or later command. lastpipe's variables/options therefore
        # remain inside this original command-substitution lifetime.
        assert pipeline.count("$(") == 1 and pipeline.count(" | ") == 1
        return "$(shopt -s lastpipe; " + pipeline[2:]

    result, count = re.subn(r"\$\(printf [^\n]*? \| sha256sum\)", scoped, source)
    assert count > 0, "host SHA capture anchors changed"
    return result


@pytest.mark.parametrize("initial_lastpipe", (False, True), ids=("outer-off", "outer-on"))
@pytest.mark.parametrize("case,capture_input", (
    ("empty", ""),
    ("missing-final-lf", "no final newline"),
    ("nul-crlf-repeated-lf", r"first\0last\r\n\n"),
    ("65536-bytes", "x" * 65536),
    ("partial-output-status-7", "payload"),
    ("native-closed-fd", "payload"),
    ("producer-pipefail-status-9", "unused"),
), ids=("empty", "missing-final-lf", "nul-crlf-repeated-lf", "65536-bytes",
        "partial-output-status-7", "native-closed-fd", "producer-pipefail-status-9"))
def test_host_sha_capture_preserves_native_bytes_errors_and_outer_lifetime(
        installer, record_property, initial_lastpipe, case, capture_input):
    """Execute the actual host transformer at the existing native-shell seam.

    JUnit retains raw output/error/trace bytes, not a hand-entered PASS summary.
    Native SHA still runs once per capture; injected faults are OS-boundary
    controls and do not establish camera behavior or a timing improvement.
    """
    installer.shell_fixture(stage_inputs=False)
    header = "#!/system/bin/sh\n# SESSION_DATA_PARSER_BEGIN\n# SESSION_DATA_PARSER_END\n"
    configuration = (
        ("shopt -s lastpipe\n" if initial_lastpipe else "shopt -u lastpipe\n") +
        "set +m\ncapture_marker=outer\n" +
        "capture_input=" + peer.shlex.quote(capture_input) + "\n")
    hash_body = "capture_marker=inside\n /usr/bin/sha256sum\n"
    native_redirect = ""
    if case == "partial-output-status-7":
        hash_body = ("capture_marker=inside\n /usr/bin/sha256sum > /dev/null || return $?\n"
                     " builtin printf 'partial-output\\n\\n'\n"
                     " builtin printf 'boundary-native-sha-error\\n' >&2\n return 7\n")
    elif case == "native-closed-fd":
        hash_body = "capture_marker=inside\n /usr/bin/sha256sum <&-\n"
        native_redirect = " <&-"
    elif case == "producer-pipefail-status-9":
        configuration += ("set -o pipefail\n"
                          "printf() { builtin printf '%s' produced; return 9; }\n")
    configuration += "sha256sum() {\n " + hash_body + "}\n"
    original_source = header + configuration + r'''
shopt -q lastpipe; capture_option_before=$?
exec 19> "$fixture/capture-native.trace"
BASH_XTRACEFD=19
PS4='+HOST_CAPTURE:'
set -x
capture_value=$(printf '%b' "$capture_input" | sha256sum)
capture_status=$?
set +x
shopt -q lastpipe; capture_option_after=$?
builtin printf '%s:%s:%s\n' "$capture_marker" "$capture_option_before" "$capture_option_after" > "$fixture/capture-outer.state"
builtin printf '%s' "$capture_value"
exit "$capture_status"
'''
    modified_source = _host_sha_capture_pipelines(original_source)
    native_source = (header + configuration +
                     "printf '%b' \"$capture_input\" | /usr/bin/sha256sum" + native_redirect +
                     "\nnative_status=$?\nexit \"$native_status\"\n")
    installer.scripts["capture-native-reference"] = native_source
    native = installer.run_script("capture-native-reference")
    observations = {}
    for variant, source in (("original", original_source), ("modified", modified_source)):
        installer.scripts["capture-control"] = source
        result = installer.run_script("capture-control")
        trace = (installer.root / "capture-native.trace").read_bytes()
        outer = (installer.root / "capture-outer.state").read_bytes()
        observations[variant] = dict(
            source_sha256=peer.sha(source.encode("ascii")), returncode=result.returncode,
            stdout_hex=result.stdout.hex(), stderr_hex=result.stderr.hex(),
            trace_hex=trace.hex(), outer_state_hex=outer.hex())
    record_property("native_capture_raw_evidence", json.dumps(dict(
        case=case, initial_lastpipe=initial_lastpipe,
        test_source_sha256=peer.sha((peer.ROOT / "tests/test_menu_lifecycle_transport.py").read_bytes()),
        native_sha_exe_sha256=peer.sha((SH.parent.parent / "usr/bin/sha256sum.exe").read_bytes()),
        native_reference=dict(returncode=native.returncode, stdout_hex=native.stdout.hex(),
                              stderr_hex=native.stderr.hex()), observations=observations), sort_keys=True))
    original, modified = (observations[name] for name in ("original", "modified"))
    for field in ("returncode", "stdout_hex", "stderr_hex", "outer_state_hex"):
        assert modified[field] == original[field], (case, field, observations)
    if case == "partial-output-status-7":
        expected = (7, b"partial-output", b"boundary-native-sha-error\n")
    else:
        expected = (native.returncode, native.stdout.rstrip(b"\n"), native.stderr)
        assert native.returncode == (1 if case == "native-closed-fd" else
                                     9 if case == "producer-pipefail-status-9" else 0)
    assert (original["returncode"], bytes.fromhex(original["stdout_hex"]),
            bytes.fromhex(original["stderr_hex"])) == expected
    expected_option = b"0" if initial_lastpipe else b"1"
    for variant, observation in observations.items():
        trace = bytes.fromhex(observation["trace_hex"])
        native_calls = [line for line in trace.splitlines()
                        if line.lstrip(b"+").startswith(b"HOST_CAPTURE:/usr/bin/sha256sum")]
        assert len(native_calls) == 1, (variant, trace)
        # This is executed-shell evidence that the transformed capture, not
        # just a source comparison or an unrelated hash test, was exercised.
        assert (b"HOST_CAPTURE:shopt -s lastpipe" in trace) == (variant == "modified")
        assert bytes.fromhex(observation["outer_state_hex"]) == (
            b"outer:" + expected_option + b":" + expected_option + b"\n")


def _trace_host_gate_checks(source):
    """Trace existing gate checks only in the host copy, without extra checks."""
    anchor = "mg_gate() {\n"
    assert source.count(anchor) == 1
    start = source.index(anchor)
    end = source.index("\n}\n", start) + 3
    gate = source[start:end]
    checks = (
        ("mg_transaction", 2), ("mg_worker", 3), ("mg_controller", 2),
        ("readonly_system", 2), ("mg_official", 2), ("unchanged_core", 2),
        ("preplaced_files", 2), ('process_birth "$$"', 1),
        ('[ "${mg_gate_birth#*:}" = "$ml_pid" ]', 1),
        ('[ "$mg_gate_wait" -lt 50 ]', 1),
        ('ml_absent "$ml_run/child.cancel"', 1), ("fresh", 1),
        ('ml_absent "$ml_run/child.admit"', 1),
        ('ml_equals "$mg_gate_identity" ml_line "$ml_run/child.offer"', 1),
        ('ml_equals "$mg_gate_identity" ml_line "$ml_run/child.admit"', 1),
        ("quiescent", 1), ("sleep .1", 1),
    )
    for index, (check, count) in enumerate(checks):
        assert gate.count(check) == count, (check, gate.count(check), count)
        gate = gate.replace(check, f"test_gate_check check-{index:02d} " + check)
    return source[:start] + gate + source[end:]


def background_fixture(installer, *, request_stop=True, setup=True, extra_hook="",
                       raw_session=None, staged_programs=False, persistent_child=False):
    from tools import menu_lifecycle_transport as lifecycle
    if setup:
        installer.shell_fixture()
        prepare_maintenance(installer)
    (installer.root / "proc/234/environ").write_bytes(b"XDG_RUNTIME_DIR=/tmp\0")
    raw = (raw_session if raw_session is not None else
           sc.encode_session(temporary_values(installer), schema=sc.MENU_VALIDATION_SCHEMA))
    fixed = lifecycle.paths(installer.manifest, raw)
    program_root = installer.root / fixed["root"].lstrip("/")
    if staged_programs:
        assert program_root.is_dir()
        programs = {name: (program_root / name).read_bytes().decode("ascii") for name in "lwtqs"}
    else:
        programs = lifecycle.render_programs(installer.manifest)
        program_root.mkdir(parents=True, exist_ok=True)
    data_path = installer.root / fixed["session"].lstrip("/")
    if staged_programs:
        assert data_path.read_bytes() == raw
    else:
        data_path.parent.mkdir(parents=True, exist_ok=True)
        data_path.write_bytes(raw)
    os_boundary = temporary_os_boundary(installer, request_stop=request_stop)
    if persistent_child:
        os_boundary = _persistent_gui_boundary(os_boundary)
    # The existing OS adapter has one simulated GUI stat.
    birth_line = next(line for line in os_boundary.splitlines()
                      if '(camera-gui) S' in line and '77700' in line)
    os_boundary = os_boundary.replace(birth_line, ''' if [ "${lifecycle_gate_exec:-0}" = 1 ]; then
  /usr/bin/cat "/proc/$test_child/stat" > "$fixture/proc/$test_child/stat"
  /usr/bin/cat "/proc/$test_child/stat" > "$fixture/test-child-host-stat"
  /usr/bin/rm -f "$fixture/proc/$test_child/host-shell"
 else
''' + birth_line + '''
 fi''', 1)
    observed_epoch = sc.decode_session(raw)["observed_epoch"]
    # MSYS helper startup is not modeled camera time. Couple epoch to the
    # requested sleeps whose physical host yield is already accelerated.
    # date is sampled in subshells but only reads the owning role's counter.
    # Scenario-specific date/sleep hooks below retain their own exact clocks.
    clock = f'''
test_lifecycle_elapsed_tenths=0
date() {{
 if [ "$#" = 2 ] && [ "$1" = -u ] && [ "$2" = +%s ]; then
  printf '%s\\n' "$(({observed_epoch}+test_lifecycle_elapsed_tenths/10))"
 else /usr/bin/date "$@"; fi
}}
sleep() {{
 case "$*" in
  .1) test_lifecycle_elapsed_tenths=$((test_lifecycle_elapsed_tenths+1));;
  1) test_lifecycle_elapsed_tenths=$((test_lifecycle_elapsed_tenths+10));;
  *) return 92;;
 esac
 /usr/bin/sleep .02
}}
'''
    hook = os_boundary + clock + r'''
# Host /proc adapter for the actual detached shell processes only.
/usr/bin/mkdir -p "$fixture/proc/$$/attr"
# Keep the real birth separate from the mutable modeled kernel state. EXIT
# removes model stat, and a later modeled reboot may replace it with fake init.
/usr/bin/cat "/proc/$$/stat" > "$fixture/proc/$$/host-stat"
/usr/bin/cp "$fixture/proc/$$/host-stat" "$fixture/proc/$$/stat"
printf 'u:r:hbl_camera_service:s0\n' > "$fixture/proc/$$/attr/current"
printf '\n' > "$fixture/proc/$$/maps"
/usr/bin/cp "$fixture/system/bin/sh" "$fixture/proc/$$/exe"
printf shell > "$fixture/proc/$$/host-shell"
printf '%s\000' "$fixture/system/bin/sh" "$0" "$@" > "$fixture/proc/$$/cmdline"
lifecycle_fixture_retire() {
 # Only the non-recovery l/q/s roles retire their complete kernel snapshot.
 # Leaving their maps behind makes every subsequent global maps scan visit
 # departed readers. Do not change t/w's existing trap/recovery semantics.
 [ "$BASHPID" = "$$" ] || return 0
 case "${0##*/}" in l|q|s) :;; *) return 0;; esac
 test_retire_proc="$fixture/proc/$$"
 [ -e "$test_retire_proc" ] || return 0
 [ -d "$test_retire_proc" ] && [ ! -L "$test_retire_proc" ] &&
 [ -d "$test_retire_proc/attr" ] && [ ! -L "$test_retire_proc/attr" ] || return 92
 # Remove only this adapter's known leaves, never recursive/unknown content.
 /usr/bin/rm -f "$test_retire_proc/stat" "$test_retire_proc/host-stat" \
  "$test_retire_proc/attr/current" "$test_retire_proc/maps" "$test_retire_proc/exe" \
  "$test_retire_proc/host-shell" "$test_retire_proc/cmdline" || return 92
 /usr/bin/rmdir "$test_retire_proc/attr" "$test_retire_proc" || return 92
}
lifecycle_fixture_finish() {
 test_retire_prior_status=$?
 trap - EXIT
 if lifecycle_fixture_retire; then :; else
  builtin printf '%s\n' HOST_PROC_RETIREMENT_INCOMPLETE >&2
  [ "$test_retire_prior_status" != 0 ] || test_retire_prior_status=92
 fi
 builtin exit "$test_retire_prior_status"
}
case "${0##*/}" in
 l|q|s) trap lifecycle_fixture_finish EXIT;;
 *) trap '/usr/bin/rm -f "$fixture/proc/$$/stat"' EXIT;;
esac
test_lifecycle_readlink=$(declare -f readlink)
eval "${test_lifecycle_readlink/readlink/test_before_lifecycle_readlink}"
readlink() {
 if [ "${1##*/}" = exe ] && [ -f "${1%/exe}/host-shell" ]; then
  printf '%s\n' "$fixture/system/bin/sh"
 else test_before_lifecycle_readlink "$@"; fi
}
cat() {
 if [ "$#" = 1 ] && [ "${1##*/}" = stat ] && [ -f "${1%/stat}/host-shell" ]; then
  test_stat_pid=${1%/stat}; test_stat_pid=${test_stat_pid##*/}
  if [ ! -e "/proc/$test_stat_pid/stat" ]; then
   /usr/bin/rm -f "$1"
   return 1
  fi
  /usr/bin/cat "/proc/$test_stat_pid/stat"
 else /usr/bin/cat "$@"; fi
}
lifecycle_fixture_exit() {
 case "${0##*/}" in
  l|q|s)
   if lifecycle_fixture_retire; then :; else
    builtin printf '%s\n' HOST_PROC_RETIREMENT_INCOMPLETE >&2
   fi;;
  *) if [ "$BASHPID" = "$$" ]; then /usr/bin/rm -f "$fixture/proc/$$/stat"; fi;;
 esac
 builtin exit "$@"
}
test_exec_transition() { :; }
test_gate_check() {
 # Only shell builtins write diagnostics. The existing command executes once
 # with its original stdout/stderr; retain its exact status after logging.
 test_gate_check_name=$1
 builtin printf 'BEGIN pid=%s bashpid=%s epoch=%s wait=%s check=%s\n' \
  "$$" "$BASHPID" "$EPOCHREALTIME" "${mg_gate_wait-unset}" "$test_gate_check_name" \
  2>/dev/null >> "$fixture/host-gate-checks.log" || :
 shift
 "$@"
 test_gate_check_status=$?
 builtin printf 'END pid=%s bashpid=%s epoch=%s wait=%s check=%s status=%s\n' \
  "$$" "$BASHPID" "$EPOCHREALTIME" "${mg_gate_wait-unset}" "$test_gate_check_name" "$test_gate_check_status" \
  2>/dev/null >> "$fixture/host-gate-checks.log" || :
 return "$test_gate_check_status"
}
lifecycle_fixture_exec_env() {
 # exec replaces the shell; its noclobber option is not an option of the GUI.
 # Generated GUI-log redirection already ran before this OS-boundary adapter.
 set +C
 test_exec_transition env
 lifecycle_gate_exec=1
 env "$@"
 lifecycle_fixture_exit $?
}
lifecycle_fixture_exec_gui() {
 set +C
 # Do not preload an Android ELF into MSYS tools used to simulate /proc. Keep
 # the value for the simulated GUI environment, without exporting it to host
 # helper processes; a real exec would not execute those fixture helpers.
 export -n LD_PRELOAD
 test_exec_transition direct
 lifecycle_gate_exec=1
 env "X2DII_MENU_EXTENSION=$X2DII_MENU_EXTENSION" "LD_PRELOAD=$LD_PRELOAD" \
  "XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR" "XDG_CACHE_HOME=$XDG_CACHE_HOME" \
  "QT_QPA_FONTDIR=$QT_QPA_FONTDIR" "$fixture/system/bin/camera-gui" "$@"
 lifecycle_fixture_exit $?
}
test_os_stat=$(declare -f fixture_stat)
eval "${test_os_stat/fixture_stat/test_original_fixture_stat}"
fixture_stat() {
 if [ "$3" = "$fixture/proc/self/fd/3" ]; then
  /usr/bin/stat "$1" "$2" /proc/self/fd/3
 elif [ "$3" = "$fixture/proc/self/fd/4" ]; then
  /usr/bin/stat "$1" "$2" /proc/self/fd/4
 else test_original_fixture_stat "$@"; fi
}
''' + extra_hook
    for name, source in programs.items():
        if not staged_programs:
            (program_root / name).write_bytes(source.encode("ascii"))
        # Only the OS exec/exit seam is adapted. bash invoked as sh disallows
        # functions named after those special builtins.
        host_source = _host_sha_capture_pipelines(source)
        if name == "t":
            host_source = _trace_host_gate_checks(host_source)
        installer.scripts["lifecycle"] = host_source.replace("exit ", "lifecycle_fixture_exit ").replace(
            "exec env ", "lifecycle_fixture_exec_env ").replace(
            "exec /system/bin/camera-gui ", "lifecycle_fixture_exec_gui ")
        with mock.patch.object(peer, "session_data", return_value=raw):
            translated = installer.run_script("lifecycle", boundary_hook=hook,
                process_runner=lambda text, args: text)
        (installer.root / (".host-lifecycle-" + name + ".sh")).write_text(translated, encoding="ascii", newline="\n")
    shell = installer.root / "system/bin/sh"
    shell.write_text(f'''#!/usr/bin/sh
host_original=$1
shift
host_leaf=${{host_original##*/}}
exec /usr/bin/sh -c 'host_script=$1; shift; . "$host_script"' "$host_original" {installer.posix}/.host-lifecycle-$host_leaf.sh "$@"
''', encoding="ascii", newline="\n")

    def run(action):
        # Fixed one-SHA command; q's only optional token is the fixed menu mode.
        # Keep the original arguments from the validated production command.
        original = lifecycle.command(installer.manifest, raw, action=action)
        maintenance.envelope(original, "123456abcdef")
        _, script, *arguments = original.split()
        timeout = {"launch": 8, "read": HOST_LIFECYCLE_READ_COMMAND_WAIT_SECONDS,
                   "menu": HOST_LIFECYCLE_MENU_COMMAND_WAIT_SECONDS,
                   "stop": HOST_LIFECYCLE_STOP_COMMAND_WAIT_SECONDS}[action]
        return subprocess.run([str(SH), installer.posix + "/system/bin/sh",
            installer.posix + script, *arguments], capture_output=True, text=True, timeout=timeout)

    return raw, fixed, programs, run


def test_background_menu_query_reuses_launched_attempt_without_inventing_ui_success(installer):
    """Real q on the same host lifecycle; not a Qt/device readiness claim."""
    from tools import menu_lifecycle_transport as lifecycle
    raw, fixed, _, run = background_fixture(installer)
    actions = []

    class Maintenance:
        def command(self, label, command):
            action = {"lifecycle-launch": "launch", "lifecycle-read": "read",
                      "lifecycle-stop": "stop", "lifecycle-menu": "menu"}[label]
            assert command == lifecycle.command(installer.manifest, raw, action=action)
            actions.append(action)
            result = run(action)
            assert result.returncode == 0, (result.stdout, result.stderr)
            return result.stdout

    sender = lifecycle.TemporaryLifecycle(installer.manifest, raw, Maintenance())
    try:
        with pytest.raises(ValueError, match="unfinished|attempted"):
            sender.read_menu()
        assert actions == []
        assert sender.launch()["status"] == "STARTED_NOT_VALIDATED"
        result = sender.read_menu()
        assert result["status"] == "MENU_UNKNOWN" and result["reason"] == "NOT_READY"
        assert result["session_sha256"] == peer.sha(raw)
        assert result["candidate_sha256"] == installer.manifest["candidate_sha256"]
        assert result["boot_id"] == sc.decode_session(raw)["boot_id"]
        assert result["ready"] is False and result["feature_validated"] is False
        assert sender.final is None
        with pytest.raises(ValueError, match="attempted"):
            sender.launch()
        assert actions == ["launch", "menu"]
        folder = installer.root / fixed["run"].lstrip("/")
        assert (folder / "attempt").read_bytes() == (peer.sha(raw) + "\n").encode()
    except BaseException as failure:
        _retain_guardian_failure(installer, failure)
        raise
    finally:
        _cleanup_guardian_fixture(installer)


@pytest.mark.parametrize("writer", ("bound", "stderr-other"))
def test_shared_menu_query_binds_actual_child_stdout_and_stderr(installer, writer):
    """Modeled GUI reports from a real child, not actual Qt/device readiness."""
    from tools import menu_lifecycle_transport as lifecycle
    hook = r'''
test_menu_previous_env=$(declare -f env)
eval "${test_menu_previous_env/env/test_menu_previous_env}"
env() {
 TEST_MENU_STDERR
 builtin printf '%s\n' 'qml: X2DII_MENU_STATE_V1:1:0:0:0:0:0:-1:-1' \
  'qml: X2DII_MENU_STATE_V1:2:1:1:1:1:1:12:11'
 test_menu_previous_env "$@"
}
test_menu_native_fd() {
 test_menu_relative=${1#"$fixture/proc/"}
 test_menu_pid=${test_menu_relative%%/fd/*}
 test_menu_fd=${test_menu_relative##*/}
 test_menu_recorded_pid=$(/usr/bin/cat "$fixture/test-child-pid") || return $?
 [ "$test_menu_pid" = "$test_menu_recorded_pid" ] || return 91
 test_menu_saved_stat=$(/usr/bin/cat "$fixture/test-child-host-stat") || return $?
 [ "${test_menu_saved_stat%% *}" = "$test_menu_pid" ] || return 91
 test_menu_tail=${test_menu_saved_stat##*) }
 [ "$test_menu_tail" != "$test_menu_saved_stat" ] || return 91
 set -f; set -- $test_menu_tail
 [ "$#" -ge 20 ] || return 91
 shift 19; test_menu_expected_ticks=$1
 test_menu_current_stat=$(/usr/bin/cat "/proc/$test_menu_pid/stat") || return $?
 [ "${test_menu_current_stat%% *}" = "$test_menu_pid" ] || return 91
 test_menu_tail=${test_menu_current_stat##*) }
 [ "$test_menu_tail" != "$test_menu_current_stat" ] || return 91
 set -- $test_menu_tail
 [ "$#" -ge 20 ] || return 91
 shift 19; [ "$1" = "$test_menu_expected_ticks" ] || return 91
 builtin printf '/proc/%s/fd/%s' "$test_menu_pid" "$test_menu_fd"
}
test_menu_previous_readlink=$(declare -f readlink)
eval "${test_menu_previous_readlink/readlink/test_menu_previous_readlink}"
readlink() {
 if [ "$#" = 1 ]; then
  case "$1" in "$fixture/proc/"*/fd/[12])
   test_menu_native_path=$(test_menu_native_fd "$1") || return $?
   builtin printf 'readlink %s\n' "$test_menu_native_path" >> "$fixture/test-menu-fd-observations"
   /usr/bin/readlink "$test_menu_native_path"; return $?;;
  esac
 fi
 test_menu_previous_readlink "$@"
}
stat() {
 if [ "$#" = 3 ] && [ "$1" = -Lc ] && [ "$2" = '%d:%i' ]; then
  case "$3" in "$fixture/proc/"*/fd/[12])
   test_menu_native_path=$(test_menu_native_fd "$3") || return $?
   builtin printf 'stat %s\n' "$test_menu_native_path" >> "$fixture/test-menu-fd-observations"
   /usr/bin/stat "$1" "$2" "$test_menu_native_path"; return $?;;
  esac
 fi
 fixture_stat "$@"
}
'''.replace("TEST_MENU_STDERR", "exec 2>/dev/null" if writer == "stderr-other" else ":")
    raw, fixed, _, run = background_fixture(
        installer, request_stop=False, persistent_child=True, extra_hook=hook)
    actions = []

    class Maintenance:
        def command(self, label, command):
            action = {"lifecycle-launch": "launch", "lifecycle-read": "read",
                      "lifecycle-stop": "stop", "lifecycle-menu": "menu"}[label]
            assert command == lifecycle.command(installer.manifest, raw, action=action)
            actions.append(action)
            result = run(action)
            assert result.returncode == 0, (result.stdout, result.stderr)
            return result.stdout

    sender = lifecycle.TemporaryLifecycle(installer.manifest, raw, Maintenance())
    try:
        sender.launch()
        folder = installer.root / fixed["run"].lstrip("/")
        transaction = installer.root / fixed["transaction"].lstrip("/")
        namespace = sc.decode_session(raw)["core_gui_mount_namespace"]
        wait_file(transaction / "child.identity", contains=("namespace=" + namespace + "\n").encode(),
                  seconds=HOST_LIFECYCLE_PREINJECTION_WAIT_SECONDS)
        result = sender.read_menu()
        if writer == "bound":
            assert result["status"] == "MENU_SNAPSHOT_NOT_FEATURE_VALIDATED", result["raw_reply"]
            pid = (installer.root / "test-child-pid").read_text().strip()
            host_stat = (installer.root / "test-child-host-stat").read_text()
            ticks = host_stat.rsplit(") ", 1)[1].split()[19]
            assert (folder / "child.admit").read_bytes() == (pid + ":" + ticks + "\n").encode()
            assert result["pid"] == int(pid) and result["start_ticks"] == ticks
            log = installer.root / fixed["transaction"].lstrip("/") / "gui.log"
            assert log.read_bytes() == (b"qml: X2DII_MENU_STATE_V1:1:0:0:0:0:0:-1:-1\n"
                                        b"qml: X2DII_MENU_STATE_V1:2:1:1:1:1:1:12:11\n")
            assert result["log_sha256"] == peer.sha(log.read_bytes())
            assert all(result[key] is True for key in (
                "ready", "model_matched", "button_instantiated", "visible", "eligible"))
            assert result["generation"] == 1 and result["sequence"] == 2
            assert result["grid_count"] == 12 and result["extension_index"] == 11
        else:
            assert result["status"] == "MENU_UNKNOWN" and result["reason"] == "IDENTITY_CHANGED"
            assert result["ready"] is False
        fd_queries = (installer.root / "test-menu-fd-observations").read_text().splitlines()
        native_pid = (installer.root / "test-child-pid").read_text().strip()
        expected_queries = ["readlink /proc/" + native_pid + "/fd/1", "stat /proc/" + native_pid + "/fd/1",
                            "readlink /proc/" + native_pid + "/fd/2"]
        if writer == "bound":
            assert fd_queries == (expected_queries + ["stat /proc/" + native_pid + "/fd/2"]) * 2
        else:
            assert fd_queries == expected_queries
        assert result["feature_validated"] is False and sender.final is None
        with pytest.raises(ValueError, match="attempted"):
            sender.launch()
        sender.stop()
        assert ":0:NOT_FEATURE_VALIDATED\n" in read_until_final(run, seconds=240)
        final = sender.read()
        assert final["exit_code"] == 0 and final["feature_validated"] is False
        assert sender.final == final and final["session_sha256"] == peer.sha(raw)
        assert actions == ["launch", "menu", "stop", "read"]
        assert (installer.root / "gui-service-state").read_text() == "running"
    except BaseException as failure:
        _retain_guardian_failure(installer, failure)
        raise
    finally:
        _cleanup_guardian_fixture(installer)


@pytest.mark.parametrize("role", ("w", "t", "q"))
@pytest.mark.parametrize("explicit_epoch", (False, True))
def test_host_clock_counts_requested_sleeps_without_helper_time_or_lost_subshell_state(installer, role, explicit_epoch):
    observed = int(peer.datetime.fromisoformat(installer.q["observed_utc"]).timestamp())
    hook = f'date() {{ printf "%s\\n" {observed + 599}; }}\n' if explicit_epoch else ""
    raw, fixed, programs, _ = background_fixture(installer, extra_hook=hook)
    originals = {name: (installer.root / fixed[name].lstrip("/")).read_bytes() for name in "lwtqs"}
    host_copy = installer.root / (".host-lifecycle-" + role + ".sh")
    # Exercise the existing installed OS adapter through its original role
    # path, stopping before the unchanged production parser/operation body.
    translated = host_copy.read_text()
    program_header = "#!" + installer.posix + "/system/bin/sh\n"
    assert translated.count(program_header) == 1
    prefix = translated.split(program_header, 1)[0]
    body = r'''
clock_start=$(date -u +%s)
printf '%s\n' "$clock_start"
clock_repeated=$(date -u +%s)
printf '%s\n' "$clock_repeated"
for clock_tenth in 1 2 3 4 5 6 7 8 9 10; do sleep .1; done
clock_after_tenths=$(date -u +%s)
printf '%s\n' "$clock_after_tenths"
sleep 1
clock_after_second=$(date -u +%s)
printf '%s\n' "$clock_after_second"
/usr/bin/sleep .05
clock_after_helper=$(date -u +%s)
printf '%s\n' "$clock_after_helper"
'''
    host_copy.write_text(prefix + body, encoding="ascii", newline="\n")
    invocation = [str(SH), installer.posix + "/system/bin/sh", installer.posix + fixed[role], peer.sha(raw)]
    first = subprocess.run(invocation, capture_output=True, text=True, timeout=8)
    second = subprocess.run(invocation, capture_output=True, text=True, timeout=8)
    for result in (first, second):
        assert result.returncode == 0 and result.stderr == "", (result.stdout, result.stderr)
        expected = [observed + 599] * 5 if explicit_epoch else [observed, observed, observed + 1, observed + 2, observed + 2]
        assert [int(epoch) for epoch in result.stdout.splitlines()] == expected
    assert {name: (installer.root / fixed[name].lstrip("/")).read_bytes() for name in "lwtqs"} == originals
    assert programs == {name: originals[name].decode("ascii") for name in "lwtqs"}
    assert not (installer.root / "operations").exists()


def read_until_final(run, *, seconds=HOST_LIFECYCLE_RECEIPT_WAIT_SECONDS):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = run("read")
        assert result.returncode == 0, (result.stdout, result.stderr)
        if result.stdout.startswith("X2DII_LIFECYCLE_FINAL:"):
            return result.stdout
        # Publication and the independent owner read are not a single kernel
        # snapshot: the owner may exit after q checked for final. UNCERTAIN
        # grants no success; a later actual final receipt is still required.
        assert result.stdout.startswith(("X2DII_LIFECYCLE_PENDING:",
                                         "X2DII_LIFECYCLE_UNCERTAIN:")), result.stdout
        time.sleep(.05)
    pytest.fail("detached lifecycle did not create a bounded final receipt")


@pytest.mark.parametrize("seconds,elapsed,expect_final", (
    (None, 187.109, True), (None, 239.999, True), (None, 274, True),
    (None, 359.999, True), (None, 360, False),
    (240, 239.999, True), (240, 240, False),
    (90, 89.999, True), (90, 90, False),
))
def test_host_receipt_wait_measured_bound_remains_finite(seconds, elapsed, expect_final):
    final = "X2DII_LIFECYCLE_FINAL:" + "a" * 64 + ":" + peer.sha(("a" * 64 + ":0\n").encode()) + ":0:NOT_FEATURE_VALIDATED\n"
    run = mock.Mock(return_value=SimpleNamespace(returncode=0, stdout=final, stderr=""))
    arguments = {} if seconds is None else {"seconds": seconds}
    with mock.patch.object(time, "monotonic", side_effect=(1000, 1000 + elapsed)):
        if expect_final:
            assert read_until_final(run, **arguments) == final
            run.assert_called_once_with("read")
        else:
            with pytest.raises(pytest.fail.Exception, match="bounded final receipt"):
                read_until_final(run, **arguments)
            run.assert_not_called()


@pytest.mark.parametrize("seconds", (None, 35))
def test_host_receipt_sequence_needs_actual_final_after_pending_and_uncertain(seconds):
    final = "X2DII_LIFECYCLE_FINAL:" + "a" * 64 + ":" + peer.sha(("a" * 64 + ":0\n").encode()) + ":0:NOT_FEATURE_VALIDATED\n"
    replies = ("X2DII_LIFECYCLE_PENDING:" + "a" * 64 + "\n",
               "X2DII_LIFECYCLE_UNCERTAIN:" + "a" * 64 + "\n", final)
    run = mock.Mock(side_effect=[SimpleNamespace(returncode=0, stdout=reply, stderr="") for reply in replies])
    with mock.patch.object(time, "monotonic", side_effect=(1000, 1000, 1034, 1187.109)), \
         mock.patch.object(time, "sleep") as sleep:
        if seconds is None:
            assert read_until_final(run) == final
            assert run.call_args_list == [mock.call("read")] * 3
        else:
            with pytest.raises(pytest.fail.Exception, match="bounded final receipt"):
                read_until_final(run, seconds=seconds)
            assert run.call_args_list == [mock.call("read")] * 2
        assert sleep.call_args_list == [mock.call(.05), mock.call(.05)]


def test_host_receipt_sequence_without_final_exhausts_deadline_without_success():
    replies = ("X2DII_LIFECYCLE_PENDING:" + "a" * 64 + "\n",
               "X2DII_LIFECYCLE_UNCERTAIN:" + "a" * 64 + "\n")
    run = mock.Mock(side_effect=[SimpleNamespace(returncode=0, stdout=reply, stderr="") for reply in replies])
    with mock.patch.object(time, "monotonic", side_effect=(1000, 1000, 1239.999, 1240)), \
         mock.patch.object(time, "sleep") as sleep:
        with pytest.raises(pytest.fail.Exception, match="bounded final receipt"):
            read_until_final(run, seconds=240)
    assert run.call_args_list == [mock.call("read")] * 2
    assert sleep.call_args_list == [mock.call(.05), mock.call(.05)]


@pytest.mark.parametrize("action,expected_timeout", (("launch", 8), ("read", 20), ("menu", 60), ("stop", 30)))
def test_host_command_wait_changes_only_stop_for_measured_reply(installer, action, expected_timeout):
    raw, _, _, run = background_fixture(installer)
    prefix = {"launch": "X2DII_LIFECYCLE_STARTED_NOT_VALIDATED:",
              "read": "X2DII_LIFECYCLE_PENDING:",
              "menu": "X2DII_MENU_UNKNOWN:",
              "stop": "X2DII_LIFECYCLE_STOP_REQUESTED_NOT_COMPLETED:"}[action]
    reply = prefix + peer.sha(raw) + (":NOT_READY" if action == "menu" else "") + "\n"

    def execute(invocation, *, capture_output, text, timeout):
        assert capture_output is True and text is True
        # Independent BH observation: the original stop took 11.172 s to
        # return its real ACK on the same Popen, after the 8 s timeout.
        # RG509 same-Popen reads returned actual receipts at up to 8.719 s.
        # The same menu snapshot process actually returned at 40.375 s.
        elapsed = {"launch": 0, "read": 8.719, "menu": 40.375, "stop": 11.172}[action]
        if elapsed > timeout:
            raise subprocess.TimeoutExpired(invocation, timeout)
        return subprocess.CompletedProcess(invocation, 0, reply, "")

    with mock.patch.object(subprocess, "run", side_effect=execute) as process:
        result = run(action)
    assert result.returncode == 0 and result.stdout == reply
    process.assert_called_once()
    assert process.call_args.kwargs["timeout"] == expected_timeout


def test_host_stop_deadline_overflow_propagates_original_timeout_without_retry(installer):
    _, _, _, run = background_fixture(installer)
    failures = []

    def execute(invocation, *, capture_output, text, timeout):
        assert capture_output is True and text is True
        assert timeout == 30
        if 30.001 > timeout:
            failure = subprocess.TimeoutExpired(invocation, timeout)
            failures.append(failure)
            raise failure
        return subprocess.CompletedProcess(invocation, 0, "must not fabricate an ACK", "")

    with mock.patch.object(subprocess, "run", side_effect=execute) as process:
        with pytest.raises(subprocess.TimeoutExpired) as caught:
            run("stop")
    assert caught.value is failures[0]
    process.assert_called_once()


@pytest.mark.parametrize("action,expected_timeout", (("read", 20), ("menu", 60)))
def test_host_read_deadline_overflow_propagates_original_timeout_without_retry(installer, action, expected_timeout):
    _, _, _, run = background_fixture(installer)
    failures = []

    def execute(invocation, *, capture_output, text, timeout):
        assert capture_output is True and text is True and timeout == expected_timeout
        if expected_timeout + .001 > timeout:
            failure = subprocess.TimeoutExpired(invocation, timeout)
            failures.append(failure)
            raise failure
        return subprocess.CompletedProcess(invocation, 0, "must not fabricate a receipt", "")

    with mock.patch.object(subprocess, "run", side_effect=execute) as process:
        with pytest.raises(subprocess.TimeoutExpired) as caught:
            run(action)
    assert caught.value is failures[0]
    process.assert_called_once()


def test_sender_receipt_wait_uses_same_measured_host_bound(installer):
    values = temporary_values(installer)
    values.update(observer_domain="u:r:hbl_camera_service:s0", observer_exe_target="/system/bin/camera-test")
    raw = sc.encode_session(values, schema=sc.MENU_VALIDATION_SCHEMA)
    digest = peer.sha(raw)
    receipt = peer.sha((digest + ":0\n").encode())

    def run(action):
        reply = ("X2DII_LIFECYCLE_STARTED_NOT_VALIDATED:" + digest + "\n" if action == "launch" else
                 "X2DII_LIFECYCLE_FINAL:" + digest + ":" + receipt + ":0:NOT_FEATURE_VALIDATED\n")
        return SimpleNamespace(returncode=0, stdout=reply, stderr="")

    with mock.patch(__name__ + ".background_fixture", return_value=(raw, {}, {}, run)), \
         mock.patch.object(time, "monotonic", side_effect=(1000, 1274)):
        test_fixed_sender_verifies_final_hash_and_does_not_invent_ui_success(installer)


def test_background_start_is_not_success_and_final_records_actual_t_exit(installer):
    raw, fixed, programs, run = background_fixture(installer)
    try:
        started = run("launch")
        assert started.returncode == 0, (started.stdout, started.stderr)
        assert started.stdout == "X2DII_LIFECYCLE_STARTED_NOT_VALIDATED:" + peer.sha(raw) + "\n"
        final = read_until_final(run)
        assert ":0:NOT_FEATURE_VALIDATED\n" in final
        assert (installer.root / "gui-service-state").read_text() == "running"
        assert (installer.root / "proc/mounts").read_text() == installer.mount_line
        transaction = installer.root / fixed["run"].lstrip("/")
        assert (transaction / "attempt").read_text() == peer.sha(raw) + "\n"
        assert (transaction / "final").is_file()
        before = {path.name: path.read_bytes() for path in transaction.iterdir() if path.is_file()}
        retry = run("launch")
        assert retry.returncode != 0
        assert {path.name: path.read_bytes() for path in transaction.iterdir() if path.is_file()} == before
    except BaseException as failure:
        _retain_guardian_failure(installer, failure)
        raise
    finally:
        _cleanup_guardian_fixture(installer)


def test_fixed_sender_verifies_final_hash_and_does_not_invent_ui_success(installer):
    from tools import menu_lifecycle_transport as lifecycle
    raw, fixed, programs, run = background_fixture(installer)

    class Maintenance:
        def command(self, label, command):
            action = {"lifecycle-launch": "launch", "lifecycle-read": "read",
                      "lifecycle-stop": "stop", "lifecycle-menu": "menu"}[label]
            assert command == lifecycle.command(installer.manifest, raw, action=action)
            result = run(action)
            if result.returncode:
                raise ValueError("fixed maintenance command failed")
            return result.stdout

    sender = lifecycle.TemporaryLifecycle(installer.manifest, raw, Maintenance())
    try:
        assert sender.launch()["status"] == "STARTED_NOT_VALIDATED"
        deadline = time.monotonic() + HOST_LIFECYCLE_RECEIPT_WAIT_SECONDS
        while time.monotonic() < deadline:
            result = sender.read()
            if result["status"] == "EXITED_NOT_FEATURE_VALIDATED":
                break
            assert result["status"] == "PENDING"
            time.sleep(.05)
        else:
            pytest.fail("sender did not retain actual final receipt")
        assert result["exit_code"] == 0 and result["feature_validated"] is False
        assert result["session_sha256"] == peer.sha(raw)
        with pytest.raises(ValueError, match="attempted"):
            sender.launch()
    except BaseException as failure:
        _retain_guardian_failure(installer, failure)
        raise
    finally:
        _cleanup_guardian_fixture(installer)


def wait_file(path, *, contains=None, seconds=35):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if path.is_file() and (contains is None or contains in path.read_bytes()):
            return
        time.sleep(.05)
    pytest.fail("expected bounded local process evidence missing: " + str(path))


def timeout_hook(installer, *, held=False):
    observed = int(peer.datetime.fromisoformat(installer.q["observed_utc"]).timestamp())
    expiry = '[ -f "$fixture/release-timeout" ] && ' if held else ""
    return f'''
printf() {{
 case "$*" in *X2DII_TEMPORARY_CHILD_LOADED_NOT_FEATURE_VERIFIED*) builtin printf used > "$fixture/loaded-event";; esac
 builtin printf "$@"
}}
date() {{
 if {expiry}[ -f "$fixture/loaded-event" ]; then
  if [ -f "$fixture/validation-started" ]; then echo {observed + 120}
  else
   # Only the actual controller owns its baseline. Worker supervision and
   # the same t program in gate mode must not consume that first sample.
   if [ "${{0##*/}}" = t ] && [ "${{mg_mode:-}}" = controller ]; then
    printf used > "$fixture/validation-started"
   fi
   echo {observed}
  fi
 else echo {observed}; fi
}}
'''


@pytest.mark.parametrize("held", (False, True))
@pytest.mark.parametrize("ordering", ("worker_first", "controller_first"))
def test_timeout_clock_preserves_controller_baseline_across_worker_reads(installer, ordering, held):
    raw, fixed, programs, _ = background_fixture(installer, request_stop=False,
        extra_hook=timeout_hook(installer, held=held))
    observed = int(peer.datetime.fromisoformat(installer.q["observed_utc"]).timestamp())
    controller_mode = "mg_mode=${2-controller}\n"
    assert programs["t"].count(controller_mode) == 1
    original_programs = {name: (installer.root / fixed[name].lstrip("/")).read_bytes() for name in "lwtqs"}
    (installer.root / "loaded-event").write_bytes(b"used")
    hook = timeout_hook(installer, held=held)

    def driver(role, body):
        # Keep the existing installed host-shell adapter: it preserves $0 as
        # the ORIGINAL fixed role path, not the translated host-copy filename.
        prefix = "fixture=" + installer.posix + "\n" + hook
        if role == "t":
            prefix += controller_mode
        (installer.root / (".host-lifecycle-" + role + ".sh")).write_text(
            prefix + 'printf "ROLE:%s\\n" "$0"\n' + body, encoding="ascii", newline="\n")

    def invocation(role):
        return [str(SH), installer.posix + "/system/bin/sh", installer.posix + fixed[role], peer.sha(raw)]

    def sample(role):
        result = subprocess.run(invocation(role), capture_output=True, text=True, timeout=8)
        assert result.returncode == 0 and result.stderr == "", (result.stdout, result.stderr)
        role_line, epoch = result.stdout.splitlines()
        assert role_line == "ROLE:" + installer.posix + fixed[role]
        return int(epoch)

    try:
        driver("w", "date -u +%s\n")
        if held:
            driver("t", "date -u +%s\n")
            assert sample("w") == observed and sample("t") == observed
            assert not (installer.root / "validation-started").exists()
            (installer.root / "release-timeout").write_bytes(b"release existing held clock\n")
        worker_epoch = sample("w") if ordering == "worker_first" else None
        driver("t", r'''date -u +%s > "$fixture/clock-controller-start"
IFS= read -r -t 8 clock_resume || exit 92
[ "$clock_resume" = resume ] || exit 93
date -u +%s
''')
        process = subprocess.Popen(invocation("t"), stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            wait_file(installer.root / "clock-controller-start", contains=b"\n", seconds=8)
            controller_start = int((installer.root / "clock-controller-start").read_text())
            if ordering == "controller_first":
                worker_epoch = sample("w")
            # Preserve the literal LF token on Windows; text-mode stdin would
            # add CR, which the real shell read intentionally does not strip.
            stdout_bytes, stderr_bytes = process.communicate(b"resume\n", timeout=8)
            stdout, stderr = stdout_bytes.decode("ascii"), stderr_bytes.decode("ascii")
            assert process.returncode == 0 and stderr == "", (stdout, stderr)
        finally:
            if process.poll() is None:
                process.kill()  # Only this test's owned Windows process handle.
            process.communicate(timeout=8)
        role_line, epoch = stdout.splitlines()
        assert role_line == "ROLE:" + installer.posix + fixed["t"]
        controller_now = int(epoch)
        print({"clock_ordering": ordering, "held": held, "observed": observed,
               "worker_epoch": worker_epoch, "controller_start": controller_start,
               "controller_now": controller_now, "controller_role": role_line,
               "physical_program_sha256": {name: peer.sha(content) for name, content in original_programs.items()}})
        assert {name: (installer.root / fixed[name].lstrip("/")).read_bytes() for name in "lwtqs"} == original_programs
        assert controller_start == observed, "worker reads must not consume the controller's baseline"
        assert controller_now == observed + 120
    except BaseException as failure:
        _retain_guardian_failure(installer, failure)
        raise


@pytest.mark.parametrize("held", (False, True))
def test_timeout_clock_gate_cannot_initialize_controller_baseline(installer, held):
    raw, fixed, programs, _ = background_fixture(installer, request_stop=False,
        extra_hook=timeout_hook(installer, held=held))
    observed = int(peer.datetime.fromisoformat(installer.q["observed_utc"]).timestamp())
    controller_mode = "mg_mode=${2-controller}\n"
    assert programs["t"].count(controller_mode) == 1
    original_programs = {name: (installer.root / fixed[name].lstrip("/")).read_bytes() for name in "lwtqs"}
    marker = installer.root / "validation-started"
    (installer.root / "loaded-event").write_bytes(b"used")
    (installer.root / ".host-lifecycle-t.sh").write_text(
        "fixture=" + installer.posix + "\n" + timeout_hook(installer, held=held) + controller_mode +
        'printf "ROLE:%s\\nMODE:%s\\n" "$0" "$mg_mode"\ndate -u +%s\n',
        encoding="ascii", newline="\n")
    samples = []

    def sample(mode):
        command = [str(SH), installer.posix + "/system/bin/sh", installer.posix + fixed["t"], peer.sha(raw)]
        if mode == "gate":
            command.append("gate")
        result = subprocess.run(command, capture_output=True, text=True, timeout=8)
        assert result.returncode == 0 and result.stderr == "", (result.stdout, result.stderr)
        role_line, mode_line, epoch = result.stdout.splitlines()
        assert role_line == "ROLE:" + installer.posix + fixed["t"]
        assert mode_line == "MODE:" + mode
        samples.append({"role": role_line, "mode": mode_line, "epoch": int(epoch), "marker_exists": marker.exists()})
        return int(epoch)

    try:
        assert sample("gate") == observed
        assert not marker.exists(), "the t gate role must not consume the controller's baseline"
        if held:
            (installer.root / "release-timeout").write_bytes(b"release existing held clock\n")
            assert sample("gate") == observed
            assert not marker.exists(), "release must not grant the t gate role baseline ownership"
        assert sample("controller") == observed
        assert marker.exists()
        assert sample("gate") == observed + 120
        assert marker.exists()
        assert {name: (installer.root / fixed[name].lstrip("/")).read_bytes() for name in "lwtqs"} == original_programs
    except BaseException as failure:
        _retain_guardian_failure(installer, failure)
        raise
    finally:
        original_failure = sys.exc_info()[1]
        try:
            print({"clock_gate_held": held, "observed": observed, "samples": samples,
                   "physical_program_sha256": {name: peer.sha(content) for name, content in original_programs.items()}})
        except BaseException as diagnostic:
            if original_failure is None:
                raise
            _guardian_failure_note(original_failure, "Clock gate trace output failed: " + repr(diagnostic))


def test_timeout_clock_gate_output_failure_preserves_original_sample_failure(installer):
    failure = AssertionError("original clock sample failure")
    real_run = subprocess.run

    def fail_gate_sample(command, **kwargs):
        if len(command) == 5 and command[1].endswith("/system/bin/sh") and command[-1] == "gate":
            raise failure
        return real_run(command, **kwargs)

    with mock.patch.object(subprocess, "run", side_effect=fail_gate_sample), \
         mock.patch("builtins.print", side_effect=OSError("clock trace output unavailable")):
        with pytest.raises(AssertionError, match="original clock sample failure") as captured:
            test_timeout_clock_gate_cannot_initialize_controller_baseline(installer, held=False)
    assert captured.value is failure
    assert any("clock trace output unavailable" in note for note in failure.__notes__)


def test_disconnected_host_does_not_prevent_local_timeout_and_original_gui_recovery(installer):
    raw, fixed, programs, run = background_fixture(installer, request_stop=False,
        extra_hook=timeout_hook(installer))
    try:
        assert run("launch").returncode == 0
        final_file = installer.root / fixed["run"].lstrip("/") / "final"
        # No status read, stop command or ACK while the detached lifecycle runs.
        wait_file(final_file, seconds=HOST_DISCONNECTED_FINAL_WAIT_SECONDS)
        assert final_file.read_bytes() == (peer.sha(raw) + ":78\n").encode()
        assert (installer.root / "gui-service-state").read_text() == "running"
        assert ":78:NOT_FEATURE_VALIDATED\n" in run("read").stdout
        assert not (installer.root / fixed["transaction"].lstrip("/") / "stop").exists()
    except BaseException as failure:
        _retain_guardian_failure(installer, failure)
        raise
    finally:
        _cleanup_guardian_fixture(installer)


def test_disconnected_final_wait_allows_measured_filesystem_receipt_before_public_read(installer):
    raw, fixed, programs, _ = background_fixture(installer, request_stop=False,
        extra_hook=timeout_hook(installer))
    final_file = installer.root / fixed["run"].lstrip("/") / "final"
    final_file.parent.mkdir(parents=True)
    final_bytes = (peer.sha(raw) + ":78\n").encode()
    final_file.write_bytes(final_bytes)
    actions = []
    real_read = type(final_file).read_bytes

    def read_bytes(path):
        if path == final_file:
            actions.append("final_bytes_observed")
        return real_read(path)

    def run(action):
        if action == "launch":
            assert actions == []
            actions.append(action)
            reply = "X2DII_LIFECYCLE_STARTED_NOT_VALIDATED:" + peer.sha(raw) + "\n"
        else:
            assert action == "read" and actions == ["launch", "final_bytes_observed"]
            actions.append(action)
            reply = "X2DII_LIFECYCLE_FINAL:" + peer.sha(raw) + ":" + peer.sha(final_bytes) + ":78:NOT_FEATURE_VALIDATED\n"
        return SimpleNamespace(returncode=0, stdout=reply, stderr="")

    with mock.patch(__name__ + ".background_fixture", return_value=(raw, fixed, programs, run)), \
         mock.patch.object(type(final_file), "read_bytes", read_bytes), \
         mock.patch.object(time, "monotonic", side_effect=(1000, 1160.390)):
        test_disconnected_host_does_not_prevent_local_timeout_and_original_gui_recovery(installer)
    assert actions == ["launch", "final_bytes_observed", "read"]


def test_generic_file_wait_still_expires_at_original_35_second_boundary(tmp_path):
    final_file = tmp_path / "final"
    final_file.write_bytes(b"existing file cannot bypass an expired waiting window\n")
    with mock.patch.object(time, "monotonic", side_effect=(1000, 1035)):
        with pytest.raises(pytest.fail.Exception, match="bounded local process evidence missing"):
            wait_file(final_file)


def test_disconnected_final_wait_without_receipt_expires_without_any_public_read(installer):
    raw, fixed, programs, _ = background_fixture(installer, request_stop=False,
        extra_hook=timeout_hook(installer))
    run = mock.Mock(return_value=SimpleNamespace(returncode=0,
        stdout="X2DII_LIFECYCLE_STARTED_NOT_VALIDATED:" + peer.sha(raw) + "\n", stderr=""))
    with mock.patch(__name__ + ".background_fixture", return_value=(raw, fixed, programs, run)), \
         mock.patch.object(time, "monotonic", side_effect=(1000, 1240)):
        with pytest.raises(pytest.fail.Exception, match="bounded local process evidence missing"):
            test_disconnected_host_does_not_prevent_local_timeout_and_original_gui_recovery(installer)
    run.assert_called_once_with("launch")


def test_fixed_stop_requests_only_its_session_and_waits_for_actual_recovery(installer):
    raw, fixed, programs, run = background_fixture(installer, request_stop=False)
    try:
        assert run("launch").returncode == 0
        log = installer.root / fixed["run"].lstrip("/") / "lifecycle.log"
        wait_file(log, contains=b"X2DII_TEMPORARY_CHILD_LOADED_NOT_FEATURE_VERIFIED",
                  seconds=HOST_LIFECYCLE_PREINJECTION_WAIT_SECONDS)
        stopped = run("stop")
        assert stopped.returncode == 0, stopped.stderr
        assert stopped.stdout == "X2DII_LIFECYCLE_STOP_REQUESTED_NOT_COMPLETED:" + peer.sha(raw) + "\n"
        assert ":0:NOT_FEATURE_VALIDATED\n" in read_until_final(run)
        assert (installer.root / "gui-service-state").read_text() == "running"
        assert run("stop").returncode != 0
    except BaseException as failure:
        _retain_guardian_failure(installer, failure)
        raise
    finally:
        _cleanup_guardian_fixture(installer)


@pytest.mark.parametrize("case", ("late-loaded-and-recovered", "missing-loaded", "recovery-expired"))
def test_host_term_wait_separates_loaded_preparation_from_bounded_recovery(tmp_path, case):
    # Exercise the original test and its real wait helpers at the already used
    # process/filesystem/clock seam; this control never launches a child.
    installer = SimpleNamespace(root=tmp_path)
    fixed = {"run": "/current-run"}
    folder = tmp_path / "current-run"
    folder.mkdir()
    stale = tmp_path / "old-run"
    stale.mkdir()
    marker = b"X2DII_TEMPORARY_CHILD_LOADED_NOT_FEATURE_VERIFIED"
    (stale / "lifecycle.log").write_bytes(marker + b"\n")
    clock = [1000.0]
    reads = []
    load_time = 1360.0 if case == "missing-loaded" else 1359.999
    end_time = 1599.999 if case == "recovery-expired" else 1599.998

    def sleep(_seconds):
        if clock[0] < load_time:
            clock[0] = load_time
            if case != "missing-loaded":
                (folder / "lifecycle.log").write_bytes(marker + b"\n")
        else:
            clock[0] = end_time

    def run(action):
        if action == "launch":
            # A launch acknowledgement/old run is not the current log marker.
            return SimpleNamespace(returncode=0, stdout=marker.decode(), stderr="")
        assert action == "read"
        reads.append(clock[0])
        assert (folder / "lifecycle.log").is_file(), "read started before actual LOADED"
        if clock[0] >= end_time:
            (tmp_path / "gui-service-state").write_text("running")
            reply = "X2DII_LIFECYCLE_FINAL:" + "a" * 64 + ":receipt:74:NOT_FEATURE_VALIDATED\n"
        else:
            reply = "X2DII_LIFECYCLE_PENDING:" + "a" * 64 + "\n"
        return SimpleNamespace(returncode=0, stdout=reply, stderr="")

    with mock.patch(__name__ + ".background_fixture", return_value=(b"", fixed, {}, run)), \
         mock.patch.object(time, "monotonic", side_effect=lambda: clock[0]), \
         mock.patch.object(time, "sleep", side_effect=sleep):
        if case == "late-loaded-and-recovered":
            test_t_lifecycle_term_records_failure_only_after_original_gui_recovery(installer)
        else:
            reason = ("bounded local process evidence missing" if case == "missing-loaded" else
                      "bounded final receipt")
            with pytest.raises(pytest.fail.Exception, match=reason):
                test_t_lifecycle_term_records_failure_only_after_original_gui_recovery(installer)
    assert reads == ([] if case == "missing-loaded" else
                     [1359.999] if case == "recovery-expired" else [1359.999, 1599.998])


def test_t_lifecycle_term_records_failure_only_after_original_gui_recovery(installer):
    hook = r'''
printf() {
 builtin printf "$@"
 case "$*" in *X2DII_TEMPORARY_CHILD_LOADED_NOT_FEATURE_VERIFIED*) builtin kill -TERM "$$";; esac
}
'''
    raw, fixed, programs, run = background_fixture(installer, request_stop=False, extra_hook=hook)
    try:
        assert run("launch").returncode == 0
        # Approved host-only split: the real current controller writes LOADED
        # immediately before the TERM hook. Preparation must not consume the
        # unchanged 240 s final/recovery allowance. This is marker-observation
        # time, not a measured exact TERM timestamp or camera time limit.
        wait_file(installer.root / fixed["run"].lstrip("/") / "lifecycle.log",
                  contains=b"X2DII_TEMPORARY_CHILD_LOADED_NOT_FEATURE_VERIFIED",
                  seconds=HOST_LIFECYCLE_PREINJECTION_WAIT_SECONDS)
        final = read_until_final(run, seconds=240)
        assert ":74:NOT_FEATURE_VALIDATED\n" in final
        assert (installer.root / "gui-service-state").read_text() == "running"
    except BaseException as failure:
        _retain_guardian_failure(installer, failure)
        raise
    finally:
        _cleanup_guardian_fixture(installer)


def test_wrapper_loss_does_not_kill_lifecycle_or_manufacture_final_receipt(installer):
    raw, fixed, programs, run = background_fixture(installer, request_stop=False,
        extra_hook=timeout_hook(installer, held=True), persistent_child=True)
    folder = installer.root / fixed["run"].lstrip("/")
    try:
        assert run("launch").returncode == 0
        wait_file(folder / "lifecycle.log", contains=b"X2DII_TEMPORARY_CHILD_LOADED_NOT_FEATURE_VERIFIED",
                  seconds=HOST_LIFECYCLE_PREINJECTION_WAIT_SECONDS)
        pid, ticks = (folder / "worker.identity").read_text().strip().split(":")
        host_stat = (installer.root / "proc" / pid / "stat").read_text()
        assert host_stat.rsplit(") ", 1)[1].split()[19] == ticks
        _signal_exact_host_lifetime(installer, pid, host_stat, "KILL", wait_for_exit=True)
        # The kernel reparents the persistent GUI after w dies. Preserve the
        # same lifetime; only its modeled parent becomes init.
        (installer.root / "proc" / pid / "stat").unlink(missing_ok=True)
        child = (installer.root / "test-child-pid").read_text().strip()
        child_stat = installer.root / "proc" / child / "stat"
        prefix, tail = child_stat.read_text().rsplit(") ", 1)
        fields = tail.split()
        child_ticks = fields[19]
        fields[1] = "1"
        child_stat.write_text(prefix + ") " + " ".join(fields) + "\n")
        assert child_stat.read_text().rsplit(") ", 1)[1].split()[19] == child_ticks
        _signal_exact_host_lifetime(installer, child,
            (installer.root / "test-child-host-stat").read_text(), "0")
        (installer.root / "release-timeout").write_bytes(b"expire the local test clock\n")
        wait_file(folder / "lifecycle.log", contains=b"X2DII_ORIGINAL_GUI_RESTORED_EXTENSION_FILES_RETAINED_PENDING_SU_REMOVAL")
        assert (installer.root / "gui-service-state").read_text() == "running"
        assert not (folder / "final").exists()
        queried = run("read")
        assert queried.returncode == 0
        assert queried.stdout == "X2DII_LIFECYCLE_UNCERTAIN:" + peer.sha(raw) + ":NO_FINAL_RECEIPT\n"
        assert run("stop").returncode != 0
    except BaseException as failure:
        _retain_guardian_failure(installer, failure)
        raise
    finally:
        _cleanup_guardian_fixture(installer)


def test_stop_rejects_same_content_transaction_directory_replacement(installer):
    # Windows denies renaming the directory while its gui.log is open. Model
    # only the changed stat inode at the existing OS boundary, not its content.
    hook = r'''
stat() {
 if [ "$2" = '%d:%i' ] && [ "$3" = "$fixture/tmp/x2dii-menu-validation-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" ] && [ -f "$fixture/directory-replaced" ]; then
  printf '1:999999\n'
 else fixture_stat "$@"; fi
}
'''
    raw, fixed, programs, run = background_fixture(installer, request_stop=False,
        extra_hook=timeout_hook(installer, held=True) + hook)
    folder = installer.root / fixed["run"].lstrip("/")
    transaction = installer.root / fixed["transaction"].lstrip("/")
    try:
        assert run("launch").returncode == 0
        wait_file(folder / "lifecycle.log", contains=b"X2DII_TEMPORARY_CHILD_LOADED_NOT_FEATURE_VERIFIED",
                  seconds=HOST_LIFECYCLE_PREINJECTION_WAIT_SECONDS)
        (installer.root / "directory-replaced").write_bytes(b"different native inode\n")
        rejected = run("stop")
        assert rejected.returncode != 0, (rejected.stdout, rejected.stderr)
        assert not (transaction / "stop").exists()
        (installer.root / "release-timeout").write_bytes(b"expire the local test clock\n")
        wait_file(folder / "final")
    except BaseException as failure:
        _retain_guardian_failure(installer, failure)
        raise
    finally:
        _cleanup_guardian_fixture(installer)


def test_reader_never_sees_a_partially_written_final_receipt(installer):
    hook = r'''
printf() {
 if [ "$#" = 3 ] && [ "$1" = '%s:%s\n' ] && [ "${#2}" = 64 ]; then
  builtin printf '%s:' "$2"
  builtin printf writing > "$fixture/final-write-started"
  /usr/bin/sleep 6
  builtin printf '%s\n' "$3"
 else builtin printf "$@"; fi
}
'''
    raw, fixed, programs, run = background_fixture(installer, extra_hook=hook)
    try:
        assert run("launch").returncode == 0
        wait_file(installer.root / "final-write-started", seconds=HOST_LIFECYCLE_PREINJECTION_WAIT_SECONDS)
        observed = run("read")
        assert observed.returncode == 0, (observed.stdout, observed.stderr)
        assert observed.stdout.startswith("X2DII_LIFECYCLE_PENDING:")
        assert ":0:NOT_FEATURE_VALIDATED\n" in read_until_final(run, seconds=240)
    except BaseException as failure:
        _retain_guardian_failure(installer, failure)
        raise
    finally:
        _cleanup_guardian_fixture(installer)


@pytest.mark.parametrize("replacement", ("same", "changed_status"))
def test_pending_replacement_is_retained_and_never_promoted_to_final(installer, replacement):
    hook = r'''
test_before_pending_cat=$(declare -f cat)
eval "${test_before_pending_cat/cat/test_original_pending_cat}"
cat() {
 if [ "$#" = 1 ] && [ "$1" = "$fixture/proc/self/attr/current" ] &&
    [ -n "${ml_run:-}" ] && [ -f "$ml_run/final.pending" ] &&
    [ ! -e "$fixture/pending-replaced" ]; then
  /usr/bin/mv "$ml_run/final.pending" "$ml_run/original-final-retained" || return 91
  REPLACEMENT
  /usr/bin/stat -c '%d:%i' "$ml_run/final.pending" > "$fixture/pending-replaced"
 fi
 test_original_pending_cat "$@"
}
'''.replace("REPLACEMENT", (
        '/usr/bin/cp "$ml_run/original-final-retained" "$ml_run/final.pending"'
        if replacement == "same" else 'printf "%s:74\\n" "$ml_sha" > "$ml_run/final.pending"'))
    raw, fixed, programs, run = background_fixture(installer, extra_hook=hook)
    folder = installer.root / fixed["run"].lstrip("/")
    try:
        assert run("launch").returncode == 0
        wait_file(installer.root / "pending-replaced", seconds=240)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            reply = run("read")
            assert reply.returncode == 0, reply.stderr
            if reply.stdout.startswith("X2DII_LIFECYCLE_UNCERTAIN:"):
                break
            assert reply.stdout.startswith("X2DII_LIFECYCLE_PENDING:"), reply.stdout
        else:
            pytest.fail("failed worker did not retain an uncertain result")
        assert (folder / "original-final-retained").read_bytes() == (peer.sha(raw) + ":0\n").encode()
        assert (folder / "final.pending").exists()
        assert not (folder / "final").exists()
        assert (installer.root / "gui-service-state").read_text() == "running"
    except BaseException as failure:
        _retain_guardian_failure(installer, failure)
        raise
    finally:
        _cleanup_guardian_fixture(installer)


def _persistent_gui_boundary(source):
    """A real child that does not help recovery by exiting when t disappears."""
    parent_guard = 'while builtin kill -0 "$$" 2>/dev/null && [ "$test_lifetime" -lt 1500 ]; do'
    assert source.count(parent_guard) == 1
    return source.replace(parent_guard, 'while [ "$test_lifetime" -lt 1500 ]; do')


@pytest.mark.parametrize("persistent_child", (False, True))
def test_background_fixture_records_every_real_gui_lifetime_once(installer, persistent_child):
    _, _, programs, _ = background_fixture(installer, persistent_child=persistent_child)
    capture = '/usr/bin/cat "/proc/$test_child/stat" > "$fixture/test-child-host-stat"'
    shell_capture = '/usr/bin/cat "/proc/$$/stat" > "$fixture/proc/$$/host-stat"'
    model_copy = '/usr/bin/cp "$fixture/proc/$$/host-stat" "$fixture/proc/$$/stat"'
    for name in "lwtqs":
        translated = (installer.root / (".host-lifecycle-" + name + ".sh")).read_text()
        assert translated.count(capture) == 1
        assert translated.count(shell_capture) == 1
        assert translated.count(model_copy) == 1
        assert translated.index(shell_capture) < translated.index(model_copy)
        assert "test-child-host-stat" not in programs[name]
        assert "host-stat" not in programs[name]


def _signal_exact_host_lifetime(installer, pid, host_stat, signal, *, absent_ok=False,
                                wait_for_exit=False):
    """Only signal the actual fixture process with its captured start ticks."""
    observed_pid, tail = host_stat.split(" (", 1)
    assert observed_pid == pid
    ticks = tail.rsplit(") ", 1)[1].split()[19]
    assert pid.isdecimal() and ticks.isdecimal()
    result = subprocess.run([str(SH), "-c", r'''
test_wait_exit=$5
if [ ! -e "/proc/$1/stat" ]; then [ "$4" = yes ]; exit $?; fi
line=$(/usr/bin/cat "/proc/$1/stat") || exit 87
tail=${line##*) }
set -- "$1" "$2" "$3" "$4" $tail
test_pid=$1; expected_ticks=$2; test_signal=$3
shift 23
[ "$1" = "$expected_ticks" ] || exit 88
builtin kill "-$test_signal" "$test_pid" || exit $?
[ "$test_wait_exit" = yes ] || exit 0
test_exit_wait=0
while [ "$test_exit_wait" -lt 60 ]; do
 [ -e "/proc/$test_pid/stat" ] || exit 0
 line=$(/usr/bin/cat "/proc/$test_pid/stat") || { [ ! -e "/proc/$test_pid/stat" ]; exit $?; }
 tail=${line##*) }
 set -- $tail
 test_exit_state=$1
 shift 19
 [ "$1" = "$expected_ticks" ] || exit 0
 case "$test_exit_state" in Z|X) exit 0;; esac
 /usr/bin/sleep .02
 test_exit_wait=$((test_exit_wait+1))
done
exit 89
''', "signal-bound-fixture-process", pid, ticks, signal, "yes" if absent_ok else "no",
        "yes" if wait_for_exit else "no"],
        capture_output=True, text=True, timeout=8)
    assert result.returncode == 0, (result.stdout, result.stderr, pid, ticks)


def _cleanup_guardian_fixture(installer):
    """Failure cleanup is limited to real lifetimes captured by this fixture."""
    original_failure = sys.exc_info()[1]
    snapshots = {}
    problems = []
    try:
        markers = list((installer.root / "proc").glob("[0-9]*/host-shell"))
    except BaseException as diagnostic:
        markers = []
        problems.append(diagnostic)
    for marker in markers:
        try:
            # A marker requires its original captured birth even after modeled
            # stat disappears. Missing/unreadable capture is an explicit error.
            snapshots[marker.parent.name] = (marker.parent / "host-stat").read_text()
        except BaseException as diagnostic:
            problems.append(diagnostic)
    for pid_name, stat_name in (
        ("test-child-pid", "test-child-host-stat"),
        ("fault-gate-pid", "fault-gate-host-stat"),
        ("fault-offer-writer-pid", "fault-offer-writer-host-stat"),
        ("fault-cancel-writer-pid", "fault-cancel-writer-host-stat"),
    ):
        try:
            pid_file, stat_file = installer.root / pid_name, installer.root / stat_name
            if pid_file.is_file() and stat_file.is_file():
                snapshots[pid_file.read_text().strip()] = stat_file.read_text()
        except BaseException as diagnostic:
            problems.append(diagnostic)
    for pid, host_stat in snapshots.items():
        try:
            _signal_exact_host_lifetime(installer, pid, host_stat, "KILL", absent_ok=True,
                                        wait_for_exit=True)
        except BaseException as diagnostic:
            problems.append(diagnostic)
    if problems:
        message = "Guardian cleanup incomplete: " + "; ".join(repr(problem) for problem in problems)
        if original_failure is None:
            raise RuntimeError(message) from problems[0]
        _guardian_failure_note(original_failure, message)


def _guardian_failure_note(failure, message):
    """Keep diagnostic failure visible without replacing the actual test error."""
    try:
        failure.add_note(message)
    except BaseException as diagnostic:
        fallback = message + "; diagnostic note writer failed: " + repr(diagnostic)
        try:
            BaseException.add_note(failure, fallback)
        except BaseException:
            # A malformed custom exception must not erase its own failure.
            try:
                print(fallback, file=sys.stderr)
            except BaseException:
                pass


def _capture_guardian_host_processes(installer):
    """One read-only, timestamped MSYS /proc sample before failure retention."""
    if not (installer.root / ".host-lifecycle-t.sh").is_file():
        return
    captures = list((installer.root / "proc").glob("[0-9]*/host-stat"))
    captures.extend(installer.root / name for name in (
        "test-child-host-stat", "fault-gate-host-stat",
        "fault-offer-writer-host-stat", "fault-cancel-writer-host-stat"))
    lifetimes = {}
    for capture in captures:
        if not capture.is_file():
            continue
        line = capture.read_text().strip()
        pid, tail = line.split(" (", 1)
        ticks = tail.rsplit(") ", 1)[1].split()[19]
        assert pid.isdecimal() and ticks.isdecimal(), (capture, line)
        lifetimes[pid] = ticks
    arguments = [value for pair in sorted(lifetimes.items()) for value in pair]
    result = subprocess.run([str(SH), "-c", r'''
builtin printf 'SAMPLE_BEGIN sampler_pid=%s epoch=%s\n' "$$" "$EPOCHREALTIME"
while [ "$#" -gt 0 ]; do
 test_diag_pid=$1; test_diag_expected_ticks=$2
 shift 2
 builtin printf 'BEGIN pid=%s expected_ticks=%s epoch=%s\n' \
  "$test_diag_pid" "$test_diag_expected_ticks" "$EPOCHREALTIME"
 if [ ! -e "/proc/$test_diag_pid/stat" ]; then
  builtin printf 'END pid=%s epoch=%s status=absent\n' "$test_diag_pid" "$EPOCHREALTIME"
 elif IFS= read -r test_diag_line 2>/dev/null < "/proc/$test_diag_pid/stat"; then
  test_diag_tail=${test_diag_line##*) }
  if [ "$test_diag_tail" = "$test_diag_line" ]; then
   builtin printf 'END pid=%s epoch=%s status=malformed raw=%s\n' \
    "$test_diag_pid" "$EPOCHREALTIME" "$test_diag_line"
  else
   test_diag_fields=( $test_diag_tail )
   builtin printf 'END pid=%s epoch=%s status=observed state=%s ppid=%s ticks=%s expected_ticks=%s raw=%s\n' \
    "$test_diag_pid" "$EPOCHREALTIME" "${test_diag_fields[0]}" "${test_diag_fields[1]}" \
    "${test_diag_fields[19]}" "$test_diag_expected_ticks" "$test_diag_line"
  fi
 else
  builtin printf 'END pid=%s epoch=%s status=read_failed\n' "$test_diag_pid" "$EPOCHREALTIME"
 fi
done
builtin printf 'SAMPLE_END sampler_pid=%s epoch=%s\n' "$$" "$EPOCHREALTIME"
''', "timestamped-fixture-proc-observation", *arguments],
        capture_output=True, text=True, timeout=8)
    (installer.root / "host-failure-proc-observation.txt").write_text(
        result.stdout + "sampler_returncode=" + str(result.returncode) + "\n" + result.stderr,
        encoding="ascii", newline="\n")
    assert result.returncode == 0, (result.stdout, result.stderr)


def _retain_guardian_failure(installer, failure):
    """Preserve source, protocol and OS observations before fixture cleanup."""
    snapshot = "not created"
    try:
        _capture_guardian_host_processes(installer)
    except BaseException as diagnostic:
        _guardian_failure_note(failure, "Guardian live host observation incomplete: " + repr(diagnostic))
    try:
        archive_root = peer.ROOT / "build/gui-guardian-failures"
        archive_root.mkdir(parents=True, exist_ok=True)
        snapshot = tempfile.mkdtemp(prefix="fixture-", dir=archive_root)
        shutil.copytree(installer.root, snapshot, dirs_exist_ok=True)
    except BaseException as diagnostic:
        _guardian_failure_note(failure, "Guardian fixture retention incomplete (diagnostics incomplete): " + repr(diagnostic) +
                               "; partial snapshot: " + snapshot)
    else:
        _guardian_failure_note(failure, "Preserved local-only guardian fixture: " + snapshot)


@pytest.mark.parametrize("diagnostic", ("copy", "note"))
def test_guardian_retention_problem_preserves_original_failure(tmp_path, diagnostic):
    class NoteFailure(RuntimeError):
        def add_note(self, note):
            raise OSError("faulted note writer")

    failure = NoteFailure("original test failure") if diagnostic == "note" else RuntimeError("original test failure")
    installer = SimpleNamespace(root=tmp_path / "fixture")
    installer.root.mkdir()
    with mock.patch.object(tempfile, "mkdtemp", return_value=str(tmp_path / "retained")), \
         mock.patch.object(shutil, "copytree", side_effect=OSError("faulted copy") if diagnostic == "copy" else None):
        with pytest.raises(RuntimeError, match="original test failure") as captured:
            try:
                raise failure
            except BaseException as original:
                _retain_guardian_failure(installer, original)
                raise
    assert captured.value is failure
    assert any("retention incomplete" in note or "note writer failed" in note for note in failure.__notes__)


@pytest.mark.parametrize("original_failure", (False, True))
def test_guardian_cleanup_problem_preserves_failure_and_attempts_remaining_lifetimes(tmp_path, original_failure):
    installer = SimpleNamespace(root=tmp_path)
    for pid in ("101", "102"):
        proc = tmp_path / "proc" / pid
        proc.mkdir(parents=True)
        (proc / "host-shell").write_text("captured host lifetime")
        (proc / "host-stat").write_text("exact fixture snapshot for " + pid)
    original = RuntimeError("original test failure")
    with mock.patch(__name__ + "._signal_exact_host_lifetime", side_effect=[OSError("first cleanup failed"), None]) as signal:
        if original_failure:
            with pytest.raises(RuntimeError, match="original test failure") as captured:
                try:
                    raise original
                finally:
                    _cleanup_guardian_fixture(installer)
            assert captured.value is original
            assert any("cleanup" in note.lower() for note in original.__notes__)
        else:
            with pytest.raises(Exception, match="cleanup"):
                _cleanup_guardian_fixture(installer)
        assert signal.call_count == 2


@pytest.mark.parametrize("model_stat", ("synthetic_reboot", "absent_after_exit"))
def test_guardian_cleanup_uses_original_host_birth_independent_of_model_stat(tmp_path, model_stat):
    installer = SimpleNamespace(root=tmp_path)
    proc = tmp_path / "proc" / "101"
    proc.mkdir(parents=True)
    (proc / "host-shell").write_text("captured host lifetime")
    original = "101 (sh) S " + "0 " * 18 + "987654 0\n"
    (proc / "host-stat").write_text(original)
    if model_stat == "synthetic_reboot":
        (proc / "stat").write_text("101 (init) S " + "0 " * 18 + "456 0\n")
    with mock.patch(__name__ + "._signal_exact_host_lifetime") as signal:
        _cleanup_guardian_fixture(installer)
    signal.assert_called_once_with(installer, "101", original, "KILL", absent_ok=True,
                                   wait_for_exit=True)


@pytest.mark.parametrize("primary_failure", (False, True))
@pytest.mark.parametrize("capture_problem", ("missing", "corrupt", "unreadable"))
def test_guardian_cleanup_refuses_unavailable_birth_and_keeps_other_cleanup(tmp_path, capture_problem, primary_failure):
    installer = SimpleNamespace(root=tmp_path)
    for pid in ("101", "102"):
        proc = tmp_path / "proc" / pid
        proc.mkdir(parents=True)
        (proc / "host-shell").write_text("captured host lifetime")
        # Even a readable modeled stat must not substitute for lost provenance.
        (proc / "stat").write_text(pid + " (init) S " + "0 " * 18 + "456 0\n")
    broken = tmp_path / "proc/101/host-stat"
    if capture_problem != "missing":
        broken.write_text("malformed original capture")
    original_other = "102 (sh) S " + "0 " * 18 + "987654 0\n"
    (tmp_path / "proc/102/host-stat").write_text(original_other)
    real_read = type(tmp_path).read_text
    real_signal = _signal_exact_host_lifetime

    def read_capture(path, *args, **kwargs):
        if capture_problem == "unreadable" and path == broken:
            raise OSError("original host birth unreadable")
        return real_read(path, *args, **kwargs)

    def signal_capture(owner, pid, host_stat, signal, **kwargs):
        if pid == "101":
            # Exercise the real parser rejection, without any real OS signal.
            return real_signal(owner, pid, host_stat, signal, **kwargs)
        assert (owner, pid, host_stat, signal, kwargs) == (
            installer, "102", original_other, "KILL", dict(absent_ok=True, wait_for_exit=True))

    original = RuntimeError("original test failure")
    with mock.patch.object(type(tmp_path), "read_text", read_capture), \
         mock.patch(__name__ + "._signal_exact_host_lifetime", side_effect=signal_capture) as signal, \
         mock.patch.object(subprocess, "run", side_effect=AssertionError("no real process access allowed")) as process:
        with pytest.raises(RuntimeError) as caught:
            if primary_failure:
                try:
                    raise original
                finally:
                    _cleanup_guardian_fixture(installer)
            else:
                _cleanup_guardian_fixture(installer)
        if primary_failure:
            assert caught.value is original
            assert any("Guardian cleanup incomplete" in note for note in original.__notes__)
        else:
            assert "Guardian cleanup incomplete" in str(caught.value)
        assert sum(call.args[1] == "102" for call in signal.call_args_list) == 1
        process.assert_not_called()


def _wait_guardian_fault(installer, fixed, name, *, seconds=HOST_LIFECYCLE_PREINJECTION_WAIT_SECONDS):
    # These positive markers follow the same admission prefix as the existing
    # loaded/stop/final markers. An absent actual fault still fails; explicit
    # stage budgets and all post-injection recovery/refusal waits stay intact.
    try:
        wait_file(installer.root / name, contains=b"\n", seconds=seconds)
    except pytest.fail.Exception:
        diagnostics = {}
        for directory in (fixed["run"], fixed["transaction"]):
            folder = installer.root / directory.lstrip("/")
            diagnostics.update({directory + "/" + path.name: path.read_text(errors="replace")[-12000:]
                                for path in folder.glob("*.log")})
        pytest.fail("guardian fault point was not reached: " + repr(diagnostics))


@pytest.mark.parametrize("explicit_seconds", (None, 160))
def test_guardian_fault_wait_remains_finite_and_requires_the_actual_marker(tmp_path, explicit_seconds):
    installer = SimpleNamespace(root=tmp_path)
    fixed = {"run": "/run", "transaction": "/transaction"}
    missing = pytest.fail.Exception("actual fault marker is absent")
    with mock.patch(__name__ + ".wait_file", side_effect=missing) as wait:
        with pytest.raises(pytest.fail.Exception, match="guardian fault point was not reached"):
            if explicit_seconds is None:
                _wait_guardian_fault(installer, fixed, "required-real-fault")
            else:
                _wait_guardian_fault(installer, fixed, "required-real-fault", seconds=explicit_seconds)
    wait.assert_called_once_with(tmp_path / "required-real-fault", contains=b"\n",
                                 seconds=360 if explicit_seconds is None else 160)


def _controller_fault_hook(stage):
    # The marker is emitted by the process making the original stop or loaded
    # call. It is not the wrapper PID from worker.identity.
    pause = r'''
test_hold_controller() {
 builtin printf '%s\n' "$$" > "$fixture/controller-at-fault"
 /usr/bin/cat "/proc/$$/stat" > "$fixture/controller-host-stat"
 test_hold_count=0
 while [ "$test_hold_count" -lt 1000 ]; do
  /usr/bin/sleep .02
  test_hold_count=$((test_hold_count+1))
 done
 exit 90
}
'''
    if stage == "first_stop":
        pause += r'''
boundary() { [ "$1" != stop ] || test_hold_controller; }
'''
    else:
        pause += r'''
printf() {
 builtin printf "$@"
 case "$*" in *X2DII_TEMPORARY_CHILD_LOADED_NOT_FEATURE_VERIFIED*) test_hold_controller;; esac
}
'''
    return pause


@pytest.mark.parametrize("stage", ("first_stop", "active_child"))
def test_controller_sigkill_recovers_stock_before_failure_receipt(installer, stage):
    pause = _controller_fault_hook(stage)
    raw, fixed, programs, run = background_fixture(
        installer, request_stop=False, extra_hook=pause, persistent_child=True)
    folder = installer.root / fixed["run"].lstrip("/")
    try:
        assert run("launch").returncode == 0
        _wait_guardian_fault(installer, fixed, "controller-host-stat")
        controller = (installer.root / "controller-at-fault").read_text().strip()
        controller_stat = (installer.root / "controller-host-stat").read_text()
        wrapper, _ = (folder / "worker.identity").read_text().strip().split(":")
        assert controller != wrapper, "fault must kill t, never w"
        assert (installer.root / "gui-service-state").read_text() == "stopped"
        if stage == "first_stop":
            assert not (installer.root / "test-child-pid").exists()
        else:
            wait_file(installer.root / "test-child-host-stat", contains=b"\n")
            assert (installer.root / fixed["transaction"].lstrip("/") / "child.identity").is_file()
        _signal_exact_host_lifetime(installer, controller, controller_stat, "KILL")
        # SIGKILL cannot execute the fixture EXIT trap. Model kernel /proc loss.
        (installer.root / "proc" / controller / "stat").unlink(missing_ok=True)
        final = read_until_final(run, seconds=240)
        assert ":0:NOT_FEATURE_VALIDATED\n" not in final
        assert (installer.root / "gui-service-state").read_text() == "running"
        log = (folder / "lifecycle.log").read_text()
        assert "X2DII_ORIGINAL_GUI_RESTORED_EXTENSION_FILES_RETAINED_PENDING_SU_REMOVAL" in log
        assert not (installer.root / "tmp/x2dii-menu-install.lock").exists()
        assert (installer.root / "proc/mounts").read_text() == installer.mount_line
        assert (installer.root / "system/etc/init/camera-gui.rc").read_bytes() == peer.boot.STOCK.read_bytes()
        for entry in installer.manifest["candidate"]["files"]:
            assert peer.sha((installer.root / entry["target"].lstrip("/")).read_bytes()) == entry["sha256"]
        operations = (installer.root / "operations").read_text().splitlines()
        assert operations.count("start:camera-gui") == 1
        if stage == "active_child":
            child = (installer.root / "test-child-pid").read_text().strip()
            assert operations.index("kill:-TERM " + child) < operations.index("start:camera-gui")
    except BaseException as failure:
        _retain_guardian_failure(installer, failure)
        raise
    finally:
        # Cleanup never starts stock GUI and is not the claimed recovery.
        # It can only terminate the captured real fixture lifetime after the
        # assertions, so a parent-death fixture shortcut cannot make RED pass.
        _cleanup_guardian_fixture(installer)


def _kill_admitted_role_hook():
    return r'''
test_kill_admitted_role() {
 test_target_role=$1
 if [ "$test_target_role" = w ]; then test_target_record=$( /usr/bin/cat "$ml_run/worker.identity" )
 else test_target_record=$( /usr/bin/cat "$ml_run/controller.identity" ); fi
 test_target_pid=${test_target_record%%:*}
 test_target_ticks=${test_target_record#*:}
 test_real_stat=$(/usr/bin/cat "/proc/$test_target_pid/stat") || return 92
 test_real_tail=${test_real_stat##*) }
 set -- $test_real_tail
 [ "$#" -ge 20 ] || return 92
 shift 19
 [ "$1" = "$test_target_ticks" ] || return 92
 builtin printf '%s\n' "$test_target_pid" > "$fixture/fault-killed-pid"
 builtin printf '%s\n' "$test_real_stat" > "$fixture/fault-killed-host-stat"
 builtin kill -KILL "$test_target_pid" || return 92
 /usr/bin/rm -f "$fixture/proc/$test_target_pid/stat"
}
'''


def guardian_transfer_fault_hook(edge, victim):
    signal = _kill_admitted_role_hook()
    if edge == "offer_visible":
        return signal + r'''
test_before_offer_cat=$(declare -f cat)
eval "${test_before_offer_cat/cat/test_original_offer_cat}"
cat() {
 if [ "${mg_mode:-worker}" = controller ] && [ "$#" = 1 ] &&
    [ "${ml_run+x}" = x ] && [ -n "$ml_run" ] &&
    [ "$1" = "$ml_run/child.offer" ] && [ ! -e "$fixture/fault-killed-pid" ]; then
  [ ! -e "$ml_run/child.admit" ] || return 92
  test_kill_admitted_role w || return 92
 fi
 test_original_offer_cat "$@"
}
'''
    predicate = (r'''[ "${0##*/}" = w ] &&
    [ "${ml_sha+x}" = x ] && [ -n "$ml_sha" ] &&
    [ "${mg_controller_pid+x}" = x ] && [ -n "$mg_controller_pid" ] &&
    [ "${mg_controller_ticks+x}" = x ] && [ -n "$mg_controller_ticks" ] &&
    [ "$2" = "$ml_sha:$mg_controller_pid:$mg_controller_ticks" ] &&
    [ -f "$ml_run/controller.identity" ] && [ ! -s "$ml_run/guardian.ready" ]'''
                 if edge == "before_ready" else r'''[ "$2" = "${child_pid:-}:${child_ticks:-}" ] &&
    [ "${child_recorded:-0}" = 1 ] && [ -f "$ml_run/gui.request" ] && [ ! -s "$ml_run/child.offer" ]''')
    return signal + r'''
printf() {
 if [ "$#" = 2 ] && [ "$1" = '%s\n' ] && [ -n "${ml_run:-}" ] &&
    [ ! -e "$fixture/fault-killed-pid" ] && PREDICATE; then
  test_kill_admitted_role VICTIM || return 92
  AFTER_SIGNAL
 fi
 builtin printf "$@"
}
'''.replace("PREDICATE", predicate).replace("VICTIM", victim).replace(
        "AFTER_SIGNAL", "builtin exit 91" if victim == "w" else ":")


def _run_guardian_transfer_hook(tmp_path, edge, body, *, caller):
    # Exercise the existing shell/hook boundary without a background lifecycle.
    # Any signal targets only this shell's own child and its captured birth.
    script = r'''
set -eu
fixture=$(cygpath -u "$1")
cat() { /usr/bin/cat "$@"; }
test_target_pid=''
test_target_ticks=''
test_cleanup_worker() {
 if [ -n "$test_target_pid" ]; then
  if [ -e "/proc/$test_target_pid/stat" ]; then
   test_cleanup_stat=$(/usr/bin/cat "/proc/$test_target_pid/stat") || return 92
   test_cleanup_tail=${test_cleanup_stat##*) }
   set -- $test_cleanup_tail
   [ "$#" -ge 20 ] || return 92
   shift 19
   [ "$1" = "$test_target_ticks" ] || return 92
   builtin kill -KILL "$test_target_pid" || return 92
  fi
  wait "$test_target_pid" 2>/dev/null || :
 fi
}
trap test_cleanup_worker EXIT
test_prepare_worker() {
 /usr/bin/sleep 30 &
 test_target_pid=$!
 test_worker_stat=$(/usr/bin/cat "/proc/$test_target_pid/stat")
 test_worker_tail=${test_worker_stat##*) }
 set -- $test_worker_tail
 shift 19
 test_target_ticks=$1
 builtin printf '%s:%s\n' "$test_target_pid" "$test_target_ticks" > "$fixture/worker.identity"
}
''' + guardian_transfer_fault_hook(edge, "w") + body
    return subprocess.run([str(SH), "-c", script, caller, str(tmp_path)],
                          capture_output=True, text=True, timeout=8)


def test_guardian_offer_hook_passes_early_reads_and_injects_only_at_offer(tmp_path):
    result = _run_guardian_transfer_hook(tmp_path, "offer_visible", r'''
mg_mode=controller
builtin printf '%s\n' stock-domain > "$fixture/early"
cat "$fixture/early"
ml_run=''
cat "$fixture/early"
[ ! -e "$fixture/fault-killed-pid" ]
ml_run=$fixture
test_prepare_worker
builtin printf '%s\n' '444:555' > "$ml_run/child.offer"
cat "$fixture/early"
[ ! -e "$fixture/fault-killed-pid" ]
cat "$ml_run/child.offer"
[ -s "$fixture/fault-killed-host-stat" ]
cat "$ml_run/child.offer"
''', caller="t")
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert result.stdout == "stock-domain\n" * 3 + "444:555\n" * 2
    assert "unbound variable" not in result.stderr
    assert (tmp_path / "fault-killed-pid").read_text().strip() == (
        tmp_path / "worker.identity").read_text().split(":")[0]


@pytest.mark.parametrize("caller", ("w", "l", "t", "q", "s"))
def test_guardian_ready_hook_passes_initialization_and_injects_only_from_worker(tmp_path, caller):
    result = _run_guardian_transfer_hook(tmp_path, "before_ready", r'''
printf '%s\n' before-run
ml_sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
ml_run=$fixture
printf '%s\n' before-controller
mg_controller_pid=''
printf '%s\n' empty-controller
mg_controller_pid=432
printf '%s\n' before-ticks
mg_controller_ticks=''
printf '%s\n' empty-ticks
mg_controller_ticks=987
unset ml_sha
printf '%s\n' before-session
ml_sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
mg_controller_pid=''; mg_controller_ticks=''
builtin printf '%s\n' early-record > "$ml_run/controller.identity"
printf '%s\n' "$ml_sha::"
[ ! -e "$fixture/fault-killed-pid" ]
test_prepare_worker
mg_controller_pid=$$
test_controller_stat=$(/usr/bin/cat "/proc/$$/stat")
test_controller_tail=${test_controller_stat##*) }
set -- $test_controller_tail
shift 19
mg_controller_ticks=$1
builtin printf '%s:%s\n' "$mg_controller_pid" "$mg_controller_ticks" > "$ml_run/controller.identity"
printf '%s\n' unrelated-record
[ ! -e "$fixture/fault-killed-pid" ]
builtin printf '%s\n' "$ml_sha:$mg_controller_pid:$mg_controller_ticks" > "$fixture/expected-message"
printf '%s\n' "$ml_sha:$mg_controller_pid:$mg_controller_ticks"
[ ! -e "$fixture/fault-killed-pid" ]
builtin printf '%s\n' continued
''', caller=caller)
    prefix = ("before-run\nbefore-controller\nempty-controller\nbefore-ticks\n"
              "empty-ticks\nbefore-session\n" + "a" * 64 + "::\nunrelated-record\n")
    assert "unbound variable" not in result.stderr
    if caller == "w":
        assert result.returncode == 91, (result.stdout, result.stderr)
        assert result.stdout == prefix
        assert (tmp_path / "fault-killed-host-stat").is_file()
        assert (tmp_path / "fault-killed-pid").read_text().strip() == (
            tmp_path / "worker.identity").read_text().split(":")[0]
    else:
        assert result.returncode == 0, (result.stdout, result.stderr)
        assert result.stdout == prefix + (tmp_path / "expected-message").read_text() + "continued\n"
        assert not (tmp_path / "fault-killed-pid").exists()


@pytest.mark.parametrize("edge,victim", (("before_offer", "t"), ("before_offer", "w"),
                                         ("offer_visible", "w"), ("before_ready", "w")))
def test_guardian_transfer_loss_never_executes_an_unadmitted_gui(installer, edge, victim):
    raw, fixed, programs, run = background_fixture(
        installer, request_stop=False, persistent_child=True,
        extra_hook=guardian_transfer_fault_hook(edge, victim))
    folder = installer.root / fixed["run"].lstrip("/")
    transaction = installer.root / fixed["transaction"].lstrip("/")
    try:
        assert run("launch").returncode == 0
        _wait_guardian_fault(installer, fixed, "fault-killed-host-stat")
        killed = (installer.root / "fault-killed-pid").read_text().strip()
        worker = (folder / "worker.identity").read_text().split(":")[0]
        assert (killed == worker) == (victim == "w")
        if edge == "before_ready":
            controller = (folder / "controller.identity").read_text().split(":")[0]
            deadline = time.monotonic() + 35
            while (installer.root / "proc" / controller / "stat").exists() and time.monotonic() < deadline:
                time.sleep(.05)
            assert not (installer.root / "proc" / controller / "stat").exists()
            operations_file = installer.root / "operations"
            operations = operations_file.read_text().splitlines() if operations_file.exists() else []
            assert not any(line.startswith(("stop:", "start:", "kill:")) for line in operations)
            assert not (folder / "stop.intent").exists()
        else:
            wait_file(folder / "lifecycle.log", seconds=35,
                      contains=b"X2DII_ORIGINAL_GUI_RESTORED_EXTENSION_FILES_RETAINED_PENDING_SU_REMOVAL")
            operations = (installer.root / "operations").read_text().splitlines()
            assert operations.count("stop:camera-gui") == 1
            assert operations.count("start:camera-gui") == 1
            if victim == "w":
                assert not any(line.startswith("kill:") for line in operations)
        assert not (folder / "child.admit").exists()
        assert not (installer.root / "launch-args").exists()
        assert (installer.root / "gui-service-state").read_text() == "running"
        assert (installer.root / "proc/mounts").read_text() == installer.mount_line
        assert (installer.root / "system/etc/init/camera-gui.rc").read_bytes() == peer.boot.STOCK.read_bytes()
        for entry in installer.manifest["candidate"]["files"]:
            assert peer.sha((installer.root / entry["target"].lstrip("/")).read_bytes()) == entry["sha256"]
        if victim == "w":
            assert not (folder / "final").exists()
            assert run("read").stdout == "X2DII_LIFECYCLE_UNCERTAIN:" + peer.sha(raw) + ":NO_FINAL_RECEIPT\n"
        else:
            assert ":0:NOT_FEATURE_VALIDATED\n" not in read_until_final(run, seconds=240)
    except BaseException as failure:
        _retain_guardian_failure(installer, failure)
        raise
    finally:
        _cleanup_guardian_fixture(installer)


def _exec_transition_fault_hook():
    # Same real PID/start time crosses the OS exec boundary. The host process
    # image/domain data is a controlled OS model, not target timing evidence.
    return _kill_admitted_role_hook() + r'''
test_before_transition_readlink=$(declare -f readlink)
eval "${test_before_transition_readlink/readlink/test_original_transition_readlink}"
readlink() {
 if [ -f "$fixture/env-transition" ] && [ "$1" = "$fixture/proc/$(/usr/bin/cat "$fixture/fault-gate-pid")/exe" ]; then
  builtin printf '/system/bin/env\n'
 else test_original_transition_readlink "$@"; fi
}
test_exec_transition() {
 builtin printf '%s\n' "$$" > "$fixture/fault-gate-pid"
 /usr/bin/cat "/proc/$$/stat" > "$fixture/fault-gate-host-stat"
 if [ "$1" = env ]; then
  builtin printf env-image > "$fixture/proc/$$/exe"
  /usr/bin/rm -f "$fixture/proc/$$/host-shell"
  builtin printf observed > "$fixture/env-transition"
 fi
 test_kill_admitted_role t || return 92
 trap 'lifecycle_fixture_exit 0' TERM
 test_transition_wait=0
 while [ "$test_transition_wait" -lt 1500 ]; do
  /usr/bin/sleep .02
  test_transition_wait=$((test_transition_wait+1))
 done
 lifecycle_fixture_exit 93
}
'''
def test_controller_loss_at_exec_transition_has_no_unowned_intermediate_image(installer):
    hook = _exec_transition_fault_hook()
    raw, fixed, programs, run = background_fixture(
        installer, request_stop=False, persistent_child=True, extra_hook=hook)
    folder = installer.root / fixed["run"].lstrip("/")
    try:
        assert run("launch").returncode == 0
        _wait_guardian_fault(installer, fixed, "fault-killed-host-stat")
        child = (installer.root / "fault-gate-pid").read_text().strip()
        offered_pid, offered_ticks = (folder / "child.offer").read_text().strip().split(":")
        assert child == offered_pid
        raw_stat = (installer.root / "fault-gate-host-stat").read_text()
        assert raw_stat.rsplit(") ", 1)[1].split()[19] == offered_ticks
        assert (folder / "child.admit").read_text() == (folder / "child.offer").read_text()
        assert ":0:NOT_FEATURE_VALIDATED\n" not in read_until_final(run, seconds=240)
        assert (installer.root / "gui-service-state").read_text() == "running", {
            str(path): path.read_text(errors="replace")[-24000:]
            for directory in (fixed["run"], fixed["transaction"])
            for path in (installer.root / directory.lstrip("/")).glob("*.log")}
        operations = (installer.root / "operations").read_text().splitlines()
        assert operations.index("kill:-TERM " + child) < operations.index("start:camera-gui")
        assert not (installer.root / "tmp/x2dii-menu-install.lock").exists()
        assert (installer.root / "proc/mounts").read_text() == installer.mount_line
    except BaseException as failure:
        _retain_guardian_failure(installer, failure)
        raise
    finally:
        _cleanup_guardian_fixture(installer)


def test_known_child_exit_between_live_check_and_ownership_is_rechecked(installer):
    # A real admitted lifetime ends after the OS delivered its last live stat.
    # It is not an unknown PID and no stale image is treated as still owned.
    hook = _exec_transition_fault_hook() + r'''
test_before_exit_race_cat=$(declare -f cat)
eval "${test_before_exit_race_cat/cat/test_original_exit_race_cat}"
cat() {
 if [ "${mg_mode:-worker}" = worker ] && [ "$#" = 1 ] &&
    [ -n "${ml_status+x}" ] && [ -f "$fixture/fault-gate-pid" ] &&
    [ ! -e "/proc/$mg_controller_pid/stat" ] &&
    [ "$1" = "$fixture/proc/$(/usr/bin/cat "$fixture/fault-gate-pid")/stat" ] &&
    [ ! -e "$fixture/exit-race-live-stat" ]; then
  test_race_pid=$(/usr/bin/cat "$fixture/fault-gate-pid") || return 92
  test_race_stat=$(/usr/bin/cat "/proc/$test_race_pid/stat") || return 92
  test_race_tail=${test_race_stat##*) }
  set -- $test_race_tail
  case "$1" in Z|X) return 92;; esac
  shift 19
  [ "$test_race_pid:$1" = "$(/usr/bin/cat "$ml_run/child.offer")" ] || return 92
  builtin printf '%s\n' "$test_race_stat" > "$fixture/exit-race-live-stat"
  builtin kill -TERM "$test_race_pid" || return 92
  test_race_wait=0
  while [ -e "/proc/$test_race_pid/stat" ] && [ "$test_race_wait" -lt 100 ]; do
   /usr/bin/sleep .02
   test_race_wait=$((test_race_wait+1))
  done
  [ ! -e "/proc/$test_race_pid/stat" ] || return 92
  /usr/bin/rm -f "$fixture/proc/$test_race_pid/stat"
  builtin printf '%s\n' "$test_race_pid" > "$fixture/exit-race-ended"
  builtin printf '%s\n' "$test_race_stat"
 else test_original_exit_race_cat "$@"; fi
}
'''
    raw, fixed, programs, run = background_fixture(
        installer, request_stop=False, persistent_child=True, extra_hook=hook)
    folder = installer.root / fixed["run"].lstrip("/")
    try:
        assert run("launch").returncode == 0
        _wait_guardian_fault(installer, fixed, "exit-race-ended", seconds=240)
        child = (installer.root / "exit-race-ended").read_text().strip()
        stat = (installer.root / "exit-race-live-stat").read_text()
        ticks = stat.rsplit(") ", 1)[1].split()[19]
        assert (folder / "child.offer").read_text() == child + ":" + ticks + "\n"
        assert (folder / "child.admit").read_text() == (folder / "child.offer").read_text()
        assert not (installer.root / "proc" / child / "stat").exists()
        final = read_until_final(run, seconds=240)
        assert ":0:NOT_FEATURE_VALIDATED\n" not in final
        assert (installer.root / "gui-service-state").read_text() == "running", (
            final, (folder / "lifecycle.log").read_text())
        operations = (installer.root / "operations").read_text().splitlines()
        assert operations.count("start:camera-gui") == 1
        assert not any(line.startswith("kill:") for line in operations)
        assert not (installer.root / "tmp/x2dii-menu-install.lock").exists()
        assert (installer.root / "proc/mounts").read_text() == installer.mount_line
    except BaseException as failure:
        _retain_guardian_failure(installer, failure)
        raise
    finally:
        _cleanup_guardian_fixture(installer)


def test_partial_child_offer_is_not_observable_as_a_completed_transfer(installer):
    hook = r'''
printf() {
 if [ "$#" = 2 ] && [ "$1" = '%s\n' ] && [ -n "${ml_run:-}" ] &&
    [ "$2" = "${child_pid:-}:${child_ticks:-}" ] && [ "${child_recorded:-0}" = 1 ] &&
    [ -f "$ml_run/gui.request" ] && [ ! -s "$ml_run/child.offer" ] &&
    [ ! -e "$fixture/offer-write-held" ]; then
  test_offer_writer=$BASHPID
  builtin printf '%s\n' "$test_offer_writer" > "$fixture/fault-offer-writer-pid"
  /usr/bin/cat "/proc/$test_offer_writer/stat" > "$fixture/fault-offer-writer-host-stat"
  builtin printf held > "$fixture/offer-write-held"
  test_hold=0
  while [ ! -e "$fixture/release-offer-write" ] && [ "$test_hold" -lt 1000 ]; do
   /usr/bin/sleep .02
   test_hold=$((test_hold+1))
  done
  [ -e "$fixture/release-offer-write" ] || return 93
 fi
 builtin printf "$@"
}
stat() {
 if [ "${mg_mode:-worker}" = controller ] && [ -n "${ml_run:-}" ] && [ "$2" = %s ] &&
    [ "$3" = "$ml_run/child.offer" ] && [ -f "$fixture/offer-write-held" ]; then
  test_offer_size=$(fixture_stat "$@") || return $?
  if [ "$test_offer_size" = 0 ]; then builtin printf empty > "$fixture/offer-reader-observed"; fi
  builtin printf '%s\n' "$test_offer_size"
 else fixture_stat "$@"; fi
}
sleep() {
 if [ "${mg_mode:-worker}" = controller ] && [ -n "${mg_offer_wait:-}" ] &&
    [ -f "$fixture/offer-write-held" ] && [ ! -e "$ml_run/child.offer" ]; then
  builtin printf waiting > "$fixture/offer-reader-observed"
 fi
 /usr/bin/sleep .02
}
'''
    raw, fixed, programs, run = background_fixture(
        installer, request_stop=True, persistent_child=True, extra_hook=hook)
    folder = installer.root / fixed["run"].lstrip("/")
    try:
        assert run("launch").returncode == 0
        # Atomic publication's MSYS stat/hash phases reached gui.request at
        # 119 s in the retained U run. Allow its measured next offer phase;
        # this bounds only the host fixture, not any generated deadline.
        wait_file(installer.root / "offer-write-held", seconds=160)
        wait_file(installer.root / "offer-reader-observed")
        assert (installer.root / "offer-reader-observed").read_bytes() == b"waiting"
        assert not (folder / "child.offer").exists()
        assert (folder / "child.offer.pending").is_file()
        assert not (folder / "child.admit").exists()
        (installer.root / "release-offer-write").write_bytes(b"publish the complete identity\n")
        # Remaining gate execution and restoration are separate host phases;
        # V measured 72.2 s to final.pending, still before atomic final
        # promotion. The 90 s host allowance includes that final phase and
        # does not change either target-side validation deadline.
        final = read_until_final(run, seconds=90)
        assert ":0:NOT_FEATURE_VALIDATED\n" in final
        assert (installer.root / "gui-service-state").read_text() == "running"
        assert (folder / "child.offer").read_text() == (folder / "child.admit").read_text()
        assert not (folder / "child.offer.pending").exists()
        operations = (installer.root / "operations").read_text().splitlines()
        child = (installer.root / "test-child-pid").read_text().strip()
        assert operations.index("kill:-TERM " + child) < operations.index("start:camera-gui")
    except BaseException as failure:
        _retain_guardian_failure(installer, failure)
        raise
    finally:
        _cleanup_guardian_fixture(installer)


def test_controller_death_between_supervisor_live_check_and_role_check_recovers(installer):
    observed = int(peer.datetime.fromisoformat(installer.q["observed_utc"]).timestamp())
    hook = _controller_fault_hook("first_stop") + _kill_admitted_role_hook() + r'''
date() {
 if [ -f "$fixture/controller-host-stat" ]; then echo DEADLINE;
 else echo OBSERVED; fi
}
test_before_controller_race_cat=$(declare -f cat)
eval "${test_before_controller_race_cat/cat/test_original_controller_race_cat}"
cat() {
 if [ "${mg_protocol_failed:-0}" = 1 ] && [ "$#" = 1 ] &&
    [ -n "${mg_controller_pid:-}" ] &&
    [ "$1" = "$fixture/proc/$mg_controller_pid/stat" ] &&
    [ ! -e "$fixture/fault-controller-last-live-stat" ]; then
  test_controller_live=$(/usr/bin/cat "/proc/$mg_controller_pid/stat") || return 92
  test_controller_tail=${test_controller_live##*) }
  case "$test_controller_tail" in Z\ *|X\ *) return 92;; esac
  builtin printf '%s\n' "$test_controller_live" > "$fixture/fault-controller-last-live-stat"
  test_kill_admitted_role t || return 92
  builtin printf '%s\n' "$test_controller_live"
 else test_original_controller_race_cat "$@"; fi
}
'''.replace("DEADLINE", str(observed + 171)).replace("OBSERVED", str(observed))
    raw, fixed, programs, run = background_fixture(
        installer, request_stop=False, extra_hook=hook)
    folder = installer.root / fixed["run"].lstrip("/")
    try:
        assert run("launch").returncode == 0
        _wait_guardian_fault(installer, fixed, "fault-killed-host-stat")
        controller = (installer.root / "fault-killed-pid").read_text().strip()
        live = (installer.root / "fault-controller-last-live-stat").read_text()
        ticks = live.rsplit(") ", 1)[1].split()[19]
        assert (folder / "controller.identity").read_text() == controller + ":" + ticks + "\n"
        worker = (folder / "worker.identity").read_text().split(":")[0]
        assert controller != worker
        # Includes the measured stock restore and atomic receipt phases;
        # the generated 170 s deadline is deliberately triggered, not changed.
        deadline = time.monotonic() + 60
        while (installer.root / "proc" / worker / "stat").exists() and time.monotonic() < deadline:
            time.sleep(.05)
        assert not (installer.root / "proc" / worker / "stat").exists()
        assert (installer.root / "gui-service-state").read_text() == "running", (
            (folder / "lifecycle.log").read_text(), (folder / "worker.log").read_text())
        assert ":0:NOT_FEATURE_VALIDATED\n" not in read_until_final(run, seconds=240)
        operations = (installer.root / "operations").read_text().splitlines()
        assert operations.count("start:camera-gui") == 1
        assert not any(line.startswith("kill:") for line in operations)
        assert not (installer.root / "tmp/x2dii-menu-install.lock").exists()
        assert (installer.root / "proc/mounts").read_text() == installer.mount_line
    except BaseException as failure:
        _retain_guardian_failure(installer, failure)
        raise
    finally:
        _cleanup_guardian_fixture(installer)


def _cancel_writer_fault_hook():
    return _kill_admitted_role_hook() + r'''
test_term_exact_controller() {
 test_term_record=$(/usr/bin/cat "$ml_run/controller.identity") || return 92
 test_term_pid=${test_term_record%%:*}; test_term_ticks=${test_term_record#*:}
 test_term_stat=$(/usr/bin/cat "/proc/$test_term_pid/stat") || return 92
 test_term_tail=${test_term_stat##*) }
 set -- $test_term_tail
 [ "$#" -ge 20 ] || return 92
 shift 19
 [ "$1" = "$test_term_ticks" ] || return 92
 builtin printf '%s\n' "$test_term_stat" > "$fixture/fault-controller-term-stat"
 builtin kill -TERM "$test_term_pid"
}
printf() {
 if [ "$#" = 2 ] && [ "$1" = '%s\n' ] && [ -n "${ml_run:-}" ]; then
  if [ "${mg_mode:-worker}" = worker ] &&
     [ "${mg_put_target:-}" = "$ml_run/child.offer" ] &&
     [ "$2" = "${child_pid:-}:${child_ticks:-}" ] &&
     [ -f "$ml_run/child.offer.pending" ] &&
     [ ! -e "$fixture/fault-offer-writer-pid" ]; then
   test_offer_writer=$BASHPID
   builtin printf '%s\n' "$test_offer_writer" > "$fixture/fault-offer-writer-pid"
   /usr/bin/cat "/proc/$test_offer_writer/stat" > "$fixture/fault-offer-writer-host-stat"
   [ "$child_recorded" = 1 ] && [ ! -e "$ml_run/child.admit" ] || return 92
   test_term_exact_controller || return 92
   test_offer_hold=0
   while [ ! -e "$fixture/fault-killed-host-stat" ] && [ "$test_offer_hold" -lt 1000 ]; do
    /usr/bin/sleep .02
    test_offer_hold=$((test_offer_hold+1))
   done
   [ -s "$fixture/fault-killed-host-stat" ] || return 92
  elif [ "${mg_mode:-worker}" = controller ] &&
       [ "${mg_put_target:-}" = "$ml_run/child.cancel" ] &&
       [ "$2" = "$ml_sha" ] && [ -f "$ml_run/child.cancel.pending" ] &&
       [ ! -e "$fixture/fault-cancel-writer-pid" ]; then
   test_cancel_writer=$BASHPID
   builtin printf '%s\n' "$test_cancel_writer" > "$fixture/fault-cancel-writer-pid"
   /usr/bin/cat "/proc/$test_cancel_writer/stat" > "$fixture/fault-cancel-writer-host-stat"
   test_kill_admitted_role t || return 92
   test_cancel_hold=0
   while [ ! -e "$fixture/release-cancel-writer" ] && [ "$test_cancel_hold" -lt 1500 ]; do
    /usr/bin/sleep .02
    test_cancel_hold=$((test_cancel_hold+1))
   done
   [ -e "$fixture/release-cancel-writer" ] || return 93
  fi
 fi
 builtin printf "$@"
}
'''


def test_controller_loss_during_cancel_publication_preserves_writer_and_recovers_owned_child(installer):
    hook = _cancel_writer_fault_hook()
    raw, fixed, programs, run = background_fixture(
        installer, request_stop=False, persistent_child=True, extra_hook=hook)
    folder = installer.root / fixed["run"].lstrip("/")
    try:
        assert run("launch").returncode == 0
        _wait_guardian_fault(installer, fixed, "fault-killed-host-stat", seconds=160)
        writer = (installer.root / "fault-cancel-writer-pid").read_text().strip()
        writer_stat = (installer.root / "fault-cancel-writer-host-stat").read_text()
        controller = (installer.root / "fault-killed-pid").read_text().strip()
        assert writer != controller
        assert (folder / "child.cancel.pending").is_file()
        assert not (folder / "child.cancel").exists()
        worker = (folder / "worker.identity").read_text().split(":")[0]
        deadline = time.monotonic() + 60
        while (installer.root / "proc" / worker / "stat").exists() and time.monotonic() < deadline:
            time.sleep(.05)
        assert not (installer.root / "proc" / worker / "stat").exists()
        _signal_exact_host_lifetime(installer, writer, writer_stat, "0")
        assert (installer.root / "gui-service-state").read_text() == "running", (
            (folder / "lifecycle.log").read_text(), (folder / "worker.log").read_text())
        assert ":0:NOT_FEATURE_VALIDATED\n" not in read_until_final(run, seconds=240)
        assert (folder / "child.cancel.pending").read_bytes() == b""
        assert not (folder / "child.cancel").exists()
        assert not (folder / "child.admit").exists()
        assert not (installer.root / "launch-args").exists()
        child = (folder / "child.offer").read_text().split(":")[0]
        assert not (installer.root / "proc" / child / "stat").exists()
        assert not (installer.root / "tmp/x2dii-menu-install.lock").exists()
        assert (installer.root / "proc/mounts").read_text() == installer.mount_line
    except BaseException as failure:
        _retain_guardian_failure(installer, failure)
        raise
    finally:
        _cleanup_guardian_fixture(installer)


@pytest.mark.parametrize("stage", ("not_spawned", "spawned_unrecorded"))
def test_controller_cancel_loss_before_child_recording_requires_no_admission_proof(installer, stage):
    hook = _cancel_writer_fault_hook() + r'''
test_before_unrecorded_cat=$(declare -f cat)
eval "${test_before_unrecorded_cat/cat/test_original_unrecorded_cat}"
cat() {
 test_unrecorded_fault=0
 if [ "${mg_mode:-worker}" = worker ] && [ "$#" = 1 ] &&
    [ -n "${ml_run:-}" ] && [ -f "$ml_run/gui.request" ] &&
    [ "${child_recorded:-0}" = 0 ] && [ ! -e "$fixture/fault-unrecorded-state" ]; then
  if [ TEST_STAGE = not_spawned ] && [ "${mg_child_offered:-0}" = 0 ] &&
     [ "$1" = "$ml_run/controller.identity" ]; then
   test_unrecorded_fault=1
  elif [ TEST_STAGE = spawned_unrecorded ] && [ "${mg_child_offered:-0}" = 1 ] &&
       [ -n "${child_pid:-}" ] && [ "$1" = "$fixture/proc/$child_pid/stat" ] &&
       [ -f "$fixture/proc/$child_pid/host-shell" ] && [ -e "/proc/$child_pid/stat" ]; then
   test_unrecorded_fault=1
  fi
 fi
 if [ "$test_unrecorded_fault" = 1 ]; then
  test_before_fault=$(test_original_unrecorded_cat "$@") || return 92
  builtin printf '%s:%s:%s\n' "$mg_child_offered" "$child_recorded" "${child_pid:-}" > "$fixture/fault-unrecorded-state"
  if [ TEST_STAGE = spawned_unrecorded ]; then
   builtin printf '%s\n' "$child_pid" > "$fixture/fault-gate-pid"
   /usr/bin/cat "/proc/$child_pid/stat" > "$fixture/fault-gate-host-stat"
  fi
  test_term_exact_controller || return 92
  test_unrecorded_hold=0
  while [ ! -e "$fixture/fault-killed-host-stat" ] && [ "$test_unrecorded_hold" -lt 1000 ]; do
   /usr/bin/sleep .02
   test_unrecorded_hold=$((test_unrecorded_hold+1))
  done
  [ -s "$fixture/fault-killed-host-stat" ] || return 92
  if [ TEST_STAGE = spawned_unrecorded ]; then
   # The gate must exit on controller loss without any admission. Return the
   # already observed birth stat to model its death before image admission.
   test_gate_exit_wait=0
   while [ -e "/proc/$child_pid/stat" ] && [ "$test_gate_exit_wait" -lt 500 ]; do
    /usr/bin/sleep .02
    test_gate_exit_wait=$((test_gate_exit_wait+1))
   done
   [ ! -e "/proc/$child_pid/stat" ] || return 92
   /usr/bin/rm -f "$fixture/proc/$child_pid/stat"
  fi
  builtin printf '%s\n' "$test_before_fault"
 else test_original_unrecorded_cat "$@"; fi
}
'''.replace("TEST_STAGE", stage)
    raw, fixed, programs, run = background_fixture(
        installer, request_stop=False, persistent_child=True, extra_hook=hook)
    folder = installer.root / fixed["run"].lstrip("/")
    try:
        assert run("launch").returncode == 0
        _wait_guardian_fault(installer, fixed, "fault-killed-host-stat", seconds=160)
        writer = (installer.root / "fault-cancel-writer-pid").read_text().strip()
        writer_stat = (installer.root / "fault-cancel-writer-host-stat").read_text()
        assert writer != (installer.root / "fault-killed-pid").read_text().strip()
        state = (installer.root / "fault-unrecorded-state").read_text().strip()
        assert state == "0:0:" if stage == "not_spawned" else state.startswith("1:0:")
        assert (folder / "child.cancel.pending").is_file()
        for name in ("child.offer", "child.offer.pending", "child.admit", "child.admit.pending"):
            assert not (folder / name).exists()
        worker = (folder / "worker.identity").read_text().split(":")[0]
        deadline = time.monotonic() + 60
        while (installer.root / "proc" / worker / "stat").exists() and time.monotonic() < deadline:
            time.sleep(.05)
        assert not (installer.root / "proc" / worker / "stat").exists()
        _signal_exact_host_lifetime(installer, writer, writer_stat, "0")
        assert (installer.root / "gui-service-state").read_text() == "running", (
            state, (folder / "lifecycle.log").read_text(), (folder / "worker.log").read_text())
        assert ":0:NOT_FEATURE_VALIDATED\n" not in read_until_final(run, seconds=240)
        assert (folder / "child.cancel.pending").read_bytes() == b""
        assert not (folder / "child.cancel").exists()
        assert not (installer.root / "launch-args").exists()
        if stage == "spawned_unrecorded":
            child = (installer.root / "fault-gate-pid").read_text().strip()
            assert not (installer.root / "proc" / child / "stat").exists()
        assert not (installer.root / "tmp/x2dii-menu-install.lock").exists()
        assert (installer.root / "proc/mounts").read_text() == installer.mount_line
    except BaseException as failure:
        _retain_guardian_failure(installer, failure)
        raise
    finally:
        _cleanup_guardian_fixture(installer)


@pytest.mark.parametrize("fault", ("reused_child", "unknown_child_domain", "restore_failed"))
def test_guardian_refuses_unknown_lifetime_or_failed_restore_without_success(installer, fault):
    stage = "first_stop" if fault == "restore_failed" else "active_child"
    hook = _controller_fault_hook(stage)
    if fault == "restore_failed":
        hook += r'''
start() { printf 'start-failed:%s\n' "$*" >> "$fixture/operations"; return 1; }
'''
    raw, fixed, programs, run = background_fixture(
        installer, request_stop=False, persistent_child=True, extra_hook=hook)
    folder = installer.root / fixed["run"].lstrip("/")
    try:
        assert run("launch").returncode == 0
        _wait_guardian_fault(installer, fixed, "controller-host-stat")
        controller = (installer.root / "controller-at-fault").read_text().strip()
        controller_stat = (installer.root / "controller-host-stat").read_text()
        assert controller != (folder / "worker.identity").read_text().split(":")[0]
        if fault != "restore_failed":
            child = (installer.root / "test-child-pid").read_text().strip()
            proc = installer.root / "proc" / child
            assert (installer.root / fixed["transaction"].lstrip("/") / "child.identity").is_file()
            if fault == "reused_child":
                before, tail = (proc / "stat").read_text().rsplit(") ", 1)
                fields = tail.split()
                fields[19] = str(int(fields[19]) + 100000)
                (proc / "stat").write_text(before + ") " + " ".join(fields) + "\n")
            else:
                (proc / "attr/current").write_text("u:r:unrelated:s0\n")
        _signal_exact_host_lifetime(installer, controller, controller_stat, "KILL", wait_for_exit=True)
        (installer.root / "proc" / controller / "stat").unlink(missing_ok=True)
        final = read_until_final(run, seconds=240)
        assert ":79:NOT_FEATURE_VALIDATED\n" in final
        log = (folder / "lifecycle.log").read_text()
        assert "X2DII_TEMPORARY_RECOVERY_FAILED_RETAIN_ATTEMPT_AND_FILES" in log
        assert "X2DII_ORIGINAL_GUI_RESTORED" not in log
        assert (installer.root / "gui-service-state").read_text() == "stopped"
        assert (installer.root / "tmp/x2dii-menu-install.lock").is_dir()
        operations = (installer.root / "operations").read_text().splitlines()
        assert "start:camera-gui" not in operations
        if fault != "restore_failed":
            assert not any(line.startswith("kill:") for line in operations)
            _signal_exact_host_lifetime(installer, child,
                (installer.root / "test-child-host-stat").read_text(), "0")
        else:
            assert "start-failed:camera-gui" in operations
        assert (installer.root / "proc/mounts").read_text() == installer.mount_line
        assert (installer.root / "system/etc/init/camera-gui.rc").read_bytes() == peer.boot.STOCK.read_bytes()
        for entry in installer.manifest["candidate"]["files"]:
            assert peer.sha((installer.root / entry["target"].lstrip("/")).read_bytes()) == entry["sha256"]
    except BaseException as failure:
        _retain_guardian_failure(installer, failure)
        raise
    finally:
        _cleanup_guardian_fixture(installer)


@pytest.mark.parametrize("fault", ("still_live", "unknown_stat", "reused_lifetime"))
def test_unrecorded_live_or_unknown_child_refuses_recovery_without_signalling(installer, fault):
    # Hold an actual gate process before its first protocol observation. w
    # observes its real birth, but never establishes image/admission ownership.
    hook = _cancel_writer_fault_hook() + r'''
test_before_refusal_cat=$(declare -f cat)
eval "${test_before_refusal_cat/cat/test_original_refusal_cat}"
cat() {
 if [ "${mg_mode:-worker}" = worker ] && [ "$#" = 1 ] &&
    [ -n "${ml_status+x}" ] && [ "${child_recorded:-0}" = 0 ] &&
    [ -n "${child_pid:-}" ] && [ "$1" = "$fixture/proc/$child_pid/stat" ] &&
    [ ! -e "/proc/$mg_controller_pid/stat" ]; then
  builtin printf '%s\n' "$child_ticks" > "$fixture/refusal-expected-ticks"
  if [ TEST_FAULT = unknown_stat ]; then
   builtin printf 'read-error\n' > "$fixture/refusal-observed-stat"
  else /usr/bin/cat "$1" > "$fixture/refusal-observed-stat"; fi
  builtin printf 'post-wait-unrecorded-child-exited\n' > "$fixture/refusal-recovery-read"
 fi
 if [ "${mg_mode:-worker}" = worker ] && [ "$#" = 1 ] &&
    [ -n "${ml_run:-}" ] && [ "${mg_child_offered:-0}" = 1 ] &&
    [ "${child_recorded:-0}" = 0 ] && [ -n "${child_pid:-}" ] &&
    [ "$1" = "$fixture/proc/$child_pid/stat" ] &&
    [ ! -e "$fixture/fault-unrecorded-state" ]; then
  test_gate_wait=0
  while [ ! -s "$fixture/fault-gate-host-stat" ] && [ "$test_gate_wait" -lt 500 ]; do
   /usr/bin/sleep .02; test_gate_wait=$((test_gate_wait+1))
  done
  [ -s "$fixture/fault-gate-host-stat" ] || return 92
  test_birth_before=$(test_original_refusal_cat "$@") || return 92
  builtin printf '%s:%s:%s\n' "$mg_child_offered" "$child_recorded" "$child_pid" > "$fixture/fault-unrecorded-state"
  test_term_exact_controller || return 92
  test_fault_wait=0
  while [ ! -s "$fixture/fault-killed-host-stat" ] && [ "$test_fault_wait" -lt 1000 ]; do
   /usr/bin/sleep .02; test_fault_wait=$((test_fault_wait+1))
  done
  [ -s "$fixture/fault-killed-host-stat" ] || return 92
  # Only OS evidence changes. The real held process is still alive, and all
  # cleanup remains bound to its captured original PID/start time.
  /usr/bin/rm -f "$fixture/proc/$child_pid/host-shell"
  if [ TEST_FAULT = unknown_stat ]; then
   builtin printf unreadable > "$fixture/refusal-stat-unreadable"
  elif [ TEST_FAULT = reused_lifetime ]; then
   test_birth_tail=${test_birth_before##*) }
   set -- $test_birth_tail
   shift
   # Reach the ticks comparison, not the already-covered live-state refusal.
   # The OS model reports another lifetime's zombie; the actual held host
   # process remains alive and is checked/cleaned with its original stat.
   test_reuse_stat="${test_birth_before%)*}) Z"
   test_field=1
   for test_value in "$@"; do
    if [ "$test_field" = 19 ]; then test_value=$((test_value+100000)); fi
    test_reuse_stat="$test_reuse_stat $test_value"
    test_field=$((test_field+1))
   done
   builtin printf '%s\n' "$test_reuse_stat" > "$fixture/proc/$child_pid/stat"
  fi
  builtin printf '%s\n' "$test_birth_before"
 elif [ "$#" = 1 ] && [ -f "$fixture/refusal-stat-unreadable" ] &&
      [ "$1" = "$fixture/proc/$(/usr/bin/cat "$fixture/fault-gate-pid")/stat" ]; then
  return 94
 else test_original_refusal_cat "$@"; fi
}
test_before_refusal_readlink=$(declare -f readlink)
eval "${test_before_refusal_readlink/readlink/test_original_refusal_readlink}"
readlink() {
 if [ TEST_FAULT = still_live ] && [ -f "$fixture/fault-unrecorded-state" ] &&
    [ "$1" = "$fixture/proc/$(/usr/bin/cat "$fixture/fault-gate-pid")/exe" ]; then
  builtin printf '/system/bin/unknown-image\n'
 else test_original_refusal_readlink "$@"; fi
}
if [ "${2:-}" = gate ]; then
 builtin printf '%s\n' "$$" > "$fixture/fault-gate-pid"
 /usr/bin/cat "/proc/$$/stat" > "$fixture/fault-gate-host-stat"
 test_held_gate=0
 while [ "$test_held_gate" -lt 1500 ]; do
  /usr/bin/sleep .02; test_held_gate=$((test_held_gate+1))
 done
 lifecycle_fixture_exit 93
fi
'''.replace("TEST_FAULT", fault)
    raw, fixed, programs, run = background_fixture(
        installer, request_stop=False, persistent_child=True, extra_hook=hook)
    folder = installer.root / fixed["run"].lstrip("/")
    try:
        assert run("launch").returncode == 0
        _wait_guardian_fault(installer, fixed, "fault-killed-host-stat", seconds=160)
        state = (installer.root / "fault-unrecorded-state").read_text().strip()
        child = (installer.root / "fault-gate-pid").read_text().strip()
        assert state == "1:0:" + child
        worker = (folder / "worker.identity").read_text().split(":")[0]
        deadline = time.monotonic() + 60
        while (installer.root / "proc" / worker / "stat").exists() and time.monotonic() < deadline:
            time.sleep(.05)
        assert not (installer.root / "proc" / worker / "stat").exists()
        assert (installer.root / "refusal-recovery-read").read_text() == "post-wait-unrecorded-child-exited\n"
        expected_ticks = (installer.root / "refusal-expected-ticks").read_text().strip()
        original_ticks = (installer.root / "fault-gate-host-stat").read_text().rsplit(") ", 1)[1].split()[19]
        assert expected_ticks == original_ticks
        observed_stat = (installer.root / "refusal-observed-stat").read_text()
        if fault == "unknown_stat":
            assert observed_stat == "read-error\n"
        else:
            observed_fields = observed_stat.rsplit(") ", 1)[1].split()
            if fault == "still_live":
                assert observed_fields[0] not in ("Z", "X")
                assert observed_fields[19] == expected_ticks
            else:
                assert observed_fields[0] == "Z"
                assert observed_fields[19] != expected_ticks
        _signal_exact_host_lifetime(installer, child,
            (installer.root / "fault-gate-host-stat").read_text(), "0")
        writer = (installer.root / "fault-cancel-writer-pid").read_text().strip()
        _signal_exact_host_lifetime(installer, writer,
            (installer.root / "fault-cancel-writer-host-stat").read_text(), "0")
        for name in ("child.offer", "child.offer.pending", "child.admit", "child.admit.pending", "final"):
            assert not (folder / name).exists()
        assert (folder / "child.cancel.pending").read_bytes() == b""
        queried = run("read")
        assert queried.returncode == 0
        assert queried.stdout == "X2DII_LIFECYCLE_UNCERTAIN:" + peer.sha(raw) + ":NO_FINAL_RECEIPT\n"
        assert "X2DII_ORIGINAL_GUI_RESTORED" not in (folder / "lifecycle.log").read_text()
        assert (installer.root / "gui-service-state").read_text() == "stopped"
        assert (installer.root / "tmp/x2dii-menu-install.lock").is_dir()
        operations = (installer.root / "operations").read_text().splitlines()
        assert not any(line.startswith(("start:", "kill:")) for line in operations)
        assert not (installer.root / "launch-args").exists()
        assert (installer.root / "proc/mounts").read_text() == installer.mount_line
        assert (installer.root / "system/etc/init/camera-gui.rc").read_bytes() == peer.boot.STOCK.read_bytes()
        for entry in installer.manifest["candidate"]["files"]:
            assert peer.sha((installer.root / entry["target"].lstrip("/")).read_bytes()) == entry["sha256"]
    except BaseException as failure:
        _retain_guardian_failure(installer, failure)
        raise
    finally:
        _cleanup_guardian_fixture(installer)
