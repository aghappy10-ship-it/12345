"""Current-source scalar OS-query regressions; no camera or lifecycle runs.

The real installer.run_script wrapper executes getprop/pidof over an empty
program. Dynamic cat is traced at its existing OS seam, not replaced by a
successful query result. Historical RED artifacts and baseline pins stay
separate from this execution's exact current source/runtime identities.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from types import CodeType

import pytest

from tests.test_release_lifecycle import installer
from tests.test_peer_install import SH
from tools import prepare_peer_install as peer, release_identity


SELF = Path(__file__).resolve()
ROOT = peer.ROOT.resolve()
WRAPPER = ROOT / "tests/test_peer_install.py"
HISTORICAL_WRAPPER_SHA = "4e5947ac8f9c8f0c871c30b6cef54d11f8b8b3d5d85d2524ab1ad38bcb524284"
HISTORICAL_SOURCE_SHA = "8affa335e88e6cccb860da0599c94a3388e79c0c26a37fffa9b2d4c7fad5cd33"
EMPTY_PROGRAM = "#!/system/bin/sh\n# SESSION_DATA_PARSER_BEGIN\n# SESSION_DATA_PARSER_END\n"
TRACE_NAME = "pending-gui-cat.trace"
HOST_FILES = {
    "launcher": SH,
    "native_bash": SH.parent.parent / "usr/bin/bash.exe",
    "posix_sh": SH.parent.parent / "usr/bin/sh.exe",
    "native_cat": SH.parent.parent / "usr/bin/cat.exe",
}
TRACE_HOOK = r'''
cat() {
 case "$1" in
  "$fixture/gui-service-state")
   printf 'read\n' >> "$fixture/pending-gui-cat.trace" || return $?
   STATE_READ_OPERATION
   ;;
  *) /usr/bin/cat "$@";;
 esac
}
'''


def file_identities(paths):
    return {name: {"path": str(path.resolve()), "bytes": len(raw),
                   "sha256": hashlib.sha256(raw).hexdigest()}
            for name, path in paths.items() for raw in (path.read_bytes(),)}


def current_run_script_code(wrapper_bytes, actual):
    # Compile only; never execute or import the independently compiled module.
    # run_script contains no Python asserts, so pytest's assertion rewriting
    # does not alter this method's code. A module label/path/hash alone would
    # not prove that the fixture's actual bound callable is current.
    module_code = compile(wrapper_bytes, actual.co_filename, "exec")
    class_code, = (value for value in module_code.co_consts
                   if isinstance(value, CodeType) and value.co_name == "PeerInstallTests")
    expected, = (value for value in class_code.co_consts
                 if isinstance(value, CodeType) and value.co_name == "run_script")
    return expected


def query(installer, record_property, body, *, raw=b"running",
          fault_output=None, mode="normal"):
    if sys.flags.optimize or not sys.dont_write_bytecode:
        raise RuntimeError("Scalar query controls require unoptimized Python with bytecode writes disabled")
    wrapper_before = WRAPPER.read_bytes()
    before_sources = release_identity.source_inputs()
    before_hosts = file_identities(HOST_FILES)
    before_test = SELF.read_bytes()
    actual = installer.run_script.__func__.__code__
    assert Path(actual.co_filename).resolve() == WRAPPER
    assert actual == current_run_script_code(wrapper_before, actual), (
        "Actual installer.run_script callable differs from current wrapper source")
    assert before_sources["tests/test_peer_install.py"] == {
        "sha256": peer.sha(wrapper_before), "bytes": len(wrapper_before)}
    installer.posix = "/f" + installer.root.as_posix()[2:]
    installer.core_hashes, installer.core_links = {}, {}
    (installer.root / "gui-service-state").write_bytes(raw)
    trace_path = installer.root / TRACE_NAME
    # Independent queries never reuse a previous trace, even in the same
    # fixture; same-shell repeated reads are checked in one separate query.
    assert not trace_path.exists(), "A scalar-query trace must start absent"
    installer.scripts["current-scalar-query"] = EMPTY_PROGRAM + body
    if fault_output is None:
        operation = '/usr/bin/cat "$@"'
    else:
        assert fault_output in ("running", "")
        operation = "printf '%s' '" + fault_output + "'; return 13"
    hook = TRACE_HOOK.replace("STATE_READ_OPERATION", operation)
    launched = []

    def execute(source, arguments):
        command = [str(SH), "-s", "--", *arguments]
        launched.append({"command": command,
                         "executed_adapter_sha256": peer.sha(source.encode("ascii"))})
        return subprocess.run(command, input=source.encode("ascii"),
                              capture_output=True, timeout=30)

    result = installer.run_script("current-scalar-query", mode=mode,
                                  boundary_hook=hook, process_runner=execute)
    trace_exists = trace_path.exists()
    trace = trace_path.read_bytes() if trace_exists else b""
    assert trace in tuple(b"read\n" * count for count in range(5)), (
        "Unexpected state-read trace bytes", trace)
    reads = len(trace) // len(b"read\n")
    after_sources = release_identity.source_inputs()
    after_hosts = file_identities(HOST_FILES)
    wrapper_after, after_test = WRAPPER.read_bytes(), SELF.read_bytes()
    evidence = {
        "camera_accesses": 0, "lifecycle_invoked": False, "installable": False,
        "counts_as_release_pass": False, "mode": mode, "input_hex": raw.hex(),
        "query_body": body, "returncode": result.returncode,
        "stdout_hex": result.stdout.hex(), "stderr_hex": result.stderr.hex(),
        "state_read_hook_installed": True,
        "fault_hook_installed": fault_output is not None,
        "fault_boundary_entered": fault_output is not None and reads > 0,
        "state_read_call_count": reads, "state_read_trace_exists": trace_exists,
        "state_read_trace_hex": trace.hex(), "launches": launched,
        "current_wrapper_sha256_before": peer.sha(wrapper_before),
        "current_wrapper_sha256_after": peer.sha(wrapper_after),
        "current_callable_matches_compiled_source": True,
        "current_source_input_count": len(before_sources),
        "current_source_inputs_sha256_before": peer.sha(release_identity.canonical(before_sources)),
        "current_source_inputs_sha256_after": peer.sha(release_identity.canonical(after_sources)),
        "current_test_sha256_before": peer.sha(before_test),
        "current_test_sha256_after": peer.sha(after_test),
        "current_test_path": str(SELF), "host_files_before": before_hosts,
        "host_files_after": after_hosts,
        "historical_wrapper_sha256_reference_only": HISTORICAL_WRAPPER_SHA,
        "historical_source_sha256_reference_only": HISTORICAL_SOURCE_SHA,
        "operations_absent": all(not (installer.root / name).exists()
            for name in ("operations", "cleanup-operations", "rc-operations")),
    }
    record_property("current_pidof_state_read", json.dumps(evidence, sort_keys=True))
    assert len(launched) == 1
    assert before_sources == after_sources and wrapper_before == wrapper_after
    assert before_hosts == after_hosts and before_test == after_test
    assert evidence["operations_absent"]
    return result, trace, evidence


@pytest.mark.parametrize("command", ("getprop init.svc.camera-gui", "pidof camera-gui"))
@pytest.mark.parametrize("fault_output", ("running", ""))
def test_failed_state_read_is_entered_once_and_preserves_status13(
        installer, record_property, command, fault_output):
    result, trace, evidence = query(installer, record_property, command + "\n",
                                    fault_output=fault_output)
    assert trace == b"read\n" and evidence["state_read_call_count"] == 1
    assert evidence["fault_hook_installed"] is True
    assert evidence["fault_boundary_entered"] is True
    stdout = fault_output.encode() if command.startswith("getprop ") else b""
    assert (result.returncode, result.stdout, result.stderr) == (13, stdout, b"")


@pytest.mark.parametrize("raw,pid_status,pid_stdout", (
    (b"running", 0, b"234\n"), (b"stopped", 1, b""),
    (b"unknown", 1, b""), (b"", 1, b""),
    (b"running\n", 0, b"234\n"), (b"running\r\n", 0, b"234\n"),
))
@pytest.mark.parametrize("command", ("getprop init.svc.camera-gui", "pidof camera-gui"))
def test_successful_state_reads_remain_dynamic_with_existing_raw_byte_contract(
        installer, record_property, raw, pid_status, pid_stdout, command):
    result, trace, evidence = query(installer, record_property, command + "\n", raw=raw)
    assert trace == b"read\n" and evidence["state_read_call_count"] == 1
    assert evidence["fault_hook_installed"] is False
    assert evidence["fault_boundary_entered"] is False
    expected = (0, raw, b"") if command.startswith("getprop ") else (pid_status, pid_stdout, b"")
    assert (result.returncode, result.stdout, result.stderr) == expected


def test_same_shell_queries_read_changed_current_file_without_cached_state(installer, record_property):
    body = r'''
getprop init.svc.camera-gui
printf '\nPROP1_STATUS=%s\n' "$?"
pidof camera-gui
printf 'PID1_STATUS=%s\n' "$?"
printf stopped > "$fixture/gui-service-state"
getprop init.svc.camera-gui
printf '\nPROP2_STATUS=%s\n' "$?"
pidof camera-gui
printf 'PID2_STATUS=%s\n' "$?"
'''
    result, trace, evidence = query(installer, record_property, body)
    assert trace == b"read\n" * 4 and evidence["state_read_call_count"] == 4
    assert evidence["fault_hook_installed"] is False and evidence["fault_boundary_entered"] is False
    assert (result.returncode, result.stdout, result.stderr) == (
        0, b"running\nPROP1_STATUS=0\n234\nPID1_STATUS=0\n"
        b"stopped\nPROP2_STATUS=0\nPID2_STATUS=1\n", b"")


@pytest.mark.parametrize("mode,pid_status,pid_stdout", (
    ("running", 0, b"234\n"), ("pidof_error", 2, b""),
))
def test_modeled_pidof_shortcuts_make_zero_state_reads_with_fault_hook_installed(
        installer, record_property, mode, pid_status, pid_stdout):
    result, trace, evidence = query(installer, record_property, "pidof camera-gui\n",
                                    mode=mode, fault_output="running")
    assert trace == b"" and evidence["state_read_call_count"] == 0
    assert evidence["state_read_trace_exists"] is False
    assert evidence["fault_hook_installed"] is True
    assert evidence["fault_boundary_entered"] is False
    assert (result.returncode, result.stdout, result.stderr) == (pid_status, pid_stdout, b"")


def test_native_host_crlf_substitution_keeps_original_and_guarded_query_agreement(
        installer, record_property):
    # The earlier draft incorrectly predicted status1 for host CRLF. This
    # literal comparison proves the actual original/guarded host expression
    # agreement; it neither normalizes cat output nor models target sh.
    body = r'''
if [ "$(cat "$fixture/gui-service-state")" = running ]; then
 printf 'ORIGINAL_RUNNING\n'
else printf 'ORIGINAL_OTHER\n'; fi
state=$(cat "$fixture/gui-service-state") || exit $?
if [ "$state" = running ]; then
 printf 'GUARDED_RUNNING\n'
else printf 'GUARDED_OTHER\n'; fi
'''
    result, trace, evidence = query(installer, record_property, body, raw=b"running\r\n")
    assert trace == b"read\n" * 2 and evidence["state_read_call_count"] == 2
    assert (result.returncode, result.stdout, result.stderr) == (
        0, b"ORIGINAL_RUNNING\nGUARDED_RUNNING\n", b"")
