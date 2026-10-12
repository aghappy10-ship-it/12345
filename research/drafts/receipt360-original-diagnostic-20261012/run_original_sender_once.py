"""UNEXECUTED original sender360 diagnostic; no changed assertions or camera.

Run only after the fixed complete audit naturally finishes every collected
node. One fixed output directory is claimed exclusively. Original run(action)
is called once, with its existing text=True, launch8/read20/final360 contracts.
Returned strings are TEXT observations, never raw native pipe byte claims.
The sole host hook records the existing final.pending -> final mv invocation.
"""
from datetime import datetime, timezone
import ctypes
from ctypes import wintypes
import hashlib
import inspect
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
AUDIT = ROOT / "build/peer-route-review-20261011-host-fixed"
RUN = HERE / "run-once"
RUNNER = AUDIT / "run_audit.py"
RUNNER_SHA = "3d45dafca02e42499ef0322c3e23ca750f407824e2ca0f1c1d45c49e6930fb19"
PYTHON = Path("C:/Users/1/AppData/Local/Programs/Python/Python311/python.exe")
PYTHON_SHA = "5f7b89a612c9b8af1d6456cdfcd1dbe5ca630849e79aebced9bee9a6694952ec"
INPUT_SHA = "655e219d41b6c6dd4b6f994ab3a89ed76cf41e0d09d4191d37fe53ba4fec79b5"
NODE = "tests/test_menu_lifecycle_transport.py::test_fixed_sender_verifies_final_hash_and_does_not_invent_ui_success"
FAILURE_SHA = "7b9beceff30c36c3c3b63b34c458d1bd1ff402afbd9ec59328de1509e4b0a0b7"
ROLES = "lwtqs"
LOG_LEAF = "receipt360-final-mv.log"
OUTPUTS = (
    "start.json", "inputs-before.json", "inputs-after.json", "result.json",
    "fixture-bindings.json", "session.data", "shell-wrapper.sh", "final-mv.log",
    "original-failure-0005.json",
    *("formal-" + role + ".sh" for role in ROLES),
    *("host-" + role + ".sh" for role in ROLES),
)
ORIGINAL_ACTORS = (("worker", "1696", "803676787"),
                   ("controller", "2414", "803702039"), ("child", "8389", "803908014"))
ORIGINAL_CAPTURE = ROOT / "build/gui-guardian-failures/fixture-ojn44xoe"
ACTOR_CAPTURE_SHA = {
    "proc/1696/host-shell": "ce635c4eabff5e4f56dba8fb1e39ca235530aa2b6b18533eef1af3862016c577",
    "proc/1696/host-stat": "13e307e038e7c7c3044e3b2da662a0c6b9b07823e796f18341d9365a4083c71f",
    "proc/2414/host-shell": "ce635c4eabff5e4f56dba8fb1e39ca235530aa2b6b18533eef1af3862016c577",
    "proc/2414/host-stat": "d47ae060693678e38851c596fa8337f4d14426fe5d0c1c8f20715f5b6608e802",
    "test-child-pid": "20a09cb9ad65cf969e7ae8ad25139d01e17ba11ef3a83dbf9c0c411bdf4008d0",
    "test-child-host-stat": "9a199943b0dc4eec97ed33e404a9bf8f5767160c897eb288ed243af1be1e4372",
}

sys.path.insert(0, str(ROOT))
from tools import release_identity as identity
from tools.output_guard import guard_output


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def checked_bytes(path):
    """A guarded, stable regular-file read; not an atomic multi-file snapshot."""
    path = guard_output(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ValueError("unshared regular evidence required: " + str(path))
    raw = path.read_bytes()
    after = path.lstat()
    fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns")
    if len(raw) != before.st_size or any(getattr(before, key) != getattr(after, key) for key in fields):
        raise ValueError("evidence changed while read: " + str(path))
    return raw


def load_reviewed_runner():
    raw = checked_bytes(RUNNER)
    if digest(raw) != RUNNER_SHA:
        raise ValueError("reviewed no-overwrite writer source changed")
    namespace = {"__name__": "_receipt360_reviewed_writer", "__file__": str(RUNNER)}
    # Only definitions/imports from the pinned runner; never its audit/main.
    exec(compile(raw, str(RUNNER), "exec"), namespace)
    return namespace


def process_terminal(record, expected_exit):
    """Refuse overlap with the exact recorded Windows PID/creation lifetime."""
    if (type(record.get("pid")) is not int or record["pid"] <= 0
            or type(record.get("birth_filetime_100ns")) is not int or record["birth_filetime_100ns"] <= 0):
        raise ValueError("audit process identity incomplete")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    opening = kernel.OpenProcess
    opening.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    opening.restype = wintypes.HANDLE
    close = kernel.CloseHandle
    close.argtypes = (wintypes.HANDLE,)
    close.restype = wintypes.BOOL
    times = kernel.GetProcessTimes
    times.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    times.restype = wintypes.BOOL
    wait = kernel.WaitForSingleObject
    wait.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    wait.restype = wintypes.DWORD
    exit_code = kernel.GetExitCodeProcess
    exit_code.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
    exit_code.restype = wintypes.BOOL
    handle = opening(0x00100000 | 0x1000, False, record["pid"])
    if not handle:
        error = ctypes.get_last_error()
        if error == 87:  # The recorded PID no longer exists.
            return {"pid": record["pid"], "state": "recorded_pid_absent"}
        raise ctypes.WinError(error)
    primary = None
    try:
        creation, ended, system, user = (wintypes.FILETIME() for _ in range(4))
        if not times(handle, ctypes.byref(creation), ctypes.byref(ended), ctypes.byref(system), ctypes.byref(user)):
            raise ctypes.WinError(ctypes.get_last_error())
        birth = (creation.dwHighDateTime << 32) | creation.dwLowDateTime
        if birth != record["birth_filetime_100ns"]:
            return {"pid": record["pid"], "state": "pid_reused_original_lifetime_ended", "current_birth": birth}
        if wait(handle, 0) != 0:
            raise ValueError("recorded full-audit process remains active or unknown")
        code = wintypes.DWORD()
        if not exit_code(handle, ctypes.byref(code)):
            raise ctypes.WinError(ctypes.get_last_error())
        if expected_exit is not None and code.value != expected_exit:
            raise ValueError("recorded audit exit code differs")
        return {"pid": record["pid"], "state": "recorded_lifetime_terminal", "exit_code": code.value}
    except BaseException as error:
        primary = error
        raise
    finally:
        if not close(handle):
            if primary is None:
                raise ctypes.WinError(ctypes.get_last_error())


def require_original_actor_stop(failure):
    """One read-only sample of three captured failure5 lifetimes, not a tree scan."""
    if (failure.get("when") != "call" or failure.get("nodeid") != NODE
            or failure.get("outcome") != "failed" or failure.get("qualification") is not False
            or type(failure.get("longrepr")) is not str
            or str(ORIGINAL_CAPTURE) not in failure["longrepr"]
            or "Guardian cleanup incomplete" in failure["longrepr"]):
        raise ValueError("original sender completed-cleanup/capture binding differs")

    def captures():
        raw = {}
        for leaf, expected in ACTOR_CAPTURE_SHA.items():
            raw[leaf] = checked_bytes(ORIGINAL_CAPTURE / leaf)
            if digest(raw[leaf]) != expected:
                raise ValueError("original actor evidence differs: " + str(ORIGINAL_CAPTURE / leaf))
        return raw

    def stat_fields(raw, pid):
        line = raw.decode("ascii").strip()
        if not line.startswith(pid + " (") or ") " not in line:
            raise ValueError("malformed fixed actor stat")
        fields = line.rsplit(") ", 1)[1].split()
        if (len(fields) < 20 or len(fields[0]) != 1 or not fields[1].isdecimal()
                or not fields[19].isdecimal() or int(fields[19]) <= 0):
            raise ValueError("unknown fixed actor stat")
        return fields[0], fields[1], fields[19]

    before = captures()
    for role, pid, ticks in ORIGINAL_ACTORS:
        leaf = "test-child-host-stat" if role == "child" else "proc/" + pid + "/host-stat"
        if stat_fields(before[leaf], pid)[2] != ticks:
            raise ValueError("original captured actor birth differs: " + leaf)
    # Existing read-only block, with root/self availability before accepting absence.
    command = r'''
unset GLOBIGNORE || exit 87
set +f
shopt -s nullglob || exit 87
test_diag_self_pid=$$
test_diag_anchor_ticks=''
test_diag_proc_available() {
 [ -d /proc ] && [ -r /proc ] && [ -x /proc ] && [ ! -L /proc ] || return 1
 test_diag_self_dirs=( /proc/[${test_diag_self_pid:0:1}]${test_diag_self_pid:1} )
 [ "${#test_diag_self_dirs[@]}" = 1 ] && [ "${test_diag_self_dirs[0]}" = "/proc/$$" ] &&
  [ -d "/proc/$$" ] && [ -r "/proc/$$" ] && [ -x "/proc/$$" ] &&
  [ ! -L "/proc/$$" ] && [ ! -L "/proc/$$/stat" ] || return 1
 IFS= read -r test_diag_self_line 2>/dev/null < "/proc/$$/stat" || return 1
 case "$test_diag_self_line" in "$$ ("*) :;; *) return 1;; esac
 test_diag_self_tail=${test_diag_self_line##*) }
 [ "$test_diag_self_tail" != "$test_diag_self_line" ] || return 1
 test_diag_self_fields=( $test_diag_self_tail )
 [ "${#test_diag_self_fields[@]}" -ge 20 ] || return 1
 case "${test_diag_self_fields[19]}" in ''|*[!0-9]*) return 1;; esac
 [ "${test_diag_self_fields[19]}" != 0 ] || return 1
 [ -z "$test_diag_anchor_ticks" ] || [ "$test_diag_anchor_ticks" = "${test_diag_self_fields[19]}" ] || return 1
 test_diag_anchor_ticks=${test_diag_self_fields[19]}
}
builtin printf 'SAMPLE_BEGIN sampler_pid=%s epoch=%s\n' "$$" "$EPOCHREALTIME"
test_diag_proc_available || exit 87
builtin printf 'PROC_ANCHOR sampler_pid=%s ticks=%s root=available raw=%s\n' \
 "$$" "$test_diag_anchor_ticks" "$test_diag_self_line"
while [ "$#" -gt 0 ]; do
 test_diag_pid=$1; test_diag_expected_ticks=$2
 shift 2
 builtin printf 'BEGIN pid=%s expected_ticks=%s epoch=%s\n' \
  "$test_diag_pid" "$test_diag_expected_ticks" "$EPOCHREALTIME"
 test_diag_proc_available || exit 87
 test_diag_pid_dirs=( /proc/[${test_diag_pid:0:1}]${test_diag_pid:1} )
 if [ "${#test_diag_pid_dirs[@]}" = 0 ]; then
  test_diag_proc_available || exit 87
  builtin printf 'END pid=%s epoch=%s status=absent\n' "$test_diag_pid" "$EPOCHREALTIME"
 elif [ "${#test_diag_pid_dirs[@]}" != 1 ] || [ "${test_diag_pid_dirs[0]}" != "/proc/$test_diag_pid" ] ||
      [ -L "/proc/$test_diag_pid" ] || [ -L "/proc/$test_diag_pid/stat" ] ||
      [ ! -d "/proc/$test_diag_pid" ] || [ ! -r "/proc/$test_diag_pid" ] || [ ! -x "/proc/$test_diag_pid" ]; then
  builtin printf 'END pid=%s epoch=%s status=path_unknown\n' "$test_diag_pid" "$EPOCHREALTIME"
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
test_diag_proc_available || exit 87
builtin printf 'PROC_ANCHOR sampler_pid=%s ticks=%s root=available raw=%s\n' \
 "$$" "$test_diag_anchor_ticks" "$test_diag_self_line"
builtin printf 'SAMPLE_END sampler_pid=%s epoch=%s\n' "$$" "$EPOCHREALTIME"
'''
    from tests.test_peer_install import SH
    clock_before = time.monotonic()
    result = subprocess.run([str(SH), "-c", command, "timestamped-original-failure5-actor-stop",
        *[value for _, pid, ticks in ORIGINAL_ACTORS for value in (pid, ticks)]],
        capture_output=True, text=True, timeout=8)
    clock_after = time.monotonic()
    if result.returncode != 0 or result.stderr:
        raise ValueError("fixed actor read-only sample failed")
    lines = result.stdout.splitlines()
    if (len(lines) != 10 or not lines[0].startswith("SAMPLE_BEGIN sampler_pid=")
            or not lines[-1].startswith("SAMPLE_END sampler_pid=")):
        raise ValueError("fixed actor sample is incomplete")
    anchors = [lines[0].split(), lines[-1].split()]
    if (any(len(row) != 3 or not row[1][12:].isdecimal() or int(row[1][12:]) <= 0
            or not row[2].startswith("epoch=") or not row[2][6:].replace(".", "", 1).isdecimal()
            for row in anchors) or anchors[0][1] != anchors[1][1]):
        raise ValueError("fixed actor sample anchors differ")
    proc_anchors = []
    for line in (lines[1], lines[-2]):
        metadata, _, raw = line.partition(" raw=")
        tokens = metadata.split()
        fields = dict(token.split("=", 1) for token in tokens[1:])
        if (not tokens or tokens[0] != "PROC_ANCHOR" or len(tokens) != 4
                or set(fields) != {"sampler_pid", "ticks", "root"} or fields["root"] != "available"
                or fields["sampler_pid"] != anchors[0][1][12:]
                or stat_fields(raw.encode("ascii"), fields["sampler_pid"])[2] != fields["ticks"]):
            raise ValueError("sampler /proc availability or self identity is unknown")
        proc_anchors.append(fields)
    if proc_anchors[0] != proc_anchors[1]:
        raise ValueError("sampler /proc self birth changed")
    actors = []
    for index, (role, pid, ticks) in enumerate(ORIGINAL_ACTORS):
        begin = lines[2 + index * 2].split()
        if (len(begin) != 4 or begin[:3] != ["BEGIN", "pid=" + pid, "expected_ticks=" + ticks]
                or not begin[3].startswith("epoch=") or not begin[3][6:].replace(".", "", 1).isdecimal()):
            raise ValueError("fixed actor sample identity differs")
        metadata, _, raw = lines[3 + index * 2].partition(" raw=")
        tokens = metadata.split()
        fields = dict(token.split("=", 1) for token in tokens[1:])
        if (tokens[0] != "END" or fields.get("pid") != pid or len(fields) != len(tokens) - 1
                or not fields.get("epoch", "").replace(".", "", 1).isdecimal()):
            raise ValueError("fixed actor result identity differs")
        if fields.get("status") == "absent" and set(fields) == {"pid", "epoch", "status"}:
            state = "absent"
        elif (fields.get("status") == "observed" and fields.get("expected_ticks") == ticks
                and set(fields) == {"pid", "epoch", "status", "state", "ppid", "ticks", "expected_ticks"}):
            observed = stat_fields(raw.encode("ascii"), pid)
            if observed != (fields["state"], fields["ppid"], fields["ticks"]):
                raise ValueError("fixed actor native stat/result differs")
            state = "reused" if observed[2] != ticks else observed[0]
            if state not in ("reused", "Z", "X"):
                raise ValueError("same original actor remains live: " + role)
        else:
            raise ValueError("fixed actor state is unknown: " + role)
        actors.append({"role": role, "pid": int(pid), "start_ticks": ticks, "state": state})
    after = captures()
    if before != after:
        raise ValueError("original actor evidence changed during sampling")
    binding = lambda rows: {leaf: {"sha256": digest(raw), "bytes": len(raw)} for leaf, raw in rows.items()}
    return {"only_fixed_original_failure5_actors": True, "actors": actors,
        "capture_before": binding(before), "capture_after": binding(after),
        "clock_before": clock_before, "clock_after": clock_after, "stdout_text": result.stdout,
        "proc_anchor_before": proc_anchors[0], "proc_anchor_after": proc_anchors[1],
        "completed_original_cleanup_call_evidence": "bound failure5 call report; no cleanup-incomplete note",
        "limits": "Sequential exact old-lifetime sample; no all-helper/descendant/computer-idle or camera proof"}


def require_completed_audit(runner):
    names = (
        "admin-launch-start.json", "admin-launch-child-start.json", "admin-launch-result.json",
        "AUDIT.json", "inputs-before.json", "inputs-after.json", "collection.json",
        "execution-collection.json", "execution.json", "suite.start.json",
        "suite.process.json", "collection.process.json", "full-offline-suite.xml",
        "failure-0005.json",
    )
    raw = {name: checked_bytes(AUDIT / name) for name in names}
    data = {name: json.loads(value) for name, value in raw.items() if name.endswith(".json")}
    start, child, admin = (data[name] for name in names[:3])
    audit = data["AUDIT.json"]
    before, after = data["inputs-before.json"], data["inputs-after.json"]
    collected, selected, executed = (data[name] for name in
        ("collection.json", "execution-collection.json", "execution.json"))
    suite, collection = data["suite.process.json"], data["collection.process.json"]
    suite_start = data["suite.start.json"]
    command = [str(PYTHON), "-B", "-X", "faulthandler", str(RUNNER)]
    if (start.get("command") != command or start.get("administrator") is not True
            or start.get("runner_sha256") != RUNNER_SHA or start.get("python_sha256") != PYTHON_SHA
            or child.get("command") != command or child.get("runner_sha256") != RUNNER_SHA
            or admin.get("admitted") is not True or admin.get("child") != child
            or type(admin.get("exit_code")) is not int or admin["exit_code"] not in (0, 1)
            or admin.get("spawn_error") is not None or admin.get("start_record_error") is not None
            or "termination_exit_code" in admin):
        raise ValueError("full audit has no bound natural administrator completion")
    for record, suffix, code in ((collection, "--collect", 0), (suite, "--suite", None)):
        if (record.get("outcome") != "finished" or record.get("command") != command + [suffix]
                or type(record.get("exit_code")) is not int or record["exit_code"] not in (0, 1)
                or (code is not None and record["exit_code"] != code)
                or any(key in record for key in ("termination_exit_code", "spawn_error", "start_record_error"))):
            raise ValueError("collection/suite timed out, was cancelled, or lacks natural completion")
        output_name = record.get("output_file")
        if type(output_name) is not str or Path(output_name).name != output_name:
            raise ValueError("invalid audit output member")
        output = checked_bytes(AUDIT / output_name)
        if len(output) != record.get("output_bytes") or digest(output) != record.get("output_sha256"):
            raise ValueError("natural child output binding differs")
    if (audit.get("status") not in ("LOCAL_AUDIT_FAILED", "LOCAL_SUITE_COMPLETE", "LOCAL_SUITE_COMPLETE_WITH_EXPLICIT_SKIPS")
            or audit.get("child_process") != suite or audit.get("collection_process") != collection
            or suite.get("child") != suite_start
            or child.get("parent_pid") != start["launcher"].get("pid")
            or suite_start.get("parent_pid") != child.get("pid")
            or collection["child"].get("parent_pid") != child.get("pid")
            or audit.get("exit_code") != suite["exit_code"]
            or audit.get("all_listed_inputs_unchanged") is not True or before.get("files") != after.get("files")
            or audit.get("input_count") != len(before["files"])
            or audit.get("exact_collected_tests_started_and_finished") is not True
            or audit.get("actual_runtime_inventory_matches_build") is not True
            or audit.get("junit_validation_error") is not None
            or executed.get("exit_code") != suite["exit_code"]
            or not runner["execution_complete"](collected, selected, executed)):
        raise ValueError("full audit is incomplete, interrupted, or inconsistent")
    expected_admin_exit = 1 if audit["status"] == "LOCAL_AUDIT_FAILED" else 0
    if admin["exit_code"] != expected_admin_exit:
        raise ValueError("administrator exit differs from the final audit outcome")
    if collected.get("duplicate_origins") or collected.get("count") != len(collected.get("items", [])):
        raise ValueError("full audit collection differs")
    runner["validate_collection"](collected, runner["approved_test_files"](before))
    summary = runner["validate_junit"](AUDIT / "full-offline-suite.xml", collected, executed)
    if (NODE not in executed["finished"] or audit.get("collected") != collected["count"]
            or audit.get("main_testcase_count") != summary["main_testcase_count"]
            or audit.get("passing_subtest_count") != executed.get("passing_subtest_count")
            or audit.get("failures") != summary["failures"] or audit.get("skips") != summary["skips"]):
        raise ValueError("materialized full-audit execution differs")
    artifacts = audit.get("artifacts")
    bound_names = set(names) - {"admin-launch-result.json", "AUDIT.json"}
    if type(artifacts) is not dict or not bound_names.issubset(artifacts):
        raise ValueError("final audit artifact membership is incomplete")
    for name, expected in artifacts.items():
        if Path(name).name != name or digest(checked_bytes(AUDIT / name)) != expected:
            raise ValueError("final audit artifact binding differs")
    if digest(checked_bytes(AUDIT / "admin-launch-output.log")) != admin.get("output_sha256"):
        raise ValueError("closed administrator output binding differs")
    failure = data["failure-0005.json"]
    if digest(raw["failure-0005.json"]) != FAILURE_SHA or failure.get("nodeid") != NODE or failure.get("outcome") != "failed":
        raise ValueError("original sender failure reference differs")
    terminals = [process_terminal(start["launcher"], admin["exit_code"]),
                 process_terminal(child, admin["exit_code"]),
                 process_terminal(suite_start, suite["exit_code"]),
                 process_terminal(collection["child"], collection["exit_code"])]
    current = runner["snapshot"]()
    if current["files"] != before["files"]:
        raise ValueError("current source/runtime bytes differ from the completed frozen audit")
    sources = identity.source_inputs()
    if len(sources) != 230 or identity.sha(identity.canonical(sources)) != INPUT_SHA:
        raise ValueError("original230/655e source identity differs")
    actor_stop = require_original_actor_stop(failure)
    current_after, sources_after = runner["snapshot"](), identity.source_inputs()
    if current_after["files"] != current["files"] or sources_after != sources:
        raise ValueError("source/runtime bytes changed during fixed actor sampling")
    return {"files": {name: digest(value) for name, value in raw.items()}, "processes": terminals,
            "full_audit_status": audit["status"], "full_audit_failures": summary["failures"],
            "known_original_actor_stop": actor_stop,
            "source_before_sha256": identity.sha(identity.canonical(sources)),
            "source_after_sha256": identity.sha(identity.canonical(sources_after)),
            "listed_runtime_before_sha256": digest(identity.canonical(current["files"])),
            "listed_runtime_after_sha256": digest(identity.canonical(current_after["files"])),
            "original_failure_sha256": FAILURE_SHA}, current, sources, raw["failure-0005.json"]


FINAL_MV_HOOK = r'''
# Save and delegate the actual preceding OS adapter once per role.
receipt360_saved_mv=$(declare -f mv)
eval "${receipt360_saved_mv/mv/receipt360_original_mv}"
receipt360_mv_log() {
 builtin printf '%s epoch=%s pid=%s bashpid=%s rc=%s\n' \
  "$1" "${EPOCHREALTIME-UNAVAILABLE}" "$$" "$BASHPID" "$2" \
  2>/dev/null >> "$fixture/receipt360-final-mv.log" || :
}
mv() {
 local receipt360_selected=0 receipt360_status
 if [ "$#" = 3 ] && [ "$1" = -n ] &&
    [ "$2" = "${ml_run-}/final.pending" ] && [ "$3" = "${ml_run-}/final" ]; then
  receipt360_selected=1
  receipt360_mv_log BEGIN not-executed
 fi
 receipt360_original_mv "$@"
 receipt360_status=$?
 if [ "$receipt360_selected" = 1 ]; then receipt360_mv_log END "$receipt360_status"; fi
 return "$receipt360_status"
}
'''


def description(error):
    try:
        detail = repr(error)
    except BaseException:
        detail = "unformattable exception"
    return {"type": type(error).__name__, "detail": detail}


def main():
    if sys.argv[1:] or os.name != "nt" or not sys.dont_write_bytecode or sys.flags.optimize:
        raise ValueError("fixed Windows draft requires python -B, no arguments or optimization")
    if Path(sys.executable).resolve() != PYTHON.resolve() or digest(PYTHON.read_bytes()) != PYTHON_SHA:
        raise ValueError("original Python runtime differs")
    runner = load_reviewed_runner()
    admission, before, sources, old_failure = require_completed_audit(runner)
    # Guard and claim before fixture creation, imports of the original tests,
    # or any lifecycle command. Never reuse a partially written attempt.
    guard_output(HERE)
    guard_output(RUN, must_be_new=True)
    for name in OUTPUTS:
        guard_output(RUN / name, must_be_new=True)
    RUN.mkdir(exist_ok=False)
    guard_output(RUN)
    for name in OUTPUTS:
        guard_output(RUN / name, must_be_new=True)
    writer = runner["write_output"]

    def save(name, value):
        return writer(guard_output(RUN / name, must_be_new=True), value)

    def save_json(name, value):
        return save(name, (json.dumps(value, indent=2, allow_nan=False) + "\n").encode("utf-8"))

    self_before = checked_bytes(Path(__file__))
    save_json("inputs-before.json", {"source230": sources, "audit_source_runtime": before})
    save("original-failure-0005.json", old_failure)
    report = {"scope": "one unchanged original sender node; diagnostic only", "original_node": NODE,
              "audit_admission": admission, "draft_sha256": digest(self_before),
              "source_inputs_count": 230, "source_inputs_sha256": INPUT_SHA,
              "calls": [], "auxiliary_failures": [], "all_original_assertions_completed": False,
              "text_observations_are_not_raw_native_pipe_bytes": True,
              "camera_accesses": 0, "camera_writes": 0, "installable": False,
              "package_created": False, "counts_as_release_pass": False,
              "limits": ["builtin log and parent text/timing observations add diagnostic overhead",
                         "admission independently samples only three exact old failure5 actor lifetimes",
                         "mv wrapper return is not an atomic filesystem publication timestamp",
                         "no native handle, descendant, reader EOF or camera UI proof",
                         "listed disk runtime bytes do not prove actual selected DLLs/processes",
                         "late final cannot rewrite the retained original360 failure"]}
    save_json("start.json", report)
    from tests.test_peer_install import PeerInstallTests
    from tests import test_menu_lifecycle_transport as original
    original_body = original.test_fixed_sender_verifies_final_hash_and_does_not_invent_ui_success
    if Path(original.__file__).resolve() != (ROOT / "tests/test_menu_lifecycle_transport.py").resolve():
        raise ValueError("original test module origin differs")
    if (original.HOST_LIFECYCLE_RECEIPT_WAIT_SECONDS != 360
            or original.HOST_LIFECYCLE_READ_COMMAND_WAIT_SECONDS != 20):
        raise ValueError("original sender deadlines differ")
    report["original_body_source_sha256"] = digest(inspect.getsource(original_body).encode("utf-8"))
    report["original_test_file_sha256"] = digest(Path(original.__file__).read_bytes())
    fixture = PeerInstallTests()
    actual_background = original.background_fixture
    primary = None
    bindings = {}

    def auxiliary(label, operation):
        try:
            return operation()
        except BaseException as error:
            report["auxiliary_failures"].append({"context": label, **description(error)})
            return None

    def observed_background(subject, **options):
        if subject is not fixture or bindings or options.get("extra_hook", ""):
            raise ValueError("unexpected original background fixture invocation")
        options["extra_hook"] = FINAL_MV_HOOK
        raw, fixed, programs, run = actual_background(subject, **options)
        guard_output(subject.root / LOG_LEAF, must_be_new=True)
        bindings.update(candidate_sha256=subject.manifest["candidate_sha256"], session_sha256=digest(raw),
                        fixed=fixed, retained_original_fixture=str(subject.root), formal={}, host={})

        def bind_programs():
            if set(programs) != set(ROLES):
                raise ValueError("original five-program membership differs")
            for role in ROLES:
                formal_path = subject.root / fixed[role].lstrip("/")
                formal = checked_bytes(formal_path)
                if formal != programs[role].encode("ascii"):
                    raise ValueError("formal staged program differs")
                host = checked_bytes(subject.root / (".host-lifecycle-" + role + ".sh"))
                bindings["formal"][role] = {"sha256": digest(formal), "bytes": len(formal)}
                bindings["host"][role] = {"sha256": digest(host), "bytes": len(host)}
                save("formal-" + role + ".sh", formal)
                save("host-" + role + ".sh", host)
            if checked_bytes(subject.root / fixed["session"].lstrip("/")) != raw:
                raise ValueError("original session data differs")
            save("session.data", raw)
            save("shell-wrapper.sh", checked_bytes(subject.root / "system/bin/sh"))
            save_json("fixture-bindings.json", bindings)

        auxiliary("production/session/executed-host binding", bind_programs)

        def observe(action):
            row = {"action": action, "command_wait_seconds":
                   {"launch": 8, "read": 20, "menu": 60, "stop": 30}[action]}
            report["calls"].append(row)
            auxiliary("action start", lambda: row.update(start_monotonic=time.monotonic(),
                        start_wall_epoch=time.time(), start_utc=datetime.now(timezone.utc).isoformat()))
            try:
                result = run(action)  # Exactly one existing text=True call.
            except BaseException as error:
                auxiliary("action original exception", lambda: row.update(outcome="ORIGINAL_EXCEPTION", exception=description(error)))
                raise
            else:
                auxiliary("returned text before sender parsing", lambda: row.update(outcome="RETURNED_TEXT",
                            returncode=result.returncode, stdout_text=result.stdout, stderr_text=result.stderr))
                return result
            finally:
                auxiliary("action end", lambda: row.update(end_monotonic=time.monotonic(),
                            end_wall_epoch=time.time(), end_utc=datetime.now(timezone.utc).isoformat()))
        return raw, fixed, programs, observe

    try:
        PeerInstallTests.setUpClass()
        fixture.setUp()
        # Preserve the original object/data for review; do not call it a
        # successful original fixture deletion or native-process termination.
        fixture.temp._finalizer.detach()
        fixture.temp.cleanup = lambda: None
        with mock.patch.object(original, "background_fixture", side_effect=observed_background):
            original_body(fixture)
        report["all_original_assertions_completed"] = True
    except BaseException as error:
        primary = error
        auxiliary("original primary description", lambda: report.update(original_failure=description(error)))
        raise
    finally:
        def retain_log_and_bindings():
            if not bindings:
                raise ValueError("original fixture was not bound")
            report["fixture_bindings"] = bindings
            log_path = fixture.root / LOG_LEAF
            if log_path.exists():
                log = checked_bytes(log_path)
                save("final-mv.log", log)
                report["final_mv_log"] = {"bytes": len(log), "sha256": digest(log),
                    "text": log.decode("ascii"), "not_atomic_publication_or_native_exit_proof": True}
            else:
                report["final_mv_log"] = {"observed": "absent_after_original_body"}
                log = b""
            if report["all_original_assertions_completed"]:
                lines = log.splitlines()
                if (len(lines) != 2 or not lines[0].startswith(b"BEGIN epoch=")
                        or not lines[1].startswith(b"END epoch=") or not lines[1].endswith(b" rc=0")
                        or b"UNAVAILABLE" in log):
                    raise ValueError("original assertions completed but required mv diagnostic is incomplete")
            for role in ROLES:
                formal = checked_bytes(fixture.root / bindings["fixed"][role].lstrip("/"))
                host = checked_bytes(fixture.root / (".host-lifecycle-" + role + ".sh"))
                if digest(formal) != bindings["formal"][role]["sha256"] or digest(host) != bindings["host"][role]["sha256"]:
                    raise ValueError("executed formal/host bytes changed during original body")
            if digest(checked_bytes(fixture.root / bindings["fixed"]["session"].lstrip("/"))) != bindings["session_sha256"]:
                raise ValueError("session changed during original body")

        auxiliary("final mv evidence and actual-program readback", retain_log_and_bindings)
        if hasattr(fixture, "temp"):
            auxiliary("retained-fixture teardown", fixture.tearDown)

        def verify_after():
            after = runner["snapshot"]()
            after_sources = identity.source_inputs()
            save_json("inputs-after.json", {"source230": after_sources, "audit_source_runtime": after})
            report["listed_source_runtime_inputs_unchanged"] = before["files"] == after["files"] and sources == after_sources
            if not report["listed_source_runtime_inputs_unchanged"] or checked_bytes(Path(__file__)) != self_before:
                raise ValueError("source/runtime/draft bytes changed during the original-node diagnostic")
        auxiliary("source/runtime after binding", verify_after)
        # This file cannot attest its own later commit/readback. A failing
        # result write leaves a diagnostic FAIL even if a file was published.
        report["diagnostic_retention_complete_before_result_write"] = not report["auxiliary_failures"]
        report["successful_result_write_and_process_exit_required"] = True
        report["diagnostic_outcome_before_result_write"] = "ORIGINAL_FAIL" if primary is not None else (
            "DIAGNOSTIC_FAIL" if report["auxiliary_failures"] else "ORIGINAL_ASSERTIONS_COMPLETED_DIAGNOSTIC_ONLY")
        auxiliary("final result retention", lambda: save_json("result.json", report))
        if report["auxiliary_failures"]:
            if primary is None:
                raise RuntimeError("original assertions completed but diagnostic retention/binding failed")
            try:
                primary.add_note("Sender360 diagnostic retention/binding incomplete; original exception preserved")
            except BaseException:
                pass


if __name__ == "__main__":
    main()
