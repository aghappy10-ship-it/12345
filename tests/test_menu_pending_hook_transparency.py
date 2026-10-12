"""RG540 native hook transparency regression controls.

Captured original hook at the existing native shell seam only. No background
lifecycle, delegation repair, projected candidate, camera or release pass.
"""
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
from tests import test_menu_lifecycle_transport as lifecycle
from tools.output_guard import guard_output

BASE = ROOT / "tests/test_menu_lifecycle_transport.py"


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


@pytest.fixture
def captured_pending_hook(request, monkeypatch, record_property):
    replacement = request.param
    source_sha = digest(BASE.read_bytes())
    original = lifecycle.test_pending_replacement_is_retained_and_never_promoted_to_final
    assert original.__globals__ is lifecycle.__dict__
    assert Path(original.__code__.co_filename).resolve() == BASE.resolve()
    background = lifecycle.background_fixture
    observed = []

    class CapturedAtExistingHookBoundary(Exception):
        pass

    def capture(installer, **kwargs):
        assert kwargs.keys() == {"extra_hook"}
        observed.append(kwargs["extra_hook"])
        raise CapturedAtExistingHookBoundary

    with monkeypatch.context() as capture_patch:
        capture_patch.setattr(lifecycle, "background_fixture", capture)
        with pytest.raises(CapturedAtExistingHookBoundary):
            original(SimpleNamespace(), replacement)
    assert len(observed) == 1
    constants = [value for value in background.__code__.co_consts
                 if isinstance(value, str) and "\ncat() {\n" in value
                 and "\nlifecycle_fixture_exit() {\n" in value]
    assert len(constants) == 1
    boundary = constants[0]
    prior_cat = boundary[boundary.index("\ncat() {\n"):
                         boundary.index("\nlifecycle_fixture_exit() {\n")]
    inputs = [BASE, Path(__file__).resolve(), ROOT / "tools/output_guard.py",
              ROOT / "tests/test_peer_install.py", Path(sys.executable), lifecycle.SH,
              *(Path("C:/Program Files/Git/usr/bin") / name for name in
                ("bash.exe", "sh.exe", "msys-2.0.dll", "cygpath.exe", "cat.exe",
                 "mv.exe", "cp.exe", "stat.exe", "mkdir.exe", "rm.exe", "sleep.exe"))]
    before = {str(path): digest(path.read_bytes()) for path in inputs}
    evidence = {"replacement": replacement, "original_source_sha256": source_sha,
                "captured_original_hook_sha256": digest(observed[0].encode()),
                "captured_background_cat_sha256": digest(prior_cat.encode()),
                "input_hashes_before": before, "full_lifecycle_executed": False,
                "complete_audit": False, "camera_accesses": 0,
                "counts_as_release_pass": False}
    record_property("captured_pending_hook_inputs", json.dumps(evidence, sort_keys=True))
    primary = None
    try:
        yield observed[0], prior_cat, replacement
    except BaseException as error:
        primary = error
        raise
    finally:
        errors = []
        after = None
        try:
            after = {str(path): digest(path.read_bytes()) for path in inputs}
            if after != before:
                errors.append("input bytes changed")
        except BaseException as error:
            errors.append(("input readback", type(error).__name__))
        try:
            record_property("captured_pending_hook_inputs_after", json.dumps(after, sort_keys=True))
        except BaseException as error:
            errors.append(("input evidence publication", type(error).__name__))
        if errors:
            if primary is None:
                raise AssertionError(errors)
            try:
                primary.add_note("Separate hook readback failures: " + repr(errors))
            except BaseException:
                pass


def run_captured_hook(tmp_path, monkeypatch, record_property, hook, prefix, body):
    guard_output(tmp_path)
    monkeypatch.setattr(lifecycle, "guardian_transfer_fault_hook",
                        lambda edge, victim: prefix + hook)
    result = lifecycle._run_guardian_transfer_hook(tmp_path, "offer_visible", body, caller="w")
    record_property("captured_hook_native_result", json.dumps({
        "returncode": result.returncode, "stdout_hex": result.stdout.encode().hex(),
        "stderr_hex": result.stderr.encode().hex(), "subprocess_mocked": False,
        "executed_hook_sha256": digest(hook.encode()),
        "preceding_cat_setup_sha256": digest(prefix.encode()),
        "seam_body_sha256": digest(body.encode()),
        "counts_as_release_pass": False}, sort_keys=True))
    return result


@pytest.mark.parametrize("captured_pending_hook", ("same", "changed_status"), indirect=True)
@pytest.mark.parametrize("prior_status", (0, 7))
def test_pending_hook_preserves_prior_stdout_stderr_and_status(
        tmp_path, monkeypatch, record_property, captured_pending_hook, prior_status):
    hook, _, _ = captured_pending_hook
    prefix = ("\ncat() { builtin printf 'previous-cat-output\\n'; "
              "builtin printf 'previous-cat-stderr\\n' >&2; return "
              + str(prior_status) + "; }\n")
    result = run_captured_hook(tmp_path, monkeypatch, record_property, hook, prefix, r'''
builtin printf 'disk-output\n' > "$fixture/prior-result"
test_status=0
if test_observed=$(cat "$fixture/prior-result"); then :; else test_status=$?; fi
builtin printf '%s:%s\n' "$test_status" "$test_observed"
[ ! -e "$fixture/pending-replaced" ]
''')
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert result.stderr == "previous-cat-stderr\n"
    assert result.stdout == str(prior_status) + ":previous-cat-output\n"


@pytest.mark.parametrize("captured_pending_hook", ("same", "changed_status"), indirect=True)
@pytest.mark.parametrize("lifetime", ("live", "retired"))
def test_pending_hook_preserves_native_pid_birth_state_and_retirement(
        tmp_path, monkeypatch, record_property, captured_pending_hook, lifetime):
    hook, prior_cat, _ = captured_pending_hook
    body = r'''
test_prepare_worker
/usr/bin/mkdir -p "$fixture/proc/$test_target_pid"
builtin printf shell > "$fixture/proc/$test_target_pid/host-shell"
builtin printf 'stale-model-stat\n' > "$fixture/proc/$test_target_pid/stat"
'''
    if lifetime == "live":
        body += r'''
test_expected=$(/usr/bin/cat "/proc/$test_target_pid/stat")
test_observed=$(cat "$fixture/proc/$test_target_pid/stat")
builtin printf 'native_expected=%s\nobserved=%s\n' "$test_expected" "$test_observed"
'''
    else:
        body += r'''
test_cleanup_worker
[ ! -e "/proc/$test_target_pid/stat" ] || exit 94
test_status=0
if test_observed=$(cat "$fixture/proc/$test_target_pid/stat"); then :; else test_status=$?; fi
builtin printf 'native_retired_pid=%s start_ticks=%s observed_status=%s observed_output=%s\n' \
 "$test_target_pid" "$test_target_ticks" "$test_status" "$test_observed"
[ "$test_status" = 1 ] && [ -z "$test_observed" ] || exit 94
[ ! -e "$fixture/proc/$test_target_pid/stat" ] || exit 94
'''
    body += '[ ! -e "$fixture/pending-replaced" ]\n'
    result = run_captured_hook(tmp_path, monkeypatch, record_property, hook, prior_cat, body)
    assert result.returncode == 0, (result.stdout, result.stderr)
    if lifetime == "live":
        expected_pid, expected_ticks = (tmp_path / "worker.identity").read_text().strip().split(":")
        assert expected_pid.isdecimal() and expected_ticks.isdecimal()
        lines = result.stdout.splitlines()
        assert len(lines) == 2
        for prefix, line in zip(("native_expected=", "observed="), lines):
            assert line.startswith(prefix)
            stat = line[len(prefix):]
            assert " (" in stat and ") " in stat, (prefix, stat)
            observed_pid = stat.split(" (", 1)[0]
            fields = stat.rsplit(") ", 1)[1].split()
            assert len(fields) >= 20, (prefix, stat)
            record_property(prefix.rstrip("=") + "_identity", json.dumps({
                "expected_pid": expected_pid, "expected_start_ticks": expected_ticks,
                "pid": observed_pid, "start_ticks": fields[19], "state": fields[0],
                "counts_as_release_pass": False}, sort_keys=True))
            assert observed_pid == expected_pid
            assert fields[19] == expected_ticks
            assert fields[0] in ("R", "S", "D", "T", "t", "W", "I", "P")
        assert "stale-model-stat" not in result.stdout
    else:
        assert result.stdout.endswith(" observed_status=1 observed_output=\n")


@pytest.mark.parametrize("captured_pending_hook", ("same", "changed_status"), indirect=True)
def test_pending_hook_retains_exact_predicate_and_one_shot_replacement(
        tmp_path, monkeypatch, record_property, captured_pending_hook):
    hook, prior_cat, replacement = captured_pending_hook
    result = run_captured_hook(tmp_path, monkeypatch, record_property, hook, prior_cat, r'''
/usr/bin/mkdir -p "$fixture/proc/self/attr" "$fixture/final-run"
builtin printf 'prior-domain\n' > "$fixture/proc/self/attr/current"
builtin printf 'other-read\n' > "$fixture/other"
unset ml_run
cat "$fixture/proc/self/attr/current" >/dev/null
[ ! -e "$fixture/pending-replaced" ]
ml_run=$fixture/final-run
cat "$fixture/proc/self/attr/current" >/dev/null
[ ! -e "$fixture/pending-replaced" ]
ml_sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
builtin printf '%s:0\n' "$ml_sha" > "$ml_run/final.pending"
test_original_identity=$(/usr/bin/stat -c '%d:%i' "$ml_run/final.pending")
cat "$fixture/other" >/dev/null
cat "$fixture/proc/self/attr/current" "$fixture/other" >/dev/null
[ ! -e "$fixture/pending-replaced" ]
ml_run=''
cat "$fixture/proc/self/attr/current" >/dev/null
[ ! -e "$fixture/pending-replaced" ]
ml_run=$fixture/final-run
test_first=$(cat "$fixture/proc/self/attr/current")
[ "$test_first" = prior-domain ]
test_pending_identity=$(/usr/bin/stat -c '%d:%i' "$ml_run/final.pending")
[ "$test_pending_identity" != "$test_original_identity" ]
[ "$(cat "$fixture/pending-replaced")" = "$test_pending_identity" ]
[ "$(cat "$ml_run/original-final-retained")" = "$ml_sha:0" ]
test_pending_content=$(cat "$ml_run/final.pending")
test_second=$(cat "$fixture/proc/self/attr/current")
[ "$test_second" = prior-domain ]
[ "$(/usr/bin/stat -c '%d:%i' "$ml_run/final.pending")" = "$test_pending_identity" ]
[ "$(cat "$fixture/pending-replaced")" = "$test_pending_identity" ]
[ "$(cat "$ml_run/original-final-retained")" = "$ml_sha:0" ]
[ "$(cat "$ml_run/final.pending")" = "$test_pending_content" ]
builtin printf 'exact-predicate-single-replacement\n'
''')
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert result.stdout == "exact-predicate-single-replacement\n"
    marker = (tmp_path / "pending-replaced").read_bytes()
    original = (tmp_path / "final-run/original-final-retained").read_bytes()
    pending = (tmp_path / "final-run/final.pending").read_bytes()
    expected_status = {"same": b"0", "changed_status": b"74"}[replacement]
    assert original == b"a" * 64 + b":0\n"
    assert pending == b"a" * 64 + b":" + expected_status + b"\n"
    record_property("actual_replacement_bytes", json.dumps({
        "marker_hex": marker.hex(), "retained_original_hex": original.hex(),
        "replacement_hex": pending.hex(), "counts_as_release_pass": False}, sort_keys=True))
