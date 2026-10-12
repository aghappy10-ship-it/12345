"""Untimed public --suite boundary controls; no full suite or device access.

Only the external pytest execution engine is substituted. The actual pytest
TempPathFactory, filesystem and Windows directory handles remain in use.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from unittest import mock

import pytest
from _pytest.tmpdir import TempPathFactory

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "build/peer-route-review-20261012-short-root/run_audit.py"
EXPECTED = "af94d46dfeb79424d3088c5b2f86837ad060e7514b76f8e73cafdeb01803cb16"
CASES = ("normal", "given-drift", "cache-drift", "second-factory", "second-alias", "first-alias", "other-factory",
         "parent-replace", "base-replace", "body-error", "close-error", "body-and-close-error")
if len(sys.argv) != 2 or sys.argv[1] not in CASES:
    raise ValueError("select one explicit public-boundary control")
case = sys.argv[1]
assert hashlib.sha256(SOURCE.read_bytes()).hexdigest() == EXPECTED
spec = importlib.util.spec_from_file_location("_short_base_boundary", SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
scratch = Path(tempfile.mkdtemp(prefix="sc-", dir=ROOT / "build")).resolve()
assert scratch.is_relative_to((ROOT / "build").resolve()) and not scratch.is_symlink()
module.HERE = scratch / "o"
module.HERE.mkdir()
module.SUITE_PARENT = scratch / "p"
module.SUITE_BASETEMP = module.SUITE_PARENT / "t"
original_consumer = TempPathFactory.getbasetemp
observed = {}


def factory(path):
    return TempPathFactory(path, 3, "all", lambda *unused: None, _ispytest=True)


def engine_boundary(arguments, plugins):
    values = [a.split("=", 1)[1] for a in arguments if a.startswith("--basetemp=")]
    assert values == [str(module.SUITE_BASETEMP)]
    if case == "first-alias":
        # This rival arrives after public admission but before first consumption.
        module.SUITE_BASETEMP.mkdir()
        marker = module.SUITE_BASETEMP / "keep-first-alias-marker"
        marker.write_bytes(b"historical context")
        observed.update(long_name_created=False, cached_base_returned=False,
                        marker=str(marker), marker_sha256=hashlib.sha256(marker.read_bytes()).hexdigest())
        factory(Path("\\\\?\\" + str(module.SUITE_BASETEMP))).getbasetemp()
        raise AssertionError("first nonliteral factory erased or accepted the rival base")
    owner = factory(module.SUITE_BASETEMP)
    base = owner.getbasetemp()
    child = owner.mktemp("test_preparation_executes_exac")
    destination = child / "blackbox/x2dii-menu-stage/fc13da09f40e7b332ddf5dbd"
    destination.mkdir(parents=True)
    marker = destination / ("session-context-" + "f" * 64 + ".data")
    marker.write_bytes(b"historical context")
    assert marker.read_bytes() == b"historical context"
    assert owner.getbasetemp() == base
    observed.update(long_name_created=True, cached_base_returned=True,
                    marker=str(marker), marker_sha256=hashlib.sha256(marker.read_bytes()).hexdigest())
    if case == "given-drift":
        # Previously this branch delegated and silently returned the alien cache.
        alternate = scratch / "alternate"
        alternate.mkdir()
        owner._given_basetemp = None
        owner._basetemp = alternate
        owner.getbasetemp()
        raise AssertionError("given drift was accepted")
    if case == "cache-drift":
        owner._basetemp = scratch
        owner.getbasetemp()
        raise AssertionError("cache drift was accepted")
    if case == "second-factory":
        factory(module.SUITE_BASETEMP).getbasetemp()
        raise AssertionError("second fixed-base owner was accepted")
    if case == "second-alias":
        factory(Path("\\\\?\\" + str(module.SUITE_BASETEMP))).getbasetemp()
        raise AssertionError("equivalent fixed-base spelling was accepted")
    if case == "other-factory":
        other = factory(scratch / "other")
        other_base = other.getbasetemp()
        assert other_base == scratch / "other"
        other_child = other.mktemp("delegated")
        assert other_child.is_dir()
        observed["other_factory_delegated"] = True
    if case in ("parent-replace", "base-replace"):
        target = module.SUITE_PARENT if case == "parent-replace" else base
        renamed = scratch / "renamed"
        try:
            target.rename(renamed)
        except OSError as error:
            observed["rename_rejected_winerror"] = getattr(error, "winerror", None)
            assert getattr(error, "winerror", None) in (5, 32)
        else:
            raise AssertionError("pinned directory replacement was permitted")
        assert marker.is_file() and owner.getbasetemp() == base
    if case in ("body-error", "body-and-close-error"):
        raise RuntimeError("original engine boundary error")
    return 0


original_close = module.output_native._win_close_handle


def close_then_report_error(handle):
    # Exercise the Win API failure branch without leaving a real handle open.
    assert original_close(handle)
    return False


returned = None
failure = None
notes = []
try:
    with mock.patch.object(pytest, "main", side_effect=engine_boundary):
        if case in ("close-error", "body-and-close-error"):
            with mock.patch.object(module.output_native, "_win_close_handle", side_effect=close_then_report_error):
                returned = module.main(["--suite"])
        else:
            returned = module.main(["--suite"])
except BaseException as error:
    failure = {"type": type(error).__name__, "message": str(error)}
    notes = list(getattr(error, "__notes__", []))
restored = TempPathFactory.getbasetemp is original_consumer
expected_message = {
    "given-drift": "owned pytest factory changed its given temporary root",
    "cache-drift": "cached fixed suite base object changed",
    "second-factory": "a second pytest factory claimed the owned fixed temporary root",
    "second-alias": "a second pytest factory claimed the owned fixed temporary root",
    "first-alias": "first pytest factory did not use the literal fixed temporary root",
    "body-error": "original engine boundary error",
    "body-and-close-error": "original engine boundary error",
}
marker = Path(observed["marker"])
preserved = marker.is_file() and marker.read_bytes() == b"historical context"
report = {"case": case, "scope": "untimed public --suite boundary; external pytest engine substituted",
          "runner_sha256": EXPECTED, "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
          "control_root": str(scratch), "observed": observed, "returned": returned,
          "failure": failure, "exception_notes": notes, "consumer_method_restored": restored,
          "long_marker_preserved": preserved, "camera_accesses": 0, "installable": False,
          "limits": "Not original staging assertions, a complete audit or device integration"}
module.write_output(scratch / "RESULT.json", (json.dumps(report, indent=2) + "\n").encode())
print(json.dumps(report, indent=2))
assert restored, "consumer method was not restored"
assert observed.get("long_name_created") is (case != "first-alias")
assert preserved, "owned temporary marker was moved or erased"
if case in expected_message:
    assert failure is not None and failure["message"] == expected_message[case], failure
elif case == "close-error":
    assert failure is not None and failure["type"] == "OSError", failure
else:
    assert failure is None and returned == 0, failure
if case == "body-and-close-error":
    assert notes and "cleanup unverified" in notes[0]
