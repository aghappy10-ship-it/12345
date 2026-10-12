"""Public --suite admission boundary only; pytest engine is a system stub.

Real TempPathFactory consumes a real late control directory. No suite, timing
benchmark, camera, settings change or original audit fixture is executed.
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
if len(sys.argv) != 2 or sys.argv[1] not in ("old", "new"):
    raise ValueError("select old or new for this single boundary control")
variant = sys.argv[1]
folder = "peer-route-review-20261011-host-fixed" if variant == "old" else "peer-route-review-20261012-short-root"
source = ROOT / "build" / folder / "run_audit.py"
expected = {"old": "3d45dafca02e42499ef0322c3e23ca750f407824e2ca0f1c1d45c49e6930fb19",
            "new": "af94d46dfeb79424d3088c5b2f86837ad060e7514b76f8e73cafdeb01803cb16"}
assert hashlib.sha256(source.read_bytes()).hexdigest() == expected[variant]
spec = importlib.util.spec_from_file_location("_single_public_suite_boundary", source)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)  # Definitions only; never its __main__.
scratch = Path(tempfile.mkdtemp(prefix="sb-", dir=ROOT / "build")).resolve()
assert scratch.is_relative_to((ROOT / "build").resolve()) and not scratch.is_symlink()
module.HERE = scratch / "o"
module.HERE.mkdir()
# Only OS test roots are modeled. Production argv admission and guards are real.
module.SUITE_PARENT = scratch / "p"
module.SUITE_BASETEMP = module.SUITE_PARENT / "t"
marker = None
argv_seen = None
original_consumer = TempPathFactory.getbasetemp


def engine_boundary(arguments, plugins):
    global marker, argv_seen
    argv_seen = list(arguments)
    values = [arg.split("=", 1)[1] for arg in arguments if arg.startswith("--basetemp=")]
    assert len(values) == 1
    base = Path(values[0])
    assert base.resolve(strict=False).is_relative_to(scratch)
    assert not base.exists() and not base.is_symlink()
    # A competitor arrives after the caller's guards, before pytest consumes it.
    base.mkdir()
    marker = base / "keep-control-marker"
    marker.write_bytes(b"late object must not be removed\n")
    assert list(base.iterdir()) == [marker]  # Only disposable control data exists.
    factory = TempPathFactory(base, 3, "all", lambda *unused: None, _ispytest=True)
    factory.getbasetemp()  # Real library consumption, including old rm_rf behavior.
    return 0


failure = None
returned = None
try:
    with mock.patch.object(pytest, "main", side_effect=engine_boundary):
        returned = module.main(["--suite"])
except BaseException as error:
    failure = {"type": type(error).__name__, "message": str(error)}
preserved = marker is not None and marker.is_file() and marker.read_bytes() == b"late object must not be removed\n"
report = {"scope": "single untimed public --suite boundary control only",
          "variant": variant, "runner_sha256": expected[variant],
          "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
          "control_root": str(scratch), "pytest_argv_seen": argv_seen,
          "returned": returned, "failure": failure, "late_marker_preserved": preserved,
          "consumer_method_restored": TempPathFactory.getbasetemp is original_consumer,
          "camera_accesses": 0, "installable": False,
          "limits": "pytest.main execution is substituted; this is not either original staging test or a complete audit"}
print(json.dumps(report, indent=2))
assert TempPathFactory.getbasetemp is original_consumer
assert preserved, "late fixed-basetemp marker was erased"
assert failure is not None, "the fixed consumer accepted an unknown late directory"
