"""Actual Windows directory-sharing control; only new synthetic directories."""
import ctypes
import hashlib
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools import output_guard as native

scratch = Path(tempfile.mkdtemp(prefix="ds-", dir=ROOT / "build")).resolve()
assert scratch.is_relative_to((ROOT / "build").resolve()) and not scratch.is_symlink()
rows = []
for access in (0x80, 0x81):
    target = scratch / ("d" + str(access))
    target.mkdir()
    native.guard_output(target)
    handle = native._win_create_file(str(target), access, 1, None, 3, 0x02200000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    row = {"access": access, "share": 1}
    try:
        child = target / "child"
        child.mkdir()
        marker = child / "keep"
        marker.write_bytes(b"synthetic control only")
        row["child_write_read"] = marker.read_bytes() == b"synthetic control only"
        destination = scratch / ("moved" + str(access))
        assert target.resolve().is_relative_to(scratch) and not destination.exists()
        try:
            target.rename(destination)
        except OSError as error:
            row["rename"] = "rejected"
            row["winerror"] = getattr(error, "winerror", None)
            row["retained_marker"] = str(marker)
        else:
            row["rename"] = "permitted"
            row["retained_marker"] = str(destination / "child/keep")
        assert Path(row["retained_marker"]).read_bytes() == b"synthetic control only"
    finally:
        if not native._win_close_handle(handle):
            raise ctypes.WinError(ctypes.get_last_error())
    rows.append(row)
report = {"scope": "untimed real Windows API synthetic directory control",
          "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
          "control_root": str(scratch), "observed": rows,
          "camera_accesses": 0, "installable": False}
native.write_output(scratch / "RESULT.json", (json.dumps(report, indent=2) + "\n").encode())
print(json.dumps(report, indent=2))
assert rows[0]["rename"] == "permitted"
assert rows[1]["rename"] == "rejected" and rows[1]["winerror"] in (5, 32)
assert all(row["child_write_read"] for row in rows)
