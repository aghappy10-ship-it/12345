"""One untimed Windows path boundary control; no camera or Windows changes."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import winreg

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
if os.name != "nt" or sys.argv[1:]:
    raise ValueError("this fixed control requires Windows and takes no arguments")
with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                   r"SYSTEM\CurrentControlSet\Control\FileSystem") as key:
    long_paths_enabled = winreg.QueryValueEx(key, "LongPathsEnabled")[0]
folder = Path(tempfile.mkdtemp(prefix="pathlen-control-", dir=BUILD)).resolve()
if not folder.is_relative_to(BUILD.resolve()) or folder.is_symlink():
    raise ValueError("control folder left the owned build directory")
padding = 184 - len(str(folder)) - 1
if not 1 <= padding <= 255:
    raise ValueError("cannot reproduce the original184-character parent")
parent = folder / ("p" * padding)
parent.mkdir()
short = parent / "short.data"
long = parent / ("session-context-" + "f" * 64 + ".data")
marker = b"isolated Windows path control\n"
assert len(str(parent)) == 184 and len(str(long)) == 270
short.write_bytes(marker)
assert short.read_bytes() == marker
report = {"scope": "untimed independent host filesystem control only",
          "python": sys.executable, "python_sha256": hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
          "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
          "long_paths_enabled_readonly": long_paths_enabled,
          "retained_folder": str(folder), "parent_length": len(str(parent)),
          "long_target_length": len(str(long)), "short_same_api": "WRITE_AND_READ_MATCH",
          "camera_accesses": 0, "windows_settings_changed": False, "installable": False}
try:
    long.write_bytes(marker)
except OSError as error:
    report["long_ordinary_api"] = {"outcome": "OS_ERROR", "type": type(error).__name__,
                                   "errno": error.errno, "winerror": getattr(error, "winerror", None),
                                   "message": str(error)}
else:
    report["long_ordinary_api"] = {"outcome": "WRITE_AND_READ_MATCH",
                                   "bytes_match": long.read_bytes() == marker}
extended = Path("\\\\?\\" + str(long))
extended.write_bytes(marker)
assert extended.read_bytes() == marker
report["long_extended_api"] = "WRITE_AND_READ_MATCH"
report["retained_files_are_control_only"] = True
print(json.dumps(report, indent=2))
