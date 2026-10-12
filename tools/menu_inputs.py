"""Bind desktop and target units to one pinned original and exact Loader URLs."""
from __future__ import annotations
import hashlib
from pathlib import Path

try:
    from .qt_unit import read_main_screen, require, GUI_SHA256
    from .build_unit import build, DEVICE_URL, validate_preservation
except ImportError:
    from qt_unit import read_main_screen, require, GUI_SHA256
    from build_unit import build, DEVICE_URL, validate_preservation

PROJECT = Path(__file__).resolve().parents[1]
GUI = PROJECT.parent / 'x2d2/work/reverse/vendor/x2dii_1_3_16_2_system_root/bin/camera-gui'


def validate_pair(original: bytes, host: bytes, device: bytes) -> dict:
    host_url = (PROJECT / 'qml/X2d2MenuBootstrap.qml').as_uri()
    host_evidence = validate_preservation(original, host, host_url)
    device_evidence = validate_preservation(original, device, DEVICE_URL)
    require(host == build(original, host_url), 'host unit is not the exact current deterministic construction')
    require(device == build(original, DEVICE_URL), 'device unit is not the exact current deterministic construction')
    return {'guiSha256': GUI_SHA256, 'host': host_evidence, 'device': device_evidence,
            'sameOriginalBytecode': True, 'onlyIntendedLoaderUrlsDiffer': True}


def verify_current_pair() -> dict:
    return validate_pair(read_main_screen(GUI),
                         (PROJECT / 'build/units/main-screen-bootstrap-host.bin').read_bytes(),
                         (PROJECT / 'build/units/main-screen-bootstrap-device.bin').read_bytes())
