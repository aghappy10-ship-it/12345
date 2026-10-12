"""Pure content-to-candidate binding, not qualification or a package publisher.

Caller-supplied hashes describe identity, not provenance or safe behavior. The
caller must pin script_hashes to this candidate and the reviewed renderer/build;
supplying matching old scripts and old hashes does not prove currentness here.
No files are loaded, archives encoded, scripts rendered, or devices contacted.
"""
import hashlib
import json

from . import boot_config as boot
from .delivery_content import plan_content, plan_role_content
from .qt_unit import GUI_SHA256


PAYLOADS = (("build/native/libx2dii_menu.so", boot.LIBRARY),
            *(("qml/" + name, "/system/etc/" + name) for name in
              ("X2d2MenuBootstrap.qml", "X2d2MenuModel.qml", "X2d2MenuPage.qml")))
PROGRAMS = ("install-files.sh", "activate-boot.sh", "restore-boot.sh")
ROLE_PROGRAMS = (*(f"preplace-{i}.sh" for i in range(4)), "activate-boot.sh", "restore-boot.sh")


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _need(condition, message):
    if not condition:
        raise ValueError(message)


def _fields(value, names):
    _need(type(value) is dict and set(value) == set(names), "unexpected content contract fields")


def plan_delivery(members, *, candidate, candidate_sha256, script_hashes):
    """Describe supplied stable content without granting installation authority."""
    return _plan_delivery(members, candidate=candidate, candidate_sha256=candidate_sha256,
                          script_hashes=script_hashes, role_aware=False)


def plan_role_delivery(members, *, candidate, candidate_sha256, script_hashes):
    """Bind the six fixed role programs, replacing v1's monolithic installation."""
    return _plan_delivery(members, candidate=candidate, candidate_sha256=candidate_sha256,
                          script_hashes=script_hashes, role_aware=True)


def _plan_delivery(members, *, candidate, candidate_sha256, script_hashes, role_aware):
    content = (plan_role_content if role_aware else plan_content)(members, candidate_sha256)
    _fields(candidate, ("gui_sha256", "files", "rc"))
    _need(candidate["gui_sha256"] == GUI_SHA256, "unsupported GUI baseline")
    _need(type(candidate["files"]) is list and len(candidate["files"]) == len(PAYLOADS),
          "exactly four payload descriptions required")
    for entry, (source, target) in zip(candidate["files"], PAYLOADS):
        _fields(entry, ("source", "target", "sha256", "bytes"))
        _need(entry["source"] == source and entry["target"] == target,
              "payload source/target/order mismatch")
        raw = members[source.rsplit("/", 1)[-1]]
        _need(type(entry["bytes"]) is int and 0 < entry["bytes"] < 8 * 1024 * 1024
              and len(raw) == entry["bytes"]
              and _sha(raw) == entry["sha256"],
              "payload differs from the candidate")
    rc = candidate["rc"]
    _fields(rc, ("source", "target", "before", "after"))
    _need(rc["source"] == "build/boot-config/camera-gui.rc.proposed"
          and rc["target"] == boot.TARGET and rc["before"] == boot.STOCK_SHA256,
          "unsupported configuration baseline or source/target")
    _need(_sha(members["camera-gui.rc.proposed"]) == rc["after"],
          "proposed configuration differs from the candidate")
    _need(_sha(json.dumps(candidate, sort_keys=True, separators=(",", ":")).encode())
          == candidate_sha256, "candidate digest mismatch")
    _fields(script_hashes, ROLE_PROGRAMS if role_aware else PROGRAMS)
    for name, expected in script_hashes.items():
        _need(_sha(members[name]) == expected, "program differs from pinned expected bytes")
    return content
