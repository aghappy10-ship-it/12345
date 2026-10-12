"""Local identity and evidence binding for fixed menu programs.

No device access, signature bypass, transfer or execution. Hashes establish
identity, not the truth of a report or human authority. Real gate results must
already have been independently reviewed; structural fixtures are not results.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

from .output_guard import guard_output
from .regression_manifest import strict_json

ROOT = Path(__file__).resolve().parents[1]
REVIEW_INPUTS = (
    "work/reverse/INHERITED_APPLICABILITY_REVIEW.json",
    "build/inherited-review-20261004/001-170.json",
    "build/inherited-review-20261004/171-260.json",
    "build/inherited-review-20261004/261-352.json",
)
AUDIT_INPUTS = ("build/peer-route-review-20261004-rg399/run_audit.py",
                "build/peer-route-review-20261004-rg405/run_audit.py",
                "build/peer-route-review-20261004-rg408/run_audit.py",
                "build/peer-route-review-20261004-rg415/run_audit.py",
                "build/peer-route-review-20261004-rg416/run_audit.py",
                "build/peer-route-review-20261004-rg417/run_audit.py",
                "build/peer-route-review-20261004-rg418/run_audit.py",
                "build/peer-route-review-20261006-menu-evidence/run_audit.py",
                "build/peer-route-review-20261006-dependency-closure/run_audit.py",
                "build/peer-route-review-20261006-rg509/run_audit.py",
                "build/peer-route-review-20261006-rg509/launch_admin_audit_once.py",
                "build/peer-route-review-20261007-host-model/run_audit.py",
                "build/peer-route-review-20261007-host-model/launch_admin_audit_once.py")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def source_inputs():
    """Bind source/test inputs and pinned tool/runtime inventories, not results.

    The full audit must additionally verify actual external tool/runtime bytes
    against their inventories. Reading a BUILD record alone is not that check.
    Test fixtures under tests remain inputs even when they are JSON reports.
    """
    from .prepare_outer_menu_fixture import FILES as stock_menu_files
    paths = set()
    for directory in ("tools", "tests", "src", "qml"):
        paths.update(p for p in (ROOT / directory).rglob("*")
                     if p.is_file() and "__pycache__" not in p.parts)
    paths.update(ROOT / name for name in (
        "AGENTS.md", "IMPLEMENTATION_PLAN.md", "pytest.ini",
        "work/reverse/X2DII_REGRESSION_GATES.json", "build/native/native-build.json",
        "build/host-bridge/native/BUILD.json", "build/host-bridge/native/host_cache_bridge.dll",
        "build/units/main-screen-bootstrap-host.bin", "build/units/main-screen-bootstrap-device.bin",
        "build/stock-qml/manifest.json"))
    paths.update(ROOT / "build/stock-qml/qt/qml/app/qml" / name for name in stock_menu_files)
    paths.update(ROOT / name for name in REVIEW_INPUTS)
    paths.update(ROOT / name for name in AUDIT_INPUTS)
    if any(p.is_symlink() or not p.resolve().is_relative_to(ROOT) for p in paths):
        raise ValueError("build input redirects outside the reviewed source tree")
    inputs = {}
    for path in sorted(paths):
        raw = path.read_bytes()
        inputs[path.relative_to(ROOT).as_posix()] = {"sha256": sha(raw), "bytes": len(raw)}
    return inputs


def build_subject(candidate, scripts, *, source_hash, retained=None, inputs=None):
    """Fixed file-set identity; a short-lived observation is never an input."""
    programs = {name: {"sha256": sha(raw.encode("ascii")), "bytes": len(raw.encode("ascii"))}
                for name, raw in scripts.items()}
    return sha(canonical({"schema": "x2dii-fixed-program-build-v1", "candidate": candidate,
                          "programs": programs, "renderer_source_sha256": source_hash,
                          "inputs": source_inputs() if inputs is None else inputs, "retained": retained}))


def validate_delivery_identity(value):
    """Validate a claimed fixed-content identity; this is not qualification."""
    from .delivery_content import FORMAT_VERSION, ROLE_FORMAT_VERSION, MAX_ARCHIVE_BYTES, BLOCK
    fields = {"package_sha256", "package_bytes", "format_version", "member_manifest_sha256"}
    if type(value) is not dict or set(value) != fields:
        raise ValueError("exact delivery identity fields required")
    if any(type(value[key]) is not str or re.fullmatch(r"[0-9a-f]{64}", value[key]) is None
           for key in ("package_sha256", "member_manifest_sha256")):
        raise ValueError("delivery identity requires lowercase SHA256")
    size = value["package_bytes"]
    if (type(size) is not int or not 0 < size <= MAX_ARCHIVE_BYTES or size % BLOCK
            or value["format_version"] not in (FORMAT_VERSION, ROLE_FORMAT_VERSION)):
        raise ValueError("unsupported delivery identity size or format")
    return dict(value)


def gate_bindings(phase, *, candidate_sha256, build_subject_sha256,
                  runtime_subject_sha256, boot_id, retained=None, delivery_identity=None):
    if phase not in ("build", "runtime"):
        raise ValueError("unknown evidence phase")
    bindings = {"phase": phase, "candidate_sha256": candidate_sha256,
                "build_subject_sha256": build_subject_sha256}
    if retained:
        bindings.update(retained)
    if phase == "runtime":
        bindings.update(runtime_subject_sha256=runtime_subject_sha256, boot_id=boot_id)
    if delivery_identity is not None:
        bindings["delivery_identity"] = validate_delivery_identity(delivery_identity)
    return bindings


def validate_runtime_references(observation):
    """Check already-normalized references, not the truth of their content.

    Recovery may explicitly lack a capture owner; that must not require a
    successful capture merely to restore the official menu configuration.
    """
    owner = observation["capture_owner"]
    if owner["state"] != "present":
        return
    route = owner["route"]
    path = guard_output(ROOT / route["evidence_file"])
    if not path.is_file():
        raise ValueError("missing runtime evidence reference")
    raw = path.read_bytes()
    if sha(raw) != route["evidence_sha256"]:
        raise ValueError("changed runtime evidence reference")


def validate_gates(gates, obligations, *, for_publication=False, **identity):
    """Require both halves of mixed gates; never promote absent obligations."""
    if set(gates) != set(obligations):
        raise ValueError("missing or extra qualification gates")
    for gate, phases in obligations.items():
        parts = gates[gate]
        if not isinstance(parts, dict) or set(parts) != set(phases):
            raise ValueError("missing or extra gate phase: " + gate)
        for phase in phases:
            proof = parts[phase]
            expected = gate_bindings(phase, **identity)
            if proof.get("status") != "PASS":
                raise ValueError("unpassed gate: " + gate + "/" + phase)
            if any(proof.get(k) != v for k, v in expected.items()):
                raise ValueError("proof subject binding mismatch: " + gate + "/" + phase)
            path = guard_output(ROOT / proof["evidence_file"])
            if not path.is_file():
                raise ValueError("missing/changed evidence: " + gate + "/" + phase)
            raw = path.read_bytes()
            if sha(raw) != proof["evidence_sha256"]:
                raise ValueError("missing/changed evidence: " + gate + "/" + phase)
            evidence = strict_json(raw)
            if for_publication and evidence.get("test_fixture_only", False) is not False:
                raise ValueError("test fixture cannot authorize publication: " + gate + "/" + phase)
            if (evidence.get("result") != "PASS" or evidence.get("synthetic") is not False
                    or evidence.get("gate") != gate
                    or any(evidence.get(k) != v for k, v in expected.items())):
                raise ValueError("evidence subject binding/result mismatch: " + gate + "/" + phase)
