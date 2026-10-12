"""Publisher boundary tests only; no positive qualification or output package.

Counterfactual admission is isolated from the real file sink. Native execution
is not involved; source bytes remain in memory and no qualified report is saved.
"""
from copy import deepcopy
from datetime import datetime, timedelta
import json
import os
from pathlib import Path
from unittest import mock

import pytest

from tests.test_release_lifecycle import recovery_fixture
from tests.test_recovery_role_v2 import role_recovery_context
from tools import prepare_peer_recovery as recovery


def _counterfactual_recovery_format_case(fixture, *, role=False):
    """TEST_ONLY external formats, never observations, authority or publication.

    The real qualifier runs unchanged; no validator is mocked. Claimed external
    review flags exist only to reach formal admission in a private host fixture.
    No positive qualifier result is passed to the source publisher.
    """
    if role:
        manifest, digest, context = role_recovery_context(fixture)
    else:
        manifest, digest, context = fixture.manifest, fixture.saved_sha, deepcopy(fixture.q)
    from tests.test_runtime_observation import synthetic_observation
    context["runtime_observation"] = synthetic_observation(context, manifest["candidate"]["gui_sha256"], recovery=True)
    context["runtime_observation"]["test_fixture_only"] = False
    context["runtime_observation"]["capture_owner"].update(state="absent", process=None, route=None)
    context.update(synthetic=False, test_provenance="TEST_ONLY_COUNTERFACTUAL_NO_DEVICE_AUTHORITY")
    build = recovery.build_subject_sha256(fixture.saved, digest)
    runtime = recovery.runtime_subject_sha256(fixture.saved, digest, context)
    subject = recovery.execution_subject_sha256(fixture.saved, digest, context)
    context.update(build_subject_sha256=build, runtime_subject_sha256=runtime,
                   execution_subject_sha256=subject, gates={})
    context["recovery_authorization"] = {
        "candidate_sha256": context["candidate_sha256"], "saved_manifest_sha256": digest,
        "boot_id": context["boot_id"], "execution_subject_sha256": subject,
        "approved": True, "session_nonce": context["recovery_nonce"],
        "purpose": "restore_official_boot_remove_owned_extension",
        "test_provenance": "TEST_ONLY_COUNTERFACTUAL_NOT_CONSENT",
    }
    for gate, phases in recovery.GATE_PHASES.items():
        context["gates"][gate] = {}
        for phase in phases:
            bindings = recovery.release_identity.gate_bindings(
                phase, candidate_sha256=context["candidate_sha256"], build_subject_sha256=build,
                runtime_subject_sha256=runtime, boot_id=context["boot_id"],
                retained={"saved_manifest_sha256": digest})
            evidence = dict(bindings, result="PASS", synthetic=False, gate=gate, test_fixture_only=False,
                            test_provenance="TEST_ONLY_COUNTERFACTUAL_NOT_GATE_EVIDENCE")
            path = fixture.root / ("format-only-" + gate + "-" + phase + ".json")
            raw = recovery.canonical(evidence)
            path.write_bytes(raw)
            context["gates"][gate][phase] = dict(bindings, status="PASS",
                evidence_file=path.relative_to(recovery.ROOT).as_posix(), evidence_sha256=recovery.sha(raw))
    return digest, context


def test_formal_recovery_refuses_generic_pass_without_pre_rollback_originals(recovery_fixture):
    fixture = recovery_fixture
    digest, context = _counterfactual_recovery_format_case(fixture)
    now = datetime.fromisoformat(context["observed_utc"])
    # Every pre-existing check succeeds through its real public interface.
    assert recovery.validate_qualification(fixture.saved, digest, context, now=now) == context["execution_subject_sha256"]
    before = deepcopy(context)
    with pytest.raises(ValueError, match="pre-rollback failure bundle"):
        recovery.validate_qualification(fixture.saved, digest, context, now=now, for_publication=True)
    assert context == before
    assert not (fixture.root / "peer-recovery-source.json").exists()


def _original_bundle_format_case(fixture, *, role=False, no_events=False):
    """Inert typed originals for format checks, not a genuine camera bundle."""
    digest, context = _counterfactual_recovery_format_case(fixture, role=role)
    observed = datetime.fromisoformat(context["observed_utc"])
    window = {"start_utc": (observed - timedelta(seconds=10)).isoformat(),
              "end_utc": (observed - timedelta(seconds=1)).isoformat()}
    identity = {key: context[key] for key in ("candidate_sha256", "saved_manifest_sha256", "boot_id",
                "active_slot", "official_slot", "slot_readback", "observed_utc")}
    identity["runtime_observation"] = deepcopy(context["runtime_observation"])
    fields = ("candidate_sha256", "saved_manifest_sha256", "boot_id", "uid", "domain", "system_mount",
              "mount_namespace", "init_mount_namespace", "observer", "gui", "active_slot", "official_slot",
              "slot_readback", "metadata", "backup_metadata", "payload_presence", "rc_sha256",
              "init_scan_roots", "init_scan_roots_complete") + (("backup_identity",) if role else ())
    configuration = {"context": {key: context[key] for key in fields},
                     "runtime_observation": deepcopy(context["runtime_observation"])}
    originals = {
        "identity": ("json", recovery.canonical(identity)),
        "recent_logcat": ("text", b"TEST_ONLY recent log original spanning the declared failure window\n"),
        "capture_filtered_logcat": ("text", b"X2DII_NO_MATCHING_EVENTS\n" if no_events else
                                   b"TEST_ONLY matching capture failure log original\n"),
        "kernel_log": ("text", b"TEST_ONLY kernel log original\n"),
        "runtime_configuration": ("json", recovery.canonical(configuration)),
        "storage_file_index": ("text", b"TEST_ONLY storage index original; explicitly no entries\n"),
        "log_index": ("text", b"TEST_ONLY log index original\n"),
        "tombstone_index": ("text", b"TEST_ONLY tombstone index original; explicitly no entries\n"),
    }
    artifacts = {}
    for name, (format_name, raw) in originals.items():
        path = fixture.root / ("TEST_ONLY_original_" + name + ".data")
        path.write_bytes(raw)
        artifacts[name] = {"format": format_name, "evidence_file": path.relative_to(recovery.ROOT).as_posix(),
                           "evidence_sha256": recovery.sha(raw), "bytes": len(raw)}
        if name in ("recent_logcat", "capture_filtered_logcat"):
            artifacts[name]["coverage"] = {"start_utc": (observed - timedelta(seconds=60)).isoformat(),
                "end_utc": observed.isoformat(),
                "events": "NONE_MATCHING" if no_events and name == "capture_filtered_logcat" else "PRESENT"}
    gate = context["gates"]["recovery_historical_regressions"]["runtime"]
    bindings = {key: gate[key] for key in ("phase", "candidate_sha256", "saved_manifest_sha256",
                "build_subject_sha256", "runtime_subject_sha256", "boot_id")}
    bundle = {"schema": "x2dii-pre-rollback-failure-bundle-v1", "synthetic": False, "test_fixture_only": False,
              "bindings": dict(bindings, execution_subject_sha256=context["execution_subject_sha256"]),
              "observed_utc": context["observed_utc"], "failure_window": window, "artifacts": artifacts}
    bundle_path = fixture.root / "TEST_ONLY_pre_rollback_failure_bundle.json"
    _retain_bundle_format(context, bundle_path, bundle)
    return digest, context, bundle_path, bundle


def _retain_bundle_format(context, path, bundle, *, raw=None):
    raw = recovery.canonical(bundle) if raw is None else raw
    path.write_bytes(raw)
    gate = context["gates"]["recovery_historical_regressions"]["runtime"]
    gate_path = recovery.ROOT / gate["evidence_file"]
    evidence = json.loads(gate_path.read_bytes())
    evidence["pre_rollback_failure_bundle"] = {"evidence_file": path.relative_to(recovery.ROOT).as_posix(),
                                              "evidence_sha256": recovery.sha(raw)}
    gate_raw = recovery.canonical(evidence)
    gate_path.write_bytes(gate_raw)
    gate["evidence_sha256"] = recovery.sha(gate_raw)


@pytest.mark.parametrize("role", (False, True))
@pytest.mark.parametrize("no_events", (False, True))
def test_complete_hash_bound_original_bundle_format_is_admitted_without_publication(recovery_fixture, role, no_events):
    fixture = recovery_fixture
    digest, context, bundle_path, bundle = _original_bundle_format_case(fixture, role=role, no_events=no_events)
    before = deepcopy(context)
    paths = [bundle_path, *(recovery.ROOT / record["evidence_file"] for record in bundle["artifacts"].values())]
    original_bytes = {path: path.read_bytes() for path in paths}
    subject = recovery.validate_qualification(fixture.saved, digest, context,
        now=datetime.fromisoformat(context["observed_utc"]), for_publication=True)
    assert subject == context["execution_subject_sha256"]
    assert context == before and {path: path.read_bytes() for path in paths} == original_bytes
    assert not (fixture.root / "peer-recovery-source.json").exists()


@pytest.mark.parametrize("role", (False, True))
def test_missing_formal_bundle_does_not_block_pure_recovery_rendering(recovery_fixture, role):
    fixture = recovery_fixture
    digest, context = _counterfactual_recovery_format_case(fixture, role=role)
    source = recovery.render_recovery(fixture.saved, digest, context)
    assert source and ("X2DII_BOOT_BOUNDARY_REQUEST:restore" in source if role else "Recovery ONLY" in source)
    with pytest.raises(ValueError, match="pre-rollback failure bundle"):
        recovery.prepare(fixture.root / "NEVER_FORMALLY_PUBLISHED", fixture.saved, digest, context)
    assert not (fixture.root / "NEVER_FORMALLY_PUBLISHED").exists()


@pytest.mark.parametrize("fault", (
    "generic-list", "schema", "synthetic", "fixture", "candidate-binding", "runtime-binding", "lease-binding",
    "observed-time", "missing-window", "reversed-window", "future-window", "naive-window", "missing-original",
    "wrong-format", "bool-length", "wrong-length", "absolute-path", "parent-path", "duplicate-original",
    "original-hash", "bundle-hash", "component-state", "active-slot-state", "runtime-config", "recent-truncated",
    "capture-truncated", "missing-log-coverage", "unrecorded-no-events", "false-present-events", "duplicate-json",
    "duplicate-identity-json", "missing-bundle-file", "missing-original-file", "empty-original", "changed-original",
    "hardlinked-original", "oversized-original",
))
def test_formal_recovery_rejects_incomplete_wrong_bound_or_nonoriginal_bundle(recovery_fixture, fault):
    fixture = recovery_fixture
    digest, context, bundle_path, bundle = _original_bundle_format_case(fixture)
    artifacts = bundle["artifacts"]
    original_path = recovery.ROOT / artifacts["kernel_log"]["evidence_file"]
    bundle_raw = None
    if fault == "generic-list":
        bundle = {"result": "PASS", "files": [record["evidence_file"] for record in artifacts.values()]}
    elif fault in ("schema", "synthetic", "fixture"):
        bundle[{"schema": "schema", "synthetic": "synthetic", "fixture": "test_fixture_only"}[fault]] = (
            "generic-pass-v1" if fault == "schema" else True)
    elif fault in ("candidate-binding", "runtime-binding", "lease-binding"):
        field = {"candidate-binding": "candidate_sha256", "runtime-binding": "runtime_subject_sha256",
                 "lease-binding": "execution_subject_sha256"}[fault]
        bundle["bindings"][field] = "0" * 64
    elif fault == "observed-time":
        bundle["observed_utc"] = (datetime.fromisoformat(context["observed_utc"]) - timedelta(seconds=1)).isoformat()
    elif fault == "missing-window":
        bundle.pop("failure_window")
    elif fault == "reversed-window":
        bundle["failure_window"]["start_utc"] = context["observed_utc"]
    elif fault == "future-window":
        bundle["failure_window"]["end_utc"] = (datetime.fromisoformat(context["observed_utc"]) + timedelta(seconds=1)).isoformat()
    elif fault == "naive-window":
        bundle["failure_window"]["start_utc"] = datetime.fromisoformat(context["observed_utc"]).replace(tzinfo=None).isoformat()
    elif fault == "missing-original":
        artifacts.pop("tombstone_index")
    elif fault == "wrong-format":
        artifacts["kernel_log"]["format"] = "generic-PASS"
    elif fault == "bool-length":
        artifacts["kernel_log"]["bytes"] = True
    elif fault == "wrong-length":
        artifacts["kernel_log"]["bytes"] += 1
    elif fault == "absolute-path":
        artifacts["kernel_log"]["evidence_file"] = str(original_path)
    elif fault == "parent-path":
        artifacts["kernel_log"]["evidence_file"] = "build/../TEST_ONLY_escape.data"
    elif fault == "duplicate-original":
        artifacts["capture_filtered_logcat"] = deepcopy(artifacts["recent_logcat"])
    elif fault == "original-hash":
        artifacts["kernel_log"]["evidence_sha256"] = "0" * 64
    elif fault in ("component-state", "active-slot-state", "runtime-config", "duplicate-identity-json"):
        name = "runtime_configuration" if fault == "runtime-config" else "identity"
        path = recovery.ROOT / artifacts[name]["evidence_file"]
        original = json.loads(path.read_bytes())
        if fault == "component-state":
            original["runtime_observation"]["sensor"]["sha256"] = "0" * 64
        elif fault == "active-slot-state":
            original["active_slot"] = "slot_1"
        elif fault == "runtime-config":
            original["context"]["rc_sha256"] = "0" * 64
        raw = recovery.canonical(original)
        if fault == "duplicate-identity-json":
            raw = b'{"active_slot":"slot_1",' + raw[1:]
        path.write_bytes(raw)
        artifacts[name].update(bytes=len(raw), evidence_sha256=recovery.sha(raw))
    elif fault in ("recent-truncated", "capture-truncated"):
        name = "recent_logcat" if fault == "recent-truncated" else "capture_filtered_logcat"
        artifacts[name]["coverage"]["end_utc"] = (
            datetime.fromisoformat(bundle["failure_window"]["start_utc"]) - timedelta(seconds=1)).isoformat()
    elif fault == "missing-log-coverage":
        artifacts["capture_filtered_logcat"].pop("coverage")
    elif fault == "unrecorded-no-events":
        artifacts["capture_filtered_logcat"]["coverage"]["events"] = "NONE_MATCHING"
    elif fault == "false-present-events":
        path = recovery.ROOT / artifacts["capture_filtered_logcat"]["evidence_file"]
        raw = b"X2DII_NO_MATCHING_EVENTS\n"
        path.write_bytes(raw)
        artifacts["capture_filtered_logcat"].update(bytes=len(raw), evidence_sha256=recovery.sha(raw))
    elif fault == "duplicate-json":
        bundle_raw = b'{"schema":"generic-pass-v1",' + recovery.canonical(bundle)[1:]
    _retain_bundle_format(context, bundle_path, bundle, raw=bundle_raw)
    if fault == "bundle-hash":
        gate = context["gates"]["recovery_historical_regressions"]["runtime"]
        gate_path = recovery.ROOT / gate["evidence_file"]
        evidence = json.loads(gate_path.read_bytes())
        evidence["pre_rollback_failure_bundle"]["evidence_sha256"] = "0" * 64
        raw = recovery.canonical(evidence)
        gate_path.write_bytes(raw)
        gate["evidence_sha256"] = recovery.sha(raw)
    elif fault == "missing-bundle-file":
        bundle_path.unlink()
    elif fault == "missing-original-file":
        original_path.unlink()
    elif fault == "empty-original":
        original_path.write_bytes(b"")
    elif fault == "changed-original":
        original_path.write_bytes(b"TEST_ONLY changed original bytes\n")
    elif fault == "hardlinked-original":
        os.link(original_path, fixture.root / "TEST_ONLY_extra_original_link.data")
    elif fault == "oversized-original":
        with original_path.open("r+b") as stream:
            stream.truncate(64 * 1024 * 1024 + 1)
    now = datetime.fromisoformat(context["observed_utc"])
    # The failure is specifically new bundle admission, not a prior generic gate.
    assert recovery.validate_qualification(fixture.saved, digest, context, now=now) == context["execution_subject_sha256"]
    before = deepcopy(context)
    retained = {path: path.read_bytes() for path in fixture.root.glob("TEST_ONLY*")
                if path.is_file() and path.stat().st_size <= 256 * 1024}
    with pytest.raises(ValueError, match="pre-rollback failure bundle|duplicate JSON key|hard-linked output"):
        recovery.validate_qualification(fixture.saved, digest, context, now=now, for_publication=True)
    assert context == before and not (fixture.root / "peer-recovery-source.json").exists()
    assert {path: path.read_bytes() for path in retained} == retained


@pytest.mark.parametrize("missing", ("identity", "recent_logcat", "capture_filtered_logcat", "kernel_log",
                                     "runtime_configuration", "storage_file_index", "log_index", "tombstone_index"))
def test_formal_recovery_requires_every_original_artifact(recovery_fixture, missing):
    fixture = recovery_fixture
    digest, context, bundle_path, bundle = _original_bundle_format_case(fixture)
    bundle["artifacts"].pop(missing)
    _retain_bundle_format(context, bundle_path, bundle)
    with pytest.raises(ValueError, match="complete original artifact set"):
        recovery.validate_qualification(fixture.saved, digest, context,
            now=datetime.fromisoformat(context["observed_utc"]), for_publication=True)


def test_actual_bundle_change_at_final_publication_admission_refuses_commit(recovery_fixture):
    fixture = recovery_fixture
    digest, context, bundle_path, bundle = _original_bundle_format_case(fixture)
    before = deepcopy(context)
    destination = fixture.root / "NEVER_COMMITTED_COUNTERFACTUAL_RECOVERY"
    original = recovery.ROOT / bundle["artifacts"]["kernel_log"]["evidence_file"]
    called = []

    def memory_sink(path, outputs, *, commit_name, before_commit):
        assert path == destination and not path.exists()
        assert commit_name == "peer-recovery-source.json" and "recover-boot.sh" in outputs
        called.append(True)
        original.write_bytes(b"TEST_ONLY changed after initial admission\n")
        before_commit()  # The real qualifier, including actual original reads.
        pytest.fail("changed original must prevent any final commit")

    # Isolate only the filesystem sink; do not fake qualification or consent.
    with mock.patch.object(recovery, "publish_output_set", side_effect=memory_sink):
        with pytest.raises(ValueError, match="pre-rollback failure bundle: original hash"):
            recovery.prepare(destination, fixture.saved, digest, context)
    assert called == [True] and context == before and not destination.exists()
    assert not (fixture.root / "peer-recovery-source.json").exists()


def test_formal_historical_runtime_reference_has_no_unbounded_duplicate_read(recovery_fixture, monkeypatch):
    fixture = recovery_fixture
    digest, context, _, _ = _original_bundle_format_case(fixture)
    now = datetime.fromisoformat(context["observed_utc"])
    assert recovery.validate_qualification(fixture.saved, digest, context, now=now,
                                         for_publication=True) == context["execution_subject_sha256"]
    gate_path = recovery.ROOT / context["gates"]["recovery_historical_regressions"]["runtime"]["evidence_file"]
    original_read = Path.read_bytes

    def refuse_unbounded_read(path):
        if path == gate_path:
            pytest.fail("formal historical runtime original reached unbounded read_bytes")
        return original_read(path)

    # Filesystem boundary only: actual bounded open/read and validators remain real.
    monkeypatch.setattr(Path, "read_bytes", refuse_unbounded_read)
    assert recovery.validate_qualification(fixture.saved, digest, context, now=now,
                                         for_publication=True) == context["execution_subject_sha256"]
    assert not (fixture.root / "peer-recovery-source.json").exists()


@pytest.mark.parametrize("original", ("runtime-report", "bundle", "identity", "runtime_configuration"))
def test_formal_recovery_refuses_actual_json_original_over_256_kib(recovery_fixture, original):
    fixture = recovery_fixture
    digest, context, bundle_path, bundle = _original_bundle_format_case(fixture)
    now = datetime.fromisoformat(context["observed_utc"])
    assert recovery.validate_qualification(fixture.saved, digest, context, now=now,
                                         for_publication=True) == context["execution_subject_sha256"]
    gate = context["gates"]["recovery_historical_regressions"]["runtime"]
    path = (recovery.ROOT / gate["evidence_file"] if original == "runtime-report" else bundle_path
            if original == "bundle" else recovery.ROOT / bundle["artifacts"][original]["evidence_file"])
    raw = path.read_bytes()
    # Real, valid JSON bytes preserve all bindings; only the actual length changes.
    oversized = raw + b" " * (256 * 1024 + 1 - len(raw))
    assert len(oversized) == 256 * 1024 + 1 and json.loads(oversized) == json.loads(raw)
    if original == "bundle":
        _retain_bundle_format(context, bundle_path, bundle, raw=oversized)
    else:
        path.write_bytes(oversized)
        if original == "runtime-report":
            gate["evidence_sha256"] = recovery.sha(oversized)
        else:
            bundle["artifacts"][original].update(bytes=len(oversized), evidence_sha256=recovery.sha(oversized))
            _retain_bundle_format(context, bundle_path, bundle)
    before = deepcopy(context)
    with pytest.raises(ValueError, match="pre-rollback failure bundle: empty or oversized original"):
        recovery.validate_qualification(fixture.saved, digest, context, now=now, for_publication=True)
    assert context == before and path.read_bytes() == oversized
    assert not (fixture.root / "peer-recovery-source.json").exists()


def test_formal_recovery_real_original_sum_exhausts_reduced_test_budget(recovery_fixture, monkeypatch):
    fixture = recovery_fixture
    digest, context, bundle_path, bundle = _original_bundle_format_case(fixture)
    now = datetime.fromisoformat(context["observed_utc"])
    gate = context["gates"]["recovery_historical_regressions"]["runtime"]
    paths = [recovery.ROOT / gate["evidence_file"], bundle_path,
             *(recovery.ROOT / record["evidence_file"] for record in bundle["artifacts"].values())]
    retained = {path: path.read_bytes() for path in paths}
    total = sum(len(raw) for raw in retained.values())
    assert all(0 < len(raw) < 256 * 1024 for raw in retained.values())
    assert total < recovery.MAX_FAILURE_BUNDLE_BYTES
    # TEST_ONLY reduced bound over real read originals, NOT an actual 128MiB run.
    # Exact admission needs report + bundle + all eight originals, not merely artifacts.
    with monkeypatch.context() as budget_patch:
        budget_patch.setattr(recovery, "MAX_FAILURE_BUNDLE_BYTES", total)
        assert recovery.validate_qualification(fixture.saved, digest, context, now=now,
                                             for_publication=True) == context["execution_subject_sha256"]
        budget_patch.setattr(recovery, "MAX_FAILURE_BUNDLE_BYTES", total - 1)
        before = deepcopy(context)
        with pytest.raises(ValueError, match="pre-rollback failure bundle: empty or oversized original"):
            recovery.validate_qualification(fixture.saved, digest, context, now=now, for_publication=True)
        assert context == before
    assert {path: path.read_bytes() for path in paths} == retained
    assert not (fixture.root / "peer-recovery-source.json").exists()


@pytest.mark.parametrize("boundary", ("opening", "reading"))
def test_formal_recovery_refuses_actual_original_metadata_drift_at_io_boundary(recovery_fixture, monkeypatch, boundary):
    fixture = recovery_fixture
    digest, context, _, bundle = _original_bundle_format_case(fixture)
    now = datetime.fromisoformat(context["observed_utc"])
    assert recovery.validate_qualification(fixture.saved, digest, context, now=now,
                                         for_publication=True) == context["execution_subject_sha256"]
    path = recovery.ROOT / bundle["artifacts"]["kernel_log"]["evidence_file"]
    assert path.parent == fixture.root and path.name == "TEST_ONLY_original_kernel_log.data"
    retained, initial_stat, before = path.read_bytes(), path.stat(), deepcopy(context)
    actual_open = Path.open
    injected = []

    def drift_metadata_once():
        assert not injected
        # Mutate only generated test-original metadata, not data or a validator.
        os.utime(path, ns=(initial_stat.st_atime_ns, initial_stat.st_mtime_ns + 2_000_000_000))
        assert path.stat().st_mtime_ns != initial_stat.st_mtime_ns
        injected.append(boundary)

    class ReadBoundary:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def fileno(self):
            return self.stream.fileno()

        def read(self, size):
            raw = self.stream.read(size)
            drift_metadata_once()
            return raw

    def open_at_boundary(open_path, *args, **kwargs):
        stream = actual_open(open_path, *args, **kwargs)
        if open_path == path and args == ("rb",) and not injected:
            if boundary == "opening":
                drift_metadata_once()
            else:
                return ReadBoundary(stream)
        return stream

    # External I/O boundary only: actual open/read/lstat/fstat and checks remain real.
    with monkeypatch.context() as io_patch:
        io_patch.setattr(Path, "open", open_at_boundary)
        with pytest.raises(ValueError, match="pre-rollback failure bundle: original changed while " + boundary):
            recovery.validate_qualification(fixture.saved, digest, context, now=now, for_publication=True)
    assert injected == [boundary] and context == before and path.read_bytes() == retained
    assert path.stat().st_mtime_ns != initial_stat.st_mtime_ns
    assert not (fixture.root / "peer-recovery-source.json").exists()


@pytest.mark.parametrize("fault", (
    "runtime-status", "runtime-phase", "runtime-candidate", "runtime-build", "runtime-saved",
    "runtime-subject", "runtime-boot", "runtime-report-gate", "runtime-report-result",
    "runtime-report-synthetic", "runtime-report-fixture", "runtime-report-missing-fixture",
    "runtime-report-binding", "missing-historical-build", "missing-historical-runtime",
    "extra-historical-phase", "historical-build-status", "historical-build-report",
    "other-runtime-status", "other-runtime-report", "missing-other-gate", "extra-gate",
))
def test_bounded_formal_phase_adaptation_preserves_every_existing_gate_check(recovery_fixture, fault):
    fixture = recovery_fixture
    digest, context, _, _ = _original_bundle_format_case(fixture)
    now = datetime.fromisoformat(context["observed_utc"])
    # Reach the real public admission before isolating one malformed obligation.
    assert recovery.validate_qualification(fixture.saved, digest, context, now=now,
                                         for_publication=True) == context["execution_subject_sha256"]
    gates = context["gates"]
    historical = gates["recovery_historical_regressions"]
    proof = historical["runtime"]
    report_field = report_value = None
    if fault == "runtime-status":
        proof["status"] = "PENDING"
    elif fault in ("runtime-phase", "runtime-candidate", "runtime-build", "runtime-saved",
                   "runtime-subject", "runtime-boot"):
        field = {"runtime-phase": "phase", "runtime-candidate": "candidate_sha256",
                 "runtime-build": "build_subject_sha256", "runtime-saved": "saved_manifest_sha256",
                 "runtime-subject": "runtime_subject_sha256", "runtime-boot": "boot_id"}[fault]
        proof[field] = "build" if field == "phase" else "0" * 64
    elif fault.startswith("runtime-report-"):
        report_field, report_value = {
            "runtime-report-gate": ("gate", "recovery_offline_audit"),
            "runtime-report-result": ("result", "PENDING"),
            "runtime-report-synthetic": ("synthetic", True),
            "runtime-report-fixture": ("test_fixture_only", True),
            "runtime-report-missing-fixture": ("test_fixture_only", None),
            "runtime-report-binding": ("runtime_subject_sha256", "0" * 64),
        }[fault]
    elif fault in ("missing-historical-build", "missing-historical-runtime"):
        historical.pop(fault.removeprefix("missing-historical-"))
    elif fault == "extra-historical-phase":
        historical["unexpected"] = deepcopy(proof)
    elif fault in ("historical-build-status", "historical-build-report"):
        proof = historical["build"]
        if fault.endswith("status"):
            proof["status"] = "PENDING"
        else:
            report_field, report_value = "result", "PENDING"
    elif fault in ("other-runtime-status", "other-runtime-report"):
        proof = gates["current_process_lifetimes"]["runtime"]
        if fault.endswith("status"):
            proof["status"] = "PENDING"
        else:
            report_field, report_value = "test_fixture_only", True
    elif fault == "missing-other-gate":
        gates.pop("current_process_lifetimes")
    elif fault == "extra-gate":
        gates["unexpected"] = deepcopy(gates["current_process_lifetimes"])
    if report_field is not None:
        path = recovery.ROOT / proof["evidence_file"]
        report = json.loads(path.read_bytes())
        if report_value is None:
            report.pop(report_field)
        else:
            report[report_field] = report_value
        raw = recovery.canonical(report)
        path.write_bytes(raw)
        proof["evidence_sha256"] = recovery.sha(raw)
    before = deepcopy(context)
    with pytest.raises(ValueError):
        recovery.validate_qualification(fixture.saved, digest, context, now=now, for_publication=True)
    assert context == before and not (fixture.root / "peer-recovery-source.json").exists()


def test_role_recovery_publishes_fixed_restore_sources_at_in_memory_boundary(recovery_fixture):
    fixture = recovery_fixture
    manifest, digest, context = role_recovery_context(fixture)
    context.update(test_fixture_only=True,
                   build_subject_sha256=recovery.build_subject_sha256(fixture.saved, digest),
                   runtime_subject_sha256="d" * 64)
    original = deepcopy(context)
    destination = fixture.root / "NEVER_PUBLISHED_ROLE_RECOVERY"
    captured = {}

    def memory_sink(path, outputs, *, commit_name, before_commit):
        assert path == destination and commit_name == "peer-recovery-source.json"
        assert not destination.exists()
        before_commit()
        captured.update(outputs)

    # The fake external admission cannot reach the real output sink. This is
    # source-routing coverage, not proof that fixture data qualifies a camera.
    with mock.patch.object(recovery, "validate_qualification", return_value="TEST_ONLY_NOT_AUTHORITY") as admission, \
         mock.patch.object(recovery, "publish_output_set", side_effect=memory_sink):
        report = recovery.prepare(destination, fixture.saved, digest, context)
    assert all(call.kwargs == {"for_publication": True} for call in admission.call_args_list)
    assert len(admission.call_args_list) == 2
    assert set(captured) == {"restore-boot.sh", "maintenance-restore", "session-context.data",
                            "peer-recovery-source.json"}
    assert set(report["script_hashes"]) == {"restore-boot.sh", "maintenance-restore"}
    assert b"X2DII_BOOT_BOUNDARY_REQUEST:restore" in captured["restore-boot.sh"]
    assert b"X2DII_BOOT_BOUNDARY_RESPONSE" not in captured["restore-boot.sh"]
    assert b"x2dii-boot-maintenance-response-v1" in captured["maintenance-restore"]
    assert b"rm " not in captured["restore-boot.sh"] and b"stop camera-gui" not in captured["restore-boot.sh"]
    assert report["recovery_scope"] == "OFFICIAL_RC_ONLY_OWNED_FILES_RETAINED"
    assert report["owned_cleanup_status"] == "REQUIRES_NEW_BOOT_STOCK_READBACK_AND_EXACT_OWNERSHIP"
    assert report["installable"] is False and report["camera_accesses"] == 0
    assert context == original and not destination.exists()


@pytest.mark.parametrize("synthetic", (True, False))
def test_real_recovery_qualifier_rejects_fixtures_before_output(recovery_fixture, synthetic):
    from tests.test_runtime_observation import synthetic_observation
    fixture = recovery_fixture
    manifest, digest, context = role_recovery_context(fixture)
    context["synthetic"] = synthetic
    context["runtime_observation"] = synthetic_observation(context, manifest["candidate"]["gui_sha256"], recovery=True)
    before = deepcopy(context)
    destination = fixture.root / "REFUSED_FIXTURE"
    with mock.patch.object(recovery, "publish_output_set") as publish:
        with pytest.raises(ValueError, match="synthetic recovery|test fixture cannot authorize"):
            recovery.prepare(destination, fixture.saved, digest, context)
    publish.assert_not_called()
    assert context == before and not destination.exists()


@pytest.mark.parametrize("stale", ("restore-boot.sh", "maintenance-restore", "recover-boot.sh", "preplace-0.sh"))
def test_unqualified_recovery_rejects_any_existing_executable(recovery_fixture, stale):
    fixture = recovery_fixture
    _, digest, context = role_recovery_context(fixture)
    destination = fixture.root / "STALE_INERT_ONLY"
    destination.mkdir()
    (destination / stale).write_bytes(b"TEST_ONLY INERT STALE SOURCE")
    with pytest.raises(ValueError, match="forbidden executable"):
        recovery.prepare(destination, fixture.saved, digest)
    assert (destination / stale).read_bytes() == b"TEST_ONLY INERT STALE SOURCE"
    assert not (destination / "peer-recovery-source.json").exists()


@pytest.mark.parametrize("reason", ("lease expired", "source changed"))
def test_final_external_admission_failure_propagates_without_any_saved_package(recovery_fixture, reason):
    fixture = recovery_fixture
    _, digest, context = role_recovery_context(fixture)
    context.update(test_fixture_only=True,
                   build_subject_sha256=recovery.build_subject_sha256(fixture.saved, digest),
                   runtime_subject_sha256="d" * 64)
    destination = fixture.root / "NEVER_COMMITTED"

    def memory_sink(path, outputs, *, commit_name, before_commit):
        assert not destination.exists()
        before_commit()
        pytest.fail("failed final admission must not reach a commit")

    with mock.patch.object(recovery, "validate_qualification",
                           side_effect=["TEST_ONLY_NOT_AUTHORITY", ValueError("TEST_ONLY " + reason)]) as admission, \
         mock.patch.object(recovery, "publish_output_set", side_effect=memory_sink):
        with pytest.raises(ValueError, match="TEST_ONLY " + reason):
            recovery.prepare(destination, fixture.saved, digest, context)
    assert len(admission.call_args_list) == 2
    assert not destination.exists()
