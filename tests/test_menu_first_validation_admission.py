"""Counterfactual admission over an in-memory filesystem and process boundary.

No approval report is published and no native API is called. Fixture records
exercise parsing/binding only, never represent a real user/camera observation.
"""
import base64
import json
import re
from copy import deepcopy
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest import mock

import pytest

from tests.test_release_lifecycle import installer
from tests.test_menu_first_validation import saved_observation
from tests.test_prepared_boot_transport import parent_plan_for
from tools import menu_first_validation as flow, prepare_peer_install as peer, release_identity
from tools import menu_content_transport as content
from tests.test_menu_first_validation_flow import ModelMaintenance, content_child, placement_child, model_worker_outputs
from tests.test_stage_peer_usb_access import recorded_launch_fixture
from tests.test_prepared_menu_transport import prior_window_evidence


@pytest.fixture
def counterfactual(installer):
    """Filesystem/time/native boundaries only; all production validators run."""
    docs, now = {}, [datetime.now(timezone.utc).replace(microsecond=0)]
    original_read, original_is_file = Path.read_bytes, Path.is_file

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return now[0] if tz else now[0].replace(tzinfo=None)

    def save(name, value):
        raw = value if type(value) is bytes else json.dumps(value).encode()
        path = peer.ROOT / "build/test-first-admission-in-memory" / name
        docs[path] = raw
        return {"evidence_file": path.relative_to(peer.ROOT).as_posix(), "evidence_sha256": peer.sha(raw)}

    with mock.patch.object(Path, "read_bytes", lambda path: docs[path] if path in docs else original_read(path)), \
         mock.patch.object(Path, "is_file", lambda path: path in docs or original_is_file(path)), \
         mock.patch.object(flow, "datetime", Clock):
        from tools.delivery_files import assemble_role_delivery
        manifest = installer.manifest
        plan = parent_plan_for(manifest)
        build = peer.build_subject_sha256(manifest)
        identity = assemble_role_delivery(manifest["candidate"], manifest["candidate_sha256"],
            peer.render_role_programs(manifest))["delivery_identity"]
        q = saved_observation(installer)
        q["synthetic"] = False
        q["observed_utc"] = now[0].isoformat()
        q["runtime_observation"]["capture_owner"]["route"].update(save("capture-route.bin", b"counterfactual capture route"))
        approval = {"schema": "x2dii-first-menu-validation-approval-v1", "approved": True,
            "purpose": "temporary_menu_validation", "action": "run_and_restore", "actions": list(flow.FIRST_VALIDATION_ACTIONS),
            "candidate_sha256": manifest["candidate_sha256"], "build_subject_sha256": build, "boot_id": q["boot_id"],
            "operation_nonce": "c" * 32, "approved_utc": now[0].isoformat(),
            "expires_utc": (now[0] + timedelta(seconds=1000)).isoformat(), "reviewed_by": "human_user",
            "source_message_id": "COUNTERFACTUAL_TEST_BOUNDARY_NOT_REAL_CONSENT"}
        approval["record"] = save("approval.json", approval)

        def inputs(q):
            raw = json.dumps(q).encode()
            sources = [save("raw-source-" + q["session_nonce"] + ".bin", b"counterfactual raw source for " + peer.sha(raw).encode())]
            prerequisites = {"saved_observation_sha256": peer.sha(raw), "observation_sources": sources,
                             "delivery_identity": identity, "gates": {}}
            runtime = peer.runtime_subject_sha256(manifest, q)
            for gate, phases in flow.FIRST_VALIDATION_GATES.items():
                prerequisites["gates"][gate] = {}
                for phase in phases:
                    bound = release_identity.gate_bindings(phase, candidate_sha256=manifest["candidate_sha256"],
                        build_subject_sha256=build, runtime_subject_sha256=runtime, boot_id=q["boot_id"], delivery_identity=identity)
                    proof = {**bound, "result": "PASS", "synthetic": False, "test_fixture_only": False, "gate": gate}
                    reference = save(gate + "-" + phase + ".json", proof)
                    prerequisites["gates"][gate][phase] = {**bound, "status": "PASS", **reference}
            return dict(saved_observation=raw, saved_observation_sha256=peer.sha(raw),
                prerequisites=prerequisites, observation_sources=sources)

        yield dict(installer=installer, manifest=manifest, plan=plan, q=q, approval=approval,
            inputs=inputs, docs=docs, save=save, now=now)


def test_public_first_validation_has_a_specific_reachable_constructor(installer):
    # RED for the missing public route; an empty object must remain refused.
    assert callable(flow.prepare_first_validation)
    with pytest.raises(ValueError):
        flow.prepare_first_validation(installer.manifest, parent_plan_for(installer.manifest),
            saved_observation=b"{}", saved_observation_sha256=peer.sha(b"{}"),
            prerequisites={}, approval={}, observation_sources=())


def test_first_validation_gate_table_never_requires_new_menu_result():
    assert "actual_menu_keys_capture" not in flow.FIRST_VALIDATION_GATES
    assert flow.FIRST_VALIDATION_GATES["official_runtime_baseline"] == ("runtime",)
    assert flow.FIRST_VALIDATION_GATES["all_applicable_historical_regressions"] == ("build",)
    assert set(flow.FIRST_VALIDATION_ACTIONS) == {
        "stage_fixed_content", "stage_temporary_programs", "place_four_extension_files",
        "run_temporary_gui", "restore_original_gui"}


def test_complete_counterfactual_input_reaches_public_object_without_any_camera_action(counterfactual):
    c = counterfactual
    with mock.patch("tools.menu_host_process.subprocess.Popen", side_effect=AssertionError("unexpected child")):
        candidate = flow.prepare_first_validation(c["manifest"], c["plan"], approval=c["approval"], **c["inputs"](c["q"]))
    assert type(candidate) is flow.FirstValidationSession
    assert candidate.phase == "content" and not candidate._completed


def test_complete_additional_legal_init_root_does_not_block_public_first_validation(counterfactual):
    c = counterfactual
    q = deepcopy(c["q"])
    q["init_scan_roots"].append("/vendor/etc/init")
    result = flow.prepare_first_validation(c["manifest"], c["plan"], approval=c["approval"], **c["inputs"](q))
    assert result.phase == "content"


@pytest.mark.parametrize("fault", ("missing-approval", "usb-only", "boot-action", "expired-approval", "future-approval",
    "stale-observation", "fixture-observation", "missing-gate", "fixture-gate", "changed-source", "boot-mismatch", "changed-approval"))
def test_first_admission_rejects_before_external_actions(counterfactual, fault):
    c = counterfactual
    approval, q = deepcopy(c["approval"]), deepcopy(c["q"])
    if fault == "missing-approval":
        approval = {}
    elif fault == "usb-only":
        approval["purpose"] = "temporary_usb_access"
    elif fault == "boot-action":
        approval["actions"].append("activate_boot")
    elif fault == "expired-approval":
        c["now"][0] += timedelta(seconds=1001)
    elif fault == "future-approval":
        c["now"][0] -= timedelta(seconds=1)
    elif fault == "stale-observation":
        c["now"][0] += timedelta(seconds=601)
    elif fault == "fixture-observation":
        q["runtime_observation"]["test_fixture_only"] = True
    elif fault == "boot-mismatch":
        approval["boot_id"] = "33333333-4444-4555-8666-777777777777"
        approval["record"] = c["save"]("changed-approval.json", {key: val for key, val in approval.items() if key != "record"})
    elif fault == "changed-approval":
        c["docs"][peer.ROOT / approval["record"]["evidence_file"]] += b"changed"
    args = c["inputs"](q)
    if fault == "missing-gate":
        del args["prerequisites"]["gates"]["official_runtime_baseline"]
    elif fault == "fixture-gate":
        proof = args["prerequisites"]["gates"]["complete_offline_audit"]["build"]
        path = peer.ROOT / proof["evidence_file"]
        value = json.loads(c["docs"][path])
        value["test_fixture_only"] = True
        c["docs"][path] = json.dumps(value).encode()
        proof["evidence_sha256"] = peer.sha(c["docs"][path])
    elif fault == "changed-source":
        c["docs"][peer.ROOT / args["observation_sources"][0]["evidence_file"]] += b"changed"
    with mock.patch("tools.menu_host_process.subprocess.Popen", side_effect=AssertionError("native child started")):
        with pytest.raises(ValueError):
            flow.prepare_first_validation(c["manifest"], c["plan"], approval=approval, **args)


def prepare_public_window(c, candidate):
    stage = candidate._flow if candidate.phase == "ready" else candidate._stage
    epoch = int(c["now"][0].timestamp())
    outputs = model_worker_outputs(c["manifest"], candidate._saved.raw_session, epoch) if candidate.phase == "ready" else []
    maintenance = ModelMaintenance(stage, outputs, [epoch])
    candidate.prepare_window(maintenance)
    report = recorded_launch_fixture()
    old = report["remote"]
    report["remote"] = "/tmp/x2a-" + {"content": "111111abcdef", "code": "222222abcdef", "ready": "333333abcdef"}[candidate.phase]
    report["commands"][0].update(utc=c["now"][0].isoformat(),
        command=report["commands"][0]["command"].replace(old, report["remote"]))
    report["bootId"] = c["q"]["boot_id"]
    if candidate.phase != "content":
        prior_window_evidence(candidate._stage._plan, candidate._stage._session, report, epoch)
    return maintenance, report, outputs


def public_window(c, candidate, spawned, *, child_fault=None):
    """Actual public object/host/driver with only external I/O substituted."""
    maintenance, report, outputs = prepare_public_window(c, candidate)

    def popen(args, **kwargs):
        # Read the real host's exact temporary source. No C# is executed and no
        # internal admission/coordinator/driver success is substituted.
        script = base64.b64decode(args[-1]).decode("utf-16le")
        path = Path(re.search(r"ReadAllBytes\('([^']+)'\)", script).group(1))
        source = path.read_text(encoding="utf-8")
        assert peer.sha(source.encode()) in script
        assert "Qualified = true;" in source and "Qualified = false;" not in source
        assert kwargs["stdin"] == kwargs["stdout"] == kwargs["stderr"]
        phase = candidate._starts[-1]
        spawned.append((candidate.phase, phase, source))
        child = placement_child(outputs) if phase == "menu-preplacement" else content_child(candidate._stage)
        child.returncode = 0
        if child_fault is not None:
            child_fault(candidate, phase, child)
        return child

    with mock.patch("tools.menu_host_process.subprocess.Popen", side_effect=popen):
        result = flow.run_first_validation(candidate, ready_launch_report=json.dumps(report).encode(),
            maintenance_session=maintenance)
    return maintenance, result


def next_public_window(c, candidate):
    c["now"][0] += timedelta(seconds=100)
    q = deepcopy(c["q"])
    q.update(observed_utc=c["now"][0].isoformat(), session_nonce=("d" if candidate.phase == "content" else "e") * 32)
    candidate.next_window(**c["inputs"](q))


def test_public_first_validation_runs_three_windows_then_recovers_after_approval_expiry(counterfactual):
    c, spawned = counterfactual, []
    approval = deepcopy(c["approval"])
    approval["expires_utc"] = (c["now"][0] + timedelta(seconds=330)).isoformat()
    approval["record"] = c["save"]("short-approval.json", {key: val for key, val in approval.items() if key != "record"})
    candidate = flow.prepare_first_validation(c["manifest"], c["plan"], approval=approval, **c["inputs"](c["q"]))
    for phase in ("content", "code", "ready"):
        assert candidate.phase == phase
        maintenance, result = public_window(c, candidate, spawned)
        assert result["installable"] is False
        if phase != "ready":
            next_public_window(c, candidate)
    assert [(phase, child) for phase, child, _ in spawned] == [
        ("content", "stable-content"), ("code", "preparation"), ("ready", "preparation"), ("ready", "menu-preplacement")]
    assert len(result["worker_result"]["completed_identities"]) == 4
    c["now"][0] += timedelta(seconds=91)
    result = candidate.launch_temporary(maintenance)
    assert result["status"] == "TEMPORARY_GUI_STARTED_AWAITING_REAL_UI_CHECK"
    assert not result["installable"] and not result["feature_validated"]
    assert not maintenance.stop_requested and candidate.read_temporary()["status"] == "PENDING"
    # Changed source/approval and elapsed consent must block *new* work, but
    # must not prevent the stop/recovery of the already launched temporary GUI.
    c["docs"][peer.ROOT / approval["record"]["evidence_file"]] += b"changed after launch"
    c["now"][0] += timedelta(seconds=40)
    assert candidate.read_temporary()["status"] == "PENDING"
    restored = candidate.finish_and_restore()
    assert restored["status"] == "TEMPORARY_GUI_EXITED_NOT_FUNCTION_QUALIFIED"
    assert restored["lifecycle"][-1]["exit_code"] == 0
    assert not restored["installable"] and not restored["feature_validated"]
    labels = [label for label, _ in maintenance.calls]
    assert labels.count("lifecycle-launch") == labels.count("lifecycle-stop") == 1


@pytest.mark.parametrize("exit_code", (0, 78))
def test_public_finish_reads_completed_worker_before_requesting_stop(counterfactual, exit_code):
    c, spawned = counterfactual, []
    candidate = flow.prepare_first_validation(c["manifest"], c["plan"],
        approval=c["approval"], **c["inputs"](c["q"]))
    for phase in ("content", "code", "ready"):
        maintenance, _ = public_window(c, candidate, spawned)
        if phase != "ready":
            next_public_window(c, candidate)
    c["now"][0] += timedelta(seconds=91)
    candidate.launch_temporary(maintenance)
    c["now"][0] += timedelta(seconds=151)  # Delayed host, beyond the poll budget.
    original = maintenance.command
    digest = candidate._flow._lifecycle.sha256
    receipt = peer.sha(f"{digest}:{exit_code}\n".encode())

    def command(label, text):
        if label == "lifecycle-stop":
            pytest.fail("finished worker must not receive a new stop request")
        if label == "lifecycle-read":
            maintenance.calls.append((label, text))
            return f"X2DII_LIFECYCLE_FINAL:{digest}:{receipt}:{exit_code}:NOT_FEATURE_VALIDATED\n"
        return original(label, text)

    maintenance.command = command
    if exit_code == 0:
        result = candidate.finish_and_restore()
        assert result["status"] == "TEMPORARY_GUI_EXITED_NOT_FUNCTION_QUALIFIED"
        assert result["lifecycle"][-1]["exit_code"] == 0
        assert not candidate._flow.failed and not result["feature_validated"]
    else:
        # The original 120-second timeout is 78, never successful validation.
        with pytest.raises(ValueError, match="temporary GUI lifecycle exited 78") as caught:
            candidate.finish_and_restore()
        assert caught.value.first_validation_evidence["final_receipt"]["exit_code"] == 78


@pytest.mark.parametrize("fault", ("natural-exit-race", "other-stop-error", "invalid-final", "failed-final"))
def test_public_finish_resolves_only_bound_success_after_stop_race(counterfactual, fault):
    c, spawned = counterfactual, []
    candidate = flow.prepare_first_validation(c["manifest"], c["plan"],
        approval=c["approval"], **c["inputs"](c["q"]))
    for phase in ("content", "code", "ready"):
        maintenance, _ = public_window(c, candidate, spawned)
        if phase != "ready":
            next_public_window(c, candidate)
    c["now"][0] += timedelta(seconds=91)
    candidate.launch_temporary(maintenance)
    original = maintenance.command
    digest = candidate._flow._lifecycle.sha256
    stopped = False
    exit_code = 34 if fault == "other-stop-error" else 33
    original_error = ValueError("camera command returned " + str(exit_code))

    def command(label, text):
        nonlocal stopped
        if label == "lifecycle-stop":
            stopped = True
            maintenance.calls.append((label, text))
            maintenance.report.setdefault("commands", []).append({"label": label,
                "command": text, "exit": exit_code, "error": str(original_error)})
            raise original_error
        if label == "lifecycle-read" and stopped:
            maintenance.calls.append((label, text))
            if fault == "invalid-final":
                return "invalid final receipt\n"
            status = 78 if fault == "failed-final" else 0
            receipt = peer.sha(f"{digest}:{status}\n".encode())
            return f"X2DII_LIFECYCLE_FINAL:{digest}:{receipt}:{status}:NOT_FEATURE_VALIDATED\n"
        return original(label, text)

    maintenance.command = command
    if fault == "natural-exit-race":
        result = candidate.finish_and_restore()
        assert result["status"] == "TEMPORARY_GUI_EXITED_NOT_FUNCTION_QUALIFIED"
        assert result["stop_errors"][-1]["error"] == str(original_error)
        assert not candidate._flow.failed and not result["feature_validated"]
    else:
        with pytest.raises(ValueError) as caught:
            candidate.finish_and_restore()
        if fault == "failed-final":
            assert str(caught.value) == "temporary GUI lifecycle exited 78"
            assert caught.value.first_validation_evidence["stop_errors"][-1]["error"] == str(original_error)
        else:
            assert caught.value is original_error
        assert candidate._flow.failed
    assert len([label for label, _ in maintenance.calls if label == "lifecycle-stop"]) == 1


@pytest.mark.parametrize("roots", (["/system/etc/init", "/vendor/../etc/init"],
    ["/system/etc/init", "/blackbox"], ["/system/etc/init", "/system/etc"],
    ["/system/etc/init", "/system/etc/init"], ["/system/etc/init", None]))
def test_malformed_duplicate_or_overlapping_init_roots_still_refuse(counterfactual, roots):
    c, q = counterfactual, deepcopy(counterfactual["q"])
    q["init_scan_roots"] = roots
    with pytest.raises(ValueError, match="init scan root"):
        flow.prepare_first_validation(c["manifest"], c["plan"], approval=c["approval"], **c["inputs"](q))


@pytest.mark.parametrize("alias", ("/system//etc", "//system", "/vendor/etc/init/", "/"))
def test_public_first_entry_refuses_noncanonical_init_root_alias(counterfactual, alias):
    c, q = counterfactual, deepcopy(counterfactual["q"])
    q["init_scan_roots"].append(alias)
    with pytest.raises(ValueError, match="init scan root"):
        flow.prepare_first_validation(c["manifest"], c["plan"], approval=c["approval"], **c["inputs"](q))


@pytest.mark.parametrize("fault", ("consent-expired", "observation-expired", "insufficient-budget", "changed-source"))
def test_public_prepared_window_refuses_new_child_after_expiry_or_drift(counterfactual, fault):
    c = counterfactual
    candidate = flow.prepare_first_validation(c["manifest"], c["plan"], approval=c["approval"], **c["inputs"](c["q"]))
    maintenance, report, _ = prepare_public_window(c, candidate)
    calls = len(maintenance.calls)
    if fault == "changed-source":
        c["docs"][peer.ROOT / candidate._sources[0]["evidence_file"]] += b"changed"
    else:
        c["now"][0] += timedelta(seconds={"consent-expired": 1001, "observation-expired": 601, "insufficient-budget": 79}[fault])
    with mock.patch("tools.menu_host_process.subprocess.Popen", side_effect=AssertionError("new child after refusal")):
        with pytest.raises(ValueError):
            flow.run_first_validation(candidate, ready_launch_report=json.dumps(report).encode(), maintenance_session=maintenance)
    assert len(maintenance.calls) == calls
    assert not candidate._completed


@pytest.mark.parametrize("fault", ("already-admitted", "mixed-code", "shortened-source"))
def test_specific_host_refuses_any_caller_supplied_admitted_or_mixed_source(counterfactual, fault):
    from tools.menu_host_process import FirstValidationHost
    c = counterfactual
    candidate = flow.prepare_first_validation(c["manifest"], c["plan"], approval=c["approval"], **c["inputs"](c["q"]))
    _, report, _ = prepare_public_window(c, candidate)
    candidate._launch_raw = json.dumps(report).encode()
    launch = flow.prepared._recorded_launch(report)
    source = content.review_content_host_source(candidate._stage._plan, candidate._stage._session, launch)
    source = (source.replace("ContentQualified = false;", "ContentQualified = true;") if fault == "already-admitted"
              else source + "\n// arbitrary caller source" if fault == "mixed-code" else source[:-10])
    with mock.patch("tools.menu_host_process.subprocess.Popen", side_effect=AssertionError("bad source child")):
        with pytest.raises(ValueError, match="exact current renderer"):
            FirstValidationHost(candidate).start("stable-content", source)
    assert not candidate._starts


@pytest.mark.parametrize("failed_phase", ("code", "ready"))
def test_public_child_failure_keeps_original_error_and_cannot_advance(counterfactual, failed_phase):
    c, spawned = counterfactual, []
    candidate = flow.prepare_first_validation(c["manifest"], c["plan"], approval=c["approval"], **c["inputs"](c["q"]))
    public_window(c, candidate, spawned)
    next_public_window(c, candidate)
    if failed_phase == "ready":
        public_window(c, candidate, spawned)
        next_public_window(c, candidate)

    def corrupt_child(candidate, phase, child):
        import io
        child.stdout = io.BytesIO(b"unexpected original child payload\n")
    with pytest.raises(ValueError) as caught:
        public_window(c, candidate, spawned, child_fault=corrupt_child)
    assert candidate.failed and failed_phase not in candidate._completed
    assert "content process" in str(caught.value)
    assert hasattr(caught.value, "first_validation_stage_evidence" if failed_phase == "code" else "first_validation_evidence")
    assert not any(phase == "menu-preplacement" for _, phase, _ in spawned)
    with pytest.raises(ValueError, match="completed|failed"):
        next_public_window(c, candidate)


def test_approval_expiring_after_ready_preparation_blocks_placement_child(counterfactual):
    c, spawned = counterfactual, []
    approval = deepcopy(c["approval"])
    approval["expires_utc"] = (c["now"][0] + timedelta(seconds=270)).isoformat()
    approval["record"] = c["save"]("ready-expiry-approval.json", {key: val for key, val in approval.items() if key != "record"})
    candidate = flow.prepare_first_validation(c["manifest"], c["plan"], approval=approval, **c["inputs"](c["q"]))
    public_window(c, candidate, spawned)
    next_public_window(c, candidate)
    public_window(c, candidate, spawned)
    next_public_window(c, candidate)

    def expire_on_wait(candidate, phase, child):
        if candidate.phase == "ready" and phase == "preparation":
            original = child.wait
            def wait(timeout=None):
                if c["now"][0] < datetime.fromisoformat(approval["expires_utc"]):
                    c["now"][0] += timedelta(seconds=71)
                return original(timeout)
            child.wait = wait
    with pytest.raises(ValueError, match="stale or future"):
        public_window(c, candidate, spawned, child_fault=expire_on_wait)
    assert candidate.failed and "ready" not in candidate._completed
    assert [phase for _, phase, _ in spawned] == ["stable-content", "preparation", "preparation"]


def test_expiry_during_stock_preflight_prevents_first_maintenance_write(counterfactual):
    c = counterfactual
    candidate = flow.prepare_first_validation(c["manifest"], c["plan"], approval=c["approval"], **c["inputs"](c["q"]))
    maintenance = ModelMaintenance(candidate._stage, [], [int(c["now"][0].timestamp())])
    original = maintenance.command
    def command(label, text):
        result = original(label, text)
        if label == "lock-absent":
            c["now"][0] += timedelta(seconds=1001)
        return result
    maintenance.command = command
    with pytest.raises(ValueError, match="stale or future"):
        candidate.prepare_window(maintenance)
    assert not any(label.startswith("prepare-observer-") for label, _ in maintenance.calls)


@pytest.mark.parametrize("phase", ("content", "code", "ready"))
def test_expiry_between_preparation_writes_stops_each_public_window(counterfactual, phase):
    c, spawned = counterfactual, []
    approval = deepcopy(c["approval"])
    seconds = {"content": 1, "code": 101, "ready": 201}[phase]
    approval["expires_utc"] = (c["now"][0] + timedelta(seconds=seconds)).isoformat()
    approval["record"] = c["save"]("between-writes-approval.json",
        {key: value for key, value in approval.items() if key != "record"})
    candidate = flow.prepare_first_validation(c["manifest"], c["plan"],
        approval=approval, **c["inputs"](c["q"]))
    while candidate.phase != phase:
        public_window(c, candidate, spawned)
        next_public_window(c, candidate)
    stage = candidate._flow if phase == "ready" else candidate._stage
    maintenance = ModelMaintenance(stage, [], [int(c["now"][0].timestamp())])
    original = maintenance.command

    def command(label, text):
        result = original(label, text)
        if label.startswith("prepare-observer-"):
            c["now"][0] += timedelta(seconds=2)
        return result

    maintenance.command = command
    with mock.patch("tools.menu_host_process.subprocess.Popen", side_effect=AssertionError("unexpected child")):
        with pytest.raises(ValueError, match="stale or future"):
            candidate.prepare_window(maintenance)
    assert candidate.failed and phase not in candidate._completed
    assert len([label for label, _ in maintenance.calls if label.startswith("prepare-observer-")]) == 1


@pytest.mark.parametrize("expiry_during", ("preflight", "final-local-validation"))
def test_expiry_during_restored_preflight_prevents_temporary_gui_launch(counterfactual, expiry_during):
    c, spawned = counterfactual, []
    approval = deepcopy(c["approval"])
    approval["expires_utc"] = (c["now"][0] + timedelta(seconds=330)).isoformat()
    approval["record"] = c["save"]("preflight-expiry.json", {key: val for key, val in approval.items() if key != "record"})
    candidate = flow.prepare_first_validation(c["manifest"], c["plan"], approval=approval, **c["inputs"](c["q"]))
    for phase in ("content", "code", "ready"):
        maintenance, _ = public_window(c, candidate, spawned)
        if phase != "ready":
            next_public_window(c, candidate)
    c["now"][0] += timedelta(seconds=91)
    original = maintenance.command
    original_read = Path.read_bytes
    armed = [False]
    def command(label, text):
        result = original(label, text)
        if label == "lock-absent":
            if expiry_during == "preflight":
                c["now"][0] += timedelta(seconds=40)
            else:
                armed[0] = True
        return result
    def read_bytes(path):
        raw = original_read(path)
        if armed[0] and path == peer.ROOT / approval["record"]["evidence_file"]:
            armed[0] = False
            c["now"][0] += timedelta(seconds=40)
        return raw
    maintenance.command = command
    with mock.patch.object(Path, "read_bytes", read_bytes), \
         pytest.raises(ValueError, match="stale or future") as caught:
        candidate.launch_temporary(maintenance)
    assert not any(label.startswith("lifecycle-") for label, _ in maintenance.calls)
    assert "stale or future" in caught.value.first_validation_evidence["original_error"]
