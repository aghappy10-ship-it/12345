"""Final-admission adapter boundaries; no qualification or native device calls."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import base64
import gzip
import io
import json
import re
import tarfile
from unittest.mock import Mock

import pytest

from tests.test_release_lifecycle import installer
from tests.test_stage_peer_usb_access import recorded_launch_fixture
from tests.test_menu_content_transport import native_fixture_source
from tools import prepare_peer_install as peer, stage_menu_delivery as stage
from tools import menu_content_transport as content, delivery_files


def inputs(installer):
    manifest, q = deepcopy(installer.manifest), deepcopy(installer.q)
    q["observer"]["domain"] = "u:r:hbl_camera_service:s0"
    programs = peer.render_role_programs(manifest)
    assembly = delivery_files.assemble_role_delivery(manifest["candidate"], manifest["candidate_sha256"], programs)
    q["delivery_identity"] = assembly["delivery_identity"]
    with tarfile.open(fileobj=io.BytesIO(assembly["archive_bytes"])) as reader:
        members = {item.name: reader.extractfile(item).read() for item in reader.getmembers() if item.name != "members.json"}
    renderer = (peer.ROOT / "tools/prepare_peer_install.py").read_bytes()
    plan = stage.plan_compressed_role_staging(members=members, candidate=manifest["candidate"],
        candidate_sha256=manifest["candidate_sha256"], script_hashes={name: peer.sha(raw.encode()) for name, raw in programs.items()},
        renderer_source=renderer, renderer_source_sha256=peer.sha(renderer), delivery_identity=q["delivery_identity"])
    session = stage.plan_raw_session_staging(plan, manifest, peer.session_data(manifest, q))
    launch = datetime.now(timezone.utc)
    report = recorded_launch_fixture()
    report["bootId"] = q["boot_id"]
    report["commands"][0]["utc"] = launch.isoformat()
    raw = json.dumps(report, indent=2).encode("utf-8")
    window = {"approved": True, "purpose": "temporary_adb_fixed_menu_staging",
        "candidate_sha256": plan.candidate_sha256, "plan_sha256": plan.plan_sha256,
        "boot_id": q["boot_id"], "session_nonce": q["session_nonce"],
        "session_data_sha256": session.data_sha256,
        "launch_session_sha256": peer.sha(raw), "launch_started_utc": launch.isoformat()}
    return dict(members=members, manifest=manifest, qualification=q, window_authorization=window,
                saved_launch_report=raw), plan, session, launch


@pytest.mark.parametrize("kind", ("synthetic", "test-fixture"))
def test_real_final_admission_still_rejects_fixtures_before_any_source(installer, monkeypatch, kind):
    arguments, _, _, _ = inputs(installer)
    if kind == "test-fixture":
        arguments["qualification"]["synthetic"] = False
    sender = Mock(side_effect=AssertionError("fixture reached source rendering"))
    monkeypatch.setattr(content, "review_content_host_source", sender)
    with pytest.raises(ValueError, match="synthetic|test fixture"):
        stage.qualified_host_source(**arguments)
    sender.assert_not_called()


@pytest.mark.parametrize("damage", ("missing", "dict-not-bytes", "hash", "duplicate-json", "failed",
                                    "stager", "decoder", "boot", "reply-time", "missing-start", "not-approved"))
def test_saved_launch_bytes_and_existing_window_scope_are_required_before_render(installer, monkeypatch, damage):
    arguments, _, _, _ = inputs(installer)
    # Counterfactual admission only: the source renderer must never be reached.
    monkeypatch.setattr(peer, "validate_qualification", Mock())
    sender = Mock(side_effect=AssertionError("invalid launch reached source rendering"))
    monkeypatch.setattr(content, "review_content_host_source", sender)
    report = json.loads(arguments["saved_launch_report"])
    if damage == "missing":
        arguments.pop("saved_launch_report")
    elif damage == "dict-not-bytes":
        arguments["saved_launch_report"] = report
    elif damage == "hash":
        arguments["saved_launch_report"] += b" "
    elif damage == "not-approved":
        arguments["window_authorization"]["approved"] = False
    else:
        if damage == "failed": report["status"] = "FAILED_OR_UNCERTAIN_DO_NOT_RETRY_AUTOMATICALLY"
        elif damage == "stager": report["stagerSha256"] = "0" * 64
        elif damage == "decoder": report["replySources"] = {}
        elif damage == "boot": report["bootId"] = "33333333-4444-4555-8666-777777777777"
        elif damage == "reply-time": arguments["window_authorization"]["launch_started_utc"] = report["launchUtc"]
        elif damage == "missing-start": report["commands"][0].pop("utc")
        raw = json.dumps(report).encode()
        if damage == "duplicate-json": raw = b'{"bootId":"duplicate",' + raw[1:]
        arguments["saved_launch_report"] = raw
        arguments["window_authorization"]["launch_session_sha256"] = peer.sha(raw)
    with pytest.raises(ValueError):
        stage.qualified_host_source(**arguments)
    sender.assert_not_called()


def test_counterfactual_role_adapter_returns_only_native_disabled_dual_role_source(installer, monkeypatch):
    arguments, plan, session, launch = inputs(installer)
    check = Mock()
    monkeypatch.setattr(peer, "validate_qualification", check)
    monkeypatch.setattr(peer, "_render", Mock(side_effect=AssertionError("legacy combined-su renderer reached")))
    real = content.review_content_host_source
    rendered = []

    def inert_source(actual_plan, actual_session, launched):
        assert actual_plan == plan and actual_session == session and launched == launch
        steps = stage.execution_steps(plan, dict(session.context), session=session)
        source = native_fixture_source(real(actual_plan, actual_session, launched), steps, session,
                                       fault="none", epoch=int(launched.timestamp()))
        assert "DllImport(" not in source and "extern " not in source
        source = source.replace("ContentQualified = true", "ContentQualified = false")
        rendered.append(source)
        return source
    monkeypatch.setattr(content, "review_content_host_source", inert_source)
    result = stage.qualified_host_source(**arguments)
    assert len(rendered) == 1 and check.call_count >= 2
    assert all(call.kwargs == {"for_publication": True} for call in check.call_args_list)
    assert result["candidate_sha256"] == plan.candidate_sha256 and result["plan_sha256"] == plan.plan_sha256
    assert result["execution_sha256"] == session.binding_sha256 and result["session_data_sha256"] == session.data_sha256
    assert result["launch_started_utc"] == launch.isoformat()
    assert result["launch_report_sha256"] == peer.sha(arguments["saved_launch_report"])
    assert set(result["sources"]) == {"X2d2MenuStage.cs"}
    source = result["sources"]["X2d2MenuStage.cs"]
    assert "DllImport(" not in source and "extern " not in source
    assert "ContentQualified = true" in source
    assert "X2DII_CONTENT_NEED:" in source and "RequireMaintenanceSupervision" not in source
    assert result["entry_point"] == result["namespace"] + ".AdbUsbCheck.RunContentStage"
    assert result["source_sha256"] == peer.sha(source.encode())
    assert "ContentDeadlineEpoch = " + str(int(launch.timestamp()) + 60) + ";" in source
    assert result["camera_accesses"] == 0 and not result["installation_executed"]
    assert result["session_data_uploaded"] is False


@pytest.mark.parametrize("late_at", (None, "entry", "render", "second-qualification"))
def test_fixed_candidate_content_budget_rejects_unavoidable_maintenance_gap_overrun(installer, monkeypatch, late_at):
    """Current 50-command candidate, not a fabricated smaller synthetic plan.

    Qualification is deliberately counterfactual and the renderer returns only
    an inert string. No source compilation, native interface or device runs.
    """
    arguments, plan, session, launch = inputs(installer)
    assert plan.candidate_sha256 == peer.inventory()["candidate_sha256"]
    # Independent frozen tarfile oracle: 66075 gzip bytes become 88100
    # base64 bytes, requiring 44 chunks plus six fixed phases. Pin the actual
    # command payload too, not a separate output of the same generator.
    assert tuple(step.label for step in plan.steps) == (
        "create-private-stage", "begin-fixed-compressed-content",
        *(f"compressed-chunk-{offset}" for offset in range(0, 88100, 2048)),
        "decode-fixed-compressed-content", "inflate-fixed-content",
        "extract-normalize-fixed-content", "verify-all-members")
    assert peer.sha(json.dumps([step.__dict__ for step in plan.steps],
        sort_keys=True, separators=(",", ":")).encode("ascii")) == (
        "3fea9c44674388a3f1a5a49fdb095971b45fcac6a8ffce0f050b79c021a71c3c")
    parts = [re.findall(r"printf %s '([A-Za-z0-9+/=]+)' >\.content-chunk-", step.command)
             for step in plan.steps[2:-4]]
    assert all(len(matches) == 1 for matches in parts)
    chunks = [matches[0] for matches in parts]
    assert [len(chunk) for chunk in chunks] == [2048] * 43 + [36]
    packed = base64.b64decode("".join(chunks), validate=True)
    assert len(packed) == 66075
    actual_archive_sha = peer.sha(gzip.decompress(packed))
    assert actual_archive_sha == (
        "ad6e564f29dd63487bd1edfd2e9b031bfb7eef43b713aa21392a3af622ff9d97")
    assert arguments["qualification"]["delivery_identity"]["package_sha256"] == actual_archive_sha
    assert len(plan.steps) == 50
    now = [launch + timedelta(seconds=20 if late_at == "entry" else 0)]
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return now[0]
    monkeypatch.setattr(stage, "datetime", Clock)
    checks, rendered = [], []
    def qualification(*args, **kwargs):
        checks.append(kwargs)
        if late_at == "second-qualification" and len(checks) == 2:
            now[0] = launch + timedelta(seconds=20)
    monkeypatch.setattr(peer, "validate_qualification", qualification)
    def inert(plan, session, launch):
        rendered.append(True)
        if late_at == "render": now[0] = launch + timedelta(seconds=20)
        original = int(content.original_window_deadline(session.observed_epoch, launch))
        return ("namespace X2d2ContentStage_0000000000000000 {\n"
                "private static readonly bool ContentQualified = false;\n"
                f"private const long ContentDeadlineEpoch = {original};\n}}\n")
    monkeypatch.setattr(content, "review_content_host_source", inert)
    if late_at is None:
        result = stage.qualified_host_source(**arguments)
        assert result["installation_executed"] is False
        assert result["deadline_utc"] == (launch + timedelta(seconds=60)).isoformat()
    else:
        with pytest.raises(ValueError, match="maintenance.*budget|maintenance.*window"):
            stage.qualified_host_source(**arguments)
        assert bool(rendered) == (late_at != "entry")


def test_content_budget_rejects_changed_pinned_cadence_source_without_loading_it(installer, monkeypatch):
    from tools import live_readout
    arguments, _, _, _ = inputs(installer)
    monkeypatch.setattr(peer, "validate_qualification", Mock())
    sender = Mock(side_effect=AssertionError("changed timing source reached source renderer"))
    monkeypatch.setattr(content, "review_content_host_source", sender)
    original = type(live_readout.TRANSPORT).read_bytes
    def changed(path):
        raw = original(path)
        return raw + b"\n# timing producer changed\n" if path == live_readout.TRANSPORT else raw
    monkeypatch.setattr(type(live_readout.TRANSPORT), "read_bytes", changed)
    monkeypatch.setattr(live_readout, "load_transport", Mock(side_effect=AssertionError("timing check loaded transport")))
    with pytest.raises(ValueError, match="transport.*changed|cadence.*changed"):
        stage.qualified_host_source(**arguments)
    sender.assert_not_called()


@pytest.mark.parametrize("commands", (1, 49, 50))
@pytest.mark.parametrize("position", ("inside", "equal", "fractional"))
def test_maintenance_budget_keeps_existing_floor_and_actual_integer_sender_deadline(commands, position):
    # Generated native constants truncate the absolute deadline to seconds.
    # Fractional authorization time cannot give the native sender extra time.
    deadline = datetime(2026, 10, 5, tzinfo=timezone.utc).replace(microsecond=800000)
    native = deadline.replace(microsecond=0)
    minimum = max(17, commands - 1 + 2)
    now = (native - timedelta(seconds=minimum+1) if position == "inside" else
           deadline - timedelta(seconds=minimum) if position == "equal" else
           native - timedelta(seconds=minimum) + timedelta(milliseconds=100))
    if position == "inside":
        stage._require_maintenance_budget(deadline, now=now, remaining_commands=commands)
    else:
        with pytest.raises(ValueError, match="maintenance.*budget"):
            stage._require_maintenance_budget(deadline, now=now, remaining_commands=commands)
