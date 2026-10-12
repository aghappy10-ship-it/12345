"""Local classification overlay tests; no historical imports or camera actions."""
from __future__ import annotations

import copy
import hashlib
import importlib
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def saved():
    return json.loads((ROOT / "work/reverse/X2DII_REGRESSION_GATES.json").read_text(encoding="utf-8"))


def test_reviewed_overlay_classifies_only_the_289_pending_historical_rows(saved):
    review = importlib.import_module("tools.reviewed_applicability")
    before = copy.deepcopy(saved)
    result = review.reviewed_overlay(saved["applicability"], saved["goals"])
    rows = result["effective_rows"]
    record = result["review_record"]
    assert saved == before
    assert set(rows) == set(saved["applicability"])
    assert len(record["changed_ids"]) == 289
    assert len(record["preserved_seed_ids"]) == 63
    assert record["inherited_counts"] == {"APPLICABLE": 146, "OUT_OF_SCOPE": 206, "PENDING_REVIEW": 0}
    assert record["counts_as_pass"] is False and record["installable"] is False
    for key, row in saved["applicability"].items():
        if key not in record["changed_ids"]:
            assert rows[key] == row
        else:
            assert row["applicability"] == "PENDING_REVIEW"
            assert {k: v for k, v in rows[key].items() if k not in ("applicability", "scope_reason")} == {
                k: v for k, v in row.items() if k not in ("applicability", "scope_reason")}
            assert rows[key]["evidence_status"] == "NOT_RUN"
            assert rows[key]["counts_as_pass"] is False and rows[key]["evidence_refs"] == []
    assert "RG093" in rows["X2D-RG-066"]["scope_reason"]
    assert "RG118" in rows["X2D-RG-066"]["scope_reason"]
    assert "fresh" in rows["X2D-RG-111"]["scope_reason"]
    rows["X2D-RG-009"]["evidence_refs"].append("caller mutation")
    assert saved == before
    assert review.reviewed_overlay(saved["applicability"], saved["goals"]) == result | {
        "effective_rows": {**result["effective_rows"], "X2D-RG-009": before["applicability"]["X2D-RG-009"]}}


@pytest.mark.parametrize("damage", ["goal", "pending_classification", "seed_reason", "evidence",
                                    "seed_extra_field", "missing_goal", "reordered_goal", "extra_row"])
def test_changed_original_goal_or_complete_seed_fails_closed(saved, damage):
    review = importlib.import_module("tools.reviewed_applicability")
    if damage == "goal":
        saved["goals"][65]["required_behavior"] = "not required"
    elif damage == "pending_classification":
        saved["applicability"]["X2D-RG-066"]["applicability"] = "OUT_OF_SCOPE"
    elif damage == "seed_reason":
        saved["applicability"]["X2D-RG-009"]["scope_reason"] = "replacement seed"
    elif damage == "evidence":
        saved["applicability"]["X2D-RG-111"]["evidence_status"] = "PASS"
    elif damage == "seed_extra_field":
        saved["applicability"]["X2D-RG-009"]["unexpected"] = True
    elif damage == "missing_goal":
        del saved["goals"][100]
    elif damage == "reordered_goal":
        saved["goals"][1], saved["goals"][2] = saved["goals"][2], saved["goals"][1]
    else:
        saved["applicability"]["X2D-RG-999"] = copy.deepcopy(saved["applicability"]["X2D-RG-009"])
    before = copy.deepcopy(saved)
    with pytest.raises(review.ReviewError):
        review.reviewed_overlay(saved["applicability"], saved["goals"])
    assert saved == before


@pytest.mark.parametrize("damage", ["acceptance", "first", "second", "third", "missing", "extra", "swapped"])
def test_exact_report_bytes_and_acceptance_cannot_be_substituted(damage):
    review = importlib.import_module("tools.reviewed_applicability")
    raw = (ROOT / "work/reverse/INHERITED_APPLICABILITY_REVIEW.json").read_bytes()
    source = json.loads(raw)["source_reports"]
    reports = {item["path"]: (ROOT / item["path"]).read_bytes() for item in source}
    if damage == "acceptance":
        raw += b" "
    elif damage in ("first", "second", "third"):
        path = source[("first", "second", "third").index(damage)]["path"]
        reports[path] += b" "
    elif damage == "missing":
        del reports[source[1]["path"]]
    elif damage == "extra":
        reports["unaccepted-report.json"] = b"{}"
    else:
        first, second = source[0]["path"], source[1]["path"]
        reports[first], reports[second] = reports[second], reports[first]
    with pytest.raises(review.ReviewError):
        review.parse_review_bundle(raw, reports)


def test_overlay_is_pure_and_keeps_report_authorship_and_old_source_bindings(saved, monkeypatch):
    review = importlib.import_module("tools.reviewed_applicability")

    def unexpected_read(*args, **kwargs):
        pytest.fail("the pure overlay attempted file I/O")

    monkeypatch.setattr(Path, "read_bytes", unexpected_read)
    monkeypatch.setattr(Path, "read_text", unexpected_read)
    monkeypatch.setattr(Path, "open", unexpected_read)
    result = review.reviewed_overlay(saved["applicability"], saved["goals"])
    record = result["review_record"]
    assert [item["author"] for item in record["source_reviews"]] == [
        "/root/menu_alignment_review", "/root/native_safety_finish", "/root/reboot_recovery_fix"]
    assert all(item["author"] != item["independent_reviewer"] for item in record["source_reviews"])
    assert record["source_reviews"][0]["source_snapshots"]["candidate"]["sha256"] == (
        "7d207d42a8bde0e87fad84f0f4448a2f5c5101e3c00be3fd4c3e1336dd43677b")
    assert record["source_reviews"][0]["reviewed_bindings"]["reviewed_current_registry_sha256"] == (
        "62747739106d11a828cfaa71c21fd5db8251db2185a3a16632be0a108abf44af")
    assert record["implementation_reviewed"] is False
    assert all(item["implementation_reviewed"] is False for item in record["source_reviews"])
    record["source_reviews"][0]["source_snapshots"]["candidate"]["sha256"] = "caller mutation"
    assert review.reviewed_overlay(saved["applicability"], saved["goals"])["review_record"]["source_reviews"][0][
        "source_snapshots"]["candidate"]["sha256"] != "caller mutation"


def test_a_new_goal_is_preserved_and_an_effective_view_cannot_replace_original_seed(saved):
    review = importlib.import_module("tools.reviewed_applicability")
    goal = {"id": f'X2D-RG-{len(saved["goals"]) + 1:03d}', "title": "New independent obligation",
            "origin": "Synthetic later requirement", "required_behavior": "Remain pending",
            "required_evidence": ["Independent evidence still needed"]}
    row = {"applicability": "PENDING_REVIEW", "scope_reason": "Unreviewed later goal",
           "goal_sha256": hashlib.sha256(json.dumps(goal, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
           "requirement_sha256": saved["requirement_sha256"], "evidence_status": "NOT_RUN",
           "counts_as_pass": False, "evidence_refs": [], "new_goal_metadata": {"keep": ["complete"]}}
    saved["goals"].append(goal)
    saved["applicability"][goal["id"]] = copy.deepcopy(row)
    result = review.reviewed_overlay(saved["applicability"], saved["goals"])
    assert result["effective_rows"][goal["id"]] == row
    assert goal["id"] not in result["review_record"]["changed_ids"]
    with pytest.raises(review.ReviewError, match="seed"):
        review.reviewed_overlay(result["effective_rows"], saved["goals"])
