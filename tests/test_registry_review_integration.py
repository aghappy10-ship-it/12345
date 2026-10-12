"""Accepted classifications preserve history and never establish PASS."""
from copy import deepcopy

import pytest

from tools import regression_manifest as registry


def test_inventory_exposes_reviewed_counts_without_replacing_original_seed():
    source = registry.SOURCE_PATH.read_bytes()
    manifest = registry.build_manifest(source)
    seed = registry.initial_applicability(manifest["goals"])
    assert manifest["applicability"] == seed
    assert "applicability_review" in manifest
    effective = registry.effective_applicability(manifest)
    assert sum(row["applicability"] == "PENDING_REVIEW" for row in seed.values()) == 289
    result = registry.validate_manifest(manifest, source)
    assert result["seed_applicability_counts"]["PENDING_REVIEW"] == 289
    assert result["applicability_counts"]["PENDING_REVIEW"] == 0
    assert result["applicability_counts"]["APPLICABLE"] == 146 + len(registry.NEW_GOALS)
    assert result["applicability_counts"]["OUT_OF_SCOPE"] == 206
    assert len(result["release_blockers"]) == 146 + len(registry.NEW_GOALS)
    assert all(row["evidence_status"] == "NOT_RUN" and row["counts_as_pass"] is False
               and row["evidence_refs"] == [] for row in effective.values())
    assert result["pass_count"] == 0 and result["installable"] is False
    assert result["machine_evidence_gaps"]
    assert manifest["applicability_review"]["implementation_reviewed"] is False
    effective["X2D-RG-111"]["scope_reason"] = "caller change"
    assert registry.effective_applicability(manifest)["X2D-RG-111"]["scope_reason"] != "caller change"


@pytest.mark.parametrize("field,value", (("counts_as_pass", True), ("installable", True),
                                        ("changed_ids", []), ("effective_rows_sha256", "0" * 64)))
def test_manifest_cannot_rewrite_accepted_review_or_infer_evidence(field, value):
    source = registry.SOURCE_PATH.read_bytes()
    manifest = registry.build_manifest(source)
    assert "applicability_review" in manifest
    manifest["applicability_review"][field] = value
    before = deepcopy(manifest)
    with pytest.raises(registry.RegistryError, match="review"):
        registry.validate_manifest(manifest, source)
    assert manifest == before


@pytest.mark.parametrize("damage", ("exclude_new_goal", "invent_pass", "weaken_new_goal"))
def test_effective_api_itself_rejects_self_reclassified_later_goals(damage):
    from tools.reviewed_applicability import reviewed_overlay
    manifest = registry.build_manifest(registry.SOURCE_PATH.read_bytes())
    key = "X2D-RG-399"
    if damage == "exclude_new_goal":
        manifest["applicability"][key]["applicability"] = "OUT_OF_SCOPE"
    elif damage == "invent_pass":
        manifest["applicability"][key].update(evidence_status="PASS", counts_as_pass=True)
    else:
        manifest["goals"][398]["required_evidence"] = []
    # The pure historical overlay deliberately preserves later rows; its hash
    # is not authority for changing the current product's newer requirements.
    manifest["applicability_review"] = reviewed_overlay(manifest["applicability"], manifest["goals"])["review_record"]
    with pytest.raises(registry.RegistryError):
        registry.effective_applicability(manifest)
