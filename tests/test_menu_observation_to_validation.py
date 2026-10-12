"""Collected context reaches the public first-validation admission.

Only shell, filesystem and clock edges are modeled. No approval or report is
published, no native child is allowed, and no model is camera qualification.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from unittest import mock

import pytest

from tests.test_release_lifecycle import installer
from tests.test_menu_first_validation_admission import counterfactual
from tests.test_menu_observation_readout import complete_case, EPOCH
from tools import menu_first_validation as validation
from tools import menu_observation_readout as readout
from tools import prepare_peer_install as peer


@pytest.mark.parametrize("fault", (None, "synthetic", "changed_saved_readout"))
def test_collected_context_enters_public_admission_only_with_exact_nonfixture_sources(counterfactual, fault):
    case = counterfactual
    synthetic = fault == "synthetic"
    session, supplied = complete_case(case["manifest"], synthetic=synthetic)
    collected = readout.collect_menu_observation(
        case["manifest"], session, external_evidence=supplied,
        collection_scope=("synthetic-" if synthetic else "") + "menu-first-validation-readonly",
        clock=lambda: EPOCH,
    )
    assert collected["missing"] == [] and collected["errors"] == []
    assert not collected["installable"] and not collected["feature_validated"]
    observed = json.loads(collected["raw_observation"])
    case["now"][0] = datetime.fromtimestamp(EPOCH, timezone.utc)
    approval = deepcopy(case["approval"])
    approval.update(
        boot_id=observed["boot_id"],
        approved_utc=(case["now"][0] - timedelta(seconds=10)).isoformat(),
        expires_utc=(case["now"][0] + timedelta(seconds=1000)).isoformat(),
    )
    approval["record"] = case["save"](
        "joined-approval.json", {key: value for key, value in approval.items() if key != "record"},
    )
    # Retain the actual adapter outputs and independent source bytes at the
    # filesystem edge; do not replace an internal assembler or identity check.
    evidence = case["save"]("joined-readout.json", {
        "queries": collected["queries"],
        "external_sources": collected["external_sources"],
        "deployment_constraints": collected["deployment_constraints"],
        "derived_sources": collected.get("derived_sources", []),
        "status": collected["status"],
    })
    references = [evidence]
    for source in collected["external_sources"].values():
        case["docs"][peer.ROOT / source["evidence_file"]] = source["raw_utf8"].encode("utf-8")
        references.append({key: source[key] for key in ("evidence_file", "evidence_sha256")})
    args = case["inputs"](observed)
    args.update(saved_observation=collected["raw_observation"],
                saved_observation_sha256=collected["raw_observation_sha256"],
                observation_sources=references)
    args["prerequisites"].update(saved_observation_sha256=collected["raw_observation_sha256"],
                                  observation_sources=references)
    if fault == "changed_saved_readout":
        case["docs"][peer.ROOT / evidence["evidence_file"]] += b"changed"
    with mock.patch("tools.menu_host_process.subprocess.Popen",
                    side_effect=AssertionError("admission must not launch a native child")):
        if fault is not None:
            with pytest.raises(ValueError):
                validation.prepare_first_validation(case["manifest"], case["plan"], approval=approval, **args)
        else:
            result = validation.prepare_first_validation(case["manifest"], case["plan"], approval=approval, **args)
            assert result.phase == "content"
