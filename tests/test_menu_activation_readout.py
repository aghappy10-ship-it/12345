"""Post-placement readout at its public boundary; all device I/O is modeled.

The non-fixture parser branch is exercised with counterfactual data, not a
camera result or consent. No connection is created and nothing is installed.
"""
from copy import deepcopy
import json

import pytest

from tests.test_release_lifecycle import installer
from tests.test_menu_observation_readout import complete_case, EPOCH
from tools import menu_observation_readout as readout, session_context


def placed_case(manifest):
    model, evidence = complete_case(manifest, synthetic=False)
    identities = tuple(f"7:{200 + index}:81a4:1:{entry['bytes']}:0:0"
                       for index, entry in enumerate(manifest["candidate"]["files"]))
    identity_by_path = dict(zip((entry["target"] for entry in manifest["candidate"]["files"]), identities))
    for entry in manifest["candidate"]["files"]:
        model.files[entry["target"]] = (entry["sha256"], entry["bytes"])
    original = model.command

    def command(label, query):
        if query.startswith("stat -c '%d:%i:%f:%h:%s:%u:%g' "):
            model.calls.append((label, query))
            return identity_by_path[query.split()[-1]] + "\n"
        if query.startswith("[ -f ") and " ] && [ ! -L " in query:
            model.calls.append((label, query))
            return ""
        if query.startswith("[ ! -e ") and query.split()[3] in identity_by_path:
            raise ValueError("target already exists")
        return original(label, query)

    model.command = command
    return model, evidence, identities


def test_post_placement_readout_produces_fresh_install_data_without_requiring_absent_files(installer):
    model, evidence, identities = placed_case(installer.manifest)
    result = readout.collect_boot_activation_observation(installer.manifest, model,
        payload_identities=identities, external_evidence=evidence,
        collection_scope="menu-boot-activation-readonly", clock=lambda: EPOCH)
    assert result["errors"] == [] and result["missing"] == []
    assert result["status"] == "COMPLETE_CONTEXT_DATA_NOT_QUALIFICATION"
    assert not result["installable"] and not result["feature_validated"]
    values = session_context.decode_session(result["raw_session"])
    assert values["kind"] == "install"
    assert result["raw_session"].startswith(b"schema=x2dii-session-context-v2\n")
    assert values["observed_epoch"] == EPOCH - 5
    q = json.loads(result["raw_observation"])
    assert q["metadata"]["/system/etc/X2d2MenuPage.qml"]["mode"] == "644"
    assert result["deployment_constraints"]["kind"] == "OBSERVED_PLACED_FILE_METADATA_NOT_WRITE_AUTHORITY"
    for identity in identities:
        assert sum(row.get("stdout") == identity + "\n" for row in result["queries"]) == 2


@pytest.mark.parametrize("fault", ("content", "second-identity", "label", "read-error", "changed-rc"))
def test_activation_observation_refuses_changed_or_unreadable_placed_files(installer, fault):
    model, evidence, identities = placed_case(installer.manifest)
    target = installer.manifest["candidate"]["files"][0]["target"]
    if fault == "content":
        model.files[target] = ("0" * 64, model.files[target][1])
    elif fault == "changed-rc":
        model.files[readout.RC] = (installer.manifest["candidate"]["rc"]["after"], model.files[readout.RC][1])
    original = model.command

    def command(label, query):
        if fault == "second-identity" and "after-placed-0-identity" in label:
            return identities[0].replace(":200:", ":999:") + "\n"
        if fault == "label" and "placed-0-label" in label:
            return "u:object_r:wrong_file:s0 " + target + "\n"
        if fault == "read-error" and "placed-0-identity" in label:
            raise OSError("counterfactual transport loss")
        return original(label, query)

    model.command = command
    result = readout.collect_boot_activation_observation(installer.manifest, model,
        payload_identities=identities, external_evidence=evidence,
        collection_scope="menu-boot-activation-readonly", clock=lambda: EPOCH)
    assert result["raw_session"] is None and result["raw_observation"] is None
    assert result["errors"] and "complete_successful_collection" in result["missing"]
    assert not result["installable"]


def test_first_menu_observation_still_requires_absence_after_adding_boot_collector(installer):
    model, evidence, _ = placed_case(installer.manifest)
    result = readout.collect_menu_observation(installer.manifest, model, external_evidence=evidence,
        collection_scope="menu-first-validation-readonly", clock=lambda: EPOCH)
    assert result["raw_session"] is None and "target already exists" in result["errors"]


@pytest.mark.parametrize("fault", ("scope", "ownership"))
def test_activation_observation_rejects_invalid_request_before_using_session(installer, fault):
    model, evidence, identities = placed_case(installer.manifest)
    with pytest.raises(ValueError):
        readout.collect_boot_activation_observation(installer.manifest, model,
            payload_identities=identities if fault == "scope" else ("unbound",) * 4,
            external_evidence=evidence, collection_scope="install" if fault == "scope" else "menu-boot-activation-readonly",
            clock=lambda: EPOCH)
    assert model.calls == []


def test_activation_observation_cannot_complete_with_wrong_maintenance_process_role(installer):
    model, evidence, identities = placed_case(installer.manifest)
    original = model.command

    def wrong_role(label, query):
        if query == "cat /proc/101/attr/current":
            return "u:r:su:s0\0"
        return original(label, query)

    model.command = wrong_role
    result = readout.collect_boot_activation_observation(installer.manifest, model,
        payload_identities=identities, external_evidence=evidence,
        collection_scope="menu-boot-activation-readonly", clock=lambda: EPOCH)
    assert result["raw_session"] is None
    assert result["status"] == "PARTIAL_MENU_CONTEXT_NOT_QUALIFICATION"
    assert result["errors"] and "valid_saved_menu_session" in result["missing"]
