"""Real collectors feed public boot/recovery entries over external I/O models.

All camera replies, human decisions and qualification reports are explicitly
counterfactual in-memory test data. No device or native API is used here.
"""
import json
from datetime import timedelta

from tests.test_menu_boot_acceptance import (
    boot_input, admission_inputs, public_run,
)
from tests.test_menu_first_validation_admission import counterfactual
from tests.test_release_lifecycle import installer
from tests.test_menu_activation_readout import placed_case
from tests.test_menu_recovery_readout import RecoverySession
from tests.test_menu_observation_readout import complete_case
from tools import menu_observation_readout, menu_recovery_readout
from tools import prepare_peer_install as peer, release_identity


def current_external_sources(c, evidence):
    """Model current external records and retain their exact bytes in test FS."""
    for record in evidence.values():
        value = json.loads(record["raw_utf8"])
        value["boot_id"] = c["q"]["boot_id"]
        record["raw_utf8"] = json.dumps(value, sort_keys=True, separators=(",", ":"))
        record["evidence_sha256"] = peer.sha(record["raw_utf8"].encode())
        record["observed_utc"] = c["now"][0].isoformat()
        c["docs"][peer.ROOT / record["evidence_file"]] = record["raw_utf8"].encode()


def collected_inputs(c, args, result, name):
    assert result["errors"] == [] and result["missing"] == [], result
    assert result["raw_session"] is not None and result["installable"] is False
    # The readout is saved as received. Never regenerate its observation or
    # manufacture fields between the collector and its public consumer.
    sources = [c["save"](name, {
        "queries": result["queries"], "external_sources": result["external_sources"],
    })]
    args.update(saved_observation=result["raw_observation"],
        saved_observation_sha256=result["raw_observation_sha256"], observation_sources=sources)
    args["prerequisites"].update(saved_observation_sha256=result["raw_observation_sha256"],
        observation_sources=sources)
    return args


def test_collected_placed_observation_is_consumed_unchanged_by_public_boot_entry(boot_input):
    c, module, original_args = boot_input
    placement = json.loads(c["docs"][peer.ROOT / original_args["placement_receipt"]["evidence_file"]])
    model, evidence, _ = placed_case(c["manifest"])
    current_external_sources(c, evidence)
    identities = dict(zip((f["target"] for f in c["manifest"]["candidate"]["files"]),
        placement["completed_identities"]))
    answer = model.command

    def current_reply(label, command):
        if command == "date -u +%s":
            return str(int(c["now"][0].timestamp())) + "\n"
        if command == "cat /proc/sys/kernel/random/boot_id":
            return c["q"]["boot_id"] + "\n"
        if command.startswith("stat -c '%d:%i:%f:%h:%s:%u:%g' "):
            return identities[command.split()[-1]] + "\n"
        return answer(label, command)

    model.command = current_reply
    result = menu_observation_readout.collect_boot_activation_observation(c["manifest"], model,
        payload_identities=tuple(placement["completed_identities"]), external_evidence=evidence,
        collection_scope="menu-boot-activation-readonly", clock=lambda: c["now"][0].timestamp())
    assert result["raw_observation"] is not None, result
    c["q"] = json.loads(result["raw_observation"])
    args = collected_inputs(c, admission_inputs(c, module, placement), result, "collected-activation.json")
    operation = module.prepare_boot_validation(c["manifest"], c["plan"], **args)
    assert operation.raw_session == result["raw_session"]
    assert operation.snapshot()["activation_receipt"] is None
    assert operation.snapshot()["installable"] is False


def test_collected_recovery_with_absent_gui_and_payloads_reaches_public_restore_entry(boot_input):
    c, module, args = boot_input
    activated = module.prepare_boot_validation(c["manifest"], c["plan"], **args)
    activated.bind_saved_intent(c["save"]("collected-recovery-intent.json", activated.snapshot()))
    public_run(c, activated)
    snapshot = activated.snapshot()
    saved = c["save"]("collected-recovery-snapshot.json", snapshot)
    c["now"][0] += timedelta(seconds=1100)  # Activation approval is already expired.
    manifest = snapshot["manifest"]
    model = RecoverySession(manifest)
    model.backup_identity = snapshot["activation_receipt"]["backup_identity"]
    model.identities[model.backup] = model.backup_identity
    del model.processes[201]
    for f in manifest["candidate"]["files"]:
        del model.files[f["target"]]
    _, evidence = complete_case(manifest, synthetic=False)
    evidence.pop("capture_route")
    current_external_sources(c, evidence)
    answer = model.answer

    def current_reply(label, command):
        if command == "date -u +%s":
            return str(int(c["now"][0].timestamp())) + "\n"
        if command == "cat /proc/sys/kernel/random/boot_id":
            return c["q"]["boot_id"] + "\n"
        return answer(label, command)

    model.answer = current_reply
    manifest_raw = json.dumps(manifest, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    result = menu_recovery_readout.collect_menu_recovery_observation(manifest_raw,
        snapshot["manifest_sha256"], model, backup_identity=model.backup_identity,
        external_evidence=evidence, collection_scope="menu-recovery-readonly",
        clock=lambda: c["now"][0].timestamp())
    inputs = collected_inputs(c, {"acceptance_snapshot": saved, "prerequisites": {"gates": {}}},
        result, "collected-recovery.json")
    q = json.loads(result["raw_observation"])
    assert q["gui"] == {"state": "absent", "service_state": "stopped"}
    assert not any(q["payload_presence"].values())
    identity = module._recovery_bindings(snapshot, saved, q)
    for gate, phases in module.BOOT_RECOVERY_GATES.items():
        inputs["prerequisites"]["gates"][gate] = {}
        for phase in phases:
            bound = release_identity.gate_bindings(phase, **identity)
            proof = {**bound, "result": "PASS", "synthetic": False, "test_fixture_only": False, "gate": gate}
            ref = c["save"]("collected-recovery-" + gate + "-" + phase + ".json", proof)
            inputs["prerequisites"]["gates"][gate][phase] = {**bound, "status": "PASS", **ref}
    operation = module.prepare_boot_validation_recovery(**inputs)
    assert operation.raw_session == result["raw_session"]
    restored, _ = public_run(c, operation)
    assert restored["status"] == "OFFICIAL_RC_RESTORED_AWAITING_EXTERNAL_NEW_BOOT"
    assert restored["installable"] is False
