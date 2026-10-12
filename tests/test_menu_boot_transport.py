"""Fixed boot dialogue binding; synthetic replies never prove live activation."""
import importlib

import pytest

from tests.test_release_lifecycle import installer
from tests.test_menu_maintenance_boundary import context
from tests.test_menu_boot_file import recovery_data
from tools import menu_boot_boundary as boundary, prepare_peer_install as peer, session_context


@pytest.mark.parametrize("action,already_original", (("activate", False), ("restore", False), ("restore", True)))
def test_boot_coordinator_binds_actual_action_and_requires_every_applicable_reply(installer, action, already_original):
    transport = importlib.import_module("tools.menu_boot_transport")
    install_raw = context(installer, session_kind="install")
    raw = install_raw if action == "activate" else recovery_data(installer)
    if already_original:
        values = session_context.decode_session(raw)
        values["rc_sha256"] = installer.manifest["candidate"]["rc"]["before"]
        raw = session_context.encode_session(values)
    values = session_context.decode_session(raw)
    identities = tuple(f"1:{2+i}:81a4:1:{entry['bytes']}:0:0"
                       for i, entry in enumerate(installer.manifest["candidate"]["files"]))
    original_bytes = len(peer.boot.STOCK.read_bytes())
    backup = f"1:9:81a4:1:{original_bytes}:0:0"
    coordinator = transport.BootCoordinator(installer.manifest, raw, action=action,
        payload_identities=identities if action == "activate" else None,
        backup_identity=backup if action == "restore" else None)
    first = 6 if already_original else 0
    for index in range(first, len(boundary.stages(action))):
        assert coordinator.next_boundary == index
        challenge = peer.sha(f"{values['boot_id']}:{values['session_nonce']}:{action}:{index}:{coordinator.program_sha256}\n".encode())
        request = boundary.make_request(installer.manifest, raw, action=action,
            worker_session_sha256=peer.sha(raw), worker_program_sha256=coordinator.program_sha256,
            boundary_index=index, challenge=challenge, issued_epoch=values["observed_epoch"])
        request_hash = peer.sha(request)
        command = coordinator.begin_boundary(f"X2DII_HOST_BOOT_BOUNDARY:{action}:{index}:{request_hash}")
        assert command.endswith(f" {action} {index} {request_hash}")
        response = request.replace(boundary.REQUEST_SCHEMA.encode(), boundary.RESPONSE_SCHEMA.encode(), 1)
        response += (f"request_sha256={request_hash}\nstarted_epoch={values['observed_epoch']}\n"
                     f"checked_epoch={values['observed_epoch']}\nresult=OBSERVED_MATCH\n"
                     "scope=ONE_BOUNDARY_ONLY_NOT_AUTHORIZATION\n").encode()
        assert coordinator.accept_reply(response, received_epoch=values["observed_epoch"]) == (
            f"X2DII_BOOT_BOUNDARY_ACK:{request_hash}:{values['observed_epoch']}:{values['observed_epoch']}\n".encode())
    result_hash = installer.manifest["candidate"]["rc"]["after" if action == "activate" else "before"]
    result_size = len(peer.boot.activate(peer.boot.STOCK.read_bytes())) if action == "activate" else original_bytes
    identity = f"1:10:81a4:1:{result_size}:0:0"
    output = ("schema=x2dii-rc-file-transaction-v1\n"
        f"action={action}\ncandidate_sha256={installer.manifest['candidate_sha256']}\n"
        f"session_data_sha256={peer.sha(raw)}\nsession_nonce={values['session_nonce']}\n"
        f"backup_identity={backup}\nidentity={identity}\nsha256={result_hash}\n"
        "maintenance_boundaries=HOST_MEDIATED_FIXED_BOOT_MATCHED\n"
        "X2DII_RC_FILE_COMMITTED_NOT_LIFECYCLE_VALIDATED\n\n"
        f"X2DII_BOOT_WORKER_{peer.sha(raw)[:24]}_{action}_RC=0\n").encode()
    assert coordinator.finish(decoded_output=output, stream_completed=True) == (
        f"X2DII_HOST_BOOT_ACK:{action}:{peer.sha(output)}\n".encode())
    assert coordinator.completed_receipt["backup_identity"] == backup
    assert coordinator.completed_receipt["identity"] == identity
    assert coordinator.next_boundary is None
    with pytest.raises(ValueError):
        coordinator.finish(decoded_output=output, stream_completed=True)


def _complete_reviewed_boot_dialogue(installer, action):
    """Use every public request/reply boundary before probing final receipt state."""
    transport = importlib.import_module("tools.menu_boot_transport")
    install_raw = context(installer, session_kind="install")
    raw = install_raw if action == "activate" else recovery_data(installer)
    values = session_context.decode_session(raw)
    identities = tuple(f"1:{i+2}:81a4:1:{entry['bytes']}:0:0"
                       for i, entry in enumerate(installer.manifest["candidate"]["files"]))
    backup = f"1:9:81a4:1:{len(peer.boot.STOCK.read_bytes())}:0:0"
    coordinator = transport.BootCoordinator(installer.manifest, raw, action=action,
        payload_identities=identities if action == "activate" else None,
        backup_identity=backup if action == "restore" else None)
    for index in range(coordinator.first_boundary, len(boundary.stages(action))):
        challenge = peer.sha(f"{values['boot_id']}:{values['session_nonce']}:{action}:{index}:{coordinator.program_sha256}\n".encode())
        request = boundary.make_request(installer.manifest, raw, action=action,
            worker_session_sha256=peer.sha(raw), worker_program_sha256=coordinator.program_sha256,
            boundary_index=index, challenge=challenge, issued_epoch=values["observed_epoch"])
        request_hash = peer.sha(request)
        coordinator.begin_boundary(f"X2DII_HOST_BOOT_BOUNDARY:{action}:{index}:{request_hash}")
        response = request.replace(boundary.REQUEST_SCHEMA.encode(), boundary.RESPONSE_SCHEMA.encode(), 1)
        response += (f"request_sha256={request_hash}\nstarted_epoch={values['observed_epoch']}\n"
                     f"checked_epoch={values['observed_epoch']}\nresult=OBSERVED_MATCH\n"
                     "scope=ONE_BOUNDARY_ONLY_NOT_AUTHORIZATION\n").encode()
        coordinator.accept_reply(response, received_epoch=values["observed_epoch"])
    after = action == "activate"
    size = len(peer.boot.activate(peer.boot.STOCK.read_bytes())) if after else len(peer.boot.STOCK.read_bytes())
    digest = installer.manifest["candidate"]["rc"]["after" if after else "before"]
    receipt = ("schema=x2dii-rc-file-transaction-v1\n"
        f"action={action}\ncandidate_sha256={installer.manifest['candidate_sha256']}\n"
        f"session_data_sha256={peer.sha(raw)}\nsession_nonce={values['session_nonce']}\n"
        f"backup_identity={backup}\nidentity=1:10:81a4:1:{size}:0:0\nsha256={digest}\n"
        "maintenance_boundaries=HOST_MEDIATED_FIXED_BOOT_MATCHED\n"
        "X2DII_RC_FILE_COMMITTED_NOT_LIFECYCLE_VALIDATED\n\n"
        f"X2DII_BOOT_WORKER_{peer.sha(raw)[:24]}_{action}_RC=0\n").encode()
    return coordinator, receipt


@pytest.mark.parametrize("action", ("activate", "restore"))
@pytest.mark.parametrize("field", (b"backup_identity=", b"\nidentity="))
def test_non_ascii_receipt_latches_failure_and_cannot_be_replaced(installer, action, field):
    coordinator, receipt = _complete_reviewed_boot_dialogue(installer, action)
    malformed = receipt.replace(field, field + b"\xff", 1)
    with pytest.raises(ValueError):
        coordinator.finish(decoded_output=malformed, stream_completed=True)
    assert coordinator.failed, "Malformed identity raised without latching the public coordinator"
    assert coordinator.completed_receipt is None
    with pytest.raises(ValueError):
        coordinator.finish(decoded_output=receipt, stream_completed=True)
    assert coordinator.completed_receipt is None


@pytest.mark.parametrize("action", ("activate", "restore"))
@pytest.mark.parametrize("fault", ("failed-shell", "duplicate-receipt", "changed-candidate", "changed-backup"))
def test_completed_receipt_grammar_error_still_latches_live_coordinator(installer, action, fault):
    coordinator, receipt = _complete_reviewed_boot_dialogue(installer, action)
    if fault == "failed-shell":
        malformed = receipt[:-2] + b"1\n"
    elif fault == "duplicate-receipt":
        malformed = receipt + receipt
    elif fault == "changed-candidate":
        malformed = receipt.replace(installer.manifest["candidate_sha256"].encode(), b"0" * 64)
    else:
        malformed = receipt.replace(b"backup_identity=1:9:", b"backup_identity=invalid:")
    with pytest.raises(ValueError):
        coordinator.finish(decoded_output=malformed, stream_completed=True)
    assert coordinator.failed and coordinator.completed_receipt is None
    with pytest.raises(ValueError):
        coordinator.finish(decoded_output=receipt, stream_completed=True)
    assert coordinator.completed_receipt is None
