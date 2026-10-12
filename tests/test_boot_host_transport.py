"""Run the fixed boot sender at its native boundary, without a USB device."""
from datetime import datetime, timezone
import base64
import re
import subprocess

import pytest

from tests.test_release_lifecycle import installer
from tests.test_menu_maintenance_boundary import context
from tests.test_menu_boot_file import recovery_data
from tests.menu_transport_wire_fixture import packet, step, run_wire
from tools import menu_boot_transport as transport, menu_boot_boundary as boundary
from tools import menu_maintenance_boundary as placement_boundary, prepare_peer_install as peer, session_context


def boot_case(installer, *, action="activate", already_original=False, host_fault=None, stream_fault=None):
    # Establish the actual fixture's maintenance role before independently
    # encoding recovery. This does not relabel an install session.
    install_raw = context(installer, session_kind="install")
    raw = install_raw if action == "activate" else recovery_data(installer)
    if already_original:
        values = session_context.decode_session(raw)
        values["rc_sha256"] = installer.manifest["candidate"]["rc"]["before"]
        raw = session_context.encode_session(values)
    values = session_context.decode_session(raw)
    epoch = values["observed_epoch"]
    identities = tuple(f"1:{2+i}:81a4:1:{entry['bytes']}:0:0"
                       for i, entry in enumerate(installer.manifest["candidate"]["files"]))
    original_bytes = len(peer.boot.STOCK.read_bytes())
    backup = f"1:9:81a4:1:{original_bytes}:0:0"
    options = {"action": action, "payload_identities": identities if action == "activate" else None,
               "backup_identity": backup if action == "restore" else None}
    coordinator = transport.BootCoordinator(installer.manifest, raw, **options)
    source = transport.review_boot_host_source(installer.manifest, raw,
        launch_started_utc=datetime.fromtimestamp(epoch, timezone.utc), **options)
    identity_command = ("printf 'UID=';id -u;printf '\nDOMAIN=';cat /proc/self/attr/current;"
                        "printf '\nUSB_CONFIG=';getprop sys.usb.config;printf 'USB_STATE=';getprop sys.usb.state;"
                        "printf 'ADBD=';getprop init.svc.adbd;printf 'X2DII_ADB_READONLY_DONE\n'")
    identity = (b"UID=0\nDOMAIN=u:r:su:s0\nUSB_CONFIG=rndis,mass_storage,bulk,acm,adb\n"
                b"USB_STATE=rndis,mass_storage,bulk,acm,adb\nADBD=running\nX2DII_ADB_READONLY_DONE\n")
    greeting = packet("CNXN", 0x01000000, 4096, b"host::\0")
    peer_greeting = packet("CNXN", 0x01000000, 4096, b"device::\0")
    okay, close = packet("OKAY", 1, 7), packet("CLSE", 1, 7)
    scripts = ["\n".join((step(greeting, peer_greeting),
        step(packet("OPEN", 1, 0, ("shell:" + identity_command + "\0").encode()),
             packet("OKAY", 7, 1) + packet("WRTE", 7, 1, identity)),
        step(okay, packet("CLSE", 7, 1)), step(close))) ]
    request_lines, acknowledgements, host_lines, responses = [], [], [], {}
    for index in range(coordinator.first_boundary, len(boundary.stages(action))):
        challenge = peer.sha(f"{values['boot_id']}:{values['session_nonce']}:{action}:{index}:{coordinator.program_sha256}\n".encode())
        request = boundary.make_request(installer.manifest, raw, action=action,
            worker_session_sha256=peer.sha(raw), worker_program_sha256=coordinator.program_sha256,
            boundary_index=index, challenge=challenge, issued_epoch=epoch)
        digest = peer.sha(request)
        command = coordinator.begin_boundary(f"X2DII_HOST_BOOT_BOUNDARY:{action}:{index}:{digest}")
        response = request.replace(boundary.REQUEST_SCHEMA.encode(), boundary.RESPONSE_SCHEMA.encode(), 1)
        response += (f"request_sha256={digest}\nstarted_epoch={epoch}\nchecked_epoch={epoch}\n"
                     "result=OBSERVED_MATCH\nscope=ONE_BOUNDARY_ONLY_NOT_AUTHORIZATION\n").encode()
        responses[command] = response.decode()
        ack = coordinator.accept_reply(response, received_epoch=epoch)
        acknowledgements.append(ack)
        host_lines.append("boundary|" + ack.decode().rstrip("\n"))
        request_lines.append(f"X2DII_BOOT_BOUNDARY_REQUEST:{action}:{index}:{digest}\r\n".encode())
    result_hash = installer.manifest["candidate"]["rc"]["after" if action == "activate" else "before"]
    result_size = len(peer.boot.activate(peer.boot.STOCK.read_bytes())) if action == "activate" else original_bytes
    marker = f"X2DII_BOOT_WORKER_{peer.sha(raw)[:24]}_{action}_RC="
    receipt = ("schema=x2dii-rc-file-transaction-v1\n"
        f"action={action}\ncandidate_sha256={installer.manifest['candidate_sha256']}\n"
        f"session_data_sha256={peer.sha(raw)}\nsession_nonce={values['session_nonce']}\n"
        f"backup_identity={backup}\nidentity=1:10:81a4:1:{result_size}:0:0\nsha256={result_hash}\n"
        "maintenance_boundaries=HOST_MEDIATED_FIXED_BOOT_MATCHED\n"
        "X2DII_RC_FILE_COMMITTED_NOT_LIFECYCLE_VALIDATED\n\n" + marker + "0\n").replace("\n", "\r\n").encode()
    output = b"".join(request_lines) + receipt
    final_ack = coordinator.finish(decoded_output=output.replace(b"\r\n", b"\n"), stream_completed=True)
    host_lines.append("file|" + final_ack.decode().rstrip("\n"))
    if stream_fault == "failed-status":
        receipt = receipt.replace((marker + "0").encode(), (marker + "81").encode())
    path = "/blackbox/x2dii-menu-stage/" + installer.manifest["candidate_sha256"][:24] + f"/{action}-boot.sh"
    dependency = peer.sha(coordinator.payload_data) if action == "activate" else backup
    command = (f'set -eu; x=$(sha256sum {path}); [ "${{x%% *}}" = {coordinator.program_sha256} ]; '
               f'sh {path} {placement_boundary.session_path(installer.manifest, peer.sha(raw))} {peer.sha(raw)} {dependency}')
    wire = f'({command}); r=$?; printf \'\\n{marker}%s\\n\' "$r"'
    steps = [step(greeting, peer_greeting),
             step(packet("OPEN", 1, 0, ("shell:" + wire + "\0").encode()),
                  packet("OKAY", 7, 1) + packet("WRTE", 7, 1, request_lines[0][:13]))]
    for offset, line in enumerate(request_lines):
        steps += [step(okay, packet("WRTE", 7, 1, line[13:])), step(okay)]
        next_chunk = request_lines[offset + 1][:13] if offset + 1 < len(request_lines) else receipt[:109]
        steps.append(step(packet("WRTE", 1, 7, acknowledgements[offset]),
                          packet("OKAY", 7, 1) + packet("WRTE", 7, 1, next_chunk)))
    steps += [step(okay, packet("WRTE", 7, 1, receipt[109:])),
              step(okay, packet("CLSE", 7, 1)), step(close)]
    scripts.append("\n".join(steps))
    if host_fault:
        if host_fault == "boundary":
            host_lines[0] = "boundary|X2DII_INVALID_ACK"
        elif host_fault == "final":
            host_lines[-1] = "file|X2DII_INVALID_ACK"
    return source, epoch, scripts, host_lines, output, raw, options, responses


@pytest.mark.parametrize("action,already_original", (("activate", False), ("restore", False), ("restore", True)))
def test_native_boot_sender_completes_only_fixed_action_after_all_current_replies(installer, tmp_path, action, already_original):
    source, epoch, scripts, host_lines, output, *_ = boot_case(installer, action=action, already_original=already_original)
    result = run_wire(source, epoch, scripts, host_lines, tmp_path)
    assert result["Error"] is None, result
    assert result["Opens"] == 2 and result["RemainingSteps"] == 0
    assert result["HostReads"] == (3 if already_original else 13 if action == "activate" else 9)
    assert result["Result"] == "X2DII_BOOT_FILE_TRANSACTION_NOT_LIFECYCLE_VALIDATION"
    lines = result["Output"].splitlines()
    chunks = [base64.b64decode(line.split(":", 2)[2]) for line in lines
              if line.startswith(f"X2DII_BOOT_WORKER_OUTPUT:{action}:")]
    assert b"".join(chunks) == output
    assert len([line for line in lines if line.startswith("X2DII_HOST_BOOT_COMPLETE:")]) == 1


@pytest.mark.parametrize("host_fault,stream_fault,error", (("boundary", None, "MENU_BOUNDARY_ACK"),
    ("final", None, "MENU_FILE_ACK_MISMATCH"), (None, "failed-status", "MENU_WORKER_STATUS")))
def test_boot_sender_rejects_wrong_host_ack_and_unsuccessful_commit(installer, tmp_path, host_fault, stream_fault, error):
    source, epoch, scripts, host_lines, *_ = boot_case(installer, host_fault=host_fault, stream_fault=stream_fault)
    result = run_wire(source, epoch, scripts, host_lines, tmp_path)
    assert result["Error"] == error, result
    assert result["Result"] is None


def test_boot_source_is_unqualified_and_retains_original_90_second_window(installer, tmp_path):
    source, epoch, scripts, host_lines, *_ = boot_case(installer)
    namespace = re.search(r"namespace (X2d2MenuBoot_[a-f0-9]+)", source)[1]
    file = tmp_path / "boot-unqualified.cs"
    file.write_text(source, encoding="utf-8")
    command = f"""
$ErrorActionPreference='Stop'
Add-Type -Path '{str(file).replace("'", "''")}'
try {{ [{namespace}.AdbUsbCheck]::RunBoot(); throw 'unexpected execution' }}
catch {{ $e=$_.Exception; while($e.InnerException){{$e=$e.InnerException}}
 if($e.Code -ne 'MENU_SUPERVISION_NOT_QUALIFIED'){{throw}} }}
"""
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    expired = run_wire(source, epoch + 81, scripts, host_lines, tmp_path)
    assert expired["Error"] == "MENU_SUPERVISION_DEADLINE" and expired["Opens"] == 0


@pytest.mark.parametrize("action,already_original", (("activate", False), ("restore", False), ("restore", True)))
@pytest.mark.parametrize("failure", (None, "maintenance", "cleanup"))
def test_real_child_boot_dialogue_preserves_recovery_receipt_and_errors(
        installer, tmp_path, action, already_original, failure):
    from tests.test_preplacement_host_dialogue import interactive_process
    source, epoch, scripts, _, output, raw, options, responses = boot_case(
        installer, action=action, already_original=already_original)
    calls = []

    class Maintenance:
        def command(self, label, command):
            assert command in responses
            calls.append(command)
            if failure == "maintenance" and len(calls) == 2:
                raise ValueError("INJECTED_BOOT_MAINTENANCE_FAILURE")
            return responses[command]

    process = interactive_process(source, epoch, scripts, tmp_path)
    if failure == "cleanup":
        class CloseFailure:
            def __init__(self, stream):
                self.stream = stream

            def __getattr__(self, name):
                return getattr(self.stream, name)

            def close(self):
                self.stream.close()
                raise OSError("INJECTED_BOOT_HOST_CLOSE_FAILURE")

        process.stdin = CloseFailure(process.stdin)
    try:
        if failure:
            message = "INJECTED_BOOT_MAINTENANCE_FAILURE" if failure == "maintenance" else "host cleanup failed"
            with pytest.raises(ValueError, match=message) as caught:
                transport.drive_boot_process(process, installer.manifest, raw, Maintenance(), clock=lambda: epoch, **options)
            evidence = caught.value.partial_evidence
            assert evidence["candidate_sha256"] == installer.manifest["candidate_sha256"]
            assert evidence["session_data_sha256"] == peer.sha(raw)
            assert evidence["action"] == action
            assert b"X2DII_BOOT_BOUNDARY_REQUEST:" in evidence["worker_outputs"][0]
            if failure == "cleanup":
                assert evidence["completed_receipt"]["backup_identity"].startswith("1:9:81a4:1:")
                assert any("INJECTED_BOOT_HOST_CLOSE_FAILURE" in row["error"] for row in evidence["cleanup_errors"])
            else:
                assert evidence["completed_receipt"] is None and len(calls) == 2
        else:
            result = transport.drive_boot_process(process, installer.manifest, raw, Maintenance(), clock=lambda: epoch, **options)
            assert result["status"] == "BOOT_FILE_TRANSACTION_NOT_LIFECYCLE_VALIDATED"
            assert result["completed_receipt"]["action"] == action
            assert result["completed_receipt"]["backup_identity"].startswith("1:9:81a4:1:")
            assert result["worker_outputs"] == (output,)
            assert len(calls) == len(responses)
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=10)
