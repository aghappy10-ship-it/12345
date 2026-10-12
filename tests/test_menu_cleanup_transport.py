"""Fixed cleanup sender at native-disabled boundaries; not removal authority."""
from datetime import datetime, timezone
import base64
import importlib
import re
import subprocess

from tests.test_release_lifecycle import installer
from tests.test_menu_owned_cleanup import cleanup_inputs
import pytest

from tools import session_context as sc, prepare_peer_install as peer


def test_cleanup_sender_compiles_and_refuses_before_native_device_access(installer, tmp_path):
    transport = importlib.import_module("tools.menu_cleanup_transport")
    raw, identities, stock, receipt = cleanup_inputs(installer)
    launch = datetime.fromtimestamp(sc.decode_session(raw)["observed_epoch"], timezone.utc)
    source = transport.review_cleanup_host_source(installer.manifest, raw, identities, stock, receipt,
        launch_started_utc=launch)
    namespace = re.search(r"namespace (X2d2MenuCleanup_[a-f0-9]+)", source)[1]
    path = tmp_path / "cleanup-refused.cs"
    path.write_text(source, encoding="utf-8")
    script = f'''
$ErrorActionPreference='Stop'
Add-Type -Path '{path}'
try {{ [{namespace}.AdbUsbCheck]::RunCleanup(); throw 'unexpected execution' }}
catch {{ $e=$_.Exception;while($e.InnerException){{$e=$e.InnerException}};
 if($e.Message -ne 'MENU_SUPERVISION_NOT_QUALIFIED'){{throw}};
 Write-Output 'COMPILED_REFUSED_BEFORE_USB' }}
'''
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, encoding="utf-8", timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "COMPILED_REFUSED_BEFORE_USB"


def cleanup_wire_case(installer):
    from tools import menu_owned_cleanup as cleanup, menu_cleanup_transport as transport
    from tools import menu_maintenance_boundary as files
    from tests.menu_transport_wire_fixture import packet, step
    options = cleanup_inputs(installer)
    raw, identities, stock, restored = options
    context = sc.decode_session(raw)
    epoch, raw_sha = context["observed_epoch"], peer.sha(raw)
    c = cleanup.CleanupCoordinator(installer.manifest, *options)
    source = transport.review_cleanup_host_source(installer.manifest, *options,
        launch_started_utc=datetime.fromtimestamp(epoch, timezone.utc))
    greeting = packet("CNXN", 0x01000000, 4096, b"host::\0")
    reply_greeting = packet("CNXN", 0x01000000, 4096, b"device::\0")
    okay, close = packet("OKAY", 1, 7), packet("CLSE", 1, 7)
    identity_command = ("printf 'UID=';id -u;printf '\nDOMAIN=';cat /proc/self/attr/current;"
        "printf '\nUSB_CONFIG=';getprop sys.usb.config;printf 'USB_STATE=';getprop sys.usb.state;"
        "printf 'ADBD=';getprop init.svc.adbd;printf 'X2DII_ADB_READONLY_DONE\n'")
    identity = (b"UID=0\nDOMAIN=u:r:su:s0\nUSB_CONFIG=rndis,mass_storage,bulk,acm,adb\n"
        b"USB_STATE=rndis,mass_storage,bulk,acm,adb\nADBD=running\nX2DII_ADB_READONLY_DONE\n")
    scripts = ["\n".join((step(greeting, reply_greeting),
        step(packet("OPEN", 1, 0, ("shell:" + identity_command + "\0").encode()),
            packet("OKAY", 7, 1) + packet("WRTE", 7, 1, identity)),
        step(okay, packet("CLSE", 7, 1)), step(close)))]
    host, responses, outputs = [], {}, []
    for file_index in range(4):
        lines, replies = [], []
        for boundary_index in range(4):
            request = c.expected_request(issued_epoch=epoch)
            digest = peer.sha(request)
            command = c.begin_boundary(f"X2DII_HOST_CLEANUP_BOUNDARY:{file_index}:{boundary_index}:{digest}")
            response = cleanup.encode_response(dict(cleanup.decode_request(request), schema=cleanup.RESPONSE_SCHEMA,
                request_sha256=digest, started_epoch=epoch, checked_epoch=epoch,
                result="OBSERVED_MATCH", scope=cleanup.SCOPE))
            responses[command] = response.decode("ascii")
            ack = c.accept_reply(response, received_epoch=epoch)
            replies.append(ack)
            host.append("boundary|" + ack.decode().rstrip("\n"))
            lines.append(f"X2DII_CLEANUP_BOUNDARY_REQUEST:{file_index}:{boundary_index}:{digest}\r\n".encode())
        entry = installer.manifest["candidate"]["files"][file_index]
        marker = f"X2DII_CLEANUP_WORKER_{raw_sha[:24]}_{file_index}_RC="
        receipt = ("schema=x2dii-one-file-cleanup-v1\n"
            f"candidate_sha256={installer.manifest['candidate_sha256']}\nsession_data_sha256={raw_sha}\n"
            f"session_nonce={context['session_nonce']}\nfile_index={file_index}\n"
            f"original_identity={identities[file_index]}\nsha256={entry['sha256']}\n"
            "maintenance_boundaries=HOST_MEDIATED_FOUR_CLEANUP_MATCHED\n"
            "X2DII_ONE_OWNED_FILE_REMOVED_NOT_FUNCTION_VALIDATED\n\n" + marker + "0\n").replace("\n", "\r\n").encode()
        output = b"".join(lines) + receipt
        outputs.append(output)
        ack = c.finish_file(file_index=file_index, decoded_output=output.replace(b"\r\n", b"\n"), stream_completed=True)
        host.append("file|" + ack.decode().rstrip("\n"))
        path = cleanup.worker_path(installer.manifest, raw, file_index)
        command = f'set -eu; x=$(sha256sum {path}); [ "${{x%% *}}" = {c.worker_hashes[file_index]} ]; '
        command += f'sh {path} {files.session_path(installer.manifest, raw_sha)} {raw_sha}'
        wire = f'({command}); r=$?; printf \'\\n{marker}%s\\n\' "$r"'
        steps = [step(greeting, reply_greeting),
            step(packet("OPEN", 1, 0, ("shell:" + wire + "\0").encode()),
                packet("OKAY", 7, 1) + packet("WRTE", 7, 1, lines[0][:13]))]
        for index, line in enumerate(lines):
            steps += [step(okay, packet("WRTE", 7, 1, line[13:])), step(okay)]
            chunk = lines[index+1][:13] if index < 3 else receipt[:109]
            steps.append(step(packet("WRTE", 1, 7, replies[index]),
                packet("OKAY", 7, 1) + packet("WRTE", 7, 1, chunk)))
        steps += [step(okay, packet("WRTE", 7, 1, receipt[109:])),
            step(okay, packet("CLSE", 7, 1)), step(close)]
        scripts.append("\n".join(steps))
    return source, epoch, scripts, host, responses, options, outputs


def test_cleanup_receiver_uses_four_own_boundaries_per_file_and_retains_exact_output(installer, tmp_path):
    from tests.menu_transport_wire_fixture import run_wire
    source, epoch, scripts, host, _, _, expected = cleanup_wire_case(installer)
    result = run_wire(source, epoch, scripts, host, tmp_path)
    assert result["Error"] is None, result
    assert result["Opens"] == 5 and result["HostReads"] == 20 and result["RemainingSteps"] == 0
    assert result["Result"] == "X2DII_FOUR_OWNED_FILES_REMOVED_NOT_FUNCTION_VALIDATED"
    lines = result["Output"].splitlines()
    for index, output in enumerate(expected):
        chunks = [base64.b64decode(line.split(":", 2)[2]) for line in lines
            if line.startswith(f"X2DII_CLEANUP_WORKER_OUTPUT:{index}:")]
        assert b"".join(chunks) == output


@pytest.mark.parametrize("fault,close_error", (("none", False), ("none", True),
    ("first", False), ("second", False), ("second", True)))
def test_cleanup_real_child_driver_retains_completed_removals_and_original_failure(
        installer, tmp_path, fault, close_error):
    from tools import menu_cleanup_transport as transport
    from tests.test_preplacement_host_dialogue import interactive_process
    source, epoch, scripts, _, responses, options, outputs = cleanup_wire_case(installer)
    calls = []
    class Maintenance:
        def command(self, label, command):
            # Substitute only the external maintenance response, not the
            # coordinator, frame codec, child pipes or receipt validation.
            calls.append(command)
            if len(calls) == {"first": 2, "second": 5}.get(fault):
                raise OSError("CLEANUP_MAINTENANCE_FAILED")
            return responses[command]
    process = interactive_process(source, epoch, scripts, tmp_path)
    if close_error:
        class CloseFailure:
            def __init__(self, stream):
                self.stream = stream
            def __getattr__(self, name):
                return getattr(self.stream, name)
            def close(self):
                self.stream.close()
                raise OSError("CLEANUP_HOST_CLOSE_FAILED")
        process.stdin = CloseFailure(process.stdin)
    try:
        if fault == "none" and not close_error:
            result = transport.drive_cleanup_process(process, installer.manifest, *options,
                Maintenance(), clock=lambda: epoch)
            assert result["status"] == "FOUR_OWNED_FILES_REMOVED_NOT_FUNCTION_VALIDATED"
            assert len(result["completed_receipts"]) == 4
            assert result["worker_outputs"] == tuple(outputs)
            assert len(calls) == 16 and process.returncode == 0
        else:
            expected = "host cleanup failed" if fault == "none" else "CLEANUP_MAINTENANCE_FAILED"
            with pytest.raises((ValueError, OSError), match=expected) as caught:
                transport.drive_cleanup_process(process, installer.manifest, *options,
                    Maintenance(), clock=lambda: epoch)
            evidence = caught.value.partial_evidence
            completed = {"first": 0, "second": 1, "none": 4}[fault]
            assert len(evidence["completed_receipts"]) == completed
            assert evidence["current_file"] == completed
            assert evidence["worker_outputs"][:completed] == tuple(outputs[:completed])
            assert len(calls) == {"first": 2, "second": 5, "none": 16}[fault]
            if close_error:
                assert any(row["step"] == "host_stdin_close" and "CLEANUP_HOST_CLOSE_FAILED" in row["error"]
                    for row in evidence["cleanup_errors"])
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
        for stream in (process.stdout, process.stderr):
            stream.close()


@pytest.mark.parametrize("fault,expected", (("ack", "MENU_BOUNDARY_ACK"),
    ("old-ack", "MENU_BOUNDARY_TIME"), ("file-ack", "MENU_FILE_ACK_MISMATCH"),
    ("eof", "MENU_HOST_EOF")))
def test_cleanup_codec_rejects_invalid_host_reply_before_any_later_file(installer, tmp_path, fault, expected):
    from tests.menu_transport_wire_fixture import run_wire
    source, epoch, scripts, host, _, _, _ = cleanup_wire_case(installer)
    if fault == "ack":
        host[0] = "boundary|X2DII_CLEANUP_BOUNDARY_ACK:" + "0" * 64 + f":{epoch}:{epoch}"
    elif fault == "old-ack":
        host[0] = host[0].rsplit(":", 2)[0] + f":{epoch-1}:{epoch-1}"
    elif fault == "eof":
        host[0] = "boundary|<EOF>"
    else:
        host[4] = "file|X2DII_HOST_CLEANUP_ACK:0:" + "0" * 64
    result = run_wire(source, epoch, scripts, host, tmp_path)
    assert result["Error"] == expected, result
    assert result["Opens"] == 2 and result["Result"] is None
