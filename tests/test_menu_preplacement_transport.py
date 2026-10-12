"""Generated fixed ADB dialogue compiles; no native USB API is called."""
import importlib
import base64
import hashlib
import re
import subprocess
from datetime import datetime, timezone

import pytest

from tests.test_release_lifecycle import installer
from tests.test_menu_maintenance_boundary import context


def review_source(installer, raw):
    from tools import menu_preplacement_transport as transport, session_context
    # Explicit synthetic USB launch observation, not inferred production state.
    launched = datetime.fromtimestamp(session_context.decode_session(raw)["observed_epoch"], timezone.utc)
    return transport.review_host_source(installer.manifest, raw, launch_started_utc=launched)


def test_host_only_acks_current_worker_after_matching_maintenance_reply(installer):
    from tools import menu_preplacement_transport as transport, menu_maintenance_boundary as boundary
    from tools import session_context
    raw = context(installer)
    epoch = session_context.decode_session(raw)["observed_epoch"]
    coordinator = transport.PreplacementCoordinator(installer.manifest, raw)
    worker_hash = hashlib.sha256(transport.render_supervised_preplacement(
        installer.manifest, file_index=0).encode("ascii")).hexdigest()
    ctx = session_context.decode_session(raw)
    challenge = hashlib.sha256(
        f"{ctx['boot_id']}:{ctx['session_nonce']}:0:0:{worker_hash}\n".encode()).hexdigest()
    request = boundary.make_request(installer.manifest, raw, worker_session_sha256=hashlib.sha256(raw).hexdigest(),
        worker_program_sha256=worker_hash, file_index=0, boundary_index=0, challenge=challenge, issued_epoch=epoch)
    request_hash = hashlib.sha256(request).hexdigest()
    command = coordinator.begin_boundary(f"X2DII_HOST_BOUNDARY:0:0:{request_hash}")
    from tools.stage_peer_usb_access import envelope
    assert len(envelope(command, "123456abcdef")[0].encode()) < 232
    response = request.replace(boundary.REQUEST_SCHEMA.encode(), boundary.RESPONSE_SCHEMA.encode(), 1)
    response += (f"request_sha256={request_hash}\nstarted_epoch={epoch}\nchecked_epoch={epoch}\n"
                 "result=OBSERVED_MATCH\nscope=ONE_BOUNDARY_ONLY_NOT_AUTHORIZATION\n").encode()
    assert coordinator.accept_reply(response, received_epoch=epoch) == (
        f"X2DII_BOUNDARY_ACK:{request_hash}:{epoch}:{epoch}\n"
    ).encode()
    assert coordinator.next_boundary == (0, 1)
    with pytest.raises(ValueError):
        coordinator.accept_reply(response, received_epoch=epoch)
    assert coordinator.failed


@pytest.mark.parametrize("identity", ("f:f:f:f:f:f:f", "1:2:81ff:1:SIZE:0:0",
    "1:2:81a4:2:SIZE:0:0", "1:2:81a4:1:1:0:0", "1:2:81a4:1:SIZE:1000:0"))
def test_malformed_completed_file_identity_cannot_advance_to_another_worker(installer, identity):
    from tools import menu_preplacement_transport as transport, menu_maintenance_boundary as boundary
    from tools import session_context
    raw = context(installer)
    data = session_context.decode_session(raw)
    coordinator = transport.PreplacementCoordinator(installer.manifest, raw)
    program_hash = hashlib.sha256(transport.render_supervised_preplacement(
        installer.manifest, file_index=0).encode("ascii")).hexdigest()
    epoch = data["observed_epoch"]
    for index in range(7):
        challenge = hashlib.sha256(f"{data['boot_id']}:{data['session_nonce']}:0:{index}:{program_hash}\n".encode()).hexdigest()
        request = boundary.make_request(installer.manifest, raw, worker_session_sha256=hashlib.sha256(raw).hexdigest(),
            worker_program_sha256=program_hash, file_index=0, boundary_index=index, challenge=challenge, issued_epoch=epoch)
        request_hash = hashlib.sha256(request).hexdigest()
        coordinator.begin_boundary(f"X2DII_HOST_BOUNDARY:0:{index}:{request_hash}")
        response = request.replace(boundary.REQUEST_SCHEMA.encode(), boundary.RESPONSE_SCHEMA.encode(), 1)
        response += (f"request_sha256={request_hash}\nstarted_epoch={epoch}\nchecked_epoch={epoch}\n"
                     "result=OBSERVED_MATCH\nscope=ONE_BOUNDARY_ONLY_NOT_AUTHORIZATION\n").encode()
        coordinator.accept_reply(response, received_epoch=epoch)
    entry = installer.manifest["candidate"]["files"][0]
    identity = identity.replace("SIZE", str(entry["bytes"]))
    output = (
        "schema=x2dii-one-file-preplacement-v1\n"
        f"candidate_sha256={installer.manifest['candidate_sha256']}\n"
        f"session_nonce={data['session_nonce']}\nfile_index=0\nidentity={identity}\n"
        f"label={data['library_label']}\nsha256={entry['sha256']}\n"
        "maintenance_boundaries=HOST_MEDIATED_SEVEN_MATCHED\nX2DII_ONE_FILE_PREPLACED_NOT_RUNTIME_VALIDATED\n\n"
        f"X2DII_WORKER_{hashlib.sha256(raw).hexdigest()[:24]}_0_RC=0\n"
    ).encode()
    with pytest.raises(ValueError, match="identity|receipt"):
        coordinator.finish_file(file_index=0, decoded_output=output, stream_completed=True)
    assert coordinator.next_boundary is None and coordinator.failed


def test_unqualified_supervision_host_compiles_and_refuses_before_usb(installer, tmp_path):
    transport = importlib.import_module("tools.menu_preplacement_transport")
    raw = context(installer)
    source = review_source(installer, raw)
    namespace = re.search(r"namespace (X2d2MenuPreplace_[a-f0-9]+)", source)[1]
    filename = tmp_path / "menu-supervision.cs"
    filename.write_text(source, encoding="utf-8")
    script = f"""
$ErrorActionPreference='Stop'
Add-Type -Path '{str(filename).replace("'", "''")}'
try {{ [{namespace}.AdbUsbCheck]::RunFourFiles(); throw 'Execution should be refused' }}
catch {{
 $problem=$_.Exception
 while($problem.InnerException){{$problem=$problem.InnerException}}
 if($problem.Code -ne 'MENU_SUPERVISION_NOT_QUALIFIED'){{throw}}
}}
'COMPILED_REFUSED_BEFORE_USB'
"""
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "COMPILED_REFUSED_BEFORE_USB" in result.stdout


@pytest.mark.parametrize("fault", ("none", "replay", "wrong-index", "wrong-hash", "future-time", "incomplete"))
def test_fixed_dialogue_never_reuses_a_prior_boundary_confirmation(installer, tmp_path, fault):
    from tools import menu_preplacement_transport as transport, session_context
    raw = context(installer)
    source = review_source(installer, raw)
    epoch = session_context.decode_session(raw)["observed_epoch"]
    namespace = re.search(r"namespace (X2d2MenuPreplace_[a-f0-9]+)", source)[1]
    filename = tmp_path / "dialogue.cs"
    filename.write_text(source, encoding="utf-8")
    script = r'''
$ErrorActionPreference='Stop'
Add-Type -Path 'SOURCE'
$type=[NAMESPACE.AdbUsbCheck+BoundaryDialogue]
$dialogue=[Activator]::CreateInstance($type,@([int]0))
$hash0='a'*64
$hash1='b'*64
$null=$dialogue.AcceptRequest('X2DII_BOUNDARY_REQUEST:0:0:'+$hash0)
$null=$dialogue.AcceptAcknowledgement('X2DII_BOUNDARY_ACK:'+$hash0+':EPOCH:EPOCH')
if($dialogue.CompletedBoundaries -ne 1 -or $dialogue.Waiting){throw 'first response not consumed'}
$fault='FAULT'
if($fault -eq 'none'){
 for($i=1;$i -lt 7;$i++){
  $h=([string]$i)*64
  $null=$dialogue.AcceptRequest('X2DII_BOUNDARY_REQUEST:0:'+$i+':'+$h)
  $null=$dialogue.AcceptAcknowledgement('X2DII_BOUNDARY_ACK:'+$h+':EPOCH:EPOCH')
 }
 $dialogue.Finish()
 if($dialogue.CompletedBoundaries -ne 7){throw 'missing boundaries'}
}else{
 try{
  if($fault -eq 'wrong-index'){
   $null=$dialogue.AcceptRequest('X2DII_BOUNDARY_REQUEST:0:2:'+$hash1)
  }elseif($fault -eq 'incomplete'){
   $dialogue.Finish()
  }else{
   $null=$dialogue.AcceptRequest('X2DII_BOUNDARY_REQUEST:0:1:'+$hash1)
   if($fault -eq 'replay'){$ack='X2DII_BOUNDARY_ACK:'+$hash0+':EPOCH:EPOCH'}
   elseif($fault -eq 'wrong-hash'){$ack='X2DII_BOUNDARY_ACK:'+('f'*64)+':EPOCH:EPOCH'}
   else{$ack='X2DII_BOUNDARY_ACK:'+$hash1+':FUTURE:FUTURE'}
   $null=$dialogue.AcceptAcknowledgement($ack)
  }
  throw 'UNEXPECTED_ACCEPTANCE'
 }catch{
  $e=$_.Exception;while($e.InnerException){$e=$e.InnerException}
  if(-not $e.Code.StartsWith('MENU_BOUNDARY_')){throw}
 }
 try{$dialogue.AcceptRequest('X2DII_BOUNDARY_REQUEST:0:1:'+$hash1);throw 'NOT_LATCHED'}
 catch{$e=$_.Exception;while($e.InnerException){$e=$e.InnerException};if($e.Code -ne 'MENU_BOUNDARY_ORDER'){throw}}
}
'DIALOGUE_ONLY_NO_USB'
'''.replace("SOURCE", str(filename).replace("'", "''")).replace("NAMESPACE", namespace).replace(
        "FAULT", fault).replace("EPOCH", str(epoch)).replace("FUTURE", str(epoch + 601))
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "DIALOGUE_ONLY_NO_USB" in result.stdout


def wire_case(installer, *, control_fault="none", host_fault="none", stream_fault="none",
              session_kind="menu_validation"):
    """Independent ADB peer transcript plus real coordinator host replies.

    Peer bytes are scripted at the native boundary, not at Receive(). They
    include a fixed identity session and four separately opened worker streams.
    Every request line and final receipt is split across two ADB WRTE frames.
    """
    from tools import menu_preplacement_transport as transport, menu_maintenance_boundary as boundary, session_context
    from tests.menu_transport_wire_fixture import packet, step
    raw = context(installer, session_kind=session_kind)
    values = session_context.decode_session(raw)
    epoch = values["observed_epoch"]
    raw_hash = hashlib.sha256(raw).hexdigest()
    coordinator = transport.PreplacementCoordinator(installer.manifest, raw)
    source = review_source(installer, raw)
    assert coordinator.completed_identities == ()
    identity_command = ("printf 'UID=';id -u;printf '\nDOMAIN=';cat /proc/self/attr/current;"
                        "printf '\nUSB_CONFIG=';getprop sys.usb.config;printf 'USB_STATE=';getprop sys.usb.state;"
                        "printf 'ADBD=';getprop init.svc.adbd;printf 'X2DII_ADB_READONLY_DONE\n'")
    identity = (b"UID=0\nDOMAIN=u:r:su:s0\nUSB_CONFIG=rndis,mass_storage,bulk,acm,adb\n"
                b"USB_STATE=rndis,mass_storage,bulk,acm,adb\nADBD=running\nX2DII_ADB_READONLY_DONE\n")
    greeting = packet("CNXN", 0x01000000, 4096, b"host::\0")
    peer_greeting = packet("CNXN", 0x01000000, 4096, b"device::\0")
    okay, close = packet("OKAY", 1, 7), packet("CLSE", 1, 7)
    scripts = ["\n".join((
        step(greeting, peer_greeting),
        step(packet("OPEN", 1, 0, ("shell:" + identity_command + "\0").encode()),
             packet("OKAY", 7, 1) + packet("WRTE", 7, 1, identity)),
        step(okay, packet("CLSE", 7, 1)), step(close),
    ))]
    host_lines, expected_outputs = [], []
    for file_index in range(4):
        program_hash = hashlib.sha256(transport.render_supervised_preplacement(
            installer.manifest, file_index=file_index, session_kind=session_kind).encode("ascii")).hexdigest()
        request_lines, replies = [], []
        for stage in range(7):
            challenge = hashlib.sha256(
                f"{values['boot_id']}:{values['session_nonce']}:{file_index}:{stage}:{program_hash}\n".encode()).hexdigest()
            request = boundary.make_request(installer.manifest, raw, worker_session_sha256=raw_hash,
                worker_program_sha256=program_hash, file_index=file_index, boundary_index=stage,
                challenge=challenge, issued_epoch=epoch)
            digest = hashlib.sha256(request).hexdigest()
            coordinator.begin_boundary(f"X2DII_HOST_BOUNDARY:{file_index}:{stage}:{digest}")
            response = request.replace(boundary.REQUEST_SCHEMA.encode(), boundary.RESPONSE_SCHEMA.encode(), 1)
            response += (f"request_sha256={digest}\nstarted_epoch={epoch}\nchecked_epoch={epoch}\n"
                         "result=OBSERVED_MATCH\nscope=ONE_BOUNDARY_ONLY_NOT_AUTHORIZATION\n").encode()
            ack = coordinator.accept_reply(response, received_epoch=epoch)
            replies.append(ack)
            host_lines.append("boundary|" + ack.decode().rstrip("\n"))
            request_lines.append(f"X2DII_BOUNDARY_REQUEST:{file_index}:{stage}:{digest}\r\n".encode())
        entry = installer.manifest["candidate"]["files"][file_index]
        label = values[("library_label", "bootstrap_label", "model_label", "page_label")[file_index]]
        marker = f"X2DII_WORKER_{raw_hash[:24]}_{file_index}_RC="
        receipt = ("schema=x2dii-one-file-preplacement-v1\n"
            f"candidate_sha256={installer.manifest['candidate_sha256']}\nsession_nonce={values['session_nonce']}\n"
            f"file_index={file_index}\nidentity=1:{2+file_index}:81a4:1:{entry['bytes']}:0:0\nlabel={label}\nsha256={entry['sha256']}\n"
            "maintenance_boundaries=HOST_MEDIATED_SEVEN_MATCHED\nX2DII_ONE_FILE_PREPLACED_NOT_RUNTIME_VALIDATED\n\n"
            f"{marker}0\n").replace("\n", "\r\n").encode()
        output = b"".join(request_lines) + receipt
        expected_outputs.append(output)
        final_ack = coordinator.finish_file(file_index=file_index,
            decoded_output=output.replace(b"\r\n", b"\n"), stream_completed=True)
        assert coordinator.completed_identities == tuple(
            f"1:{2+index}:81a4:1:{row['bytes']}:0:0"
            for index, row in enumerate(installer.manifest["candidate"]["files"][:file_index + 1]))
        host_lines.append("file|" + final_ack.decode().rstrip("\n"))
        if file_index == 0 and stream_fault == "missing-status":
            receipt = receipt.replace((marker + "0\r\n").encode(), b"")
        if file_index == 0 and stream_fault == "unfinished-line":
            receipt = receipt[:-2]
        expected_outputs[-1] = b"".join(request_lines) + receipt
        stage_path = "/blackbox/x2dii-menu-stage/" + installer.manifest["candidate_sha256"][:24]
        path = stage_path + (f"/menu-validation-preplace-{file_index}.sh" if session_kind == "menu_validation"
                             else f"/preplace-{file_index}.sh")
        command = (f'set -eu; x=$(sha256sum {path}); [ "${{x%% *}}" = {program_hash} ]; '
                   f'sh {path} {boundary.session_path(installer.manifest, raw_hash)} {raw_hash}')
        wire = f'({command}); r=$?; printf \'\\n{marker}%s\\n\' "$r"'
        initial_extra = b"x" if file_index == 0 and control_fault == "initial-okay" else b""
        first_write = packet("WRTE", 7, 1, request_lines[0][:13])
        if file_index == 0:
            if stream_fault == "checksum":
                first_write = first_write[:-1] + bytes((first_write[-1] ^ 1,))
            elif stream_fault == "wrong-local":
                first_write = packet("WRTE", 7, 2, request_lines[0][:13])
            elif stream_fault == "wrong-remote":
                first_write = packet("WRTE", 8, 1, request_lines[0][:13])
            elif stream_fault == "early-close":
                first_write = packet("CLSE", 7, 1)
        steps = [step(greeting, peer_greeting),
                 step(packet("OPEN", 1, 0, ("shell:" + wire + "\0").encode()),
                      packet("OKAY", 7, 1, initial_extra) + first_write)]
        if file_index == 0 and stream_fault == "early-close":
            scripts.append("\n".join(steps + [step(close)]))
            continue
        for stage, line in enumerate(request_lines):
            steps += [step(okay, packet("WRTE", 7, 1, line[13:])), step(okay)]
            next_chunk = request_lines[stage + 1][:13] if stage < 6 else receipt[:109]
            stdin_extra = b"x" if file_index == stage == 0 and control_fault == "stdin-okay" else b""
            steps.append(step(packet("WRTE", 1, 7, replies[stage]),
                              packet("OKAY", 7, 1, stdin_extra) + packet("WRTE", 7, 1, next_chunk)))
        close_extra = b"x" if file_index == 0 and control_fault == "close" else b""
        steps += [step(okay, packet("WRTE", 7, 1, receipt[109:])),
                  step(okay, packet("CLSE", 7, 1, close_extra)), step(close)]
        scripts.append("\n".join(steps))
    if host_fault != "none":
        role, fault = host_fault.split("-", 1)
        index = 0 if role == "boundary" else 7
        replacement = {"wrong": "X2DII_INVALID_ACK", "eof": "<EOF>", "timeout": "<TIMEOUT>"}[fault]
        host_lines[index] = role + "|" + replacement
    return source, epoch, scripts, host_lines, expected_outputs


@pytest.mark.parametrize("session_kind", ("menu_validation", "install"))
def test_full_generated_receiver_preserves_split_output_and_waits_after_wire_ack(installer, tmp_path, session_kind):
    from tests.menu_transport_wire_fixture import run_wire
    source, epoch, scripts, host_lines, expected = wire_case(installer, session_kind=session_kind)
    result = run_wire(source, epoch, scripts, host_lines, tmp_path)
    assert result["Error"] is None, result
    assert result["Result"] == "X2DII_FOUR_FILES_PREPLACED_NOT_MENU_OR_INSTALLATION_VALIDATION"
    assert result["Opens"] == 5 and result["HostReads"] == 32 and result["RemainingSteps"] == 0
    assert result["NativeReads"] > 500  # Headers and payloads both arrive as 3-byte native fragments.
    lines = result["Output"].splitlines()
    for index, raw_output in enumerate(expected):
        chunks = [base64.b64decode(line.split(":", 2)[2]) for line in lines
                  if line.startswith(f"X2DII_WORKER_OUTPUT:{index}:")]
        assert b"".join(chunks) == raw_output
        final = [line for line in lines if line.startswith(f"X2DII_HOST_FILE_COMPLETE:{index}:")]
        assert len(final) == 1
        assert base64.b64decode(final[0].split(":", 2)[2]) == raw_output.replace(b"\r\n", b"\n")
    assert sum(line.startswith("X2DII_HOST_BOUNDARY:") for line in lines) == 28
    events = result["Events"]
    for index, event in enumerate(events):
        if event.startswith("HOST:"):
            _, connection, role = event.split(":")
            assert events[index - 1] == f"SEND:{connection}:" + ("OKAY" if role == "boundary" else "CLSE")


def test_expired_original_usb_window_cannot_be_replaced_by_600_second_session_lease(installer, tmp_path):
    from tests.menu_transport_wire_fixture import run_wire
    source, epoch, scripts, host_lines, _ = wire_case(installer, session_kind="install")
    result = run_wire(source, epoch + 81, scripts, host_lines, tmp_path)
    assert result["Error"] == "MENU_SUPERVISION_DEADLINE", result
    assert result["Opens"] == 0 and result["Result"] is None


@pytest.mark.parametrize("fault", ("initial-okay", "stdin-okay", "close"))
def test_full_receiver_rejects_nonempty_control_payload_before_file_completion(installer, tmp_path, fault):
    from tests.menu_transport_wire_fixture import run_wire
    source, epoch, scripts, host_lines, _ = wire_case(installer, control_fault=fault)
    result = run_wire(source, epoch, scripts, host_lines, tmp_path)
    assert result["Error"] == "MENU_CONTROL_PAYLOAD", result
    assert result["Opens"] == 2
    assert "X2DII_HOST_FILE_COMPLETE:" not in result["Output"]


@pytest.mark.parametrize("fault,error", (
    ("boundary-wrong", "MENU_BOUNDARY_ACK"),
    ("boundary-eof", "MENU_HOST_EOF"),
    ("boundary-timeout", "MENU_HOST_REPLY_TIMEOUT"),
    ("file-wrong", "MENU_FILE_ACK_MISMATCH"),
    ("file-eof", "MENU_HOST_EOF"),
    ("file-timeout", "MENU_HOST_REPLY_TIMEOUT"),
))
def test_full_sender_never_opens_a_later_file_without_matching_host_ack(installer, tmp_path, fault, error):
    from tests.menu_transport_wire_fixture import run_wire
    source, epoch, scripts, host_lines, expected = wire_case(installer, host_fault=fault)
    result = run_wire(source, epoch, scripts, host_lines, tmp_path)
    assert result["Error"] == error, result
    assert result["Result"] is None and result["Opens"] == 2
    assert "X2DII_WORKER_OUTPUT:1:" not in result["Output"]
    chunks = [base64.b64decode(line.split(":", 2)[2]) for line in result["Output"].splitlines()
              if line.startswith("X2DII_WORKER_OUTPUT:0:")]
    if fault.startswith("file-"):
        assert b"".join(chunks) == expected[0]
        assert "X2DII_HOST_FILE_COMPLETE:0:" in result["Output"]
        assert result["HostReads"] == 8
    else:
        assert b"".join(chunks) == expected[0].split(b"\r\n", 1)[0] + b"\r\n"
        assert "X2DII_HOST_FILE_COMPLETE:" not in result["Output"]
        assert result["HostReads"] == 1


@pytest.mark.parametrize("fault,error", (
    ("checksum", "ADB_CHECKSUM"),
    ("wrong-local", "ADB_STREAM_ID"),
    ("wrong-remote", "ADB_REMOTE_ID"),
    ("early-close", "MENU_BOUNDARY_INCOMPLETE"),
    ("missing-status", "MENU_WORKER_STATUS"),
    ("unfinished-line", "MENU_UNFINISHED_STREAM"),
))
def test_full_receiver_requires_valid_wire_and_completed_worker_before_final_receipt(installer, tmp_path, fault, error):
    from tests.menu_transport_wire_fixture import run_wire
    source, epoch, scripts, host_lines, expected = wire_case(installer, stream_fault=fault)
    result = run_wire(source, epoch, scripts, host_lines, tmp_path)
    assert result["Error"] == error, result
    assert result["Opens"] == 2 and result["Result"] is None
    assert "X2DII_HOST_FILE_COMPLETE:" not in result["Output"]
    if fault in ("missing-status", "unfinished-line"):
        chunks = [base64.b64decode(line.split(":", 2)[2]) for line in result["Output"].splitlines()
                  if line.startswith("X2DII_WORKER_OUTPUT:0:")]
        assert b"".join(chunks) == expected[0]
