"""Real host/C# dialogue with native USB and maintenance transport substituted."""
import json
import re
import subprocess

import pytest

from tests.test_release_lifecycle import installer
from tests.test_menu_preplacement_transport import wire_case
from tests.menu_transport_wire_fixture import native_disabled_source
from tools import menu_preplacement_transport as transport, session_context


def interactive_process(source, epoch, scripts, tmp_path):
    namespace = re.search(r"namespace (X2d2Menu(?:Preplace|Boot|Cleanup)_[a-f0-9]+)", source)[1]
    filename = tmp_path / "native-disabled-interactive.cs"
    filename.write_text(native_disabled_source(source, epoch), encoding="utf-8")
    transcript = tmp_path / "native-transcript.json"
    transcript.write_text(json.dumps(scripts), encoding="ascii")
    program = f"""
$ErrorActionPreference='Stop'
Add-Type -Path '{str(filename).replace("'", "''")}'
[string[]]$frames=Get-Content -LiteralPath '{str(transcript).replace("'", "''")}' -Raw | ConvertFrom-Json
$result=[{namespace}.WireFixture]::Run($frames,@(),3,$true)
if($result.Error){{[Console]::Error.WriteLine($result.Error);exit 1}}
"""
    return subprocess.Popen(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", program],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


@pytest.mark.parametrize("failure", (None, "maintenance", "second-file"))
@pytest.mark.parametrize("cleanup_failure", (False, True))
def test_actual_console_driver_bridges_only_current_boundary_and_stops_on_failure(
        installer, tmp_path, failure, cleanup_failure):
    from tools import menu_maintenance_boundary as boundary, prepare_peer_install as peer
    source, epoch, scripts, _, _ = wire_case(installer, session_kind="install")
    raw = peer.session_data(installer.manifest, installer.q)
    values = session_context.decode_session(raw)
    calls = []

    class Maintenance:
        # Only the external maintenance transport is substituted. Production
        # coordination, C# stream decoder and both real process pipes run.
        def command(self, label, command):
            _, program, data_hash, file, stage, request_hash = command.split()
            file, stage = int(file), int(stage)
            assert program == boundary.paths(installer.manifest, file, stage,
                session_data_sha256=peer.sha(raw), session_kind="install")["program"]
            assert data_hash == peer.sha(raw)
            calls.append((file, stage))
            if failure and (file, stage) == ((1, 0) if failure == "second-file" else (0, 1)):
                raise ValueError("TEST_MAINTENANCE_COMPLETION_FAILED")
            program_hash = peer.sha(transport.render_supervised_preplacement(
                installer.manifest, file_index=file, session_kind="install").encode("ascii"))
            challenge = peer.sha(f"{values['boot_id']}:{values['session_nonce']}:{file}:{stage}:{program_hash}\n".encode())
            request = boundary.make_request(installer.manifest, raw, worker_session_sha256=peer.sha(raw),
                worker_program_sha256=program_hash, file_index=file, boundary_index=stage,
                challenge=challenge, issued_epoch=epoch)
            assert request_hash == peer.sha(request)
            response = request.replace(boundary.REQUEST_SCHEMA.encode(), boundary.RESPONSE_SCHEMA.encode(), 1)
            return (response + f"request_sha256={request_hash}\nstarted_epoch={epoch}\nchecked_epoch={epoch}\n"
                "result=OBSERVED_MATCH\nscope=ONE_BOUNDARY_ONLY_NOT_AUTHORIZATION\n".encode()).decode("ascii")

    process = interactive_process(source, epoch, scripts, tmp_path)
    if cleanup_failure:
        class CloseFailure:
            def __init__(self, stream):
                self.stream = stream

            def __getattr__(self, name):
                return getattr(self.stream, name)

            def close(self):
                self.stream.close()
                raise OSError("INJECTED_HOST_STDIN_CLOSE_FAILURE")

        process.stdin = CloseFailure(process.stdin)
    try:
        if failure or cleanup_failure:
            message = "TEST_MAINTENANCE_COMPLETION_FAILED" if failure else "host cleanup failed"
            with pytest.raises(ValueError, match=message) as caught:
                transport.drive_preplacement_process(process, installer.manifest, raw, Maintenance(), clock=lambda: epoch)
            evidence = caught.value.partial_evidence
            assert evidence["candidate_sha256"] == installer.manifest["candidate_sha256"]
            assert evidence["session_data_sha256"] == peer.sha(raw)
            if cleanup_failure:
                assert any(row["step"] == "host_stdin_close" and
                           "INJECTED_HOST_STDIN_CLOSE_FAILURE" in row["error"]
                           for row in evidence["cleanup_errors"])
            if failure == "second-file":
                assert calls == [(0, stage) for stage in range(7)] + [(1, 0)]
                assert evidence["current_file"] == 1
                assert evidence["completed_identities"] == (
                    f"1:2:81a4:1:{installer.manifest['candidate']['files'][0]['bytes']}:0:0",)
                assert b"ONE_FILE_PREPLACED" in evidence["worker_outputs"][0]
                assert b"X2DII_BOUNDARY_REQUEST:1:0:" in evidence["worker_outputs"][1]
            elif failure:
                assert calls == [(0, 0), (0, 1)]
                assert evidence["completed_identities"] == () and evidence["current_file"] == 0
            else:
                assert evidence["current_file"] == 4
                assert evidence["completed_identities"] == tuple(
                    f"1:{2+index}:81a4:1:{file['bytes']}:0:0"
                    for index, file in enumerate(installer.manifest["candidate"]["files"]))
                assert calls == [(file, stage) for file in range(4) for stage in range(7)]
        else:
            result = transport.drive_preplacement_process(process, installer.manifest, raw, Maintenance(), clock=lambda: epoch)
            assert result["status"] == "FOUR_FILES_PREPLACED_NOT_FEATURE_VALIDATED"
            assert result["completed_identities"] == tuple(
                f"1:{2+index}:81a4:1:{file['bytes']}:0:0"
                for index, file in enumerate(installer.manifest["candidate"]["files"]))
            assert calls == [(file, stage) for file in range(4) for stage in range(7)]
            assert len(result["worker_outputs"]) == 4 and process.returncode == 0
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=10)
