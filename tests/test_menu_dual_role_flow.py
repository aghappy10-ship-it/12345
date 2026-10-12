"""Actual two generated roles and host reply validation in one local file tree.

Native USB and SELinux remain OS substitutes; no live result is claimed. The
maintainer reads the waiting worker's actual files, never re-creates payloads.
"""
import hashlib

import pytest

from tests.test_release_lifecycle import installer
from tests.test_menu_maintenance_boundary import context, execute_observer
from tests.test_menu_supervision import dialogue
from tests.test_temporary_domain_integration import payload_snapshot
from tests.test_temporary_menu_session import run_temporary, temporary_os_boundary
from tools import menu_maintenance_boundary as boundary
from tools import menu_preplacement_transport as transport
from tools import session_context, prepare_peer_install as peer


@pytest.mark.parametrize("drift", (False, True))
@pytest.mark.parametrize("session_kind", ("menu_validation", "install"))
def test_worker_really_waits_for_current_maintenance_observation_before_commit(installer, drift, session_kind):
    raw = context(installer, session_kind=session_kind)
    values = session_context.decode_session(raw)
    (installer.root / "proc/self/attr/current").write_text("u:r:su:s0\n")
    coordinator = transport.PreplacementCoordinator(installer.manifest, raw)
    snapshots = []
    observer_results = []

    def respond(index, _synthetic_ack, worker_values):
        path = installer.root / boundary.paths(installer.manifest, file_index, index,
            session_data_sha256=peer.sha(raw), session_kind=session_kind)["request"].lstrip("/")
        request = path.read_bytes()
        request_hash = hashlib.sha256(request).hexdigest()
        before = (path.stat().st_ino, path.read_bytes(), (installer.root / "proc/mounts").read_bytes())
        command = coordinator.begin_boundary(f"X2DII_HOST_BOUNDARY:{file_index}:{index}:{request_hash}")
        assert command.endswith(f" {file_index} {index} {request_hash}")
        if drift and index == 4:
            (installer.root / "proc/345/attr/current").write_text("u:r:changed:s0\n")
        result = execute_observer(installer, raw, request, file_index=file_index, boundary_index=index)
        observer_results.append(result)
        assert before == (path.stat().st_ino, path.read_bytes(), (installer.root / "proc/mounts").read_bytes())
        assert (installer.root / "proc/self/attr/current").read_text() == "u:r:su:s0\n"
        snapshots.append(before)
        if result.returncode:
            assert drift and index == 4, (result.stdout, result.stderr)
            return None  # No ACK on failed maintenance/native completion.
        return coordinator.accept_reply(result.stdout, received_epoch=values["observed_epoch"])

    session_snapshot = None
    for file_index in range(1 if drift else 4):
        before_payloads = payload_snapshot(installer, count=file_index)
        result, observed = dialogue(installer, reply=respond, file_index=file_index,
                                    setup=False, values=values, wrap_status=True, session_kind=session_kind,
                                    use_observer=True, host_wait_seconds=30)
        assert payload_snapshot(installer, count=file_index) == before_payloads
        session_path = installer.root / boundary.paths(installer.manifest, 0, 0,
            session_data_sha256=peer.sha(raw), session_kind=session_kind)["session"].lstrip("/")
        current_session = (session_path.stat().st_ino, session_path.stat().st_mtime_ns, session_path.read_bytes())
        if session_snapshot is not None:
            assert current_session == session_snapshot
        session_snapshot = current_session
        assert (installer.root / "proc/mounts").read_text() == installer.mount_line
        assert (installer.root / "gui-service-state").read_text() == "running"
        assert not (installer.root / "operations").exists()
        entry = installer.manifest["candidate"]["files"][file_index]
        target = installer.root / entry["target"].lstrip("/")
        if drift:
            assert len(observed) == 5 and observer_results[-1].returncode != 0, (result.stdout, result.stderr)
            assert b"ONE_FILE_PREPLACED" not in result.stdout
            assert not target.exists()
            assert b"_RC=81\n" in result.stdout
            assert not any(line.startswith("mv:") for line in (installer.root / "worker-operations").read_text().splitlines())
        else:
            assert len(observed) == 7 and all(reply.returncode == 0 for reply in observer_results), (result.stdout, result.stderr)
            acknowledgement = coordinator.finish_file(file_index=file_index, decoded_output=result.stdout, stream_completed=True)
            assert acknowledgement == f"X2DII_HOST_FILE_ACK:{file_index}:{hashlib.sha256(result.stdout).hexdigest()}\n".encode()
            assert coordinator.next_boundary == ((file_index + 1, 0) if file_index < 3 else None)
            assert target.is_file()
            assert hashlib.sha256(target.read_bytes()).hexdigest() == entry["sha256"]
    if not drift and session_kind == "menu_validation":
        before = payload_snapshot(installer)
        original_rc = (installer.root / "system/etc/init/camera-gui.rc").read_bytes()
        assert original_rc == peer.boot.STOCK.read_bytes()
        # Model only the next process's calling role; do not recreate any
        # component/process records or the four actually written payloads.
        (installer.root / "proc/self/attr/current").write_text("u:r:hbl_camera_service:s0\n")
        outcome = run_temporary(installer, temporary_os_boundary(installer))
        assert outcome.returncode == 0, (outcome.stdout, outcome.stderr)
        assert b"X2DII_TEMPORARY_CHILD_LOADED_NOT_FEATURE_VERIFIED" in outcome.stdout
        assert b"X2DII_ORIGINAL_GUI_RESTORED_EXTENSION_FILES_RETAINED_PENDING_SU_REMOVAL" in outcome.stdout
        assert b"COVERAGE_UNVERIFIED_NOT_REMOVAL_AUTHORITY" in outcome.stdout
        assert payload_snapshot(installer) == before
        assert (installer.root / "system/etc/init/camera-gui.rc").read_bytes() == original_rc
        assert (installer.root / "gui-service-state").read_text() == "running"
        assert (installer.root / "proc/mounts").read_text() == installer.mount_line
