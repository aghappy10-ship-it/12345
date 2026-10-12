"""One actual staged content set across role/session transitions, no camera.

Only OS roots, ownership/labels, process observations and host waits are modeled. Original
archive-extracted programs are never regenerated or replaced during execution;
separate host copies implement the already existing OS-path adapters.
"""
from datetime import timedelta
from dataclasses import replace
import io
import json
from pathlib import Path
import tarfile
import tempfile
from unittest import mock

import pytest

from tests.test_release_lifecycle import installer
from tests.test_compressed_role_staging import role_shell
from tests.test_menu_supervision import dialogue
from tests.test_menu_maintenance_boundary import execute_observer
from tests.test_menu_boot_boundary import execute_boot_observer
from tests.test_menu_boot_file import boot_dialogue, recovery_data
from tests.test_temporary_domain_integration import payload_snapshot
from tests.test_temporary_menu_session import (prepare_maintenance, temporary_values,
                                              temporary_os_boundary)
from tests.test_menu_lifecycle_transport import (background_fixture, read_until_final,
                                                _retain_guardian_failure, _cleanup_guardian_fixture)
from tools import prepare_peer_install as peer, session_context as sc
from tools import delivery_files, stage_menu_delivery as stage
from tools import menu_maintenance_boundary as file_boundary, menu_boot_boundary as boot_boundary
from tools import menu_preplacement_transport as file_transport, menu_boot_transport as boot_transport


def snapshot(paths):
    return {str(path): (path.stat().st_ino, path.stat().st_mtime_ns, path.read_bytes()) for path in paths}


def test_same_staged_programs_survive_temporary_gui_then_fresh_activation_and_recovery(installer):
    try:
        _run_same_staged_programs_survive_temporary_gui_then_fresh_activation_and_recovery(installer)
    except BaseException as failure:
        try:
            _retain_guardian_failure(installer, failure)
        except BaseException as diagnostic_failure:
            try:
                failure.add_note("Role failure diagnostics incomplete: " + type(diagnostic_failure).__name__)
            except BaseException:
                pass
        raise
    finally:
        _cleanup_guardian_fixture(installer)


class _FaultingManifestInstaller:
    def __init__(self, root, failure):
        self.root = root
        self.failure = failure

    @property
    def manifest(self):
        raise self.failure


def test_missing_role_failure_tree_does_not_replace_original_error():
    failure = RuntimeError("original role failure")
    with tempfile.TemporaryDirectory(prefix="role-retention-test-", dir=peer.ROOT / "build") as fixture_root:
        installer = _FaultingManifestInstaller(Path(fixture_root) / "missing-tree", failure)
        with pytest.raises(BaseException) as caught:
            test_same_staged_programs_survive_temporary_gui_then_fresh_activation_and_recovery(installer)
    assert caught.value is failure
    assert any("diagnostics incomplete" in note for note in failure.__notes__)


def test_successful_role_failure_retention_preserves_original_error_and_actual_tree():
    failure = RuntimeError("original role failure")
    with tempfile.TemporaryDirectory(prefix="role-retention-test-", dir=peer.ROOT / "build") as fixture_root:
        root = Path(fixture_root)
        (root / "final-observation.txt").write_bytes(b"actual last fixture state\n")
        installer = _FaultingManifestInstaller(root, failure)
        with pytest.raises(BaseException) as caught:
            test_same_staged_programs_survive_temporary_gui_then_fresh_activation_and_recovery(installer)
    assert caught.value is failure
    prefix = "Preserved local-only guardian fixture: "
    retained = Path(next(note.removeprefix(prefix) for note in failure.__notes__ if note.startswith(prefix)))
    assert (retained / "final-observation.txt").read_bytes() == b"actual last fixture state\n"


def test_role_failure_note_error_does_not_replace_original_error():
    class NoteFailure(RuntimeError):
        def add_note(self, note):
            raise OSError("diagnostic note unavailable")

    failure = NoteFailure("original role failure")
    with tempfile.TemporaryDirectory(prefix="role-retention-test-", dir=peer.ROOT / "build") as fixture_root:
        installer = _FaultingManifestInstaller(Path(fixture_root), failure)
        with pytest.raises(BaseException) as caught:
            test_same_staged_programs_survive_temporary_gui_then_fresh_activation_and_recovery(installer)
    assert caught.value is failure


@pytest.mark.parametrize("primary_failure", (False, True))
def test_role_wrapper_always_cleans_exact_lifetimes_without_hiding_failure(tmp_path, primary_failure):
    proc = tmp_path / "proc" / "101"
    proc.mkdir(parents=True)
    (proc / "host-shell").write_text("captured host lifetime")
    (proc / "host-stat").write_text("fixture snapshot never sent to an actual process")
    failure = RuntimeError("original role failure")
    installer = _FaultingManifestInstaller(tmp_path, failure)
    with mock.patch(__name__ + "._run_same_staged_programs_survive_temporary_gui_then_fresh_activation_and_recovery",
                    side_effect=failure if primary_failure else None), \
         mock.patch("tests.test_menu_lifecycle_transport._signal_exact_host_lifetime",
                    side_effect=OSError("exact cleanup unavailable")) as signal:
        with pytest.raises(RuntimeError) as caught:
            test_same_staged_programs_survive_temporary_gui_then_fresh_activation_and_recovery(installer)
        assert signal.call_count == 1
        if primary_failure:
            assert caught.value is failure
            assert any("cleanup incomplete" in note for note in failure.__notes__)
        else:
            assert "cleanup incomplete" in str(caught.value)


def _run_same_staged_programs_survive_temporary_gui_then_fresh_activation_and_recovery(installer):
    manifest = installer.manifest
    programs = peer.render_role_programs(manifest)
    assembled = delivery_files.assemble_role_delivery(manifest["candidate"], manifest["candidate_sha256"], programs)
    with tarfile.open(fileobj=io.BytesIO(assembled["archive_bytes"]), mode="r:") as reader:
        members = {entry.name: reader.extractfile(entry).read() for entry in reader.getmembers()
                   if entry.name != "members.json"}
    renderer_source = (peer.ROOT / "tools/prepare_peer_install.py").read_bytes()
    plan = stage.plan_compressed_role_staging(members=members, candidate=manifest["candidate"],
        candidate_sha256=manifest["candidate_sha256"], script_hashes={name: peer.sha(raw.encode()) for name, raw in programs.items()},
        renderer_source=renderer_source, renderer_source_sha256=peer.sha(renderer_source),
        delivery_identity=assembled["delivery_identity"])
    destination, shell = role_shell(installer.root, plan)
    installer.shell_fixture(stage_inputs=False)
    assert not destination.exists(), "the OS fixture must not pre-generate stage members"
    prepare_maintenance(installer, preplace=False)
    (installer.root / "proc/self/attr/current").write_text("u:r:su:s0\n")
    (installer.root / "proc/234/environ").write_bytes(b"XDG_RUNTIME_DIR=/tmp\0")
    temporary = sc.encode_session(temporary_values(installer), schema=sc.MENU_VALIDATION_SCHEMA)
    values = sc.decode_session(temporary)

    def run_steps(steps, raw_session):
        current = sc.decode_session(raw_session)
        os_boundary = f'''id() {{ echo 0; }}
date() {{ echo {current['observed_epoch']}; }}
cat() {{ case "$1" in
 /proc/self/attr/current) echo u:r:su:s0;;
 /proc/sys/kernel/random/boot_id) echo {current['boot_id']};;
 *) command cat "$@";; esac; }}
readlink() {{ case "$1" in
 /proc/self/ns/mnt) echo '{current['mount_namespace']}';;
 /proc/1/ns/mnt) return 93;;
 *) command readlink "$@";; esac; }}
'''
        for step in steps:
            # role_shell predates /tmp support staging and maps only /blackbox.
            # Keep the new fixed /tmp writes inside this same test's OS root.
            scoped = replace(step, command=step.command.replace("/tmp", installer.posix + "/tmp"))
            result = shell(scoped, os_boundary)
            assert result.returncode == 0 and result.stderr == "", (step.label, result.stdout, result.stderr)
            assert result.stdout.replace(installer.posix + "/blackbox", "/blackbox").replace(
                installer.posix + "/tmp", "/tmp") == step.expected_stdout

    run_steps(plan.steps, temporary)
    assert (destination / ".content.tar").read_bytes() == assembled["archive_bytes"]
    formal_files = [destination / name for name in plan.member_names]
    formal_before = snapshot(formal_files)
    # Code preparation and fresh execution are different windows. This OS
    # harness does not simulate USB wall-clock budgets or establish a live lease.
    code_values = dict(values, session_nonce="a" * 32)
    code_raw = sc.encode_session(code_values, schema=sc.MENU_VALIDATION_SCHEMA)
    temporary_workers = stage.plan_menu_validation_worker_staging(plan, manifest, code_raw)
    run_steps(temporary_workers.steps, code_raw)
    support = stage.plan_menu_support_staging(plan, manifest, code_raw)
    run_steps(support.steps, code_raw)
    run_steps(stage.plan_raw_session_staging(plan, manifest, temporary).steps, temporary)
    retained_paths = [*formal_files, *(installer.root / path.lstrip("/") for path, _ in temporary_workers.files),
                      *(installer.root / path.lstrip("/") for path, _ in support.files),
                      installer.root / file_boundary.session_path(manifest, peer.sha(temporary)).lstrip("/")]
    retained = snapshot(retained_paths)
    coordinator = file_transport.PreplacementCoordinator(manifest, temporary)

    def respond_file(index, unused_ack, request_values):
        fixed = file_boundary.paths(manifest, file_index, index, session_data_sha256=peer.sha(temporary), session_kind="menu_validation")
        request = (installer.root / fixed["request"].lstrip("/")).read_bytes()
        coordinator.begin_boundary(f"X2DII_HOST_BOUNDARY:{file_index}:{index}:{peer.sha(request)}")
        reply = execute_observer(installer, temporary, request, file_index=file_index, boundary_index=index,
                                 staged_program=True)
        assert reply.returncode == 0, (reply.stdout, reply.stderr)
        return coordinator.accept_reply(reply.stdout, received_epoch=values["observed_epoch"])

    for file_index in range(4):
        result, observations = dialogue(installer, setup=False, values=values, file_index=file_index,
            reply=respond_file, wrap_status=True, session_kind="menu_validation", staged_program=True,
            host_wait_seconds=30)
        assert result.returncode == 0, (result.stdout, result.stderr)
        assert len(observations) == 7
        coordinator.finish_file(file_index=file_index, decoded_output=result.stdout, stream_completed=True)
        assert snapshot(retained_paths) == retained
    identities = coordinator.completed_identities
    assert len(identities) == 4
    payloads = payload_snapshot(installer)
    (installer.root / "proc/self/attr/current").write_text("u:r:hbl_camera_service:s0\n")
    _, fixed_lifecycle, _, run_lifecycle = background_fixture(installer, setup=False,
        raw_session=temporary, staged_programs=True)
    started = run_lifecycle("launch")
    assert started.returncode == 0, (started.stdout, started.stderr)
    assert ":0:NOT_FEATURE_VALIDATED\n" in read_until_final(run_lifecycle)
    lifecycle_log = installer.root / fixed_lifecycle["run"].lstrip("/") / "lifecycle.log"
    assert b"X2DII_ORIGINAL_GUI_RESTORED_EXTENSION_FILES_RETAINED_PENDING_SU_REMOVAL" in lifecycle_log.read_bytes()
    assert payload_snapshot(installer) == payloads and snapshot(retained_paths) == retained
    (installer.root / "proc/self/attr/current").write_text("u:r:su:s0\n")
    installer.q["session_nonce"] = "d" * 32
    installer.q["observed_utc"] = (peer.datetime.fromisoformat(installer.q["observed_utc"]) + timedelta(seconds=1)).isoformat()
    install_raw = peer.session_data(manifest, installer.q)
    run_steps(stage.plan_raw_session_staging(plan, manifest, install_raw).steps, install_raw)
    dependencies = stage.plan_boot_payload_identity_staging(plan, manifest, install_raw, identities)
    run_steps(dependencies.steps, install_raw)

    def run_boot(action, raw, backup=None):
        # Each fresh action delivers its own actual observer; temporary support
        # neither consumes nor pre-stages the independent a/r boot programs.
        observer = stage.plan_boot_observer_staging(plan, manifest, raw, action=action)
        (observer_path, observer_bytes), = observer.files
        observer_file = installer.root / observer_path.lstrip("/")
        assert not observer_file.exists()
        run_steps(observer.steps, raw)
        assert observer_file.read_bytes() == observer_bytes
        observer_before = snapshot([observer_file])
        current = sc.decode_session(raw)
        boot = boot_transport.BootCoordinator(manifest, raw, action=action,
            payload_identities=identities if action == "activate" else None, backup_identity=backup)

        def respond(index, unused_ack, request_values):
            fixed = boot_boundary.paths(manifest, action, index,
                session_nonce=current["session_nonce"], session_data_sha256=peer.sha(raw))
            request = (installer.root / fixed["request"].lstrip("/")).read_bytes()
            boot.begin_boundary(f"X2DII_HOST_BOOT_BOUNDARY:{action}:{index}:{peer.sha(request)}")
            reply = execute_boot_observer(installer, raw, request, action=action, index=index,
                                          staged_program=True)
            assert reply.returncode == 0, (reply.stdout, reply.stderr)
            return boot.accept_reply(reply.stdout, received_epoch=current["observed_epoch"])

        result, observations = boot_dialogue(installer, setup=False, action=action, raw=raw,
            reply=respond, backup_identity=backup, staged_program=True, wrap_status=True,
            host_wait_seconds=30)
        assert result.returncode == 0, (result.stdout, result.stderr)
        boot.finish(decoded_output=result.stdout, stream_completed=True)
        assert snapshot(formal_files) == formal_before
        assert snapshot([observer_file]) == observer_before
        return boot.completed_receipt

    activation = run_boot("activate", install_raw)
    assert (installer.root / peer.boot.TARGET.lstrip("/")).read_bytes() == peer.boot.activate(peer.boot.STOCK.read_bytes())
    recovery_values = sc.decode_session(recovery_data(installer))
    recovery_values.update(session_nonce="e" * 32, recovery_nonce="e" * 32)
    recovery_raw = sc.encode_session(recovery_values)
    run_steps(stage.plan_raw_session_staging(plan, manifest, recovery_raw).steps, recovery_raw)
    restored = run_boot("restore", recovery_raw, activation["backup_identity"])
    assert restored["backup_identity"] == activation["backup_identity"]
    assert (installer.root / peer.boot.TARGET.lstrip("/")).read_bytes() == peer.boot.STOCK.read_bytes()
    assert payload_snapshot(installer) == payloads and snapshot(retained_paths) == retained
    assert (installer.root / "proc/mounts").read_text() == installer.mount_line

    # Explicit new-boot OS model: old /tmp is unavailable, and old leases are
    # not reused. Keep the old fixture directory for inspection, not deletion.
    # This does not claim an actual camera reboot or physical menu/capture use.
    from tools import menu_stock_boot as stock, menu_content_transport as content
    from tests.test_menu_stock_boot import DeviceBoundary
    from tests.test_menu_owned_cleanup import run_four_file_dialogue
    (installer.root / "tmp").rename(installer.root / "tmp-retained-priorboot")
    (installer.root / "tmp").mkdir()
    fresh_values = dict(recovery_values, boot_id="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        session_nonce="f" * 32, recovery_nonce="f" * 32, gui_state="present",
        gui_service_state="running", gui_pid=234, gui_start_ticks="4567",
        gui_exe_target="/system/bin/camera-gui", gui_exe_sha256=manifest["candidate"]["gui_sha256"],
        gui_domain="u:r:hbl_camera_service:s0", gui_mount_namespace=recovery_values["mount_namespace"],
        rc_sha256=manifest["candidate"]["rc"]["before"])
    fresh_raw = sc.encode_session(fresh_values)
    saved_manifest = json.dumps(manifest, sort_keys=True).encode()
    stock_readback = stock.observe_stock_boot(saved_manifest, peer.sha(saved_manifest), recovery_raw,
        restored, fresh_raw, DeviceBoundary(manifest, fresh_values), clock=lambda: fresh_values["observed_epoch"])
    assert stock_readback["status"] == "OBSERVED_STOCK_GUI_NOT_FUNCTION_VERIFIED"
    # Only modeled kernel state changes after the reboot. Exact previously
    # placed payloads, rc transaction bytes and original inode receipts remain.
    (installer.root / "proc/sys/kernel/random/boot_id").write_text(fresh_values["boot_id"] + "\n")
    (installer.root / "proc/100/attr/current").write_text("u:r:hbl_camera_service:s0\n")
    (installer.root / "proc/1").mkdir(exist_ok=True)
    for proc in (installer.root / "proc").iterdir():
        if proc.name.isdigit():
            if not (proc / "stat").exists():
                (proc / "stat").write_text(proc.name + " (init) S " + "0 " * 18 + "456 0\n")
            (proc / "maps").write_bytes(b"1000-2000 r-xp 00000000 08:01 19 /system/bin/original\n")
    (installer.root / "proc/234/stat").write_text("234 (camera-gui) S " + "0 " * 18 + "4567 0\n")
    (installer.root / "proc/234/environ").write_bytes(b"XDG_RUNTIME_DIR=/tmp\0")
    (installer.root / "proc/mounts").write_text(installer.mount_line +
        f"proc {installer.posix}/proc proc rw,nosuid,nodev,noexec 0 0\n")
    cleanup_plan = content.plan_cleanup_preparation(plan, manifest, fresh_raw, identities, stock_readback, restored)
    run_steps(cleanup_plan.plan.steps, fresh_raw)
    cleaned = run_four_file_dialogue(installer, fresh_raw, identities, stock_readback, restored)
    assert len(cleaned) == 4
    assert snapshot(formal_files) == formal_before
