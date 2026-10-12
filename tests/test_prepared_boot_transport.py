"""Preparation then boot over real child pipes; native camera I/O is disabled."""
from datetime import datetime, timezone
import importlib
import io
import re
import subprocess
import tarfile

import pytest

from tests.test_release_lifecycle import installer
from tests.test_boot_host_transport import boot_case
from tests.test_preplacement_host_dialogue import interactive_process
from tests.test_menu_content_transport import native_fixture_source
from tests.test_stage_menu_delivery import maintenance_result
from tests.test_stage_peer_usb_access import recorded_launch_fixture
from tools import menu_content_transport as content, stage_menu_delivery as stage
from tools import delivery_files, prepare_peer_install as peer, session_context


def parent_plan_for(manifest):
    programs = peer.render_role_programs(manifest)
    assembled = delivery_files.assemble_role_delivery(manifest["candidate"], manifest["candidate_sha256"], programs)
    with tarfile.open(fileobj=io.BytesIO(assembled["archive_bytes"]), mode="r:") as reader:
        members = {entry.name: reader.extractfile(entry).read() for entry in reader.getmembers()
                   if entry.name != "members.json"}
    renderer = (peer.ROOT / "tools/prepare_peer_install.py").read_bytes()
    return stage.plan_compressed_role_staging(members=members, candidate=manifest["candidate"],
        candidate_sha256=manifest["candidate_sha256"], script_hashes={key: peer.sha(value.encode()) for key, value in programs.items()},
        renderer_source=renderer, renderer_source_sha256=peer.sha(renderer), delivery_identity=assembled["delivery_identity"])


def preparation_case(installer, action):
    source, epoch, scripts, lines, output, raw, options, responses = boot_case(installer, action=action)
    manifest = installer.manifest
    parent = parent_plan_for(manifest)
    prepared = content.plan_boot_preparation(parent, manifest, raw, action=action,
        payload_identities=options["payload_identities"])
    report = recorded_launch_fixture()
    report["commands"][0]["utc"] = datetime.fromtimestamp(epoch, timezone.utc).isoformat()
    report["bootId"] = session_context.decode_session(raw)["boot_id"]
    return prepared, report, epoch, scripts, responses, options


@pytest.mark.parametrize("action", ("activate", "restore"))
@pytest.mark.parametrize("fault", ("none", "preparation", "preparation-cleanup", "expired-before-worker"))
def test_prepared_boot_uses_same_launch_and_does_not_start_worker_after_failed_preparation(
        installer, tmp_path, action, fault):
    module = importlib.import_module("tools.menu_prepared_transport")
    prepared, report, epoch, scripts, responses, options = preparation_case(installer, action)
    now, launches = [epoch], []
    operation = module.PreparedBootOperation(prepared, backup_identity=options["backup_identity"], clock=lambda: now[0])

    class Maintenance:
        def command(self, label, command):
            if label.startswith("prepare-observer-"):
                expected = operation.coordinator.next_preparation
                assert expected.command == command
                return expected.expected_stdout  # External pre-window file transport boundary only.
            if label.startswith("content-observe-"):
                if fault == "preparation":
                    raise OSError("injected preparation transport failure")
                index = int(label.rsplit("-", 1)[1])
                expected = operation.coordinator.observer.observations[index]
                assert expected.command == command
                actual = maintenance_result(expected, prepared.session, observer=operation.coordinator.observer, epoch=epoch)
                assert actual.returncode == 0, actual.stderr
                return actual.stdout
            return responses[command]

    def start_process(phase, source):
        launches.append(phase)
        # Both actual generated sources retain the original pre-command time.
        launch_name = "ContentLaunchEpoch" if phase == "preparation" else "OriginalWindowLaunch"
        assert f"{launch_name} = {epoch}" in source
        if phase == "preparation":
            steps = stage.execution_steps(prepared.plan, dict(prepared.session.context), session=prepared.session)
            rendered = native_fixture_source(source, steps, prepared.session, fault="none", epoch=epoch)
            namespace = re.search(r"namespace (X2d2ContentStage_[a-f0-9]+)", rendered)[1]
            file = tmp_path / "prepared-native-disabled.cs"
            file.write_text(rendered, encoding="utf-8")
            script = f"$ErrorActionPreference='Stop';Add-Type -Path '{file}';[{namespace}.AdbUsbCheck]::RunContentStage()"
            process = subprocess.Popen(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if fault == "preparation-cleanup":
                class CloseFailure:
                    def __init__(self, stream):
                        self.stream = stream
                    def __getattr__(self, name):
                        return getattr(self.stream, name)
                    def close(self):
                        self.stream.close()
                        raise OSError("injected preparation pipe close failure")
                process.stdin = CloseFailure(process.stdin)
            if fault == "expired-before-worker":
                real_wait = process.wait
                def waited(*args, **kwargs):
                    result = real_wait(*args, **kwargs)
                    now[0] = epoch + 81
                    return result
                process.wait = waited
            return process
        return interactive_process(source, epoch, scripts, tmp_path)

    maintenance = Maintenance()
    operation.prepare_observer(maintenance)
    if fault == "none":
        result = operation.run(report, maintenance, start_process)
        assert launches == ["preparation", "boot-" + action]
        assert result["status"] == "PREPARED_BOOT_FILE_TRANSACTION_NOT_LIFECYCLE_VALIDATED"
        assert result["session_data_sha256"] == peer.sha(prepared.raw_session)
        assert result["launch_started_utc"] == report["commands"][0]["utc"]
        assert not result["installable"] and not result["usb_restore_verified"]
    else:
        with pytest.raises((OSError, ValueError)) as caught:
            operation.run(report, maintenance, start_process)
        assert launches == ["preparation"] and operation.failed
        evidence = caught.value.prepared_operation_evidence
        assert evidence["phase"] == ("before-worker" if fault == "expired-before-worker" else "preparation")
        assert (evidence["preparation_result"] is not None) == (fault != "preparation")
        if fault == "preparation-cleanup":
            assert evidence["cleanup_errors"] == [{"step": "close-host-stdin", "error": "injected preparation pipe close failure"}]
    with pytest.raises(ValueError, match="already attempted|failed"):
        operation.run(report, maintenance, start_process)


@pytest.mark.parametrize("fault", ("boot", "failed-launch"))
def test_prepared_boot_rejects_wrong_boot_or_failed_session_before_any_child_start(installer, fault):
    module = importlib.import_module("tools.menu_prepared_transport")
    prepared, report, epoch, _, _, options = preparation_case(installer, "restore")
    operation = module.PreparedBootOperation(prepared, backup_identity=options["backup_identity"], clock=lambda: epoch)
    class Maintenance:
        def command(self, label, command):
            return operation.coordinator.next_preparation.expected_stdout
    operation.prepare_observer(Maintenance())
    if fault == "boot":
        report["bootId"] = "f0000000-0000-0000-0000-000000000001"
    else:
        report["status"] = "FAILED_OR_UNCERTAIN_DO_NOT_RETRY_AUTOMATICALLY"
    def forbidden(*args):
        raise AssertionError("child must not start")
    with pytest.raises(ValueError, match="boot|launch"):
        operation.run(report, Maintenance(), forbidden)
    assert operation.failed


@pytest.mark.parametrize("fault", ("stager", "decoder", "missing", "extra", "collector", "transport"))
def test_prepared_boot_rejects_unbound_saved_launch_sources(installer, fault):
    module = importlib.import_module("tools.menu_prepared_transport")
    prepared, report, epoch, _, _, options = preparation_case(installer, "restore")
    operation = module.PreparedBootOperation(prepared, backup_identity=options["backup_identity"], clock=lambda: epoch)
    class Maintenance:
        def command(self, label, command):
            return operation.coordinator.next_preparation.expected_stdout
    operation.prepare_observer(Maintenance())
    if fault == "stager":
        report["stagerSha256"] = "0" * 64
    elif fault == "decoder":
        report["replySources"]["replyDecoderSha256"] = "0" * 64
    elif fault == "missing":
        del report["replySources"]
    elif fault == "extra":
        report["replySources"]["unreviewedProducer"] = "0" * 64
    else:
        report["replySources"][fault + "Sha256"] = "0" * 64
    def forbidden(*args):
        raise AssertionError("unattributed launch reached a child")
    with pytest.raises(ValueError, match="source attribution"):
        operation.run(report, Maintenance(), forbidden)
    assert operation.failed
