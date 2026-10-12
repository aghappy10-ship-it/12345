"""Actual child pipes for cleanup preparation/execution; all native I/O disabled."""
from datetime import datetime, timezone
import importlib
import re
import subprocess

import pytest

from tests.test_release_lifecycle import installer
from tests.test_menu_cleanup_transport import cleanup_wire_case
from tests.test_prepared_boot_transport import parent_plan_for, preparation_case
from tests.test_preplacement_host_dialogue import interactive_process
from tests.test_menu_content_transport import native_fixture_source
from tests.test_stage_menu_delivery import maintenance_result
from tests.test_stage_peer_usb_access import recorded_launch_fixture
from tools import menu_content_transport as content, stage_menu_delivery as stage, session_context as sc


@pytest.mark.parametrize("fault", ("none", "preparation", "expired-before-worker", "second-file"))
def test_prepared_cleanup_uses_same_launch_and_retains_each_completed_removal(installer, tmp_path, fault):
    module = importlib.import_module("tools.menu_prepared_transport")
    _, epoch, scripts, _, responses, options, outputs = cleanup_wire_case(installer)
    prepared = content.plan_cleanup_preparation(parent_plan_for(installer.manifest), installer.manifest, *options)
    now, launches, boundaries = [epoch], [], []
    operation = module.PreparedCleanupOperation(prepared, clock=lambda: now[0])
    report = recorded_launch_fixture()
    report["bootId"] = sc.decode_session(prepared.raw_session)["boot_id"]
    report["commands"][0]["utc"] = datetime.fromtimestamp(epoch, timezone.utc).isoformat()

    class Maintenance:
        def command(self, label, command):
            if label.startswith("prepare-observer-"):
                step = operation.coordinator.next_preparation
                assert step.command == command
                return step.expected_stdout
            if label.startswith("content-observe-"):
                if fault == "preparation":
                    raise OSError("cleanup preparation transport failed")
                step = operation.coordinator.observer.observations[int(label.rsplit("-", 1)[1])]
                assert step.command == command
                result = maintenance_result(step, prepared.session, observer=operation.coordinator.observer, epoch=epoch)
                assert result.returncode == 0, result.stderr
                return result.stdout
            boundaries.append(command)
            if fault == "second-file" and len(boundaries) == 5:
                raise OSError("cleanup failed after first removal")
            return responses[command]

    def start_process(phase, source):
        launches.append(phase)
        constant = "ContentLaunchEpoch" if phase == "preparation" else "OriginalWindowLaunch"
        assert f"{constant} = {epoch}" in source
        if phase == "preparation":
            steps = stage.execution_steps(prepared.plan, dict(prepared.session.context), session=prepared.session)
            rendered = native_fixture_source(source, steps, prepared.session, fault="none", epoch=epoch)
            namespace = re.search(r"namespace (X2d2ContentStage_[a-f0-9]+)", rendered)[1]
            path = tmp_path / "cleanup-preparation-native-disabled.cs"
            path.write_text(rendered, encoding="utf-8")
            script = f"$ErrorActionPreference='Stop';Add-Type -Path '{path}';[{namespace}.AdbUsbCheck]::RunContentStage()"
            process = subprocess.Popen(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if fault == "expired-before-worker":
                real_wait = process.wait
                def waited(*args, **kwargs):
                    result = real_wait(*args, **kwargs)
                    now[0] = epoch + 81
                    return result
                process.wait = waited
            return process
        assert phase == "owned-cleanup"
        return interactive_process(source, epoch, scripts, tmp_path)

    maintenance = Maintenance()
    operation.prepare_observer(maintenance)
    if fault == "none":
        result = operation.run(report, maintenance, start_process)
        assert launches == ["preparation", "owned-cleanup"] and len(boundaries) == 16
        assert result["status"] == "PREPARED_FOUR_OWNED_FILES_REMOVED_NOT_FUNCTION_VALIDATED"
        assert len(result["worker_result"]["completed_receipts"]) == 4
        assert result["worker_result"]["worker_outputs"] == tuple(outputs)
        assert not result["installable"] and not result["usb_restore_verified"]
        assert result["preparation_result"]["launch_started_utc"] == result["launch_started_utc"]
    else:
        with pytest.raises((ValueError, OSError)) as caught:
            operation.run(report, maintenance, start_process)
        evidence = caught.value.prepared_operation_evidence
        assert operation.failed
        if fault == "second-file":
            assert str(caught.value) == "cleanup failed after first removal"
            assert launches == ["preparation", "owned-cleanup"]
            assert len(caught.value.partial_evidence["completed_receipts"]) == 1
            assert caught.value.partial_evidence["worker_outputs"][0] == outputs[0]
            assert evidence["phase"] == "owned-cleanup"
        else:
            assert launches == ["preparation"] and not boundaries
            assert evidence["phase"] == ("preparation" if fault == "preparation" else "before-worker")
    with pytest.raises(ValueError, match="already attempted|failed"):
        operation.run(report, maintenance, start_process)


def test_prepared_cleanup_cannot_reinterpret_boot_restoration_as_removal(installer):
    module = importlib.import_module("tools.menu_prepared_transport")
    prepared, _, epoch, _, _, _ = preparation_case(installer, "restore")
    with pytest.raises(ValueError, match="fixed cleanup preparation"):
        module.PreparedCleanupOperation(prepared, clock=lambda: epoch)
