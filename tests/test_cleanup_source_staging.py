"""Only the exact owned-cleanup sources are staged; no cleanup is executed."""
from dataclasses import replace
from datetime import datetime, timezone
import io
import re
import shlex
import subprocess
import tarfile

import pytest

from tests.test_release_lifecycle import installer
from tests.test_menu_owned_cleanup import cleanup_inputs
from tests.test_raw_session_staging import raw_shell, sha
from tools import stage_menu_delivery as stage, prepare_peer_install as peer, delivery_files
from tools import menu_owned_cleanup as cleanup
from tools import menu_content_transport as transport
from tests.test_menu_content_transport import native_fixture_source
from tests.test_stage_menu_delivery import maintenance_result


def cleanup_fixture(installer):
    manifest = installer.manifest
    programs = peer.render_role_programs(manifest)
    assembly = delivery_files.assemble_role_delivery(manifest['candidate'], manifest['candidate_sha256'], programs)
    with tarfile.open(fileobj=io.BytesIO(assembly['archive_bytes'])) as reader:
        members = {item.name: reader.extractfile(item).read() for item in reader.getmembers() if item.name != 'members.json'}
    renderer = (peer.ROOT / 'tools/prepare_peer_install.py').read_bytes()
    plan = stage.plan_compressed_role_staging(members=members, candidate=manifest['candidate'],
        candidate_sha256=manifest['candidate_sha256'], script_hashes={k: sha(v.encode()) for k,v in programs.items()},
        renderer_source=renderer, renderer_source_sha256=sha(renderer))
    args = cleanup_inputs(installer)
    return plan, manifest, args


@pytest.mark.parametrize('existing', (None, 'worker', 'observer'))
def test_exact_five_cleanup_sources_and_unknown_targets(tmp_path, installer, existing):
    plan, manifest, args = cleanup_fixture(installer)
    prepared = stage.plan_owned_cleanup_staging(plan, manifest, *args)
    destination, original_run = raw_shell(tmp_path, plan, args[0])
    camera_tmp = tmp_path / 'camera-tmp'
    camera_tmp.mkdir()
    posix = subprocess.run(['C:/Program Files/Git/bin/sh.exe', '-c', 'cygpath -u "$1"', 'test', str(camera_tmp)],
                            capture_output=True, text=True, check=True).stdout.strip()
    assert dict(prepared.files) == cleanup.render_programs(manifest, *args)
    def local(path):
        return (camera_tmp / path.removeprefix('/tmp/')) if path.startswith('/tmp/') else (destination / path.rsplit('/',1)[1])
    victim = None
    if existing is not None:
        victim = local(prepared.files[0 if existing == 'worker' else 4][0])
        victim.parent.mkdir(parents=True, exist_ok=True)
        victim.write_bytes(b'UNKNOWN KEEP')
    for operation in prepared.steps:
        result = original_run(replace(operation, command=operation.command.replace('/tmp', shlex.quote(posix))))
        result.stdout = result.stdout.replace(posix, '/tmp')
        if victim is not None:
            assert result.returncode != 0 and victim.read_bytes() == b'UNKNOWN KEEP'
            return
        assert result.returncode == 0 and not result.stderr, (operation.label, result.stderr)
        assert result.stdout == operation.expected_stdout
    assert all(local(path).read_bytes() == raw for path,raw in prepared.files)
    assert not prepared.installable


def test_cleanup_preparation_binds_exact_raw_and_sources_without_renewing_recovery(installer):
    plan, manifest, args = cleanup_fixture(installer)
    prepared = transport.plan_cleanup_preparation(plan, manifest, *args)
    assert prepared.purpose == 'owned_cleanup_preparation'
    assert prepared.raw_session == prepared.session.data == args[0]
    assert prepared.payload_identities == args[1]
    assert prepared.parent_plan == plan and prepared.plan.phase == 'second-window-preparation'
    assert len(prepared.plan.steps) == 2 + len(stage.plan_owned_cleanup_staging(plan, manifest, *args).steps)
    assert not prepared.installable
    for damaged in (replace(prepared, cleanup_evidence=b'{}'), replace(prepared, payload_identities=args[1][:3]),
                    replace(prepared, raw_session=args[0] + b'\n'), replace(prepared, purpose='boot_recovery_preparation')):
        with pytest.raises(ValueError):
            transport.SecondWindowPreparationCoordinator(damaged)


@pytest.mark.parametrize('replacement', (False, True))
def test_cleanup_tar_preserves_late_new_or_replaced_member(tmp_path, installer, replacement):
    plan, manifest, args = cleanup_fixture(installer)
    prepared = stage.plan_owned_cleanup_staging(plan, manifest, *args)
    destination, original_run = raw_shell(tmp_path, plan, args[0])
    camera_tmp = tmp_path / 'camera-tmp'
    camera_tmp.mkdir()
    def posix(path):
        return subprocess.run(['C:/Program Files/Git/bin/sh.exe', '-c', 'cygpath -u "$1"', 'test', str(path)],
                              capture_output=True, text=True, check=True).stdout.strip()
    tmp = posix(camera_tmp)
    victim = destination / prepared.files[0 if replacement else 1][0].rsplit('/', 1)[1]
    target = posix(victim)
    reached = False
    for operation in prepared.steps:
        hook = ''
        if operation.label == 'extract-fixed-cleanup-sources':
            reached = True
            move = f'command mv {shlex.quote(target)} {shlex.quote(target + ".retained")} || return 17;' if replacement else ''
            hook = f'''tar() {{
if [ "$3" = cleanup-0 ]; then
 {move}
 printf UNKNOWN >{shlex.quote(target)} || return 18
fi
command tar "$@"
}}
'''
        result = original_run(replace(operation, command=operation.command.replace('/tmp', shlex.quote(tmp))), hook)
        result.stdout = result.stdout.replace(tmp, '/tmp')
        if reached:
            assert victim.read_bytes() == b'UNKNOWN'
        if result.returncode != 0 or result.stdout != operation.expected_stdout:
            assert reached
            return
    pytest.fail('late cleanup source replacement was accepted')


def test_cleanup_preparation_actual_native_disabled_child_keeps_original_deadline(tmp_path, installer):
    plan, manifest, args = cleanup_fixture(installer)
    prepared = transport.plan_cleanup_preparation(plan, manifest, *args)
    session = prepared.session
    now = session.observed_epoch
    host = transport.SecondWindowPreparationCoordinator(prepared, clock=lambda: now)
    while (operation := host.next_preparation) is not None:
        host.accept_preparation(exit_code=0, stdout=operation.expected_stdout, completion_validated=True)
    launch = datetime.fromtimestamp(now, timezone.utc)
    host.start_window(launch)
    source = transport.review_preparation_host_source(prepared, launch)
    assert 'ContentQualified = false' in source
    steps = stage.execution_steps(prepared.plan, dict(session.context), session=session)
    source = native_fixture_source(source, steps, session, fault='none', epoch=now)
    namespace = re.search(r'namespace (X2d2ContentStage_[a-f0-9]+)', source)[1]
    filename = tmp_path / 'cleanup-preparation-native-disabled.cs'
    filename.write_text(source, encoding='utf-8')
    script = f"$ErrorActionPreference='Stop';Add-Type -Path '{filename}';[{namespace}.AdbUsbCheck]::RunContentStage()"
    process = subprocess.Popen(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    class Maintenance:
        count = 0
        def command(self, label, command):
            operation = host.observer.observations[self.count]
            assert command == operation.command
            self.count += 1
            result = maintenance_result(operation, session, observer=host.observer, epoch=now)
            assert result.returncode == 0 and not result.stderr
            return result.stdout
    maintenance = Maintenance()
    try:
        result = transport.drive_preparation_process(process, host, maintenance)
        assert result['purpose'] == 'owned_cleanup_preparation' and result['worker_followup_allowed']
        assert result['status'] == 'OWNED_CLEANUP_SOURCES_STAGED_NOT_EXECUTED_USB_RESTORE_UNVERIFIED'
        assert not result['installable'] and maintenance.count == len(steps)
        assert host.all_results_validated and host.remaining_window_seconds() == 80
    finally:
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=5)
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()
