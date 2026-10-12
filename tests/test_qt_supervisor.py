"""Real child-process failures may never be promoted from observations to PASS."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

import pytest

from tools.output_guard import PROJECT, output_directory, write_output
from tools.qt_supervisor import PENDING, supervise_worker


@pytest.fixture
def workspace():
    output_directory(PROJECT / "build/supervisor-tests")
    # Preserve each run as diagnostic evidence, including intentional failures.
    return Path(tempfile.mkdtemp(prefix="case-", dir=PROJECT / "build/supervisor-tests"))


def worker(workspace, body):
    prefix = """import json, sys, time
from pathlib import Path
from tools.output_guard import write_output
run = Path(sys.argv[2])
print('captured stdout', flush=True)
print('captured stderr', file=sys.stderr, flush=True)
observations = {'result':'EXECUTED_PENDING_PROCESS_EXIT','installable':False,'cameraAccesses':0,'scope':'supervisor-fixture','workerOptimize':sys.flags.optimize}
def observe():
    write_output(run / 'observations.json', json.dumps(observations).encode())
"""
    return write_output(workspace / "worker.py", (prefix + body + "\n").encode())


def run_worker(workspace, body, *, timeout=10, inputs=()):
    script = worker(workspace, body)
    name = "supervisor-test-" + workspace.name + ".json"
    write_output(PROJECT / "build" / name, b'{"result":"PASS","stale":true}')
    before_qt = {name for name in sys.modules if name.startswith(("PySide6", "shiboken6"))}
    report = supervise_worker(script, name, "supervisor-test-runs", timeout, input_paths=inputs)
    assert {name for name in sys.modules if name.startswith(("PySide6", "shiboken6"))} == before_qt
    assert json.loads((PROJECT / "build" / name).read_text()) == report
    run_dir = Path(report["runDirectory"])
    assert json.loads((run_dir / "RESULT.json").read_text()) == report
    assert "captured stdout" in (run_dir / "stdout.txt").read_text()
    assert "captured stderr" in (run_dir / "stderr.txt").read_text()
    assert report["startedUtc"] and report["finishedUtc"]
    assert "stale" not in report
    return report, run_dir


def test_normal_exit_publishes_pass_and_bound_sources_without_loading_qt(workspace):
    report, directory = run_worker(workspace, "observe()")
    assert report["result"] == "PASS" and report["workerExitCode"] == 0
    assert report["processExitVerified"] and report["sourceInputsUnchanged"]
    assert report["inputsBefore"] == report["inputsAfter"]
    assert str(PROJECT / "tools/qt_supervisor.py") in report["inputsBefore"]
    assert json.loads((directory / "observations.json").read_text())["result"] == PENDING


@pytest.mark.parametrize('destination', ['run', 'global'])
@pytest.mark.parametrize('point', ['before', 'after'])
@pytest.mark.parametrize('persistent', [False, True])
def test_final_publication_failure_cannot_leave_success_evidence(
        workspace, monkeypatch, destination, point, persistent):
    from tools import qt_supervisor as supervisor
    name = 'publication-' + workspace.name + '.json'
    global_path = PROJECT / 'build' / name
    script = worker(workspace, 'observe()')
    original_write = supervisor.write_output
    attempted = []
    injected = False

    def failing_write(path, data, *args, **kwargs):
        nonlocal injected
        if Path(path).suffix == '.json':
            record = json.loads(data)
            if record.get('result') == 'PASS':
                attempted.append(record)
                selected = ((Path(path).name == 'RESULT.json')
                            if destination == 'run' else Path(path) == global_path)
                if selected and not injected:
                    injected = True
                    if point == 'after':
                        original_write(path, data, *args, **kwargs)
                    raise OSError('injected final publication fault')
            if injected and persistent:
                raise OSError('output remains unavailable')
        return original_write(path, data, *args, **kwargs)

    monkeypatch.setattr(supervisor, 'write_output', failing_write)
    report = None
    try:
        report = supervisor.supervise_worker(script, name, 'supervisor-test-runs')
    except OSError:
        # A persistently unavailable output may propagate, but it must never
        # leave selectable success from this failed invocation.
        assert persistent
    assert injected and attempted
    run_directory = Path(attempted[0]['runDirectory'])
    for path in (run_directory / 'RESULT.json', global_path):
        if path.exists():
            assert json.loads(path.read_text())['result'] != 'PASS'
    assert (run_directory / 'observations.json').exists()
    assert (run_directory / 'stdout.txt').exists()
    assert (run_directory / 'stderr.txt').exists()
    if not persistent:
        assert report['result'] == 'FAIL'
        assert report['failure'] == 'REPORT_PUBLICATION_FAILED'
        assert json.loads(global_path.read_text()) == report
        assert json.loads((run_directory / 'RESULT.json').read_text()) == report


def test_publication_rollback_does_not_overwrite_a_replaced_report(workspace, monkeypatch):
    from tools import qt_supervisor as supervisor
    name = 'foreign-publication-' + workspace.name + '.json'
    global_path = PROJECT / 'build' / name
    script = worker(workspace, 'observe()')
    original_write = supervisor.write_output
    foreign = b'{"result":"FAIL","owner":"another-writer"}'
    run_path = None

    def replace_then_fail(path, data, *args, **kwargs):
        nonlocal run_path
        if Path(path).suffix == '.json' and json.loads(data).get('result') == 'PASS':
            if Path(path) == global_path:
                original_write(path, foreign)
                raise OSError('report replaced before failed publication')
            run_path = Path(path)
        return original_write(path, data, *args, **kwargs)

    monkeypatch.setattr(supervisor, 'write_output', replace_then_fail)
    with pytest.raises(RuntimeError, match='Cannot retract success evidence'):
        supervisor.supervise_worker(script, name, 'supervisor-test-runs')
    assert global_path.read_bytes() == foreign
    assert not run_path.exists() or json.loads(run_path.read_text())['result'] != 'PASS'


def test_observations_then_nonzero_exit_remains_fail(workspace):
    report, directory = run_worker(workspace, "observe()\nsys.exit(23)")
    assert report["result"] == "FAIL" and report["workerExitCode"] == 23
    assert report["failure"] == "WORKER_NONZERO_EXIT"
    assert not report["processExitVerified"] and (directory / "observations.json").exists()


def test_observations_then_timeout_remains_fail_and_captures_output(workspace):
    report, directory = run_worker(workspace, "observe()\ntime.sleep(10)", timeout=0.5)
    assert report["result"] == "FAIL" and report["failure"] == "WORKER_TIMEOUT"
    assert report["timedOut"] is True and not report["processExitVerified"]
    assert (directory / "observations.json").exists()


@pytest.mark.parametrize("body", [
    "pass", "write_output(run / 'observations.json', b'broken JSON')",
    "observations['result']='PASS'; observe()",
    "observations['installable']=True; observe()",
    "observations['cameraAccesses']=1; observe()",
    "observations['cameraAccesses']=False; observe()",
    "write_output(run / 'observations.json', b'{\"result\":\"PASS\",\"result\":\"EXECUTED_PENDING_PROCESS_EXIT\",\"installable\":false,\"cameraAccesses\":0}')",
])
def test_missing_damaged_or_invalid_observations_are_fail(workspace, body):
    report, _ = run_worker(workspace, body)
    assert report["workerExitCode"] == 0
    assert report["result"] == "FAIL" and report["failure"] == "INVALID_OBSERVATIONS"


def test_input_mutation_during_successful_worker_invalidates_result(workspace):
    bound = write_output(workspace / "bound-input.txt", b"before")
    report, _ = run_worker(workspace, "observe()\nwrite_output(Path(" + repr(str(bound)) + "), b'after')", inputs=[bound])
    assert report["result"] == "FAIL" and report["failure"] == "INPUTS_CHANGED"
    assert report["inputsBefore"] != report["inputsAfter"]


def test_missing_input_invalidates_old_pass_before_any_worker(workspace):
    script = worker(workspace, "observe()")
    name = "supervisor-test-" + workspace.name + ".json"
    write_output(PROJECT / "build" / name, b'{"result":"PASS"}')
    report = supervise_worker(script, name, "supervisor-test-runs", input_paths=[workspace / "missing"])
    assert report["result"] == "FAIL" and report["workerExitCode"] is None
    assert report["failure"] == "SUPERVISOR_EXCEPTION"
    assert json.loads((PROJECT / "build" / name).read_text())["result"] == "FAIL"


@pytest.mark.parametrize('change', ['none', 'content', 'addition', 'removal'])
def test_dynamic_runtime_members_are_rescanned_after_worker_exit(workspace, change):
    runtime = output_directory(workspace / 'runtime')
    member = write_output(runtime / 'core.fixture', b'original')
    actions = {
        'none': '',
        'content': 'write_output(Path(' + repr(str(member)) + "), b'changed')",
        'addition': 'write_output(Path(' + repr(str(runtime / 'new.fixture')) + "), b'new')",
        'removal': 'Path(' + repr(str(member)) + ').unlink()',
    }
    script = worker(workspace, 'observe()\n' + actions[change])
    report = supervise_worker(script, 'runtime-' + workspace.name + '.json',
                              'supervisor-test-runs', input_provider=lambda: runtime.glob('*.fixture'))
    assert report['result'] == ('PASS' if change == 'none' else 'FAIL')
    assert report['sourceInputsUnchanged'] is (change == 'none')
    if change != 'none':
        assert report['failure'] == 'INPUTS_CHANGED'


def test_failed_runtime_inventory_invalidates_old_pass_before_launch(workspace):
    name = 'runtime-' + workspace.name + '.json'
    write_output(PROJECT / 'build' / name, b'{"result":"PASS"}')
    def invalid_runtime():
        raise ValueError('changed pinned runtime')
    report = supervise_worker(worker(workspace, 'observe()'), name,
                              'supervisor-test-runs', input_provider=invalid_runtime)
    assert report['result'] == 'FAIL' and report['workerExitCode'] is None
    assert report['failure'] == 'SUPERVISOR_EXCEPTION'
    assert json.loads((PROJECT / 'build' / name).read_text())['result'] == 'FAIL'


def test_optimized_observer_preserves_worker_optimization(workspace):
    script = worker(workspace, "observe()")
    name = "supervisor-test-" + workspace.name + ".json"
    code = ("import json; from tools.qt_supervisor import supervise_worker; "
            "from pathlib import Path; print(json.dumps(supervise_worker(Path(" + repr(str(script)) + "), "
            + repr(name) + ", 'supervisor-test-runs')))")
    run = subprocess.run([sys.executable, "-B", "-O", "-c", code], cwd=PROJECT,
                         capture_output=True, text=True, timeout=20)
    assert run.returncode == 0, run.stderr
    report = json.loads(run.stdout)
    assert report["result"] == "PASS" and report["workerOptimize"] == report["pythonOptimize"] == 1
    assert "-O" in report["workerCommand"]
