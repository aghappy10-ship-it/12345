"""Bound actual publication seams only; never call audit/main/UAC/camera.

The native creator is scheduled at the real rename/replace system boundary.
This changes interleaving, not commit behavior: the original OS call still runs.
Loads exact current formal on-disk sources. This isolated regression does not run the full audit.
"""
import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import types

import pytest

SELF = Path(__file__).resolve()
ROOT = SELF.parents[1]
FORMAL = ROOT / "build/peer-route-review-20261011-host-fixed"
RUNNER = FORMAL / "run_audit.py"
LAUNCHER = FORMAL / "launch_admin_audit_once.py"
RUNNER_SHA = "3d45dafca02e42499ef0322c3e23ca750f407824e2ca0f1c1d45c49e6930fb19"
LAUNCHER_SHA = "1b3242656b6c5691e10b4d31e8933ac60cdf2132130c6494ec68ea81c6df1cb8"
RIVAL = b"RIVAL_KEEP\n"
sys.path.insert(0, str(ROOT))

def identity(path):
    raw = path.read_bytes()
    info = path.stat()
    return {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
            "device": info.st_dev, "inode": info.st_ino,
            "mtime_ns": info.st_mtime_ns}


@pytest.fixture(scope="session", autouse=True)
def fixed_inputs(record_testsuite_property):
    assert os.name == "nt" and not sys.flags.optimize and sys.dont_write_bytecode
    assert identity(RUNNER)["sha256"] == RUNNER_SHA
    assert identity(LAUNCHER)["sha256"] == LAUNCHER_SHA
    protected = (RUNNER, LAUNCHER, ROOT / "tools/output_guard.py",
                 Path(sys.executable), SELF)
    before = {str(path): identity(path) for path in protected}
    record_testsuite_property("host_output_inputs_before", json.dumps(before, sort_keys=True))
    yield
    after = {str(path): identity(path) for path in protected}
    record_testsuite_property("host_output_inputs_after", json.dumps(after, sort_keys=True))
    assert before == after, "actual formal writer inputs changed during regression"

def load_source(path, name):
    raw = path.read_bytes()
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)
    assert module.__name__ != "__main__"
    return module, ast.parse(raw, filename=str(path))


def expression_for(tree, function_name, filename, *, launcher=False):
    function = next(node for node in tree.body
                    if isinstance(node, ast.FunctionDef) and node.name == function_name)
    found = []
    for node in ast.walk(function):
        if not (isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Name)
                and node.value.func.id == "write_output"):
            continue
        first = node.value.args[0]
        leaf = first.slice if launcher else first.right
        if isinstance(leaf, ast.Constant) and leaf.value == filename:
            found.append(node)
    assert len(found) == 1, (filename, len(found))
    return found[0]


def actual_entry(seam, directory):
    runner_path = RUNNER
    runner, runner_tree = load_source(runner_path, "output_proof_bound_runner")
    runner.HERE = directory
    if seam == "save":
        return lambda: runner.save("saved.json", {"literal": "AUDIT_OUTPUT"}), directory / "saved.json"
    if seam.startswith("admin-"):
        launcher_path = LAUNCHER
        launcher, tree = load_source(launcher_path, "output_proof_bound_launcher")
        launcher.RUNNER = runner_path
        function = next(node for node in tree.body
                        if isinstance(node, ast.FunctionDef) and node.name == "main")
        for node in function.body:
            if isinstance(node, ast.ImportFrom) and node.module == "tools.output_guard":
                exec(compile(ast.Module(body=[node], type_ignores=[]), str(launcher_path), "exec"), launcher.__dict__)
            if (isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "write_output"):
                exec(compile(ast.Module(body=[node], type_ignores=[]), str(launcher_path), "exec"), launcher.__dict__)
        writer = launcher.write_output
        assert Path(writer.__code__.co_filename) == runner_path
        assert writer.__globals__["__name__"] != "__main__"
        assert writer.__globals__["RUNNER_SOURCE_SHA256"] == identity(runner_path)["sha256"]
        target = directory / seam
        launcher.__dict__.update(destinations={seam: target}, start={"literal": "START"},
                                 child={"literal": "CHILD"}, result={"literal": "RESULT"})
        expression = expression_for(tree, "main", seam, launcher=True)
        code = compile(ast.Module(body=[expression], type_ignores=[]), str(launcher_path), "exec")
        return lambda: exec(code, launcher.__dict__), target
    target = directory / seam
    if not (directory / "collection.output.log").exists():
        with (directory / "collection.output.log").open("xb") as output:
            output.write(b"COLLECTION_STDOUT\n")
    runner.__dict__.update(collected={"output_file": "collection.output.log"},
                           suite_output=b"SUITE_STDOUT\n")
    expression = expression_for(runner_tree, "audit", seam)
    code = compile(ast.Module(body=[expression], type_ignores=[]), str(runner_path), "exec")
    return lambda: exec(code, runner.__dict__), target


SEAMS = ("save", "collection.stdout", "collection.stderr", "suite.stdout", "suite.stderr",
         "admin-launch-start.json", "admin-launch-child-start.json", "admin-launch-result.json")


@pytest.mark.parametrize("seam", SEAMS)
def test_actual_publication_does_not_overwrite_native_rival(seam, tmp_path, monkeypatch, record_property):
    entry, target = actual_entry(seam, tmp_path)
    real_replace, real_rename = os.replace, os.rename
    calls = []
    rival_identity = None

    def race_commit(actual, source, destination, *args, **kwargs):
        nonlocal rival_identity
        if Path(destination).absolute() == target.absolute():
            assert not target.exists(), "interleaving must begin with target absent"
            code = "from pathlib import Path; import sys; p=Path(sys.argv[1]); f=p.open('xb'); f.write(b'RIVAL_KEEP\\n'); f.flush(); f.close()"
            result = subprocess.run([sys.executable, "-B", "-c", code, str(target)],
                                    capture_output=True, timeout=10)
            assert result.returncode == 0, result.stderr
            assert target.read_bytes() == RIVAL
            rival_identity = identity(target)
            calls.append({"api": actual.__name__, "creator_exit": result.returncode,
                          "before_commit": rival_identity})
        return actual(source, destination, *args, **kwargs)

    monkeypatch.setattr(os, "replace", lambda src, dst, *a, **k: race_commit(real_replace, src, dst, *a, **k))
    monkeypatch.setattr(os, "rename", lambda src, dst, *a, **k: race_commit(real_rename, src, dst, *a, **k))
    failure = None
    try:
        entry()
    except BaseException as error:
        failure = error
    after = identity(target)
    record_property("actual_output_race", json.dumps({"source_mode": "CURRENT_FORMAL_ON_DISK", "seam": seam,
                    "calls": calls, "error_type": type(failure).__name__ if failure else None,
                    "after": after, "rival_unchanged": after == rival_identity,
                    "native_commit_executed": True, "audit_main_invoked": False,
                    "launcher_main_invoked": False, "installable": False}, sort_keys=True))
    assert len(calls) == 1
    assert isinstance(failure, FileExistsError), "native no-overwrite commit must reject rival"
    assert target.read_bytes() == RIVAL and after == rival_identity
    assert not list(tmp_path.glob(".*.tmp")), "owned staging bytes must be cleaned"


@pytest.fixture(autouse=True)
def controls_source_binding(record_property):
    path = Path(__file__).resolve()
    before = identity(path)
    record_property("controls_source_sha256", before["sha256"])
    yield
    assert identity(path) == before


@pytest.mark.parametrize("seam", SEAMS)
def test_new_output_commits_exact_bytes_including_empty_stderr(seam, tmp_path, monkeypatch):
    entry, target = actual_entry(seam, tmp_path)
    real_rename = os.rename
    committed = []

    def observe(source, destination, *args, **kwargs):
        if Path(destination).absolute() == target.absolute():
            committed.append((Path(source).read_bytes(), str(destination)))
        return real_rename(source, destination, *args, **kwargs)

    monkeypatch.setattr(os, "rename", observe)
    entry()
    expected = {"save": b'{\n  "literal": "AUDIT_OUTPUT"\n}\n',
                "collection.stdout": b"COLLECTION_STDOUT\n", "collection.stderr": b"",
                "suite.stdout": b"SUITE_STDOUT\n", "suite.stderr": b"",
                "admin-launch-start.json": b'{\n  "literal": "START"\n}\n',
                "admin-launch-child-start.json": b'{\n  "literal": "CHILD"\n}\n',
                "admin-launch-result.json": b'{\n  "literal": "RESULT"\n}\n'}[seam]
    assert target.read_bytes() == expected
    assert len(committed) == 1 and committed[0][0] == expected
    assert not list(tmp_path.glob(".*.tmp"))


@pytest.mark.parametrize("seam", SEAMS)
def test_preexisting_output_is_not_replaced(seam, tmp_path):
    entry, target = actual_entry(seam, tmp_path)
    with target.open("xb") as output:
        output.write(RIVAL)
    before = identity(target)
    with pytest.raises(ValueError, match="output already exists"):
        entry()
    assert target.read_bytes() == RIVAL and identity(target) == before
    assert not list(tmp_path.glob(".*.tmp"))


@pytest.mark.parametrize("seam", SEAMS)
def test_rival_refusal_survives_owned_staging_cleanup_failure(seam, tmp_path, monkeypatch):
    entry, target = actual_entry(seam, tmp_path)
    real_rename = os.rename
    real_unlink = Path.unlink
    before = None
    native_failure = None

    def race(source, destination, *args, **kwargs):
        nonlocal before, native_failure
        if Path(destination).absolute() == target.absolute():
            code = "from pathlib import Path; import sys; p=Path(sys.argv[1]); f=p.open('xb'); f.write(b'RIVAL_KEEP\\n'); f.close()"
            result = subprocess.run([sys.executable, "-B", "-c", code, str(target)],
                                    capture_output=True, timeout=10)
            assert result.returncode == 0, result.stderr
            before = identity(target)
        try:
            return real_rename(source, destination, *args, **kwargs)
        except FileExistsError as error:
            native_failure = error
            raise

    def refuse_owned_cleanup(path, *args, **kwargs):
        if path.parent == tmp_path and path.suffix == ".tmp":
            raise PermissionError("CONTROL_OWNED_STAGING_UNLINK_DENIED")
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "rename", race)
    monkeypatch.setattr(Path, "unlink", refuse_owned_cleanup)
    with pytest.raises(FileExistsError) as raised:
        entry()
    assert raised.value is native_failure
    assert "CONTROL_OWNED_STAGING_UNLINK_DENIED" in "\n".join(raised.value.__notes__)
    assert identity(target) == before and target.read_bytes() == RIVAL
    assert len(list(tmp_path.glob(".*.tmp"))) == 1


@pytest.mark.parametrize("seam", ("save", "collection.stderr"))
def test_fsync_failure_survives_cleanup_failure(seam, tmp_path, monkeypatch):
    entry, target = actual_entry(seam, tmp_path)
    primary = OSError("CONTROL_FSYNC_FAILURE")
    real_unlink = Path.unlink

    def fail_fsync(descriptor):
        raise primary

    def fail_cleanup(path, *args, **kwargs):
        if path.parent == tmp_path and path.suffix == ".tmp":
            raise PermissionError("CONTROL_CLEANUP_FAILURE")
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "fsync", fail_fsync)
    monkeypatch.setattr(Path, "unlink", fail_cleanup)
    with pytest.raises(OSError) as raised:
        entry()
    assert raised.value is primary
    assert "CONTROL_CLEANUP_FAILURE" in "\n".join(primary.__notes__)
    assert not target.exists()


@pytest.mark.parametrize("seam", ("save", "collection.stderr"))
@pytest.mark.parametrize("failed_stage", ("write", "fsync"))
def test_primary_failure_survives_stream_close_failure(seam, failed_stage, tmp_path, monkeypatch):
    entry, target = actual_entry(seam, tmp_path)
    primary = OSError("CONTROL_" + failed_stage.upper() + "_BEFORE_CLOSE_FAILURE")
    secondary = OSError("CONTROL_STREAM_CLOSE_FAILURE")
    real_fdopen = os.fdopen

    class ClosingFailure:
        def __init__(self, stream):
            self.stream = stream

        def __getattr__(self, name):
            return getattr(self.stream, name)

        def write(self, data):
            if failed_stage == "write":
                raise primary
            return self.stream.write(data)

        def __enter__(self):
            return self

        def __exit__(self, *arguments):
            self.close()

        def close(self):
            self.stream.close()
            raise secondary

    def fail_fsync(descriptor):
        raise primary

    monkeypatch.setattr(os, "fdopen", lambda *a, **k: ClosingFailure(real_fdopen(*a, **k)))
    monkeypatch.setattr(os, "fsync", fail_fsync)
    with pytest.raises(OSError) as raised:
        entry()
    assert raised.value is primary
    assert "CONTROL_STREAM_CLOSE_FAILURE" in "\n".join(primary.__notes__)
    assert not target.exists() and not list(tmp_path.glob(".*.tmp"))


def test_stream_close_only_failure_is_primary_and_prevents_publish(tmp_path, monkeypatch):
    entry, target = actual_entry("save", tmp_path)
    secondary = OSError("CONTROL_STREAM_CLOSE_ONLY_FAILURE")
    real_fdopen = os.fdopen

    class ClosingFailure:
        def __init__(self, stream):
            self.stream = stream

        def __getattr__(self, name):
            return getattr(self.stream, name)

        def close(self):
            self.stream.close()
            raise secondary

    monkeypatch.setattr(os, "fdopen", lambda *a, **k: ClosingFailure(real_fdopen(*a, **k)))
    with pytest.raises(OSError) as raised:
        entry()
    assert raised.value is secondary
    assert not target.exists() and not list(tmp_path.glob(".*.tmp"))


@pytest.mark.parametrize("secondary_stage", ("stream_close", "staging_cleanup"))
def test_diagnostic_add_note_failure_cannot_replace_primary(secondary_stage, tmp_path, monkeypatch, record_property):
    entry, target = actual_entry("save", tmp_path)

    class PrimaryFailure(OSError):
        def add_note(self, note):
            raise RuntimeError("CONTROL_DIAGNOSTIC_ADD_NOTE_FAILURE")

    primary = PrimaryFailure("CONTROL_PRIMARY_BEFORE_DIAGNOSTIC_FAILURE")
    real_fdopen, real_unlink = os.fdopen, Path.unlink

    class ClosingFailure:
        def __init__(self, stream):
            self.stream = stream

        def __getattr__(self, name):
            return getattr(self.stream, name)

        def close(self):
            self.stream.close()
            raise OSError("CONTROL_SECONDARY_STREAM_CLOSE_FAILURE")

    def fail_fsync(descriptor):
        raise primary

    def fail_cleanup(path, *a, **k):
        if path.parent == tmp_path and path.suffix == ".tmp":
            raise PermissionError("CONTROL_SECONDARY_STAGING_CLEANUP_FAILURE")
        return real_unlink(path, *a, **k)

    if secondary_stage == "stream_close":
        monkeypatch.setattr(os, "fdopen", lambda *a, **k: ClosingFailure(real_fdopen(*a, **k)))
    else:
        monkeypatch.setattr(Path, "unlink", fail_cleanup)
    monkeypatch.setattr(os, "fsync", fail_fsync)
    record_property("diagnostic_runner_source_sha256", identity(RUNNER)["sha256"])
    with pytest.raises(PrimaryFailure) as raised:
        entry()
    assert raised.value is primary
    assert not target.exists()


def test_launcher_loads_hash_bound_explicit_path_not_cwd_shadow(tmp_path, monkeypatch):
    launcher, _ = load_source(LAUNCHER, "proof_loader")
    runner = RUNNER
    launcher.RUNNER = runner
    with (tmp_path / "run_audit.py").open("x", encoding="utf-8") as shadow:
        shadow.write("raise AssertionError('CWD_SHADOW_EXECUTED')\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.syspath_prepend(str(tmp_path))
    writer = launcher.load_runner_writer()
    assert Path(writer.__code__.co_filename) == runner
    assert writer.__globals__["RUNNER_SOURCE_SHA256"] == identity(runner)["sha256"]
    assert writer.__globals__["__name__"] != "__main__"
    output = tmp_path / "explicit-loader-output.data"
    writer(output, b"EXPLICIT_LOADED_WRITER\n")
    assert output.read_bytes() == b"EXPLICIT_LOADED_WRITER\n"


def test_launcher_refuses_wrong_hash_without_executing_its_source(tmp_path):
    launcher, _ = load_source(LAUNCHER, "proof_bad_loader")
    wrong = tmp_path / "wrong-runner.py"
    with wrong.open("x", encoding="utf-8") as source:
        source.write("raise AssertionError('WRONG_HASH_SOURCE_EXECUTED')\n")
    launcher.RUNNER = wrong
    with pytest.raises(ValueError, match="fixed runner output helper hash mismatch"):
        launcher.load_runner_writer()


def test_staged_readback_failure_does_not_publish(tmp_path, monkeypatch):
    entry, target = actual_entry("save", tmp_path)
    real_read = Path.read_bytes

    def fail_read(path):
        if path.parent == tmp_path and path.suffix == ".tmp":
            return b"CONTROL_WRONG_STAGED_BYTES"
        return real_read(path)

    monkeypatch.setattr(Path, "read_bytes", fail_read)
    with pytest.raises(ValueError, match="audit staged output readback mismatch"):
        entry()
    assert not target.exists() and not list(tmp_path.glob(".*.tmp"))


def test_final_readback_failure_retains_published_file(tmp_path, monkeypatch):
    entry, target = actual_entry("save", tmp_path)
    real_read = Path.read_bytes

    def fail_final_read(path):
        return b"CONTROL_WRONG_COMMITTED_READBACK" if path == target else real_read(path)

    monkeypatch.setattr(Path, "read_bytes", fail_final_read)
    with pytest.raises(ValueError, match="audit committed output readback mismatch"):
        entry()
    assert real_read(target) == b'{\n  "literal": "AUDIT_OUTPUT"\n}\n'
    assert not list(tmp_path.glob(".*.tmp"))


def test_non_windows_refuses_before_creating_output(tmp_path, monkeypatch):
    entry, target = actual_entry("save", tmp_path)
    runner, _ = load_source(RUNNER, "proof_platform")
    writer = runner.write_output
    monkeypatch.setattr(os, "name", "posix")
    with pytest.raises(NotImplementedError, match="Windows no-overwrite rename"):
        writer(target, b"PLATFORM_REFUSAL")
    monkeypatch.undo()
    assert not target.exists() and not list(tmp_path.glob(".*.tmp"))


@pytest.mark.parametrize("change_copied_launcher", (False, True))
def test_snapshot_actual_membership_hash_read_and_stable_predicate(change_copied_launcher, tmp_path, record_property):
    """Actual AST boundaries, not a full snapshot/runtime inventory execution."""
    runner_path = RUNNER
    launcher_path = LAUNCHER
    runner, tree = load_source(runner_path, "proof_snapshot_boundaries")
    runner.HERE = tmp_path
    copied_launcher = tmp_path / "launch_admin_audit_once.py"
    original_launcher = launcher_path.read_bytes()
    with copied_launcher.open("xb") as output:
        output.write(original_launcher)
    snapshot = next(node for node in tree.body
                    if isinstance(node, ast.FunctionDef) and node.name == "snapshot")
    membership = next(node for node in snapshot.body
                      if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                      and isinstance(node.value.func, ast.Attribute)
                      and isinstance(node.value.func.value, ast.Name)
                      and node.value.func.value.id == "paths" and node.value.func.attr == "update"
                      and isinstance(node.value.args[0], ast.Tuple))
    file_init = next(node for node in snapshot.body
                     if isinstance(node, ast.Assign) and len(node.targets) == 1
                     and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "files")
    file_read_loop = next(node for node in snapshot.body
                          if isinstance(node, ast.For) and isinstance(node.target, ast.Name)
                          and node.target.id == "path")
    audit = next(node for node in tree.body
                 if isinstance(node, ast.FunctionDef) and node.name == "audit")
    predicates = [next(node for node in audit.body
                       if isinstance(node, ast.Assign) and len(node.targets) == 1
                       and isinstance(node.targets[0], ast.Name) and node.targets[0].id == name)
                  for name in ("stable", "complete")]

    def read_actual_boundary():
        # Only historical/source/runtime membership enumeration is excluded.
        # The exact tuple membership and final byte-read loop execute unchanged.
        runner.paths = set()
        code = compile(ast.Module(body=[membership, file_init, file_read_loop], type_ignores=[]),
                       str(runner_path), "exec")
        exec(code, runner.__dict__)
        return dict(runner.files)

    before = read_actual_boundary()
    if change_copied_launcher:
        with copied_launcher.open("ab") as output:
            output.write(b"\n# RG545_ACTUAL_COPIED_LAUNCHER_CHANGE\n")
    after = read_actual_boundary()
    runner.__dict__.update(before={"files": before}, after={"files": after},
                           run={"outcome": "finished", "exit_code": 0}, exact_execution=True,
                           junit_error=None, failed=0, immediate_failures=[])
    exec(compile(ast.Module(body=predicates, type_ignores=[]), str(runner_path), "exec"),
         runner.__dict__)
    key = str(copied_launcher)
    record_property("snapshot_boundary", json.dumps({
        "runner_source_sha256": identity(runner_path)["sha256"],
        "launcher_source_sha256": identity(launcher_path)["sha256"],
        "copied_launcher_changed": change_copied_launcher,
        "before": before.get(key), "after": after.get(key),
        "stable": runner.stable, "complete": runner.complete,
        "actual_ast_membership_and_read_loop_executed": True,
        "actual_ast_stable_and_complete_predicates_executed": True,
        "full_snapshot_called": False, "external_membership_enumeration_excluded": True,
        "formal_launcher_modified": False, "camera_accesses": 0,
        "installable": False}, sort_keys=True))
    if change_copied_launcher:
        assert not runner.stable and not runner.complete
        assert before[key] != after[key]
    else:
        assert before[key] == {"sha256": hashlib.sha256(original_launcher).hexdigest(),
                               "bytes": len(original_launcher)}
        assert runner.stable and runner.complete


def test_fixed_runner_consumes_current_readback_and_registry(record_property):
    """Actual snapshot readback selection, excluding the full audit/native I/O."""
    runner, tree = load_source(RUNNER, "proof_current_readback_selection")
    snapshot = next(node for node in tree.body
                    if isinstance(node, ast.FunctionDef) and node.name == "snapshot")

    def assigned(name):
        nodes = [node for node in snapshot.body if isinstance(node, ast.Assign)
                 and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                 and node.targets[0].id == name]
        assert len(nodes) == 1
        return nodes[0]

    updates = [node for node in snapshot.body if isinstance(node, ast.Expr)
               and isinstance(node.value, ast.Call)
               and isinstance(node.value.func, ast.Attribute)
               and isinstance(node.value.func.value, ast.Name)
               and node.value.func.value.id == "paths" and node.value.func.attr == "update"]
    membership, = [node for node in updates if isinstance(node.value.args[0], ast.Tuple)]
    payload_update, = [node for node in updates if isinstance(node.value.args[0], ast.Name)
                      and node.value.args[0].id == "payloads"]
    payload_check, = [node for node in snapshot.body if isinstance(node, ast.If)
                     and any(isinstance(child, ast.Name) and child.id == "payloads"
                             for child in ast.walk(node.test))]
    file_read, = [node for node in snapshot.body if isinstance(node, ast.For)
                 and isinstance(node.target, ast.Name) and node.target.id == "path"]
    runner.paths = set()
    actual_boundary = [membership, assigned("payloads"), payload_check,
                       payload_update, assigned("files"), file_read]
    exec(compile(ast.Module(body=actual_boundary, type_ignores=[]), str(RUNNER), "exec"),
         runner.__dict__)

    selected = runner.READBACK_FIXTURE
    source = selected / "source-only/peer-install-source.json"
    stage = selected / "exact-stage/payload-stage.json"
    source_bytes, stage_bytes = source.read_bytes(), stage.read_bytes()
    assert runner.files[str(source)] == {
        "sha256": hashlib.sha256(source_bytes).hexdigest(), "bytes": len(source_bytes)}
    assert runner.files[str(stage)] == {
        "sha256": hashlib.sha256(stage_bytes).hexdigest(), "bytes": len(stage_bytes)}
    saved, staged = json.loads(source_bytes), json.loads(stage_bytes)
    registry_sha = identity(ROOT / "work/reverse/X2DII_REGRESSION_GATES.json")["sha256"]
    record_property("actual_readback_selection", json.dumps({
        "selected_directory": str(selected), "expected_directory": str(FORMAL),
        "read_files": runner.files, "stage_registry_before": staged["source_hashes_before"]["regression_registry"],
        "stage_registry_after": staged["source_hashes_after"]["regression_registry"],
        "current_registry_sha256": registry_sha, "full_snapshot_called": False,
        "actual_snapshot_readback_boundaries_executed": True,
        "camera_accesses": 0, "installable": False}, sort_keys=True))
    payload_metadata = {}
    for item in saved["candidate"]["files"]:
        name = Path(item["source"]).name
        assert name not in payload_metadata
        payload_metadata[name] = {"sha256": item["sha256"], "bytes": item["bytes"]}
        current = identity(ROOT / item["source"])
        assert {key: current[key] for key in ("sha256", "bytes")} == payload_metadata[name]
    rc = saved["candidate"]["rc"]
    current_rc = identity(ROOT / rc["source"])
    assert current_rc["sha256"] == rc["after"]
    payload_metadata[Path(rc["source"]).name] = {
        "sha256": rc["after"], "bytes": current_rc["bytes"]}
    assert set(payload_metadata) == {"libx2dii_menu.so", "X2d2MenuBootstrap.qml",
        "X2d2MenuModel.qml", "X2d2MenuPage.qml", "camera-gui.rc.proposed"}
    expected = {RUNNER, LAUNCHER, Path(sys.executable), Path("C:/Program Files/Git/bin/sh.exe"),
                FORMAL / "source-only/peer-install-source.json", FORMAL / "exact-stage/payload-stage.json",
                *(FORMAL / "exact-stage/payloads" / name for name in payload_metadata)}
    assert runner.HERE == FORMAL
    assert selected == FORMAL, "fixed runner selected an obsolete readback directory"
    assert set(runner.files) == {str(path) for path in expected}
    assert staged["readback"]["file_count"] == len(payload_metadata)
    assert staged["readback"]["files"] == payload_metadata
    for name, metadata in payload_metadata.items():
        assert runner.files[str(FORMAL / "exact-stage/payloads" / name)] == metadata
    assert staged["saved_manifest_sha256"] == identity(source)["sha256"]
    assert saved["candidate_sha256"] == staged["candidate_sha256"]
    assert staged["source_hashes_before"]["regression_registry"] == registry_sha
    assert staged["source_hashes_after"]["regression_registry"] == registry_sha
    assert staged["source_hashes_before"] == staged["source_hashes_after"]
    assert saved["installable"] is False and saved["package_created"] is False
    assert staged["installable"] is False and staged["package_created"] is False
