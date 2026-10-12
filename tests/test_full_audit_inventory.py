"""A zero pytest status cannot certify an incomplete execution inventory."""
from copy import deepcopy
from contextlib import redirect_stdout
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace

import pytest


@pytest.fixture
def current_runner():
    path = Path(__file__).resolve().parents[1] / "build/peer-route-review-20261006-menu-evidence/run_audit.py"
    spec = importlib.util.spec_from_file_location("current_full_audit_runner", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def current_destination(current_runner):
    with tempfile.TemporaryDirectory(prefix="audit-closure-", dir=current_runner.ROOT / "build") as name:
        yield Path(name)


@pytest.fixture
def prospective_runner():
    path = Path(__file__).resolve().parents[1] / "build/peer-route-review-20261006-dependency-closure/run_audit.py"
    spec = importlib.util.spec_from_file_location("prospective_full_audit_runner", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_public_main_does_not_bind_the_still_growing_parent_log(prospective_runner, monkeypatch):
    # Keep the real main, audit verdict, preflight, snapshots and guarded writers.
    # ONLY child-process I/O is synthetic; this is not an actual full-audit PASS.
    from tools.output_guard import output_directory
    evidence = output_directory(prospective_runner.ROOT / "build/rg508-local-parent-log-20261006")
    destination = Path(tempfile.mkdtemp(prefix="public-main-", dir=evidence))
    prospective_runner.HERE = destination
    (destination / "source-only").mkdir()
    (destination / "source-only/peer-install-source.json").write_bytes(b"unused local boundary fixture")
    payloads = destination / "exact-stage/payloads"
    payloads.mkdir(parents=True)
    (destination / "exact-stage/payload-stage.json").write_bytes(b"unused local boundary fixture")
    for index in range(5):
        (payloads / str(index)).write_bytes(b"unused local boundary payload")
    closed = {
        "TEST_BOUNDARY.json": b'{"test_fixture_only":true,"child_process_io_substituted":true,"installable":false}\n',
        "admin-launch-start.json": b'{"test_fixture_only":true,"camera_accesses":0}\n',
        "admin-launch-output.log.complete": b"closed similarly named log must remain bound\n",
        "retained-child.output.log": b"closed child log must remain bound\n",
    }
    for name, raw in closed.items():
        prospective_runner.write_output(destination / name, raw)
    node = "tests/test_full_audit_inventory.py::test_public_main_does_not_bind_the_still_growing_parent_log"
    inventory = {"count": 1, "duplicate_origins": [], "items": [
        {"nodeid": node, "origin": ["test_full_audit_inventory", node.split("::")[-1], ""]}]}
    execution = {"started": [node], "finished": [node], "passing_subtest_count": 0, "exit_code": 0}
    xml = (b'<testsuites><testsuite tests="1" failures="0" errors="0" skipped="0">'
           b'<testcase classname="tests.test_full_audit_inventory" '
           b'name="test_public_main_does_not_bind_the_still_growing_parent_log" />'
           b'</testsuite></testsuites>')
    outputs = {"--collect": b"synthetic collection child output\n", "--suite": b"synthetic suite child output\n"}

    def child_io(command, **kwargs):
        assert command[-1] in outputs
        if command[-1] == "--collect":
            prospective_runner.save("collection.json", inventory)
        else:
            prospective_runner.save("execution-collection.json", inventory)
            prospective_runner.save("execution.json", execution)
            prospective_runner.write_output(destination / "full-offline-suite.xml", xml)
        return SimpleNamespace(returncode=0, stdout=outputs[command[-1]], stderr=b"")

    monkeypatch.setattr(subprocess, "run", child_io)
    parent_log = destination / "admin-launch-output.log"
    with parent_log.open("x", encoding="utf-8", newline="") as output, redirect_stdout(output):
        outcome = prospective_runner.main([])
    result = json.loads((destination / "AUDIT.json").read_bytes())
    final_raw = parent_log.read_bytes()
    final_sha = hashlib.sha256(final_raw).hexdigest()
    observation = {"test_fixture_only": True, "child_process_io_substituted": True,
                   "installable": False, "camera_accesses": 0, "network_actions": 0,
                   "public_main_exit_code": outcome, "audit_parent_log_sha256": result["artifacts"].get(parent_log.name),
                   "final_parent_log_sha256": final_sha, "final_parent_log_bytes": len(final_raw),
                   "fixture_directory": str(destination)}
    prospective_runner.write_output(evidence / (destination.name + "-observation.json"),
                                    (json.dumps(observation, indent=2) + "\n").encode())
    print("Retained public main fixture:", destination, file=sys.stderr)
    assert outcome == 0 and result["status"] == "LOCAL_SUITE_COMPLETE"
    assert result["installable"] is False and result["package_created"] is False
    assert result["exact_collected_tests_started_and_finished"] is True
    assert result["all_listed_inputs_unchanged"] is True
    assert b"synthetic suite child output" in final_raw and b"LOCAL_SUITE_COMPLETE" in final_raw
    assert parent_log.name not in result["artifacts"], observation
    expected = set(closed) | {
        "build-preflight.json", "inputs-before.json", "inputs-after.json", "collection.json",
        "collection.output.log", "collection.process.json", "collection.stdout", "collection.stderr",
        "execution-collection.json", "execution.json", "full-offline-suite.xml",
        "suite.output.log", "suite.process.json", "suite.stdout", "suite.stderr",
    }
    assert set(result["artifacts"]) == expected
    for name in expected:
        assert result["artifacts"][name] == hashlib.sha256((destination / name).read_bytes()).hexdigest()
    for name, raw in closed.items():
        assert result["artifacts"][name] == hashlib.sha256(raw).hexdigest()
    for stage, mode in (("collection", "--collect"), ("suite", "--suite")):
        record = result[stage + "_process" if stage == "collection" else "child_process"]
        assert record["outcome"] == "finished" and record["exit_code"] == 0
        assert record["output_sha256"] == hashlib.sha256(outputs[mode]).hexdigest()


def test_prospective_public_runner_is_in_the_actual_source_input_closure(prospective_runner):
    from tools.release_identity import source_inputs
    inputs = source_inputs()
    path = Path(prospective_runner.__file__).resolve()
    relative = path.relative_to(prospective_runner.ROOT).as_posix()
    assert relative == "build/peer-route-review-20261006-dependency-closure/run_audit.py"
    assert relative in inputs
    raw = path.read_bytes()
    assert inputs[relative] == {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
    # The added real consumer must not replace any of the eight retained runners.
    for name in (
        "build/peer-route-review-20261004-rg399/run_audit.py",
        "build/peer-route-review-20261004-rg405/run_audit.py",
        "build/peer-route-review-20261004-rg408/run_audit.py",
        "build/peer-route-review-20261004-rg415/run_audit.py",
        "build/peer-route-review-20261004-rg416/run_audit.py",
        "build/peer-route-review-20261004-rg417/run_audit.py",
        "build/peer-route-review-20261004-rg418/run_audit.py",
        "build/peer-route-review-20261006-menu-evidence/run_audit.py",
    ):
        previous = (prospective_runner.ROOT / name).read_bytes()
        assert inputs[name] == {"sha256": hashlib.sha256(previous).hexdigest(), "bytes": len(previous)}


UNAPPROVED_TEST_PATHS = (
    "reference/scripts/CodeTests/test_build_contract.py",
    "build/rg372/test_generated.py",
    "../x2d2/work/reverse/test_foreign.py",
    "tests/test_unreviewed.py",
)


def _pin_one_approved_test(module, destination):
    import hashlib
    path = module.ROOT / "tests/test_full_audit_inventory.py"
    raw = path.read_bytes()
    module.save("inputs-before.json", {"files": {
        str(path): {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
    }})
    return path


@pytest.mark.parametrize("name", UNAPPROVED_TEST_PATHS)
def test_current_collector_refuses_unapproved_path_before_any_test_start(current_runner, current_destination, name):
    tmp_path = current_destination
    current_runner.HERE = tmp_path
    _pin_one_approved_test(current_runner, tmp_path)
    item = SimpleNamespace(nodeid=name + "::test_unapproved", path=current_runner.ROOT / name,
                           obj=test_current_collector_refuses_unapproved_path_before_any_test_start)
    with pytest.raises(ValueError, match="unapproved test path"):
        current_runner.Collect().pytest_collection_finish(SimpleNamespace(items=[item]))


def test_current_collector_accepts_exact_frozen_test_file(current_runner, current_destination):
    tmp_path = current_destination
    current_runner.HERE = tmp_path
    path = _pin_one_approved_test(current_runner, tmp_path)
    item = SimpleNamespace(nodeid="tests/test_full_audit_inventory.py::test_current_collector_accepts_exact_frozen_test_file",
                           path=path, obj=test_current_collector_accepts_exact_frozen_test_file)
    current_runner.Collect().pytest_collection_finish(SimpleNamespace(items=[item]))
    result = json.loads((tmp_path / "collection.json").read_bytes())
    assert result["count"] == 1 and result["duplicate_origins"] == []
    assert result["items"][0]["nodeid"] == item.nodeid


def test_current_collector_refuses_nodeid_with_different_actual_file(current_runner, current_destination):
    current_runner.HERE = current_destination
    _pin_one_approved_test(current_runner, current_destination)
    item = SimpleNamespace(nodeid="tests/test_full_audit_inventory.py::test_current_collector_accepts_exact_frozen_test_file",
                           path=current_runner.ROOT / "tests/test_audit_build_preflight.py",
                           obj=test_current_collector_accepts_exact_frozen_test_file)
    with pytest.raises(ValueError, match="unapproved test path"):
        current_runner.Collect().pytest_collection_finish(SimpleNamespace(items=[item]))


def test_current_collector_refuses_approved_file_changed_since_freeze(current_runner, current_destination, monkeypatch):
    current_runner.HERE = current_destination
    path = _pin_one_approved_test(current_runner, current_destination)
    item = SimpleNamespace(nodeid="tests/test_full_audit_inventory.py::test_current_collector_accepts_exact_frozen_test_file",
                           path=path, obj=test_current_collector_accepts_exact_frozen_test_file)
    read = Path.read_bytes
    monkeypatch.setattr(Path, "read_bytes", lambda p: read(p) + b" " if p == path else read(p))
    with pytest.raises(ValueError, match="approved test file changed"):
        current_runner.Collect().pytest_collection_finish(SimpleNamespace(items=[item]))


def test_current_real_pytest_hook_rejects_generated_test_without_running_body(current_runner, current_destination):
    current_runner.HERE = current_destination
    _pin_one_approved_test(current_runner, current_destination)
    case = current_destination / "test_unapproved.py"
    case.write_text("def test_unapproved():\n    raise AssertionError('UNAPPROVED_BODY_EXECUTED')\n")
    code = (
        "import importlib.util, pathlib, pytest\n"
        f"spec=importlib.util.spec_from_file_location('audit_runner', {current_runner.__file__!r})\n"
        "module=importlib.util.module_from_spec(spec)\nspec.loader.exec_module(module)\n"
        f"module.HERE=pathlib.Path({str(current_destination)!r})\n"
        f"raise SystemExit(pytest.main({[str(case), '-q', '-p', 'no:cacheprovider']!r}, plugins=[module.Execution()]))\n"
    )
    process = subprocess.run([sys.executable, "-B", "-c", code], cwd=current_runner.ROOT,
                             capture_output=True, timeout=30)
    assert process.returncode == 3, process.stdout + process.stderr
    assert b"unapproved test path" in process.stdout + process.stderr
    assert b"UNAPPROVED_BODY_EXECUTED" not in process.stdout + process.stderr
    execution = json.loads((current_destination / "execution.json").read_bytes())
    assert execution["started"] == [] and execution["finished"] == []
    assert not (current_destination / "execution-collection.json").exists()


@pytest.mark.parametrize("name", UNAPPROVED_TEST_PATHS)
def test_current_parent_rejects_unapproved_collected_path_before_suite(current_runner, monkeypatch, current_destination, name):
    # Preserve the real preflight, snapshot, collection admission and writers.
    # Only replace the child-process I/O boundary; no foreign test is executed.
    tmp_path = current_destination
    current_runner.HERE = tmp_path
    (tmp_path / "source-only").mkdir()
    (tmp_path / "source-only/peer-install-source.json").write_bytes(b"unused negative fixture")
    payloads = tmp_path / "exact-stage/payloads"
    payloads.mkdir(parents=True)
    (tmp_path / "exact-stage/payload-stage.json").write_bytes(b"unused negative fixture")
    for number in range(5):
        (payloads / str(number)).write_bytes(b"unused negative payload")
    calls = []

    def child_io(command, **kwargs):
        calls.append(command[-1])
        assert command[-1] == "--collect", "unapproved collection reached suite launch"
        current_runner.save("collection.json", {
            "count": 1, "duplicate_origins": [],
            "items": [{"nodeid": name + "::test_unapproved", "origin": ["foreign", "test_unapproved", ""]}]
        })
        return SimpleNamespace(returncode=0, stdout=b"negative collection fixture", stderr=b"")

    monkeypatch.setattr(subprocess, "run", child_io)
    with pytest.raises(ValueError, match="unapproved test path"):
        current_runner.audit()
    assert calls == ["--collect"]
    assert not (tmp_path / "execution.json").exists()
    assert not (tmp_path / "full-offline-suite.xml").exists()


@pytest.fixture
def runner():
    path = Path(__file__).resolve().parents[1] / "build/peer-route-review-20261004-rg418/run_audit.py"
    spec = importlib.util.spec_from_file_location("local_full_audit_runner", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def inventories():
    expected = {"items": [{"nodeid": "tests/test_a.py::test_one"}, {"nodeid": "tests/test_b.py::test_two"}]}
    names = [row["nodeid"] for row in expected["items"]]
    return expected, deepcopy(expected), {"started": names[:], "finished": names[:]}


def test_incomplete_stage_stops_before_children_and_cannot_reuse_the_preflight_attempt(runner, monkeypatch):
    # Regression of existing rejection behavior after a root orchestration
    # error. The real incident was launching before a yielded stage completed,
    # not the runner accepting missing evidence. Do not invent a code RED.
    def no_subprocess(*args, **kwargs):
        pytest.fail("missing stage launched a collection or suite child")

    with tempfile.TemporaryDirectory(prefix="audit-unfinished-stage-", dir=runner.ROOT / "build") as name:
        destination = Path(name)
        (destination / "source-only").mkdir()
        (destination / "source-only/peer-install-source.json").write_bytes(b"synthetic unused manifest")
        payloads = destination / "exact-stage/payloads"
        payloads.mkdir(parents=True)
        for index in range(5):
            (payloads / ("synthetic-" + str(index))).write_bytes(b"synthetic unused payload")
        monkeypatch.setattr(runner, "HERE", destination)
        monkeypatch.setattr(subprocess, "run", no_subprocess)
        with pytest.raises(FileNotFoundError, match="payload-stage.json"):
            runner.audit()
        retained = (destination / "build-preflight.json").read_bytes()
        assert not any((destination / name).exists() for name in (
            "AUDIT.json", "inputs-before.json", "collection.json", "execution.json", "full-offline-suite.xml"))
        with pytest.raises(ValueError, match="output already exists"):
            runner.audit()
        assert (destination / "build-preflight.json").read_bytes() == retained


@pytest.mark.parametrize("damage", ("selected_subset", "missing_start", "missing_finish", "duplicate_finish", "empty"))
def test_zero_status_with_missing_or_replaced_execution_is_not_complete(runner, damage):
    expected, selected, executed = inventories()
    if damage == "selected_subset":
        selected["items"].pop()
        executed["started"].pop()
        executed["finished"].pop()
    elif damage == "missing_start":
        executed["started"].pop()
    elif damage == "missing_finish":
        executed["finished"].pop()
    elif damage == "duplicate_finish":
        executed["finished"][1] = executed["finished"][0]
    else:
        expected["items"].clear()
        selected["items"].clear()
        executed["started"].clear()
        executed["finished"].clear()
    assert runner.execution_complete(expected, selected, executed) is False


def test_all_base_tests_must_start_and_finish_independently_of_subtest_count(runner):
    assert runner.execution_complete(*inventories()) is True


@pytest.mark.parametrize("arguments", [[], ["--collect"], ["--suite"], ["direct-audit"]])
def test_stale_bridge_stops_runner_before_collection_or_suite(runner, monkeypatch, arguments):
    # Filesystem and subprocess are the external boundaries. Keep the real
    # preflight, entry point and output writer; never mutate the actual build.
    build_path = runner.ROOT / "build/host-bridge/native/BUILD.json"
    read = Path.read_bytes

    def stale(path):
        raw = read(path)
        if path == build_path:
            report = json.loads(raw)
            report["inputs"]["tools/output_guard.py"] = "0" * 64
            return json.dumps(report).encode()
        return raw

    def no_subprocess(*args, **kwargs):
        pytest.fail("stale build launched collection or suite")

    def no_pytest(*args, **kwargs):
        pytest.fail("stale build entered pytest collection or suite")

    with tempfile.TemporaryDirectory(prefix="audit-stale-", dir=runner.ROOT / "build") as name:
        monkeypatch.setattr(runner, "HERE", Path(name))
        monkeypatch.setattr(Path, "read_bytes", stale)
        monkeypatch.setattr(subprocess, "run", no_subprocess)
        monkeypatch.setattr(pytest, "main", no_pytest)
        outcome = runner.audit() if arguments == ["direct-audit"] else runner.main(arguments)
        assert outcome == 1
        reports = list(Path(name).glob("*preflight*.json"))
        assert len(reports) == 1
        result = json.loads(reports[0].read_bytes())
        assert result["status"] == "LOCAL_BUILD_PREFLIGHT_FAILED"
        assert "tools/output_guard.py" in result["error"]
        assert result["installable"] is False and result["camera_accesses"] == 0
        assert not (Path(name) / "collection.json").exists()
        assert not (Path(name) / "execution.json").exists()


@pytest.mark.parametrize("artifact", ["collect-preflight-failed.json", "suite-preflight-failed.json"])
def test_full_audit_cannot_reuse_a_directory_with_a_child_preflight_failure(runner, monkeypatch, artifact):
    with tempfile.TemporaryDirectory(prefix="audit-failed-child-", dir=runner.ROOT / "build") as name:
        destination = Path(name)
        prior = destination / artifact
        prior.write_bytes(b"immutable prior failure")
        monkeypatch.setattr(runner, "HERE", destination)
        with pytest.raises(ValueError, match="already exists"):
            runner.main([])
        assert prior.read_bytes() == b"immutable prior failure"
        assert sorted(p.name for p in destination.iterdir()) == [artifact]


@pytest.mark.parametrize("arguments,artifact", [
    (["--collect"], "collection.json"),
    (["--suite"], "execution-collection.json"),
    (["--suite"], "execution.json"),
    (["--suite"], "full-offline-suite.xml"),
] + [([mode], artifact) for mode in ("--collect", "--suite")
     for artifact in ("AUDIT.json", "audit-preflight-failed.json",
                      "collect-preflight-failed.json", "suite-preflight-failed.json")])
def test_direct_child_cannot_enter_pytest_with_existing_stage_outputs(runner, monkeypatch, arguments, artifact):
    def no_pytest(*args, **kwargs):
        pytest.fail("existing stage output did not stop pytest before collection/report writing")

    with tempfile.TemporaryDirectory(prefix="audit-existing-child-", dir=runner.ROOT / "build") as name:
        destination = Path(name)
        prior = destination / artifact
        prior.write_bytes(b"immutable prior report")
        monkeypatch.setattr(runner, "HERE", destination)
        monkeypatch.setattr(pytest, "main", no_pytest)
        with pytest.raises(ValueError, match="already exists"):
            runner.main(arguments)
        assert prior.read_bytes() == b"immutable prior report"


def test_direct_suite_preserves_existing_xml_with_real_pytest_in_a_child(runner):
    with tempfile.TemporaryDirectory(prefix="audit-xml-preserve-", dir=runner.ROOT / "build") as name:
        destination = Path(name)
        prior = destination / "full-offline-suite.xml"
        prior.write_bytes(b"immutable prior XML")
        case = destination / "test_probe.py"
        case.write_text("def test_probe():\n    assert True\n")
        # Only replace pytest's filesystem suite argument with a tiny real
        # suite. Its real XML writer would overwrite the sentinel if entered.
        code = (
            "import importlib.util, pathlib, pytest\n"
            f"spec=importlib.util.spec_from_file_location('audit_runner', {runner.__file__!r})\n"
            "module=importlib.util.module_from_spec(spec)\nspec.loader.exec_module(module)\n"
            f"module.HERE=pathlib.Path({str(destination)!r})\n"
            "original=pytest.main\n"
            f"pytest.main=lambda args, plugins: original([{str(case)!r} if a == 'tests' else a for a in args], plugins=plugins)\n"
            "try:\n    module.main(['--suite'])\n"
            "except ValueError as error:\n    print(error)\n    raise SystemExit(86)\n"
            "raise SystemExit(99)\n"
        )
        process = subprocess.run([sys.executable, "-B", "-c", code], cwd=runner.ROOT,
                                 capture_output=True, timeout=30)
        assert process.returncode == 86, process.stdout + process.stderr
        assert b"output already exists" in process.stdout
        assert prior.read_bytes() == b"immutable prior XML"
        assert not (destination / "execution.json").exists()


def test_historical_inventory_is_rejected_before_its_paths_can_be_trusted(runner, monkeypatch):
    historical = runner.ROOT / "build/peer-route-review-20261004-rg390/inputs-before.json"
    read = Path.read_bytes

    def changed(path):
        raw = read(path)
        return raw + b" " if path == historical else raw

    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="historical input inventory hash"):
        runner.snapshot()


def test_real_pytest_hooks_detect_subset_and_include_skipped_base_test(runner):
    with tempfile.TemporaryDirectory(prefix="audit-hooks-", dir=runner.ROOT / "build") as name:
        root = Path(name)
        case = root / "test_probe.py"
        case.write_text("import pytest\ndef test_one(subtests):\n"
                        "    for value in (1, 2):\n"
                        "        with subtests.test(value=value):\n"
                        "            assert value > 0\n"
                        "def test_two():\n    pytest.skip('explicit mini-suite skip')\n")
        results = []
        for label, selector in (("all", []), ("subset", ["-k", "test_one"])):
            destination = root / label
            destination.mkdir()
            code = (
                "import importlib.util, pathlib, pytest; "
                f"s=importlib.util.spec_from_file_location('audit_runner', {runner.__file__!r}); "
                "m=importlib.util.module_from_spec(s); s.loader.exec_module(m); "
                f"m.HERE=pathlib.Path({str(destination)!r}); "
                f"raise SystemExit(pytest.main({[str(case), '-q', '-p', 'no:cacheprovider', *selector]!r}, plugins=[m.Execution()]))"
            )
            process = subprocess.run([sys.executable, "-B", "-c", code], cwd=runner.ROOT,
                                     capture_output=True, timeout=30)
            assert process.returncode == 0, process.stdout + process.stderr
            results.append((json.loads((destination / "execution-collection.json").read_bytes()),
                            json.loads((destination / "execution.json").read_bytes())))
        full, full_execution = results[0]
        subset, subset_execution = results[1]
        assert full["count"] == 2 and subset["count"] == 1
        assert full_execution["passing_subtest_count"] == subset_execution["passing_subtest_count"] == 2
        assert runner.execution_complete(full, full, full_execution) is True
        assert runner.execution_complete(full, subset, subset_execution) is False
