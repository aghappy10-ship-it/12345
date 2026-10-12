"""RG090/RG141: the current parent must count real, exact JUnit rows."""
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import xml.etree.ElementTree as ET

import pytest


@pytest.fixture
def current_runner():
    path = Path(__file__).resolve().parents[1] / "build/peer-route-review-20261006-menu-evidence/run_audit.py"
    spec = importlib.util.spec_from_file_location("junit_audit_runner", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def audit_destination(current_runner):
    import tempfile
    with tempfile.TemporaryDirectory(prefix="audit-junit-", dir=current_runner.ROOT / "build") as name:
        current_runner.HERE = Path(name)
        yield Path(name)


def inventory_and_execution():
    nodes = ["tests/test_full_audit_junit.py::test_one", "tests/test_full_audit_junit.py::test_two"]
    inventory = {"count": 2, "duplicate_origins": [], "items": [
        {"nodeid": node, "origin": ["tests.test_full_audit_junit", node.split("::")[-1], ""]}
        for node in nodes]}
    execution = {"started": nodes[:], "finished": nodes[:], "passing_subtest_count": 0, "exit_code": 0}
    return inventory, execution


def xml_bytes(*, names=("test_one", "test_two"), tests=None, failures=0, errors=0, skipped=0):
    root = ET.Element("testsuites")
    suite = ET.SubElement(root, "testsuite", tests=str(len(names) if tests is None else tests),
                          failures=str(failures), errors=str(errors), skipped=str(skipped))
    for name in names:
        ET.SubElement(suite, "testcase", classname="tests.test_full_audit_junit", name=name)
    return ET.tostring(root)


@pytest.mark.parametrize("names,header", [(('test_one',), 2), (('test_one',), 999)])
def test_parent_refuses_subset_rows_even_with_complete_execution_and_inflated_header(
        current_runner, audit_destination, monkeypatch, names, header):
    # Real parent verdict/writers, with ONLY build preflight/snapshot and child
    # I/O substituted. The old parent accepted this exact forged-row contract.
    inventory, execution = inventory_and_execution()
    path = Path(__file__).resolve()
    raw = path.read_bytes()
    snapshot = {"files": {str(path): {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}},
                "runtime_file_count": 0, "actual_runtime_inventory_matches_build": True}
    monkeypatch.setattr(current_runner, "snapshot", lambda: snapshot)
    monkeypatch.setattr(current_runner, "preflight", lambda label: {"test_only": True})

    def child(command, **kwargs):
        if command[-1] == "--collect":
            current_runner.save("collection.json", inventory)
        else:
            assert command[-1] == "--suite"
            current_runner.save("execution-collection.json", inventory)
            current_runner.save("execution.json", execution)
            current_runner.write_output(audit_destination / "full-offline-suite.xml",
                                        xml_bytes(names=names, tests=header))
        return SimpleNamespace(returncode=0, stdout=b"test-only child I/O", stderr=b"")

    monkeypatch.setattr(current_runner.subprocess, "run", child)
    assert current_runner.audit() == 1
    result = json.loads((audit_destination / "AUDIT.json").read_bytes())
    assert result["status"] == "LOCAL_AUDIT_FAILED"
    assert result["installable"] is False and result["package_created"] is False
    assert result["failures"] is None and result["skips"] is None
    assert result["junit_validation_error"]


def test_exact_rows_and_passing_subtest_total_are_distinct(current_runner, audit_destination):
    inventory, execution = inventory_and_execution()
    execution["passing_subtest_count"] = 3
    path = audit_destination / "valid.xml"
    path.write_bytes(xml_bytes(tests=5))
    result = current_runner.validate_junit(path, inventory, execution)
    assert result["main_testcase_count"] == 2
    assert result["passing_subtest_count"] == 3
    assert result["reported_test_count"] == 5
    assert result["failures"] == [] and result["skips"] == []


@pytest.mark.parametrize("damage", [
    "blank_class", "blank_name", "duplicate", "foreign", "missing_row", "extra_row",
    "inflated_header", "wrong_failures", "wrong_errors", "wrong_skips", "missing_tests",
    "nonnumeric_tests", "collection_error", "multiple_outcomes", "duplicate_suite",
    "unsupported_testcase_child", "namespaced_failure",
])
def test_current_strict_junit_refuses_semantic_damage(current_runner, audit_destination, damage):
    inventory, execution = inventory_and_execution()
    root = ET.fromstring(xml_bytes())
    suite = root.find("testsuite")
    first, second = list(suite)
    if damage == "blank_class": first.set("classname", "")
    elif damage == "blank_name": first.set("name", "")
    elif damage == "duplicate": second.set("name", first.get("name"))
    elif damage == "foreign": first.set("classname", "reference.third_party.test_vendor")
    elif damage == "missing_row": suite.remove(second)
    elif damage == "extra_row": ET.SubElement(suite, "testcase", classname="foreign", name="test_other")
    elif damage == "inflated_header": suite.set("tests", "999")
    elif damage == "wrong_failures": suite.set("failures", "1")
    elif damage == "wrong_errors": suite.set("errors", "1")
    elif damage == "wrong_skips": suite.set("skipped", "1")
    elif damage == "missing_tests": del suite.attrib["tests"]
    elif damage == "nonnumeric_tests": suite.set("tests", "2.0")
    elif damage == "collection_error": ET.SubElement(suite, "error", message="vendor collection failure")
    elif damage == "multiple_outcomes":
        ET.SubElement(first, "failure"); ET.SubElement(first, "skipped")
    elif damage == "duplicate_suite": root.append(ET.fromstring(ET.tostring(suite)))
    elif damage == "unsupported_testcase_child": ET.SubElement(first, "bogus", message="not an accepted outcome")
    elif damage == "namespaced_failure": ET.SubElement(first, "{unapproved}failure", message="hidden failure")
    path = audit_destination / "invalid.xml"
    path.write_bytes(ET.tostring(root))
    with pytest.raises(ValueError):
        current_runner.validate_junit(path, inventory, execution)


def test_actual_failure_and_skip_children_are_counted_without_hiding_them(current_runner, audit_destination):
    inventory, execution = inventory_and_execution()
    root = ET.fromstring(xml_bytes(failures=1, skipped=1))
    suite = root.find("testsuite")
    ET.SubElement(suite[0], "failure", message="actual failure")
    ET.SubElement(suite[1], "skipped", message="explicit skip")
    path = audit_destination / "outcomes.xml"
    path.write_bytes(ET.tostring(root))
    result = current_runner.validate_junit(path, inventory, execution)
    assert result["failures"] == ["tests.test_full_audit_junit.test_one"]
    assert result["skips"] == [{"name": "tests.test_full_audit_junit.test_two", "reason": "explicit skip"}]


def test_parameter_node_with_double_colon_uses_real_pytest_identity(current_runner, audit_destination):
    node = "tests/test_full_audit_junit.py::Sample::test_param[tools::entry]"
    inventory = {"count": 1, "duplicate_origins": [], "items": [{"nodeid": node}]}
    execution = {"started": [node], "finished": [node], "passing_subtest_count": 0}
    root = ET.fromstring(xml_bytes(names=("test_param[tools::entry]",)))
    root.find("testsuite/testcase").set("classname", "tests.test_full_audit_junit.Sample")
    path = audit_destination / "param.xml"
    path.write_bytes(ET.tostring(root))
    assert current_runner.validate_junit(path, inventory, execution)["main_testcase_count"] == 1
