"""Three input additions projected in memory; never a formal-source GREEN.

Only the reviewed AUDIT_INPUTS hunk is applied to an independent module.
The existing public build-identity test body and its three-case caller are
reused. Formal files, source inventories and the regression registry stay frozen.
"""
import ast
import hashlib
import os
from pathlib import Path
import sys
import types
from unittest import mock
import xml.etree.ElementTree as ET


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))
from tools import release_identity as formal
from tools.output_guard import guard_output


PATCH = HERE / "update_consumed_inputs_after_freeze.patch"
CALLER = HERE / "test_consumed_audit_inputs.py"
BODY = ROOT / "tests/test_current_audit_lifetime.py"
EXPECTED = {
    PATCH: "076b96776eb450191204e4bbd608750fb5f21ffec5cb1a8632cabe0e52e15a5e",
    CALLER: "9bbba3287c9311e86375dc4443af0ea77dbe60ee7c3b4ff31ca57160e86bb6f7",
    BODY: "9025710e72631147550ce069ce44e84958a219029dc9cbd31de0567bf5065e6f",
    Path(formal.__file__): "a2667476d4d87ae6a32ca13cec383c4f9aa5d5d341705eaa9a2c9d563354edc3",
}
ADDITIONS = (
    "build/peer-route-review-20261011-host-fixed/run_audit.py",
    "build/peer-route-review-20261011-host-fixed/launch_admin_audit_once.py",
    "build/peer-route-review-20261012-short-root/run_audit.py",
)
XML = HERE / "inputbind-projection-green-20261012.xml"
RESULT = HERE / "inputbind-projection-20261012.json"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def assignment(tree):
    found = [node for node in tree.body if isinstance(node, ast.Assign)
             and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
             and node.targets[0].id == "AUDIT_INPUTS"]
    require(len(found) == 1, "one AUDIT_INPUTS assignment required")
    return found[0]


def main():
    require(not sys.argv[1:], "projection control accepts no arguments")
    require(sys.dont_write_bytecode and not sys.flags.optimize,
            "use normal Python with -B; optimized assertions are forbidden")
    guard_output(XML, must_be_new=True)
    guard_output(RESULT, must_be_new=True)
    raw_inputs = {path: path.read_bytes() for path in EXPECTED}
    for path, raw in raw_inputs.items():
        require(digest(raw) == EXPECTED[path], "reviewed control input changed: " + str(path))

    patch = raw_inputs[PATCH].decode("utf-8")
    marker = "*** Update File: tools/release_identity.py\n@@\n"
    require(patch.count(marker) == 1, "reviewed input hunk missing or ambiguous")
    hunk = patch.split(marker, 1)[1].split("*** Update File:", 1)[0].splitlines()
    require(len(hunk) == 5 and hunk[0].startswith("-")
            and all(line.startswith("+") for line in hunk[1:]), "unexpected projection hunk")
    old = hunk[0][1:]
    new = "\n".join(line[1:] for line in hunk[1:])
    source_path = Path(formal.__file__)
    source = raw_inputs[source_path].decode("utf-8")
    require(source.count(old) == 1, "formal hunk target missing or ambiguous")
    projected_source = source.replace(old, new, 1)
    before_tree = ast.parse(source, filename=str(source_path))
    after_tree = ast.parse(projected_source, filename=str(source_path))
    original_tuple = tuple(ast.literal_eval(assignment(before_tree).value))
    projected_tuple = tuple(ast.literal_eval(assignment(after_tree).value))
    require(len(original_tuple) == 13 and len(set(original_tuple)) == 13,
            "unexpected retained thirteen-item inventory")
    require(projected_tuple == original_tuple + ADDITIONS,
            "projection must retain every original item and add exactly the three reviewed paths")
    require(not set(original_tuple).intersection(ADDITIONS), "addition already existed")
    assignment(after_tree).value = assignment(before_tree).value
    require(ast.dump(after_tree) == ast.dump(before_tree),
            "projection changed something besides AUDIT_INPUTS")

    projected = types.ModuleType("tools._projected_consumed_inputs")
    projected.__file__ = str(source_path)
    projected.__package__ = "tools"
    exec(compile(projected_source, str(source_path), "exec"), projected.__dict__)
    require(projected.AUDIT_INPUTS == original_tuple + ADDITIONS,
            "executed projected tuple differs from reviewed additions")
    baseline = formal.source_inputs()
    baseline_sha = formal.sha(formal.canonical(baseline))
    require(len(baseline) == 230 and baseline_sha ==
            "655e219d41b6c6dd4b6f994ab3a89ed76cf41e0d09d4191d37fe53ba4fec79b5",
            "formal frozen 230/655e baseline changed")
    projected_inputs = projected.source_inputs()
    require(set(projected_inputs) - set(baseline) == set(ADDITIONS)
            and all(projected_inputs[path] == record for path, record in baseline.items()),
            "projected inventory must preserve all existing source records")
    for relative in ADDITIONS:
        raw = (ROOT / relative).read_bytes()
        require(projected_inputs[relative] == {"sha256": digest(raw), "bytes": len(raw)},
                "projected added source bytes differ: " + relative)
    inert_candidate = {"test_fixture_only": True}
    inert_scripts = {"fixture.sh": "exit 0\n"}
    baseline_subject = formal.build_subject(inert_candidate, inert_scripts, source_hash="a" * 64)
    projected_subject = projected.build_subject(inert_candidate, inert_scripts, source_hash="a" * 64)
    require(projected_subject != baseline_subject, "public build subject ignored the additions")

    import pytest
    import tools
    with mock.patch.object(tools, "release_identity", projected), \
            mock.patch.dict(os.environ, {"PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"}, clear=False):
        code = pytest.main([str(CALLER), "-q", "-p", "no:cacheprovider",
                            "--junitxml=" + str(XML)])
    require(tools.release_identity is formal, "formal module attribute was not restored")
    guard_output(XML)
    root = ET.parse(XML).getroot()
    suites = list(root)
    require(root.tag == "testsuites" and len(suites) == 1, "unexpected projection JUnit structure")
    suite = suites[0]
    require(code == 0 and suite.get("tests") == "3"
            and all(suite.get(field) == "0" for field in ("failures", "errors", "skipped"))
            and len(suite.findall("testcase")) == 3,
            "three original-body projection cases did not all pass")
    for path, raw in raw_inputs.items():
        require(path.read_bytes() == raw, "formal/control source changed during projection: " + str(path))
    require(formal.source_inputs() == baseline,
            "formal inventory changed during independent projection")
    require(formal.build_subject(inert_candidate, inert_scripts, source_hash="a" * 64)
            == baseline_subject, "formal public subject changed")
    require(projected.source_inputs() == projected_inputs
            and projected.build_subject(inert_candidate, inert_scripts, source_hash="a" * 64)
            == projected_subject, "projected identity was not restored after read-boundary faults")
    report = {
        "status": "PROJECTED_INPUT_CONTROL_GREEN_NOT_FORMAL_GREEN",
        "patch_applied_to_formal_files": False,
        "scope": "Independent in-memory AUDIT_INPUTS projection; three original public identity test bodies only",
        "script_sha256": digest(Path(__file__).read_bytes()),
        "reviewed_inputs": {str(path): digest(raw) for path, raw in raw_inputs.items()},
        "projected_release_identity_source_sha256": digest(projected_source.encode("utf-8")),
        "original_audit_inputs": list(original_tuple),
        "projected_audit_inputs": list(projected_tuple),
        "exact_three_additions": list(ADDITIONS),
        "original_thirteen_items_preserved_verbatim_and_in_order": True,
        "only_audit_inputs_ast_changed": True,
        "all_formal_source_records_unchanged": True,
        "formal_source_input_count": len(baseline), "formal_source_input_sha256": baseline_sha,
        "projected_source_input_count": len(projected_inputs),
        "projected_source_input_sha256": projected.sha(projected.canonical(projected_inputs)),
        "actual_added_source_records": {path: projected_inputs[path] for path in ADDITIONS},
        "formal_public_build_subject_sha256": baseline_subject,
        "projected_public_build_subject_sha256": projected_subject,
        "pytest_exit_code": code, "test_count": 3, "failures": 0, "errors": 0, "skips": 0,
        "xml_sha256": digest(XML.read_bytes()), "original_test_body_substituted": False,
        "module_attribute_restored": True, "native_shell_executions": 0,
        "complete_audit_executed": False, "camera_accesses": 0, "installable": False,
        "limits": "Formal sources remain unchanged and missing these inputs; projected GREEN cannot qualify the unapplied patch or replace fresh formal tests/full audit.",
    }
    guard_output(RESULT, must_be_new=True)
    encoded = (formal.json.dumps(report, indent=2) + "\n").encode("utf-8")
    with RESULT.open("xb") as output:
        require(output.write(encoded) == len(encoded), "short projection report write")
        output.flush()
        os.fsync(output.fileno())
    guard_output(RESULT)
    require(RESULT.read_bytes() == encoded, "projection report readback mismatch")
    print(formal.json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
