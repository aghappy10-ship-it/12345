"""Prepare one unapplied goal append and validate it with the existing APIs.

No formal source/registry write, native execution, camera access or release PASS.
Every pending input is pinned as a complete file; any change refuses this run.
"""
import ast
import hashlib
import json
import os
from pathlib import Path
import sys
import types


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))
from tools import regression_manifest as registry
from tools import release_identity
from tools.output_guard import guard_output


PENDING = (
    ("build/install160-original-diagnostic-20261012/PENDING_REGRESSION_GOAL.json", "a62b4547d7a7cca3c67c13d645b05c6da51e01e253aa08566fe076587539ebf3"),
    ("build/path-length-control-20261012/PENDING_REGRESSION_GOAL.json", "a998505475fd1f2ec59b6008dac353cdaff46b288bc291d47b41c450b60d47f8"),
    ("build/receipt360-original-diagnostic-20261012/PENDING_REGRESSION_GOAL.json", "05bf4db44a0a17113056d3cceda8c154f6a6dc6032c7e9a9e745fb5d4c3c10ef"),
    ("build/receipt360-original-diagnostic-20261012/PENDING_DISCONNECTED_REGRESSION_GOAL.json", "5abf0329444b1a16aebc6994f465a2407e5af7da3a5d3958e03d691a14c1720d"),
    ("build/path-length-control-20261012/PENDING_DEPENDENCY_REGRESSION_GOAL.json", "bfba7226459e267269d90f2acd25e3df72d08962c2cd85c7d2278fe94fd462d2"),
    ("build/receipt360-original-diagnostic-20261012/PENDING_REPLACEMENT_REGRESSION_GOAL.json", "c3d5950c50f01a45f02bcdad101a361e5e5399106315ca6fef0481f08ec72435"),
    ("build/receipt360-original-diagnostic-20261012/PENDING_OFFER_REGRESSION_GOAL.json", "3619228fed06e62486f46bd85f0c70d5e3f08a91772c3db39e510a47adf75568"),
    ("build/receipt360-original-diagnostic-20261012/PENDING_GUARDIAN_PREINJECTION_REGRESSION_GOAL.json", "8d5e8ce5a0ef3db3060f84eafede5baf76abb0bf94a4caa0ea8112f7b2d18f38"),
)
GENERATOR = ROOT / "tools/regression_manifest.py"
GENERATOR_SHA = "d2c69c974927b818fc7ccae920ff28bc4d6013e50c5be1f02a3b3dccb3447c90"
MANIFEST_SHA = "bd164c267b563d710047d734d735d47c8dfef358f5b3f0cdf37293527df0d656"
FROZEN_INPUTS_SHA = "655e219d41b6c6dd4b6f994ab3a89ed76cf41e0d09d4191d37fe53ba4fec79b5"
PATCH = HERE / "append_regression_548_555_after_freeze_v2.patch"
RESULT = HERE / "regression-548-555-projection-v2-20261012.json"
REFUSAL = HERE / "regression-548-555-projection-refused-v2-20261012.json"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def publish(path, raw):
    guard_output(path, must_be_new=True)
    with path.open("xb") as output:
        require(output.write(raw) == len(raw), "short owned artifact write")
        output.flush()
        os.fsync(output.fileno())
    guard_output(path)
    require(path.read_bytes() == raw, "owned artifact readback differs")


def same_inputs(raw_inputs):
    changed = []
    for path, old in raw_inputs.items():
        current = path.read_bytes()
        if current != old:
            changed.append({"path": str(path), "expected_sha256": sha(old),
                            "actual_sha256": sha(current)})
    require(not changed, "pinned input changed; refuse mixed binding: " + json.dumps(changed))


def run():
    require(not sys.argv[1:], "append projection takes no arguments")
    require(sys.dont_write_bytecode and not sys.flags.optimize, "normal Python -B required")
    for path in (PATCH, RESULT, REFUSAL):
        guard_output(path, must_be_new=True)
    expected = {ROOT / relative: digest for relative, digest in PENDING}
    expected.update({GENERATOR: GENERATOR_SHA, registry.MANIFEST_PATH: MANIFEST_SHA,
                     registry.SOURCE_PATH: registry.SOURCE_SHA256})
    raw_inputs = {path: path.read_bytes() for path in expected}
    mismatches = [{"path": str(path), "expected_sha256": expected[path],
                   "actual_sha256": sha(raw)} for path, raw in raw_inputs.items()
                  if sha(raw) != expected[path]]
    require(not mismatches, "pending or formal input changed; refuse mixed binding: " + json.dumps(mismatches))
    formal_inputs = release_identity.source_inputs()
    require(len(formal_inputs) == 230 and sha(release_identity.canonical(formal_inputs))
            == FROZEN_INPUTS_SHA, "formal 230/655e source boundary changed")
    goals = []
    for number, (relative, ignored_digest) in enumerate(PENDING, 548):
        document = registry.strict_json(raw_inputs[ROOT / relative])
        if "expected_prior_goal_count" in document:
            require(document["expected_prior_goal_count"] == 547, "pending prior count differs")
        if "expected_prior_registry_sha256" in document:
            require(document["expected_prior_registry_sha256"] == MANIFEST_SHA, "pending prior registry differs")
        goal = document["proposed_goal"]
        require(set(goal) == registry.GOAL_FIELDS and goal["id"] == f"X2D-RG-{number:03d}",
                "pending goal fields/order differ")
        require(all(type(goal[field]) is str for field in registry.GOAL_FIELDS - {"required_evidence"})
                and type(goal["required_evidence"]) is list
                and all(type(value) is str for value in goal["required_evidence"]),
                "goals must retain only exact string fields and evidence strings")
        goals.append(goal)

    source = raw_inputs[GENERATOR].decode("utf-8")
    anchor = "MACHINE_EVIDENCE_GAPS = ["
    require(source.count(anchor) == 1, "unique end-of-NEW_GOALS anchor required")
    addition = "NEW_GOALS += " + json.dumps(goals, ensure_ascii=False, indent=4, allow_nan=False) + "\n\n\n"
    projected_source = source.replace(anchor, addition + anchor, 1)
    original_tree = ast.parse(source, filename=str(GENERATOR))
    projected_tree = ast.parse(projected_source, filename=str(GENERATOR))
    new_nodes = [index for index, node in enumerate(projected_tree.body)
                 if isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name)
                 and node.target.id == "NEW_GOALS" and ast.literal_eval(node.value) == goals]
    require(len(new_nodes) == 1, "one exact eight-goal append required")
    projected_tree.body.pop(new_nodes[0])
    require(ast.dump(projected_tree) == ast.dump(original_tree), "append changed existing generator logic")
    patch = ("*** Begin Patch\n*** Update File: tools/regression_manifest.py\n@@\n-" + anchor + "\n"
             + "\n".join("+" + line for line in (addition + anchor).splitlines())
             + "\n*** End Patch\n").encode("utf-8")
    projected = types.ModuleType("tools._projected_regression_append_548_555")
    projected.__file__ = str(GENERATOR)
    projected.__package__ = "tools"
    exec(compile(projected_source, str(GENERATOR), "exec"), projected.__dict__)
    require(registry.canonical(projected.NEW_GOALS) == registry.canonical(registry.NEW_GOALS + goals),
            "executed append differs from exact proposed_goal objects")
    inherited = raw_inputs[registry.SOURCE_PATH]
    prior = registry.strict_json(raw_inputs[registry.MANIFEST_PATH])
    prior_check = registry.validate_manifest(prior, inherited)
    require(prior_check["goal_count"] == 547, "prior registry must contain exactly547 goals")
    manifest = projected.build_manifest(inherited)
    check = projected.validate_manifest(manifest, inherited)
    require(check["inventory_valid"] is True and check["goal_count"] == 555,
            "existing manifest API refused the eight-item projection")
    require(registry.canonical(manifest["goals"][:547]) == registry.canonical(prior["goals"])
            and registry.canonical(manifest["goals"][547:]) == registry.canonical(goals),
            "old goals or new proposed strings changed")
    old_ids = [goal["id"] for goal in prior["goals"]]
    new_ids = [goal["id"] for goal in goals]
    require(set(manifest["applicability"]) == set(old_ids + new_ids), "seed identities lost or invented")
    require(registry.canonical({key: manifest["applicability"][key] for key in old_ids})
            == registry.canonical(prior["applicability"]), "complete prior seed changed")
    prior_effective = registry.effective_applicability(prior)
    effective = projected.effective_applicability(manifest)
    require(registry.canonical({key: effective[key] for key in old_ids})
            == registry.canonical(prior_effective), "accepted historical effective rows changed")
    aggregate_review_fields = {"input_seed_sha256", "input_goals_sha256", "effective_rows_sha256"}
    require(registry.canonical({key: value for key, value in manifest["applicability_review"].items()
                                if key not in aggregate_review_fields})
            == registry.canonical({key: value for key, value in prior["applicability_review"].items()
                                   if key not in aggregate_review_fields}), "accepted review history changed")
    for key in new_ids:
        for row in (manifest["applicability"][key], effective[key]):
            require(row["applicability"] == "APPLICABLE" and row["evidence_status"] == "NOT_RUN"
                    and row["counts_as_pass"] is False and row["evidence_refs"] == [],
                    "new goal gained evidence or lost release applicability: " + key)
    for key in ("schema", "inherited_source", "requirement_contract", "requirement_sha256", "policy", "qualification"):
        require(registry.canonical(manifest[key]) == registry.canonical(prior[key]), "existing field changed: " + key)
    require(check["pass_count"] == 0 and check["installable"] is False and check["package_eligible"] is False
            and manifest["qualification"]["installable"] is False
            and manifest["qualification"]["package_created"] is False, "projection acquired release authority")
    same_inputs(raw_inputs)
    require(release_identity.source_inputs() == formal_inputs, "formal inputs changed during projection")
    publish(PATCH, patch)
    same_inputs(raw_inputs)
    report = {
        "status": "UNAPPLIED_APPEND_PROJECTION_VALID_NOT_FORMAL_GREEN",
        "script_sha256": sha(Path(__file__).read_bytes()), "patch_sha256": sha(patch),
        "projected_generator_sha256": sha(projected_source.encode("utf-8")),
        "pinned_inputs": {str(path): sha(raw) for path, raw in raw_inputs.items()},
        "pending_goals_sha256": {goal["id"]: sha(registry.canonical(goal)) for goal in goals},
        "prior_goal_count": 547, "projected_goal_count": 555,
        "prior_goals_preserved_exactly": True, "complete_prior_seed_preserved_exactly": True,
        "accepted_review_history_and_effective_rows_preserved_exactly": True,
        "only_review_aggregate_hashes_recomputed": sorted(aggregate_review_fields),
        "new_seed_rows": {key: manifest["applicability"][key] for key in new_ids},
        "policy_and_qualification_unchanged": True,
        "formal_input_count": 230, "formal_input_sha256": FROZEN_INPUTS_SHA,
        "existing_build_and_validate_api_used": True, "inventory_valid": True,
        "qualified": False, "installable": False, "formal_patch_applied": False,
        "formal_registry_written": False, "complete_suite_executed": False,
        "native_execution": False, "camera_accesses": 0,
        "limits": "Only an independent in-memory append was validated. Formal generator/registry and all547 goals remain frozen. New555-source formal GREEN and complete JSON update remain required after freeze.",
    }
    same_inputs(raw_inputs)
    publish(RESULT, (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    print(json.dumps({key: report[key] for key in ("status", "patch_sha256", "prior_goal_count", "projected_goal_count",
                     "formal_input_count", "formal_input_sha256", "qualified", "installable")}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(run())
    except (OSError, ValueError, KeyError, TypeError, SyntaxError) as error:
        try:
            refusal = {"status": "APPEND_PROJECTION_REFUSED_NO_MIXED_INPUT_BINDING",
                       "error": type(error).__name__ + ": " + str(error),
                       "formal_patch_applied": False, "qualified": False, "installable": False,
                       "camera_accesses": 0, "draft_patch_may_be_retained_but_is_not_admitted": PATCH.exists()}
            publish(REFUSAL, (json.dumps(refusal, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
            print(json.dumps(refusal, ensure_ascii=False, indent=2), file=sys.stderr)
        except BaseException as reporting_error:
            try:
                error.add_note("Append refusal reporting failed: " + repr(reporting_error))
            except BaseException:
                pass
        raise
