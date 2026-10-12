"""A local, classification-only overlay over immutable inherited seed rows.

Only load_review_record reads files, all under this project. It never follows
source paths named in reports. reviewed_overlay is pure over its two inputs and
the pinned review snapshot loaded at import; it does not read current source,
run a test, issue an authorization, or access the frozen historical project.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REVIEW_PATH = ROOT / "work/reverse/INHERITED_APPLICABILITY_REVIEW.json"
REVIEW_SHA256 = "ebc4fe679e0376ea6be6b240f59fda5bb0452d6db0f7c69440558779ed43b489"


class ReviewError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def require(ok, message):
    if not ok:
        raise ReviewError(message)


def parse_review_bundle(record_bytes, report_bytes):
    """Validate exact accepted document bytes, without any filesystem reads."""
    require(digest(record_bytes) == REVIEW_SHA256, "accepted review SHA-256 mismatch")
    record = json.loads(record_bytes)
    require(set(report_bytes) == {r["path"] for r in record["source_reports"]},
            "exactly the three accepted reports are required")
    proposals, goal_hashes, source_reviews = {}, {}, []
    preserved = record["preserved_seed_rows"]
    for source in record["source_reports"]:
        raw = report_bytes[source["path"]]
        require(digest(raw) == source["sha256"], "source report SHA-256 mismatch: " + source["path"])
        document = json.loads(raw)
        require(document["reviewer"] == source["author"], "source report author mismatch")
        first, last = source["first"], source["last"]
        expected = {f"X2D-RG-{i:03d}" for i in range(first, last + 1)}
        if "proposals" in document:
            source_rows = document["proposals"] | document["preserved_existing"]
            pending = document["proposals"]
            require(not set(pending) & set(document["preserved_existing"]), "overlapping report rows")
            for key, summary in document["preserved_existing"].items():
                original = preserved[key]
                # The second report records a seed summary, not a replacement.
                require(all(original.get(field) == value for field, value in summary.items()
                            if field != "unchanged"), "preserved seed summary mismatch: " + key)
        else:
            source_rows = {row["id"]: row for row in document["rows"]}
            require(len(source_rows) == len(document["rows"]), "duplicate report row")
            pending = {key: row for key, row in source_rows.items() if key not in preserved}
            for key in set(source_rows) & set(preserved):
                require(source_rows[key]["goal_sha256"] == preserved[key]["goal_sha256"]
                        and source_rows[key]["applicability"] == preserved[key]["applicability"],
                        "preserved seed identity/classification mismatch: " + key)
        require(set(source_rows) == expected and len(pending) == source["pending"],
                "report range or pending count mismatch")
        require(len(expected - set(pending)) == source["preserved"], "report preserved count mismatch")
        for key, row in source_rows.items():
            require(key not in goal_hashes, "overlapping report ranges")
            goal_hashes[key] = row["goal_sha256"]
        for key, row in pending.items():
            decision = row.get("proposed_applicability", row.get("applicability"))
            require(decision in ("APPLICABLE", "OUT_OF_SCOPE"), "unresolved proposal")
            require(row["counts_as_pass"] is False and row["evidence_status"] == "NOT_RUN"
                    and not row.get("evidence_refs", []), "classification contains execution evidence")
            proposals[key] = {"applicability": decision, "scope_reason": row["scope_reason"]}
        source_reviews.append({
            **source,
            "reviewed_bindings": document.get("bindings", document.get("inherited_source")),
            "source_snapshots": document.get("source_evidence", document.get("source_snapshots")),
            "reviewed_scope": document["scope"],
            "implementation_reviewed": False,
        })
    for key, correction in record["rationale_corrections"].items():
        require(proposals[key]["applicability"] == correction["applicability"],
                "rationale correction changes classification")
        proposals[key]["scope_reason"] = correction["scope_reason"]
    require(len(proposals) == record["reviewed_pending_count"], "reviewed count mismatch")
    require({state: sum(r["applicability"] == state for r in proposals.values())
             for state in record["expected_proposal_counts"]} == record["expected_proposal_counts"],
            "proposal classification counts mismatch")
    return {"record": record, "proposals": proposals, "goal_hashes": goal_hashes,
            "source_reviews": source_reviews}


def load_review_record():
    """Read only the pinned acceptance record and three local review reports."""
    raw = REVIEW_PATH.read_bytes()
    require(digest(raw) == REVIEW_SHA256, "accepted review SHA-256 mismatch")
    paths = json.loads(raw)["source_reports"]
    return parse_review_bundle(raw, {r["path"]: (ROOT / r["path"]).read_bytes() for r in paths})


_REVIEW = load_review_record()


def reviewed_overlay(seed, goals):
    """Return independent review metadata and effective rows; never mutate seed."""
    record, proposals = _REVIEW["record"], _REVIEW["proposals"]
    count = record["inherited_count"]
    require(type(goals) is list and len(goals) >= count
            and all(type(goal) is dict for goal in goals), "invalid goal collection")
    identifiers = [goal.get("id") for goal in goals]
    require(identifiers == [f"X2D-RG-{i:03d}" for i in range(1, len(goals) + 1)],
            "goals must remain unique, ordered and contiguous")
    require(type(seed) is dict and set(seed) == set(identifiers), "seed/goal identity mismatch")
    require(digest(canonical(goals[:count])) == record["inherited_goals_sha256"],
            "original inherited goals changed")
    original_seed = {key: seed[key] for key in identifiers[:count]}
    require(digest(canonical(original_seed)) == record["inherited_seed_sha256"],
            "complete original inherited seed changed")
    for goal in goals[:count]:
        key = goal["id"]
        require(digest(canonical(goal)) == _REVIEW["goal_hashes"][key],
                "original goal differs from reviewed report: " + key)
    for key, row in record["preserved_seed_rows"].items():
        require(canonical(seed[key]) == canonical(row), "preserved complete seed differs: " + key)
    for key in proposals:
        require(seed[key]["applicability"] == "PENDING_REVIEW", "only original pending rows may change")
    effective = copy.deepcopy(seed)
    for key, proposal in proposals.items():
        effective[key].update(proposal)
    inherited = {key: effective[key] for key in _REVIEW["goal_hashes"]}
    review = {
        "schema": "x2dii-reviewed-applicability-overlay-v1",
        "status": "CLASSIFICATION_ONLY_NOT_RELEASE_EVIDENCE",
        "accepted_review_sha256": REVIEW_SHA256,
        "input_seed_sha256": digest(canonical(seed)),
        "input_goals_sha256": digest(canonical(goals)),
        "effective_rows_sha256": digest(canonical(effective)),
        "changed_ids": sorted(proposals),
        "preserved_seed_ids": sorted(record["preserved_seed_rows"]),
        "inherited_counts": {state: sum(row["applicability"] == state for row in inherited.values())
                             for state in ("APPLICABLE", "OUT_OF_SCOPE", "PENDING_REVIEW")},
        "source_reviews": copy.deepcopy(_REVIEW["source_reviews"]),
        "independent_acceptance": copy.deepcopy(record["independent_acceptance"]),
        "rationale_corrections": copy.deepcopy(record["rationale_corrections"]),
        "limitations": list(record["limitations"]),
        "counts_as_pass": False, "installable": False, "package_eligible": False,
        "implementation_reviewed": False,
    }
    return {"review_record": review, "effective_rows": effective}
