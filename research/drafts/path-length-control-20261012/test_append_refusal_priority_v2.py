"""Only actual refusal-publisher collision; no projection/native/main workload.

Execute the exact source's main-entry body with its run boundary raising one
known error. The real guarded publisher sees an existing synthetic file.
"""
import ast
import hashlib
import os
from pathlib import Path
import tempfile

import pytest


HERE = Path(__file__).resolve().parent
VARIANT = os.environ["X2D_APPEND_REFUSAL_VARIANT"]
EXPECTED_SHA = os.environ["X2D_APPEND_REFUSAL_SHA256"]
SOURCES = {
    "old": HERE / "project_regression_append_548_555.py",
    "v2": HERE / "project_regression_append_548_555_v2.py",
}
if VARIANT not in SOURCES:
    raise ValueError("select old or v2 refusal entry")


@pytest.mark.parametrize("note_failure", (False, True), ids=("publisher-collision", "publisher-and-note-failure"))
def test_refusal_entry_preserves_exact_original_exception(note_failure, record_property):
    source = SOURCES[VARIANT]
    raw = source.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == EXPECTED_SHA
    namespace = {"__name__": "_refusal_priority_control", "__file__": str(source)}
    exec(compile(raw, str(source), "exec"), namespace)
    scratch = Path(tempfile.mkdtemp(prefix="refusal-", dir=HERE))
    namespace["guard_output"](scratch)
    refusal = scratch / "refusal.json"
    sentinel = b"KEEP_EXISTING_REFUSAL\n"
    with refusal.open("xb") as output:
        assert output.write(sentinel) == len(sentinel)
    before = refusal.stat()

    class Primary(ValueError):
        def add_note(self, value):
            if note_failure:
                raise OSError("injected note failure")
            return super().add_note(value)

    primary = Primary("original fixed-input refusal")

    def refused_run():
        raise primary

    namespace.update(run=refused_run, REFUSAL=refusal, PATCH=scratch / "absent.patch")
    tree = ast.parse(raw, filename=str(source))
    entries = [node for node in tree.body if isinstance(node, ast.If)
               and ast.unparse(node.test) == "__name__ == '__main__'"]
    assert len(entries) == 1
    body = ast.Module(body=entries[0].body, type_ignores=[])
    observed = None
    try:
        exec(compile(body, str(source), "exec"), namespace)
    except BaseException as error:
        observed = error
    after = refusal.stat()
    preserved = refusal.read_bytes() == sentinel and (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)
    record_property("scope", "actual guarded publisher collision; projection run boundary substituted")
    record_property("source_sha256", EXPECTED_SHA)
    record_property("variant", VARIANT)
    record_property("existing_refusal_preserved", str(preserved))
    record_property("retained_marker", str(refusal))
    record_property("observed_error_type", type(observed).__name__)
    assert preserved
    assert source.read_bytes() == raw
    assert observed is primary, "refusal publication replaced the exact original error"
    if not note_failure:
        assert primary.__notes__ and "refusal reporting failed" in primary.__notes__[0]
