"""Pure entry controls: no native sampler, original diagnostic or camera."""
from pathlib import Path
import hashlib
import runpy

import pytest


HERE = Path(__file__).resolve().parent
CONTROL = HERE / "run_proc_availability_semantics_once.py"


def test_unbound_shared_definitions_are_rejected_before_execution(tmp_path):
    context = runpy.run_path(str(CONTROL), run_name="_native_binding_control")["main"].__globals__
    shared = tmp_path / "unbound-shared.py"
    shared.write_bytes(b"raise RuntimeError('unchecked definitions executed')\n")
    context["SHARED"] = shared
    with pytest.raises(ValueError, match="shared source differs"):
        context["main"]()


def test_shared_replacement_between_loads_cannot_execute_new_definitions(tmp_path):
    context = runpy.run_path(str(CONTROL), run_name="_native_binding_control")["main"].__globals__
    shared = tmp_path / "bound-shared.py"
    original = b'''import hashlib
from pathlib import Path
def digest(raw):
    return hashlib.sha256(raw).hexdigest()
def checked_bytes(path):
    return Path(path).read_bytes()
def load_reviewed_runner():
    return {}
def require_completed_audit(runner):
    Path(__file__).write_bytes(b"raise RuntimeError('replacement definitions executed')\\n")
    return {}, None, None, b'{}'
def require_original_actor_stop(failure):
    raise ValueError('original bound definitions retained')
def main():
    pass
'''
    shared.write_bytes(original)
    context.update(SHARED=shared, SHARED_SHA=hashlib.sha256(original).hexdigest(),
                   RESULT=tmp_path / "result.json")
    with pytest.raises(ValueError, match="original bound definitions retained"):
        context["main"]()
    assert shared.read_bytes() != original
    assert not context["RESULT"].exists()

