"""Real pinned-emulator lifetime at the host runner boundary, never a camera."""
import gc
from unittest import mock
import weakref

import pytest

from tools import check_native as native


@pytest.fixture
def lifetime_probe():
    gc.collect()
    automatic = gc.isenabled()
    gc.disable()
    references = []
    live_before_creation = []
    real = native.Uc

    def create(*args, **kwargs):
        live_before_creation.append(sum(ref() is not None for ref in references))
        engine = real(*args, **kwargs)
        references.append(weakref.ref(engine))
        return engine

    try:
        with mock.patch.object(native, "Uc", create):
            yield references, live_before_creation, real
    finally:
        if automatic:
            gc.enable()
        gc.collect()


def test_completed_actual_native_cases_do_not_retain_callback_engines(lifetime_probe):
    references, live_before_creation, _ = lifetime_probe
    harness = native.NativeHarness()
    for case in ("success", "bad_aot", "restore_write_fail"):
        result = harness.run(case)
        assert result["result"] == "PASS"
        assert all(ref() is None for ref in references)
    assert live_before_creation == [0, 0, 0]


def test_failure_traceback_is_not_forced_closed_but_is_collected_before_next_case(lifetime_probe):
    references, live_before_creation, _ = lifetime_probe
    harness = native.NativeHarness()
    # An unrecognized scenario reaches the real constructor, then fails the
    # host expected-result contract. Keep no exception/traceback reference.
    try:
        harness.run("unrecognized-lifetime-negative")
    except ValueError:
        pass
    else:
        pytest.fail("real runner did not reject its mismatched expectation")
    assert len(references) == 1
    result = harness.run("success")
    assert result["result"] == "PASS"
    assert live_before_creation == [0, 0]
    assert all(ref() is None for ref in references)


def test_unrelated_live_engine_survives_collection_and_still_executes(lifetime_probe):
    _, _, real = lifetime_probe
    live = real(native.UC_ARCH_ARM64, native.UC_MODE_ARM)
    live.mem_map(0x1000, 0x1000)
    live.mem_write(0x1000, bytes.fromhex("1f2003d5"))  # ARM64 nop
    live.hook_add(native.UC_HOOK_CODE, lambda *_: None)
    assert native.NativeHarness().run("success")["result"] == "PASS"
    live.emu_start(0x1000, 0x1004)
    assert live.reg_read(native.UC_ARM64_REG_PC) == 0x1004


def test_retained_real_failure_traceback_keeps_its_engine_until_owner_releases_it(lifetime_probe):
    references, live_before_creation, _ = lifetime_probe
    harness = native.NativeHarness()
    retained_error = None
    try:
        harness.run("unrecognized-retained-lifetime-negative")
    except ValueError as error:
        retained_error = error
    assert retained_error is not None
    assert harness.run("success")["result"] == "PASS"
    assert live_before_creation == [0, 1]
    failed_engine = references[0]()
    assert failed_engine is not None
    # The traceback owns this real engine; normal collection must leave its
    # handle and mapped memory operational. Do not close or edit the runtime.
    assert failed_engine.reg_read(native.UC_ARM64_REG_PC) == native.STUBS
    assert bytes(failed_engine.mem_read(native.APP, 4)) == b"\x7fELF"
    del failed_engine
    retained_error = None
    assert harness.run("success")["result"] == "PASS"
    assert live_before_creation == [0, 1, 0]
    assert all(ref() is None for ref in references)
