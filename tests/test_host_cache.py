"""Desktop-only real Qt cache loading, native callback concurrency and rejects."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

import pytest

from tools import host_cache as host
from tools import build_host_bridge as builder
from tools.output_guard import output_directory, write_output, guard_output


@pytest.fixture
def output_sandbox():
    output_directory(host.BUILD)
    with tempfile.TemporaryDirectory(prefix="output-test-", dir=host.BUILD) as value:
        yield Path(value)


def make_junction(link: Path, target: Path) -> None:
    if os.name == "nt":
        run = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, text=True)
        assert run.returncode == 0, run.stdout + run.stderr
    else:
        link.symlink_to(target, target_is_directory=True)


def remove_junction(link: Path) -> None:
    if os.name == "nt":
        os.rmdir(link)
    else:
        link.unlink()


def test_host_workdir_rejects_junction_even_when_target_is_inside_build(output_sandbox):
    target = output_directory(output_sandbox / "target")
    link = output_sandbox / "redirected"
    make_junction(link, target)
    try:
        with pytest.raises(ValueError, match="reparse|junction"):
            host.confined_workdir(link / "runtime")
        assert list(target.iterdir()) == []
    finally:
        remove_junction(link)


def test_bridge_rejects_redirected_root_before_reading_dependencies(output_sandbox, monkeypatch):
    target = output_directory(output_sandbox / "target")
    link = output_sandbox / "redirected"
    make_junction(link, target)
    monkeypatch.setattr(builder, "BUILD", link)
    def no_dependencies(*_):
        pytest.fail("redirected output must fail before dependency reads or compiler execution")
    monkeypatch.setattr(builder, "sha", no_dependencies)
    try:
        with pytest.raises(ValueError, match="reparse|junction"):
            builder.build()
        assert list(target.iterdir()) == []
    finally:
        remove_junction(link)


def test_host_cache_directory_is_new_and_does_not_reuse_redirected_cache(output_sandbox):
    target = output_directory(output_sandbox / "target")
    link = output_sandbox / "qml-cache"
    make_junction(link, target)
    try:
        first = host.fresh_cache_directory(output_sandbox)
        second = host.fresh_cache_directory(output_sandbox)
        assert first != second and first.parent == second.parent == output_sandbox
        assert list(first.iterdir()) == list(second.iterdir()) == list(target.iterdir()) == []
    finally:
        remove_junction(link)


def test_host_generated_file_rejects_hardlink_without_modifying_original(output_sandbox):
    original = write_output(output_sandbox / "original", b"keep")
    alias = output_sandbox / "generated.bin"
    os.link(original, alias)
    try:
        with pytest.raises(ValueError, match="hard-linked"):
            write_output(alias, b"replace")
        assert original.read_bytes() == alias.read_bytes() == b"keep"
    finally:
        alias.unlink()


def _child(directory: Path) -> dict:
    from concurrent.futures import ThreadPoolExecutor
    import ctypes
    import gc

    before = host.prepare_host(directory)
    from PySide6.QtCore import QCoreApplication, QUrl
    from PySide6.QtQml import QQmlEngine, QQmlComponent, qmlClearTypeRegistrations
    import shiboken6

    application = QCoreApplication.instance() or QCoreApplication([])
    source = directory / "Probe.qml"
    write_output(source, b"import QtQml\nQtObject { property int answer: { return 6 * 7; } function calculate() { return answer + 1; } }\n")
    source_hash = host.sha(source)
    cache = guard_output(directory / "compiled-bytecode.bin", must_be_new=True)
    command = [str(host.HOST / "PySide6/qmlcachegen.exe"), "--only-bytecode", "-o", str(cache), str(source)]
    compiled = subprocess.run(command, capture_output=True, text=True, timeout=30)
    assert compiled.returncode == 0, compiled.stderr
    guard_output(cache)
    generated = cache.read_bytes()
    static = host.as_static_cache(generated)
    static_path = directory / "static-compiled-unit.bin"
    write_output(static_path, static)
    write_output(source, b"not valid QML: source fallback must fail\n")
    url = QUrl.fromLocalFile(str(source))

    # Before registration this exact source is unusable. Its .bin cache name
    # cannot be discovered by the disk-cache loader as a sibling .qmlc.
    negative_engine = QQmlEngine()
    negative_component = QQmlComponent(negative_engine, url)
    assert negative_component.isError(), negative_component.errors()
    shiboken6.delete(negative_component)
    shiboken6.delete(negative_engine)

    cache_owner = host.HostCache(static_path, url.toString(), directory, expected_sha256=hashlib.sha256(static).hexdigest())
    engine = QQmlEngine()
    component = QQmlComponent(engine, url)
    assert component.isReady(), [error.toString() for error in component.errors()]
    root = component.create()
    assert root is not None, [error.toString() for error in component.errors()]
    assert root.property("answer") == 42
    assert engine.newQObject(root).property("calculate").call().toInt() == 43
    assert cache_owner.hits > 0
    actual_qt_hits = cache_owner.hits

    mismatch = QUrl.fromLocalFile(str(directory / "Wrong.qml"))
    assert not cache_owner.callback(shiboken6.getCppPointer(mismatch)[0])
    assert cache_owner.hits == actual_qt_hits
    assert not cache_owner.callback(None)

    address = shiboken6.getCppPointer(url)[0]
    wanted = ctypes.addressof(cache_owner.unit)
    def lookup_many():
        for _ in range(1000):
            assert cache_owner.callback(address) == wanted
    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(lambda _: lookup_many(), range(8)))
    assert cache_owner.hits == actual_qt_hits + 8000
    with pytest.raises(ValueError, match="one active"):
        host.HostCache(static_path, url.toString(), directory)

    # Closing is idempotent. Already returned immutable data remains pinned,
    # so an existing engine may safely execute its function after removal.
    cache_owner.close()
    cache_owner.close()
    assert not cache_owner.callback(address)
    assert engine.newQObject(root).property("calculate").call().toInt() == 43
    assert cache_owner.bridge.bridge_active() == 0
    # The stock Qt 6.8.2 setData baseline reproduces an access violation if
    # its product is manually destroyed before this component's creator.
    # Destroy the factory first, then its product, then the engine; skip none.
    shiboken6.delete(component)
    shiboken6.delete(root)
    shiboken6.delete(engine)
    gc.collect()

    # A fresh registration has its own counter; the old owner keeps its final
    # count and cannot deactivate or overwrite the new registration.
    second = host.HostCache(static_path, url.toString(), directory)
    assert second.hits == 0
    assert second.callback(address) == ctypes.addressof(second.unit)
    assert second.hits == 1
    old_count = cache_owner.hits
    cache_owner.close()
    assert second.bridge.bridge_active() == 1 and cache_owner.hits == old_count
    def race_reads():
        for _ in range(1000):
            result = second.callback(address)
            assert result in (None, ctypes.addressof(second.unit))
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(race_reads) for _ in range(4)]
        second.close()
        for future in futures:
            future.result()
    assert not second.callback(address)

    assert not shiboken6.isValid(engine) and not shiboken6.isValid(negative_engine)
    qmlClearTypeRegistrations()
    shiboken6.delete(application)
    assert not shiboken6.isValid(application)

    assert host.runtime_snapshot() == before["runtime_files"]
    build = json.loads((host.BUILD / "native/BUILD.json").read_text(encoding="utf-8"))
    return {
        "schema": "x2dii-desktop-compiled-cache-smoke-v1", "status": "PASS_DESKTOP_SMALL_COMPILED_UNIT_ONLY",
        "device_tested": False, "full_camera_gui_tested": False, "installable": False,
        "runtime_files": before["runtime_files"], "bridge_sha256": build["dll_sha256"],
        "source_sha256_before_poison": source_hash, "source_sha256_executed_fallback_negative": host.sha(source),
        "qmlcachegen_output_sha256": hashlib.sha256(generated).hexdigest(),
        "registered_unit_sha256": hashlib.sha256(static).hexdigest(),
        "static_ownership_change": {"before_flags": struct.unpack_from("<I", generated, 108)[0], "after_flags": struct.unpack_from("<I", static, 108)[0]},
        "compiler": {"argv": command, "exit_code": compiled.returncode, "stdout": compiled.stdout, "stderr": compiled.stderr},
        "checks": {"source_negative": True, "actual_compiled_property": 42, "actual_compiled_function": 43,
                   "qt_lookup_hits": actual_qt_hits, "native_concurrent_exact_lookups": 8000,
                   "wrong_url_rejected": True, "repeated_close": True, "retained_data_after_close": True,
                   "new_owner_counter_reset": True, "concurrent_close": True, "frozen_runtime_unchanged": True,
                   "qml_type_registrations_cleared": True, "application_deleted": True},
        "sources": {str(path.relative_to(host.ROOT)).replace("\\", "/"): host.sha(path) for path in (Path(__file__), host.ROOT / "tools/host_cache.py", host.ROOT / "src/host_cache_bridge.c", host.ROOT / "tools/build_host_bridge.py")},
    }


def test_real_qt_compiled_cache_in_isolated_process():
    output_directory(host.BUILD)
    directory = Path(tempfile.mkdtemp(prefix="smoke-", dir=host.BUILD))
    guard_output(directory)
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(host.ROOT)
    command = [sys.executable, "-B", "-X", "faulthandler", str(Path(__file__).resolve()), "--child", str(directory)]
    started = datetime.now(timezone.utc).isoformat()
    try:
        run = subprocess.run(command, cwd=host.ROOT, env=environment, capture_output=True, text=True, timeout=90)
    except subprocess.TimeoutExpired as error:
        def decoded(value):
            return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value
        write_output(directory / "subprocess.json", json.dumps({"argv": command, "outcome": "TIMEOUT", "exit_code": None, "started_utc": started, "finished_utc": datetime.now(timezone.utc).isoformat(), "stdout": decoded(error.stdout), "stderr": decoded(error.stderr)}, indent=2).encode("utf-8"))
        raise
    write_output(directory / "subprocess.json", json.dumps({"argv": command, "outcome": "EXITED", "exit_code": run.returncode, "started_utc": started, "finished_utc": datetime.now(timezone.utc).isoformat(), "stdout": run.stdout, "stderr": run.stderr}, indent=2).encode("utf-8"))
    assert run.returncode == 0, run.stdout + run.stderr
    report = json.loads((directory / "CHILD_RESULT.json").read_text(encoding="utf-8"))
    assert report["status"] == "PASS_DESKTOP_SMALL_COMPILED_UNIT_ONLY"
    assert report["full_camera_gui_tested"] is False
    assert report["checks"]["qml_type_registrations_cleared"] is True
    assert report["checks"]["application_deleted"] is True
    report["process_exit_verified"] = True
    write_output(directory / "RESULT.json", json.dumps(report, indent=2).encode("utf-8"))


@pytest.fixture(scope="module")
def small_cache():
    # Independent fixture: collection order and prior smoke outputs are not
    # evidence. This compiler invocation never imports the host Qt in pytest.
    output_directory(host.BUILD)
    directory = guard_output(Path(tempfile.mkdtemp(prefix="header-fixture-", dir=host.BUILD)))
    source, output = directory / "Header.qml", directory / "Header.bin"
    write_output(source, b"import QtQml\nQtObject { property int value: 7 }\n")
    guard_output(output, must_be_new=True)
    run = subprocess.run([str(host.HOST / "PySide6/qmlcachegen.exe"), "--only-bytecode", "-o", str(output), str(source)], capture_output=True, text=True, timeout=30)
    assert run.returncode == 0, run.stderr
    guard_output(output)
    return host.as_static_cache(output.read_bytes())


@pytest.mark.parametrize("field", ["magic", "structure", "qt", "compile_hash", "static", "size", "checksum", "truncated"])
def test_cache_header_mismatches_fail_before_native_loading(small_cache, field):
    value = bytearray(small_cache)
    offsets = {"magic": 0, "structure": 8, "qt": 12, "compile_hash": 28, "size": 24, "checksum": 76}
    if field == "static":
        struct.pack_into("<I", value, 108, struct.unpack_from("<I", value, 108)[0] & ~2)
    elif field == "truncated":
        value = value[:80]
    else:
        value[offsets[field]] ^= 1
    with pytest.raises(ValueError):
        host.validate_cache(bytes(value))


def test_host_workdir_cannot_write_frozen_tree():
    with pytest.raises(ValueError, match="outside its declared project root"):
        host.confined_workdir(host.HOST / "should-not-exist")
    assert not (host.HOST / "should-not-exist").exists()


def test_ownership_adaptation_cannot_repair_untrusted_checksum(small_cache):
    damaged = bytearray(small_cache)
    damaged[76] ^= 1
    with pytest.raises(ValueError, match="MD5"):
        host.as_static_cache(bytes(damaged))


def test_layout_and_export_contract():
    import ctypes
    assert ctypes.sizeof(host.CachedUnit) == 24
    assert ctypes.sizeof(host.Registration) == 16
    assert host.Registration.lookup.offset == 8
    assert host.REGISTER_SYMBOL in host.pe_exports(host.HOST / "PySide6/Qt6Qml.dll")
    assert host.UNREGISTER_SYMBOL in host.pe_exports(host.HOST / "PySide6/Qt6Qml.dll")
    assert host.EQUALS_SYMBOL in host.pe_exports(host.HOST / "PySide6/Qt6Core.dll")


if __name__ == "__main__":
    assert len(sys.argv) == 3 and sys.argv[1] == "--child"
    location = host.confined_workdir(Path(sys.argv[2]))
    result = _child(location)
    # The parent alone publishes RESULT after successful interpreter shutdown.
    result["process_exit_verified"] = False
    write_output(location / "CHILD_RESULT.json", json.dumps(result, indent=2).encode("utf-8"))
    print(result["status"])
