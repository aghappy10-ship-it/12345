"""Actual temporary lifecycle/file sources are staged; boot prepares its own observer."""
from dataclasses import replace
import shlex
import subprocess

import pytest

from tests.test_raw_session_staging import raw_fixture, raw_shell
from tools import stage_menu_delivery as stage


def support_fixture(tmp_path):
    plan, manifest, raw = raw_fixture("menu_validation")
    prepared = stage.plan_menu_support_staging(plan, manifest, raw)
    destination, original_run = raw_shell(tmp_path, plan, raw)
    camera_tmp = tmp_path / "camera-tmp"
    camera_tmp.mkdir()
    posix = subprocess.run(["C:/Program Files/Git/bin/sh.exe", "-c", 'cygpath -u "$1"', "test", str(camera_tmp)],
                            capture_output=True, text=True, check=True).stdout.strip()

    def run(step, extra=""):
        result = original_run(replace(step, command=step.command.replace("/tmp", shlex.quote(posix))), extra)
        result.stdout = result.stdout.replace(posix, "/tmp")
        return result
    return plan, manifest, raw, prepared, destination, camera_tmp, run


def test_six_temporary_support_sources_are_exact_and_do_not_mutate_existing_observer(tmp_path):
    _, _, _, prepared, destination, camera_tmp, run = support_fixture(tmp_path)
    assert tuple(path.rsplit("/", 1)[1] for path, _ in prepared.files) == ("l", "w", "t", "q", "s", "v")
    assert len(prepared.files) == 6
    menu_root = camera_tmp / prepared.files[0][0].split("/")[2]
    menu_root.mkdir()
    existing = menu_root / "o"
    existing.write_bytes(b"EXISTING FORMAL FILE OBSERVER")
    before = existing.stat()
    for step in prepared.steps:
        result = run(step)
        assert result.returncode == 0 and result.stderr == "", (step.label, result.stderr)
        assert result.stdout == step.expected_stdout
    for path, raw in prepared.files:
        assert (camera_tmp / path.removeprefix("/tmp/")).read_bytes() == raw
    assert set(camera_tmp.iterdir()) == {menu_root}
    assert existing.read_bytes() == b"EXISTING FORMAL FILE OBSERVER" and existing.stat().st_ino == before.st_ino
    snapshot = {p.name: p.read_bytes() for p in destination.iterdir()}
    assert run(prepared.steps[0]).returncode != 0
    assert {p.name: p.read_bytes() for p in destination.iterdir()} == snapshot
    assert not prepared.installable


@pytest.mark.parametrize("fault", ("existing-target", "existing-parent-file", "gzip-corrupt", "tar-status"))
def test_support_preparation_refuses_unknown_targets_or_failed_decoding(tmp_path, fault):
    _, _, _, prepared, destination, camera_tmp, run = support_fixture(tmp_path)
    target = camera_tmp / prepared.files[0][0].removeprefix("/tmp/")
    if fault == "existing-target":
        target.parent.mkdir()
        target.write_bytes(b"UNKNOWN")
    elif fault == "existing-parent-file":
        target.parent.write_bytes(b"NOT A DIRECTORY")
    for step in prepared.steps:
        extra = ""
        if fault == "gzip-corrupt" and step.label == "inflate-menu-support":
            packed = next(destination.glob("*.gz"))
            packed.write_bytes(b"X" * packed.stat().st_size)
        if fault == "tar-status" and step.label == "extract-menu-support":
            extra = 'tar() { command tar "$@"; return 9; }\n'
        result = run(step, extra)
        if result.returncode != 0:
            if fault == "existing-target":
                assert target.read_bytes() == b"UNKNOWN" and not list(destination.iterdir())
            elif fault == "existing-parent-file":
                assert target.parent.read_bytes() == b"NOT A DIRECTORY" and not list(destination.iterdir())
            elif fault == "gzip-corrupt":
                assert not target.exists()
            return
    pytest.fail("fault was accepted")
