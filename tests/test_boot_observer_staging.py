"""Boot preparation must not depend on the preceding boot's /tmp observer."""
from dataclasses import replace
import shlex
import subprocess

import pytest

from tools import stage_menu_delivery as stage, menu_boot_boundary as boundary
from tests.test_menu_preparation_transport import preparation_fixture
from tests.test_raw_session_staging import raw_shell


@pytest.mark.parametrize("action", ("activate", "restore"))
@pytest.mark.parametrize("state", ("absent-after-reboot", "exact-existing", "unknown-existing"))
def test_current_boot_stages_missing_fixed_observer_without_replacing_existing(tmp_path, action, state):
    plan, manifest, raw, _ = preparation_fixture("install" if action == "activate" else "recovery")
    prepared = stage.plan_boot_observer_staging(plan, manifest, raw, action=action)
    destination, original_run = raw_shell(tmp_path, plan, raw)
    camera_tmp = tmp_path / "camera-tmp"
    camera_tmp.mkdir()
    posix = subprocess.run(["C:/Program Files/Git/bin/sh.exe", "-c", 'cygpath -u "$1"', "test", str(camera_tmp)],
                            capture_output=True, text=True, check=True).stdout.strip()
    (path, expected), = prepared.files
    target = camera_tmp / path.removeprefix("/tmp/")
    assert expected == boundary.render_observer(manifest, action=action).encode("ascii")
    before = None
    if state != "absent-after-reboot":
        target.parent.mkdir()
        target.write_bytes(expected if state == "exact-existing" else b"UNKNOWN KEEP")
        before = target.stat()
    for operation in prepared.steps:
        mapped = replace(operation, command=operation.command.replace("/tmp", shlex.quote(posix)))
        result = original_run(mapped)
        result.stdout = result.stdout.replace(posix, "/tmp")
        if state == "unknown-existing":
            assert result.returncode != 0 and target.read_bytes() == b"UNKNOWN KEEP"
            assert target.stat().st_ino == before.st_ino and not list(destination.iterdir())
            return
        assert result.returncode == 0 and not result.stderr, (operation.label, result.stderr)
        assert result.stdout == operation.expected_stdout
    assert target.read_bytes() == expected
    if state == "exact-existing":
        assert target.stat().st_ino == before.st_ino and target.stat().st_mtime_ns == before.st_mtime_ns
        assert not list(destination.iterdir())
    assert not prepared.installable


def test_wrong_boot_observer_action_or_session_is_rejected():
    plan, manifest, raw, _ = preparation_fixture("recovery")
    for action in ("activate", "other"):
        with pytest.raises(ValueError):
            stage.plan_boot_observer_staging(plan, manifest, raw, action=action)
