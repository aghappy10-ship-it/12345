"""Fixed maintenance-index upload must not mutate replaced scratch objects."""
import subprocess
import shlex

import pytest

from tests.test_stage_menu_delivery import make_plan, session_fixture
from tools import stage_menu_delivery as stage


def observer_shell(tmp_path):
    plan = make_plan()
    session = stage.plan_session_staging(plan, *session_fixture(plan))
    observer = stage.plan_maintenance_staging(plan, dict(session.context), session=session, request_nonce="a" * 32)
    root = tmp_path / "observer"
    shell = "C:/Program Files/Git/bin/sh.exe"
    mapped = subprocess.run([shell, "-c", 'cygpath -u "$1"', "test", str(root)],
                             capture_output=True, text=True, check=True).stdout.strip()

    def run(step, model=""):
        return subprocess.run([shell, "-s"], input=model + "\n" + step.command.replace(observer.root, shlex.quote(mapped)),
                               capture_output=True, text=True, timeout=10)
    return observer, root, mapped, run


def test_unknown_observer_upload_is_never_appended_to(tmp_path):
    observer, root, _, run = observer_shell(tmp_path)
    target = root / "po"
    introduced = False
    for step in observer.preparation:
        if step.label == "prepare-observer-chunk-o-0":
            if target.exists():
                target.rename(root / "retained-prior-upload")
            target.write_bytes(b"UNKNOWN")
            introduced = True
        result = run(step)
        if introduced:
            assert target.read_bytes() == b"UNKNOWN"
        if result.returncode != 0:
            assert introduced
            return
    pytest.fail("unknown scratch upload was never refused")


def test_post_decode_replacement_never_has_its_permissions_changed(tmp_path):
    observer, root, mapped, run = observer_shell(tmp_path)
    for step in observer.preparation:
        if step.label == "prepare-observer-decode-o":
            model = f'''base64() {{
 command base64 "$@" || return $?
 command mv {shlex.quote(mapped + '/o')} {shlex.quote(mapped + '/retained-original-o')} || return $?
 printf UNKNOWN >{shlex.quote(mapped + '/o')}
}}
chmod() {{ printf CALLED >{shlex.quote(mapped + '/unexpected-chmod')}; command chmod "$@"; }}
'''
            run(step, model)
            assert (root / "o").read_bytes() == b"UNKNOWN"
            assert not (root / "unexpected-chmod").exists()
            return
        result = run(step)
        assert result.returncode == 0, (step.label, result.stderr)
    pytest.fail("observer decode was not reached")
