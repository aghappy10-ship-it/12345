"""Real archive stdout cannot clobber late new or replaced member inodes."""
import shlex
import subprocess

import pytest

from tools import stage_menu_delivery as stage
from tests.test_compressed_role_staging import make_role_plan, role_shell
from tests.test_raw_session_staging import raw_fixture, raw_shell
from tests.test_menu_support_staging import support_fixture


@pytest.mark.parametrize("kind", ("stable", "temporary-worker", "support"))
@pytest.mark.parametrize("collision", ("later-member", "replace-open-member"))
def test_all_archive_producers_preserve_late_unknown_inodes(tmp_path, kind, collision):
    if kind == "stable":
        plan = make_role_plan()
        destination, run = role_shell(tmp_path, plan)
        steps, label = plan.steps, "extract-normalize-fixed-content"
        paths = [destination / name for name in plan.member_names[:2]]
        first_member = plan.member_names[0]
    elif kind == "temporary-worker":
        plan, manifest, raw = raw_fixture("menu_validation")
        prepared = stage.plan_menu_validation_worker_staging(plan, manifest, raw)
        destination, run = raw_shell(tmp_path, plan, raw)
        steps, label = prepared.steps, "extract-verify-temporary-workers"
        paths = [destination / path.rsplit("/", 1)[1] for path, _ in prepared.files[:2]]
        first_member = prepared.files[0][0].rsplit("/", 1)[1]
    else:
        _, _, _, prepared, _, camera_tmp, run = support_fixture(tmp_path)
        steps, label = prepared.steps, "extract-menu-support"
        paths = [camera_tmp / path.removeprefix("/tmp/") for path, _ in prepared.files[:2]]
        first_member = prepared.files[0][0].removeprefix("/tmp/")
    victim = paths[1 if collision == "later-member" else 0]
    posix = subprocess.run(["C:/Program Files/Git/bin/sh.exe", "-c", 'cygpath -u "$1"', "test", str(victim)],
                            capture_output=True, text=True, check=True).stdout.strip()
    reached = False
    failed = False
    for operation in steps:
        hook = ""
        if operation.label == label:
            reached = True
            move = "" if collision == "later-member" else f"command mv {shlex.quote(posix)} {shlex.quote(posix + '.retained')} || return 17;"
            hook = f'''tar() {{
if [ "$3" = {shlex.quote(first_member)} ]; then
 {move}
 printf UNKNOWN >{shlex.quote(posix)} || return 18
 command stat -c '%d:%i' {shlex.quote(posix)} >{shlex.quote(posix + '.introduced')}
fi
command tar "$@"
}}
'''
        result = run(operation, hook)
        if reached:
            assert victim.read_bytes() == b"UNKNOWN"
            expected_identity = victim.with_name(victim.name + ".introduced").read_text().strip()
            current_identity = subprocess.run(["C:/Program Files/Git/bin/sh.exe", "-c", 'stat -c "%d:%i" "$1"', "test", posix],
                                              capture_output=True, text=True, check=True).stdout.strip()
            assert current_identity == expected_identity
        if result.returncode != 0 or result.stdout != operation.expected_stdout:
            failed = True
            break
    assert reached and failed
