"""Reference-style gzip transfer of fixed v2 content, local synthetic files only."""
from pathlib import Path
import json
import base64
import gzip
import shlex
import subprocess
import pytest

from tools import stage_menu_delivery as stage
from tools import delivery_content as content
from tests.test_delivery_role_v2 import role_fixture, NAMES
from tests.test_delivery_files import candidate_hash
from tests.test_stage_menu_delivery import (RENDERER, sha, session_fixture,
                                            complete_observer_preparation, maintenance_result)


def make_role_plan():
    members, candidate, scripts = role_fixture()
    return stage.plan_compressed_role_staging(
        members=members, candidate=candidate, candidate_sha256=candidate_hash(candidate),
        script_hashes=scripts, renderer_source=RENDERER, renderer_source_sha256=sha(RENDERER))


def test_fixed_compressed_role_staging_never_includes_second_windows_session_data():
    plan = make_role_plan()
    assert plan.member_names == NAMES
    assert plan.include_session_file is False
    session = stage.plan_session_staging(plan, *session_fixture(plan))
    operations = stage.execution_steps(plan, dict(session.context), session=session)
    assert len(operations) == len(plan.steps)
    assert all("session-context.data" not in item.command for item in operations)
    assert all(len(("shell:(" + item.command + ");r=$?;printf '\\nX2DII_STAGE_" +
                    session.binding_sha256[:24] + "_999_RC=%s\\n' \"$r\"\0").encode("ascii")) <= 4096
               for item in operations)
    assert not plan.installable and not plan.transport_invocation_available


def role_shell(tmp_path, plan):
    blackbox = tmp_path / "blackbox"
    blackbox.mkdir()
    shell = "C:/Program Files/Git/bin/sh.exe"
    mapped = subprocess.run([shell, "-c", 'cygpath -u "$1"', "fixture", str(blackbox)],
                            capture_output=True, text=True, encoding="utf-8", check=True).stdout.strip()
    # Only Android ownership/mode and SHA display are modeled. Actual gzip,
    # USTAR extraction, content hashes, sizes, no-clobber and files are executed.
    model = r'''
sha256sum() { value=$(command sha256sum "$@") || return $?; printf '%s\n' "$value" | sed 's/ \*/  /'; }
stat() { case "$2" in
 '%u %g %a') printf '0 0 700\n';;
 '%u %g %a %h')
  printf '0 0 600 %s\n' "$(command stat -c %h "$3")";;
 *) command stat "$@";; esac; }
'''

    def run(step, fault_model=""):
        source = model + fault_model + "\nstage_step=" + shlex.quote(step.label) + "\n" + step.command.replace(
            "/blackbox", shlex.quote(mapped)).replace("export PATH=/system/bin:/system/xbin:/sbin;",
                                                     "export PATH=/usr/bin:/bin;")
        return subprocess.run([shell, "-s"], input=source, capture_output=True, text=True,
                              encoding="utf-8", timeout=10)
    return blackbox / "x2dii-menu-stage" / plan.candidate_sha256[:24], run


def test_generated_compressed_plan_stages_exact_fixed_members_and_rejects_reuse(tmp_path):
    plan = make_role_plan()
    members = role_fixture()[0]
    destination, run = role_shell(tmp_path, plan)
    for operation in plan.steps:
        result = run(operation)
        assert result.returncode == 0 and result.stderr == "", (operation.label, result.stderr)
        assert result.stdout == operation.expected_stdout, operation.label
    expected = {**members, "members.json": json.dumps(content.plan_role_content(members, plan.candidate_sha256),
                                                      sort_keys=True, separators=(",", ":")).encode("ascii")}
    archive = content.encode_role_content(members, plan.candidate_sha256)
    compressed = gzip.compress(archive, mtime=0)
    expected.update({".content.tar": archive, ".content.gz": compressed,
                     ".content.b64": base64.b64encode(compressed)})
    encoded = base64.b64encode(compressed)
    expected.update({f".content-chunk-{offset}.b64": encoded[offset:offset + stage.CHUNK_CHARS]
                     for offset in range(0, len(encoded), stage.CHUNK_CHARS)})
    assert {p.name: p.read_bytes() for p in destination.iterdir()} == expected
    assert not (destination / "session-context.data").exists()
    repeated = run(plan.steps[0])
    assert repeated.returncode != 0
    assert {name: (destination / name).read_bytes() for name in expected} == expected


@pytest.mark.parametrize("fault", ("gzip-hash", "tar-hash", "existing-member", "existing-directory",
                                 "gzip-status", "hash-status", "tar-status", "missing-member"))
def test_corrupt_or_failed_compressed_transfer_does_not_advance_or_replace_prior_member(tmp_path, fault):
    plan = make_role_plan()
    destination, run = role_shell(tmp_path, plan)
    target_phase = {"gzip-hash": "inflate-fixed-content", "tar-hash": "extract-normalize-fixed-content",
                    "existing-member": "extract-normalize-fixed-content", "existing-directory": "extract-normalize-fixed-content",
                    "gzip-status": "inflate-fixed-content", "hash-status": "decode-fixed-compressed-content",
                    "tar-status": "extract-normalize-fixed-content", "missing-member": "extract-normalize-fixed-content"}[fault]
    review = stage.StagingReadback(plan)
    step_index = 0
    while (operation := review.next_step) is not None:
        fault_model = ""
        if operation.label == target_phase:
            if fault in ("gzip-hash", "tar-hash"):
                artifact = destination / (".content.gz" if fault == "gzip-hash" else ".content.tar")
                raw = artifact.read_bytes()
                artifact.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
            elif fault == "existing-member":
                (destination / NAMES[0]).write_bytes(b"PRIOR BYTES DO NOT REPLACE")
            elif fault == "existing-directory":
                (destination / NAMES[0]).mkdir()
            elif fault == "missing-member":
                fault_model = '\ntar() { command tar "$@" && rm libx2dii_menu.so; }\n'
            elif fault == "hash-status":
                fault_model = '\nsha256sum() { value=$(command sha256sum "$@"); printf \'%s\\n\' "$value" | sed \'s/ \\*/  /\'; return 2; }\n'
            else:
                tool = "gzip" if fault == "gzip-status" else "tar"
                fault_model = f'\n{tool}() {{ command {tool} "$@"; return 2; }}\n'
        result = run(operation, fault_model)
        record = dict(index=step_index, command=operation.command, exit_code=result.returncode,
                      stdout=result.stdout, completion_validated=True)
        if operation.label == target_phase:
            assert result.returncode != 0, fault
            with pytest.raises(ValueError):
                review.accept(**record)
            assert review.failed and review.next_step is None
            if fault == "existing-member":
                assert (destination / NAMES[0]).read_bytes() == b"PRIOR BYTES DO NOT REPLACE"
            if fault == "existing-directory":
                assert (destination / NAMES[0]).is_dir()
            if fault in ("gzip-hash", "tar-hash", "gzip-status", "hash-status"):
                assert not (destination / NAMES[0]).exists()
            return
        assert result.returncode == 0 and result.stderr == "", operation.label
        review.accept(**record)
        step_index += 1
    pytest.fail("fault boundary was never reached")


def test_compressed_stable_stage_reuses_supervised_roles_without_uploading_session(tmp_path):
    plan = make_role_plan()
    session = stage.plan_session_staging(plan, *session_fixture(plan))
    exchange = stage.FixedStagingExchange(plan, dict(session.context), session=session,
                                          clock=lambda: session.observed_epoch)
    # Observer upload itself is exercised by the full legacy dual-role test.
    # Here its fixed program runs for every observation of the new content plan.
    complete_observer_preparation(exchange)
    destination, run = role_shell(tmp_path, plan)
    model = f'''
id() {{ printf '0\\n'; }}
date() {{ printf '{session.observed_epoch}\\n'; }}
cat() {{ case "$1" in
 /proc/self/attr/current) printf 'u:r:su:s0\\n';;
 /proc/sys/kernel/random/boot_id) printf '{dict(session.context)['boot_id']}\\n';;
 *) command cat "$@";; esac; }}
readlink() {{ case "$1" in
 /proc/self/ns/mnt) printf '{dict(session.context)['mount_namespace']}\\n';;
 /proc/1/ns/mnt) return 93;;
 *) command readlink "$@";; esac; }}
'''
    roles = []
    while (operation := exchange.next_step) is not None:
        roles.append(operation.role)
        result = (maintenance_result(operation, session, observer=exchange.observer)
                  if operation.role == "maintenance" else run(operation, model))
        assert result.returncode == 0 and result.stderr == "", (operation.label, result.stderr)
        exchange.accept(role=operation.role, index=operation.index, command=operation.command,
                        exit_code=result.returncode, stdout=result.stdout, completion_validated=True)
    assert exchange.all_results_validated
    assert roles == ["maintenance", "su"] * len(plan.steps)
    assert sorted(path.name for path in destination.iterdir()) == sorted(
        (*NAMES, "members.json", ".content.b64", ".content.gz", ".content.tar",
         *(f".content-chunk-{step.label.rsplit('-', 1)[1]}.b64"
           for step in plan.steps if step.label.startswith("compressed-chunk-"))))


@pytest.mark.parametrize("name", (".content.b64", ".content-chunk-0.b64"))
def test_compressed_chunks_do_not_append_or_replace_unknown_existing_uploads(tmp_path, name):
    plan = make_role_plan()
    destination, run = role_shell(tmp_path, plan)
    for operation in plan.steps:
        if operation.label == "compressed-chunk-0":
            target = destination / name
            target.write_bytes(b"UNKNOWN")
        result = run(operation)
        if operation.label.startswith("compressed-chunk-") or operation.label == "decode-fixed-compressed-content":
            assert target.read_bytes() == b"UNKNOWN"
        if result.returncode != 0:
            assert operation.label == ("compressed-chunk-0" if "chunk" in name else "decode-fixed-compressed-content")
            return
    pytest.fail("preexisting transfer object was not refused")


@pytest.mark.parametrize("name", (".content.b64", ".content.gz", ".content.tar"))
def test_final_readback_never_deletes_unknown_replaced_transfer_intermediate(tmp_path, name):
    plan = make_role_plan()
    destination, run = role_shell(tmp_path, plan)
    for operation in plan.steps[:-1]:
        result = run(operation)
        assert result.returncode == 0, (operation.label, result.stderr)
    original = destination / name
    before = original.stat()
    original.rename(destination / (name + ".retained-original"))
    unknown = b"UNKNOWN NEW OBJECT MUST REMAIN"
    original.write_bytes(unknown)
    after = original.stat()
    assert (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
    # The last action is only payload readback; it never removes an input.
    result = run(plan.steps[-1])
    assert result.returncode == 0
    assert result.stdout == plan.steps[-1].expected_stdout and result.stderr == ""
    assert original.read_bytes() == unknown
    assert plan.steps[-1].label == "verify-all-members"


def test_unknown_post_extraction_member_is_rejected_before_any_permission_change(tmp_path):
    plan = make_role_plan()
    destination, run = role_shell(tmp_path, plan)
    for operation in plan.steps:
        if operation.label == "extract-normalize-fixed-content":
            fault = r'''
tar() {
 command tar "$@" || return $?
 command mv libx2dii_menu.so libx2dii_menu.so.retained-original || return $?
 printf 'UNKNOWN REPLACEMENT' > libx2dii_menu.so
}
chmod() { printf 'CHMOD CALLED\n' >> .unexpected-chmod; command chmod "$@"; }
'''
            result = run(operation, fault)
            assert result.returncode != 0
            original = (destination / "libx2dii_menu.so.retained-original").stat()
            replacement = (destination / "libx2dii_menu.so").stat()
            assert (original.st_dev, original.st_ino) != (replacement.st_dev, replacement.st_ino)
            assert (destination / "libx2dii_menu.so").read_bytes() == b"UNKNOWN REPLACEMENT"
            assert not (destination / ".unexpected-chmod").exists()
            return
        result = run(operation)
        assert result.returncode == 0, (operation.label, result.stderr)
    pytest.fail("extraction boundary not reached")


def test_failed_private_directory_guard_never_falls_through_into_extraction(tmp_path):
    plan = make_role_plan()
    destination, run = role_shell(tmp_path, plan)
    for operation in plan.steps:
        if operation.label == "extract-normalize-fixed-content":
            fault = r'''
stat() {
 case "$2" in
  '%u %g %a') printf '1 0 700\n';;
  '%u %g %a %h') printf '0 0 600 1\n';;
  *) command stat "$@";;
 esac
}
tar() { printf 'EXTRACTION REACHED\n' > .unexpected-extraction; command tar "$@"; }
''' + "\ncd " + shlex.quote(destination.as_posix()) + "\nx2dii_files=" + shlex.quote(" ".join((*NAMES, "members.json"))) + "\n"
            result = run(operation, fault)
            assert result.returncode != 0
            assert not (destination / ".unexpected-extraction").exists()
            assert not (destination / NAMES[0]).exists()
            return
        result = run(operation)
        assert result.returncode == 0, (operation.label, result.stderr)
    pytest.fail("extraction boundary not reached")
