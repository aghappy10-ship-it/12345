"""Fresh second-window data only; no worker upload, camera or authorization."""
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
import base64
import gzip
import shlex
import subprocess

import pytest

from tests.test_compressed_role_staging import make_role_plan, role_shell
from tests.test_stage_menu_delivery import session_fixture, sha
from tests.test_session_context import recovery
from tests.test_release_lifecycle import installer
from tools import prepare_peer_install as peer, session_context as sc
from tools import stage_menu_delivery as stage


def raw_fixture(kind="install"):
    plan = make_role_plan()
    manifest, q = session_fixture(plan)
    raw = peer.session_data(manifest, q)
    schema = sc.INSTALL_SCHEMA
    values = sc.decode_session(raw)
    if kind == "menu_validation":
        values.update(kind=kind, purpose="temporary_menu_validation", action="run_and_restore",
                      candidate_sha256=plan.candidate_sha256)
        schema = sc.MENU_VALIDATION_SCHEMA
    elif kind == "recovery":
        values = recovery(True)
        schema = sc.SCHEMA
    return plan, manifest, sc.encode_session(values, schema=schema)


@pytest.mark.parametrize("kind", ("install", "menu_validation", "recovery"))
def test_new_session_is_exact_immutable_data_without_worker_or_content_reupload(kind):
    plan, manifest, raw = raw_fixture(kind)
    before = deepcopy(plan)
    session = stage.plan_raw_session_staging(plan, manifest, raw)
    assert session.data == raw and session.data_sha256 == sha(raw)
    assert session.path == plan.stage_root + "/session-context-" + sha(raw) + ".data"
    assert session.binding_schema == "x2dii-current-stage-session-v2"
    assert session.observed_epoch == 1791040000
    assert session.observed_utc == datetime.fromtimestamp(1791040000, timezone.utc).isoformat()
    assert session.session_nonce == "b" * 32
    assert not session.installable and not session.worker_preparation_included
    assert len(session.steps) == 2
    assert all(name not in step.command for step in session.steps for name in plan.member_names)
    assert plan == before and not plan.include_session_file
    # Supplying a new execution lease never adds session data to window one.
    operations = stage.execution_steps(plan, dict(session.context), session=session)
    assert len(operations) == len(plan.steps)
    assert all("session-context-" not in item.command for item in operations)


def raw_shell(tmp_path, plan, raw, *, epoch=None, fault=""):
    destination, run_base = role_shell(tmp_path, plan)
    destination.mkdir(parents=True)
    values = sc.decode_session(raw)
    observed = values["observed_epoch"] if epoch is None else epoch
    mapped = subprocess.run(["C:/Program Files/Git/bin/sh.exe", "-c", 'cygpath -u "$1"',
                             "fixture", str(tmp_path / "blackbox")],
                            capture_output=True, text=True, check=True).stdout.strip()

    def run(operation, extra=""):
        result = run_base(operation, f'date() {{ printf "%s\\n" {observed}; }}\n' + fault + extra)
        result.stdout = result.stdout.replace(mapped, "/blackbox")
        return result
    return destination, run


@pytest.mark.parametrize("kind", ("install", "menu_validation", "recovery"))
def test_new_context_executes_and_decodes_exact_original_bytes_preserving_history_and_workers(tmp_path, kind):
    plan, manifest, raw = raw_fixture(kind)
    session = stage.plan_raw_session_staging(plan, manifest, raw)
    destination, run = raw_shell(tmp_path, plan, raw)
    existing = {"session-context-" + "0" * 64 + ".data": b"old context",
                "preplace-0.sh": b"formal install worker is not a temporary worker",
                "menu-validation-preplace-0.sh": b"separate temporary worker",
                ".content.tar": b"prior stable content"}
    for name, data in existing.items():
        (destination / name).write_bytes(data)
    for step in session.steps:
        result = run(step)
        assert result.returncode == 0 and result.stderr == "", result.stderr
        assert result.stdout == step.expected_stdout
    path = destination / session.path.rsplit("/", 1)[1]
    assert path.read_bytes() == raw and sc.decode_session(path.read_bytes()) == sc.decode_session(raw)
    compressed = gzip.compress(raw, mtime=0)
    expected = {**existing, path.name: raw, path.name + ".gz": compressed,
                path.name + ".b64": base64.b64encode(compressed)}
    assert {p.name: p.read_bytes() for p in destination.iterdir()} == expected
    repeated = run(session.steps[0])
    assert repeated.returncode != 0
    assert {p.name: p.read_bytes() for p in destination.iterdir()} == expected


@pytest.mark.parametrize("suffix", ("", ".b64", ".gz"))
@pytest.mark.parametrize("object_kind", ("file", "directory"))
def test_existing_context_or_intermediate_refuses_all_creation_without_overwrite(tmp_path, suffix, object_kind):
    plan, manifest, raw = raw_fixture()
    session = stage.plan_raw_session_staging(plan, manifest, raw)
    destination, run = raw_shell(tmp_path, plan, raw)
    existing = destination / (session.path.rsplit("/", 1)[1] + suffix)
    if object_kind == "directory":
        existing.mkdir()
        (existing / "keep").write_bytes(b"preserved")
    else:
        existing.write_bytes(b"preserved")
    result = run(session.steps[0])
    assert result.returncode != 0
    assert list(destination.iterdir()) == [existing]
    assert (existing / "keep" if object_kind == "directory" else existing).read_bytes() == b"preserved"


@pytest.mark.parametrize("offset", (-1, 601))
def test_future_or_expired_raw_context_is_not_renewed(tmp_path, offset):
    plan, manifest, raw = raw_fixture()
    session = stage.plan_raw_session_staging(plan, manifest, raw)
    destination, run = raw_shell(tmp_path, plan, raw, epoch=session.observed_epoch + offset)
    result = run(session.steps[0])
    assert result.returncode != 0 and list(destination.iterdir()) == []


@pytest.mark.parametrize("fault", (
    "date() { command date +%s; return 7; }\n",
    "stat() { case \"$2\" in '%u %g %a') printf '0 0 700\\n'; return 7;; *) command stat \"$@\";; esac; }\n",
    "base64() { command base64 \"$@\"; return 7; }\n",
    "gzip() { command gzip \"$@\"; return 7; }\n",
    "gzip() { printf 'wrong raw bytes'; }\n",
    "sha256sum() { command sha256sum \"$@\"; return 7; }\n",
))
def test_failed_native_tools_never_produce_a_success_receipt(tmp_path, fault):
    plan, manifest, raw = raw_fixture()
    session = stage.plan_raw_session_staging(plan, manifest, raw)
    destination, run = raw_shell(tmp_path, plan, raw, fault=fault)
    for step in session.steps:
        result = run(step)
        if result.returncode != 0:
            break
    assert result.returncode != 0
    # No opportunistic cleanup: inspectable transfer evidence remains.
    assert all(p.name.startswith("session-context-" + sha(raw)) for p in destination.iterdir())


def test_new_nonce_gets_a_new_path_and_cannot_relabel_original_observation():
    plan, manifest, raw = raw_fixture("menu_validation")
    first = stage.plan_raw_session_staging(plan, manifest, raw)
    values = sc.decode_session(raw)
    values["session_nonce"] = "c" * 32
    second = stage.plan_raw_session_staging(plan, manifest,
        sc.encode_session(values, schema=sc.MENU_VALIDATION_SCHEMA))
    assert first.path != second.path and first.binding_sha256 != second.binding_sha256
    assert first.observed_epoch == second.observed_epoch
    for altered in (replace(first, observed_epoch=first.observed_epoch + 1),
                    replace(first, path=second.path), replace(first, session_nonce=second.session_nonce),
                    replace(first, binding_schema="x2dii-current-stage-session-v1")):
        with pytest.raises(ValueError):
            stage.execution_steps(plan, dict(first.context), session=altered)


def test_wrong_raw_candidate_manifest_plan_and_historical_install_schema_are_rejected():
    plan, manifest, raw = raw_fixture("menu_validation")
    values = sc.decode_session(raw)
    values["candidate_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="candidate"):
        stage.plan_raw_session_staging(plan, manifest, sc.encode_session(values, schema=sc.MENU_VALIDATION_SCHEMA))
    for altered in ({**manifest, "candidate_sha256": "f" * 64},
                    {**manifest, "candidate": {**manifest["candidate"], "gui_sha256": "f" * 64}}):
        with pytest.raises(ValueError, match="candidate"):
            stage.plan_raw_session_staging(plan, altered, raw)
    from tests.test_session_context import INSTALL_BYTES
    with pytest.raises(ValueError, match="current install"):
        stage.plan_raw_session_staging(plan, manifest, INSTALL_BYTES)
    for altered in (replace(plan, include_session_file=True), replace(plan, stage_root=plan.stage_root + "/other")):
        with pytest.raises(ValueError):
            stage.plan_raw_session_staging(altered, manifest, raw)
    for altered in (raw + b"\n", raw.replace(b"\n", b"\r\n"), bytearray(raw)):
        with pytest.raises(ValueError):
            stage.plan_raw_session_staging(plan, manifest, altered)


def test_each_new_context_is_separate_without_overwriting_prior_context(tmp_path):
    plan, manifest, raw = raw_fixture("menu_validation")
    first = stage.plan_raw_session_staging(plan, manifest, raw)
    values = sc.decode_session(raw)
    values["session_nonce"] = "d" * 32
    next_raw = sc.encode_session(values, schema=sc.MENU_VALIDATION_SCHEMA)
    second = stage.plan_raw_session_staging(plan, manifest, next_raw)
    destination, run = raw_shell(tmp_path, plan, raw)
    for session in (first, second):
        for step in session.steps:
            result = run(step)
            assert result.returncode == 0 and result.stdout == step.expected_stdout
    assert len(list(destination.iterdir())) == 6
    for session in (first, second):
        assert (destination / session.path.rsplit("/", 1)[1]).read_bytes() == session.data


def test_same_size_wrong_raw_content_cannot_pass_after_successful_gzip(tmp_path):
    plan, manifest, raw = raw_fixture()
    session = stage.plan_raw_session_staging(plan, manifest, raw)
    fault = "gzip() { printf '%s' " + shlex.quote("X" * len(raw)) + "; }\n"
    destination, run = raw_shell(tmp_path, plan, raw, fault=fault)
    assert run(session.steps[0]).returncode == 0
    result = run(session.steps[1])
    assert result.returncode != 0 and result.stdout == ""
    assert (destination / session.path.rsplit("/", 1)[1]).read_bytes() == b"X" * len(raw)


def test_oversized_but_canonical_context_is_refused_instead_of_fragmented():
    import random
    plan, manifest, raw = raw_fixture("menu_validation")
    values = sc.decode_session(raw)
    rng = random.Random(153)
    def text(size, alphabet="abcdefghijklmnopqrstuvwxyz0123456789"):
        return "".join(rng.choice(alphabet) for _ in range(size))
    for field, kind in sc.FIELD_KINDS.items():
        if field not in values:
            continue
        if kind == "label":
            values[field] = "u:object_r:" + text(96) + ":s0"
        elif kind == "hex64" and field != "candidate_sha256":
            values[field] = text(64, "0123456789abcdef")
    values["mount_device"] = "/dev/block/" + text(189)
    values["mount_options"] = "ro," + text(253)
    # The shared capture/service executable must retain identical bytes.
    for prefix in ("core_gui", "core_service", "core_capture"):
        for previous in ("core_gui", "core_service", "core_capture"):
            if previous == prefix:
                break
            if values[prefix + "_exe_target"] == values[previous + "_exe_target"]:
                values[prefix + "_exe_sha256"] = values[previous + "_exe_sha256"]
    large = sc.encode_session(values, schema=sc.MENU_VALIDATION_SCHEMA)
    assert sc.decode_session(large) == values
    with pytest.raises(ValueError, match="ADB frame"):
        stage.plan_raw_session_staging(plan, manifest, large)


def test_actual_candidate_hashes_fit_both_fresh_session_commands_and_native_stable_frames(installer):
    import io
    import tarfile
    from tools import delivery_files, menu_content_transport
    from tests.test_temporary_menu_session import temporary_values
    manifest = installer.manifest
    programs = peer.render_role_programs(manifest)
    assembly = delivery_files.assemble_role_delivery(manifest["candidate"], manifest["candidate_sha256"], programs)
    with tarfile.open(fileobj=io.BytesIO(assembly["archive_bytes"]), mode="r:") as reader:
        members = {entry.name: reader.extractfile(entry).read() for entry in reader.getmembers()
                   if entry.name != "members.json"}
    renderer = (peer.ROOT / "tools/prepare_peer_install.py").read_bytes()
    plan = stage.plan_compressed_role_staging(members=members, candidate=manifest["candidate"],
        candidate_sha256=manifest["candidate_sha256"], script_hashes={name: sha(data.encode()) for name, data in programs.items()},
        renderer_source=renderer, renderer_source_sha256=sha(renderer))
    raw = sc.encode_session(temporary_values(installer), schema=sc.MENU_VALIDATION_SCHEMA)
    session = stage.plan_raw_session_staging(plan, manifest, raw)
    assert len(session.steps) == 2
    source = menu_content_transport.review_content_host_source(plan, session,
        datetime.fromtimestamp(session.observed_epoch, timezone.utc))
    assert "ContentQualified = false" in source


def test_changed_gzip_between_steps_is_not_inflated_into_a_new_context(tmp_path):
    plan, manifest, raw = raw_fixture()
    session = stage.plan_raw_session_staging(plan, manifest, raw)
    destination, run = raw_shell(tmp_path, plan, raw)
    assert run(session.steps[0]).returncode == 0
    data_name = session.path.rsplit("/", 1)[1]
    compressed = destination / (data_name + ".gz")
    unknown = b"X" * compressed.stat().st_size
    compressed.write_bytes(unknown)
    result = run(session.steps[1])
    assert result.returncode != 0 and not (destination / data_name).exists()
    assert compressed.read_bytes() == unknown
