"""Two exact preparation gaps only; synthetic contexts, no camera sender."""
import pytest
from tools import stage_menu_delivery as stage, temporary_menu_files as workers
from tools import menu_boot_file as boot
from tests.test_raw_session_staging import raw_fixture, raw_shell, sha


def test_temporary_workers_are_exact_separate_production_sources_not_formal_members():
    plan, manifest, raw = raw_fixture("menu_validation")
    prepared = stage.plan_menu_validation_worker_staging(plan, manifest, raw)
    assert prepared.purpose == "menu_validation_workers"
    assert prepared.plan_sha256 == plan.plan_sha256
    assert prepared.session_data_sha256 == sha(raw)
    assert not prepared.installable
    assert tuple(path.rsplit("/", 1)[1] for path, _ in prepared.files) == tuple(
        f"menu-validation-preplace-{i}.sh" for i in range(4))
    for index, (path, data) in enumerate(prepared.files):
        assert path == workers.worker_path(manifest, index, session_kind="menu_validation")
        assert data == workers.render_supervised_preplacement(
            manifest, file_index=index, session_kind="menu_validation").encode("ascii")
        assert path.rsplit("/", 1)[1] not in plan.member_names


def payload_identities(manifest):
    return tuple(f"11:{120+i}:81a4:1:{entry['bytes']}:0:0"
                 for i, entry in enumerate(manifest["candidate"]["files"]))


def test_boot_dependency_preparation_only_uses_exact_encoder_and_current_install_context():
    plan, manifest, raw = raw_fixture()
    identities = payload_identities(manifest)
    prepared = stage.plan_boot_payload_identity_staging(plan, manifest, raw, identities)
    assert prepared.purpose == "boot_payload_identities"
    assert prepared.session_data_sha256 == sha(raw) and not prepared.installable
    assert prepared.files == ((plan.stage_root + "/.payload-identities-" + "b" * 32 + ".data",
                                boot.encode_payload_identities(manifest, identities)),)
    assert len(prepared.steps) == 1


def prepare(kind):
    plan, manifest, raw = raw_fixture("menu_validation" if kind == "workers" else "install")
    operation = (stage.plan_menu_validation_worker_staging(plan, manifest, raw) if kind == "workers" else
                 stage.plan_boot_payload_identity_staging(plan, manifest, raw, payload_identities(manifest)))
    return plan, manifest, raw, operation


@pytest.mark.parametrize("kind", ("workers", "dependencies"))
def test_preparation_executes_exact_bytes_without_replacing_any_formal_content(tmp_path, kind):
    plan, manifest, raw, prepared = prepare(kind)
    destination, run = raw_shell(tmp_path, plan, raw)
    old = {name: b"FORMAL ORIGINAL " + name.encode() for name in plan.member_names}
    old["session-context-" + "f" * 64 + ".data"] = b"historical context"
    for name, data in old.items():
        (destination / name).write_bytes(data)
    for step in prepared.steps:
        result = run(step)
        assert result.returncode == 0 and result.stderr == "", (step.label, result.stderr)
        assert result.stdout == step.expected_stdout
    for path, expected in prepared.files:
        assert (destination / path.rsplit("/", 1)[1]).read_bytes() == expected
    assert all((destination / name).read_bytes() == data for name, data in old.items())
    snapshot = {p.name: p.read_bytes() for p in destination.iterdir()}
    repeated = run(prepared.steps[0])
    assert repeated.returncode != 0
    assert {p.name: p.read_bytes() for p in destination.iterdir()} == snapshot
    if kind == "workers":
        chunk_count = sum(step.label.startswith("temporary-worker-chunk-") for step in prepared.steps)
        assert len(list(destination.glob(".menu-validation-workers-*"))) == 3 + chunk_count
    else:
        assert len(list(destination.glob(".payload-identities-*"))) == 2


@pytest.mark.parametrize("kind", ("workers", "dependencies"))
@pytest.mark.parametrize("object_kind", ("file", "directory"))
def test_existing_target_is_preserved_before_any_auxiliary_creation(tmp_path, kind, object_kind):
    plan, _, raw, prepared = prepare(kind)
    destination, run = raw_shell(tmp_path, plan, raw)
    target = destination / prepared.files[-1][0].rsplit("/", 1)[1]
    if object_kind == "directory":
        target.mkdir()
    else:
        target.write_bytes(b"UNKNOWN DO NOT OVERWRITE")
    result = run(prepared.steps[0])
    assert result.returncode != 0 and list(destination.iterdir()) == [target]
    if object_kind == "file":
        assert target.read_bytes() == b"UNKNOWN DO NOT OVERWRITE"


@pytest.mark.parametrize("kind", ("workers", "dependencies"))
@pytest.mark.parametrize("offset", (-1, 601))
def test_auxiliary_preparation_does_not_renew_context_lease(tmp_path, kind, offset):
    plan, _, raw, prepared = prepare(kind)
    destination, run = raw_shell(tmp_path, plan, raw, epoch=1791040000 + offset)
    result = run(prepared.steps[0])
    assert result.returncode != 0 and not list(destination.iterdir())


@pytest.mark.parametrize("fault", ("compressed-content", "archive-content", "target-between", "tar-status",
                                 "gzip-status", "hash-status", "directory-status"))
def test_temporary_workers_reject_corruption_and_failed_native_tools(tmp_path, fault):
    plan, _, raw, prepared = prepare("workers")
    destination, run = raw_shell(tmp_path, plan, raw)
    phase = {"compressed-content": "inflate-temporary-workers", "archive-content": "extract-verify-temporary-workers",
             "target-between": "extract-verify-temporary-workers", "tar-status": "extract-verify-temporary-workers",
             "gzip-status": "inflate-temporary-workers", "hash-status": "decode-temporary-workers",
             "directory-status": "extract-verify-temporary-workers"}[fault]
    for step in prepared.steps:
        extra = ""
        if step.label == phase:
            if fault in ("compressed-content", "archive-content"):
                file = next(destination.glob("*.gz" if fault == "compressed-content" else "*.tar"))
                content = file.read_bytes()
                file.write_bytes(bytes([content[0] ^ 1]) + content[1:])
            elif fault == "target-between":
                (destination / prepared.files[2][0].rsplit("/", 1)[1]).write_bytes(b"UNKNOWN")
            elif fault == "tar-status":
                extra = 'tar() { command tar "$@"; return 9; }\n'
            elif fault == "gzip-status":
                extra = 'gzip() { command gzip "$@"; return 9; }\n'
            elif fault == "hash-status":
                extra = 'sha256sum() { command sha256sum "$@"; return 9; }\n'
            else:
                extra = '''stat() { case "$2" in '%u %g %a') printf '0 0 700\\n'; return 9;; *) command stat "$@";; esac; }\n'''
            result = run(step, extra)
            assert result.returncode != 0
            if fault == "target-between":
                assert (destination / prepared.files[2][0].rsplit("/", 1)[1]).read_bytes() == b"UNKNOWN"
            if fault not in ("tar-status", "target-between"):
                assert not any((destination / path.rsplit("/", 1)[1]).exists() for path, _ in prepared.files)
            return
        result = run(step)
        assert result.returncode == 0, (step.label, result.stderr)
    raise AssertionError("fault phase did not execute")


def test_wrong_session_kinds_and_invalid_dependency_identities_are_refused():
    for kind in ("install", "recovery"):
        plan, manifest, raw = raw_fixture(kind)
        with pytest.raises(ValueError, match="temporary worker session"):
            stage.plan_menu_validation_worker_staging(plan, manifest, raw)
    for kind in ("menu_validation", "recovery"):
        plan, manifest, raw = raw_fixture(kind)
        with pytest.raises(ValueError, match="current install session"):
            stage.plan_boot_payload_identity_staging(plan, manifest, raw, payload_identities(manifest))
    plan, manifest, raw = raw_fixture()
    identities = payload_identities(manifest)
    for invalid in (identities[:3], (*identities[:3], identities[0]),
                    (identities[0].replace(":81a4:", ":81ff:"), *identities[1:])):
        with pytest.raises(ValueError):
            stage.plan_boot_payload_identity_staging(plan, manifest, raw, invalid)


@pytest.mark.parametrize("fault", ("base64-status", "same-size-wrong-content", "hash-status"))
def test_dependency_corruption_or_failed_tool_cannot_create_a_success_receipt(tmp_path, fault):
    plan, _, raw, prepared = prepare("dependencies")
    destination, run = raw_shell(tmp_path, plan, raw)
    if fault == "base64-status":
        extra = 'base64() { command base64 "$@"; return 9; }\n'
    elif fault == "hash-status":
        extra = 'sha256sum() { command sha256sum "$@"; return 9; }\n'
    else:
        extra = "base64() { printf '%s' '" + "X" * len(prepared.files[0][1]) + "'; }\n"
    result = run(prepared.steps[0], extra)
    assert result.returncode != 0 and result.stdout == ""
    assert len(list(destination.iterdir())) == 2  # Retain evidence, no auto-cleanup.


@pytest.mark.parametrize("same_content", (False, True))
def test_worker_next_chunk_never_modifies_previous_replaced_chunk(tmp_path, same_content):
    plan, _, raw, prepared = prepare("workers")
    destination, run = raw_shell(tmp_path, plan, raw)
    first = destination / (".menu-validation-workers-" + "b" * 32 + "-0.b64")
    for step in prepared.steps:
        if step.label == "temporary-worker-chunk-2048":
            before = first.stat()
            previous = first.read_bytes()
            first.rename(destination / "retained-original-block")
            replacement = previous if same_content else b"X" * len(previous)
            first.write_bytes(replacement)
            assert first.stat().st_ino != before.st_ino
            result = run(step)
            assert result.returncode == 0
            assert first.read_bytes() == replacement
            # Repeating a chunk refuses instead of appending to its output.
            next_chunk = destination / (".menu-validation-workers-" + "b" * 32 + "-2048.b64")
            saved = next_chunk.read_bytes()
            assert run(step).returncode != 0 and next_chunk.read_bytes() == saved
            return
        assert run(step).returncode == 0
    pytest.fail("second worker chunk not reached")
