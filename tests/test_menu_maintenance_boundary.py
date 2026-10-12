"""Fixed maintenance observation protocol; local fixtures are not live access."""
import hashlib
import os
import subprocess
from unittest import mock

import pytest

from tests.test_release_lifecycle import installer
from tests.test_temporary_menu_session import prepare_maintenance, temporary_values
from tools import session_context
from tools import prepare_peer_install as peer


def context(installer, *, session_kind="menu_validation"):
    installer.shell_fixture()
    prepare_maintenance(installer, preplace=False)
    (installer.root / "proc/234/environ").write_bytes(b"XDG_RUNTIME_DIR=/tmp\0XDG_CACHE_HOME=/data\0")
    if session_kind == "install":
        return peer.session_data(installer.manifest, installer.q)
    return session_context.encode_session(temporary_values(installer),
                                          schema=session_context.MENU_VALIDATION_SCHEMA)


def test_session_path_is_immutable_exact_sha_without_reusing_legacy_name(installer):
    from tools import menu_maintenance_boundary as boundary
    first = context(installer)
    values = session_context.decode_session(first)
    values["session_nonce"] = "d" * 32
    second = session_context.encode_session(values, schema=session_context.MENU_VALIDATION_SCHEMA)
    first_path = boundary.session_path(installer.manifest, peer.sha(first))
    second_path = boundary.session_path(installer.manifest, peer.sha(second))
    assert first_path != second_path
    assert first_path.endswith("/session-context-" + peer.sha(first) + ".data")
    for invalid in ("", "a" * 63, "A" * 64, "a" * 64 + "/../other", None):
        with pytest.raises(ValueError):
            boundary.session_path(installer.manifest, invalid)


def test_fixed_request_binds_one_boundary_and_original_session_without_authority(installer):
    from tools import menu_maintenance_boundary as boundary
    raw = context(installer)
    values = session_context.decode_session(raw)
    request = boundary.make_request(installer.manifest, raw,
        worker_session_sha256=hashlib.sha256(raw).hexdigest(), worker_program_sha256="a" * 64,
        file_index=2, boundary_index=4, challenge="c" * 64, issued_epoch=values["observed_epoch"])
    decoded = boundary.decode_request(request)
    assert decoded["boundary_name"] == "commit_rename"
    assert decoded["mount_access"] == "rw"
    assert decoded["deadline_epoch"] == values["observed_epoch"] + 600
    assert decoded["maintenance_session_sha256"] == hashlib.sha256(raw).hexdigest()
    assert decoded["worker_session_sha256"] == decoded["maintenance_session_sha256"]
    assert decoded["maintenance_program_sha256"] == hashlib.sha256(
        boundary.render_observer(installer.manifest).encode("ascii")).hexdigest()
    assert b"approved=" not in request
    assert boundary.paths(installer.manifest, 2, 4, session_data_sha256=peer.sha(raw), session_kind="menu_validation")["request"].endswith("/.boundary-2-4.data")


def run_observer(installer, *, file_index=0, boundary_index=0, hook="", request_change=None,
                 session_kind="menu_validation", program_kind=None):
    """Real generated shell; only fixed roots and the existing OS fixture adapt."""
    from tools import menu_maintenance_boundary as boundary
    raw = context(installer, session_kind=session_kind)
    values = session_context.decode_session(raw)
    request = boundary.make_request(installer.manifest, raw,
        worker_session_sha256=peer.sha(raw), worker_program_sha256="a" * 64,
        file_index=file_index, boundary_index=boundary_index, challenge="c" * 64,
        issued_epoch=values["observed_epoch"])
    if request_change:
        request = request_change(request)
    fixed = boundary.paths(installer.manifest, file_index, boundary_index, session_data_sha256=peer.sha(raw),
                           session_kind=boundary.session_kind_for_context(installer.manifest, raw))
    (installer.root / fixed["session"].lstrip("/")).write_bytes(raw)
    (installer.root / fixed["request"].lstrip("/")).write_bytes(request)
    if boundary.STAGES[boundary_index][2] == "rw":
        (installer.root / "proc/mounts").write_text(installer.mount_line.replace(" ro,", " rw,"))
    result = execute_observer(installer, raw, request, file_index=file_index,
                              boundary_index=boundary_index, hook=hook, self_domain=None,
                              program_kind=program_kind)
    return result, request, values


def execute_observer(installer, raw_session, raw_request, *, file_index, boundary_index,
                     hook="", self_domain="u:r:hbl_camera_service:s0", program_kind=None,
                     staged_program=False):
    """Read a live local worker fixture without resetting any shared state.

    Only the observer's test program is staged, once. The existing run_script
    adapter also emits its unused top-level legacy session file; it never
    touches the worker's candidate-scoped session/request or payload paths.
    Its OS-self adapter is process-local, so the waiting worker remains su.
    """
    from tools import menu_maintenance_boundary as boundary
    raw = raw_session
    request = raw_request
    values = session_context.decode_session(raw)
    fixed = boundary.paths(installer.manifest, file_index, boundary_index, session_data_sha256=peer.sha(raw),
                           session_kind=boundary.session_kind_for_context(installer.manifest, raw))
    assert (installer.root / fixed["session"].lstrip("/")).read_bytes() == raw
    assert (installer.root / fixed["request"].lstrip("/")).read_bytes() == request
    program_path = installer.root / fixed["program"].lstrip("/")
    if not staged_program:
        program_path.parent.mkdir(parents=True, exist_ok=True)
    if program_kind is None:
        program_kind = boundary.session_kind_for_context(installer.manifest, raw)
    program = (program_path.read_bytes().decode("ascii") if staged_program else
               boundary.render_observer(installer.manifest, session_kind=program_kind))
    installer.scripts["boundary"] = program
    os_hook = r'''
readlink() {
 if [ "$1" = "$fixture/proc/100/exe" ]; then echo /system/bin/camera-test
 else fixture_readlink "$@"; fi
}
test_base_sha=$(declare -f sha256sum)
eval "${test_base_sha/sha256sum/test_base_sha256sum}"
sha256sum() {
 if [ "$#" = 1 ] && [ "$1" = "$fixtureTEST_PROGRAM" ]; then
  test_observed_program=$(/usr/bin/sha256sum "$1") || return 1
  if [ "${test_observed_program%% *}" = "$X2DII_TEST_HOST_PROGRAM_SHA" ]; then
   printf 'TEST_PROGRAM_SHA  %s\n' "$1"
  else printf '%s\n' "$test_observed_program"; fi
 else test_base_sha256sum "$@"; fi
}
date() { printf 'TEST_EPOCH\n'; }
mount() { printf forbidden-mount >&2; return 90; }
start() { printf forbidden-start >&2; return 90; }
stop() { printf forbidden-stop >&2; return 90; }
chcon() { printf forbidden-chcon >&2; return 90; }
chown() { printf forbidden-chown >&2; return 90; }
chmod() { printf forbidden-chmod >&2; return 90; }
rm() { printf forbidden-rm >&2; return 90; }
rmdir() { printf forbidden-rmdir >&2; return 90; }
mv() { printf forbidden-mv >&2; return 90; }
cp() { printf forbidden-cp >&2; return 90; }
mkdir() { printf forbidden-mkdir >&2; return 90; }
'''.replace("TEST_PROGRAM_SHA", peer.sha(program.encode("ascii"))).replace(
        "TEST_PROGRAM", fixed["program"]).replace("TEST_EPOCH", str(values["observed_epoch"]))
    if self_domain is not None:
        os_hook += '''
cat() {
 if [ "$#" = 1 ] && [ "$1" = "$fixture/proc/self/attr/current" ]; then
  printf '%s\\n' TEST_SELF_DOMAIN
 else /usr/bin/cat "$@"; fi
}
'''.replace("TEST_SELF_DOMAIN", peer.shlex.quote(self_domain))
    actual_run = subprocess.run

    def run_file(args, **kwargs):
        if args[1] != "-s":
            return actual_run(args, **kwargs)
        # The old harness supplies all original core observations. Execute its
        # transformed script as a file so $0 and native source identity matter.
        source = kwargs.pop("input").decode("ascii").replace(
            'mb_file "$X2DII_SESSION_CORE_CAPTURE_EXE_TARGET"',
            'mb_file "$fixture$X2DII_SESSION_CORE_CAPTURE_EXE_TARGET"')
        expected_program = source.encode("ascii")
        original = None
        if staged_program:
            original = (program_path.stat().st_ino, program_path.stat().st_mtime_ns, program_path.read_bytes())
            host_path = installer.root / ".host-file-observer.sh"
            host_path.write_bytes(expected_program)
        if not program_path.exists():
            with program_path.open("xb") as output:
                output.write(expected_program)
        env = os.environ.copy()
        env["X2DII_TEST_HOST_PROGRAM_SHA"] = peer.sha(expected_program)
        args = [args[0], installer.posix + fixed["program"], peer.sha(raw),
                str(file_index), str(boundary_index), peer.sha(request)]
        if staged_program:
            args = [args[0], "-c", 'host_source=$1; shift; . "$host_source"', args[1],
                    installer.posix + "/.host-file-observer.sh", *args[2:]]
        result = actual_run(args, env=env, **kwargs)
        if original is not None:
            assert (program_path.stat().st_ino, program_path.stat().st_mtime_ns, program_path.read_bytes()) == original
        return result

    with mock.patch.object(peer, "session_data", return_value=raw), mock.patch(
            "tests.test_peer_install.subprocess.run", side_effect=run_file):
        result = installer.run_script("boundary", boundary_hook=os_hook + hook)
    return result


@pytest.mark.parametrize("file_index,boundary_index", ((0, 0), (2, 4), (3, 6)))
def test_generated_maintenance_observer_checks_fixed_boundary_without_writes(installer, file_index, boundary_index):
    from tools import menu_maintenance_boundary as boundary
    result, request, values = run_observer(installer, file_index=file_index, boundary_index=boundary_index)
    assert result.returncode == 0, (result.stdout, result.stderr)
    response = boundary.decode_response(result.stdout, request, received_epoch=values["observed_epoch"])
    assert response["result"] == "OBSERVED_MATCH"
    assert response["scope"] == "ONE_BOUNDARY_ONLY_NOT_AUTHORIZATION"
    assert b"forbidden-" not in result.stderr
    assert not (installer.root / "operations").exists()


@pytest.mark.parametrize("damage,hook,exit_code", (
    ("role", "printf 'u:r:su:s0\\n' > \"$fixture/proc/self/attr/current\"\n", 31),
    ("boot", "printf 'different\\n' > \"$fixture/proc/sys/kernel/random/boot_id\"\n", 35),
    ("slot", "unrd() { printf '0\\n'; }\n", 35),
    ("namespace", "readlink() { echo 'mnt:[999]'; }\n", 35),
    ("service", "printf 'u:r:changed:s0\\n' > \"$fixture/proc/345/attr/current\"\n", 35),
    ("observer", "printf 'u:r:su:s0\\n' > \"$fixture/proc/100/attr/current\"\n", 35),
    ("gui_environment", "printf 'LD_PRELOAD=unexpected\\000' > \"$fixture/proc/234/environ\"\n", 35),
    ("gui_maps_denied", r'''grep() { printf 'Permission denied\n' >&2; return 2; }
''', 35),
    ("rw_mount", r'''printf '/dev/block/current-attested-slot %s/system ext4 rw,seclabel,relatime 0 0\n' "$fixture" > "$fixture/proc/mounts"
''', 35),
))
def test_changed_runtime_or_query_failure_never_emits_matching_boundary(installer, damage, hook, exit_code):
    result, _, _ = run_observer(installer, hook=hook)
    assert result.returncode == exit_code, (damage, result.stdout, result.stderr)
    assert b"OBSERVED_MATCH" not in result.stdout
    assert not (installer.root / "operations").exists()


@pytest.mark.parametrize("phase", ("start", "finish"))
def test_observer_checks_original_deadline_before_and_after_queries(installer, phase):
    epoch = int(peer.datetime.fromisoformat(installer.q["observed_utc"]).timestamp())
    hook = f'''
date() {{
 if [ "{phase}" = start ] || [ -f "$fixture/time-read" ]; then echo {epoch + 601}
 else printf used > "$fixture/time-read"; echo {epoch}; fi
}}
'''
    result, _, _ = run_observer(installer, hook=hook)
    assert result.returncode == 34, (result.stdout, result.stderr)
    assert b"OBSERVED_MATCH" not in result.stdout
    assert not (installer.root / "operations").exists()


@pytest.mark.parametrize("old,new", (
    (b"boundary_name=remount_rw", b"boundary_name=commit_rename"),
    (b"mount_access=ro", b"mount_access=rw"),
    (b"file_index=0", b"file_index=1"),
    (b"boundary_index=0", b"boundary_index=1"),
    (b"challenge=" + b"c" * 64, b"challenge=$(touch owned)"),
    (b"worker_session_sha256=", b"unrecognized_session_sha256="),
))
def test_observer_rejects_misbound_or_noncanonical_request_data(installer, old, new):
    result, _, _ = run_observer(installer, request_change=lambda raw: raw.replace(old, new))
    assert result.returncode == 33, (result.stdout, result.stderr)
    assert b"OBSERVED_MATCH" not in result.stdout
    assert not (installer.root / "owned").exists()


def test_response_for_another_challenge_or_boundary_is_not_the_waiting_request(installer):
    from tools import menu_maintenance_boundary as boundary
    result, request, values = run_observer(installer)
    assert result.returncode == 0, (result.stdout, result.stderr)
    for other_request in (request.replace(b"c" * 64, b"d" * 64),
                          request.replace(b"file_index=0", b"file_index=1")):
        with pytest.raises(ValueError, match="binding differs"):
            boundary.decode_response(result.stdout, other_request, received_epoch=values["observed_epoch"])
    with pytest.raises(ValueError, match="expired"):
        boundary.decode_response(result.stdout, request, received_epoch=values["observed_epoch"] + 601)


def test_unrelated_process_maps_are_not_a_preplacement_or_removal_claim(installer):
    hook = r'''
grep() {
 case "$*" in *"$fixture/proc/123/maps"*) printf forbidden-unrelated-maps >&2; return 2;; esac
 /usr/bin/grep "$@"
}
'''
    result, _, _ = run_observer(installer, hook=hook)
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert b"forbidden-unrelated-maps" not in result.stderr
    assert b"scope=ONE_BOUNDARY_ONLY_NOT_AUTHORIZATION" in result.stdout


def test_reused_observer_reads_existing_worker_state_without_resetting_it(installer):
    from tools import menu_maintenance_boundary as boundary
    raw = context(installer)
    values = session_context.decode_session(raw)
    request = boundary.make_request(installer.manifest, raw,
        worker_session_sha256=peer.sha(raw), worker_program_sha256="a" * 64,
        file_index=0, boundary_index=0, challenge="c" * 64,
        issued_epoch=values["observed_epoch"])
    fixed = boundary.paths(installer.manifest, 0, 0, session_data_sha256=peer.sha(raw), session_kind="menu_validation")
    session_path = installer.root / fixed["session"].lstrip("/")
    request_path = installer.root / fixed["request"].lstrip("/")
    session_path.write_bytes(raw)
    request_path.write_bytes(request)
    worker_self = installer.root / "proc/self/attr/current"
    worker_self.write_text("u:r:su:s0\n")
    staged_payload = session_path.parent / "libx2dii_menu.so"
    staged_payload.write_bytes(b"worker-state-must-not-be-recreated")
    before = {path: (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
              for path in (session_path, request_path, worker_self, staged_payload,
                           installer.root / "proc/mounts")}

    first = execute_observer(installer, raw, request, file_index=0, boundary_index=0)
    assert first.returncode == 0, (first.stdout, first.stderr)
    program_path = installer.root / fixed["program"].lstrip("/")
    program_before = (program_path.read_bytes(), program_path.stat().st_ino,
                      program_path.stat().st_mtime_ns)
    (installer.root / "gui-service-state").write_text("stopped")
    second = execute_observer(installer, raw, request, file_index=0, boundary_index=0)
    assert second.returncode == 35, (second.stdout, second.stderr)
    assert b"OBSERVED_MATCH" not in second.stdout
    assert (installer.root / "gui-service-state").read_text() == "stopped"
    assert all((path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns) == evidence
               for path, evidence in before.items())
    assert (program_path.read_bytes(), program_path.stat().st_ino,
            program_path.stat().st_mtime_ns) == program_before


def test_request_tail_read_error_is_not_clean_eof(installer):
    result, _, _ = run_observer(installer, hook=r'''
read() {
 if [ "$#" = 2 ] && [ "$1" = -r ] && [ "$2" = mb_extra ]; then return 2; fi
 builtin read "$@"
}
''')
    assert result.returncode == 33, (result.stdout, result.stderr)
    assert b"OBSERVED_MATCH" not in result.stdout


def test_request_issued_epoch_cannot_exceed_the_shell_scalar_range(installer):
    from tools import menu_maintenance_boundary as boundary
    values = session_context.decode_session(context(installer))
    values["observed_epoch"] = 2147483047
    raw = session_context.encode_session(values, schema=session_context.MENU_VALIDATION_SCHEMA)
    arguments = dict(worker_session_sha256=peer.sha(raw), worker_program_sha256="a" * 64,
                     file_index=0, boundary_index=0, challenge="c" * 64)
    valid = boundary.make_request(installer.manifest, raw, issued_epoch=2147483047, **arguments)
    assert boundary.decode_request(valid)["deadline_epoch"] == 2147483647
    with pytest.raises(ValueError, match="invalid epoch"):
        boundary.make_request(installer.manifest, raw, issued_epoch=2147483048, **arguments)


def test_response_timestamps_cannot_exceed_the_shell_scalar_range(installer):
    from tools import menu_maintenance_boundary as boundary
    values = session_context.decode_session(context(installer))
    values["observed_epoch"] = 2147483047
    raw = session_context.encode_session(values, schema=session_context.MENU_VALIDATION_SCHEMA)
    request = boundary.make_request(installer.manifest, raw,
        worker_session_sha256=peer.sha(raw), worker_program_sha256="a" * 64,
        file_index=0, boundary_index=0, challenge="c" * 64, issued_epoch=2147483047)
    prefix = request.replace(b"schema=x2dii-menu-maintenance-request-v1\n",
                             b"schema=x2dii-menu-maintenance-response-v1\n", 1)
    suffix = ("request_sha256=" + peer.sha(request) + "\nstarted_epoch=2147483047\n"
              "checked_epoch=2147483047\nresult=OBSERVED_MATCH\n"
              "scope=ONE_BOUNDARY_ONLY_NOT_AUTHORIZATION\n").encode("ascii")
    response = prefix + suffix
    assert boundary.decode_response(response, request, received_epoch=2147483047)["checked_epoch"] == 2147483047
    beyond_shell_range = prefix + suffix.replace(b"2147483047", b"2147483048")
    with pytest.raises(ValueError, match="invalid response time"):
        boundary.decode_response(beyond_shell_range, request, received_epoch=2147483048)


def test_install_request_binds_the_explicit_v2_observer_not_temporary_validation(installer):
    from tools import menu_maintenance_boundary as boundary
    context(installer)
    raw = peer.session_data(installer.manifest, installer.q)
    values = session_context.decode_session(raw)
    assert values["kind"] == "install"
    request = boundary.make_request(installer.manifest, raw,
        worker_session_sha256=peer.sha(raw), worker_program_sha256="a" * 64,
        file_index=0, boundary_index=0, challenge="c" * 64, issued_epoch=values["observed_epoch"])
    assert boundary.session_kind_for_context(installer.manifest, raw) == "install"
    parsed = boundary.decode_request(request)
    install_program = boundary.render_observer(installer.manifest, session_kind="install")
    assert parsed["maintenance_program_sha256"] == peer.sha(install_program.encode("ascii"))
    assert install_program != boundary.render_observer(installer.manifest)


@pytest.mark.parametrize("data_kind,program_kind,expected", (
    ("install", "install", 0),
    ("install", "menu_validation", 32),
    ("menu_validation", "install", 32),
))
def test_actual_observer_enforces_its_compiled_session_variant(installer, data_kind, program_kind, expected):
    from tools import menu_maintenance_boundary as boundary
    result, request, values = run_observer(installer, session_kind=data_kind, program_kind=program_kind)
    assert result.returncode == expected, (result.stdout, result.stderr)
    if expected == 0:
        assert boundary.decode_response(result.stdout, request, received_epoch=values["observed_epoch"])["result"] == "OBSERVED_MATCH"
    else:
        assert b"OBSERVED_MATCH" not in result.stdout
    assert not (installer.root / "operations").exists()


@pytest.mark.parametrize("fault", ("v1-install", "su-observer", "recovery"))
def test_formal_protocol_rejects_legacy_or_wrong_role_contexts(installer, fault):
    from tools import menu_maintenance_boundary as boundary
    raw = context(installer, session_kind="install")
    values = session_context.decode_session(raw)
    if fault == "v1-install":
        raw = session_context.encode_session({key: values[key] for key in session_context.COMMON_FIELDS})
    elif fault == "su-observer":
        values["observer_domain"] = "u:r:su:s0"
        raw = session_context.encode_session(values, schema=session_context.INSTALL_SCHEMA)
    else:
        from tests.test_menu_boot_file import recovery_data
        raw = recovery_data(installer)
    with pytest.raises(ValueError, match="maintenance (session|context)"):
        boundary.session_kind_for_context(installer.manifest, raw)


@pytest.mark.parametrize("kind", (None, True, "recovery", "install;exit 0"))
def test_only_two_fixed_program_variants_can_be_rendered(installer, kind):
    from tools import menu_maintenance_boundary as boundary, temporary_menu_files as files
    with pytest.raises(ValueError, match="session kind"):
        boundary.render_observer(installer.manifest, session_kind=kind)
    with pytest.raises(ValueError, match="session kind"):
        files.render_supervised_preplacement(installer.manifest, file_index=0, session_kind=kind)
