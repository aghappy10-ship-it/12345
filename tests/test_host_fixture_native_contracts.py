"""Fresh current-only native contracts for real on-disk fixtures; local only."""
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import pytest

from tests.test_release_lifecycle import installer
from tests.test_peer_install import SH
from tests import test_menu_owned_cleanup as cleanup
from tests.test_install_core_runtime import distinct_capture_owner
from tools import prepare_peer_install as peer

SELF = Path(__file__).resolve()
ROOT = peer.ROOT.resolve()
SUBJECT_FILES = (
    SELF,
    ROOT / "tests/test_peer_install.py",
    ROOT / "tests/test_menu_owned_cleanup.py",
    ROOT / "tests/test_install_core_runtime.py",
    ROOT / "tools/prepare_peer_install.py",
    ROOT / "tests/test_runtime_observation.py",
)
RUNTIME_FILES = (SH,
    Path("C:/Program Files/Git/usr/bin/sha256sum.exe"),
    Path("C:/Program Files/Git/usr/bin/stat.exe"))


def bindings():
    return {str(path): peer.sha(path.read_bytes())
        for path in (*SUBJECT_FILES, *RUNTIME_FILES)}


HEADER = "#!/system/bin/sh\n# SESSION_DATA_PARSER_BEGIN\n# SESSION_DATA_PARSER_END\n"
FORMAT = "%d:%i:%f:%h:%s:%u:%g"


def probe(fixture, command, *, trace=False, hook=""):
    assert sys.dont_write_bytecode and not sys.flags.optimize
    before = bindings()
    if trace:
        command = ('printf \'ADAPTER_SHELL=%s\\n\' "$BASHPID" >&2\n'
            'PS4=\'+NATIVE_BOUNDARY:$BASHPID:\'\nset -x\n' + command +
            '\ncommand_status=$?\nset +x\nexit "$command_status"\n')
    fixture.scripts["native-contract"] = HEADER + command + "\n"
    captured = {"adapter": "actual_on_disk_current", "source_before": before,
        "installable": False, "camera_accesses": 0, "lifecycle_executed": False}

    def execute(source, arguments):
        captured["current_emitted_source_sha256"] = peer.sha(source.encode("ascii"))
        captured["executed_source_sha256"] = peer.sha(source.encode("ascii"))
        try:
            return subprocess.run([str(SH), "-s", "--", *arguments],
                input=source.encode("ascii"), capture_output=True, timeout=30)
        except subprocess.TimeoutExpired as error:
            fixture.temp._finalizer.detach()
            fixture.temp.cleanup = lambda: None
            captured.update(retained_original_fixture=str(fixture.root),
                timeout_seconds=error.timeout,
                partial_stdout_hex=(error.stdout or b"").hex(),
                partial_stderr_hex=(error.stderr or b"").hex())
            error.native_contract_capture = captured
            error.add_note("native_contract_capture=" + json.dumps(captured, sort_keys=True))
            raise

    result = fixture.run_script("native-contract", process_runner=execute,
        boundary_hook=cleanup.os_hook(fixture, {"observed_epoch": 0}, observer=True, hook=hook))
    after = bindings()
    assert after == before
    captured["source_after"] = after
    return result, captured


def triple(result):
    return result.returncode, result.stdout, result.stderr


def native_pids(result, tool):
    return [int(match[1]) for match in re.finditer(
        rb"(?m)^\++NATIVE_BOUNDARY:(\d+):/usr/bin/" + tool.encode() + rb"(?: |$)", result.stderr)]


@pytest.mark.parametrize("tool", ("sha256sum", "stat"))
def test_current_no_extra_host_shell(installer, record_property, tool):
    installer.shell_fixture()
    (installer.root / "native-control.data").write_bytes(b"fresh real bytes\n")
    command = ('sha256sum "$fixture/native-control.data"' if tool == "sha256sum" else
        f'stat -c \'{FORMAT}\' "$fixture/native-control.data"')
    actual, captured = probe(installer, command, trace=True)
    adapter_pid = int(re.search(rb"(?m)^ADAPTER_SHELL=(\d+)$", actual.stderr)[1])
    pids = native_pids(actual, tool)
    captured.update(adapter_shell_pid=adapter_pid, native_shell_pids=pids,
        does_not_prove_30_second_cleanup=True)
    record_property("native_boundary", json.dumps(captured, sort_keys=True))
    assert actual.returncode == 0 and pids == [adapter_pid], (actual, pids)


@pytest.mark.parametrize("shape", ("default", "distinct", "dynamic_child"))
def test_current_every_actual_mapping_changed_and_restored(installer, record_property, shape):
    if shape == "distinct":
        distinct_capture_owner(installer)
    installer.shell_fixture()
    if shape == "dynamic_child":
        child = installer.root / "proc/456/exe"
        child.parent.mkdir(parents=True)
        child.write_bytes((installer.root / "system/bin/camera-gui").read_bytes())
        installer.core_hashes[child] = (peer.sha(child.read_bytes()),
            installer.q["runtime_observation"]["gui"]["process"]["exe_sha256"])
    observations = []
    keys = tuple(installer.core_hashes)
    assert len(keys) == {"default": 5, "distinct": 7, "dynamic_child": 6}[shape]
    if shape == "distinct":
        assert installer.root / "system/bin/capture-owner" in keys
        assert installer.root / "proc/456/exe" in keys
    if shape == "dynamic_child":
        assert child in keys
    for path in keys:
        original = path.read_bytes()
        argument = peer.shlex.quote("/" + path.relative_to(installer.root).as_posix())
        for state in ("original", "changed", "restored"):
            path.write_bytes(original + b"\0changed fresh bytes\n" if state == "changed" else original)
            reference, _ = probe(installer, "/usr/bin/sha256sum " + argument)
            actual, captured = probe(installer, "sha256sum " + argument, trace=True)
            expected = reference.stdout if state == "changed" else (
                installer.core_hashes[path][1] + "  " + installer.posix + "/" +
                path.relative_to(installer.root).as_posix() + "\n").encode()
            pids = native_pids(actual, "sha256sum")
            captured.update(shape=shape, state=state, path=str(path), native_shell_pids=pids)
            observations.append(captured)
            assert reference.returncode == actual.returncode == 0
            assert actual.stdout == expected and len(pids) == 1, (path, state, actual, reference)
    record_property("all_dynamic_mapping_keys", json.dumps(
        {"keys": [str(path) for path in keys], "observations": observations}, sort_keys=True))


def projected_identity_contract(native):
    """Historic modeled projection, with native output/error as independent input."""
    if native.returncode:
        return native.returncode, b"", native.stderr
    fields = native.stdout.rstrip(b"\n").split(b":") + [b""] * 5
    output = b":".join((fields[0], fields[1], b"81a4", fields[3], fields[4], b"0", b"0")) + b"\n"
    return 0, output, native.stderr


@pytest.mark.parametrize("tool", ("sha256sum", "stat"))
def test_current_option_calls_preserve_historic_adapter_output(installer, record_property, tool):
    installer.shell_fixture()
    (installer.root / "native-control.data").write_bytes(b"abc\n")
    if tool == "sha256sum":
        digest = hashlib.sha256(b"abc\n").hexdigest()
        command = ("printf '%s  %s\\n%s  %s\\n' '" + digest +
            "' \"$fixture/native-control.data\" '" + "0" * 64 +
            "' \"$fixture/native-missing.data\" | sha256sum --check")
        native_command = command.replace("sha256sum", "/usr/bin/sha256sum")
    else:
        command = f"stat -c '{FORMAT}' --help"
        native_command = "/usr/bin/" + command
    native, native_binding = probe(installer, native_command)
    actual, captured = probe(installer, command)
    if tool == "sha256sum":
        assert native.returncode == 1 and b": OK\n" in native.stdout
        expected = (1, b"", native.stderr)
    else:
        expected = projected_identity_contract(native)
    captured.update(tool=tool, native_binding=native_binding,
        native_status=native.returncode, native_stdout_hex=native.stdout.hex(),
        expected_stdout_hex=expected[1].hex(), actual_stdout_hex=actual.stdout.hex())
    record_property("option_contract", json.dumps(captured, sort_keys=True))
    assert triple(actual) == expected, (actual, native, expected)


def test_current_sha_native_paths_stdin_options_and_errors(installer, record_property):
    installer.shell_fixture()
    (installer.root / "native-control.data").write_bytes(b"abc\n")
    (installer.root / "native-directory").mkdir()
    near = installer.root / "system/bin/camera-gui-near-prefix"
    near.write_bytes(b"not mapped original\n")
    observations = []
    commands = (
        ("near_prefix", 'sha256sum "/system/bin/camera-gui-near-prefix"'),
        ("stdin_zero_args", "printf 'abc\\n' | sha256sum"),
        ("stdin_dash", "printf 'abc\\n' | sha256sum -"),
        ("multiple_partial_failure", 'sha256sum "$fixture/native-control.data" "$fixture/native-missing.data"'),
        ("missing", 'sha256sum "$fixture/native-missing.data"'),
        ("directory", 'sha256sum "$fixture/native-directory"'),
        ("escaped_windows_path", 'native_winpath=$(/usr/bin/cygpath -w "$fixture/native-control.data"); sha256sum "$native_winpath"'),
        ("option_help", "sha256sum --help"),
        ("option_version", "sha256sum --version"),
    )
    for case, command in commands:
        native_command = command.replace("sha256sum", "/usr/bin/sha256sum")
        native, reference_binding = probe(installer, native_command)
        actual, captured = probe(installer, command)
        captured.update(case=case, reference_binding=reference_binding)
        observations.append(captured)
        expected = (native.returncode, native.stdout.rstrip(b"\n") + b"\n", native.stderr) if case in ("option_help", "option_version") else triple(native)
        assert triple(actual) == expected, (case, actual, native, expected)
        if case == "escaped_windows_path":
            assert actual.returncode == 0 and actual.stdout.startswith(b"\\"), actual
        if case in ("stdin_zero_args", "stdin_dash", "multiple_partial_failure", "missing", "directory", "escaped_windows_path", "near_prefix"):
            native_command = command.replace("sha256sum", "/usr/bin/sha256sum")
            native, _ = probe(installer, native_command)
            assert triple(actual) == triple(native), (case, actual, native)
    record_property("sha_boundary_vectors", json.dumps(observations, sort_keys=True))


def test_current_stat_fallback_and_native_freshness(installer, record_property):
    installer.shell_fixture()
    data = installer.root / "native-control.data"
    data.write_bytes(b"abc\n")
    (installer.root / "native-second.data").write_bytes(b"other bytes\n")
    (installer.root / "native-directory").mkdir()
    observations = []
    for case, arguments in (
        ("dash_dash_fallback", f"-c '{FORMAT}' -- \"$fixture/native-control.data\""),
        ("multiple_fallback", f"-c '{FORMAT}' \"$fixture/native-control.data\" \"$fixture/native-second.data\""),
        ("Lc_fallback", f"-Lc '{FORMAT}' \"$fixture/native-control.data\""),
        ("option_help", f"-c '{FORMAT}' --help"),
        ("option_version", f"-c '{FORMAT}' --version"),
    ):
        native, reference_binding = probe(installer, "/usr/bin/stat " + arguments)
        actual, captured = probe(installer, "stat " + arguments)
        expected = projected_identity_contract(native)
        assert triple(actual) == expected, (case, actual, native, expected)
        captured.update(case=case, reference_binding=reference_binding)
        observations.append(captured)
    for case in ("regular", "fresh_size", "replacement", "hardlink", "directory", "missing"):
        if case == "fresh_size":
            data.write_bytes(b"changed actual size\0no final LF")
        if case == "replacement":
            replacement = installer.root / "replacement.data"
            replacement.write_bytes(b"replacement real bytes")
            replacement.replace(data)
        if case == "hardlink":
            os.link(data, installer.root / "native-hardlink.data")
        name = "native-directory" if case == "directory" else "native-missing.data" if case == "missing" else data.name
        arguments = f"-c '{FORMAT}' \"$fixture/{name}\""
        native_arguments = arguments.replace(FORMAT, "%d:%i:81a4:%h:%s:0:0")
        reference, reference_binding = probe(installer, "/usr/bin/stat " + native_arguments)
        actual, captured = probe(installer, "stat " + arguments)
        assert triple(actual) == triple(reference), (case, actual, reference)
        captured.update(case=case, reference_binding=reference_binding)
        observations.append(captured)
    record_property("stat_boundary_vectors", json.dumps(observations, sort_keys=True))


def test_current_stat_native_symlink_identity(installer, record_property):
    installer.shell_fixture()
    data = installer.root / "native-control.data"
    data.write_bytes(b"actual link target\n")
    link = installer.root / "native-symlink.data"
    try:
        os.symlink(data, link)
    except OSError as error:
        record_property("native_symlink_unavailable", repr(error))
        raise
    reference, binding = probe(installer,
        "/usr/bin/stat -c '%d:%i:81a4:%h:%s:0:0' \"$fixture/native-symlink.data\"")
    actual, captured = probe(installer,
        f"stat -c '{FORMAT}' \"$fixture/native-symlink.data\"")
    captured["reference_binding"] = binding
    record_property("actual_native_symlink_contract", json.dumps(captured, sort_keys=True))
    assert triple(actual) == triple(reference), (actual, reference)


def test_current_existing_wrong_mode_hook_reaches_short_refusal(installer, record_property):
    installer.shell_fixture()
    target = installer.root / "system/lib64/libx2dii_menu.so"
    target.write_bytes(b"short refusal hook fixture only\n")
    tree = ast.parse(Path(cleanup.__file__).read_text())
    hook = next(node.value for node in ast.walk(tree) if isinstance(node, ast.Constant)
        and isinstance(node.value, str) and node.value.startswith("saved_stat=$(declare -f stat);"))
    command = (f"identity=$(stat -c '{FORMAT}' \"/system/lib64/libx2dii_menu.so\")\n"
        'printf \'%s\\n\' "$identity"\ncase "$identity" in *:81a4:*) exit 0;; *) exit 47;; esac')
    native_command = command.replace("identity=$(stat ", "identity=$(/usr/bin/stat ").replace(FORMAT, "%d:%i:8180:%h:%s:0:0")
    native, binding = probe(installer, native_command)
    actual, captured = probe(installer, command, hook=hook)
    captured.update(reference_binding=binding, existing_hook_sha256=peer.sha(hook.encode()),
        full_cleanup_worker_executed=False)
    record_property("short_wrong_mode_refusal", json.dumps(captured, sort_keys=True))
    assert triple(actual) == triple(native) and actual.returncode == 47
    assert b":8180:" in actual.stdout and not (installer.root / "cleanup-operations").exists()

