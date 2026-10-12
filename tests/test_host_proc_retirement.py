"""Real MSYS fixture exits must not retain departed /proc/PID directories.

This tests only the existing host OS adapter, never the Android kernel or a
camera. The generated five lifecycle programs remain byte-for-byte unchanged.
"""
import subprocess

import pytest

from tests.test_release_lifecycle import installer
from tests.test_peer_install import SH
from tests.test_menu_lifecycle_transport import background_fixture
from tools import prepare_peer_install as peer


@pytest.mark.parametrize("query", ("namespace", "file-hash", "stdin-hash"))
def test_unrelated_host_queries_do_not_consume_gui_pid_file(installer, query):
    # Reuse the installed OS adapter, not the production lifecycle body. An
    # unrelated query must not leak an error from reading GUI-only state.
    hook = r'''
cat() {
 if [ "$#" = 1 ] && [ "$1" = "$fixture/test-child-pid" ]; then
  builtin printf '%s\n' UNRELATED_GUI_PID_READ >&2
  return 77
 fi
 /usr/bin/cat "$@"
}
'''
    raw, fixed, programs, _ = background_fixture(installer, extra_hook=hook)
    (installer.root / "test-child-pid").write_bytes(b"234\n")
    data = b"unrelated\x00query\r\n"
    (installer.root / "query-opaque.data").write_bytes(data)
    translated = installer.root / ".host-lifecycle-q.sh"
    header = "#!" + installer.posix + "/system/bin/sh\n"
    source = translated.read_text(encoding="ascii")
    assert source.count(header) == 1
    queries = {
        "namespace": ('readlink "$fixture/proc/self/ns/mnt"\n', b"mnt:[4026531840]\n"),
        "file-hash": ('sha256sum "$fixture/query-opaque.data"\n',
                      (peer.sha(data) + " *" + installer.posix + "/query-opaque.data\n").encode()),
        "stdin-hash": ("printf 'unrelated\\000query\\r\\n' | sha256sum\n",
                       (peer.sha(data) + " *-\n").encode()),
    }
    body, expected = queries[query]
    translated.write_text(source.split(header, 1)[0] + body, encoding="ascii", newline="\n")
    result = subprocess.run([str(SH), installer.posix + "/system/bin/sh",
        installer.posix + fixed["q"], peer.sha(raw)], capture_output=True, timeout=12)
    assert (result.returncode, result.stdout, result.stderr) == (0, expected, b"")
    assert {name: (installer.root / fixed[name].lstrip("/")).read_bytes()
            for name in "lwtqs"} == {name: text.encode("ascii") for name, text in programs.items()}
    assert not (installer.root / "operations").exists()


def test_gui_executable_mapping_still_reads_the_current_pid_and_real_bytes(installer):
    raw, fixed, programs, _ = background_fixture(installer)
    (installer.root / "test-child-pid").write_bytes(b"4242\n")
    proc = installer.root / "proc/4242"
    proc.mkdir()
    old_executable = b"non-gui executable\x00\r\n"
    (proc / "exe").write_bytes(old_executable)
    translated = installer.root / ".host-lifecycle-q.sh"
    header = "#!" + installer.posix + "/system/bin/sh\n"
    source = translated.read_text(encoding="ascii")
    assert source.count(header) == 1
    body = r'''
readlink "$fixture/proc/4242/exe"
sha256sum "$fixture/proc/4242/exe"
printf '4243\n' > "$fixture/test-child-pid"
readlink "$fixture/proc/4243/exe"
sha256sum "$fixture/proc/4242/exe"
'''
    translated.write_text(source.split(header, 1)[0] + body, encoding="ascii", newline="\n")
    result = subprocess.run([str(SH), installer.posix + "/system/bin/sh",
        installer.posix + fixed["q"], peer.sha(raw)], capture_output=True, timeout=12)
    expected = ("/system/bin/camera-gui\n" +
        installer.manifest["candidate"]["gui_sha256"] + "  " + installer.posix + "/system/bin/camera-gui\n" +
        "/system/bin/camera-gui\n" + peer.sha(old_executable) + " *" + installer.posix + "/proc/4242/exe\n").encode()
    assert (result.returncode, result.stdout, result.stderr) == (0, expected, b"")
    assert {name: (installer.root / fixed[name].lstrip("/")).read_bytes()
            for name in "lwtqs"} == {name: text.encode("ascii") for name, text in programs.items()}
    assert not (installer.root / "operations").exists()


@pytest.mark.parametrize("role", ("l", "q", "s"))
@pytest.mark.parametrize("explicit_exit", (False, True))
def test_completed_host_roles_retire_only_their_own_proc_directory(installer, role, explicit_exit):
    raw, fixed, programs, _ = background_fixture(installer)
    proc = installer.root / "proc"
    originals = {path.relative_to(proc): path.read_bytes()
                 for path in proc.rglob("*") if path.is_file()}
    translated = installer.root / (".host-lifecycle-" + role + ".sh")
    header = "#!" + installer.posix + "/system/bin/sh\n"
    source = translated.read_text(encoding="ascii")
    assert source.count(header) == 1
    # Reuse the actual installed OS adapter; end before the production body,
    # so this cannot launch a GUI or provide a successful lifecycle receipt.
    body = "printf '%s\\n' \"$$\"\n"
    if explicit_exit:
        body += "lifecycle_fixture_exit 37\n"
    translated.write_text(source.split(header, 1)[0] + body, encoding="ascii", newline="\n")
    command = [str(SH), installer.posix + "/system/bin/sh",
               installer.posix + fixed[role], peer.sha(raw)]
    for _ in range(3):
        completed = subprocess.run(command, capture_output=True, text=True, timeout=12)
        assert completed.returncode == (37 if explicit_exit else 0), completed.stderr
        assert completed.stderr == ""
        pid = completed.stdout.strip()
        assert pid.isdecimal() and int(pid) > 0
        assert not (proc / pid).exists(), "departed host PID still participates in maps enumeration"
    assert {path.relative_to(proc): path.read_bytes()
            for path in proc.rglob("*") if path.is_file()} == originals
    assert {name: (installer.root / fixed[name].lstrip("/")).read_bytes()
            for name in "lwtqs"} == {name: text.encode("ascii") for name, text in programs.items()}
    assert not (installer.root / "operations").exists()


@pytest.mark.parametrize("explicit_exit", (False, True))
def test_unknown_proc_content_is_retained_and_original_error_is_not_replaced(installer, explicit_exit):
    raw, fixed, _, _ = background_fixture(installer)
    translated = installer.root / ".host-lifecycle-q.sh"
    header = "#!" + installer.posix + "/system/bin/sh\n"
    prefix = translated.read_text(encoding="ascii").split(header, 1)[0]
    body = 'set -eu\nprintf "%s\\n" "$$"\nprintf retained > "$fixture/proc/$$/unknown"\n'
    if explicit_exit:
        body += "lifecycle_fixture_exit 37\n"
    translated.write_text(prefix + body, encoding="ascii", newline="\n")
    completed = subprocess.run([str(SH), installer.posix + "/system/bin/sh",
        installer.posix + fixed["q"], peer.sha(raw)], capture_output=True, text=True, timeout=12)
    assert completed.returncode == (37 if explicit_exit else 92)
    assert "HOST_PROC_RETIREMENT_INCOMPLETE" in completed.stderr
    pid = completed.stdout.strip()
    assert pid.isdecimal()
    assert (installer.root / "proc" / pid / "unknown").read_bytes() == b"retained"


def test_subshell_retirement_does_not_remove_live_parent_snapshot(installer):
    raw, fixed, _, _ = background_fixture(installer)
    translated = installer.root / ".host-lifecycle-q.sh"
    header = "#!" + installer.posix + "/system/bin/sh\n"
    prefix = translated.read_text(encoding="ascii").split(header, 1)[0]
    body = ('set -eu\n(lifecycle_fixture_retire)\n'
            'test -f "$fixture/proc/$$/stat"\ntest -f "$fixture/proc/$$/maps"\n'
            'printf "%s\\n" "$$"\n')
    translated.write_text(prefix + body, encoding="ascii", newline="\n")
    completed = subprocess.run([str(SH), installer.posix + "/system/bin/sh",
        installer.posix + fixed["q"], peer.sha(raw)], capture_output=True, text=True, timeout=12)
    assert completed.returncode == 0 and completed.stderr == "", completed.stderr
    assert not (installer.root / "proc" / completed.stdout.strip()).exists()


@pytest.mark.parametrize("role", ("t", "w"))
@pytest.mark.parametrize("explicit_exit", (False, True))
@pytest.mark.parametrize("remove_error", (False, True))
def test_recovery_roles_keep_original_exit_and_errexit_semantics(
        installer, role, explicit_exit, remove_error):
    raw, fixed, _, _ = background_fixture(installer)
    translated = installer.root / (".host-lifecycle-" + role + ".sh")
    header = "#!" + installer.posix + "/system/bin/sh\n"
    prefix = translated.read_text(encoding="ascii").split(header, 1)[0]
    # These inert bodies exercise the actual OS adapter, not a GUI/recovery
    # program. A directory at stat makes the literal old rm -f fail under -e.
    body = 'set -eu\nprintf "%s\\n" "$$"\n'
    if remove_error:
        body += ('/usr/bin/rm -f "$fixture/proc/$$/stat"\n'
                 '/usr/bin/mkdir "$fixture/proc/$$/stat"\n')
    if explicit_exit:
        body += "lifecycle_fixture_exit 37\n"
    translated.write_text(prefix + body, encoding="ascii", newline="\n")
    completed = subprocess.run([str(SH), installer.posix + "/system/bin/sh",
        installer.posix + fixed[role], peer.sha(raw)],
        capture_output=True, text=True, timeout=12)
    # With set -e the literal old EXIT trap's failing rm also exits 1; it
    # cannot be treated as a successful natural termination.
    expected = 1 if remove_error else (37 if explicit_exit else 0)
    assert completed.returncode == expected, completed.stderr
    assert "HOST_PROC_RETIREMENT_INCOMPLETE" not in completed.stderr
    proc = installer.root / "proc" / completed.stdout.strip()
    assert proc.is_dir() and (proc / "maps").is_file()
    if remove_error:
        assert (proc / "stat").is_dir() and "Is a directory" in completed.stderr
    else:
        assert not (proc / "stat").exists() and completed.stderr == ""
