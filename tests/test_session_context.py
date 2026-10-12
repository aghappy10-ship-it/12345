"""Host-only session-data contract; no camera or authorization is exercised."""
import pytest
import hashlib
from pathlib import Path
import subprocess

from tools import session_context as session


INSTALL = {
    "kind": "install", "observed_epoch": 1791040000,
    "boot_id": "11111111-2222-3333-4444-555555555555", "session_nonce": "b" * 32,
    "mount_device": "/dev/block/current-attested-slot", "mount_filesystem": "ext4",
    "mount_options": "ro,seclabel,relatime", "mount_namespace": "mnt:[4026531840]",
    "init_mount_namespace": "mnt:[4026531840]", "observer_pid": 100,
    "observer_start_ticks": "12345", "observer_exe_target": "/system/bin/adbd",
    "observer_exe_sha256": "a" * 64, "observer_domain": "u:r:su:s0",
    "observer_mount_namespace": "mnt:[4026531840]", "active_slot": "slot_2",
    "official_slot": "slot_1", "slot1_active": "0", "slot1_bootable": "1",
    "slot1_successful": "1", "slot2_active": "1", "slot2_bootable": "1",
    "slot2_successful": "1", "rc_label": "u:object_r:system_file:s0",
    "library_label": "u:object_r:system_file:s0", "bootstrap_label": "u:object_r:system_file:s0",
    "model_label": "u:object_r:system_file:s0", "page_label": "u:object_r:system_file:s0",
}
INSTALL_BYTES = b"""schema=x2dii-session-context-v1
kind=install
observed_epoch=1791040000
boot_id=11111111-2222-3333-4444-555555555555
session_nonce=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
mount_device=/dev/block/current-attested-slot
mount_filesystem=ext4
mount_options=ro,seclabel,relatime
mount_namespace=mnt:[4026531840]
init_mount_namespace=mnt:[4026531840]
observer_pid=100
observer_start_ticks=12345
observer_exe_target=/system/bin/adbd
observer_exe_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
observer_domain=u:r:su:s0
observer_mount_namespace=mnt:[4026531840]
active_slot=slot_2
official_slot=slot_1
slot1_active=0
slot1_bootable=1
slot1_successful=1
slot2_active=1
slot2_bootable=1
slot2_successful=1
rc_label=u:object_r:system_file:s0
library_label=u:object_r:system_file:s0
bootstrap_label=u:object_r:system_file:s0
model_label=u:object_r:system_file:s0
page_label=u:object_r:system_file:s0
"""


def test_exact_install_data_is_canonical_and_round_trips_without_authority():
    before = dict(INSTALL)
    assert session.encode_session(INSTALL) == INSTALL_BYTES
    assert session.decode_session(INSTALL_BYTES) == INSTALL
    assert INSTALL == before
    assert b"approved" not in INSTALL_BYTES and b"PASS" not in INSTALL_BYTES


@pytest.mark.parametrize("raw", [
    b"", INSTALL_BYTES[:-1], INSTALL_BYTES + b"\n", INSTALL_BYTES + b"extra=1\n",
    INSTALL_BYTES.replace(b"kind=install\n", b"kind=install\nkind=install\n"),
    INSTALL_BYTES.replace(b"kind=install\n", b""),
    INSTALL_BYTES.replace(b"kind=install\nobserved_epoch=1791040000\n",
                          b"observed_epoch=1791040000\nkind=install\n"),
    INSTALL_BYTES.replace(b"observer_pid=100", b"observer_pid=0100"),
    INSTALL_BYTES.replace(b"observer_pid=100", b"observer_pid=+100"),
    INSTALL_BYTES.replace(b"kind=install", b"kind=inst\x00all"),
    INSTALL_BYTES.replace(b"kind=install", b"kind=inst\xffall"),
    INSTALL_BYTES.replace(b"\n", b"\r\n"), INSTALL_BYTES + b"x" * 16385,
    bytearray(INSTALL_BYTES), INSTALL_BYTES.decode("ascii"),
], ids=["empty", "no-final-newline", "blank-tail", "extra-field", "duplicate-field",
        "missing-field", "reordered", "leading-zero", "plus-integer", "nul", "non-ascii",
        "crlf", "oversized", "bytearray", "text-not-bytes"])
def test_decode_rejects_noncanonical_or_incomplete_bytes(raw):
    with pytest.raises(session.SessionContextError):
        session.decode_session(raw)


@pytest.mark.parametrize("change", [
    {"observed_epoch": True}, {"observed_epoch": "1791040000"},
    {"observer_pid": False}, {"session_nonce": 1}, {"approved": True},
])
def test_encode_rejects_wrong_types_or_extra_authority_fields(change):
    with pytest.raises(session.SessionContextError):
        session.encode_session({**INSTALL, **change})


def test_encode_rejects_a_missing_required_field():
    values = dict(INSTALL)
    del values["boot_id"]
    with pytest.raises(session.SessionContextError):
        session.encode_session(values)


def recovery(present=False):
    values = {**INSTALL, "kind": "recovery", "recovery_nonce": "b" * 32,
              "gui_state": "absent", "gui_service_state": "stopped", "gui_pid": "-",
              "gui_start_ticks": "-", "gui_exe_target": "-", "gui_exe_sha256": "-",
              "gui_domain": "-", "gui_mount_namespace": "-",
              "backup_owner_label": "u:object_r:system_file:s0",
              "present_library": "1", "present_bootstrap": "0", "present_model": "1",
              "present_page": "1", "rc_sha256": "c" * 64}
    if present:
        values.update(gui_state="present", gui_service_state="running", gui_pid=234,
                      gui_start_ticks="67890", gui_exe_target="/system/bin/camera-gui",
                      gui_exe_sha256="d" * 64, gui_domain="u:r:hbl_camera_service:s0",
                      gui_mount_namespace="mnt:[4026531840]")
    return values


def test_recovery_has_a_fixed_tail_and_no_invented_absent_gui_identity():
    raw = session.encode_session(recovery())
    assert raw.endswith(b"""recovery_nonce=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
gui_state=absent
gui_service_state=stopped
gui_pid=-
gui_start_ticks=-
gui_exe_target=-
gui_exe_sha256=-
gui_domain=-
gui_mount_namespace=-
backup_owner_label=u:object_r:system_file:s0
present_library=1
present_bootstrap=0
present_model=1
present_page=1
rc_sha256=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
""")
    assert session.decode_session(raw) == recovery()
    assert session.decode_session(session.encode_session(recovery(True))) == recovery(True)


@pytest.mark.parametrize("change", [
    {"kind": "command"}, {"observed_epoch": 0}, {"observed_epoch": 2147483048},
    {"boot_id": "11111111x2222-3333-4444-555555555555"}, {"session_nonce": "B" * 32},
    {"mount_device": "/dev/block/../other"}, {"mount_device": "/dev/block//name"},
    {"mount_device": "/dev/block/name;touch-owned"}, {"mount_filesystem": "f2fs"},
    {"mount_options": "rw,seclabel"}, {"mount_options": "ro,seclabel,rw"},
    {"mount_options": "ro,,seclabel"}, {"mount_options": "ro," + "x" * 254},
    {"mount_namespace": "mnt:[04026531840]"}, {"init_mount_namespace": "mnt:[9]"},
    {"observer_mount_namespace": "mnt:[9]"}, {"observer_pid": 1}, {"observer_pid": 2147483648},
    {"observer_start_ticks": "0"}, {"observer_start_ticks": "9" * 21},
    {"observer_exe_target": "/system/bin/../sh"}, {"observer_exe_target": "/system/bin/sh/x"},
    {"observer_exe_sha256": "A" * 64}, {"observer_domain": "$(touch owned)"},
    {"active_slot": "slot_1"}, {"official_slot": "slot_2"}, {"slot1_active": "1"},
    {"slot2_bootable": "0"}, {"slot2_successful": "01"},
    {"rc_label": "u:object_r:system_file:s0;touch-owned"}, {"page_label": "u:r:su:s0"},
])
def test_host_rejects_invalid_field_values_and_inconsistent_observations(change, tmp_path):
    with pytest.raises(session.SessionContextError):
        session.encode_session({**INSTALL, **change})
    result, _ = shell_read(tmp_path, changed_bytes(INSTALL_BYTES, change))
    assert result.returncode == 42, (change, result.stdout, result.stderr)


@pytest.mark.parametrize("change", [
    {"recovery_nonce": "a" * 32}, {"gui_state": "unknown"}, {"gui_service_state": "crashed"},
    {"gui_pid": 234}, {"gui_start_ticks": "1"}, {"gui_exe_target": "/system/bin/camera-gui"},
    {"gui_exe_sha256": "d" * 64}, {"gui_domain": "u:r:su:s0"},
    {"gui_mount_namespace": "mnt:[4026531840]"}, {"present_library": True},
    {"present_page": "2"}, {"rc_sha256": ""}, {"backup_owner_label": "-"},
])
def test_host_rejects_recovery_nonce_drift_and_ambiguous_absent_process(change, tmp_path):
    with pytest.raises(session.SessionContextError):
        session.encode_session({**recovery(), **change})
    result, _ = shell_read(tmp_path, changed_bytes(session.encode_session(recovery()), change))
    assert result.returncode == 42, (change, result.stdout, result.stderr)


@pytest.mark.parametrize("change", [
    {"gui_pid": "-"}, {"gui_pid": True}, {"gui_exe_target": "/system/bin/sh"},
    {"gui_mount_namespace": "mnt:[9]"},
])
def test_present_gui_requires_its_actual_supported_process_identity(change, tmp_path):
    with pytest.raises(session.SessionContextError):
        session.encode_session({**recovery(True), **change})
    result, _ = shell_read(tmp_path, changed_bytes(session.encode_session(recovery(True)), change))
    assert result.returncode == 42, (change, result.stdout, result.stderr)


SH = Path("C:/Program Files/Git/bin/sh.exe")


def changed_bytes(raw, change):
    lines = raw.decode("ascii").splitlines()
    for index, line in enumerate(lines):
        key = line.split("=", 1)[0]
        if key in change:
            lines[index] = key + "=" + str(change[key])
    return ("\n".join(lines) + "\n").encode("ascii")


def shell_read(tmp_path, raw=INSTALL_BYTES, *, expected_sha=None, before="", after=None):
    data = tmp_path / "session.ctx"
    data.write_bytes(raw)
    posix = subprocess.run([str(SH), "-c", 'cygpath -u "$1"', "path", str(data)],
                           capture_output=True, text=True, check=True).stdout.strip()
    tail = after or '''
x2dii_load_session "$1" "$2" || exit 42
printf '%s|%s|%s|%s|%s\\n' "$X2DII_SESSION_VALID" "$X2DII_SESSION_KIND" "$X2DII_SESSION_OBSERVED_EPOCH" "$X2DII_SESSION_OBSERVER_PID" "$X2DII_SESSION_RC_LABEL"
'''
    # Windows cannot represent camera root ownership or Unix permission bits.
    # Only that external metadata result is adapted; identity, links, size,
    # actual file reads and every digest still use real host tools/files.
    metadata_adapter = '''
test_host_stat() {
 if [ "$#" = 3 ] && [ "$1" = -c ] && [ "$2" = '%u:%g:%a' ]; then
  if [ -d "$3" ]; then printf '%s\\n' "${test_parent_metadata-0:0:700}"
  else printf '%s\\n' "${test_file_metadata-0:0:600}"; fi
 else command stat "$@"; fi
}
stat() { test_host_stat "$@"; }
'''
    script = "set -eu\n" + session.shell_parser() + "\n" + metadata_adapter + "\n" + before + "\n" + tail
    # Git's Windows -c argument truncates this generated program; feed the
    # identical source on stdin, leaving only the two data arguments in argv.
    result = subprocess.run([str(SH), "-s", "--", posix,
                             hashlib.sha256(raw).hexdigest() if expected_sha is None else expected_sha],
                            input=script, capture_output=True, text=True, cwd=tmp_path, timeout=15)
    return result, data


def test_fixed_shell_parser_reads_real_hash_bound_file_as_data(tmp_path):
    code = session.shell_parser()
    result, data = shell_read(tmp_path)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "1|install|1791040000|100|u:object_r:system_file:s0\n"
    assert data.read_bytes() == INSTALL_BYTES
    changed = session.encode_session({**INSTALL, "observed_epoch": 1791040100, "session_nonce": "a" * 32})
    second, _ = shell_read(tmp_path, changed)
    assert second.returncode == 0, second.stderr
    assert second.stdout.startswith("1|install|1791040100|100|")
    assert session.shell_parser() == code


@pytest.mark.parametrize("present", [False, True], ids=["absent", "present"])
def test_shell_publishes_complete_recovery_identity_without_inventing_a_process(tmp_path, present):
    values = recovery(present)
    result, data = shell_read(tmp_path, session.encode_session(values), after='''
x2dii_load_session "$1" "$2" || exit 42
printf '%s|%s|%s|%s|%s|%s|%s|%s|%s\\n' "$X2DII_SESSION_VALID" "$X2DII_SESSION_KIND" "$X2DII_SESSION_GUI_STATE" "$X2DII_SESSION_GUI_PID" "$X2DII_SESSION_GUI_EXE_TARGET" "$X2DII_SESSION_RECOVERY_NONCE" "$X2DII_SESSION_SESSION_NONCE" "$X2DII_SESSION_PRESENT_BOOTSTRAP" "$X2DII_SESSION_RC_SHA256"
''')
    assert result.returncode == 0, result.stderr
    identity = "present|234|/system/bin/camera-gui" if present else "absent|-|-"
    assert result.stdout == "1|recovery|" + identity + "|" + "b" * 32 + "|" + "b" * 32 + "|0|" + "c" * 64 + "\n"
    assert data.read_bytes() == session.encode_session(values)


@pytest.mark.parametrize("raw", [
    b"", INSTALL_BYTES[:-1], INSTALL_BYTES + b"\n", INSTALL_BYTES + b"extra=1\n",
    INSTALL_BYTES + b"partial-tail", INSTALL_BYTES + b"\x00", INSTALL_BYTES + b"\x00\n",
    INSTALL_BYTES.replace(b"kind=install\n", b"kind=install\nkind=install\n"),
    INSTALL_BYTES.replace(b"kind=install\n", b""),
    INSTALL_BYTES.replace(b"kind=install\nobserved_epoch=1791040000\n",
                          b"observed_epoch=1791040000\nkind=install\n"),
    INSTALL_BYTES.replace(b"kind=install", b"kind=inst\x00all"),
    INSTALL_BYTES.replace(b"kind=install", b"kind=inst\xffall"),
    INSTALL_BYTES.replace(b"kind=install", b"kind=inst\tall"),
    INSTALL_BYTES.replace(b"kind=install", b"kind=install "),
    INSTALL_BYTES.replace(b"kind=install", b"kind=install=install"),
    INSTALL_BYTES.replace(b"schema=x2dii-session-context-v1", b"schema"),
    INSTALL_BYTES.replace(b"kind=install", b"kind=" + b"a" * 513),
    INSTALL_BYTES.replace(b"observer_pid=100", b"observer_pid=0100"),
    INSTALL_BYTES.replace(b"observer_pid=100", b"observer_pid=+100"),
    INSTALL_BYTES.replace(b"observer_pid=100", b"observer_pid= 100"),
    INSTALL_BYTES.replace(b"observer_pid=100", b"observer_pid=100 "),
    INSTALL_BYTES.replace(b"observer_pid=100", b"observer_pid=\x00100"),
    INSTALL_BYTES.replace(b"observer_pid=100", b"observer_pid=1\x0000"),
    INSTALL_BYTES.replace(b"observer_pid=100", b"observer_pid=100\x00"),
    INSTALL_BYTES.replace(b"\n", b"\r\n"), INSTALL_BYTES + b"x" * 16385,
], ids=["empty", "no-final-lf", "blank-tail", "extra-field", "partial-tail", "nul-tail",
        "nul-line", "duplicate", "missing", "reordered", "nul-scalar", "non-ascii",
        "tab", "space", "extra-equal", "missing-equal", "long-line", "leading-zero",
        "plus-integer", "space-prefix-integer", "space-suffix-integer", "nul-prefix-integer",
        "nul-mid-integer", "nul-suffix-integer", "crlf", "oversized"])
def test_shell_rejects_noncanonical_framing_even_with_its_correct_raw_hash(tmp_path, raw):
    with pytest.raises(session.SessionContextError):
        session.decode_session(raw)
    result, data = shell_read(tmp_path, raw)
    assert result.returncode == 42, (result.stdout, result.stderr)
    assert data.read_bytes() == raw


@pytest.mark.parametrize("digest", ["", "a" * 64, "A" * 64, "0" * 63, "0" * 65, "$(touch owned)"])
def test_shell_rejects_missing_malformed_or_unbound_digest(tmp_path, digest):
    result, data = shell_read(tmp_path, expected_sha=digest)
    assert result.returncode == 42, (result.stdout, result.stderr)
    assert sorted(p.name for p in tmp_path.iterdir()) == [data.name]


@pytest.mark.parametrize("arguments", ["", '"$1"', '"$1" "$2" extra'])
def test_shell_requires_exactly_path_and_digest_arguments(tmp_path, arguments):
    result, _ = shell_read(tmp_path, after="x2dii_load_session " + arguments + " || exit 42\n")
    assert result.returncode == 42, result.stderr


@pytest.mark.parametrize("argument", [
    '"${1%/*}"', '"$1.missing"', '"session.ctx"', '"${1%/*}/./session.ctx"',
    '"${1%/*}/../session.ctx"', '"${1%/*}//session.ctx"', '"$1/"', '"$1/.."',
    '"$1/."', '"$1;touch-owned"', '""',
])
def test_shell_rejects_missing_nonregular_and_noncanonical_paths(tmp_path, argument):
    result, data = shell_read(tmp_path, after="x2dii_load_session " + argument + ' "$2" || exit 42\n')
    assert result.returncode == 42, result.stderr
    assert data.read_bytes() == INSTALL_BYTES


@pytest.mark.parametrize("change", [
    {"observed_epoch": 1, "observer_pid": 2},
    {"observed_epoch": 2147483047, "observer_pid": 2147483647},
    {"observed_epoch": 2000000008, "observer_pid": 2000000009},
    {"observer_start_ticks": "9" * 20},
    {"mount_namespace": "mnt:[" + "9" * 20 + "]", "init_mount_namespace": "mnt:[" + "9" * 20 + "]",
     "observer_mount_namespace": "mnt:[" + "9" * 20 + "]"},
    {"observer_exe_target": "/system/xbin/" + "A" * 100},
    {"observer_domain": "u:r:" + "a" * 96 + ":s0", "rc_label": "u:object_r:" + "b" * 96 + ":s0"},
    {"mount_options": "ro," + "x" * 253, "mount_device": "/dev/block/" + "A" * 189},
    {"active_slot": "slot_1", "official_slot": "slot_2", "slot1_active": "1", "slot2_active": "0"},
])
def test_host_and_shell_accept_valid_scalar_boundaries(tmp_path, change):
    values = {**INSTALL, **change}
    raw = session.encode_session(values)
    assert session.decode_session(raw) == values
    result, _ = shell_read(tmp_path, raw)
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("1|install|")


@pytest.mark.parametrize("tool_failure", [
    "stat() { return 23; }",
    "sha256sum() { return 24; }",
    'sha256sum() { [ "$#" != 0 ] || return 25; command sha256sum "$@"; }',
    '''sha256sum() {
 if [ "$#" = 0 ]; then command sha256sum; return; fi
 [ ! -f hash-observed ] || return 26
 printf seen > hash-observed
 command sha256sum "$@"
}''',
    '''stat() {
 if [ "$2" = '%d:%i:%f:%h:%s:%u:%g' ]; then
  [ ! -f identity-observed ] || return 27
  printf seen > identity-observed
 fi
 test_host_stat "$@"
}''',
], ids=["stat", "sha", "canonical-sha", "final-sha", "final-stat"])
def test_shell_fails_closed_on_external_metadata_or_hash_tool_failure(tmp_path, tool_failure):
    result, data = shell_read(tmp_path, before=tool_failure)
    assert result.returncode == 42, (result.stdout, result.stderr)
    assert data.read_bytes() == INSTALL_BYTES


def test_shell_rejects_a_same_content_inode_replacement_after_hashing(tmp_path):
    result, data = shell_read(tmp_path, before='''
sha256sum() {
 command sha256sum "$@" || return
 if [ "$#" != 0 ] && [ ! -f replaced ]; then
  command cp "$1" "$1.replacement" || return
  command mv "$1.replacement" "$1" || return
  printf yes > replaced
 fi
}
''')
    assert result.returncode == 42, (result.stdout, result.stderr)
    assert data.read_bytes() == INSTALL_BYTES
    assert (tmp_path / "replaced").read_text() == "yes"


def test_shell_rejects_a_same_length_file_mutation_after_parsing(tmp_path):
    result, data = shell_read(tmp_path, before='''
test_session_path=$1
sha256sum() {
 command sha256sum "$@" || return
 if [ "$#" = 0 ]; then
  command sed 's/observer_pid=100/observer_pid=101/' "$test_session_path" > changed.ctx || return
  command cat changed.ctx > "$test_session_path" || return
 fi
}
''')
    assert result.returncode == 42, (result.stdout, result.stderr)
    assert data.read_bytes() == INSTALL_BYTES.replace(b"observer_pid=100", b"observer_pid=101")


@pytest.mark.parametrize("failure", [
    'x2dii_load_session "$1" ""',
    'x2dii_load_session "$1" "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"',
    'stat() { return 23; }; x2dii_load_session "$1" "$2"',
    'sha256sum() { return 24; }; x2dii_load_session "$1" "$2"',
    '''printf 'invalid\\n' > "$1"
test_digest=$(sha256sum "$1")
x2dii_load_session "$1" "${test_digest%% *}"''',
], ids=["argument", "digest", "metadata", "hash-tool", "parse"])
def test_failed_reload_clears_every_public_install_and_recovery_value(tmp_path, failure):
    # Expected public names come from the independent complete schema fixture.
    published = " ".join('"${X2DII_SESSION_' + key.upper() + '+set}"' for key in recovery(True))
    after = '''
x2dii_load_session "$1" "$2" || exit 80
[ "$X2DII_SESSION_VALID" = 1 ] || exit 81
if ''' + failure + '''; then exit 82; fi
printf '%s\\n' "$X2DII_SESSION_VALID"
printf '%s' ''' + published + "\n"
    result, _ = shell_read(tmp_path, session.encode_session(recovery(True)), after=after)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "0\n"


def test_successful_install_reload_also_clears_previous_recovery_tail(tmp_path):
    # Start with a recovery context, then supply a separate valid install context.
    (tmp_path / "install.ctx").write_bytes(INSTALL_BYTES)
    recovery_only = set(recovery(True)) - set(INSTALL)
    absent = " ".join('"${X2DII_SESSION_' + key.upper() + '+set}"' for key in sorted(recovery_only))
    after = '''
x2dii_load_session "$1" "$2" || exit 80
test_install_path=${1%/*}/install.ctx
test_digest=$(sha256sum "$test_install_path")
x2dii_load_session "$test_install_path" "${test_digest%% *}" || exit 81
printf '%s|%s\\n' "$X2DII_SESSION_VALID" "$X2DII_SESSION_KIND"
printf '%s' ''' + absent + "\n"
    result, _ = shell_read(tmp_path, session.encode_session(recovery(True)), after=after)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "1|install\n"


@pytest.mark.parametrize("payload", ["$(touch owned)", "`touch owned`", "x;touch owned", "x\nextra=value"])
def test_invalid_data_never_executes_or_reaches_callers_write_branch(tmp_path, payload):
    raw = changed_bytes(INSTALL_BYTES, {"observer_domain": payload})
    forbidden = ("mkdir", "touch", "mount", "umount", "stop", "start", "setenforce", "cp", "mv", "rm", "dd")
    guard = "\n".join(name + '() { printf "forbidden:' + name + '\\n"; exit 90; }' for name in forbidden)
    result, data = shell_read(tmp_path, raw, before=guard, after='''
if x2dii_load_session "$1" "$2"; then
 printf 'write-branch-reached\\n'
 exit 91
fi
printf '%s\\n' "$X2DII_SESSION_VALID"
''')
    assert result.returncode == 0, result.stderr
    assert result.stdout == "0\n"
    assert data.read_bytes() == raw
    assert sorted(p.name for p in tmp_path.iterdir()) == ["session.ctx"]


def test_shell_rejects_real_hardlinked_file(tmp_path):
    (tmp_path / "other.ctx").write_bytes(INSTALL_BYTES)
    (tmp_path / "session.ctx").hardlink_to(tmp_path / "other.ctx")
    result, data = shell_read(tmp_path)
    assert result.returncode == 42, result.stderr
    assert data.read_bytes() == (tmp_path / "other.ctx").read_bytes() == INSTALL_BYTES


@pytest.mark.parametrize("ancestor", [False, True], ids=["file", "ancestor"])
def test_shell_rejects_real_symbolic_link_path(tmp_path, ancestor):
    actual = tmp_path / "actual"
    actual.mkdir()
    (actual / "session.ctx").write_bytes(INSTALL_BYTES)
    try:
        if ancestor:
            (tmp_path / "linked").symlink_to(actual, target_is_directory=True)
            path = tmp_path / "linked"
        else:
            (tmp_path / "session.ctx").symlink_to(actual / "session.ctx")
            path = tmp_path
    except OSError as error:
        if getattr(error, "winerror", None) != 1314:
            raise
        pytest.skip("Host cannot create real symlink; target link gate remains PENDING: " + str(error))
    result, _ = shell_read(path)
    assert result.returncode == 42, result.stderr
    assert (actual / "session.ctx").read_bytes() == INSTALL_BYTES


@pytest.mark.parametrize("metadata", ["1000:0:600", "0:1000:600", "0:0:644", "0:0:660", "0:0:400", "0:0:4600", ""])
def test_shell_requires_root_owned_private_regular_data_file(tmp_path, metadata):
    result, data = shell_read(tmp_path, before="test_file_metadata='" + metadata + "'")
    assert result.returncode == 42, (result.stdout, result.stderr)
    assert data.read_bytes() == INSTALL_BYTES


@pytest.mark.parametrize("metadata", ["1000:0:700", "0:1000:700", "0:0:755", "0:0:770", "0:0:600", "0:0:1700", ""])
def test_shell_requires_root_owned_private_direct_parent(tmp_path, metadata):
    result, data = shell_read(tmp_path, before="test_parent_metadata='" + metadata + "'")
    assert result.returncode == 42, (result.stdout, result.stderr)
    assert data.read_bytes() == INSTALL_BYTES


@pytest.mark.parametrize("target", ["file", "parent"])
@pytest.mark.parametrize("stage", ["initial-hash", "canonical-hash", "final-hash"])
def test_shell_rejects_file_or_parent_permission_drift_during_load(tmp_path, target, stage):
    after_digest = {
        "initial-hash": '[ "$#" != 0 ]',
        "canonical-hash": '[ "$#" = 0 ]',
        "final-hash": '[ "$#" != 0 ] && [ -f canonical-seen ]',
    }[stage]
    wrong_target = '[ -d "$3" ]' if target == "parent" else '[ ! -d "$3" ]'
    wrong_mode = "0:0:755" if target == "parent" else "0:0:644"
    before = '''
stat() {
 if [ "$2" = '%u:%g:%a' ] && [ -f metadata-changed ] && ''' + wrong_target + '''; then
  printf '%s\\n' ''' + wrong_mode + '''
 else test_host_stat "$@"; fi
}
sha256sum() {
 command sha256sum "$@" || return
 if ''' + after_digest + '''; then printf changed > metadata-changed; fi
 if [ "$#" = 0 ]; then printf seen > canonical-seen; fi
}
'''
    result, data = shell_read(tmp_path, before=before)
    assert result.returncode == 42, (result.stdout, result.stderr)
    assert (tmp_path / "metadata-changed").read_text() == "changed"
    assert data.read_bytes() == INSTALL_BYTES


def test_successful_parser_does_not_execute_mutation_commands_or_write_files(tmp_path):
    forbidden = ("mkdir", "touch", "mount", "umount", "stop", "start", "setenforce", "cp", "mv", "rm", "dd")
    guard = "\n".join(name + '() { printf "forbidden:' + name + '\\n"; exit 90; }' for name in forbidden)
    result, data = shell_read(tmp_path, before=guard)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "1|install|1791040000|100|u:object_r:system_file:s0\n"
    assert data.read_bytes() == INSTALL_BYTES
    assert sorted(p.name for p in tmp_path.iterdir()) == ["session.ctx"]
