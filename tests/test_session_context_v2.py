"""Local v2 data parsing, not evidence of sensor application or capture use."""
import pytest

from tools import session_context as session
from test_session_context import INSTALL, INSTALL_BYTES, changed_bytes, recovery, shell_read


V2_SCHEMA = "x2dii-session-context-v2"
TAIL = b"""core_gui_pid=201
core_gui_start_ticks=20001
core_gui_exe_target=/system/bin/camera-gui
core_gui_exe_sha256=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
core_gui_domain=u:r:hbl_camera_service:s0
core_gui_mount_namespace=mnt:[4026531840]
core_gui_bytes=123456
core_service_pid=202
core_service_start_ticks=20002
core_service_exe_target=/system/bin/camera-service
core_service_exe_sha256=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
core_service_domain=u:r:hbl_camera_service:s0
core_service_mount_namespace=mnt:[4026531840]
core_service_bytes=234567
core_capture_pid=203
core_capture_start_ticks=20003
core_capture_exe_target=/system/bin/capture-worker
core_capture_exe_sha256=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
core_capture_domain=u:r:hbl_camera_service:s0
core_capture_mount_namespace=mnt:[4026531840]
core_capture_bytes=345678
core_gui_service_state=running
core_service_service_state=running
core_sensor_sha256=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
core_sensor_bytes=456789
"""
V2_BYTES = INSTALL_BYTES.replace(b"context-v1\n", b"context-v2\n") + TAIL
V2 = {
    **INSTALL,
    "core_gui_pid": 201, "core_gui_start_ticks": "20001",
    "core_gui_exe_target": "/system/bin/camera-gui", "core_gui_exe_sha256": "d" * 64,
    "core_gui_domain": "u:r:hbl_camera_service:s0", "core_gui_mount_namespace": "mnt:[4026531840]",
    "core_gui_bytes": 123456,
    "core_service_pid": 202, "core_service_start_ticks": "20002",
    "core_service_exe_target": "/system/bin/camera-service", "core_service_exe_sha256": "e" * 64,
    "core_service_domain": "u:r:hbl_camera_service:s0", "core_service_mount_namespace": "mnt:[4026531840]",
    "core_service_bytes": 234567,
    "core_capture_pid": 203, "core_capture_start_ticks": "20003",
    "core_capture_exe_target": "/system/bin/capture-worker", "core_capture_exe_sha256": "f" * 64,
    "core_capture_domain": "u:r:hbl_camera_service:s0", "core_capture_mount_namespace": "mnt:[4026531840]",
    "core_capture_bytes": 345678,
    "core_gui_service_state": "running", "core_service_service_state": "running",
    "core_sensor_sha256": "c" * 64, "core_sensor_bytes": 456789,
}


def test_v2_is_explicit_install_only_data_with_exact_order_and_unchanged_v1():
    assert session.SCHEMA == "x2dii-session-context-v1"
    assert session.INSTALL_SCHEMA == V2_SCHEMA
    assert session.INSTALL_RUNTIME_FIELDS == tuple(line.split(b"=", 1)[0].decode() for line in TAIL.splitlines())
    before = dict(V2)
    assert session.encode_session(V2, schema=V2_SCHEMA) == V2_BYTES
    assert session.decode_session(V2_BYTES) == V2
    assert V2 == before
    assert session.encode_session(INSTALL) == INSTALL_BYTES
    assert session.encode_session(INSTALL, schema=session.SCHEMA) == INSTALL_BYTES
    assert session.decode_session(INSTALL_BYTES) == INSTALL
    for present in (False, True):
        values = recovery(present)
        assert session.decode_session(session.encode_session(values)) == values


@pytest.mark.parametrize("values,schema,raw", [
    (V2, V2_SCHEMA, V2_BYTES), (INSTALL, "x2dii-session-context-v1", INSTALL_BYTES),
    (recovery(False), "x2dii-session-context-v1", session.encode_session(recovery(False))),
    (recovery(True), "x2dii-session-context-v1", session.encode_session(recovery(True))),
], ids=["v2-install", "v1-install-compatibility", "v1-recovery-absent", "v1-recovery-present"])
def test_shell_exposes_exact_schema_and_complete_selected_context(tmp_path, values, schema, raw):
    after = 'x2dii_load_session "$1" "$2" || exit 42\n'
    after += 'printf "schema=%s\\n" "$X2DII_SESSION_SCHEMA"\n'
    after += "".join('printf "' + key + '=%s\\n" "$X2DII_SESSION_' + key.upper() + '"\n' for key in values)
    result, data = shell_read(tmp_path, raw, after=after)
    assert result.returncode == 0, result.stderr
    assert result.stdout.encode() == raw
    assert data.read_bytes() == raw


@pytest.mark.parametrize("change", [
    {"core_gui_exe_target": "/system/bin/other-gui"},
    {"core_service_exe_target": "/system/bin/other-service"},
    {"core_gui_mount_namespace": "mnt:[9]"},
    {"core_service_mount_namespace": "mnt:[9]"},
    {"core_capture_mount_namespace": "mnt:[9]"},
    {"core_gui_pid": 202}, {"core_capture_pid": 201}, {"core_capture_pid": 202},
    {"core_gui_pid": 100}, {"core_service_pid": 100}, {"core_capture_pid": 100},
    {"core_capture_exe_target": "/system/bin/camera-gui", "core_capture_exe_sha256": "d" * 64},
    {"core_capture_exe_target": "/system/bin/camera-service", "core_capture_bytes": 234567},
])
@pytest.mark.parametrize("boundary", ["codec", "shell"])
def test_v2_rejects_inconsistent_runtime_identities(tmp_path, change, boundary):
    raw = changed_bytes(V2_BYTES, change)
    if boundary == "codec":
        with pytest.raises(session.SessionContextError):
            session.encode_session({**V2, **change}, schema=V2_SCHEMA)
        with pytest.raises(session.SessionContextError):
            session.decode_session(raw)
    else:
        result, _ = shell_read(tmp_path, raw)
        assert result.returncode == 42, (result.stdout, result.stderr)


PROCESS_FIELDS = ("pid", "start_ticks", "exe_target", "exe_sha256", "domain", "mount_namespace", "bytes")


def alias_process(source, destination):
    fields = PROCESS_FIELDS[:-1] if destination == "observer" else PROCESS_FIELDS
    return {destination + "_" + key: V2[source + "_" + key] for key in fields}


@pytest.mark.parametrize("change", [
    alias_process("core_gui", "observer"), alias_process("core_service", "observer"),
    alias_process("core_capture", "observer"), alias_process("core_gui", "core_capture"),
    alias_process("core_service", "core_capture"),
    {**alias_process("core_gui", "core_capture"), "core_capture_pid": 204,
     "core_capture_start_ticks": "98765", "core_capture_domain": "u:r:another_domain:s0"},
    {**alias_process("core_service", "core_capture"), "core_capture_pid": 204,
     "core_capture_start_ticks": "98765", "core_capture_domain": "u:r:another_domain:s0"},
])
def test_v2_accepts_consistent_same_pid_or_same_executable_observations(tmp_path, change):
    values = {**V2, **change}
    raw = session.encode_session(values, schema=V2_SCHEMA)
    assert session.decode_session(raw) == values
    result, _ = shell_read(tmp_path, raw)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("source,destination", [
    ("core_gui", "observer"), ("core_service", "observer"), ("core_capture", "observer"),
    ("core_gui", "core_capture"), ("core_service", "core_capture"),
])
@pytest.mark.parametrize("field,value", [
    ("start_ticks", "987654"), ("exe_target", "/system/xbin/another-executable"),
    ("exe_sha256", "1" * 64), ("domain", "u:r:another_domain:s0"),
    ("mount_namespace", "mnt:[9]"),
])
def test_every_shared_pid_identity_member_must_agree(tmp_path, source, destination, field, value):
    change = {**alias_process(source, destination), destination + "_" + field: value}
    with pytest.raises(session.SessionContextError):
        session.encode_session({**V2, **change}, schema=V2_SCHEMA)
    raw = changed_bytes(V2_BYTES, change)
    with pytest.raises(session.SessionContextError):
        session.decode_session(raw)
    result, _ = shell_read(tmp_path, raw)
    assert result.returncode == 42, result.stderr


@pytest.mark.parametrize("source", ["core_gui", "core_service"])
@pytest.mark.parametrize("same_pid", [False, True])
@pytest.mark.parametrize("field,value", [("exe_sha256", "1" * 64), ("bytes", 2)])
def test_same_core_executable_binds_both_hash_and_bytes(tmp_path, source, same_pid, field, value):
    change = {**alias_process(source, "core_capture"), "core_capture_" + field: value}
    if not same_pid:
        change["core_capture_pid"] = 204
    with pytest.raises(session.SessionContextError):
        session.encode_session({**V2, **change}, schema=V2_SCHEMA)
    raw = changed_bytes(V2_BYTES, change)
    with pytest.raises(session.SessionContextError):
        session.decode_session(raw)
    result, _ = shell_read(tmp_path, raw)
    assert result.returncode == 42, result.stderr


BAD_PROCESS_VALUES = [
    ("pid", "-"), ("pid", 0), ("pid", 1), ("pid", 2147483648), ("pid", True),
    ("start_ticks", "0"), ("start_ticks", "01"), ("start_ticks", "9" * 21),
    ("exe_target", "/system/bin/../sh"), ("exe_target", "/system/bin/a/b"),
    ("exe_sha256", "A" * 64), ("exe_sha256", "a" * 63),
    ("domain", "u:r:su:s0;touch-owned"), ("domain", "u:object_r:system_file:s0"),
    ("mount_namespace", "mnt:[01]"), ("mount_namespace", "mnt:[" + "9" * 21 + "]"),
    ("bytes", 0), ("bytes", -1), ("bytes", 2147483648), ("bytes", True), ("bytes", "-"),
]


@pytest.mark.parametrize("prefix", ["core_gui", "core_service", "core_capture"])
@pytest.mark.parametrize("field,value", BAD_PROCESS_VALUES)
def test_v2_requires_present_strictly_typed_bounded_process_scalars(tmp_path, prefix, field, value):
    change = {prefix + "_" + field: value}
    with pytest.raises(session.SessionContextError):
        session.encode_session({**V2, **change}, schema=V2_SCHEMA)
    raw = changed_bytes(V2_BYTES, change)
    with pytest.raises(session.SessionContextError):
        session.decode_session(raw)
    result, _ = shell_read(tmp_path, raw)
    assert result.returncode == 42, result.stderr


@pytest.mark.parametrize("change", [
    {"core_gui_service_state": "absent"}, {"core_service_service_state": "unknown"},
    {"core_sensor_sha256": "A" * 64}, {"core_sensor_sha256": "0" * 63},
    {"core_sensor_bytes": 0}, {"core_sensor_bytes": -1}, {"core_sensor_bytes": 2147483648},
    {"core_sensor_bytes": True}, {"core_sensor_bytes": "-"},
])
def test_v2_sensor_and_service_scalars_are_bounded_data_not_claims(tmp_path, change):
    with pytest.raises(session.SessionContextError):
        session.encode_session({**V2, **change}, schema=V2_SCHEMA)
    raw = changed_bytes(V2_BYTES, change)
    with pytest.raises(session.SessionContextError):
        session.decode_session(raw)
    result, _ = shell_read(tmp_path, raw)
    assert result.returncode == 42, result.stderr


@pytest.mark.parametrize("value", [1, 2000000008, 2147483647])
def test_v2_accepts_positive_byte_boundaries_and_existing_scalar_limits(tmp_path, value):
    change = {key: value for key in ("core_gui_bytes", "core_service_bytes", "core_capture_bytes", "core_sensor_bytes")}
    change.update(core_gui_pid=2, core_service_pid=2147483647, core_capture_pid=2000000009,
                  core_gui_start_ticks="9" * 20, core_capture_exe_target="/system/xbin/" + "A" * 100,
                  core_capture_domain="u:r:" + "a" * 96 + ":s0",
                  core_gui_service_state="stopped", core_service_service_state="restarting")
    values = {**V2, **change}
    raw = session.encode_session(values, schema=V2_SCHEMA)
    assert session.decode_session(raw) == values
    result, _ = shell_read(tmp_path, raw)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("field", ["core_gui_pid", "core_service_pid", "core_capture_pid",
                                    "core_gui_bytes", "core_service_bytes", "core_capture_bytes", "core_sensor_bytes"])
@pytest.mark.parametrize("wrong_type", ["123", 123.0, False])
def test_encoder_never_coerces_runtime_integer_types(field, wrong_type):
    with pytest.raises(session.SessionContextError):
        session.encode_session({**V2, field: wrong_type}, schema=V2_SCHEMA)


@pytest.mark.parametrize("values,schema", [
    (V2, "x2dii-session-context-v1"), (INSTALL, V2_SCHEMA),
    (recovery(False), V2_SCHEMA), (recovery(True), V2_SCHEMA),
    ({**V2, "kind": "recovery"}, V2_SCHEMA),
    (V2, "x2dii-session-context-v3"), (V2, ""), (V2, None), (V2, True),
])
def test_encoder_does_not_upgrade_or_guess_a_schema(values, schema):
    with pytest.raises(session.SessionContextError):
        session.encode_session(values, schema=schema)


def test_encoder_requires_explicit_keyword_and_does_not_default_to_v2():
    with pytest.raises(TypeError):
        session.encode_session(V2, V2_SCHEMA)
    with pytest.raises(session.SessionContextError):
        session.encode_session(V2)


@pytest.mark.parametrize("raw", [
    V2_BYTES.replace(b"context-v2", b"context-v3"),
    V2_BYTES.replace(b"context-v2", b"context-v1"),
    INSTALL_BYTES.replace(b"context-v1", b"context-v2"),
    session.encode_session(recovery(False)).replace(b"context-v1", b"context-v2"),
    session.encode_session(recovery(True)).replace(b"context-v1", b"context-v2"),
    V2_BYTES.replace(b"kind=install", b"kind=recovery"),
    V2_BYTES.replace(b"schema=", b"schema =", 1),
    V2_BYTES.replace(b"context-v2", b"context-v2 "),
    V2_BYTES.replace(b"context-v2", b"context-v2\x00"),
    V2_BYTES[:-1], V2_BYTES + b"\n", V2_BYTES + b"extra=1\n", V2_BYTES + b"incomplete",
    V2_BYTES + b"\x00", V2_BYTES + b"\xff\n", V2_BYTES.replace(b"\n", b"\r\n"),
    V2_BYTES.replace(b"core_gui_pid=201", b"core_gui_pid=2\x0001"),
    V2_BYTES.replace(b"core_sensor_bytes=456789", b"core_sensor_bytes=456789\x00"),
    V2_BYTES.replace(b"core_sensor_sha256=", b"core_sensor_sha256=" + b"a" * 513),
    V2_BYTES + b"a" * 16385,
])
def test_python_and_shell_reject_wrong_schema_and_noncanonical_framing(tmp_path, raw):
    with pytest.raises(session.SessionContextError):
        session.decode_session(raw)
    result, data = shell_read(tmp_path, raw)
    assert result.returncode == 42, (result.stdout, result.stderr)
    assert data.read_bytes() == raw


@pytest.mark.parametrize("field", [line.split(b"=", 1)[0].decode() for line in TAIL.splitlines()])
@pytest.mark.parametrize("damage", ["missing", "duplicate", "reordered"])
def test_every_v2_tail_field_is_required_once_in_order(tmp_path, field, damage):
    lines = V2_BYTES.splitlines(keepends=True)
    index = next(i for i, line in enumerate(lines) if line.startswith(field.encode() + b"="))
    if damage == "missing":
        del lines[index]
        values = dict(V2)
        del values[field]
        with pytest.raises(session.SessionContextError):
            session.encode_session(values, schema=V2_SCHEMA)
    elif damage == "duplicate":
        lines.insert(index, lines[index])
    else:
        lines[index - 1], lines[index] = lines[index], lines[index - 1]
    raw = b"".join(lines)
    with pytest.raises(session.SessionContextError):
        session.decode_session(raw)
    result, _ = shell_read(tmp_path, raw)
    assert result.returncode == 42, (result.stdout, result.stderr)


@pytest.mark.parametrize("field", ["core_gui_pid", "core_service_pid", "core_capture_pid",
                                    "core_gui_bytes", "core_service_bytes", "core_capture_bytes", "core_sensor_bytes"])
@pytest.mark.parametrize("value", ["0123", "+123", " 123", "123 ", "123.0", "0x7b"])
def test_runtime_integer_bytes_must_use_canonical_decimal(tmp_path, field, value):
    raw = changed_bytes(V2_BYTES, {field: value})
    with pytest.raises(session.SessionContextError):
        session.decode_session(raw)
    result, _ = shell_read(tmp_path, raw)
    assert result.returncode == 42, (result.stdout, result.stderr)


@pytest.mark.parametrize("field", ["core_gui_domain", "core_service_domain", "core_capture_domain", "core_sensor_sha256"])
@pytest.mark.parametrize("payload", ["$(touch owned)", "`touch owned`", "x;touch owned", "x\nextra=value"])
def test_injected_v2_data_does_not_execute_or_reach_write_branch(tmp_path, field, payload):
    raw = changed_bytes(V2_BYTES, {field: payload})
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


ALL_PUBLIC = tuple(dict.fromkeys(("schema", *V2, *recovery(True))))


@pytest.mark.parametrize("failure", [
    'x2dii_load_session', 'x2dii_load_session "$1" ""',
    'x2dii_load_session "$1" "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"',
    'x2dii_load_session "session.ctx" "$2"',
    'stat() { return 23; }; x2dii_load_session "$1" "$2"',
    'sha256sum() { return 24; }; x2dii_load_session "$1" "$2"',
    'test_file_metadata=0:0:644; x2dii_load_session "$1" "$2"',
    'test_parent_metadata=0:0:755; x2dii_load_session "$1" "$2"',
    'test_bad_path=${1%/*}/invalid.ctx; test_digest=$(sha256sum "$test_bad_path"); '
    'x2dii_load_session "$test_bad_path" "${test_digest%% *}"',
    'sha256sum() { [ "$#" != 0 ] || return 25; command sha256sum "$@"; }; '
    'x2dii_load_session "$1" "$2"',
])
def test_failure_clears_schema_and_all_v1_v2_fields_after_success(tmp_path, failure):
    (tmp_path / "invalid.ctx").write_bytes(V2_BYTES.replace(b"core_capture_pid=203", b"core_capture_pid=201"))
    published = " ".join('"${X2DII_SESSION_' + key.upper() + '+set}"' for key in ALL_PUBLIC)
    old_tail = set(recovery(True)) - set(V2)
    after = 'x2dii_load_session "$1" "$2" || exit 80\n'
    after += 'test "$X2DII_SESSION_VALID" = 1 || exit 81\n'
    after += "".join('X2DII_SESSION_' + key.upper() + '=stale\n' for key in old_tail)
    after += "if " + failure + "; then exit 82; fi\n"
    after += 'printf "%s\\n" "$X2DII_SESSION_VALID"\nprintf "%s" ' + published + "\n"
    result, _ = shell_read(tmp_path, V2_BYTES, after=after)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "0\n"


@pytest.mark.parametrize("next_values,next_raw,next_schema", [
    (INSTALL, INSTALL_BYTES, "x2dii-session-context-v1"),
    (recovery(False), session.encode_session(recovery(False)), "x2dii-session-context-v1"),
    (recovery(True), session.encode_session(recovery(True)), "x2dii-session-context-v1"),
])
def test_v2_to_v1_reload_removes_every_v2_only_field(tmp_path, next_values, next_raw, next_schema):
    (tmp_path / "next.ctx").write_bytes(next_raw)
    absent = " ".join('"${X2DII_SESSION_' + key.upper() + '+set}"' for key in ALL_PUBLIC
                      if key != "schema" and key not in next_values)
    after = '''
x2dii_load_session "$1" "$2" || exit 80
test_next_path=${1%/*}/next.ctx
test_digest=$(sha256sum "$test_next_path")
x2dii_load_session "$test_next_path" "${test_digest%% *}" || exit 81
printf '%s|%s|%s\\n' "$X2DII_SESSION_VALID" "$X2DII_SESSION_SCHEMA" "$X2DII_SESSION_KIND"
printf '%s' ''' + absent + "\n"
    result, _ = shell_read(tmp_path, V2_BYTES, after=after)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "1|" + next_schema + "|" + next_values["kind"] + "\n"


@pytest.mark.parametrize("present", [False, True])
def test_recovery_to_v2_reload_removes_every_recovery_only_field(tmp_path, present):
    (tmp_path / "next.ctx").write_bytes(V2_BYTES)
    absent = " ".join('"${X2DII_SESSION_' + key.upper() + '+set}"' for key in recovery(present) if key not in V2)
    after = '''
x2dii_load_session "$1" "$2" || exit 80
test_next_path=${1%/*}/next.ctx
test_digest=$(sha256sum "$test_next_path")
x2dii_load_session "$test_next_path" "${test_digest%% *}" || exit 81
printf '%s|%s|%s\\n' "$X2DII_SESSION_VALID" "$X2DII_SESSION_SCHEMA" "$X2DII_SESSION_KIND"
printf '%s' ''' + absent + "\n"
    result, _ = shell_read(tmp_path, session.encode_session(recovery(present)), after=after)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "1|" + V2_SCHEMA + "|install\n"


def test_v2_loader_remains_read_only_and_runs_no_mutation_commands(tmp_path):
    forbidden = ("mkdir", "touch", "mount", "umount", "stop", "start", "setenforce", "cp", "mv", "rm", "dd")
    guard = "\n".join(name + '() { printf "forbidden:' + name + '\\n"; exit 90; }' for name in forbidden)
    result, data = shell_read(tmp_path, V2_BYTES, before=guard)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "1|install|1791040000|100|u:object_r:system_file:s0\n"
    assert data.read_bytes() == V2_BYTES
    assert sorted(p.name for p in tmp_path.iterdir()) == ["session.ctx"]


def test_v2_loader_rejects_real_hardlinked_session(tmp_path):
    (tmp_path / "other.ctx").write_bytes(V2_BYTES)
    (tmp_path / "session.ctx").hardlink_to(tmp_path / "other.ctx")
    result, data = shell_read(tmp_path, V2_BYTES)
    assert result.returncode == 42, result.stderr
    assert data.read_bytes() == (tmp_path / "other.ctx").read_bytes() == V2_BYTES


@pytest.mark.parametrize("mutation", ["same-content-replacement", "post-parse-byte-change"])
def test_v2_loader_preserves_file_identity_and_final_hash_checks(tmp_path, mutation):
    before = '''
sha256sum() {
 command sha256sum "$@" || return
 if [ "$#" != 0 ] && [ ! -f replaced ]; then
  command cp "$1" "$1.replacement" || return
  command mv "$1.replacement" "$1" || return
  printf yes > replaced
 fi
}
''' if mutation == "same-content-replacement" else '''
test_session_path=$1
sha256sum() {
 command sha256sum "$@" || return
 if [ "$#" = 0 ]; then
  command sed 's/core_sensor_bytes=456789/core_sensor_bytes=456788/' "$test_session_path" > changed.ctx || return
  command cat changed.ctx > "$test_session_path" || return
 fi
}
'''
    result, _ = shell_read(tmp_path, V2_BYTES, before=before)
    assert result.returncode == 42, (result.stdout, result.stderr)


@pytest.mark.parametrize("raw", [
    V2_BYTES, INSTALL_BYTES, session.encode_session(recovery(False)), session.encode_session(recovery(True)),
], ids=["v2-install", "v1-install-compatibility", "v1-recovery-absent", "v1-recovery-present"])
@pytest.mark.parametrize("stat_status", [0, 2], ids=["successful-stat-control", "expected-output-but-exit-2"])
def test_public_reader_requires_successful_link_stat_and_clears_failed_reload(tmp_path, raw, stat_status):
    published = " ".join('"${X2DII_SESSION_' + key.upper() + '+set}"' for key in ALL_PUBLIC)
    # A successful public load establishes that these exact v1/v2 bytes work.
    # Then inject only at the external stat boundary: retain its real output,
    # but give it a nonzero exit status, even though that output looks correct.
    after = 'x2dii_load_session "$1" "$2" || exit 80\n'
    after += 'test "$X2DII_SESSION_VALID" = 1 || exit 81\n'
    after += "".join('X2DII_SESSION_' + key.upper() + '=stale\n' for key in ALL_PUBLIC)
    after += '''
stat() {
 test_host_stat "$@" || return
 if [ "$2" = '%h' ]; then
  printf 'TEST_ONLY stat emitted expected link count; status=%s\\n' ''' + str(stat_status) + ''' >&2
  return ''' + str(stat_status) + '''
 fi
}
if x2dii_load_session "$1" "$2"; then
 printf 'accepted|%s|%s|%s\\n' "$X2DII_SESSION_VALID" "$X2DII_SESSION_SCHEMA" "$X2DII_SESSION_KIND"
else
 printf 'rejected|%s\\n' "$X2DII_SESSION_VALID"
 printf '%s' ''' + published + '''
fi
'''
    result, data = shell_read(tmp_path, raw, after=after)
    assert result.returncode == 0, result.stderr
    assert "TEST_ONLY stat emitted expected link count; status=" + str(stat_status) in result.stderr
    if stat_status:
        assert result.stdout == "rejected|0\n"
    else:
        schema = raw.splitlines()[0].split(b"=", 1)[1].decode()
        kind = raw.splitlines()[1].split(b"=", 1)[1].decode()
        assert result.stdout == "accepted|1|" + schema + "|" + kind + "\n"
    assert data.read_bytes() == raw
    assert sorted(path.name for path in tmp_path.iterdir()) == ["session.ctx"]


@pytest.mark.parametrize("raw", [
    V2_BYTES, INSTALL_BYTES, session.encode_session(recovery(False)), session.encode_session(recovery(True)),
], ids=["v2-install", "v1-install-compatibility", "v1-recovery-absent", "v1-recovery-present"])
@pytest.mark.parametrize("identity_observation", [2, 3], ids=["before-final-hash", "after-final-hash"])
@pytest.mark.parametrize("stat_status", [0, 2], ids=["successful-stat-control", "expected-output-but-exit-2"])
def test_public_reader_requires_each_final_stat_success_and_clears_failed_reload(
        tmp_path, raw, identity_observation, stat_status):
    published = " ".join('"${X2DII_SESSION_' + key.upper() + '+set}"' for key in ALL_PUBLIC)
    after = 'x2dii_load_session "$1" "$2" || exit 80\n'
    after += 'test "$X2DII_SESSION_VALID" = 1 || exit 81\n'
    after += "".join('X2DII_SESSION_' + key.upper() + '=stale\n' for key in ALL_PUBLIC)
    # Count only external identity observations in this second load. The
    # wrapper emits the unchanged real stat output, then fails exactly one
    # final observation; the parser and its public read path remain real.
    after += '''
stat() {
 test_host_stat "$@" || return
 if [ "$2" = '%d:%i:%f:%h:%s:%u:%g' ]; then
  printf 'observed\\n' >> TEST_ONLY-stat-calls
  test_stat_calls=$(command wc -l < TEST_ONLY-stat-calls) || return
  if [ "$test_stat_calls" -eq ''' + str(identity_observation) + ''' ]; then
   printf 'TEST_ONLY stat emitted expected identity; observation=%s; status=%s\\n' ''' + str(identity_observation) + ' ' + str(stat_status) + ''' >&2
   return ''' + str(stat_status) + '''
  fi
 fi
}
if x2dii_load_session "$1" "$2"; then
 printf 'accepted|%s|%s|%s\\n' "$X2DII_SESSION_VALID" "$X2DII_SESSION_SCHEMA" "$X2DII_SESSION_KIND"
else
 printf 'rejected|%s\\n' "$X2DII_SESSION_VALID"
 printf '%s' ''' + published + '''
fi
'''
    result, data = shell_read(tmp_path, raw, after=after)
    assert result.returncode == 0, result.stderr
    assert ("TEST_ONLY stat emitted expected identity; observation=" + str(identity_observation)
            + "; status=" + str(stat_status)) in result.stderr
    if stat_status:
        assert result.stdout == "rejected|0\n"
    else:
        schema = raw.splitlines()[0].split(b"=", 1)[1].decode()
        kind = raw.splitlines()[1].split(b"=", 1)[1].decode()
        assert result.stdout == "accepted|1|" + schema + "|" + kind + "\n"
    assert data.read_bytes() == raw
    assert sorted(path.name for path in tmp_path.iterdir()) == ["TEST_ONLY-stat-calls", "session.ctx"]
