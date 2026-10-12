"""Local-only preflight/caller seam tests; no real session or device calls."""
import pytest
import binascii
import struct
import hashlib
import copy
import tempfile
from pathlib import Path

from tools import stage_peer_usb_access as stage
from tools import factory_reply


HASH_REPLY = (
    'eb65334f497c12f63e73528973b734e3e79078de885f43f2a0be67ba93080765  /proc/1120/exe\n'
    'd018fee011426aefef1ded0bd2554ec6f4d31ea0b2529b63f9d5baddc44c42e0  /proc/1180/exe\n')


class ReadonlySession:
    def __init__(self, hash_reply=HASH_REPLY):
        self.hash_reply = hash_reply
        self.report = {}
        self.commands = []

    def command(self, label, command):
        self.commands.append((label, command))
        return {
            'transport-hash': self.hash_reply,
            'boot-id': '00000000-0000-0000-0000-000000000001\n',
            'usb-state': stage.BASE + '\n' + stage.BASE + '\nstopped\n',
            'uid': '0\n', 'lock-absent': '',
        }[label]


def test_preflight_rejects_unrecognized_active_transport_before_other_work():
    session = ReadonlySession(HASH_REPLY.replace('eb653', '00000'))
    with pytest.raises(ValueError, match='active transport'):
        stage.preflight(session)
    assert [label for label, _ in session.commands] == ['transport-hash']


def test_session_failure_saves_validated_partial_packets(monkeypatch):
    root = stage.output_directory(stage.PROJECT / 'build/peer-usb-live')
    with tempfile.TemporaryDirectory(prefix='offline-reply-test-', dir=root) as folder:
        session = stage.Session(Path(folder), {'commands': []})
        def fail(*args, **kwargs):
            session.transport.socket.chunks.append(b'all raw bytes')
            raise factory_reply.ReplyFailure('bad later record', [b'validated packet'])
        monkeypatch.setattr(session.transport, 'run', fail)
        with pytest.raises(factory_reply.ReplyFailure):
            session.command('read-only-test', 'id')
        assert (Path(folder) / '001-read-only-test.received.bin').read_bytes() == b'all raw bytes'
        assert (Path(folder) / '001-read-only-test.packets.bin').read_bytes() == b'validated packet'


def test_failed_fresh_preflight_cannot_reuse_previous_verified_binding():
    session = ReadonlySession('')
    session.report['transportExecutableBinding'] = {'verifiedDuringThisPreflight': True}
    with pytest.raises(ValueError):
        stage.preflight(session)
    assert session.report['transportExecutableBinding']['verifiedDuringThisPreflight'] is False


def test_session_rejects_retained_list_omitting_terminal(monkeypatch):
    def logical(text, function):
        body = b'\0' * 4 + text.encode().ljust(232, b'\0')
        return (b'\x09\x00\x05\x09\xfc' + struct.pack('<IIII', 0x41, function, 0,
                binascii.crc_hqx(body, 0)) + body + b'\0' * 3)
    notice = logical('\n__RC_123456abcdef__0\n__RD_123456abcdef__\n', 4)
    terminal = logical('', 1)
    root = stage.output_directory(stage.PROJECT / 'build/peer-usb-live')
    with tempfile.TemporaryDirectory(prefix='offline-reply-test-', dir=root) as folder:
        session = stage.Session(Path(folder), {'commands': []})
        def omit(*args, **kwargs):
            session.transport.socket.chunks.append(notice + b'\xa5' * 764 + terminal + b'\xa5' * 764)
            return [notice], []
        monkeypatch.setattr(session.transport, 'run', omit)
        monkeypatch.setattr(stage.secrets, 'token_hex', lambda _: '123456abcdef')
        with pytest.raises(ValueError, match='retained/raw'):
            session.command('read-only-test', 'id')


def test_session_binds_current_adapter_sources_before_preflight(tmp_path):
    session = stage.Session(tmp_path, {'commands': []})
    assert session.report['replySources']['replyDecoderSha256'] == hashlib.sha256(
        Path(factory_reply.__file__).read_bytes()).hexdigest()
    assert session.report['stagerSha256'] == hashlib.sha256(Path(stage.__file__).read_bytes()).hexdigest()


def simulated_session_reply(monkeypatch, text):
    """Native offline reply bytes at Session.command; never run the command."""
    def logical(value, function):
        data = value.encode()
        assert len(data) < 232
        body = b'\0' * 4 + data.ljust(232, b'\0')
        return (b'\x09\x00\x05\x09\xfc' + struct.pack('<IIII', 0x41, function, 0,
                binascii.crc_hqx(body, 0)) + body + b'\0' * 3)
    notice, terminal = logical(text, 4), logical('', 1)
    raw = notice + b'\xa5' * 764 + terminal + b'\xa5' * 764
    root = stage.output_directory(stage.PROJECT / 'build/rg229-local-boundary-20261006')
    # Retain the actual public command's raw evidence for both RED and GREEN.
    folder = Path(tempfile.mkdtemp(prefix='offline-session-records-', dir=root))
    session = stage.Session(folder, {'commands': []})
    def run(*args, **kwargs):
        session.transport.socket.chunks.append(raw)
        return [notice, terminal], []
    monkeypatch.setattr(session.transport, 'run', run)
    monkeypatch.setattr(stage.secrets, 'token_hex', lambda _: '123456abcdef')
    return session, raw, notice + terminal


@pytest.mark.parametrize('ending', ['\n', '\r\n'], ids=['lf', 'crlf'])
def test_session_preserves_logged_control_tokens_before_one_standalone_completion(monkeypatch, ending):
    payload = "camera-test log: printf '\\n__RC_123456abcdef__%s\\n__RD_123456abcdef__\\n'" + ending
    session, raw, packets = simulated_session_reply(monkeypatch,
        payload + '\n__RC_123456abcdef__0' + ending + '__RD_123456abcdef__' + ending)
    assert session.command('offline-control-record', 'id -u') == payload
    assert session.report['commands'][-1]['exit'] == 0
    assert (session.folder / '001-offline-control-record.received.bin').read_bytes() == raw
    assert (session.folder / '001-offline-control-record.packets.bin').read_bytes() == packets


@pytest.mark.parametrize('body', [
    '\n__RD_123456abcdef__\n',
    '\n__RC_123456abcdef__0\n',
    '\n__RD_123456abcdef__\n__RC_123456abcdef__0\n',
    '\n__RC_123456abcdef__0\n__RC_123456abcdef__0\n__RD_123456abcdef__\n',
    '\n__RD_123456abcdef__\n\n__RC_123456abcdef__0\n__RD_123456abcdef__\n',
    'payload\n__RC_123456abcdef__oops\n\n__RC_123456abcdef__0\n__RD_123456abcdef__\n',
    '\n__RC_123456abcdef__7\n\n__RC_123456abcdef__0\n__RD_123456abcdef__\n',
    '\n__RC_123456abcdef__0\n__RD_123456abcdef__\nextra\n',
    '\n__RC_123456abcdef__0\n__RD_123456abcdef__',
    '\n__RC_123456abcdef__999\n__RD_123456abcdef__\n',
])
@pytest.mark.parametrize('ending', ['\n', '\r\n'], ids=['lf', 'crlf'])
def test_session_rejects_invalid_standalone_control_records_and_retains_raw(monkeypatch, body, ending):
    session, raw, packets = simulated_session_reply(monkeypatch, body.replace('\n', ending))
    with pytest.raises(ValueError, match='missing, duplicated or invalid completion'):
        session.command('offline-control-record', 'id -u')
    assert session.report['commands'][-1]['error'] == 'missing, duplicated or invalid completion'
    assert (session.folder / '001-offline-control-record.received.bin').read_bytes() == raw
    assert (session.folder / '001-offline-control-record.packets.bin').read_bytes() == packets


@pytest.mark.parametrize('digest', [
    '', HASH_REPLY.splitlines()[0], HASH_REPLY + HASH_REPLY,
    HASH_REPLY.replace('d018f', '00000'),
    HASH_REPLY.replace('/proc/1120/exe', '/system/bin/msg2dbus'),
    HASH_REPLY.replace('/proc/1120/exe', '/proc/1120 1121/exe'),
    HASH_REPLY.replace('/proc/1120/exe', '/proc/0/exe'),
    HASH_REPLY.replace('/proc/1180/exe', '/proc/1120/exe'),
    '\n'.join(reversed(HASH_REPLY.splitlines())),
])
def test_preflight_missing_ambiguous_wrong_or_disk_only_executable_evidence_blocks(digest):
    session = ReadonlySession(digest)
    with pytest.raises(ValueError, match='active transport'):
        stage.preflight(session)
    assert [label for label, _ in session.commands] == ['transport-hash']
    assert session.report['transportExecutableBinding']['verifiedDuringThisPreflight'] is False


def test_each_preflight_requires_fresh_active_hashes_and_preserves_baseline_checks():
    session = ReadonlySession()
    for _ in range(2):
        assert stage.preflight(session) == '00000000-0000-0000-0000-000000000001'
    assert [label for label, _ in session.commands] == ['transport-hash', 'boot-id', 'usb-state', 'uid', 'lock-absent'] * 2
    assert session.commands[0][1] == 'sha256sum /proc/$(pidof msg2dbus)/exe /proc/$(pidof camera-test)/exe'
    proof = session.report['transportExecutableBinding']
    assert proof['verifiedDuringThisPreflight'] is True
    assert proof['ongoingProcessLifetimeProven'] is False
    assert proof['executables']['msg2dbus']['pid'] == 1120
    assert proof['executables']['camera-test']['pid'] == 1180


def test_session_cleanup_error_retains_strictly_validated_raw_packets(monkeypatch):
    terminal = b'\x09\x00\x05\x09\xfc' + struct.pack('<IIII', 0x41, 1, 0, 0) + b'\0' * 239
    wire = terminal + b'\xa5' * 764
    root = stage.output_directory(stage.PROJECT / 'build/peer-usb-live')
    with tempfile.TemporaryDirectory(prefix='offline-reply-test-', dir=root) as folder:
        session = stage.Session(Path(folder), {'commands': []})
        def cleanup_failure(*args, **kwargs):
            session.transport.socket.chunks.append(wire)
            raise OSError('injected cleanup failure')
        monkeypatch.setattr(session.transport, 'run', cleanup_failure)
        with pytest.raises(OSError, match='cleanup failure'):
            session.command('read-only-test', 'id')
        assert (Path(folder) / '001-read-only-test.received.bin').read_bytes() == wire
        assert (Path(folder) / '001-read-only-test.packets.bin').read_bytes() == terminal


@pytest.mark.parametrize('change', ['decoder', 'stager', 'missing'])
def test_resume_rejects_changed_or_missing_sources_without_relabeling_history(tmp_path, change):
    report = {'commands': [{'prior': 'must remain unchanged'}],
              'replySources': stage.live.source_hashes(),
              'stagerSha256': hashlib.sha256(Path(stage.__file__).read_bytes()).hexdigest()}
    if change == 'decoder': report['replySources']['replyDecoderSha256'] = '0' * 64
    elif change == 'stager': report['stagerSha256'] = '0' * 64
    else:
        del report['replySources']
        del report['stagerSha256']
    original = copy.deepcopy(report)
    with pytest.raises(ValueError, match='session source attribution'):
        stage.Session(tmp_path, report)
    assert report == original


def test_resume_identical_sources_preserves_existing_command_history(tmp_path):
    report = {'commands': [{'prior': 'unchanged'}], 'replySources': stage.live.source_hashes(),
              'stagerSha256': hashlib.sha256(Path(stage.__file__).read_bytes()).hexdigest()}
    original = copy.deepcopy(report)
    stage.Session(tmp_path, report)
    assert report == original


def test_session_overlimit_cleanup_error_preserves_only_receiver_validated_prefix(monkeypatch):
    notice = b'\x09\x00\x05\x09\xfc' + struct.pack('<IIII', 0x41, 4, 0, 0) + b'\0' * 239
    wire = (notice + b'\xa5' * 764) * 2056
    root = stage.output_directory(stage.PROJECT / 'build/peer-usb-live')
    with tempfile.TemporaryDirectory(prefix='offline-reply-test-', dir=root) as folder:
        session = stage.Session(Path(folder), {'commands': []})
        def cleanup_failure(*args, **kwargs):
            session.transport.socket.chunks.append(wire)
            kwargs['read_evidence']['validated_record_count'] = 2048
            raise OSError('cleanup masked receive limit')
        monkeypatch.setattr(session.transport, 'run', cleanup_failure)
        with pytest.raises(OSError):
            session.command('read-only-test', 'id')
        assert (Path(folder) / '001-read-only-test.received.bin').read_bytes() == wire
        assert (Path(folder) / '001-read-only-test.packets.bin').read_bytes() == notice * 2048


def recorded_launch_fixture():
    root = "/tmp/x2a-123456abcdef"
    return {"scriptSha256": stage.SCRIPT_SHA, "remote": root, "usbLaunchRequested": True,
            "stagerSha256": hashlib.sha256(Path(stage.__file__).read_bytes()).hexdigest(),
            "replySources": stage.live.source_hashes(),
            "launcherPid": 345, "status": "LAUNCH_REQUESTED_AWAITING_REAL_USB_EVIDENCE",
            "launchUtc": "2026-10-05T00:00:30+00:00",
            "commands": [{"label": "launch", "utc": "2026-10-05T00:00:00+00:00", "exit": 0,
                "text": "345\n", "command": f"umask 077;nohup sh {root}/s --approved-temporary-usb-access >{root}/log 2>&1 </dev/null & echo $!"}]}


def test_window_uses_saved_pre_command_time_not_late_reply_or_reenumeration():
    from datetime import datetime
    from tools.menu_content_transport import original_window_deadline
    report = recorded_launch_fixture()
    original = copy.deepcopy(report)
    started = stage.recorded_launch_start(report)
    assert started == datetime.fromisoformat("2026-10-05T00:00:00+00:00")
    assert original_window_deadline(int(started.timestamp()), started) == started.timestamp() + 80
    assert report == original


@pytest.mark.parametrize("fault", ("missing", "duplicate", "failed", "wrong-command", "no-zone", "late-alias"))
def test_launch_time_cannot_be_reconstructed_from_ambiguous_or_changed_history(fault):
    report = recorded_launch_fixture()
    if fault == "missing":
        report["commands"] = []
    elif fault == "duplicate":
        report["commands"] *= 2
    elif fault == "failed":
        report["commands"][0]["error"] = "transport disconnected"
    elif fault == "wrong-command":
        report["commands"][0]["command"] = "id -u"
    elif fault == "no-zone":
        report["commands"][0]["utc"] = "2026-10-05T00:00:00"
    else:
        report["launchStartedUtc"] = report["launchUtc"]
    with pytest.raises(ValueError):
        stage.recorded_launch_start(report)


def test_usb_worker_staging_does_not_append_to_replaced_upload_inode(tmp_path):
    import re
    import subprocess
    shell = "C:/Program Files/Git/bin/sh.exe"
    posix = subprocess.run([shell, "-c", 'cygpath -u "$1"', "fixture", str(tmp_path)],
                           capture_output=True, text=True, check=True).stdout.strip()
    remote = "/tmp/x2a-123456abcdef"
    commands = stage.stage_commands(remote, stage.validate_script())
    local = posix + "/x2a-123456abcdef"
    chunks = [index for index, command in enumerate(commands) if command.startswith("printf %s") or "printf %s" in command]
    first, second = chunks[:2]
    before = "\n".join(command.replace(remote, local) for command in commands[:first + 1])
    result = subprocess.run([shell, "-c", "set -e\n" + before], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    path = re.search(r">>?([^ )]+)", commands[first])[1].replace(remote, str(tmp_path / "x2a-123456abcdef"))
    upload = Path(path)
    upload.rename(upload.with_name(upload.name + ".owned"))
    unknown = b"UNRELATED REPLACEMENT CONTENT\n"
    upload.write_bytes(unknown)
    result = subprocess.run([shell, "-c", commands[second].replace(remote, local)], capture_output=True, text=True)
    assert upload.read_bytes() == unknown, "next upload step modified a replacement it did not create"


def test_exclusive_worker_blocks_reassemble_exact_pinned_bytes_without_running_them(tmp_path):
    import subprocess
    shell = "C:/Program Files/Git/bin/sh.exe"
    posix = subprocess.run([shell, "-c", 'cygpath -u "$1"', "fixture", str(tmp_path)],
                           capture_output=True, text=True, check=True).stdout.strip()
    remote = "/tmp/x2a-123456abcdef"
    raw = stage.validate_script()
    commands = stage.stage_commands(remote, raw)
    local = posix + "/x2a-123456abcdef"
    for command in commands:
        stage.envelope(command, "123456abcdef")
        assert ">>" not in command and "rm " not in command
    # Long host fixture paths exceed the MSYS single-argument limit when the
    # otherwise bounded device commands are concatenated into one -c argument.
    # Feed the same script through stdin; each production command is framed above.
    result = subprocess.run([shell], input="set -e\n" + "\n".join(
        command.replace(remote, local) for command in commands), capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "x2a-123456abcdef/s").read_bytes() == raw
    # Git's Windows coreutils marks binary-mode files with '*'; the target
    # completion parser remains strict for the camera's own sha256sum format.
    assert result.stdout.strip() in (
        stage.SCRIPT_SHA + "  " + local + "/s",
        stage.SCRIPT_SHA + " *" + local + "/s",
    )


@pytest.mark.parametrize("fault", ("existing-result", "missing-block", "extra-block", "changed-block"))
def test_pinned_worker_staging_never_overwrites_result_or_admits_damaged_blocks(tmp_path, fault):
    import subprocess
    shell = "C:/Program Files/Git/bin/sh.exe"
    posix = subprocess.run([shell, "-c", 'cygpath -u "$1"', "fixture", str(tmp_path)],
                           capture_output=True, text=True, check=True).stdout.strip()
    remote = "/tmp/x2a-123456abcdef"
    local = posix + "/x2a-123456abcdef"
    commands = stage.stage_commands(remote, stage.validate_script())
    # Execute actual upload commands, without running the reconstructed worker.
    result = subprocess.run([shell], input="set -e\n" + "\n".join(
        command.replace(remote, local) for command in commands[:-2]), capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    root = tmp_path / "x2a-123456abcdef"
    if fault == "existing-result":
        protected = root / "s"
        protected.write_bytes(b"UNRELATED EXISTING RESULT\n")
    elif fault == "missing-block":
        protected = root / "p000"
        protected.rename(root / "retained-missing-block")
        protected = root / "retained-missing-block"
    elif fault == "extra-block":
        protected = root / "p999"
        protected.write_bytes(b"I2V4dHJhCg==")  # A valid base64 extra line, not a decoder failure.
    else:
        protected = root / "p000"
        protected.rename(root / "original-first-block")
        protected.write_bytes(b"I2NoYW5nZWQK")
    before = (protected.stat().st_ino, protected.read_bytes())
    result = subprocess.run([shell], input="set -e\n" + "\n".join(
        command.replace(remote, local) for command in commands[-2:]), capture_output=True, text=True)
    assert (protected.stat().st_ino, protected.read_bytes()) == before
    if result.returncode == 0:
        # The real stage/launch CLI requires this exact digest. A decodable
        # corrupted script is not admitted merely because shell syntax passed.
        assert hashlib.sha256((root / "s").read_bytes()).hexdigest() != stage.SCRIPT_SHA
    else:
        assert result.stderr
