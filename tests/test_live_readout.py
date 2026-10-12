"""Validate readout evidence offline; tests must never contact the camera."""
import json
import hashlib
import os
from pathlib import Path
import py_compile
import struct
import subprocess
import sys
import types
from unittest.mock import patch

import pytest

from tools import live_readout as live


def test_load_transport_compiles_checked_bytes_not_timestamp_valid_pyc(monkeypatch, tmp_path):
    """Only constant-only temporary source/cache files are executed here."""
    source = tmp_path / 'harmless_transport.py'
    checked = b"MARKER = 'checked-source'\n"
    poisoned = b"MARKER = 'poisoned-cache'\n"
    assert len(checked) == len(poisoned)
    source.write_bytes(poisoned)
    metadata = source.stat()
    cached = Path(py_compile.compile(str(source), doraise=True,
                                    invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP))
    source.write_bytes(checked)
    os.utime(source, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    assert cached.is_file()
    monkeypatch.setattr(live, 'TRANSPORT', source)
    monkeypatch.setattr(live, 'TRANSPORT_SHA', hashlib.sha256(checked).hexdigest())
    assert live.load_transport().MARKER == 'checked-source'


def test_load_transport_ignores_sys_modules_shadow(monkeypatch, tmp_path):
    source = tmp_path / 'harmless_transport.py'
    checked = b"MARKER = 'checked-source'\n"
    source.write_bytes(checked)
    shadow = types.ModuleType('x2dii_reviewed_transport')
    shadow.MARKER = 'poisoned-sys-modules'
    monkeypatch.setitem(sys.modules, shadow.__name__, shadow)
    monkeypatch.setattr(live, 'TRANSPORT', source)
    monkeypatch.setattr(live, 'TRANSPORT_SHA', hashlib.sha256(checked).hexdigest())
    assert live.load_transport().MARKER == 'checked-source'


def test_load_transport_uses_retained_checked_bytes_after_source_path_changes(monkeypatch, tmp_path):
    source = tmp_path / 'harmless_transport.py'
    checked = b"MARKER = 'checked-source'\n"
    changed = b"MARKER = 'changed-after-read'\n"
    source.write_bytes(checked)
    class ChangingSourcePath:
        def read_bytes(self):
            return source.read_bytes()
        def __str__(self):
            # load_transport resolves the path only after retaining/checking bytes.
            source.write_bytes(changed)
            return str(source)
    monkeypatch.setattr(live, 'TRANSPORT', ChangingSourcePath())
    monkeypatch.setattr(live, 'TRANSPORT_SHA', hashlib.sha256(checked).hexdigest())
    result = live.load_transport()
    assert source.read_bytes() == changed
    assert result.MARKER == 'checked-source'


def reply(transport, text, function=4):
    body = bytearray(252)
    struct.pack_into('<III', body, 0, 0x41, function, 0)
    data = text.encode()
    assert len(data) < 232
    body[20:20 + len(data)] = data
    struct.pack_into('<I', body, 12, transport.crc16_hbl(body[16:]))
    return struct.pack('<HBB', 9, 5, 9) + b'\xfc' + body + b'\0' * 3


def native_record(packet):
    # Correct the old packed-260/"relay-tail" fixture: pinned NetIO expands
    # EVERY logical reply to 1024 bytes. Expansion is retained, not scanned.
    assert len(packet) == 260
    return packet + b'\xa5' * 764


def simulated_query(text_builder):
    transport = live.load_transport()
    def run(command, timeout, completion_marker, read_evidence):
        packet = reply(transport, text_builder(completion_marker))
        terminal = reply(transport, '', function=1)
        transport.socket.chunks.append(native_record(packet) + native_record(terminal))
        return [packet, terminal], []
    with patch.object(transport, 'run', side_effect=run), patch.object(live.secrets, 'token_hex', return_value='123456abcdef'):
        return live.query('gui_hash', transport)


def test_fresh_nonce_rc_order_and_complete_raw_bytes_retained():
    result = simulated_query(lambda end: 'payload\n\n__RC_123456abcdef__0\n' + end + '\n')
    assert result['text'] == 'payload\n'
    assert result['shellLastExitCode'] == 0
    assert len(result['rawReceived']) > len(result['packets'])


@pytest.mark.parametrize('ending', ['\n', '\r\n'], ids=['lf', 'crlf'])
def test_query_preserves_logged_control_tokens_before_one_standalone_completion(ending):
    payload = "camera-test log: printf '\\n__RC_123456abcdef__%s\\n__RD_123456abcdef__\\n'" + ending
    result = simulated_query(lambda end: payload + '\n__RC_123456abcdef__0' + ending + end + ending)
    assert result['text'] == payload
    assert result['shellLastExitCode'] == 0
    assert result['rawReceived'] and result['packets']


@pytest.mark.parametrize('payload,exit_code', [('u:r:hbl_camera_service:s0', 0), ('no-newline', 7), ('line\n', 0), ('', 3)])
def test_query_preserves_unterminated_output_and_original_shell_status(payload, exit_code):
    """Execute the actual shell envelope locally, never a camera command."""
    transport = live.load_transport()
    def run(command, timeout, completion_marker, read_evidence):
        output = subprocess.run(
            [r'C:\Program Files\Git\bin\sh.exe', '-c', command],
            capture_output=True, check=True, timeout=5).stdout.decode()
        packet = reply(transport, output)
        terminal = reply(transport, '', function=1)
        transport.socket.chunks.append(native_record(packet) + native_record(terminal))
        return [packet, terminal], []
    base = "printf '%s' '" + payload + "'; (exit " + str(exit_code) + ')'
    with patch.dict(live.QUERIES, {'su_identity': base}), patch.object(transport, 'run', side_effect=run):
        result = live.query('su_identity', transport)
    assert result['text'] == payload
    assert result['shellLastExitCode'] == exit_code


@pytest.mark.parametrize('body', [
    '__RD_123456abcdef__\n__RC_123456abcdef__0\n',
    '__RC_123456abcdef__0\n__RD_123456abcdef__\nextra\n',
    '__RC_123456abcdef__0\n__RD_123456abcdef__',
    '__RC_123456abcdef__0\n__RC_123456abcdef__0\n__RD_123456abcdef__\n',
    '__RC_123456abcdef__0\n__RD_123456abcdef__\n',
    'payload\n__RC_123456abcdef__oops\n\n__RC_123456abcdef__0\n__RD_123456abcdef__\n',
    '\n__RC_123456abcdef__999\n__RD_123456abcdef__\n',
    'payload\n__RD_123456abcdef__\n\n__RC_123456abcdef__0\n__RD_123456abcdef__\n',
    'payload\n__RC_123456abcdef__7\n\n__RC_123456abcdef__0\n__RD_123456abcdef__\n',
])
@pytest.mark.parametrize('ending', ['\n', '\r\n'], ids=['lf', 'crlf'])
def test_wrong_marker_order_duplicates_trailer_or_truncation_fails(body, ending):
    with pytest.raises(live.QueryFailure) as caught:
        simulated_query(lambda _: body.replace('\n', ending))
    assert caught.value.raw and caught.value.packets


def test_crc_and_route_reject_corruption():
    transport = live.load_transport()
    original = reply(transport, 'ok\n')
    assert live.validate_packet(original, transport) == 'ok\n'
    for offset in (0, 3, 4, 5, 9, 13, 17, 25):
        changed = bytearray(original); changed[offset] ^= 1
        with pytest.raises(ValueError): live.validate_packet(bytes(changed), transport)


def test_already_received_duplicate_after_completion_is_not_ignored():
    transport = live.load_transport()
    def run(command, timeout, completion_marker, read_evidence):
        packet = reply(transport, '\n__RC_123456abcdef__0\n' + completion_marker + '\n')
        terminal = reply(transport, '', function=1)
        class Socket:
            def settimeout(self, _): pass
            def recv(self, _):
                # Duplicate completion remains a failure with real framing.
                wire = native_record(packet) * 2 + native_record(terminal)
                transport.socket.chunks.append(wire)
                return wire
        return transport.receive_packets(Socket(), timeout, completion_marker, read_evidence=read_evidence), []
    with patch.object(transport, 'run', side_effect=run), patch.object(live.secrets, 'token_hex', return_value='123456abcdef'):
        with pytest.raises(live.QueryFailure) as caught:
            live.query('su_identity', transport)
    assert len(caught.value.raw) > len(caught.value.packets)


def test_query_rejects_omitted_retained_terminal_even_when_raw_is_valid():
    transport = live.load_transport()
    def run(command, timeout, completion_marker, read_evidence):
        notice = reply(transport, '\n__RC_123456abcdef__0\n' + completion_marker + '\n')
        terminal = reply(transport, '', function=1)
        transport.socket.chunks.append(native_record(notice) + native_record(terminal))
        return [notice], []
    with patch.object(transport, 'run', side_effect=run), patch.object(live.secrets, 'token_hex', return_value='123456abcdef'):
        with pytest.raises(live.QueryFailure, match='retained replies'):
            live.query('gui_hash', transport)


def test_query_failure_retains_validated_packets_before_bad_record():
    transport = live.load_transport()
    notice = reply(transport, 'partial output\n')
    bad = bytearray(reply(transport, '', function=1)); bad[5] ^= 1
    wire = native_record(notice) + native_record(bytes(bad))
    def run(command, timeout, completion_marker, read_evidence):
        class Socket:
            def settimeout(self, _): pass
            def recv(self, _):
                transport.socket.chunks.append(wire)
                return wire
        return transport.receive_packets(Socket(), timeout, completion_marker, read_evidence=read_evidence), []
    with patch.object(transport, 'run', side_effect=run):
        with pytest.raises(live.QueryFailure) as caught:
            live.query('gui_hash', transport)
    assert caught.value.raw == wire
    assert caught.value.packets == notice
    assert caught.value.receive['validated_record_count'] == 1


def test_query_cleanup_error_keeps_validated_packets_from_actual_frozen_run(monkeypatch, tmp_path):
    transport = live.load_transport()
    notice = reply(transport, '\n__RC_123456abcdef__0\n__RD_123456abcdef__\n')
    terminal = reply(transport, '', function=1)
    wire = native_record(notice) + native_record(terminal)
    class CloseFailure:
        def __enter__(self): return self
        def __exit__(self, *args): raise OSError('injected post-receive close error')
        def setsockopt(self, *args): pass
        def settimeout(self, _): pass
        def sendall(self, _): pass
        def recv(self, _): return wire
    monkeypatch.setattr(live.socket, 'create_connection', lambda *args, **kwargs: CloseFailure())
    monkeypatch.setattr(transport, 'FACTORY_TUNNEL_LOCK', tmp_path / 'offline-only-factory.lock')
    monkeypatch.setattr(live.secrets, 'token_hex', lambda _: '123456abcdef')
    with pytest.raises(live.QueryFailure, match='post-receive close error') as caught:
        live.query('gui_hash', transport)
    assert caught.value.raw == wire
    assert caught.value.packets == notice + terminal
    assert caught.value.receive['validated_record_count'] == 2


def test_query_cleanup_error_cannot_erase_prefix_when_receive_limit_also_fails(monkeypatch, tmp_path):
    transport = live.load_transport()
    notice = reply(transport, 'bounded partial\n')
    chunk = native_record(notice) * 8
    class LimitAndCloseFailure:
        def __enter__(self): return self
        def __exit__(self, *args): raise OSError('cleanup masked receive limit')
        def setsockopt(self, *args): pass
        def settimeout(self, _): pass
        def sendall(self, _): pass
        def recv(self, _): return chunk
    monkeypatch.setattr(live.socket, 'create_connection', lambda *args, **kwargs: LimitAndCloseFailure())
    monkeypatch.setattr(transport, 'FACTORY_TUNNEL_LOCK', tmp_path / 'offline-only-factory.lock')
    with pytest.raises(live.QueryFailure, match='cleanup masked receive limit') as caught:
        live.query('gui_hash', transport, timeout=10)
    assert len(caught.value.raw) == 2 * 1024 * 1024 + 8192
    assert caught.value.receive['validated_record_count'] == 2048
    assert caught.value.packets == notice * 2048


def test_fixed_commands_fit_protocol_capacity():
    for command in live.QUERIES.values():
        if command is None: continue
        complete = command + ";printf '\\n__RC_123456abcdef__%s\\n__RD_123456abcdef__\\n' $?"
        assert len(complete.encode()) < 232


def test_cache_read_retains_full_arm64_address_and_binds_exact_gui():
    context = {
        'gui_hash': 'b1b643cb36176cd5a49129dd9bb2be480aa045a96ed1c35c30a779ab5af0801b  /system/bin/camera-gui',
        'gui_lifetime': '370 (camera-gui) S 1',
        'gui_maps': ('556c2e3000-556ecb3000 r-xp 00000000 103:09 573 /system/bin/camera-gui\n'
                     '556ecb4000-556eda2000 r--p 029d0000 103:09 573 /system/bin/camera-gui\n')}
    address = 0x556c2e3000 + 0x29d4b80
    assert live.cache_command(context) == f'od -An -tx8 -j {address} -N24 /proc/370/mem'
    for field, value in (('gui_hash', '0' * 64), ('gui_lifetime', '370 371 (camera-gui) S'),
                         ('gui_maps', context['gui_maps'].splitlines()[0])):
        with pytest.raises(ValueError): live.cache_command({**context, field: value})


@pytest.mark.parametrize('base,end', [
    pytest.param(1 << 64, (1 << 64) + 0x4000000, id='image-base-over-u64'),
    pytest.param(1, 0x4000001, id='unaligned-image-base'),
    pytest.param((1 << 64) - 0x29d4b80, (1 << 64) + 24, id='cache-address-over-u64'),
    pytest.param((1 << 64) - 0x29d4b80 - 16, (1 << 64) + 8, id='cache-read-end-over-u64'),
    pytest.param(0, 1 << 64, id='mapping-end-over-u64'),
])
def test_cache_read_rejects_out_of_range_or_unaligned_addresses(base, end):
    context = {
        'gui_hash': 'b1b643cb36176cd5a49129dd9bb2be480aa045a96ed1c35c30a779ab5af0801b  /system/bin/camera-gui',
        'gui_lifetime': '370 (camera-gui) S 1',
        'gui_maps': f'{base:x}-{end:x} r-xp 00000000 08:01 2 /system/bin/camera-gui',
    }
    with pytest.raises(ValueError):
        live.cache_command(context)


@pytest.mark.parametrize('extra_mapping', [
    pytest.param('4001000-4001000 r--p 00000000', id='empty-span'),
    pytest.param('4002000-4001000 r--p 00000000', id='reversed-span'),
    pytest.param('10000000000000000-10000000000001000 r--p 00000000', id='start-over-u64'),
    pytest.param('fffffffffffff000-10000000000000000 r--p 00000000', id='end-over-u64'),
    pytest.param('4001000-4002000 r--p -1', id='negative-offset'),
    pytest.param('4001000-4002000 r--p 10000000000000000', id='offset-over-u64'),
    pytest.param('1000-2000 r--p 00000000', id='overlapping-span'),
    pytest.param('5000000-5001000 r--p 00000000\n4001000-4002000 r--p 00000000',
                 id='out-of-order-spans'),
    pytest.param('4001000 r--p 00000000', id='missing-range-end'),
    pytest.param('4001000-nothex r--p 00000000', id='malformed-range-end'),
])
def test_cache_read_rejects_invalid_mapping_ranges_even_when_cache_is_readable(extra_mapping):
    suffix = ' 08:01 2 /system/bin/camera-gui'
    context = {
        'gui_hash': 'b1b643cb36176cd5a49129dd9bb2be480aa045a96ed1c35c30a779ab5af0801b  /system/bin/camera-gui',
        'gui_lifetime': '370 (camera-gui) S 1',
        'gui_maps': ('0-4000000 r-xp 00000000' + suffix + '\n'
                     + '\n'.join(line + suffix for line in extra_mapping.splitlines())),
    }
    with pytest.raises(ValueError):
        live.cache_command(context)


@pytest.mark.parametrize('base', [
    pytest.param((1 << 64) - 0x29d4b80, id='computed-cache-address-over-u64'),
    pytest.param((1 << 64) - 0x29d4b80 - 16, id='computed-cache-read-end-over-u64'),
])
def test_cache_read_rejects_computed_overflow_with_valid_mapping_endpoints(base):
    context = {
        'gui_hash': 'b1b643cb36176cd5a49129dd9bb2be480aa045a96ed1c35c30a779ab5af0801b  /system/bin/camera-gui',
        'gui_lifetime': '370 (camera-gui) S 1',
        'gui_maps': f'{base:x}-ffffffffffffffff r-xp 00000000 08:01 2 /system/bin/camera-gui',
    }
    with pytest.raises(ValueError, match='invalid unsigned 64-bit or unaligned cache address'):
        live.cache_command(context)


def test_cache_read_accepts_exact_half_open_mapping_end():
    context = {
        'gui_hash': 'b1b643cb36176cd5a49129dd9bb2be480aa045a96ed1c35c30a779ab5af0801b  /system/bin/camera-gui',
        'gui_lifetime': '370 (camera-gui) S 1',
        'gui_maps': '0-29d4b98 r-xp 00000000 08:01 2 /system/bin/camera-gui',
    }
    assert live.cache_command(context) == 'od -An -tx8 -j 43862912 -N24 /proc/370/mem'


def test_cache_read_rejects_partial_interval_at_half_open_mapping_end():
    context = {
        'gui_hash': 'b1b643cb36176cd5a49129dd9bb2be480aa045a96ed1c35c30a779ab5af0801b  /system/bin/camera-gui',
        'gui_lifetime': '370 (camera-gui) S 1',
        'gui_maps': '0-29d4b97 r-xp 00000000 08:01 2 /system/bin/camera-gui',
    }
    with pytest.raises(ValueError):
        live.cache_command(context)


def test_duplicate_query_names_do_not_overwrite_before_evidence():
    counter = iter((b'first', b'second'))
    def query(name, transport):
        value = next(counter)
        return dict(name=name, command=live.QUERIES[name], shellLastExitCode=0,
                    text=value.decode(), packets=value, rawReceived=value, receive={})
    with patch.object(live, 'query', side_effect=query):
        report = live.collect(['gui_lifetime', 'gui_lifetime'])
    folder = Path(report['output'])
    assert (folder / '001-gui_lifetime.txt').read_bytes() == b'first'
    assert (folder / '002-gui_lifetime.txt').read_bytes() == b'second'
    assert len(json.loads((folder / 'READOUT.json').read_text())['queries']) == 2
    assert report['installable'] is False
    assert report['replyDecoderSha256'] == hashlib.sha256(Path(live.factory_reply.__file__).read_bytes()).hexdigest()


def test_failure_saves_raw_bytes_and_never_reports_complete():
    created = []
    make_directory = live.tempfile.mkdtemp
    def track_directory(*args, **kwargs):
        path = make_directory(*args, **kwargs)
        created.append(Path(path))
        return path
    with patch.object(live.tempfile, 'mkdtemp', side_effect=track_directory), patch.object(
            live, 'query', side_effect=live.QueryFailure('bad CRC', b'raw', b'packet', {})):
        with pytest.raises(live.QueryFailure): live.collect(['gui_hash'])
    assert len(created) == 1
    assert (created[0] / '001-gui_hash.received.bin').read_bytes() == b'raw'
    assert (created[0] / '001-gui_hash.packets.bin').read_bytes() == b'packet'
    report = json.loads((created[0] / 'READOUT.json').read_text())
    assert report['status'] == 'TRANSPORT_OR_VALIDATION_FAILURE'
    assert report['installable'] is False
    assert 'bad CRC' in report['queries']['001-gui_hash']['error']
