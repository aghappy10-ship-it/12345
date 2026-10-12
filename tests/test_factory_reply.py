"""Exercise the receiver seam with local byte streams; never open a socket."""
import binascii
import struct
import socket
import pytest

from tools import live_readout as live


def packet(text='', *, function=4, result=0):
    body = struct.pack('<I', result) + text.encode().ljust(232, b'\0')
    assert len(body) == 236
    command = struct.pack('<IIII', 0x41, function, 0, binascii.crc_hqx(body, 0)) + body
    return b'\x09\x00\x05\x09\xfc' + command + b'\0' * 3


def record(logical, padding=None):
    # Pinned native NetIO expands each 260-byte AppsMessage to 1024 bytes.
    # Extension bytes are opaque, not more logical messages or zero padding.
    extension = b'\xa5' * 764 if padding is None else padding
    assert len(logical) == 260 and len(extension) == 764
    return logical + extension


class ByteSocket:
    def __init__(self, chunks):
        self.chunks = iter(chunks)
        self.received = bytearray()

    def settimeout(self, timeout):
        assert timeout > 0

    def recv(self, size):
        chunk = next(self.chunks, b'')
        assert len(chunk) <= size
        self.received.extend(chunk)
        return chunk


def test_receiver_uses_native_records_and_waits_past_marker_for_terminal():
    transport = live.load_transport()
    end = '__RD_123456abcdef__'
    notice = packet('\n__RC_123456abcdef__0\n' + end + '\n')
    terminal = packet(function=1)
    # Even a complete valid-looking reply inside expansion bytes is not a frame.
    padding = packet('must not decode') + b'\xa5' * 504
    wire = record(notice, padding) + record(terminal)
    sock = ByteSocket([wire[:27], wire[27:1400], wire[1400:]])
    evidence = {}
    replies = transport.receive_packets(sock, 1, end, read_evidence=evidence)
    assert replies == [notice, terminal]
    assert bytes(sock.received) == wire
    assert evidence['complete_record_count'] == 2
    assert evidence['expansion_bytes'] == 1528
    assert evidence['terminal_count'] == 1
    assert evidence['stop_reason'] == 'native_terminal_success'


def test_native_terminal_observation_does_not_claim_active_binary_verification():
    transport = live.load_transport()
    evidence = {}
    transport.receive_packets(ByteSocket([record(packet(function=1))]), 1,
                              read_evidence=evidence)
    assert evidence['remote_termination_proven'] is False
    assert evidence['active_producer_hashes_verified'] is False
    assert evidence['native_terminal_success_observed'] is True


def test_receiver_itself_bounds_wire_bytes_and_counts_the_overlimit_chunk():
    transport = live.load_transport()
    notice = record(packet('bounded\n'))
    sock = ByteSocket([notice * 8] * 257 + [record(packet(function=1))])
    evidence = {}
    with pytest.raises(ValueError, match='receive limit') as caught:
        transport.receive_packets(sock, 10, read_evidence=evidence)
    assert evidence['wire_bytes'] == len(sock.received) == 2 * 1024 * 1024 + 8192
    assert evidence['complete_record_count'] == 2056
    assert evidence['validated_record_count'] == len(caught.value.packets) == 2048


def test_expired_deadline_is_not_misreported_as_packet_corruption():
    transport = live.load_transport()
    evidence = {}
    with pytest.raises(ValueError, match='missing unique native terminal'):
        transport.receive_packets(ByteSocket([]), 0, read_evidence=evidence)
    assert evidence['stop_reason'] == 'deadline'
    assert evidence['wire_bytes'] == 0


@pytest.mark.parametrize('cut', [1, 4, 5, 259, 260, 261, 1023, 1024, 1025, 2047])
def test_arbitrary_socket_splits_preserve_exact_native_record_boundaries(cut):
    transport = live.load_transport()
    notice, terminal = packet('payload'), packet(function=1)
    wire = record(notice) + record(terminal)
    evidence = {}
    assert transport.receive_packets(ByteSocket([wire[:cut], wire[cut:]]), 1,
                                     read_evidence=evidence) == [notice, terminal]
    assert live.received_packets(wire, transport) == [notice, terminal]
    assert evidence['unparsed_bytes'] == evidence['incomplete_record_bytes'] == 0


@pytest.mark.parametrize('wire,error', [
    (b'x' + record(packet(function=1)), 'framing'),
    (packet('packed260') + packet(function=1), 'truncated'),
    (record(packet('no terminal')), 'missing unique native terminal'),
    (record(packet('before')) + record(packet(function=1))[:1023], 'truncated'),
    (record(packet(function=1, result=1)), 'reported failure'),
    (record(packet('not allowed', function=1)), 'terminal body'),
    (record(packet(function=1, result=2)), 'terminal body'),
    (record(packet('error notification', result=1)), 'notification body'),
    (record(packet(function=0)), 'operation/function/header'),
    (record(packet(function=5)), 'operation/function/header'),
    (record(packet(function=1)) * 2, 'after native terminal'),
    (record(packet(function=1)) + record(packet('late')), 'after native terminal'),
    (record(packet(function=1)) + b'x', 'after native terminal'),
])
def test_malformed_incomplete_and_after_terminal_streams_fail_closed(wire, error):
    transport = live.load_transport()
    evidence = {}
    with pytest.raises(ValueError, match=error):
        transport.receive_packets(ByteSocket([wire]), 1, read_evidence=evidence)
    with pytest.raises(ValueError, match=error):
        live.received_packets(wire, transport)
    assert evidence['wire_bytes'] == len(wire)
    assert evidence['complete_record_count'] == len(wire) // 1024
    assert evidence['incomplete_record_bytes'] == len(wire) % 1024
    assert evidence['resync_discarded_bytes'] == 0


@pytest.mark.parametrize('offset', [0, 2, 3, 4, 5, 9, 13, 17, 25, 257, 259])
def test_aligned_corruption_is_rejected_not_resynchronized(offset):
    transport = live.load_transport()
    corrupt = bytearray(packet('valid before corruption'))
    corrupt[offset] ^= 1
    wire = record(bytes(corrupt)) + record(packet(function=1))
    with pytest.raises(ValueError):
        transport.receive_packets(ByteSocket([wire]), 1)


@pytest.mark.parametrize('exception,reason', [
    (socket.timeout(), 'socket_timeout'),
    (ConnectionResetError(), 'connection_reset'),
    (ConnectionAbortedError(), 'connection_aborted'),
    (OSError('other socket error'), 'receive_error'),
])
def test_receive_failure_preserves_complete_records_and_stop_reason(exception, reason):
    transport = live.load_transport()
    notice = packet('partial')
    class FailingSocket(ByteSocket):
        def recv(self, size):
            if self.received:
                raise exception
            return super().recv(size)
    evidence = {}
    with pytest.raises(ValueError) as caught:
        transport.receive_packets(FailingSocket([record(notice)]), 1, read_evidence=evidence)
    assert caught.value.packets == [notice]
    assert evidence['stop_reason'] == reason
    assert evidence['wire_bytes'] == 1024 and evidence['terminal_count'] == 0


@pytest.mark.parametrize('notices', [[], ['__END__'], ['__END__\n', '__END__\n']])
def test_terminal_does_not_waive_complete_unique_completion_line(notices):
    transport = live.load_transport()
    wire = b''.join(record(packet(text)) for text in notices) + record(packet(function=1))
    with pytest.raises(ValueError, match='unique completion line'):
        transport.receive_packets(ByteSocket([wire]), 1, '__END__')


def test_native_error_body_is_not_treated_as_successful_header_zero():
    transport = live.load_transport()
    evidence = {}
    with pytest.raises(ValueError, match='reported failure') as caught:
        transport.receive_packets(ByteSocket([record(packet(function=1, result=1))]), 1,
                                  read_evidence=evidence)
    assert caught.value.packets == [packet(function=1, result=1)]
    assert evidence['native_body_result'] == 1
    assert evidence['terminal_count'] == 1
    assert evidence['stop_reason'] == 'native_terminal_failure'
    assert evidence['native_terminal_success_observed'] is False


def test_frozen_run_keeps_send_inputs_endpoint_and_lock_with_local_receiver(monkeypatch, tmp_path):
    transport = live.load_transport()
    notice, terminal = packet('END\n'), packet(function=1)
    wire = record(notice) + record(terminal)
    class ConnectedSocket(ByteSocket):
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def setsockopt(self, *args): self.options = args
        def sendall(self, data): self.sent = data
    sock = ConnectedSocket([wire[:500], wire[500:]])
    lock = tmp_path / 'offline-only-factory.lock'
    monkeypatch.setattr(transport, 'FACTORY_TUNNEL_LOCK', lock)
    def connect(address, *, timeout):
        assert address == ('192.168.42.2', 30303) and timeout == 3.0
        assert lock.is_file()  # The unmodified serialized body precedes connection.
        return sock
    # Only the external network boundary is substituted; frozen run/build/lock
    # and local receiver execute. This test cannot open a network connection.
    monkeypatch.setattr(live.socket, 'create_connection', connect)
    evidence = {}
    replies, texts = transport.run('id', 2, 'END', output_delay_ms=23, read_evidence=evidence)
    assert replies == [notice, terminal] and texts == ['END\n']
    assert b''.join(transport.socket.chunks) == wire
    assert sock.options == (socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    assert sock.sent[:5] == b'\x05\x00\x09\x05\xfc' and len(sock.sent) == 260
    request = sock.sent[5:257]
    assert struct.unpack_from('<III', request) == (0x41, 1, 0)
    assert struct.unpack_from('<I', request, 16)[0] == 23
    assert request[20:23] == b'id\0'
    assert struct.unpack_from('<I', request, 12)[0] == binascii.crc_hqx(request[16:], 0)
    assert evidence['terminal_count'] == 1
