"""Strict reply adapter for the pinned factory NetIO / HblShell path only.

The original msg2dbus SendMessage resizes each AppsMessage to 1024 bytes.
Its first 260 bytes contain the logical test reply; the 764-byte expansion is
opaque and must never be scanned for more packets. Original camera-test
HblShell::finished emits a notification then SUTest::ok/error, retaining request
function 1. This static evidence is not proof of the active camera binaries.
"""
from __future__ import annotations

import socket
import struct
import time

RECORD_SIZE = 1024
PACKET_SIZE = 260
MAX_RECEIVE_BYTES = 2 * 1024 * 1024


class ReplyFailure(ValueError):
    """Failed receive retaining only packets validated before the failure."""
    def __init__(self, message, packets):
        super().__init__(message)
        self.packets = list(packets)


def decode_packet(packet, transport):
    """Return (function, body result, text), rejecting non-HblShell replies."""
    if (len(packet) != PACKET_SIZE or packet[:5] != b'\x09\x00\x05\x09\xfc'
            or packet[257:] != b'\0' * 3):
        raise ValueError('unexpected reply framing or logical padding')
    command = packet[5:257]
    operation, function, header_word, checksum = struct.unpack_from('<IIII', command)
    if operation != 0x41 or function not in (1, 4) or header_word != 0:
        raise ValueError('unexpected reply operation/function/header')
    body = command[16:]
    if checksum != transport.crc16_hbl(body):
        raise ValueError('reply checksum mismatch')
    result = struct.unpack_from('<I', body)[0]
    if function == 1:
        if result not in (0, 1) or body[4:] != b'\0' * 232:
            raise ValueError('unexpected native terminal body')
        return function, result, ''
    if result != 0:
        raise ValueError('unexpected notification body result')
    return function, result, transport.response_text(packet)


class ReplyStream:
    """One dedicated, record-aligned connection; never resynchronizes."""
    def __init__(self, transport):
        self.transport = transport
        self.pending = bytearray()
        self.packets = []
        self.texts = []
        self.wire_bytes = 0
        self.terminal_count = 0
        self.terminal_result = None

    def feed(self, chunk):
        self.wire_bytes += len(chunk)
        self.pending.extend(chunk)
        if self.wire_bytes > MAX_RECEIVE_BYTES:
            raise ValueError('fixed readout exceeded receive limit')
        while len(self.pending) >= RECORD_SIZE:
            if self.terminal_count:
                raise ValueError('reply record after native terminal result')
            logical = bytes(self.pending[:PACKET_SIZE])
            function, result, text = decode_packet(logical, self.transport)
            del self.pending[:RECORD_SIZE]
            self.packets.append(logical)
            if function == 1:
                self.terminal_count += 1
                self.terminal_result = result
            else:
                self.texts.append(text)
        if self.terminal_count and self.pending:
            raise ValueError('trailing bytes after native terminal result')

    def finish(self, completion_marker=None):
        if self.pending:
            raise ValueError('truncated native 1024-byte reply record')
        if self.terminal_count != 1:
            raise ValueError('missing unique native terminal result')
        if self.terminal_result != 0:
            raise ValueError('native terminal reported failure')
        if completion_marker is not None:
            count = self.transport.completion_line_count(''.join(self.texts), completion_marker)
            if count != 1:
                raise ValueError('missing unique completion line before native terminal result')
        return self.packets

    def diagnostics(self, completion_marker=None):
        count = (self.transport.completion_line_count(''.join(self.texts), completion_marker)
                 if completion_marker is not None else 0)
        complete, incomplete = divmod(self.wire_bytes, RECORD_SIZE)
        return dict(record_size=RECORD_SIZE, logical_message_size=PACKET_SIZE,
                    wire_bytes=self.wire_bytes, complete_record_count=complete,
                    validated_record_count=len(self.packets), packet_count=len(self.packets),
                    expansion_bytes=complete * (RECORD_SIZE - PACKET_SIZE),
                    logical_padding_bytes=complete * 3, incomplete_record_bytes=incomplete,
                    unparsed_bytes=len(self.pending), resync_discarded_bytes=0,
                    terminal_count=self.terminal_count, native_body_result=self.terminal_result,
                    completion_line_count=count, completion_line_observed=count == 1,
                    native_terminal_success_observed=(self.terminal_count == 1 and self.terminal_result == 0),
                    active_producer_hashes_verified=False, remote_termination_proven=False)


def received_packets(raw, transport):
    stream = ReplyStream(transport)
    try:
        stream.feed(raw)
        return stream.finish()
    except Exception as error:
        raise ReplyFailure(str(error), stream.packets) from error


def failure_packets(error, raw, transport, receive):
    """Keep validated evidence even if frozen run's socket/lock cleanup fails."""
    if isinstance(error, ReplyFailure):
        return error.packets
    # A cleanup error may mask a receive-limit failure. Reconstruct only the
    # prefix the receiver actually validated, not the whole overlimit buffer.
    # Revalidate its bytes as well; counters alone are never packet evidence.
    count = receive.get('validated_record_count')
    if type(count) is int and 0 <= count <= min(len(raw), MAX_RECEIVE_BYTES) // RECORD_SIZE:
        raw = raw[:count * RECORD_SIZE]
    try:
        return received_packets(raw, transport)
    except ReplyFailure as invalid:
        return invalid.packets


def receive_packets(sock, timeout, completion_marker=None, *, read_evidence=None, transport):
    """Adapter for the pinned run() seam; no endpoint, lock or send changes."""
    started = time.monotonic()
    deadline = started + timeout
    stream = ReplyStream(transport)
    reason = 'deadline'
    try:
        while time.monotonic() < deadline:
            reason = 'receive_error'
            sock.settimeout(max(0.05, deadline - time.monotonic()))
            try:
                chunk = sock.recv(8192)
            except socket.timeout:
                reason = 'socket_timeout'
                break
            except ConnectionResetError:
                reason = 'connection_reset'
                break
            except ConnectionAbortedError:
                reason = 'connection_aborted'
                break
            if not chunk:
                reason = 'peer_eof'
                break
            reason = 'validation_failure'
            stream.feed(chunk)
            if stream.terminal_count:
                if stream.terminal_result != 0:
                    reason = 'native_terminal_failure'
                packets = stream.finish(completion_marker)
                reason = 'native_terminal_success'
                return packets
            reason = 'deadline'
        # EOF and timeout cannot turn a partial result into successful evidence.
        return stream.finish(completion_marker)
    except Exception as error:
        raise ReplyFailure(str(error), stream.packets) from error
    finally:
        if read_evidence is not None:
            read_evidence.update(stream.diagnostics(completion_marker), stop_reason=reason,
                                 elapsed_seconds=time.monotonic() - started)
