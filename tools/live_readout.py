"""Fixed, read-only menu qualification queries over the existing USB network.

Never uploads, remounts, changes properties, starts/stops services or triggers
capture. Uses the separately inspected, hash-pinned historical transport only;
does not invoke its command-line runner or any historical probe/installer.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from functools import partial
import hashlib
import json
from pathlib import Path
import re
import secrets
import socket
import tempfile
import types

try:
    from .output_guard import PROJECT, output_directory, write_output
    from . import factory_reply
    from .observation_query_bridge import SINGLE_QUERY_COMMANDS
except ImportError:
    from output_guard import PROJECT, output_directory, write_output
    import factory_reply
    from observation_query_bridge import SINGLE_QUERY_COMMANDS

TRANSPORT = PROJECT.parent / 'x2d2/work/reverse/x2d2_root_tcphost.py'
TRANSPORT_SHA = 'daedb6b38e8825a63e9ab6939119e9312eff4469ac6a84838225b0c7207455dc'
QUERIES = {
    'identity': 'id;cat /proc/self/attr/current;getprop ro.product.model;getprop ro.dji.build.version;cat /proc/sys/kernel/random/boot_id',
    'boot': 'cat /proc/cmdline;getprop sys.usb.state;pidof camera-gui;pidof camera-service',
    'slot1': 'unrd slot_1.status_active;unrd slot_1.status_bootable;unrd slot_1.status_successful',
    'slot2': 'unrd slot_2.status_active;unrd slot_2.status_bootable;unrd slot_2.status_successful',
    'mounts': 'cat /proc/mounts',
    'gui_hash': 'sha256sum /system/bin/camera-gui /system/etc/init/camera-gui.rc',
    'service_hash': 'sha256sum /system/bin/camera-service /system/etc/imx861bqr_hb722.conf',
    'transport_hash': 'sha256sum /proc/$(pidof msg2dbus)/exe /proc/$(pidof camera-test)/exe',
    'library_hash': 'sha256sum /system/lib64/libc.so /system/lib64/libdl.so',
    'gui_init': 'cat /system/etc/init/camera-gui.rc',
    'gui_process': 'p=$(pidof camera-gui);cat /proc/$p/attr/current;readlink /proc/$p/exe;cat /proc/$p/status',
    'gui_maps': 'p=$(pidof camera-gui);grep -E "camera-gui|Qt6Qml|Qt6Quick|libx2d|menu" /proc/$p/maps',
    'gui_environment': 'p=$(pidof camera-gui);tr "\\0" "\\n" </proc/$p/environ|grep -E "^(LD_|QML_|QT_|X2D)"',
    'file_metadata': 'ls -ldZ /system/etc/init /system/etc/init/camera-gui.rc /system/lib64 /dev /blackbox',
    'extension_paths': 'ls -lZ /system/lib64/libx2dii_menu.so /system/etc/X2d2Menu*.qml /dev/x2dii-menu* /blackbox/x2dii-menu.disable',
    'runtime_after': 'cat /proc/sys/kernel/random/boot_id;cat /proc/uptime;pidof camera-gui;pidof camera-service',
    'tmp_metadata': 'ls -ldZ /tmp;stat -c "%u %g %a %h %s %n" /tmp /dev /system/etc/init/camera-gui.rc',
    'gui_lifetime': 'p=$(pidof camera-gui);cat /proc/$p/stat;readlink /proc/$p/ns/mnt;readlink /proc/self/ns/mnt',
    'gui_mounts': 'p=$(pidof camera-gui);cat /proc/$p/mounts',
    'gui_cache': None,  # Generated only from a preceding hash/lifetime/maps read.
    'gui_auxv': 'p=$(pidof camera-gui);od -An -tx8 /proc/$p/auxv',
    'selinux_policy': 'getenforce;sha256sum /sys/fs/selinux/policy /system/etc/selinux/plat_sepolicy.cil /vendor/etc/selinux/vendor_sepolicy.cil',
    'tmp_extension_paths': 'ls -lZ /tmp/x2dii-menu*',
    'shell_arithmetic': 'echo $((0x100000000));echo $((0x7fffffffff+1))',
    'adb_state': 'getprop sys.usb.config;getprop sys.usb.state;getprop init.svc.adbd;getprop service.adb.tcp.port;pidof adbd',
    'usb_functions': 'ls -l /sys/kernel/config/usb_gadget/g1/configs/c.1;cat /sys/kernel/config/usb_gadget/g1/UDC',
    'maintenance_tools': 'command -v su;command -v runcon;command -v dbus-send;command -v unshare;ls -lZ /system/bin/su /system/xbin/su',
    'listen_sockets': 'cat /proc/net/tcp /proc/net/tcp6',
    'su_identity': '/system/xbin/su 0 /system/bin/sh -c "id;cat /proc/self/attr/current"',
    'install_tools': 'for t in sh stat sha256sum cp chmod chown chcon mv sync mount getprop pidof unrd getfattr;do command -v $t||echo MISSING:$t;done',
    'install_aux_tools': 'for t in stop start grep cut touch ls cat mkdir rmdir rm sleep readlink nohup base64 printf;do command -v $t||echo MISSING:$t;done',
    'rc_metadata': 'stat -c "%u %g %a %h %s %n" /system/etc/init/camera-gui.rc;ls -Zd /system/etc/init/camera-gui.rc',
    'install_tool_flags': 'cp --help;mv --help;sync --help',
}
QUERIES.update(SINGLE_QUERY_COMMANDS)


def cache_command(context):
    if context is None: raise ValueError('cache read requires current baseline context')
    expected = 'b1b643cb36176cd5a49129dd9bb2be480aa045a96ed1c35c30a779ab5af0801b'
    if expected + '  /system/bin/camera-gui' not in context['gui_hash'].splitlines():
        raise ValueError('unknown current GUI baseline')
    lifetime = re.match(r'([1-9][0-9]*) \(camera-gui\) ', context['gui_lifetime'])
    if not lifetime: raise ValueError('ambiguous GUI process')
    u64_max = (1 << 64) - 1
    maps = []
    for line in context['gui_maps'].splitlines():
        fields = line.split()
        if len(fields) != 6 or fields[-1] != '/system/bin/camera-gui':
            raise ValueError('unexpected GUI mapping')
        start, end = fields[0].split('-')
        start, end, offset = int(start, 16), int(end, 16), int(fields[2], 16)
        if not 0 <= start < end <= u64_max or not 0 <= offset <= u64_max:
            raise ValueError('GUI mapping outside unsigned 64-bit range')
        if maps and start < maps[-1][1]:
            raise ValueError('unordered or overlapping GUI mappings')
        maps.append((start, end, fields[1], offset))
    bases = [start for start, end, flags, offset in maps if flags == 'r-xp' and offset == 0]
    if len(bases) != 1: raise ValueError('ambiguous GUI image base')
    address = bases[0] + 0x29d4b80
    read_end = address + 24
    # Both half-open endpoints must fit in u64; do not admit a 2**64 sentinel.
    if not 0 <= address < read_end <= u64_max or address % 8:
        raise ValueError('invalid unsigned 64-bit or unaligned cache address')
    if not any(start <= address and read_end <= end and 'r' in flags for start, end, flags, offset in maps):
        raise ValueError('cache not in current mapped image')
    # Compute large pointers in the host: the target shell may use 32-bit
    # arithmetic even though the camera is ARM64. Never truncate an address.
    return f'od -An -tx8 -j {address} -N24 /proc/{lifetime[1]}/mem'


class RecordedSocket:
    """Passive raw receive tap; the local receiver bounds and counts every read."""
    def __init__(self, wrapped, chunks):
        self.wrapped, self.chunks = wrapped, chunks
    def __getattr__(self, name):
        return getattr(self.wrapped, name)
    def __enter__(self):
        self.wrapped.__enter__()
        return self
    def __exit__(self, *args):
        return self.wrapped.__exit__(*args)
    def recv(self, size):
        chunk = self.wrapped.recv(size)
        self.chunks.append(chunk)
        return chunk


class RecordedNetwork:
    def __init__(self):
        self.chunks = []
    def __getattr__(self, name):
        return getattr(socket, name)
    def create_connection(self, address, *args, **kwargs):
        if address != ('192.168.42.2', 30303):
            raise ValueError('unexpected device endpoint')
        return RecordedSocket(socket.create_connection(address, *args, **kwargs), self.chunks)


class QueryFailure(ValueError):
    def __init__(self, message, raw, packets, receive):
        super().__init__(message)
        self.raw, self.packets, self.receive = raw, packets, receive


def load_transport():
    raw = TRANSPORT.read_bytes()
    if hashlib.sha256(raw).hexdigest() != TRANSPORT_SHA:
        raise ValueError('reviewed transport changed')
    # -B prevents cache writes, not reads. Execute exactly the bytes just
    # verified, never an existing timestamp-valid historical .pyc file.
    module = types.ModuleType('x2dii_reviewed_transport')
    module.__file__ = str(TRANSPORT)
    exec(compile(raw, str(TRANSPORT), 'exec'), module.__dict__)
    module.socket = RecordedNetwork()
    # Explicit local receive adapter. Frozen run/build/locking/socket arguments
    # remain intact, but its historical magic-scanning receiver is not used.
    module.receive_packets = partial(factory_reply.receive_packets, transport=module)
    return module


def validate_packet(packet: bytes, transport) -> str:
    return factory_reply.decode_packet(packet, transport)[2]


def received_packets(raw: bytes, transport) -> list[bytes]:
    """Check complete native records, including bytes after completion."""
    return factory_reply.received_packets(raw, transport)


def source_hashes():
    return {'transportSha256': TRANSPORT_SHA,
            'collectorSha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'replyDecoderSha256': hashlib.sha256(Path(factory_reply.__file__).read_bytes()).hexdigest()}


def query(name: str, transport, timeout=8, *, context=None):
    token = secrets.token_hex(6)
    end = '__RD_' + token + '__'
    rc = '__RC_' + token + '__'
    base_command = cache_command(context) if name == 'gui_cache' else QUERIES[name]
    # /proc/self/attr/current has no trailing newline. Frame independently of
    # payload termination, expanding the previous status before printf runs.
    command = base_command + ";printf '\\n" + rc + "%s\\n" + end + "\\n' $?"
    if len(command.encode()) >= transport.SUTEST_TEXT_CAPACITY:
        raise ValueError('fixed query too long: ' + name)
    receive = {}
    packets = []
    transport.socket.chunks.clear()
    try:
        packets, _ = transport.run(command, timeout, completion_marker=end, read_evidence=receive)
        wire_packets = received_packets(b''.join(transport.socket.chunks), transport)
        if wire_packets != packets:
            raise ValueError('retained replies do not match recorded receive bytes')
        text = ''.join(validate_packet(p, transport) for p in wire_packets)
        ordered = re.search(r'\n' + re.escape(rc) + r'(0|[1-9][0-9]{0,2})\r?\n' + re.escape(end) + r'\r?\n\Z', text)
        # Only terminated standalone records count; logged/quoted tokens are output.
        # Reserve RC-prefixed lines even when malformed, so they cannot hide a duplicate.
        rc_count = len(re.findall(r'(?:^|\n)' + re.escape(rc) + r'[^\r\n]*\r?(?=\n)', text))
        end_count = transport.completion_line_count(text, end)
        if rc_count != 1 or end_count != 1 or ordered is None or int(ordered[1]) > 255:
            raise ValueError('missing unique query completion and exit status: ' + name)
    except Exception as error:
        raw = b''.join(transport.socket.chunks)
        packets = factory_reply.failure_packets(error, raw, transport, receive)
        raise QueryFailure(str(error), raw, b''.join(packets), receive) from error
    clean = text[:ordered.start()]
    return {'name': name, 'command': base_command, 'shellLastExitCode': int(ordered[1]),
            'text': clean, 'packets': b''.join(packets),
            'rawReceived': b''.join(transport.socket.chunks), 'receive': receive,
            'validatedReceivedPacketCount': len(wire_packets), 'relayTailsFullyExplained': False}


def collect(names):
    transport = load_transport()
    root = output_directory(PROJECT / 'build/live-readout')
    destination = Path(tempfile.mkdtemp(prefix='run-', dir=root))
    report = {'schema': 'x2dii-menu-readonly-readout-v1', 'startedUtc': datetime.now(timezone.utc).isoformat(),
              **source_hashes(),
              'endpoint': '192.168.42.2:30303', 'cameraWritten': False, 'captureTriggered': False,
              'installable': False, 'status': 'INCOMPLETE', 'queries': {}, 'output': str(destination)}
    def save():
        write_output(destination / 'READOUT.json', (json.dumps(report, indent=2) + '\n').encode())
    save()
    for index, name in enumerate(names, 1):
        record_name = f'{index:03d}-{name}'
        try:
            if name == 'gui_cache':
                context = {r['name']: r['text'] for r in report['queries'].values()
                           if r.get('shellLastExitCode') == 0}
                result = query(name, transport, context=context)
            else:
                result = query(name, transport)
            packets = result.pop('packets')
            raw = result.pop('rawReceived')
            write_output(destination / (record_name + '.txt'), result['text'].encode())
            write_output(destination / (record_name + '.packets.bin'), packets)
            write_output(destination / (record_name + '.received.bin'), raw)
            result['retainedPacketsSha256'] = hashlib.sha256(packets).hexdigest()
            result['rawReceivedSha256'] = hashlib.sha256(raw).hexdigest()
            result['rawReceivedBytes'] = len(raw)
            report['queries'][record_name] = result
            print(json.dumps({'query': name, 'exit': result['shellLastExitCode'],
                              'bytes': len(result['text'].encode()), 'output': str(destination)}), flush=True)
        except Exception as error:
            report['queries'][record_name] = {'error': type(error).__name__ + ': ' + str(error)}
            if isinstance(error, QueryFailure):
                write_output(destination / (record_name + '.received.bin'), error.raw)
                write_output(destination / (record_name + '.packets.bin'), error.packets)
                report['queries'][record_name]['receive'] = error.receive
            report['status'] = 'TRANSPORT_OR_VALIDATION_FAILURE'
            save()
            raise
        save()
    if hashlib.sha256(TRANSPORT.read_bytes()).hexdigest() != TRANSPORT_SHA:
        raise ValueError('transport changed during collection')
    report['status'] = 'FIXED_READOUT_COMPLETE_NOT_QUALIFICATION'
    report['finishedUtc'] = datetime.now(timezone.utc).isoformat()
    save()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('queries', choices=list(QUERIES), nargs='+')
    args = parser.parse_args()
    report = collect(args.queries)
    print(json.dumps({'status': report['status'], 'output': report['output'], 'installable': False}))


if __name__ == '__main__':
    main()
