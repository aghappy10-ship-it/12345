"""Stage/launch only the explicitly approved, hash-pinned temporary ADB worker.

Not a firmware installer. No system files, services, persistent properties,
drivers or extension payloads are written. Uses the already reviewed transport.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import secrets
import tempfile

from . import live_readout as live
from .output_guard import PROJECT, guard_output, output_directory, write_output

SCRIPT = PROJECT / 'build/peer-usb-access/temporary-usb-adb.sh'
SCRIPT_SHA = 'b7bc82e4db70e74250b72f5580fa2588b754cfbe5fc81d736b04424872a60e56'
BASE = 'rndis,mass_storage,bulk,acm'
TRANSPORT_PRODUCERS = (
    ('msg2dbus', 'eb65334f497c12f63e73528973b734e3e79078de885f43f2a0be67ba93080765'),
    ('camera-test', 'd018fee011426aefef1ded0bd2554ec6f4d31ea0b2529b63f9d5baddc44c42e0'),
)


def need(ok, message):
    if not ok:
        raise ValueError(message)


def envelope(command, token):
    rc, end = '__RC_' + token + '__', '__RD_' + token + '__'
    framed = command + ";printf '\\n" + rc + "%s\\n" + end + "\\n' $?"
    need(len(framed.encode()) < 232, 'fixed command exceeds transport capacity')
    return framed, rc, end


def validate_script():
    raw = SCRIPT.read_bytes()
    need(hashlib.sha256(raw).hexdigest() == SCRIPT_SHA, 'reviewed USB worker changed')
    return raw


def stage_commands(root, raw):
    need(re.fullmatch(r'/tmp/x2a-[0-9a-f]{12}', root), 'unexpected temporary directory')
    need(hashlib.sha256(raw).hexdigest() == SCRIPT_SHA, 'unreviewed payload')
    encoded = base64.b64encode(raw).decode('ascii')
    commands = [f'umask 077;mkdir -m 700 {root}']
    # Each block is exclusively created. No later command appends to or
    # deletes an earlier pathname that might now identify a different file.
    chunks = [encoded[i:i+96] for i in range(0, len(encoded), 96)]
    need(len(chunks) <= 1000, 'fixed worker exceeds three-digit block layout')
    commands += [f"(set -C;umask 077;printf %s '{chunk}' >{root}/p{index:03d})"
                 for index, chunk in enumerate(chunks)]
    commands += [f'(set -C;umask 077;cat {root}/p??? | base64 -d >{root}/s) && sh -n {root}/s',
                 f'sha256sum {root}/s']
    for command in commands:
        envelope(command, '123456abcdef')
    return commands


class Session:
    def __init__(self, folder, report):
        self.folder, self.report = folder, report
        self.transport = live.load_transport()
        sources = live.source_hashes()
        stager_sha = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        if report.get('commands') or 'replySources' in report or 'stagerSha256' in report:
            need(report.get('replySources') == sources and report.get('stagerSha256') == stager_sha,
                 'session source attribution missing or changed; existing evidence cannot be reused')
        else:
            self.report['replySources'] = sources
            self.report['stagerSha256'] = stager_sha

    def save(self):
        write_output(self.folder / 'SESSION.json', (json.dumps(self.report, indent=2) + '\n').encode())

    def command(self, label, command):
        index = len(self.report['commands']) + 1
        name = f'{index:03d}-{label}'
        wire, rc, end = envelope(command, secrets.token_hex(6))
        self.transport.socket.chunks.clear()
        packets, receive = [], {}
        row = {'label': label, 'command': command, 'utc': datetime.now(timezone.utc).isoformat()}
        self.report['commands'].append(row)
        self.save()
        try:
            packets, _ = self.transport.run(wire, 8, completion_marker=end, read_evidence=receive)
            observed = live.received_packets(b''.join(self.transport.socket.chunks), self.transport)
            need(observed == packets, 'retained/raw packet mismatch')
            text = ''.join(live.validate_packet(p, self.transport) for p in observed)
            tail = re.search(r'\n' + re.escape(rc) + r'(0|[1-9][0-9]{0,2})\r?\n' + re.escape(end) + r'\r?\n\Z', text)
            # Only terminated standalone records count; logged/quoted tokens are output.
            # Reserve RC-prefixed lines even when malformed, so they cannot hide a duplicate.
            rc_count = len(re.findall(r'(?:^|\n)' + re.escape(rc) + r'[^\r\n]*\r?(?=\n)', text))
            end_count = self.transport.completion_line_count(text, end)
            need(rc_count == end_count == 1 and tail is not None and int(tail[1]) <= 255,
                 'missing, duplicated or invalid completion')
            row['exit'] = int(tail[1])
            row['text'] = text[:tail.start()]
            need(row['exit'] == 0, 'camera command returned ' + str(row['exit']))
            return row['text']
        except Exception as error:
            packets = live.factory_reply.failure_packets(
                error, b''.join(self.transport.socket.chunks), self.transport, receive)
            row['error'] = str(error)
            raise
        finally:
            raw = b''.join(self.transport.socket.chunks)
            write_output(self.folder / (name + '.received.bin'), raw)
            write_output(self.folder / (name + '.packets.bin'), b''.join(packets))
            row['rawSha256'] = hashlib.sha256(raw).hexdigest()
            row['receive'] = receive
            self.save()


def preflight(session):
    # Decode this harmless query first, then bind the format to the currently
    # running executables before either staging or launch can mutate anything.
    # A launch repeats this gate; it is not an ongoing process-lifetime claim.
    session.report['transportExecutableBinding'] = {
        'verifiedDuringThisPreflight': False, 'ongoingProcessLifetimeProven': False,
        'executables': {},
    }
    digest_lines = session.command('transport-hash', live.QUERIES['transport_hash']).splitlines()
    need(len(digest_lines) == 2, 'ambiguous active transport executables')
    producers = {}
    for line, (name, expected) in zip(digest_lines, TRANSPORT_PRODUCERS):
        match = re.fullmatch(r'([0-9a-f]{64})  (/proc/([1-9][0-9]*)/exe)', line)
        need(match is not None and match[1] == expected, 'unrecognized active transport executable: ' + name)
        producers[name] = {'sha256': match[1], 'path': match[2], 'pid': int(match[3])}
    need(producers['msg2dbus']['pid'] != producers['camera-test']['pid'], 'ambiguous active transport PIDs')
    session.report['transportExecutableBinding'] = {
        'verifiedDuringThisPreflight': True, 'ongoingProcessLifetimeProven': False,
        'executables': producers,
    }
    boot = session.command('boot-id', 'cat /proc/sys/kernel/random/boot_id').strip()
    need(re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', boot), 'invalid boot id')
    state = session.command('usb-state', 'getprop sys.usb.config;getprop sys.usb.state;getprop init.svc.adbd')
    need(state.splitlines() == [BASE, BASE, 'stopped'], 'USB baseline changed')
    need(session.command('uid', 'id -u').strip() == '0', 'maintenance UID changed')
    need(session.command('lock-absent', '[ ! -e /tmp/x2dii-peer-adb.lock ] && [ ! -L /tmp/x2dii-peer-adb.lock ]') == '', 'unexpected lock response')
    return boot


def recorded_launch_start(report):
    """Extract the existing command's pre-send time, without renewing a window.

    This reads retained data only and is not proof of current connection,
    consent, restoration or report authenticity. Old `launchUtc` is a reply
    timestamp and must never be used to extend the original device timer.
    """
    need(type(report) is dict and report.get('scriptSha256') == SCRIPT_SHA and
         report.get('usbLaunchRequested') is True, 'recorded original USB launch required')
    root = report.get('remote')
    need(type(root) is str and re.fullmatch(r'/tmp/x2a-[0-9a-f]{12}', root), 'unexpected recorded launch path')
    pid = report.get('launcherPid')
    need(type(pid) is int and 0 < pid < 2**31, 'unambiguous recorded launcher PID required')
    history = report.get('commands')
    need(type(history) is list and all(type(row) is dict for row in history), 'recorded command history required')
    rows = [row for row in history if row.get('label') == 'launch']
    need(len(rows) == 1, 'one original launch command required; do not infer from a later reply')
    row = rows[0]
    expected = f'umask 077;nohup sh {root}/s --approved-temporary-usb-access >{root}/log 2>&1 </dev/null & echo $!'
    need(row.get('command') == expected and type(row.get('exit')) is int and row['exit'] == 0 and
         row.get('text') == str(pid) + '\n' and 'error' not in row,
         'recorded launch completion or fixed command differs')
    need(type(row.get('utc')) is str, 'pre-command launch timestamp required')
    started = datetime.fromisoformat(row['utc'])
    need(started.tzinfo is not None, 'timezone-aware pre-command launch timestamp required')
    if 'launchStartedUtc' in report:
        need(report['launchStartedUtc'] == row['utc'], 'launch start alias is not the original command time')
    return started


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('stage', 'launch'))
    parser.add_argument('--approved-temporary-usb-access', action='store_true', required=True)
    parser.add_argument('--session', type=Path)
    args = parser.parse_args()
    raw = validate_script()
    if args.action == 'stage':
        need(args.session is None, 'stage always creates a new session')
        folder = Path(tempfile.mkdtemp(prefix='run-', dir=output_directory(PROJECT / 'build/peer-usb-live')))
        report = {'schema': 'x2dii-approved-temporary-adb-session-v1', 'status': 'PREFLIGHT',
                  'authorization': 'User approved temporary original ADB verification only; no extension installation.',
                  'scriptSha256': SCRIPT_SHA, 'remote': '/tmp/x2a-' + secrets.token_hex(6),
                  'cameraTemporaryFilesWritten': False, 'usbLaunchRequested': False,
                  'extensionInstalled': False, 'commands': []}
    else:
        need(args.session is not None, 'launch requires the exact staged session')
        path = guard_output(args.session, PROJECT / 'build/peer-usb-live')
        folder = path.parent
        report = json.loads(path.read_text())
        need(report['status'] == 'STAGED_NOT_STARTED' and report['scriptSha256'] == SCRIPT_SHA, 'session is not staged')
        need(re.fullmatch(r'/tmp/x2a-[0-9a-f]{12}', report['remote']), 'unrecognized staged directory')
    session = Session(folder, report)
    print(json.dumps({'session': str(folder / 'SESSION.json'), 'action': args.action}), flush=True)
    try:
        boot = preflight(session)
        if args.action == 'stage':
            report['bootId'] = boot
            report['cameraTemporaryFilesWritten'] = True  # Conservative before first attempted write.
            for i, command in enumerate(stage_commands(report['remote'], raw)):
                output = session.command('stage-' + str(i), command)
            need(output.strip() == SCRIPT_SHA + '  ' + report['remote'] + '/s', 'remote script hash mismatch')
            report['status'] = 'STAGED_NOT_STARTED'
        else:
            need(boot == report['bootId'], 'camera rebooted since staging')
            root = report['remote']
            digest = session.command('recheck-script', f'sha256sum {root}/s')
            need(digest.strip() == SCRIPT_SHA + '  ' + root + '/s', 'staged script changed')
            session.command('check-syntax', f'sh -n {root}/s')
            report['usbLaunchRequested'] = True
            report['status'] = 'LAUNCH_REQUESTED_AWAITING_REAL_USB_EVIDENCE'
            session.save()
            pid = session.command('launch', f'umask 077;nohup sh {root}/s --approved-temporary-usb-access >{root}/log 2>&1 </dev/null & echo $!')
            need(re.fullmatch(r'[1-9][0-9]*\n', pid), 'ambiguous launcher PID')
            report['launcherPid'] = int(pid)
            report['launchUtc'] = datetime.now(timezone.utc).isoformat()
            report['launchStartedUtc'] = recorded_launch_start(report).isoformat()
    except Exception as error:
        report['status'] = 'FAILED_OR_UNCERTAIN_DO_NOT_RETRY_AUTOMATICALLY'
        report['error'] = str(error)
        raise
    finally:
        session.save()
    print(json.dumps({'status': report['status'], 'session': str(folder / 'SESSION.json')}), flush=True)


if __name__ == '__main__':
    main()
