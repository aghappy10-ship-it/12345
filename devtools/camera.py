"""Bounded OS-only X2D II USB discovery, not a camera/debug transport.

No USB endpoint is opened, no Phocus SDK/controller is loaded, no photo/storage
access is performed and no device setting/driver/ADB state is changed. One fixed
present-PnP query proves OS presence; read-only local configuration-manager calls
supplement optional metadata without CIM property queries. Historical source
identity is labelled separately from current OS enumeration and live body proof.
"""
from __future__ import annotations
import base64
import ctypes
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from uuid import UUID

PROJECT = Path(__file__).resolve().parents[1]
PREFIX = r'USB\VID_2756&PID_000B'
IDENTITY = re.compile(r'\AUSB\\VID_2756&PID_000B(?:&MI_([0-9A-F]{2}))?\\[^\\]+\Z', re.I)
POWERSHELL = r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
QUERY_TIMEOUT_SECONDS = 8
MAX_QUERY_BYTES = 1024 * 1024
OFFICIAL_USB_RC = PROJECT.parent / 'x2d2/work/reverse/vendor/x2dii_1_3_16_2_system_root/etc/init/init.eagle2.usb.rc'
OFFICIAL_USB_SHA = '20280da06de47b0fc0ec784aacef9a291bc194833f48bcd8b8871b586c603fdc'
PRIOR_DISCOVERY = PROJECT.parent / 'x2d2/work/reverse/live_usb_mode_check_4_1_1.json'
PRIOR_DISCOVERY_SHA = '889e89deb6cef40ff3a73c52973832204915cd619d83e942e99133d73d18447f'

# One Get-PnpDevice snapshot is enough to prove OS presence. Optional properties
# must not turn this into 24 serial CIM calls or erase an observed USB identity.
OS_QUERY = r'''
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$all = @(Get-PnpDevice -PresentOnly -ErrorAction Stop)
$matched = @($all | Where-Object { $_.InstanceId -match '\AUSB\\VID_2756&PID_000B(?:&MI_[0-9A-F]{2})?\\[^\\]+\z' } | Sort-Object InstanceId)
$rows = @(foreach ($item in $matched) {
    [pscustomobject]@{
        InstanceId = [string]$item.InstanceId; Present = $true
        Class = $item.Class; FriendlyName = $item.FriendlyName
        Status = $item.Status; Problem = $item.Problem
        Parent = $null; ContainerId = $null; BusReportedDeviceDesc = $null
        Service = $item.Service; MetadataErrors = @()
    }
})
[pscustomobject]@{ Complete = $true; TotalPresent = $all.Count; Devices = $rows } | ConvertTo-Json -Depth 6 -Compress
'''


class _GUID(ctypes.Structure):
    _fields_ = [('Data1', ctypes.c_uint32), ('Data2', ctypes.c_uint16),
                ('Data3', ctypes.c_uint16), ('Data4', ctypes.c_ubyte * 8)]


class _DEVPROPKEY(ctypes.Structure):
    _fields_ = [('fmtid', _GUID), ('pid', ctypes.c_uint32)]


class _WindowsMetadataReader:
    """Only local CM_* metadata reads, always flags=0 (no phantom devnodes)."""

    def __init__(self):
        self.dll = ctypes.WinDLL('cfgmgr32.dll', winmode=0x800)  # System32 only.
        uint, pointer = ctypes.c_uint32, ctypes.POINTER
        signatures = {
            'CM_Locate_DevNodeW': [pointer(uint), ctypes.c_wchar_p, uint],
            'CM_Get_Parent': [pointer(uint), uint, uint],
            'CM_Get_Device_IDW': [uint, ctypes.c_wchar_p, uint, uint],
            'CM_Get_DevNode_PropertyW': [uint, pointer(_DEVPROPKEY), pointer(uint),
                                       ctypes.c_void_p, pointer(uint), uint],
        }
        for name, arguments in signatures.items():
            function = getattr(self.dll, name)
            function.argtypes, function.restype = arguments, uint

    @staticmethod
    def _check(code, operation):
        if code != 0:
            raise OSError(f'{operation} failed (CONFIGRET={code})')

    def _device_id(self, node):
        buffer = ctypes.create_unicode_buffer(1024)
        self._check(self.dll.CM_Get_Device_IDW(node, buffer, len(buffer), 0),
                    'CM_Get_Device_IDW')
        return buffer.value

    def _property(self, node, fmtid, pid, expected_type):
        key = _DEVPROPKEY(_GUID.from_buffer_copy(UUID(fmtid).bytes_le), pid)
        buffer = ctypes.create_string_buffer(4096)
        value_type, size = ctypes.c_uint32(), ctypes.c_uint32(len(buffer))
        self._check(self.dll.CM_Get_DevNode_PropertyW(node, ctypes.byref(key),
                    ctypes.byref(value_type), buffer, ctypes.byref(size), 0),
                    f'CM_Get_DevNode_PropertyW pid={pid}')
        if value_type.value != expected_type or not 0 < size.value <= len(buffer):
            raise ValueError('Native metadata has unexpected type or size')
        data = buffer.raw[:size.value]
        if expected_type == 0x0D:  # DEVPROP_TYPE_GUID
            if len(data) != 16:
                raise ValueError('Native container ID has invalid size')
            return str(UUID(bytes_le=data))
        return data.decode('utf-16le', errors='strict').rstrip('\x00')

    def __call__(self, instance_id):
        if not IDENTITY.fullmatch(instance_id):
            raise ValueError('Native metadata requires an audited present USB ID')
        node = ctypes.c_uint32()
        self._check(self.dll.CM_Locate_DevNodeW(ctypes.byref(node), instance_id, 0),
                    'CM_Locate_DevNodeW')
        actual_id = self._device_id(node.value)
        if actual_id.casefold() != instance_id.casefold():
            raise ValueError('Native devnode identity differs from requested USB ID')
        result = {'InstanceId': actual_id, 'Parent': None, 'ContainerId': None,
                  'BusReportedDeviceDesc': None, 'MetadataErrors': []}
        try:
            parent = ctypes.c_uint32()
            self._check(self.dll.CM_Get_Parent(ctypes.byref(parent), node.value, 0),
                        'CM_Get_Parent')
            result['Parent'] = self._device_id(parent.value)
        except (OSError, ValueError) as error:
            result['MetadataErrors'].append(str(error))
        for name, fmtid, pid, value_type in (
                ('ContainerId', '8c7ed206-3f8a-4827-b3ab-ae9e1faefc6c', 2, 0x0D),
                ('BusReportedDeviceDesc', '540b947e-8b40-45bc-a8a2-6a0b894cbda2', 4, 0x12)):
            try:
                result[name] = self._property(node.value, fmtid, pid, value_type)
            except (OSError, ValueError, UnicodeError) as error:
                result['MetadataErrors'].append(name + ': ' + str(error))
        result['Complete'] = not result['MetadataErrors']
        return result


def _supplement_metadata(payload, reader):
    """An optional OS-boundary failure cannot invalidate confirmed enumeration."""
    complete = True
    for raw in payload['Devices']:
        if not raw.get('Present') or not IDENTITY.fullmatch(raw['InstanceId']):
            continue
        errors = list(raw.get('MetadataErrors', []))
        try:
            metadata = reader(raw['InstanceId'])
            if type(metadata) is not dict or type(metadata.get('Complete')) is not bool:
                raise ValueError('Native metadata missing explicit completeness')
            identity = metadata.get('InstanceId')
            if type(identity) is not str or identity.casefold() != raw['InstanceId'].casefold():
                raise ValueError('Native metadata identity differs from requested USB ID')
            names = ('Parent', 'ContainerId', 'BusReportedDeviceDesc')
            if any(name not in metadata or (metadata[name] is not None and
                   type(metadata[name]) is not str) for name in names):
                raise ValueError('Native metadata fields must be string or null')
            native_errors = metadata.get('MetadataErrors', [])
            if type(native_errors) is not list or any(type(e) is not str for e in native_errors):
                raise ValueError('Native metadata errors must be a string array')
            raw.update({name: metadata[name] for name in names})
            errors.extend(native_errors)
            if not metadata['Complete']:
                complete = False
        except Exception as error:
            errors.append('Native metadata: ' + type(error).__name__ + ': ' + str(error)[:512])
            complete = False
        raw['MetadataErrors'] = errors
        if errors:
            complete = False
    return complete


def _provenance():
    sources = []
    for path, expected in ((OFFICIAL_USB_RC, OFFICIAL_USB_SHA), (PRIOR_DISCOVERY, PRIOR_DISCOVERY_SHA)):
        row = {'path': str(path), 'expected_sha256': expected, 'verified': False, 'historical': True}
        try:
            raw = path.read_bytes()
            actual = hashlib.sha256(raw).hexdigest()
            row.update(actual_sha256=actual, verified=actual == expected)
            if actual != expected:
                row['error'] = 'local identity evidence differs from pinned source'
        except OSError as error:
            row['error'] = str(error)
        sources.append(row)
    return {'audited_usb_prefix': PREFIX, 'mapped_product': 'X2D II 100C',
            'mapping_basis': 'pinned official USB rc vendor/product/product-string declarations plus historical discovery',
            'local_sources_verified': all(s['verified'] for s in sources), 'sources': sources,
            'historical_evidence_is_current_presence': False, 'current_body_firmware_identity_verified': False}


def _transport(rows, complete):
    def selected(predicate):
        return [row['instance_id'] for row in rows if predicate(row)]
    rndis = selected(lambda r: 'rndis' in (r['service'] or '').lower())
    network = selected(lambda r: (r['class'] or '').lower() == 'net')
    portable = selected(lambda r: (r['class'] or '').lower() == 'wpd')
    winusb = selected(lambda r: (r['service'] or '').lower() == 'winusb')
    serial = selected(lambda r: (r['service'] or '').lower() == 'usbser')
    storage = selected(lambda r: (r['service'] or '').lower() == 'usbstor')
    return {
        'usb_enumeration': {'state': 'observed' if rows else 'not_observed' if complete else 'unknown',
                            'pnp_only': True, 'endpoint_opened': False},
        'rndis': {'driver_instances': rndis, 'network_class_instances': network,
                  'network_reachability': 'not_tested', 'camera_protocol_connected': False},
        'mtp_ptp': {'portable_device_instances': portable, 'protocol_confirmed': False,
                    'storage_accessed': False},
        'winusb': {'driver_instances': winusb, 'endpoints_opened': False,
                   'protocol_handshake': 'not_tested'},
        'serial_acm': {'driver_instances': serial, 'port_opened': False},
        'mass_storage': {'driver_instances': storage, 'mounted_or_read_by_tool': False},
        'adb': {'state': 'not_probed', 'availability': None, 'enabled_by_tool': False,
                'identity_query_sent': False},
        'camera_debug': {'implemented': False, 'connected': False,
                        'reason': 'This module provides OS identification only; no authenticated camera command/file/debug transport.'}}


def _analyze(payload):
    if type(payload) is not dict or type(payload.get('Complete')) is not bool:
        raise ValueError('OS query missing explicit enumeration completeness')
    complete = payload['Complete']
    raw_rows = payload.get('Devices')
    if type(raw_rows) is not list or len(raw_rows) > 1024:
        raise ValueError('OS query Devices must be a bounded array')
    total = payload.get('TotalPresent')
    if type(total) is not int or total < len(raw_rows):
        raise ValueError('OS query present count is invalid')
    rows, seen = [], set()
    for raw in raw_rows:
        if type(raw) is not dict or type(raw.get('InstanceId')) is not str or type(raw.get('Present')) is not bool:
            raise ValueError('OS query device row is malformed')
        identity = IDENTITY.fullmatch(raw['InstanceId'])
        if not identity or not raw['Present']:
            continue
        folded = raw['InstanceId'].casefold()
        if folded in seen:
            continue
        seen.add(folded)
        values = {}
        for key, target in [('Class', 'class'), ('FriendlyName', 'friendly_name'), ('Status', 'status'),
                ('Parent', 'parent_instance_id'), ('ContainerId', 'container_id'),
                ('BusReportedDeviceDesc', 'bus_reported_description'), ('Service', 'service')]:
            value = raw.get(key)
            if value is not None and type(value) is not str:
                raise ValueError('OS metadata must be string or null: ' + key)
            values[target] = value
        problem = raw.get('Problem')
        if problem is not None and type(problem) not in (str, int):
            raise ValueError('OS PnP problem code is malformed')
        errors = raw.get('MetadataErrors', [])
        if type(errors) is not list or any(type(e) is not str for e in errors):
            raise ValueError('OS metadata error list is malformed')
        rows.append(dict(instance_id=raw['InstanceId'], present=True,
            interface='MI_' + identity.group(1).upper() if identity.group(1) else 'PARENT',
            problem=problem, metadata_errors=errors, **values))
    rows.sort(key=lambda r: (r['interface'], r['instance_id'].casefold()))
    parents = {r['instance_id'].casefold(): r for r in rows if r['interface'] == 'PARENT'}
    container_parents = {}
    for parent in parents.values():
        container = parent['container_id']
        if container and container.strip('{}0-'):
            container_parents.setdefault(container.casefold(), []).append(parent['instance_id'])
    groups = {}
    for row in rows:
        parent = row['instance_id'] if row['interface'] == 'PARENT' else row['parent_instance_id']
        row['physical_join_basis'] = 'self-parent' if row['interface'] == 'PARENT' else 'os-parent-property'
        candidates = container_parents.get((row['container_id'] or '').casefold(), [])
        if not parent and len(candidates) == 1:
            parent = candidates[0]
            row['physical_join_basis'] = 'os-container-id-to-unique-observed-parent'
        if parent and IDENTITY.fullmatch(parent) and not IDENTITY.fullmatch(parent).group(1):
            key = 'parent:' + parent.casefold()
        elif row['container_id'] and row['container_id'].strip('{}0-') and len(candidates) < 2:
            key = 'container:' + row['container_id'].casefold()
            row['physical_join_basis'] = 'os-container-id-parent-unobserved'
        else:
            key = 'unjoined:' + row['instance_id'].casefold()
            row['physical_join_basis'] = 'unjoined-or-ambiguous'
        group = groups.setdefault(key, {'group_id': key, 'parent_instance_id': parent if key.startswith('parent:') else None,
            'parent_observed': bool(parent and parent.casefold() in parents),
            'container_id': row['container_id'], 'instances': []})
        group['instances'].append(row['instance_id'])
    observed_name = any(re.search(r'\bX2D\s+II\s+100C\b', text, re.I) for r in rows
        for text in (r['friendly_name'] or '', r['bus_reported_description'] or ''))
    problems = any((r['status'] or '').lower() == 'error' or r['problem'] not in (None, 0, '0', 'CM_PROB_NONE') for r in rows)
    unknown_status = any(not r['status'] or r['status'].lower() not in ('ok', 'error') for r in rows)
    present = bool(rows) if rows or complete else None
    return dict(enumeration={'complete': complete, 'total_present_pnp_instances': total},
        present=present, absence_conclusive=complete and not rows,
        identification_level='audited_usb_vid_pid' if rows else 'not_detected' if complete else 'unknown',
        device_state='usb_enumerated_with_pnp_problem' if rows and problems else
            'usb_enumerated_status_unknown' if rows and unknown_status else
            'usb_enumerated' if rows else 'not_detected' if complete else 'unknown',
        model_name_observed_in_os_metadata=observed_name, matched_instance_count=len(rows),
        instances=rows, physical_devices=list(groups.values()), transport=_transport(rows, complete))


def discover(*, runner=None, metadata_reader=None):
    """Return JSON-safe host facts with separate enumeration/metadata OS seams.

    metadata_reader(instance_id) returns identity-bound CM metadata. An injected
    runner never causes real native probing unless a reader is explicitly given.

    Failure means unknown presence, never a false no-camera assertion. Successful
    empty present enumeration is the only conclusive absence. No cached live
    report is ever substituted for a current query.
    """
    report = {'schema': 'x2dii-devtools-os-discovery-v1',
        'timestamp_utc': datetime.now(timezone.utc).isoformat(),
        'status': 'discovery_failed', 'present': None, 'absence_conclusive': False,
        'identification_level': 'unknown', 'debug_connected': False,
        'camera_contacted': False, 'camera_written': False, 'photos_read': False,
        'transport': _transport([], False), 'identity_basis': _provenance(),
        'metadata': {'complete': False, 'backend': 'not_run', 'read_only': True}}
    if os.name != 'nt':
        report.update(error='Windows present-PnP discovery is unavailable on this platform',
                      enumeration={'complete': False})
        return report
    encoded = base64.b64encode(OS_QUERY.encode('utf-16le')).decode('ascii')
    command = [POWERSHELL, '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded]
    query = runner or subprocess.run
    try:
        # Binary capture avoids Windows subprocess reader-thread decode errors
        # being lost while the main thread accepts otherwise valid stdout.
        result = query(command, capture_output=True, text=False,
            timeout=QUERY_TIMEOUT_SECONDS, shell=False, creationflags=subprocess.CREATE_NO_WINDOW)
        if type(result.stdout) is not bytes or type(result.stderr) is not bytes:
            raise ValueError('OS query must return captured bytes')
        report['query'] = {'kind': 'fixed-windows-present-pnp',
            'timeout_seconds': QUERY_TIMEOUT_SECONDS,
            'source_sha256': hashlib.sha256(OS_QUERY.encode('utf-8')).hexdigest(),
            'arbitrary_command_supported': False, 'stdout_bytes': len(result.stdout),
            'stdout_sha256': hashlib.sha256(result.stdout).hexdigest(),
            'stderr_bytes': len(result.stderr), 'stderr_sha256': hashlib.sha256(result.stderr).hexdigest()}
        if result.returncode != 0:
            raise RuntimeError('Fixed OS PnP query failed: ' + result.stderr[-2048:].decode('utf-8', errors='replace'))
        if result.stderr:
            report['query']['stderr_diagnostic_lossy_utf8'] = result.stderr[:2048].decode('utf-8', errors='replace')
        if len(result.stdout) > MAX_QUERY_BYTES:
            raise ValueError('OS query output is missing or oversized')
        stdout = result.stdout.decode('utf-8', errors='strict')
        def unique(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError('duplicate OS JSON field: ' + key)
                value[key] = item
            return value
        payload = json.loads(stdout.lstrip('\ufeff'), object_pairs_hook=unique)
        report.update(_analyze(payload))
        if report['present']:
            reader = metadata_reader
            if reader is None and runner is None:
                try:
                    reader = _WindowsMetadataReader()
                except (OSError, AttributeError) as error:
                    report['metadata']['error'] = type(error).__name__ + ': ' + str(error)[:512]
            if reader is not None:
                report['metadata'].update(backend='windows-config-manager-readonly' if
                    metadata_reader is None else 'injected-reader',
                    complete=_supplement_metadata(payload, reader))
                report.update(_analyze(payload))
            else:
                report['metadata']['backend'] = 'skipped-injected-query' if runner is not None else 'unavailable'
        elif report['absence_conclusive']:
            report['metadata'].update(complete=True, backend='no-present-matches')
        report['status'] = 'usb_identified' if report['present'] else 'not_detected' if report['absence_conclusive'] else 'discovery_incomplete'
    except subprocess.TimeoutExpired:
        report.update(error=f'OS USB enumeration timed out after {QUERY_TIMEOUT_SECONDS} seconds; presence remains unknown.',
                      enumeration={'complete': False})
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, UnicodeError) as error:
        report.update(error=type(error).__name__ + ': ' + str(error), enumeration={'complete': False})
    report['finished_utc'] = datetime.now(timezone.utc).isoformat()
    return report


if __name__ == '__main__':
    if len(sys.argv) != 1:
        raise SystemExit('camera discovery accepts no commands or device actions')
    result = discover()
    print(json.dumps(result, ensure_ascii=True, indent=2))
    raise SystemExit(0 if result.get('enumeration', {}).get('complete') else 1)
