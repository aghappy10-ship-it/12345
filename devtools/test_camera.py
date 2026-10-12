"""Discovery public seam; replace only the external OS process boundary."""
import json
import base64
import os
import subprocess
import unittest
from unittest.mock import patch

try:
    from . import camera
    from .camera import discover
except ImportError:
    import camera
    from camera import discover


class CameraTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'nt', 'WindowsPowerShell-only OS boundary')
    def test_windows_query_identifies_present_camera_without_property_cmdlet(self):
        """Execute the real query; only its two OS command boundaries are fake."""
        fake_pnp = r'''
function Get-PnpDevice {
    [CmdletBinding()] param([switch]$PresentOnly)
    [pscustomobject]@{
        InstanceId='USB\VID_2756&PID_000B\SYNTHETIC'; Class='USB'
        FriendlyName='Synthetic camera'; Status='OK'; Problem=0; Service='usbccgp'
    }
}
function Get-PnpDeviceProperty {
    [CmdletBinding()] param([string]$InstanceId, [string]$KeyName)
    [Console]::Error.WriteLine('PROHIBITED_PROPERTY_QUERY')
    throw 'Synthetic unavailable metadata provider'
}
'''
        def synthetic_os(command, **kwargs):
            source = base64.b64decode(command[-1]).decode('utf-16le')
            synthetic_command = [*command[:-1], base64.b64encode(
                (fake_pnp + source).encode('utf-16le')).decode('ascii')]
            result = subprocess.run(synthetic_command, **kwargs)
            self.assertNotIn(b'PROHIBITED_PROPERTY_QUERY', result.stderr)
            return result
        result = discover(runner=synthetic_os)
        self.assertTrue(result['present'], result.get('error'))
        self.assertEqual(result['instances'][0]['service'], 'usbccgp')

    def test_generic_present_parent_is_usb_identified_not_debug_connected(self):
        calls = []
        def os_query(command, **kwargs):
            calls.append((command, kwargs))
            data = {'Complete': True, 'TotalPresent': 401, 'Devices': [
                {'InstanceId': r'USB\VID_2756&PID_000B\BODY', 'Present': True,
                 'Class': 'USB', 'FriendlyName': '', 'Status': 'OK', 'Problem': 0,
                 'Parent': r'USB\ROOT_HUB30\ROOT', 'ContainerId': 'body-container',
                 'BusReportedDeviceDesc': 'X2D II 100C', 'Service': 'usbccgp'}]}
            return subprocess.CompletedProcess(command, 0, json.dumps(data).encode('utf-8'), b'')
        result = discover(runner=os_query)
        self.assertTrue(result['present'])
        self.assertEqual(result['identification_level'], 'audited_usb_vid_pid')
        self.assertFalse(result['debug_connected'])
        self.assertFalse(result['transport']['camera_debug']['implemented'])
        self.assertFalse(calls[0][1]['shell'])
        self.assertLessEqual(calls[0][1]['timeout'], 10)

    def query(self, rows, *, complete=True, total=401):
        def os_query(command, **kwargs):
            return subprocess.CompletedProcess(command, 0,
                json.dumps({'Complete': complete, 'TotalPresent': total, 'Devices': rows}).encode('utf-8'), b'')
        return discover(runner=os_query)

    def test_optional_native_metadata_failure_never_erases_observed_presence(self):
        payload = {'Complete': True, 'TotalPresent': 1, 'Devices': [{
            'InstanceId': r'USB\VID_2756&PID_000B&MI_02\SYNTHETIC',
            'Present': True, 'Status': 'Error', 'Problem': 28}]}
        def os_query(command, **kwargs):
            return subprocess.CompletedProcess(command, 0, json.dumps(payload).encode('utf-8'), b'')
        def unavailable_metadata(instance_id):
            raise OSError('synthetic configuration manager unavailable')
        result = discover(runner=os_query, metadata_reader=unavailable_metadata)
        self.assertTrue(result['present'])
        self.assertEqual(result['status'], 'usb_identified')
        self.assertEqual(result['device_state'], 'usb_enumerated_with_pnp_problem')
        self.assertFalse(result['metadata']['complete'])
        self.assertIn('configuration manager unavailable', result['instances'][0]['metadata_errors'][0])

    def test_injected_os_query_never_accidentally_reads_real_native_metadata(self):
        with patch.object(camera, '_WindowsMetadataReader', side_effect=AssertionError('real native access')) as native:
            result = self.query([{'InstanceId': r'USB\VID_2756&PID_000B\SYNTHETIC', 'Present': True}])
        native.assert_not_called()
        self.assertTrue(result['present'])
        self.assertEqual(result['metadata']['backend'], 'skipped-injected-query')

    def test_identity_bound_native_metadata_keeps_two_cameras_separate(self):
        parents = [r'USB\VID_2756&PID_000B\BODY_A', r'USB\VID_2756&PID_000B\BODY_B']
        child = r'USB\VID_2756&PID_000B&MI_00\CHILD_A'
        payload = {'Complete': True, 'TotalPresent': 3, 'Devices': [
            {'InstanceId': identity, 'Present': True} for identity in [*parents, child]]}
        def os_query(command, **kwargs):
            return subprocess.CompletedProcess(command, 0, json.dumps(payload).encode('utf-8'), b'')
        def native_metadata(instance_id):
            belongs_to_a = instance_id != parents[1]
            return {'InstanceId': instance_id, 'Complete': True,
                    'Parent': parents[0] if instance_id == child else r'USB\ROOT_HUB30\ROOT',
                    'ContainerId': 'container-A' if belongs_to_a else 'container-B',
                    'BusReportedDeviceDesc': 'X2D II 100C', 'MetadataErrors': []}
        result = discover(runner=os_query, metadata_reader=native_metadata)
        self.assertTrue(result['metadata']['complete'])
        self.assertEqual(len(result['physical_devices']), 2)
        camera_a = next(group for group in result['physical_devices'] if group['parent_instance_id'] == parents[0])
        self.assertEqual(set(camera_a['instances']), {parents[0], child})

    def test_wrong_native_identity_cannot_reassign_present_child_to_another_camera(self):
        child = r'USB\VID_2756&PID_000B&MI_02\CHILD_A'
        other = r'USB\VID_2756&PID_000B\BODY_B'
        payload = {'Complete': True, 'TotalPresent': 1, 'Devices': [{'InstanceId': child, 'Present': True}]}
        def os_query(command, **kwargs):
            return subprocess.CompletedProcess(command, 0, json.dumps(payload).encode('utf-8'), b'')
        def wrong_metadata(instance_id):
            return {'InstanceId': other, 'Complete': True, 'Parent': other,
                    'ContainerId': 'container-B', 'BusReportedDeviceDesc': 'X2D II 100C', 'MetadataErrors': []}
        result = discover(runner=os_query, metadata_reader=wrong_metadata)
        self.assertTrue(result['present'])
        self.assertFalse(result['metadata']['complete'])
        self.assertIsNone(result['instances'][0]['parent_instance_id'])
        self.assertEqual(result['instances'][0]['physical_join_basis'], 'unjoined-or-ambiguous')

    def test_native_reader_initialization_failure_preserves_current_enumeration(self):
        payload = {'Complete': True, 'TotalPresent': 1, 'Devices': [
            {'InstanceId': r'USB\VID_2756&PID_000B\SYNTHETIC', 'Present': True}]}
        process_result = subprocess.CompletedProcess('fixed', 0, json.dumps(payload).encode('utf-8'), b'')
        with patch.object(camera.subprocess, 'run', return_value=process_result), \
                patch.object(camera, '_WindowsMetadataReader', side_effect=OSError('synthetic load failure')):
            result = discover()
        self.assertTrue(result['present'])
        self.assertEqual(result['status'], 'usb_identified')
        self.assertFalse(result['metadata']['complete'])
        self.assertEqual(result['metadata']['backend'], 'unavailable')

    def test_all_actual_composite_children_join_parent_and_keep_driver_status(self):
        parent = r'USB\VID_2756&PID_000B\BODY'
        rows = [{'InstanceId': parent, 'Present': True, 'Class': 'USB', 'Status': 'OK', 'Problem': 0}]
        for number in range(6):
            rows.append({'InstanceId': rf'USB\VID_2756&PID_000B&MI_{number:02X}\CHILD{number}',
                'Present': True, 'Parent': parent, 'FriendlyName': None, 'Status': 'Error' if number == 4 else 'OK',
                'Problem': 28 if number == 4 else 0, 'Class': 'Net' if number == 0 else 'USBDevice',
                'Service': 'RNDISMP6' if number == 0 else 'WinUSB' if number == 4 else None})
        result = self.query(rows)
        self.assertEqual(result['matched_instance_count'], 7)
        self.assertEqual(len(result['physical_devices']), 1)
        self.assertTrue(result['physical_devices'][0]['parent_observed'])
        self.assertEqual(result['device_state'], 'usb_enumerated_with_pnp_problem')
        self.assertEqual(len(result['transport']['rndis']['driver_instances']), 1)
        self.assertEqual(len(result['transport']['winusb']['driver_instances']), 1)
        self.assertFalse(result['transport']['winusb']['endpoints_opened'])
        self.assertEqual(result['transport']['adb']['state'], 'not_probed')

    def test_generic_child_without_parent_still_proves_usb_presence_not_parent_join(self):
        result = self.query([{'InstanceId': r'USB\VID_2756&PID_000B&MI_03\GENERIC', 'Present': True,
                             'FriendlyName': 'USB Device', 'Status': 'Unknown'}])
        self.assertTrue(result['present'])
        self.assertFalse(result['physical_devices'][0]['parent_observed'])
        self.assertFalse(result['model_name_observed_in_os_metadata'])
        self.assertFalse(result['debug_connected'])

    def test_stale_wrong_vendor_product_and_prefix_collision_do_not_match(self):
        rows = [{'InstanceId': identity, 'Present': True} for identity in (
            r'USB\VID_2AEF&PID_000B\WRONG', r'USB\VID_2756&PID_000C\WRONG',
            r'USB\VID_2756&PID_000B0\COLLISION', r'USB\VID_2756&PID_000B&MI_00X\COLLISION')]
        rows.append({'InstanceId': r'USB\VID_2756&PID_000B\STALE', 'Present': False})
        result = self.query(rows)
        self.assertFalse(result['present'])
        self.assertTrue(result['absence_conclusive'])
        self.assertEqual(result['matched_instance_count'], 0)

    def test_empty_complete_query_is_absent_but_incomplete_query_is_unknown(self):
        absent = self.query([])
        self.assertFalse(absent['present'])
        self.assertTrue(absent['absence_conclusive'])
        unknown = self.query([], complete=False)
        self.assertIsNone(unknown['present'])
        self.assertFalse(unknown['absence_conclusive'])
        self.assertEqual(unknown['status'], 'discovery_incomplete')

    def test_timeout_os_failure_and_malformed_output_never_claim_absence(self):
        for response in (
            subprocess.TimeoutExpired('fixed-os-query', 8),
            subprocess.CompletedProcess('fixed-os-query', 1, b'', b'access denied'),
            subprocess.CompletedProcess('fixed-os-query', 0, b'not JSON', b''),
            subprocess.CompletedProcess('fixed-os-query', 0, b'\xff', b''),
            subprocess.CompletedProcess('fixed-os-query', 0, b'{"Complete":true,"Complete":true,"TotalPresent":0,"Devices":[]}', b''),
            subprocess.CompletedProcess('fixed-os-query', 0, b'{"Complete":true,"TotalPresent":1,"Devices":[{"InstanceId":"USB\\\\VID_2756&PID_000B\\\\X","Present":"true"}]}', b''),
        ):
            def os_query(command, **kwargs):
                if isinstance(response, Exception):
                    raise response
                return response
            result = discover(runner=os_query)
            self.assertEqual(result['status'], 'discovery_failed')
            self.assertIsNone(result['present'])
            self.assertFalse(result['absence_conclusive'])
            self.assertFalse(result['debug_connected'])

    def test_timeout_error_is_short_and_does_not_expose_encoded_command(self):
        def timed_out_query(command, **kwargs):
            raise subprocess.TimeoutExpired(command, kwargs['timeout'])
        result = discover(runner=timed_out_query)
        self.assertIsNone(result['present'])
        self.assertFalse(result['absence_conclusive'])
        self.assertLess(len(result['error']), 200)
        self.assertNotIn('EncodedCommand', result['error'])
        self.assertIn('8', result['error'])

    def test_fixed_command_is_hidden_bounded_os_metadata_only(self):
        calls = []
        def os_query(command, **kwargs):
            calls.append((command, kwargs))
            return subprocess.CompletedProcess(command, 0, b'{"Complete":true,"TotalPresent":0,"Devices":[]}', b'')
        result = discover(runner=os_query)
        self.assertEqual(len(calls), 1)
        command, options = calls[0]
        self.assertEqual(command[0], camera.POWERSHELL)
        source = base64.b64decode(command[-1]).decode('utf-16le')
        self.assertEqual(source, camera.OS_QUERY)
        self.assertIn('Get-PnpDevice -PresentOnly', source)
        self.assertNotIn('Get-PnpDeviceProperty', source)
        for forbidden in ('Add-Type', 'Phocus', 'Start-Process', 'Set-PnpDevice', 'Enable-PnpDevice',
                'Disable-PnpDevice', 'Restart-PnpDevice', 'Invoke-Expression', 'Get-ChildItem', 'setprop', 'adb'):
            self.assertNotIn(forbidden, source)
        self.assertFalse(options['shell'])
        self.assertEqual(options['timeout'], 8)
        self.assertTrue(result['identity_basis']['historical_evidence_is_current_presence'] is False)

    def test_two_bodies_are_not_joined_by_same_vid_pid(self):
        parents = [r'USB\VID_2756&PID_000B\BODY_A', r'USB\VID_2756&PID_000B\BODY_B']
        rows = []
        for index, parent in enumerate(parents):
            rows.append({'InstanceId': parent, 'Present': True})
            rows.append({'InstanceId': rf'USB\VID_2756&PID_000B&MI_00\CHILD{index}', 'Present': True, 'Parent': parent})
        self.assertEqual(len(self.query(rows)['physical_devices']), 2)

    def test_shared_os_container_joins_child_only_to_unique_observed_parent(self):
        parent = r'USB\VID_2756&PID_000B\BODY'
        result = self.query([
            {'InstanceId': parent, 'Present': True, 'ContainerId': 'body-container'},
            {'InstanceId': r'USB\VID_2756&PID_000B&MI_02\CHILD', 'Present': True,
             'ContainerId': 'body-container', 'MetadataErrors': ['parent property unavailable']},
        ])
        self.assertEqual(len(result['physical_devices']), 1)
        self.assertTrue(result['physical_devices'][0]['parent_observed'])

    def test_non_windows_does_not_execute_process_or_infer_disconnect(self):
        calls = []
        def os_query(*args, **kwargs):
            calls.append(args)
            raise AssertionError('must not execute')
        with patch.object(camera.os, 'name', 'posix'):
            result = discover(runner=os_query)
        self.assertEqual(calls, [])
        self.assertIsNone(result['present'])
        self.assertFalse(result['absence_conclusive'])

    def test_local_encoded_stderr_cannot_crash_hidden_reader_thread(self):
        def os_query(command, **kwargs):
            self.assertFalse(kwargs['text'])
            return subprocess.CompletedProcess(command, 0,
                b'{"Complete":true,"TotalPresent":0,"Devices":[]}', b'\xd5\xfd\xd4\xda')
        result = discover(runner=os_query)
        self.assertTrue(result['enumeration']['complete'])
        self.assertTrue(result['absence_conclusive'])
        self.assertEqual(result['query']['stderr_bytes'], 4)
        self.assertEqual(len(result['query']['stderr_sha256']), 64)


if __name__ == '__main__':
    unittest.main()
