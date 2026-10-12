"""Offline only: execute shell recovery with recorded properties; compile WinUSB.

No test enumerates USB, opens a camera, uploads files, or calls a real setprop.
"""
import base64
import hashlib
import contextlib
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import peer_usb_access as usb
from tools.output_guard import output_directory


SHELL = shutil.which("sh") or r"C:\Program Files\Git\bin\sh.exe"
POWERSHELL = shutil.which("powershell") or shutil.which("pwsh")

MOCK_COMMANDS = r'''
id() { [ "$1" = -u ] || return 1; printf '%s\n' "$MOCK_UID"; }
getprop() {
    case "$1" in sys.usb.config|sys.usb.state|init.svc.adbd) ;; *) return 96;; esac
    IFS= read -r value < "$MOCK/$1" || return 1
    printf '%s\n' "$value"
}
setprop() {
    [ "$#" = 2 ] && [ "$1" = sys.usb.config ] || return 97
    printf '%s %s\n' "$1" "$2" >> "$MOCK/events"
    if [ "$2" = none ] && [ "$MOCK_FAULT" = KILL_during_restore ] && [ -e "$MOCK/saw_adb" ]; then
        kill -KILL $$
    fi
    case "$MOCK_FAULT:$2" in
        fail_none:none)
            if mkdir "$MOCK/failed_once" 2>/dev/null; then return 1; fi;;
        fail_adb:rndis,mass_storage,bulk,acm,adb) return 1;;
        restore_failure:rndis,mass_storage,bulk,acm) return 1;;
    esac
    printf '%s\n' "$2" > "$MOCK/sys.usb.config"
    if [ "$MOCK_FAULT:$2" != never_ready:rndis,mass_storage,bulk,acm,adb ]; then
        printf '%s\n' "$2" > "$MOCK/sys.usb.state"
    fi
    case "$2" in
        none) printf 'stopped\n' > "$MOCK/init.svc.adbd";;
        rndis,mass_storage,bulk,acm,adb) printf 'running\n' > "$MOCK/init.svc.adbd";;
    esac
    if [ "$2" = rndis,mass_storage,bulk,acm,adb ]; then
        printf 'yes\n' > "$MOCK/saw_adb"
        case "$MOCK_FAULT" in
            after_adb_failure) return 1;;
            TERM|INT|HUP|KILL) kill -"$MOCK_FAULT" $$;;
            worker_TERM) kill -TERM "$BASHPID";;
        esac
    fi
    if [ "$2" = rndis,mass_storage,bulk,acm ] && [ "$MOCK_FAULT" = physical_not_restored ]; then
        printf 'disconnected\n' > "$MOCK/physical"
        echo MOCK_PROPERTIES_MATCH_BUT_PHYSICAL_USB_DISCONNECTED >&2
    fi
}
sleep() {
    printf '%s\n' "$1" >> "$MOCK/sleeps"
    if [ "$1" = 90 ]; then
        [ "$MOCK_FAULT" != timer_failure ] || return 1
        command sleep 0.35
    elif [ "$1" = 2 ] && [ "$MOCK_FAULT" = delayed_setup ]; then
        command sleep 0.7
    else
        command sleep 0.005
    fi
}
'''


class PeerUsbAccessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        output_directory(usb.OUTPUT, usb.OUTPUT)
        cls.generated = usb.generate()

    def fixture(self, *, fault="", baseline=None, state=None, adbd="stopped", uid="0", approved=True, lock=False):
        if not Path(SHELL).is_file():
            self.fail("A real local POSIX shell is required; recovery execution cannot be skipped")
        with tempfile.TemporaryDirectory(prefix="shell-case-", dir=usb.OUTPUT) as folder:
            root = Path(folder)
            values = {"sys.usb.config": baseline or usb.BASELINE,
                      "sys.usb.state": state or usb.BASELINE, "init.svc.adbd": adbd}
            for name, value in values.items():
                (root / name).write_text(value + "\n", encoding="ascii")
            (root / "events").write_text("", encoding="ascii")
            (root / "sleeps").write_text("", encoding="ascii")
            if lock:
                (root / "lock").mkdir()
                (root / "lock/keep").write_text("foreign", encoding="ascii")
            body = usb.DEVICE_SCRIPT.replace("LOCK=/tmp/x2dii-peer-adb.lock", "LOCK=" + shlex.quote((root / "lock").as_posix()))
            harness = ("MOCK=" + shlex.quote(root.as_posix()) + "\nMOCK_UID=" + shlex.quote(uid)
                       + "\nMOCK_FAULT=" + shlex.quote(fault) + "\n" + MOCK_COMMANDS + "\n" + body)
            script = root / "fixture.sh"
            script.write_text(harness, encoding="utf-8", newline="\n")
            # The production script fixes PATH; mocks are shell functions, so
            # restore the local command sleep path within the test function only.
            harness = harness.replace("command sleep", shlex.quote(str(Path(SHELL).parent / "sleep.exe").replace("\\", "/"))) if os.name == "nt" else harness
            # Git's usr/bin has sleep; bin only has sh/bash/git.
            if os.name == "nt":
                harness = harness.replace("C:/Program Files/Git/bin/sleep.exe", "C:/Program Files/Git/usr/bin/sleep.exe")
                # mkdir/rmdir are stock local utilities, not camera utilities.
                harness = harness.replace("PATH=/system/bin:/system/xbin:/sbin", "PATH='/c/Program Files/Git/usr/bin:/usr/bin:/bin'")
            script.write_text(harness, encoding="utf-8", newline="\n")
            result = subprocess.run([SHELL, str(script), *( ["--approved-temporary-usb-access"] if approved else [])],
                                    capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=12)
            # An inherited pipe keeps communicate() waiting until the independent
            # watchdog has actually exited, including a SIGKILL foreground test.
            observed = {name: (root / name).read_text().strip() for name in values}
            events = (root / "events").read_text().splitlines()
            sleeps = (root / "sleeps").read_text().splitlines()
            return result, observed, events, sleeps, (root / "lock").exists()

    def assert_baseline(self, observed):
        self.assertEqual(observed, {"sys.usb.config": usb.BASELINE, "sys.usb.state": usb.BASELINE, "init.svc.adbd": "stopped"})

    def test_local_plan_and_hash_binding(self):
        report = self.generated
        self.assertFalse(report["installable"])
        self.assertFalse(report["device_operations_performed"])
        self.assertFalse(report["installation_authorized"])
        self.assertTrue(report["temporary_usb_switch_requires_separate_permission"])
        self.assertEqual(report["restore_deadline_seconds"], 90)
        for name, expected in report["files"].items():
            data = (usb.OUTPUT / name).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), expected["sha256"])
            self.assertEqual(len(data), expected["bytes"])

    def test_source_pins_and_no_camera_entrypoint_in_python(self):
        with self.assertRaisesRegex(ValueError, "SHA256"):
            usb.host_source(usb.REFERENCE.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "anchor"):
            usb.replace_once("aaa", "a", "b")
        with self.assertRaises(ValueError):
            usb.generate(usb.ROOT / "build/outside-usb-access")
        self.assertEqual(usb.DEVICE_SCRIPT.count("setprop sys.usb.config"), 4)
        for disallowed in ("persist.", "setenforce", "remount", "idProduct", "idVendor", "stop camera", "restart camera"):
            self.assertNotIn(disallowed, usb.DEVICE_SCRIPT)
        src = usb.host_source(usb.REFERENCE.read_bytes())
        for disallowed in ("RunShellBatch", "ProbeSystemRemount", "DiagnosticLibrary", "ReadOnlyProtocol", "pid_0009", "mi_06", "descriptor.Number != 6", "setprop", "mount -o"):
            self.assertNotIn(disallowed, src)
        self.assertIn('public static string Query()', src)
        self.assertIn('private static string RunShell()', src)
        self.assertNotIn("/sys/kernel/config", usb.DEVICE_SCRIPT)

    def test_python_cli_cannot_upload_or_connect(self):
        for option in ("--connect", "--upload", "--enable-adb"):
            with self.subTest(option=option), patch.object(usb, "generate") as generate, contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as stopped:
                usb.main([option])
            self.assertEqual(stopped.exception.code, 2)
            generate.assert_not_called()

    def test_actual_shell_syntax(self):
        result = subprocess.run([SHELL, "-n", str(usb.OUTPUT / "temporary-usb-adb.sh")], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_normal_window_restores_and_releases_lock(self):
        result, state, events, sleeps, lock = self.fixture()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_baseline(state)
        self.assertEqual(events, ["sys.usb.config none", "sys.usb.config " + usb.ADB,
                                  "sys.usb.config none", "sys.usb.config " + usb.BASELINE])
        self.assertEqual(sleeps.count("90"), 1)
        self.assertFalse(lock)
        self.assertIn("USB_RESTORE_REQUESTED", result.stdout)
        self.assertIn("USB_PROPERTIES_MATCH_CONNECTIVITY_UNVERIFIED", result.stdout)

    def test_preflight_and_permission_fail_closed_without_writes(self):
        cases = ({"approved": False}, {"baseline": "none"}, {"state": usb.ADB},
                 {"adbd": "running"}, {"uid": "2000"}, {"lock": True})
        for case in cases:
            with self.subTest(case=case):
                result, _, events, sleeps, lock = self.fixture(**case)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(events, [])
                self.assertEqual(sleeps, [])
                self.assertEqual(lock, case.get("lock", False))

    def test_command_and_readback_failures_restore_on_exit(self):
        for fault in ("fail_none", "fail_adb", "after_adb_failure", "never_ready"):
            with self.subTest(fault=fault):
                result, state, events, sleeps, lock = self.fixture(fault=fault)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assert_baseline(state)
                self.assertEqual(sleeps.count("90"), 0)
                self.assertIn("sys.usb.config " + usb.BASELINE, events)
                self.assertTrue(lock, "abnormal worker retains its exclusion lock")
                self.assertNotIn("USB_RESTORED_EXACT", result.stdout)

    def test_signals_and_foreground_sigkill_still_restore(self):
        for fault in ("HUP", "INT", "TERM", "KILL", "KILL_during_restore"):
            with self.subTest(signal=fault):
                result, state, events, _, lock = self.fixture(fault=fault)
                self.assertNotEqual(result.returncode, 0)
                self.assert_baseline(state)
                self.assertEqual(events[-1], "sys.usb.config " + usb.BASELINE)
                self.assertFalse(lock)
                self.assertNotIn("USB_RESTORED_EXACT", result.stdout)

    def test_setup_and_timed_recovery_have_a_single_writer(self):
        result, state, events, _, lock = self.fixture(fault="delayed_setup")
        self.assertEqual(result.returncode, 0)
        self.assert_baseline(state)
        self.assertEqual(events, ["sys.usb.config none", "sys.usb.config " + usb.ADB,
                                  "sys.usb.config none", "sys.usb.config " + usb.BASELINE])
        self.assertFalse(lock)
        # Permanent regressions for the removed dual-writer expiry and orphaned
        # mutex designs: exactly one background body owns every setprop call.
        body = usb.DEVICE_SCRIPT.split("(\n    changed=0", 1)[1].split(") </dev/null &", 1)[0]
        self.assertEqual(body.count("setprop sys.usb.config"), usb.DEVICE_SCRIPT.count("setprop sys.usb.config"))
        self.assertNotIn("restoring", usb.DEVICE_SCRIPT)
        self.assertNotIn("expired", usb.DEVICE_SCRIPT)

    def test_worker_catchable_signal_restores(self):
        result, state, events, sleeps, lock = self.fixture(fault="worker_TERM")
        self.assertNotEqual(result.returncode, 0)
        self.assert_baseline(state)
        self.assertEqual(events[-1], "sys.usb.config " + usb.BASELINE)
        self.assertNotIn("90", sleeps)
        self.assertTrue(lock)
        self.assertIn("USB_ABNORMAL_WORKER_LOCK_RETAINED", result.stderr)

    def test_properties_never_attest_physical_usb_restoration(self):
        result, state, _, _, lock = self.fixture(fault="physical_not_restored")
        self.assertEqual(result.returncode, 0)
        self.assert_baseline(state)
        self.assertIn("USB_RESTORE_REQUESTED", result.stdout)
        self.assertIn("CONNECTIVITY_UNVERIFIED", result.stdout)
        self.assertIn("MOCK_PROPERTIES_MATCH_BUT_PHYSICAL_USB_DISCONNECTED", result.stderr)
        self.assertNotIn("RESTORED_EXACT", result.stdout)
        self.assertNotIn("RESTORE_VERIFIED", result.stdout)
        self.assertFalse(lock)

    def test_recovery_failure_is_not_success(self):
        result, state, events, _, lock = self.fixture(fault="restore_failure")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotEqual(state["sys.usb.config"], usb.BASELINE)
        self.assertIn("USB_RESTORE_REQUEST_FAILED_REQUIRES_ATTENTION", result.stderr)
        self.assertNotIn("USB_RESTORED_EXACT", result.stdout)
        self.assertNotIn("USB_PROPERTIES_MATCH_CONNECTIVITY_UNVERIFIED", result.stdout)
        self.assertTrue(lock)
        self.assertLessEqual(events.count("sys.usb.config " + usb.BASELINE), 6)

    def test_timer_command_failure_enters_restore(self):
        result, state, events, _, _ = self.fixture(fault="timer_failure")
        self.assertNotEqual(result.returncode, 0)
        self.assert_baseline(state)
        self.assertEqual(events[-1], "sys.usb.config " + usb.BASELINE)
        self.assertNotIn("USB_RESTORED_EXACT", result.stdout)

    def test_host_compiles_and_pure_checks_run_without_enumeration(self):
        self.assertIsNotNone(POWERSHELL, "PowerShell compilation is required")
        source = str(usb.OUTPUT / "X2d2PeerAdb.cs").replace("'", "''")
        check = r'''
$ErrorActionPreference='Stop'
Add-Type -Path 'SOURCE'
function Reject([scriptblock]$Call) { try { & $Call } catch { return }; throw 'Expected rejection' }
$type=[X2d2PeerAdb.AdbUsbCheck]
$prefix='\\?\usb#vid_2756&pid_000b&mi_'
$suffix='#fixture-only#{f72fe0d4-cbcb-407d-8814-9ed673d0dd6b}'
foreach($number in @(0, 1, 6, 7, 15, 255)) {
    $path=$prefix+$number.ToString('x2')+$suffix
    if($type::ObservedInterfaceNumber($path) -ne $number){throw 'Dynamic MI parsing failed'}
    $type::ValidateInterface($number,$number,0,255,66,1,2)
}
foreach($path in @($null,'garbage',($prefix+'06'+$suffix+'trailing'),($prefix+'06'+$suffix).Replace('000b','0009'))) {
    if($type::ObservedInterfaceNumber($path) -ne -1){throw 'Wrong identity accepted'}
}
Reject { $type::ValidateInterface(7,6,0,255,66,1,2) }
Reject { $type::ValidateInterface(7,7,1,255,66,1,2) }
Reject { $type::ValidateInterface(7,7,0,255,66,0,2) }
Reject { $type::ValidateInterface(7,7,0,255,66,1,4) }
$type::ValidateEndpoints(0x81,0x02)
$type::ValidateEndpoints(0x02,0x81)
Reject { $type::ValidateEndpoints(0x81,0x82) }
Reject { $type::ValidateEndpoints(0x80,0x02) }
Reject { $type::ValidateEndpoints(0xf1,0x02) }
$type::ValidateHandshake([uint32]0x4e584e43)
Reject { $type::ValidateHandshake([uint32]0x48545541) }
Reject { $type::ValidateHandshake([uint32]0x45534c43) }
if($type::AcceptRemoteId(0,7) -ne 7){throw 'Wrong initial remote ID'}
Reject { $type::AcceptRemoteId(0,0) }
Reject { $type::AcceptRemoteId(7,7) }
Reject { $type::AcceptRemoteId(7,8) }
$identity="UID=0`nDOMAIN=u:r:su:s0`nUSB_CONFIG=rndis,mass_storage,bulk,acm,adb`nUSB_STATE=rndis,mass_storage,bulk,acm,adb`nADBD=running`nX2DII_ADB_READONLY_DONE`n"
$type::ValidateIdentity($identity)
Reject { $type::ValidateIdentity($identity.Replace('UID=0','UID=2000')) }
Reject { $type::ValidateIdentity($identity.Replace('u:r:su:s0','u:r:hbl_camera_service:s0')) }
Reject { $type::ValidateIdentity($identity.Replace('ADBD=running','ADBD=stopped')) }
Reject { $type::ValidateIdentity($identity.Replace('X2DII_ADB_READONLY_DONE','')) }
Reject { $type::ValidateIdentity($identity+$identity) }
if($type.GetMethod('Query').GetParameters().Length -ne 0){throw 'Arbitrary command API'}
'OFFLINE_HOST_CHECKS_PASSED_NO_DEVICE_CALLS'
'''.replace("SOURCE", source)
        result = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", check], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=45)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("OFFLINE_HOST_CHECKS_PASSED_NO_DEVICE_CALLS", result.stdout)

    def test_host_default_only_compiles(self):
        result = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-File", str(usb.OUTPUT / "Check-AdbReadOnly.ps1")],
                                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=45)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("LOCAL_SOURCE_COMPILED_NO_DEVICE_ACCESS", result.stdout)

    def test_known_peer_advertisements_accept_actual_cnxn_tuple_without_usb(self):
        source = str(usb.OUTPUT / "X2d2PeerAdb.cs").replace("'", "''")
        check = r'''
$ErrorActionPreference='Stop'
Add-Type -Path 'SOURCE'
$type=[X2d2PeerAdb.AdbUsbCheck]
# Actual run-x40kmx2z tuple; AOSP also permits the legacy peer advertisement.
foreach($version in @([uint32]0x01000000,[uint32]0x01000001)) {
    $type::ValidateHandshakePacket([uint32]0x4e584e43,$version,4096,144)
}
'KNOWN_ADVERTISEMENTS_ACCEPTED_NO_DEVICE_CALLS'
'''.replace("SOURCE", source)
        result = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", check],
                                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=45)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("KNOWN_ADVERTISEMENTS_ACCEPTED_NO_DEVICE_CALLS", result.stdout)

    def test_saved_identity_accepts_one_domain_terminator_without_usb(self):
        # Replay the retained decoded response, not another camera query. The
        # historical checker failure remains untouched in the source record.
        saved = json.loads((usb.ROOT / "build/temporary-adb-20261004-1152/RESULT.json").read_text(encoding="utf-8"))
        raw = saved["identityDecodedUtf8"].encode("utf-8")
        self.assertEqual(len(raw), 147)
        encoded = base64.b64encode(raw).decode("ascii")
        self.assertEqual(encoded,
            "VUlEPTAKCkRPTUFJTj11OnI6c3U6czAAClVTQl9DT05GSUc9cm5kaXMsbWFzc19zdG9yYWdlLGJ1bGssYWNtLGFkYgpVU0JfU1RBVEU9cm5kaXMsbWFzc19zdG9yYWdlLGJ1bGssYWNtLGFkYgpBREJEPXJ1bm5pbmcKWDJESUlfQURCX1JFQURPTkxZX0RPTkUK")
        source = str(usb.OUTPUT / "X2d2PeerAdb.cs").replace("'", "''")
        check = r'''
$ErrorActionPreference='Stop'
Add-Type -Path 'SOURCE'
$identity=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('RESPONSE'))
[X2d2PeerAdb.AdbUsbCheck]::ValidateIdentity($identity)
[X2d2PeerAdb.AdbUsbCheck]::ValidateIdentity($identity.Replace("`n","`r`n"))
[X2d2PeerAdb.AdbUsbCheck]::ValidateIdentity($identity.Replace(([string][char]0),''))
'SAVED_IDENTITY_ACCEPTED_NO_DEVICE_CALLS'
'''.replace("SOURCE", source).replace("RESPONSE", encoded)
        result = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", check],
                                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=45)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("SAVED_IDENTITY_ACCEPTED_NO_DEVICE_CALLS", result.stdout)

    def test_identity_rejection_preserves_exact_bounded_output_without_usb(self):
        source = str(usb.OUTPUT / "X2d2PeerAdb.cs").replace("'", "''")
        check = r'''
$ErrorActionPreference='Stop'
Add-Type -Path 'SOURCE'
$type=[X2d2PeerAdb.AdbUsbCheck]
$identity="UID=0`r`nDOMAIN=u:r:su:s0`r`nUSB_CONFIG=rndis,mass_storage,bulk,acm,adb`r`nUSB_STATE=rndis,mass_storage,bulk,acm,adb`r`nADBD=running`r`nX2DII_ADB_READONLY_DONE`r`n"
$type::ValidateIdentity($identity)
$cases=@(
    @($identity.Replace('UID=0','UID=2000'),'ADB_IDENTITY_MISMATCH',6,0,'UID=0'),
    @($identity.Replace('DOMAIN=u:r:su:s0','DOMAIN=u:r:hbl_camera_service:s0'),'ADB_IDENTITY_MISMATCH',6,1,'DOMAIN=u:r:su:s0'),
    @($identity.Replace('USB_CONFIG=rndis,mass_storage,bulk,acm,adb','USB_CONFIG=none'),'ADB_IDENTITY_MISMATCH',6,2,'USB_CONFIG=rndis,mass_storage,bulk,acm,adb'),
    @($identity.Replace('USB_STATE=rndis,mass_storage,bulk,acm,adb','USB_STATE=none'),'ADB_IDENTITY_MISMATCH',6,3,'USB_STATE=rndis,mass_storage,bulk,acm,adb'),
    @($identity.Replace('ADBD=running','ADBD=stopped'),'ADB_IDENTITY_MISMATCH',6,4,'ADBD=running'),
    @($identity.Replace('X2DII_ADB_READONLY_DONE','WRONG_DONE'),'ADB_IDENTITY_MISMATCH',6,5,'X2DII_ADB_READONLY_DONE'),
    @($identity.Replace('X2DII_ADB_READONLY_DONE',''),'ADB_IDENTITY_INCOMPLETE',5,-1,''),
    @(($identity+$identity),'ADB_IDENTITY_INCOMPLETE',12,-1,''),
    @('','ADB_IDENTITY_INCOMPLETE',0,-1,''),
    @($identity.Replace('UID=0',('UID='+[char]0x96ea)),'ADB_IDENTITY_MISMATCH',6,0,'UID=0'),
    @($identity.Replace('UID=0',('UID=0'+[char]0)),'ADB_IDENTITY_MISMATCH',6,0,'UID=0'),
    @($identity.Replace('DOMAIN=u:r:su:s0',('DOMAIN=u:r:su:'+ [char]0 +'s0')),'ADB_IDENTITY_MISMATCH',6,1,'DOMAIN=u:r:su:s0'),
    @($identity.Replace('DOMAIN=u:r:su:s0',('DOMAIN=u:r:su:s0'+[char]0+[char]0)),'ADB_IDENTITY_MISMATCH',6,1,'DOMAIN=u:r:su:s0'),
    @($identity.Replace('DOMAIN=u:r:su:s0',('DOMAIN=u:r:su:s0'+[char]0+'unexpected')),'ADB_IDENTITY_MISMATCH',6,1,'DOMAIN=u:r:su:s0'),
    @($identity.Replace('DOMAIN=u:r:su:s0',('DOMAIN=u:r:hbl_camera_service:s0'+[char]0)),'ADB_IDENTITY_MISMATCH',6,1,'DOMAIN=u:r:su:s0'),
    @($identity.Replace('DOMAIN=u:r:su:s0',([char]0+'DOMAIN=u:r:su:s0')),'ADB_IDENTITY_MISMATCH',6,1,'DOMAIN=u:r:su:s0'),
    @($identity.Replace('USB_CONFIG=rndis,mass_storage,bulk,acm,adb',('USB_CONFIG=rndis,mass_storage,bulk,acm,adb'+[char]0)),'ADB_IDENTITY_MISMATCH',6,2,'USB_CONFIG=rndis,mass_storage,bulk,acm,adb'),
    @($identity.Replace('USB_STATE=rndis,mass_storage,bulk,acm,adb',('USB_STATE=rndis,mass_storage,bulk,acm,adb'+[char]0)),'ADB_IDENTITY_MISMATCH',6,3,'USB_STATE=rndis,mass_storage,bulk,acm,adb'),
    @($identity.Replace('ADBD=running',('ADBD=running'+[char]0)),'ADB_IDENTITY_MISMATCH',6,4,'ADBD=running'),
    @($identity.Replace('X2DII_ADB_READONLY_DONE',('X2DII_ADB_READONLY_DONE'+[char]0)),'ADB_IDENTITY_MISMATCH',6,5,'X2DII_ADB_READONLY_DONE'),
    @(('Z'*8192),'ADB_IDENTITY_INCOMPLETE',1,-1,''),
    @(('Z'*8193),'ADB_IDENTITY_INCOMPLETE',1,-1,''),
    @((('Z'*8189)+[char]0x96ea),'ADB_IDENTITY_INCOMPLETE',1,-1,''),
    @((('Z'*8190)+[char]0x96ea),'ADB_IDENTITY_INCOMPLETE',1,-1,''),
    @((('Z'*8191)+[char]0x96ea),'ADB_IDENTITY_INCOMPLETE',1,-1,'')
)
foreach($case in $cases){
    if($case.Count -ne 5){throw 'Malformed identity test case'}
    $caught=$null
    try { $type::ValidateIdentity([string]$case[0]) }
    catch { $caught=$_.Exception.InnerException }
    if($null -eq $caught -or $caught.Code -ne $case[1]){
        throw ('Identity rejection category changed: expected='+$case[1]+'; actual='+$caught.Code+'; inputLength='+([string]$case[0]).Length)
    }
    $fields=@{}
    foreach($part in $caught.Details.Split(@('; '),[StringSplitOptions]::None)){
        $pair=$part.Split(@('='),2,[StringSplitOptions]::None)
        if($pair.Length -eq 2){$fields[$pair[0]]=$pair[1]}
    }
    if(-not $fields.ContainsKey('identityUtf8Base64')){throw 'Exact identity diagnostic missing'}
    $raw=[Text.Encoding]::UTF8.GetBytes([string]$case[0])
    $captured=[Convert]::FromBase64String($fields['identityUtf8Base64'])
    $limit=[Math]::Min($raw.Length,8192)
    if($captured.Length -ne $limit -or [int]$fields['capturedBytes'] -ne $limit){throw 'Identity logging bound wrong'}
    if([int]$fields['identityUtf8Bytes'] -ne $raw.Length){throw 'Identity input size lost'}
    if($fields['identityTruncated'] -cne ($raw.Length -gt 8192).ToString().ToLowerInvariant()){throw 'Truncation not explicit'}
    for($i=0;$i -lt $limit;$i++){if($captured[$i] -ne $raw[$i]){throw 'Identity input bytes changed'}}
    if([int]$fields['actualLines'] -ne $case[2] -or [int]$fields['expectedLines'] -ne 6){throw 'Line-count diagnostic wrong'}
    if([int]$fields['mismatchIndex'] -ne $case[3]){throw 'Mismatch index wrong'}
    $expected=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($fields['expectedFieldUtf8Base64']))
    if($expected -cne $case[4]){throw 'Expected field diagnostic wrong'}
    if(-not $caught.Message.Contains($caught.Details)){throw 'Message discarded identity evidence'}
    $exceptionText=$caught.ToString()
    $jsonText=ConvertTo-Json -InputObject $exceptionText -Compress
    $roundTrip=ConvertFrom-Json -InputObject $jsonText
    if($roundTrip -cne $exceptionText -or -not $roundTrip.Contains($caught.Details)){
        throw 'Exception JSON roundtrip discarded identity evidence'
    }
}
'IDENTITY_DIAGNOSTICS_PASSED_NO_DEVICE_CALLS'
'''.replace("SOURCE", source)
        result = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", check],
                                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=45)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("IDENTITY_DIAGNOSTICS_PASSED_NO_DEVICE_CALLS", result.stdout)

    def test_handshake_rejection_preserves_observed_parameters_without_usb(self):
        source = str(usb.OUTPUT / "X2d2PeerAdb.cs").replace("'", "''")
        check = r'''
$ErrorActionPreference='Stop'
Add-Type -Path 'SOURCE'
$type=[X2d2PeerAdb.AdbUsbCheck]
$type::ValidateHandshakePacket([uint32]0x4e584e43,[uint32]0x01000000,4096,7)
$cases=@(
    @(0x4e584e43,0x01000002,4096,7,'ADB_VERSION','version=0x01000002','maxdata=4096'),
    @(0x4e584e43,0x00ffffff,4096,144,'ADB_VERSION','version=0x00ffffff','maxdata=4096'),
    @(0x4e584e43,0x02000000,4096,144,'ADB_VERSION','version=0x02000000','maxdata=4096'),
    @(0x4e584e43,0x01000000,1024,8,'ADB_VERSION','version=0x01000000','maxdata=1024'),
    @(0x4e584e43,0x01000001,1024,9,'ADB_VERSION','version=0x01000001','maxdata=1024'),
    @(0x4e584e43,0x01000000,4095,144,'ADB_VERSION','version=0x01000000','maxdata=4095'),
    @(0x4e584e43,0x01000001,4095,144,'ADB_VERSION','version=0x01000001','maxdata=4095'),
    @(0x48545541,1,0,20,'ADB_AUTHORIZATION_REQUIRED','version=0x00000001','maxdata=0'),
    @(0x45534c43,0,0,0,'ADB_CONNECT','version=0x00000000','maxdata=0')
)
foreach($case in $cases){
    $caught=$null
    try { $type::ValidateHandshakePacket([uint32]$case[0],[uint32]$case[1],[uint32]$case[2],[int]$case[3]) }
    catch { $caught=$_.Exception.InnerException }
    if($null -eq $caught -or $caught.Code -ne $case[4]){throw 'Expected unchanged rejection category'}
    foreach($part in @($case[5],$case[6],('payloadBytes='+$case[3]),('command=0x'+$case[0].ToString('x8')),
                      'acceptedPeerVersions=0x01000000,0x01000001','hostVersion=0x01000000','minimumMaxdata=4096')){
        if(-not $caught.Details.Contains($part) -or -not $caught.Message.Contains($part)){throw 'Handshake evidence lost'}
    }
}
'HANDSHAKE_DIAGNOSTICS_PASSED_NO_DEVICE_CALLS'
'''.replace("SOURCE", source)
        result = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", check],
                                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=45)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("HANDSHAKE_DIAGNOSTICS_PASSED_NO_DEVICE_CALLS", result.stdout)


if __name__ == "__main__":
    unittest.main()
