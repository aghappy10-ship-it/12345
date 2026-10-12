"""Generate the narrowly scoped peer USB-ADB access adaptation, locally only.

No upload, device connection, USB switching, driver installation, or authorization
is performed by this module. Generated device code requires separate permission.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from .output_guard import output_directory, write_output

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "build/peer-usb-access"
REFERENCE = ROOT / "reference/x2d/CodeTests/temporary_af_speed_probe/AdbUsbCheck.cs"
REFERENCE_SHA256 = "eae9357679e9566792d9edbe06e40a066bd5af5995a12b53ce58c3cb3ff462e4"
STOCK_USB = ROOT.parent / "x2d2/work/reverse/vendor/x2dii_1_3_16_2_system_root/etc/init/init.eagle2.usb.rc"
STOCK_SHA256 = "20280da06de47b0fc0ec784aacef9a291bc194833f48bcd8b8871b586c603fdc"
BASELINE = "rndis,mass_storage,bulk,acm"
ADB = BASELINE + ",adb"


DEVICE_SCRIPT = r'''#!/system/bin/sh
# LOCAL CANDIDATE. Upload/launch requires separate user permission.
# This flag acknowledges a permission already obtained; it does not grant it.
# Start detached (nohup) only after the exact script/hash has been reviewed.
set -u
PATH=/system/bin:/system/xbin:/sbin
export PATH
umask 077
[ "$#" = 1 ] && [ "$1" = --approved-temporary-usb-access ] || exit 30
BASE='rndis,mass_storage,bulk,acm'
ADB='rndis,mass_storage,bulk,acm,adb'
LOCK=/tmp/x2dii-peer-adb.lock
baseline() {
    [ "$(getprop sys.usb.config)" = "$BASE" ] &&
    [ "$(getprop sys.usb.state)" = "$BASE" ] &&
    [ "$(getprop init.svc.adbd)" = stopped ]
}
[ "$(id -u)" = 0 ] && baseline || exit 31
# Atomic exclusion; never follow, clear, or take over an existing lock.
mkdir "$LOCK" || exit 32
baseline || { rmdir "$LOCK"; exit 31; }

wait_state() {
    wanted=$1
    tries=0
    while [ "$tries" -lt 6 ]; do
        [ "$(getprop sys.usb.config)" = "$wanted" ] &&
        [ "$(getprop sys.usb.state)" = "$wanted" ] && return 0
        tries=$((tries + 1))
        sleep 1 || return 1
    done
    return 1
}

# A SINGLE independent worker owns ALL property writes and recovery.
# The foreground only waits: its death cannot steal a recovery lock or race a
# second writer after a timer restored USB. The worker itself must not be killed.
(
    changed=0
    restore_usb() {
        attempt=0
        while [ "$attempt" -lt 3 ]; do
            attempt=$((attempt + 1))
            none_requested=0
            setprop sys.usb.config none && wait_state none && none_requested=1
            # Always try BASE even after a failed none request. Never call the
            # result verified: init publishes state from CURRENT config, so
            # delayed actions can make property readback look correct early.
            setprop sys.usb.config "$BASE" && wait_state "$BASE"
            echo USB_RESTORE_REQUESTED
            if [ "$none_requested" = 1 ] && baseline; then
                echo USB_PROPERTIES_MATCH_CONNECTIVITY_UNVERIFIED
                return 0
            fi
        done
        echo USB_RESTORE_REQUEST_FAILED_REQUIRES_ATTENTION >&2
        return 1
    }
    finish() {
        result=$1
        trap - EXIT
        trap '' HUP INT TERM
        if [ "$changed" = 1 ]; then
            restore_usb || { echo USB_LOCK_RETAINED >&2; exit 70; }
        fi
        if [ "$result" != 0 ]; then echo USB_ABNORMAL_WORKER_LOCK_RETAINED >&2; exit "$result"; fi
        rmdir "$LOCK" || exit 71
        exit "$result"
    }
    trap 'finish $?' EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    sleep 2 || exit 34
    baseline || exit 31
    changed=1
    setprop sys.usb.config none && wait_state none || exit 35
    setprop sys.usb.config "$ADB" && wait_state "$ADB" || exit 36
    [ "$(getprop init.svc.adbd)" = running ] || exit 37
    echo USB_ADB_WINDOW_OPEN_NOT_AUTHENTICATION
    # Same fixed 90-second ADB window as the peer, wholly device-local.
    sleep 90 || exit 38
    # EXIT performs the restore request. It never attests physical reconnection.
    exit 0
) </dev/null &
worker=$!
wait "$worker"
'''


def replace_once(text: str, before: str, after: str) -> str:
    if text.count(before) != 1:
        raise ValueError("reference adaptation anchor changed")
    return text.replace(before, after, 1)


def host_source(raw: bytes) -> str:
    """Retain reviewed WinUSB transport, but remove all arbitrary/mutating calls."""
    if hashlib.sha256(raw).hexdigest() != REFERENCE_SHA256:
        raise ValueError("reference AdbUsbCheck.cs SHA256 mismatch")
    source = raw.decode("utf-8-sig").replace("\r\n", "\n")
    # Drop unrelated first-generation proprietary protocol code entirely.
    head = source[:source.index("    public static class ReadOnlyProtocol")]
    core = source[source.index("    public sealed class AdbUsbCheck"):
                  source.index("        // Standard ADB handshake only.")]
    # Keep only the private single-shell receiver and Dispose, never the public
    # RunShellBatch/remount/install/remove methods between those anchors.
    tail = source[source.index("        private static string RunShell(string script)"):]
    result = head + core + tail
    result = replace_once(result, "namespace X2DAdbCheck", "namespace X2d2PeerAdb")
    result = replace_once(result,
                          'public UsbFailure(string code, int error = 0) : base(code) { Code = code; Win32 = error; }',
                          '''public string Details;
        public UsbFailure(string code, int error = 0, string details = "")
            : base(code + (details.Length == 0 ? "" : "; " + details)) {
            Code = code; Win32 = error; Details = details;
        }''')
    result = replace_once(result, source.splitlines()[0],
                          "// X2D II stock USB ADB, fixed read-only query only; local source candidate.")
    result = replace_once(result, source.splitlines()[1],
                          "// Adapted from pinned peer WinUSB transport; no device operations by compilation.")
    before = '''if (devicePath != null && devicePath.StartsWith(@"\\\\?\\usb#vid_2756&pid_0009&mi_06#", StringComparison.OrdinalIgnoreCase)
                            && devicePath.EndsWith("#{" + InterfaceGuid.ToString() + "}", StringComparison.OrdinalIgnoreCase)) paths.Add(devicePath);'''
    result = replace_once(result, before, "if (ObservedInterfaceNumber(devicePath) >= 0) paths.Add(devicePath);")
    check = '''if (descriptor.Number != 6 || descriptor.Alternate != 0 || descriptor.Class != 255 || descriptor.Subclass != 66 || descriptor.Protocol != 1
                || descriptor.EndpointCount != 2) throw new UsbFailure("USB_INTERFACE_MISMATCH");'''
    result = replace_once(result, check, '''ValidateInterface(ObservedInterfaceNumber(paths[0]), descriptor.Number,
                descriptor.Alternate, descriptor.Class, descriptor.Subclass, descriptor.Protocol, descriptor.EndpointCount);''')
    result = replace_once(result, '''if ((pipeOrder[0] & 128) == (pipeOrder[1] & 128)) throw new UsbFailure("ADB_ENDPOINTS");''',
                          '''ValidateEndpoints(pipeOrder[0], pipeOrder[1]);''')
    result = replace_once(result, "        private static uint Cmd(string name)", HOST_HELPERS + "\n        private static uint Cmd(string name)")
    result = replace_once(result, "        private static string RunShell(string script)",
                          "        public static string Query() { return RunShell(); }\n        private static string RunShell()")
    result = replace_once(result, "s.Open(new ReadResult());s.Send", "ReadResult observed=new ReadResult();s.Open(observed);s.Send")
    result = replace_once(result, '''if(p.Command==Cmd("AUTH"))return "ADB_AUTHORIZATION_REQUIRED";
                if(p.Command!=Cmd("CNXN"))throw new UsbFailure("ADB_CONNECT");''',
                          '''ValidateHandshakePacket(p.Command,p.A,p.B,p.Data.Length);''')
    result = replace_once(result, '''string command="shell:"+script+"\\0";''',
                          '''string command="shell:"+IdentityScript+"\\0";''')
    result = replace_once(result, '''if(p.Command==Cmd("OKAY")){remote=p.A;continue;}''',
                          '''if(p.Command==Cmd("OKAY")){remote=AcceptRemoteId(remote,p.A);continue;}''')
    result = replace_once(result, '''if(p.Command==Cmd("CLSE")){s.Send("CLSE",1,p.A,new byte[0]);return "ADB_CONNECTED\\n"+result.ToString();}''',
                          '''if(p.Command==Cmd("CLSE")){
                        if(remote==0 || p.A!=remote) throw new UsbFailure("ADB_REMOTE_ID");
                        s.Send("CLSE",1,p.A,new byte[0]);
                        string identity=result.ToString();
                        ValidateIdentity(identity);
                        return "ADB_CONNECTED_READONLY_SU\\nINTERFACE="+observed.InterfaceNumber+
                            "\\nPIPE_IN="+observed.PipeIn+"\\nPIPE_OUT="+observed.PipeOut+"\\n"+identity;
                    }''')
    result = replace_once(result, "        private byte pipeIn, pipeOut;",
                          "        private byte pipeIn, pipeOut;\n        private Stopwatch deadline = Stopwatch.StartNew();")
    result = replace_once(result, "uint sent;Check(WinUsb_WritePipe", "CheckDeadline();uint sent;Check(WinUsb_WritePipe")
    result = replace_once(result, "while(offset<length){byte[] piece=", "while(offset<length){CheckDeadline();byte[] piece=")
    return result


HOST_HELPERS = r'''
        private void CheckDeadline() {
            if (deadline.ElapsedMilliseconds > 15000) throw new UsbFailure("ADB_DEADLINE");
        }
        // Pure checks are public for offline tests; none opens a device.
        public static int ObservedInterfaceNumber(string path) {
            if (path == null) return -1;
            Match m=Regex.Match(path, @"\A\\\\\?\\usb#vid_2756&pid_000b&mi_([0-9a-f]{2})#[^#]+#\{f72fe0d4-cbcb-407d-8814-9ed673d0dd6b\}\z",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            return m.Success ? int.Parse(m.Groups[1].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture) : -1;
        }
        public static void ValidateInterface(int expected, int actual, int alternate, int cls, int subclass, int protocol, int count) {
            if(expected<0 || expected>255 || actual!=expected || alternate!=0 || cls!=255 || subclass!=66 || protocol!=1 || count!=2)
                throw new UsbFailure("USB_INTERFACE_MISMATCH");
        }
        public static void ValidateEndpoints(byte a, byte b) {
            if((a & 0x0f)==0 || (b & 0x0f)==0 || (a & 0x70)!=0 || (b & 0x70)!=0 || (a & 128)==(b & 128))
                throw new UsbFailure("ADB_ENDPOINTS");
        }
        public static void ValidateHandshake(uint command) {
            if(command==Cmd("AUTH")) throw new UsbFailure("ADB_AUTHORIZATION_REQUIRED");
            if(command!=Cmd("CNXN")) throw new UsbFailure("ADB_CONNECT");
        }
        public static void ValidateHandshakePacket(uint command, uint version, uint maxdata, int payloadBytes) {
            // Preserve evidence before rejecting. Do not infer the peer's
            // numbers from a generic failure, or silently relax negotiation.
            string details=String.Format(CultureInfo.InvariantCulture,
                "command=0x{0:x8}; version=0x{1:x8}; maxdata={2}; payloadBytes={3}; acceptedPeerVersions=0x01000000,0x01000001; hostVersion=0x01000000; minimumMaxdata=4096",
                command,version,maxdata,payloadBytes);
            try {
                ValidateHandshake(command);
                // AOSP advertises its maximum; our legacy host negotiates 0.
                // Keep mandatory packet checksums and reject unknown versions.
                if((version!=0x01000000 && version!=0x01000001) || maxdata<4096) throw new UsbFailure("ADB_VERSION");
            } catch(UsbFailure error) {
                throw new UsbFailure(error.Code,error.Win32,details);
            }
        }
        public static uint AcceptRemoteId(uint current, uint incoming) {
            // This client sends one OPEN and no shell WRTE. Only one initial
            // OKAY is expected; neither duplicates nor a new ID may rebind it.
            if(current!=0 || incoming==0) throw new UsbFailure("ADB_REMOTE_ID");
            return incoming;
        }
        private const string IdentityScript = "printf 'UID=';id -u;printf '\nDOMAIN=';cat /proc/self/attr/current;"+
            "printf '\nUSB_CONFIG=';getprop sys.usb.config;printf 'USB_STATE=';getprop sys.usb.state;"+
            "printf 'ADBD=';getprop init.svc.adbd;printf 'X2DII_ADB_READONLY_DONE\n'";
        public static void ValidateIdentity(string identity) {
            string[] lines=identity.Replace("\r", "").Split(new char[]{'\n'}, StringSplitOptions.RemoveEmptyEntries);
            string[] expected={"UID=0", "DOMAIN=u:r:su:s0", "USB_CONFIG=rndis,mass_storage,bulk,acm,adb",
                "USB_STATE=rndis,mass_storage,bulk,acm,adb", "ADBD=running", "X2DII_ADB_READONLY_DONE"};
            int mismatchIndex=-1;
            try {
                if(lines.Length!=expected.Length) throw new UsbFailure("ADB_IDENTITY_INCOMPLETE");
                // /proc/self/attr/current may include its single C-string
                // terminator. Accept that exact domain representation only;
                // do not strip NULs from arbitrary fields or damaged values.
                for(int i=0;i<expected.Length;i++) if(lines[i]!=expected[i] &&
                    !(i==1 && lines[i]==expected[i]+"\0")) {
                    mismatchIndex=i;
                    throw new UsbFailure("ADB_IDENTITY_MISMATCH");
                }
            } catch(UsbFailure error) {
                // Preserve this fixed query's original decoded input before
                // CR/empty-line normalization. Capture at most 8192 UTF-8 bytes;
                // the Base64 representation and exception message may be longer.
                byte[] raw=Encoding.UTF8.GetBytes(identity);
                int captured=Math.Min(raw.Length,8192);
                string expectedField=mismatchIndex<0 ? "" : expected[mismatchIndex];
                string details=String.Format(CultureInfo.InvariantCulture,
                    "identityUtf8Base64={0}; identityUtf8Bytes={1}; capturedBytes={2}; identityTruncated={3}; expectedLines={4}; actualLines={5}; mismatchIndex={6}; expectedFieldUtf8Base64={7}",
                    Convert.ToBase64String(raw,0,captured),raw.Length,captured,raw.Length>8192 ? "true" : "false",
                    expected.Length,lines.Length,mismatchIndex,Convert.ToBase64String(Encoding.UTF8.GetBytes(expectedField)));
                throw new UsbFailure(error.Code,error.Win32,details);
            }
        }
'''


HOST_ENTRY = r'''# Compile by default: no enumeration, opening, or USB traffic.
param([switch]$EnumerateOnly, [switch]$ConnectReadOnly)
$ErrorActionPreference='Stop'
if($EnumerateOnly -and $ConnectReadOnly){throw 'Choose one action'}
Add-Type -Path (Join-Path $PSScriptRoot 'X2d2PeerAdb.cs')
if($ConnectReadOnly){
    # Explicit action: standard CNXN and one fixed identity-only shell command.
    # AUTH stops. No root command, credentials, policy changes or driver install.
    [X2d2PeerAdb.AdbUsbCheck]::Query()
} elseif($EnumerateOnly){
    [X2d2PeerAdb.AdbUsbCheck]::Probe() | ConvertTo-Json
} else {
    'LOCAL_SOURCE_COMPILED_NO_DEVICE_ACCESS'
}
'''


def generate(output: Path = OUTPUT) -> dict:
    # Pin the reviewed inputs, but do not import or execute upstream scripts.
    upstream = REFERENCE.read_bytes()
    stock = STOCK_USB.read_bytes()
    if hashlib.sha256(stock).hexdigest() != STOCK_SHA256:
        raise ValueError("II stock USB init SHA256 mismatch")
    contents = {"temporary-usb-adb.sh": DEVICE_SCRIPT,
                "X2d2PeerAdb.cs": host_source(upstream), "Check-AdbReadOnly.ps1": HOST_ENTRY}
    output_directory(output, OUTPUT)
    files = {}
    for name, text in contents.items():
        data = text.encode("utf-8")
        write_output(output / name, data, OUTPUT)
        files[name] = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
    report = {
        "schema": "x2dii-peer-usb-access-v1", "status": "LOCAL_SOURCE_UNQUALIFIED",
        "installable": False, "installation_authorized": False,
        "device_operations_performed": False, "camera_written": False,
        "temporary_usb_switch_requires_separate_permission": True,
        "source_reference_commit": "9f6c9baffeaf30ac805905f8052973f60b11acf6",
        "historical_reference_commit": "dc517d8ba8ea10dfb6e1a1535cd7525a6088c061",
        "reference_adb_sha256": REFERENCE_SHA256, "stock_usb_init_sha256": STOCK_SHA256,
        "baseline": BASELINE, "temporary": ADB, "restore_deadline_seconds": 90,
        "timer_origin": "single worker, 90 seconds after temporary properties report adbd running",
        "usb_identity": {"vid": "2756", "pid": "000b", "interface": "enumerated, descriptor-confirmed"},
        "readonly_configfs_paths": ["/sys/kernel/config/usb_gadget/g1/configs/c.1",
                                   "/sys/kernel/config/usb_gadget/g1/UDC"],
        "files": files,
        "device_launch": "NOT_PERFORMED; no upload or launcher is supplied",
        "pending": ["explicit permission for temporary files and USB switch", "device-local timer survives actual USB disconnect",
                    "actual II WinUSB interface and standard ADB acceptance", "actual UID0 plus su domain (maintenance su stays hbl_camera_service)",
                    "actual USB baseline and adbd stopped after restoration"],
        "limits": ["Single worker owns all mutations and recovery; launcher SIGKILL does not kill it. SIGKILL/SIGSTOP of the worker, kernel failure and power loss cannot be guaranteed recoverable by a shell trap.",
                   "A worker error or failed recovery request retains the exclusion lock for inspection. Launcher death alone does not turn an otherwise normal worker completion into a worker error.",
                   "Property or init failure can prevent restoration; never report inferred physical restoration.",
                   "The known maintenance-domain configfs read denial is not made an impossible prerequisite. Device output is RESTORE_REQUESTED only; host original USB re-enumeration and maintenance identity are required separately.",
                   "90 seconds is the time to start recovery, not a guarantee of USB reconnection by the deadline; bounded recovery checks follow.",
                   "No persist properties, SELinux changes, driver installation, AUTH response, GUI restart, mount or firmware write.",
                   "No current device facts are inferred from static init source or host compilation."]}
    write_output(output / "access-plan.json", (json.dumps(report, indent=2) + "\n").encode(), OUTPUT)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description="Generate local USB-ADB access sources only; never upload or connect")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args(argv)
    report = generate(args.output)
    print(json.dumps({"status": report["status"], "output": str(args.output), "device_operations_performed": False}))


if __name__ == "__main__":
    main()
