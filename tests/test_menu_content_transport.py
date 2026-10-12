"""First-window fixed-content sender: local dialogue/native-edge replay only."""
import base64
from datetime import datetime, timedelta, timezone
import importlib
import json
import re
import subprocess
import sys

import pytest

from tools import stage_menu_delivery as stage
from tests.test_compressed_role_staging import make_role_plan
from tests.test_stage_menu_delivery import session_fixture, maintenance_result, sha


def prepared_coordinator():
    transport = importlib.import_module("tools.menu_content_transport")
    plan = make_role_plan()
    session = stage.plan_session_staging(plan, *session_fixture(plan))
    now = [session.observed_epoch]
    host = transport.ContentStageCoordinator(plan, session, clock=lambda: now[0])
    while (operation := host.next_preparation) is not None:
        host.accept_preparation(exit_code=0, stdout=operation.expected_stdout, completion_validated=True)
    return host, plan, session, now


@pytest.mark.parametrize("count", (200, 100000))
def test_content_failure_keeps_bounded_sender_error_without_blocking_its_pipe(count):
    """Real local child, no shell/device edge: stderr must explain first error."""
    from tools import menu_content_transport as transport
    host, _, _, now = prepared_coordinator()
    host.start_window(datetime.fromtimestamp(now[0], timezone.utc))
    payload = b"CONTENT_ORIGINAL_WINDOW_DEADLINE\n" + b"x" * count
    process = subprocess.Popen([sys.executable, "-c",
        "import sys;sys.stderr.buffer.write(b'CONTENT_ORIGINAL_WINDOW_DEADLINE\\n'+b'x'*" +
        str(count) + ");sys.stderr.flush();sys.exit(3)"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        with pytest.raises(ValueError, match="before exact final receipt") as caught:
            transport.drive_content_process(process, host, None)
        evidence = caught.value.partial_evidence
        assert evidence["stderr"] == payload[:65536]
        assert evidence["stderr_bytes"] == len(payload)
        assert evidence["stderr_truncated"] is (len(payload) > 65536)
        assert evidence["phase"] == "validate-final-process" and evidence["command_index"] == 0
        assert evidence["sender_exit_code"] == 3
        assert evidence["installable"] is False and evidence["retained_adb_payloads"] == ()
    finally:
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=5)
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()


def test_first_window_fixed_handshake_uses_actual_maintenance_before_each_su_command():
    host, plan, session, now = prepared_coordinator()
    host.start_window(datetime.fromtimestamp(now[0], timezone.utc))
    steps = stage.execution_steps(plan, dict(session.context), session=session)
    for index, operation in enumerate(steps):
        digest = sha(operation.command.encode("ascii"))
        observation = host.begin_command(f"X2DII_CONTENT_NEED:{index}:{session.binding_sha256}:{digest}")
        result = maintenance_result(observation, session, observer=host.observer)
        permit = host.accept_maintenance(exit_code=result.returncode, stdout=result.stdout, completion_validated=True)
        assert permit == f"X2DII_CONTENT_GO:{index}:{session.binding_sha256}:{digest}:{now[0]}\n"
        raw = (operation.expected_stdout + f"\nX2DII_CONTENT_{session.binding_sha256[:24]}_{index}_RC=0\n").encode()
        ack = host.accept_su_reply(f"X2DII_CONTENT_REPLY:{index}:" + base64.b64encode(raw).decode())
        assert ack == f"X2DII_CONTENT_ACCEPTED:{index}:{sha(raw)}\n"
    assert host.all_results_validated
    assert not host.installable


def test_review_content_sender_compiles_and_refuses_before_native_access(tmp_path):
    from tools import menu_content_transport as transport
    host, plan, session, now = prepared_coordinator()
    source = transport.review_content_host_source(plan, session, datetime.fromtimestamp(now[0], timezone.utc))
    namespace = re.search(r"namespace (X2d2ContentStage_[a-f0-9]+)", source)[1]
    filename = tmp_path / "content-stage.cs"
    filename.write_text(source, encoding="utf-8")
    script = f'''
$ErrorActionPreference='Stop'
Add-Type -Path '{str(filename).replace("'", "''")}'
try {{ [{namespace}.AdbUsbCheck]::RunContentStage(); throw 'unexpected native execution' }}
catch {{ $e=$_.Exception;while($e.InnerException){{$e=$e.InnerException}};
 if($e.Code -ne 'CONTENT_SOURCE_NOT_QUALIFIED'){{throw}} }}
'COMPILED_REFUSED_BEFORE_USB'
'''
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "COMPILED_REFUSED_BEFORE_USB" in result.stdout


def native_fixture_source(source, steps, session, *, fault, epoch):
    """Model native I/O and both clocks; keep packet/time-check logic real.

    Windows observer subprocess startup is not camera time. Explicit fault
    cases advance the modeled wall or monotonic clock, without relaxing the
    production 80-second window or the sender's before-payload deadline check.
    """
    markers = [f"X2DII_CONTENT_{session.binding_sha256[:24]}_{i}_RC=" for i in range(len(steps))]
    opens = ["shell:(" + step.command + ");r=$?;printf '\\n" + marker + "%s\\n' \"$r\"\0"
             for step, marker in zip(steps, markers)]
    outputs = [step.expected_stdout + "\n" + marker + "0\n" for step, marker in zip(steps, markers)]
    lines = []
    for i, (step, output) in enumerate(zip(steps, outputs)):
        checked = epoch - 9 if fault == "stale-permit" else epoch
        lines.extend((f"X2DII_CONTENT_GO:{i}:{session.binding_sha256}:{sha(step.command.encode())}:{checked}",
                      f"X2DII_CONTENT_ACCEPTED:{i}:{sha(output.encode())}"))
    source = source.replace("private static readonly bool ContentQualified = false;",
                            "private static readonly bool ContentQualified = true;")
    source = source.replace("return (long)(DateTime.UtcNow-new DateTime(1970,1,1,0,0,0,DateTimeKind.Utc)).TotalSeconds;",
                            "return FixtureNow;")
    assert source.count("contentClock.ElapsedMilliseconds") == 1
    source = source.replace("contentClock.ElapsedMilliseconds", "FixtureElapsedMilliseconds")
    start = source.index("        private void Open(ReadResult result) {")
    stop = source.index("        private void CheckDeadline()", start)
    source = source[:start] + ("        private void Open(ReadResult result) { FixtureOpened++; "
                              "file=null;usb=IntPtr.Zero;pipeIn=129;pipeOut=1; }\n") + source[stop:]
    for name in ("Write", "Read"):
        declaration = (f'        [DllImport("winusb.dll", SetLastError = true)] private static extern bool WinUsb_{name}Pipe'
                       '(IntPtr handle, byte pipe, byte[] data, uint count, out uint transferred, IntPtr overlapped);')
        replacement = (f'        private static bool WinUsb_{name}Pipe'
                       '(IntPtr handle, byte pipe, byte[] data, uint count, out uint transferred, IntPtr overlapped) '
                       f'{{ return Fixture{name}(data,count,out transferred); }}')
        assert source.count(declaration) == 1
        source = source.replace(declaration, replacement)
    # Open is already local and the read/write edges are byte fixtures. Remove
    # the remaining unreachable native declarations too, so a future control-
    # flow change cannot accidentally enumerate or access a host device.
    declarations = re.findall(r"        \[DllImport\([^\n]+\] private static extern ([^\n]+);", source)
    assert len(declarations) == 10
    for declaration in declarations:
        name = re.search(r" (\w+)\(", declaration)[1]
        pattern = r"        \[DllImport\([^\n]+\] private static extern " + re.escape(declaration) + ";"
        source, count = re.subn(pattern, "        private static " + declaration +
            ' { throw new InvalidOperationException("NATIVE_BOUNDARY_DISABLED:' + name + '"); }', source)
        assert count == 1
    assert "DllImport" not in source and " extern " not in source and "Enumerate();" not in source
    fixture = r'''
        public static int FixtureOpened, FixtureCompleteOpens, FixtureOpenHeaders;
        private static long FixtureNow = @EPOCH@;
        private static long FixtureElapsedMilliseconds;
        private static readonly string FixtureFault = @FAULT@;
        private static readonly string[] FixtureOpens = new string[] { @OPENS@ };
        private static readonly string[] FixtureOutputs = new string[] { @OUTPUTS@ };
        private static readonly Queue<byte> FixtureIncoming = new Queue<byte>();
        private static uint fixtureCommand,fixtureA,fixtureB,fixtureLength,fixtureChecksum;
        private static bool fixturePayload;
        private static int fixtureIndex;
        public static void FixtureInput() { Console.SetIn(new System.IO.StringReader(@INPUT@)); }
        private static void FixturePacket(string command,uint a,uint b,byte[] payload) {
            uint sum=0;foreach(byte value in payload)sum+=value;
            uint cmd=Cmd(command);
            uint[] fields={cmd,a,b,(uint)payload.Length,sum,cmd^0xffffffff};
            if(FixtureFault=="checksum" && command=="WRTE") fields[4]++;
            foreach(uint field in fields)foreach(byte value in BitConverter.GetBytes(field))FixtureIncoming.Enqueue(value);
            foreach(byte value in payload)FixtureIncoming.Enqueue(value);
        }
        private static void FixtureProcess(byte[] payload) {
            uint sum=0;foreach(byte value in payload)sum+=value;
            if(sum!=fixtureChecksum)throw new Exception("fixture host checksum");
            if(fixtureCommand==Cmd("CNXN")) { FixturePacket("CNXN",0x01000000,4096,new byte[0]);return; }
            if(fixtureCommand==Cmd("OPEN")) {
                if(fixtureIndex>=FixtureOpens.Length || Encoding.ASCII.GetString(payload)!=FixtureOpens[fixtureIndex] ||
                   fixtureA!=(uint)fixtureIndex+1 || fixtureB!=0)throw new Exception("fixture fixed OPEN differs");
                FixtureCompleteOpens++;
                uint remote=(uint)fixtureIndex+71;
                FixturePacket("OKAY",remote,fixtureA,new byte[0]);
                byte[] output=Encoding.ASCII.GetBytes(FixtureOutputs[fixtureIndex]);
                if(FixtureFault=="incomplete") output=new byte[0];
                if(FixtureFault=="character")output=new byte[]{0};
                FixturePacket("WRTE",FixtureFault=="remote" ? remote+1 : remote,fixtureA,output);
                FixturePacket("CLSE",remote,fixtureA,new byte[0]);
                fixtureIndex++;return;
            }
            if(fixtureCommand!=Cmd("OKAY") && fixtureCommand!=Cmd("CLSE"))throw new Exception("fixture unexpected host packet");
        }
        private static bool FixtureWrite(byte[] bytes,uint count,out uint transferred) {
            transferred=count;
            if(!fixturePayload) {
                if(count!=24)throw new Exception("fixture header length");
                fixtureCommand=BitConverter.ToUInt32(bytes,0);fixtureA=BitConverter.ToUInt32(bytes,4);
                fixtureB=BitConverter.ToUInt32(bytes,8);fixtureLength=BitConverter.ToUInt32(bytes,12);
                fixtureChecksum=BitConverter.ToUInt32(bytes,16);
                if((fixtureCommand^0xffffffff)!=BitConverter.ToUInt32(bytes,20) || fixtureLength>4096)
                    throw new Exception("fixture host header invalid");
                fixturePayload=fixtureLength!=0;
                if(fixtureCommand==Cmd("OPEN")) {
                    FixtureOpenHeaders++;
                    if(FixtureFault=="delay-before-payload")FixtureNow+=9;
                    if(FixtureFault=="window-before-payload")FixtureNow+=80;
                    if(FixtureFault=="monotonic-before-payload")FixtureElapsedMilliseconds=79000;
                }
                if(!fixturePayload)FixtureProcess(new byte[0]);
            } else {
                if(count!=fixtureLength)throw new Exception("fixture host payload length");
                fixturePayload=false;FixtureProcess(bytes);
            }
            return true;
        }
        private static bool FixtureRead(byte[] bytes,uint count,out uint transferred) {
            if(FixtureIncoming.Count==0)throw new Exception("fixture unexpected native receive");
            // Fragment headers and payloads to exercise ReceiveExact's loop.
            transferred=(uint)Math.Min(7,Math.Min((int)count,FixtureIncoming.Count));
            for(int i=0;i<transferred;i++)bytes[i]=FixtureIncoming.Dequeue();
            return true;
        }
'''
    for key, value in {"@EPOCH@": str(epoch), "@FAULT@": json.dumps(fault),
                       "@OPENS@": ",\n".join(map(json.dumps, opens)),
                       "@OUTPUTS@": ",\n".join(map(json.dumps, outputs)),
                       "@INPUT@": json.dumps("\n".join(lines) + "\n")}.items():
        fixture = fixture.replace(key, value)
    return source.replace("        public void Dispose() {", fixture + "\n        public void Dispose() {")


@pytest.mark.parametrize("fault,expected_code,opens", (
    ("none", "", None), ("stale-permit", "CONTENT_MAINTENANCE_PERMIT_EXPIRED", 0),
    ("delay-before-payload", "CONTENT_MAINTENANCE_PERMIT_EXPIRED", 0),
    ("window-before-payload", "CONTENT_ORIGINAL_WINDOW_DEADLINE", 0),
    ("monotonic-before-payload", "CONTENT_ORIGINAL_WINDOW_DEADLINE", 0),
    ("remote", "CONTENT_REMOTE_ID", 1), ("checksum", "ADB_CHECKSUM", 1),
    ("incomplete", "CONTENT_EXACT_REPLY", 1), ("character", "CONTENT_OUTPUT_CHARACTER", 1)))
def test_actual_fixed_native_sender_wire_replay_stops_before_next_unsafe_send(tmp_path, fault, expected_code, opens):
    from tools import menu_content_transport as transport
    _, plan, session, now = prepared_coordinator()
    steps = stage.execution_steps(plan, dict(session.context), session=session)
    source = transport.review_content_host_source(plan, session, datetime.fromtimestamp(now[0], timezone.utc))
    source = native_fixture_source(source, steps, session, fault=fault, epoch=now[0])
    namespace = re.search(r"namespace (X2d2ContentStage_[a-f0-9]+)", source)[1]
    filename = tmp_path / "native-edge-fixture.cs"
    filename.write_text(source, encoding="utf-8")
    script = f'''
$ErrorActionPreference='Stop'
Add-Type -Path '{str(filename).replace("'", "''")}'
[{namespace}.AdbUsbCheck]::FixtureInput()
$caught=''
try {{ $result=[{namespace}.AdbUsbCheck]::RunContentStage() }}
catch {{ $e=$_.Exception;while($e.InnerException){{$e=$e.InnerException}};$caught=$e.Code;if(-not $caught){{throw}} }}
if($caught -ne '{expected_code}'){{throw ('wrong failure: '+$caught)}}
if([{namespace}.AdbUsbCheck]::FixtureOpened -ne 1){{throw 'not one native connection'}}
if([{namespace}.AdbUsbCheck]::FixtureCompleteOpens -ne {len(steps) if opens is None else opens}){{throw 'wrong sent command count'}}
if('{fault}' -in @('delay-before-payload','window-before-payload','monotonic-before-payload') -and [{namespace}.AdbUsbCheck]::FixtureOpenHeaders -ne 1){{throw 'delay edge not reached'}}
if('{fault}' -eq 'none' -and $result -ne 'X2DII_STABLE_CONTENT_STAGED_NOT_INSTALLED_USB_RESTORE_UNVERIFIED'){{throw 'wrong success scope'}}
'WIRE_REPLAY_CHECKED'
'''
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "WIRE_REPLAY_CHECKED" in result.stdout


@pytest.mark.parametrize("fault", ("none", "maintenance-failed"))
def test_process_driver_connects_real_child_handshake_to_fixed_maintenance_route(tmp_path, fault):
    from tools import menu_content_transport as transport
    host, plan, session, now = prepared_coordinator()
    launched = datetime.fromtimestamp(now[0], timezone.utc)
    host.start_window(launched)
    steps = stage.execution_steps(plan, dict(session.context), session=session)
    source = native_fixture_source(transport.review_content_host_source(plan, session, launched),
                                   steps, session, fault="none", epoch=now[0])
    namespace = re.search(r"namespace (X2d2ContentStage_[a-f0-9]+)", source)[1]
    filename = tmp_path / "driven-native-edge.cs"
    filename.write_text(source, encoding="utf-8")
    # Do not invoke FixtureInput: production Console.In reads this real child's
    # stdin. Only native camera I/O and the recorded maintenance edge are faked.
    script = f"$ErrorActionPreference='Stop';Add-Type -Path '{filename}';[{namespace}.AdbUsbCheck]::RunContentStage()"
    process = subprocess.Popen(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    class FixedMaintenance:
        def __init__(self):
            self.count = 0

        def command(self, label, command):
            operation = host.observer.observations[self.count]
            assert label == f"content-observe-{self.count}" and command == operation.command
            self.count += 1
            if fault == "maintenance-failed":
                raise ValueError("synthetic recorded maintenance completion failure")
            result = maintenance_result(operation, session, observer=host.observer)
            assert result.returncode == 0 and result.stderr == ""
            return result.stdout

    maintenance = FixedMaintenance()
    try:
        if fault == "none":
            result = transport.drive_content_process(process, host, maintenance)
            assert result["status"] == "STABLE_CONTENT_STAGED_NOT_INSTALLED_USB_RESTORE_UNVERIFIED"
            assert result["candidate_sha256"] == plan.candidate_sha256
            assert result["plan_sha256"] == plan.plan_sha256
            assert result["session_data_sha256"] == session.data_sha256
            assert result["session_binding_sha256"] == session.binding_sha256
            assert result["launch_started_utc"] == launched.isoformat()
            assert len(result["retained_adb_payloads"]) == maintenance.count == len(steps)
            assert host.all_results_validated and process.returncode == 0
            assert result["usb_restore_verified"] is False and result["installable"] is False
        else:
            with pytest.raises(ValueError, match="maintenance completion failure"):
                transport.drive_content_process(process, host, maintenance)
            assert host.failed and not host.all_results_validated and maintenance.count == 1
    finally:
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=5)
        process.stdin.close()
        process.stdout.close()
        process.stderr.close()


@pytest.mark.parametrize("seconds,allowed", ((0, True), (500, True), (589, True), (590, False), (599, False), (600, False)))
def test_original_window_deadline_never_renews_lease_or_spends_restore_reserve(seconds, allowed):
    from tools import menu_content_transport as transport
    epoch = 1800000000
    launched = datetime.fromtimestamp(epoch + seconds, timezone.utc)
    if allowed:
        deadline = transport.original_window_deadline(epoch, launched)
        assert deadline == min(epoch + seconds + 90, epoch + 600) - 10
    else:
        with pytest.raises(ValueError):
            transport.original_window_deadline(epoch, launched)


@pytest.mark.parametrize("fault", ("not-started", "original-window", "future-launch", "restart", "stale-after-release"))
def test_host_coordinator_stops_on_window_or_permit_change(fault):
    host, plan, session, now = prepared_coordinator()
    launch = datetime.fromtimestamp(now[0], timezone.utc)
    if fault == "future-launch":
        with pytest.raises(ValueError):
            host.start_window(launch + timedelta(seconds=1))
        assert host.failed
        return
    if fault != "not-started":
        host.start_window(launch)
    if fault == "restart":
        with pytest.raises(ValueError):
            host.start_window(launch)
        assert host.failed
        return
    operation = stage.execution_steps(plan, dict(session.context), session=session)[0]
    need = f"X2DII_CONTENT_NEED:0:{session.binding_sha256}:{sha(operation.command.encode())}"
    if fault in ("not-started", "original-window"):
        if fault == "original-window":
            now[0] += 80
        with pytest.raises(ValueError):
            host.begin_command(need)
    else:
        observation = host.begin_command(need)
        result = maintenance_result(observation, session, observer=host.observer)
        host.accept_maintenance(exit_code=0, stdout=result.stdout, completion_validated=True)
        now[0] += 9
        raw = (operation.expected_stdout + f"\nX2DII_CONTENT_{session.binding_sha256[:24]}_0_RC=0\n").encode()
        with pytest.raises(ValueError, match="expired"):
            host.accept_su_reply("X2DII_CONTENT_REPLY:0:" + base64.b64encode(raw).decode())
    assert host.failed and not host.all_results_validated
