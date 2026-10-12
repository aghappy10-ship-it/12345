"""Native-boundary fixture for the fixed menu ADB sender, never a device runner.

The test assembly differs from production: all native imports become throwing
stubs (read/write use this byte fixture), Open is local, and clocks are fixed.
Send, ReceiveExact, Receive, and both worker loops remain unchanged. Only this
native-disabled assembly permits reflection past the production refusal flag.
"""
import base64
import json
import re
import struct
import subprocess


def packet(command, a, b, payload=b""):
    command = int.from_bytes(command.encode("ascii"), "little")
    return struct.pack("<6I", command, a, b, len(payload), sum(payload), command ^ 0xffffffff) + payload


def step(outgoing, incoming=b""):
    return base64.b64encode(outgoing).decode() + "|" + base64.b64encode(incoming).decode()


def native_disabled_source(source, epoch):
    """Change only the explicitly approved external boundaries, fail on drift."""
    protected = (
        source[source.index("        private void WriteBytes"):source.index("        // Review sources")],
        source[source.index("        private static string ReadBoundedHostLine"):source.index("        public void Dispose")],
    )
    start = source.index("        private void Open(ReadResult result) {")
    end = source.index("        private int connectionLimitMs", start)
    source = source[:start] + ("        private void Open(ReadResult result) { "
        "file=null; usb=IntPtr.Zero; pipeIn=129; pipeOut=2; WireFixture.Open(result); }\n") + source[end:]
    declarations = re.findall(r"        \[DllImport\([^\n]+\] private static extern ([^\n]+);", source)
    assert len(declarations) == 12
    for declaration in declarations:
        name = re.search(r" (\w+)\(", declaration)[1]
        if name == "WinUsb_ReadPipe":
            body = "return WireFixture.Read(data, count, out transferred);"
        elif name == "WinUsb_WritePipe":
            body = "return WireFixture.Write(data, count, out transferred);"
        else:
            body = 'throw new InvalidOperationException("NATIVE_BOUNDARY_DISABLED:' + name + '");'
        pattern = r"        \[DllImport\([^\n]+\] private static extern " + re.escape(declaration) + ";"
        source, count = re.subn(pattern, "        private static " + declaration + " { " + body + " }", source)
        assert count == 1
    assert "DllImport" not in source and " extern " not in source
    assert "private static readonly bool SupervisionQualified = false;" in source
    assert "Enumerate();" not in source  # No remaining call to device discovery.
    assert source.count("DateTime.UtcNow") == 1
    source = source.replace("DateTime.UtcNow", "new DateTime(1970,1,1,0,0,0,DateTimeKind.Utc).AddSeconds(" + str(epoch) + ")")
    # Keep deadline comparisons, only replace the two monotonic clock reads.
    assert source.count("deadline.ElapsedMilliseconds") == source.count("batch.ElapsedMilliseconds") == 1
    source = source.replace("deadline.ElapsedMilliseconds", "WireFixture.ElapsedMilliseconds")
    source = source.replace("batch.ElapsedMilliseconds", "WireFixture.ElapsedMilliseconds")
    # Harness integrity, not a replacement behavioral test: the transport and
    # host readers plus both public/private loops must retain their exact bytes.
    assert all(block in source for block in protected)
    fixture = WIRE_FIXTURE
    if "public static string RunBoot()" in source:
        fixture = fixture.replace("AdbUsbCheck.RunFourFiles()", "AdbUsbCheck.RunBoot()")
    elif "public static string RunCleanup()" in source:
        fixture = fixture.replace("AdbUsbCheck.RunFourFiles()", "AdbUsbCheck.RunCleanup()")
    return source[:source.rfind("}")] + fixture + "\n}\n"


def run_wire(source, epoch, scripts, host_lines, tmp_path, *, fragment=3):
    namespace = re.search(r"namespace (X2d2Menu(?:Preplace|Boot|Cleanup)_[a-f0-9]+)", source)[1]
    test_source = native_disabled_source(source, epoch)
    filename = tmp_path / "native-disabled-menu.cs"
    filename.write_text(test_source, encoding="utf-8")
    encode = lambda values: ",".join("'" + value.replace("'", "''") + "'" for value in values)
    script = f"""
$ErrorActionPreference='Stop'
Add-Type -Path '{str(filename).replace("'", "''")}'
[string[]]$wire=@({encode(scripts)})
[string[]]$hostLines=@({encode(host_lines)})
$result=[{namespace}.WireFixture]::Run($wire,$hostLines,{fragment})
$result | ConvertTo-Json -Depth 5 -Compress
"""
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=35)
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads(result.stdout.strip())


WIRE_FIXTURE = r'''
    public sealed class WireResult {
        public string Error, Output, Result;
        public int Opens, HostReads, NativeReads, RemainingSteps;
        public string[] Events;
    }
    public static class WireFixture {
        public static long ElapsedMilliseconds;
        private static string[][] scripts;
        private static string[] hostLines;
        private static int connection, nextStep, fragment, nativeReads, hostReads;
        private static readonly Queue<byte> inbound=new Queue<byte>();
        private static readonly List<byte> outgoing=new List<byte>();
        private static readonly List<byte> delivered=new List<byte>();
        private static readonly List<string> events=new List<string>();
        private static string lastCommand;
        private static bool deviceWriteNeedsAck;
        public static void Open(ReadResult result) {
            if(connection>=0 && (nextStep!=scripts[connection].Length || inbound.Count!=0 || outgoing.Count!=0))
                throw new InvalidOperationException("FIXTURE_OPEN_BEFORE_PRIOR_STREAM_DONE");
            connection++;
            if(connection>=scripts.Length) throw new InvalidOperationException("FIXTURE_UNEXPECTED_DEVICE_OPEN");
            nextStep=0;
            result.InterfaceNumber=6; result.PipeIn=129; result.PipeOut=2;
            events.Add("OPEN:"+connection);
        }
        public static bool Write(byte[] data,uint count,out uint transferred) {
            transferred=count;
            for(int i=0;i<count;i++) outgoing.Add(data[i]);
            if(outgoing.Count<24) return true;
            int length=checked(24+(int)BitConverter.ToUInt32(outgoing.ToArray(),12));
            if(outgoing.Count<length) return true;
            if(outgoing.Count!=length || nextStep>=scripts[connection].Length)
                throw new InvalidOperationException("FIXTURE_UNEXPECTED_WIRE_WRITE");
            string[] expected=scripts[connection][nextStep++].Split('|');
            if(Convert.ToBase64String(outgoing.ToArray())!=expected[0])
                throw new InvalidOperationException("FIXTURE_WIRE_WRITE_DIFFERS:"+connection+":"+(nextStep-1));
            lastCommand=Encoding.ASCII.GetString(outgoing.ToArray(),0,4);
            events.Add("SEND:"+connection+":"+lastCommand);
            if(lastCommand=="OKAY") deviceWriteNeedsAck=false;
            outgoing.Clear();
            foreach(byte value in Convert.FromBase64String(expected[1])) inbound.Enqueue(value);
            return true;
        }
        public static bool Read(byte[] data,uint count,out uint transferred) {
            nativeReads++;
            if(inbound.Count==0) throw new InvalidOperationException("FIXTURE_READ_WITHOUT_PEER_REPLY");
            transferred=(uint)Math.Min(Math.Min((int)count,fragment),inbound.Count);
            for(int i=0;i<transferred;i++) { data[i]=inbound.Dequeue(); delivered.Add(data[i]); }
            if(delivered.Count>=24) {
                int length=checked(24+(int)BitConverter.ToUInt32(delivered.ToArray(),12));
                if(delivered.Count==length) {
                    string command=Encoding.ASCII.GetString(delivered.ToArray(),0,4);
                    events.Add("RECV:"+connection+":"+command);
                    if(command=="WRTE") deviceWriteNeedsAck=true;
                    delivered.Clear();
                } else if(delivered.Count>length) throw new InvalidOperationException("FIXTURE_FRAME_SPLIT_ERROR");
            }
            return true;
        }
        private sealed class HostReader : System.IO.TextReader {
            private int line, offset;
            public override int Read() {
                if(line>=hostLines.Length) return -1;
                string[] entry=hostLines[line].Split(new char[]{'|'},2);
                if(offset==0) {
                    hostReads++;
                    string expected=entry[0]=="boundary" ? "OKAY" : "CLSE";
                    if(deviceWriteNeedsAck || outgoing.Count!=0 || lastCommand!=expected)
                        throw new InvalidOperationException("FIXTURE_HOST_WAIT_BEFORE_WIRE_ACK");
                    events.Add("HOST:"+connection+":"+entry[0]);
                    if(entry[1]=="<TIMEOUT>") { System.Threading.Thread.Sleep(9000); return -1; }
                    if(entry[1]=="<EOF>") { line++; return -1; }
                }
                if(offset==entry[1].Length) { line++; offset=0; return 10; }
                return entry[1][offset++];
            }
        }
        public static WireResult Run(string[] wire,string[] replies,int fragmentBytes,bool interactive=false) {
            scripts=new string[wire.Length][];
            for(int i=0;i<wire.Length;i++) scripts[i]=wire[i].Split('\n');
            hostLines=replies; connection=-1; fragment=fragmentBytes;
            var output=new System.IO.StringWriter(CultureInfo.InvariantCulture);
            var savedOut=Console.Out; var savedIn=Console.In;
            var result=new WireResult();
            try {
                if(!interactive) { Console.SetOut(output); Console.SetIn(new HostReader()); }
                // Production source is still false. Only this assembly has no
                // native import or device-enumeration call and permits bypass.
                var field=typeof(AdbUsbCheck).GetField("SupervisionQualified",
                    System.Reflection.BindingFlags.Static|System.Reflection.BindingFlags.NonPublic);
                if((bool)field.GetValue(null)) throw new InvalidOperationException("FIXTURE_EXPECTED_PRODUCTION_REFUSAL");
                field.SetValue(null,true);
                result.Result=AdbUsbCheck.RunFourFiles();
                if(interactive) { Console.WriteLine(result.Result); Console.Out.Flush(); }
            } catch(Exception error) {
                while(error.InnerException!=null) error=error.InnerException;
                var usbError=error as UsbFailure;
                result.Error=usbError==null ? error.Message : usbError.Code;
            } finally {
                Console.SetOut(savedOut); Console.SetIn(savedIn);
                result.Output=output.ToString(); result.Opens=connection+1;
                result.HostReads=hostReads; result.NativeReads=nativeReads;
                result.Events=events.ToArray();
                result.RemainingSteps=connection<0 ? 0 : scripts[connection].Length-nextStep;
            }
            return result;
        }
    }
'''
