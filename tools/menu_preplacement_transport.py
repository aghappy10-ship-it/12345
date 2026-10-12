"""Fixed four-file ADB stream adaptation with seven maintenance pauses each.

Pure source generation: no publisher, device access or installation authority.
The public review source refuses before native access. It is not a replacement
for qualification or the host's independent maintenance reply validation.
"""
from __future__ import annotations

import hashlib
import json
import re
import base64
import queue
import threading
import time
import subprocess
from copy import deepcopy

from . import peer_usb_access as usb
from . import session_context
from .temporary_menu_files import render_supervised_preplacement, worker_path


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


class PreplacementCoordinator:
    """Fixed dialogue ordering, not a sender or a grant of installation rights.

    A caller executes only begin_boundary's fixed command on its already
    admitted maintenance channel, validates its native completion/status, then
    passes the unmodified reply here. Only the returned ACK goes to the same
    waiting ADB stream. Saved replies are not live observation evidence.
    """
    def __init__(self, manifest, raw_session):
        from . import menu_maintenance_boundary as boundary
        self._manifest = deepcopy(manifest)
        self._raw = raw_session
        self._context = session_context.decode_session(raw_session)
        # This validates the fixed context and candidate before any next step.
        self._kind = boundary.session_kind_for_context(self._manifest, raw_session)
        self._paths = boundary.paths(self._manifest, 0, 0,
            session_data_sha256=_sha(raw_session), session_kind=self._kind)
        self._programs = tuple(render_supervised_preplacement(
            self._manifest, file_index=i, session_kind=self._kind) for i in range(4))
        self._hashes = tuple(_sha(program.encode("ascii")) for program in self._programs)
        self._file = self._boundary = 0
        self._waiting = None
        self._completed_identities = []
        self.failed = False

    @property
    def completed_identities(self):
        """Exact receipts retained for activation/removal, not live authority."""
        return tuple(self._completed_identities)

    @property
    def next_boundary(self):
        if self.failed or self._waiting is not None or self._file >= 4 or self._boundary >= 7:
            return None
        return self._file, self._boundary

    def _need(self, ok, reason):
        if not ok:
            self.failed = True
            raise ValueError("preplacement coordinator: " + reason)

    def begin_boundary(self, line):
        self._need(self.next_boundary is not None, "no next boundary or prior observation still pending")
        match = re.fullmatch(r"X2DII_HOST_BOUNDARY:([0-3]):([0-6]):([0-9a-f]{64})", line) if type(line) is str else None
        self._need(match is not None and (int(match[1]), int(match[2])) == (self._file, self._boundary),
                   "wrong or replayed file/boundary")
        self._waiting = match[3]
        # All strings are fixed or scalar-validated; never caller-provided code.
        return (f"sh {self._paths['program']} {_sha(self._raw)} "
                f"{self._file} {self._boundary} {self._waiting}")

    def accept_reply(self, raw_response, *, received_epoch):
        from . import menu_maintenance_boundary as boundary
        self._need(not self.failed and self._waiting is not None, "no pending observation")
        try:
            # Only issued time comes from the device. Reconstruct every other
            # request field independently from this frozen candidate/session.
            # The full decoder below rejects duplicate/reordered/extra fields.
            self._need(type(raw_response) is bytes and len(raw_response) <= boundary.MAX_DATA_BYTES,
                       "bounded raw response required")
            times = re.findall(rb"(?m)^issued_epoch=([1-9][0-9]{0,9})$", raw_response)
            self._need(len(times) == 1 and type(received_epoch) is int, "unique issued time required")
            issued = int(times[0])
            self._need(0 <= received_epoch - issued <= 8, "response too old or future")
            challenge = _sha((f"{self._context['boot_id']}:{self._context['session_nonce']}:"
                              f"{self._file}:{self._boundary}:{self._hashes[self._file]}\n").encode("ascii"))
            expected = boundary.make_request(self._manifest, self._raw, worker_session_sha256=_sha(self._raw),
                worker_program_sha256=self._hashes[self._file], file_index=self._file,
                boundary_index=self._boundary, challenge=challenge, issued_epoch=issued)
            self._need(_sha(expected) == self._waiting, "request is not this frozen worker/context")
            response = boundary.decode_response(raw_response, expected, received_epoch=received_epoch)
            ack = (f"X2DII_BOUNDARY_ACK:{self._waiting}:{response['started_epoch']}:"
                   f"{response['checked_epoch']}\n").encode("ascii")
            self._waiting = None
            self._boundary += 1
            return ack
        except Exception:
            self.failed = True
            raise

    def finish_file(self, *, file_index, decoded_output, stream_completed):
        """Require native stream completion and exact bounded final receipt.

        The caller validates ADB transport and shell completion before setting
        stream_completed; this flag is not itself physical wire evidence.
        """
        self._need(not self.failed and self._waiting is None and self._boundary == 7 and
                   type(file_index) is int and file_index == self._file and stream_completed is True,
                   "file closed before all seven observations and native completion")
        self._need(type(decoded_output) is bytes and len(decoded_output) <= 32768,
                   "bounded completed worker output required")
        text = decoded_output.replace(b"\r\n", b"\n")
        marker = (f"X2DII_WORKER_{_sha(self._raw)[:24]}_{file_index}_RC=").encode()
        self._need(text.endswith(b"\n" + marker + b"0\n") and text.count(marker) == 1,
                   "missing or failed shell completion")
        receipt = text.split(b"schema=x2dii-one-file-preplacement-v1\n")
        self._need(len(receipt) == 2, "unique final preplacement receipt required")
        lines = receipt[1].splitlines()
        identity_pattern = (rb"identity=(0|[1-9][0-9]{0,19}):([1-9][0-9]{0,19}):81a4:1:" +
                            str(self._manifest["candidate"]["files"][file_index]["bytes"]).encode() + rb":0:0")
        identity = re.fullmatch(identity_pattern, lines[3]) if len(lines) == 10 else None
        self._need(identity is not None and int(identity[1]) <= 2**64 - 1 and
                   int(identity[2]) <= 2**64 - 1, "final file identity differs")
        self._need(len(lines) == 10 and lines[0] == f"candidate_sha256={self._manifest['candidate_sha256']}".encode() and
                   lines[1] == f"session_nonce={self._context['session_nonce']}".encode() and
                   lines[2] == f"file_index={file_index}".encode() and
                   lines[4] == f"label={self._context[('library_label','bootstrap_label','model_label','page_label')[file_index]]}".encode() and
                   lines[5] == f"sha256={self._manifest['candidate']['files'][file_index]['sha256']}".encode() and
                   lines[6] == b"maintenance_boundaries=HOST_MEDIATED_SEVEN_MATCHED" and
                   lines[7] == b"X2DII_ONE_FILE_PREPLACED_NOT_RUNTIME_VALIDATED" and
                   lines[8] == b"" and lines[9] == marker + b"0", "final worker receipt differs")
        self._completed_identities.append(lines[3].removeprefix(b"identity=").decode("ascii"))
        self._file += 1
        self._boundary = 0
        return f"X2DII_HOST_FILE_ACK:{file_index}:{_sha(decoded_output)}\n".encode("ascii")


def drive_preplacement_process(process, manifest, raw_session, maintenance_session, *, clock=time.time):
    """Connect the fixed native sender's pipes to the existing maintenance API.

    The caller owns qualification and launches only the hash-bound sender.
    This does not start USB, spawn a process, change permissions or authorize
    installation. Session.command keeps its existing raw-packet/completion
    validation; an error closes this host pipe, never the USB recovery worker.
    """
    return _drive_fixed_worker_process(process, manifest, raw_session, maintenance_session,
        coordinator=PreplacementCoordinator(manifest, raw_session), clock=clock)


def _drive_fixed_worker_process(process, manifest, raw_session, maintenance_session, *, coordinator,
                                clock, boot_action=None, cleanup_profile=None):
    """Internal pipe implementation for fixed placement, boot and cleanup."""
    is_boot = boot_action is not None
    is_cleanup = cleanup_profile is not None
    if is_boot and boot_action not in ("activate", "restore"):
        raise ValueError("unsupported fixed boot action")
    if is_cleanup and (cleanup_profile != "owned-cleanup" or is_boot):
        raise ValueError("unsupported or mixed fixed cleanup dialogue")
    count = 1 if is_boot else 4
    error_prefix = ("cleanup host dialogue: " if is_cleanup else
                    "boot host dialogue: " if is_boot else "preplacement host dialogue: ")
    boundary_prefix = ("X2DII_HOST_CLEANUP_BOUNDARY:" if is_cleanup else
                       "X2DII_HOST_BOOT_BOUNDARY:" if is_boot else "X2DII_HOST_BOUNDARY:")
    output_prefix = ("X2DII_CLEANUP_WORKER_OUTPUT:" if is_cleanup else
                     "X2DII_BOOT_WORKER_OUTPUT:" if is_boot else "X2DII_WORKER_OUTPUT:")
    complete_prefix = ("X2DII_HOST_CLEANUP_COMPLETE:" if is_cleanup else
                       "X2DII_HOST_BOOT_COMPLETE:" if is_boot else "X2DII_HOST_FILE_COMPLETE:")
    stream_pattern = "(" + boot_action + ")" if is_boot else "([0-3])"
    final_marker = ("X2DII_FOUR_OWNED_FILES_REMOVED_NOT_FUNCTION_VALIDATED" if is_cleanup else
                    "X2DII_BOOT_FILE_TRANSACTION_NOT_LIFECYCLE_VALIDATION" if is_boot else
                    "X2DII_FOUR_FILES_PREPLACED_NOT_MENU_OR_INSTALLATION_VALIDATION")
    lines = queue.Queue(maxsize=512)
    errors = bytearray()
    stopped = threading.Event()
    buffers = [bytearray() for _ in range(count)]
    completed = 0
    final_seen = False
    active_error = None

    def stdout_reader():
        try:
            while not stopped.is_set():
                line = process.stdout.readline(49153)
                lines.put(line, timeout=1)
                if not line or len(line) > 49152 or not line.endswith(b"\n"):
                    break
        except Exception as error:
            try:
                lines.put(error, timeout=1)
            except queue.Full:
                pass

    def stderr_reader():
        while not stopped.is_set():
            data = process.stderr.read(4096)
            if not data:
                break
            if len(errors) < 65536:
                errors.extend(data[:65536 - len(errors)])

    threads = [threading.Thread(target=stdout_reader, daemon=True),
               threading.Thread(target=stderr_reader, daemon=True)]
    for thread in threads:
        thread.start()

    def need(ok, reason):
        if not ok:
            raise ValueError(error_prefix + reason)

    def completed_evidence():
        if is_cleanup:
            return {"completed_receipts": coordinator.completed_receipts}
        if is_boot:
            return {"action": boot_action, "completed_receipt": coordinator.completed_receipt}
        return {"completed_identities": coordinator.completed_identities}

    def failure_evidence(status):
        return {"status": status, "candidate_sha256": manifest["candidate_sha256"],
                "session_data_sha256": _sha(raw_session), "current_file": completed,
                "worker_outputs": tuple(bytes(value) for value in buffers), "stderr": bytes(errors),
                **completed_evidence()}

    def reply(raw):
        process.stdin.write(raw)
        process.stdin.flush()

    try:
        while True:
            try:
                line = lines.get(timeout=12)
            except queue.Empty as error:
                raise ValueError(error_prefix + "bounded sender wait expired") from error
            if isinstance(line, Exception):
                raise ValueError(error_prefix + "sender pipe failed") from line
            if not line:
                break
            need(len(line) <= 49152 and line.endswith(b"\n"), "unbounded or unfinished sender line")
            text = line.rstrip(b"\n").removesuffix(b"\r").decode("ascii")
            need(not final_seen, "output after final result")
            if text.startswith(boundary_prefix):
                need(completed < count, "boundary after completed transaction")
                command = coordinator.begin_boundary(text)
                # Existing Session.command raises unless all native packet and
                # completion checks succeed. Only its validated text is used.
                response = maintenance_session.command("menu-" + text.split(":", 1)[1][:3], command)
                need(type(response) is str, "maintenance did not return validated text")
                reply(coordinator.accept_reply(response.encode("ascii"), received_epoch=int(clock())))
            elif text.startswith(output_prefix):
                match = re.fullmatch(output_prefix + stream_pattern + r":([A-Za-z0-9+/=]*)", text)
                need(match is not None and completed < count and (is_boot or int(match[1]) == completed),
                     "worker output order differs")
                data = base64.b64decode(match[2], validate=True)
                need(len(buffers[completed]) + len(data) <= 32768, "worker output exceeds bound")
                buffers[completed].extend(data)
            elif text.startswith(complete_prefix):
                match = re.fullmatch(complete_prefix + stream_pattern + r":([A-Za-z0-9+/=]+)", text)
                need(match is not None and completed < count and (is_boot or int(match[1]) == completed),
                     "completed file order differs")
                output = base64.b64decode(match[2], validate=True)
                need(output == bytes(buffers[completed]).replace(b"\r\n", b"\n"),
                     "final receipt differs from retained stream")
                ack = (coordinator.finish(decoded_output=output, stream_completed=True) if is_boot else
                       coordinator.finish_file(file_index=completed, decoded_output=output, stream_completed=True))
                reply(ack)
                completed += 1
            else:
                need(text == final_marker and completed == count,
                     "unexpected or premature final result")
                final_seen = True
        need(final_seen and completed == count, "sender ended without completing fixed transaction")
        need(process.wait(timeout=5) == 0, "native sender process failed")
        threads[1].join(timeout=1)
        need(not threads[1].is_alive(), "sender error output did not close")
        return {"status": ("FOUR_OWNED_FILES_REMOVED_NOT_FUNCTION_VALIDATED" if is_cleanup else
                           "BOOT_FILE_TRANSACTION_NOT_LIFECYCLE_VALIDATED" if is_boot else
                           "FOUR_FILES_PREPLACED_NOT_FEATURE_VALIDATED"), **completed_evidence(),
                "worker_outputs": tuple(bytes(value) for value in buffers), "stderr": bytes(errors)}
    except BaseException as error:
        # A later failure does not undo earlier completed renames. Preserve
        # their exact ownership receipts so recovery never has to guess.
        error.partial_evidence = failure_evidence("FAILED_OR_INCOMPLETE_NOT_INSTALLATION_SUCCESS")
        active_error = error
        raise
    finally:
        stopped.set()
        cleanup_errors = []

        def cleanup(name, operation):
            try:
                return operation()
            except Exception as error:
                cleanup_errors.append({"step": name, "error": repr(error)})

        if process.stdin is not None and not process.stdin.closed:
            cleanup("host_stdin_close", process.stdin.close)
        if cleanup("host_poll", process.poll) is None:
            # Only the caller-supplied HOST sender; never the camera watchdog.
            cleanup("host_wait_after_close", lambda: process.wait(timeout=2))
            if cleanup("host_poll_after_wait", process.poll) is None:
                cleanup("host_terminate", process.terminate)
                cleanup("host_wait_after_terminate", lambda: process.wait(timeout=5))
        for index, thread in enumerate(threads):
            cleanup("reader_join_" + str(index), lambda: thread.join(timeout=1))
            if thread.is_alive():
                cleanup_errors.append({"step": "reader_join_" + str(index), "error": "reader still running"})
        if cleanup_errors:
            if active_error is not None:
                active_error.partial_evidence["cleanup_errors"] = tuple(cleanup_errors)
            else:
                error = ValueError(error_prefix + "host cleanup failed")
                error.partial_evidence = failure_evidence("HOST_CLEANUP_FAILED_NOT_INSTALLATION_SUCCESS")
                error.partial_evidence["cleanup_errors"] = tuple(cleanup_errors)
                raise error


def review_host_source(manifest, raw_session, *, launch_started_utc):
    """Compile-only candidate: no mode or caller flag enables execution."""
    from . import menu_maintenance_boundary as boundary
    kind = boundary.session_kind_for_context(manifest, raw_session)
    programs = [render_supervised_preplacement(manifest, file_index=index, session_kind=kind) for index in range(4)]
    program_hashes = [_sha(text.encode("ascii")) for text in programs]
    commands = []
    for index, digest in enumerate(program_hashes):
        path = worker_path(manifest, index, session_kind=kind)
        commands.append(
            "set -eu; x=$(sha256sum " + path + "); [ \"${x%% *}\" = " + digest +
            " ]; sh " + path + " " + boundary.session_path(manifest, _sha(raw_session)) + " " + _sha(raw_session)
        )
    return _review_fixed_host_source(manifest, raw_session, launch_started_utc=launch_started_utc,
                                     commands=commands, program_hashes=program_hashes)


def _review_fixed_host_source(manifest, raw_session, *, launch_started_utc, commands, program_hashes,
                              boot_profile=None, cleanup_profile=None):
    """Private receiver reuse by three fixed producers; never an executor.

    No public arbitrary-shell method or qualification flag is exposed. Boot
    uses the identical packet decoder, acknowledgement timing and pipe limits.
    """
    if cleanup_profile is not None and (cleanup_profile != "owned-cleanup" or boot_profile is not None):
        raise ValueError("unsupported or mixed fixed cleanup dialogue")
    context = session_context.decode_session(raw_session)
    from .menu_content_transport import original_window_deadline
    window_deadline = original_window_deadline(context["observed_epoch"], launch_started_utc)
    source = usb.host_source(usb.REFERENCE.read_bytes())
    namespace = ("X2d2MenuCleanup_" if cleanup_profile else
                 "X2d2MenuBoot_" if boot_profile else "X2d2MenuPreplace_") + _sha(
        raw_session + launch_started_utc.isoformat().encode("ascii"))[:16]
    source = usb.replace_once(source, "namespace X2d2PeerAdb", "namespace " + namespace)
    source = usb.replace_once(source,
        "        public static ProbeResult Probe() { return new ProbeResult { MatchingInterfaces = Enumerate().Count }; }",
        "        // No separate enumeration entry in this fixed adapter.")
    source = usb.replace_once(source, "        public static string Query() { return RunShell(); }\n", "")
    # Keep the original single identity-only query and its 15s per-connection
    # guard intact. The supervised stream additionally checks its own deadline
    # immediately before/after every host pause; it cannot renew the lease.
    source = usb.replace_once(source, "        private void CheckDeadline() {\n",
        "        private int connectionLimitMs = 15000;\n        private void CheckDeadline() {\n"
        "            CheckSupervisionTime(supervisionClock,2000);\n"
        "            if(sendingMaintenanceAck) CheckMaintenanceTime(ackCheckedEpoch);\n")
    source = usb.replace_once(source, "deadline.ElapsedMilliseconds > 15000",
                              "deadline.ElapsedMilliseconds > connectionLimitMs")
    additions = r'''
        // Review sources have no public method/flag that can change this value.
        private static readonly bool SupervisionQualified = false;
        private static readonly string[] FixedWorkerCommands = new string[] { @COMMANDS@ };
        private static readonly string[] FixedWorkerHashes = new string[] { @HASHES@ };
        private const string FixedCandidate = @CANDIDATE@;
        private const string FixedSession = @SESSION@;
        private const long OriginalSessionDeadline = @DEADLINE@;
        private const long OriginalWindowLaunch = @LAUNCH@;
        private const long OriginalWindowDeadline = @WINDOW_DEADLINE@;
        private const long OriginalObservedEpoch = @OBSERVED@;
        private static int supervisionAttempted;
        private static Stopwatch supervisionClock;
        private static long supervisionRemainingMs;
        private bool sendingMaintenanceAck;
        private long ackCheckedEpoch;

        public sealed class BoundaryDialogue {
            private readonly int file;
            private int boundary;
            private bool waiting, failed;
            private string pendingHash;
            public BoundaryDialogue(int fileIndex) {
                if(fileIndex < 0 || fileIndex > 3) throw new UsbFailure("MENU_FILE_INDEX");
                file = fileIndex;
            }
            public int CompletedBoundaries { get { return boundary; } }
            public bool Waiting { get { return waiting; } }
            public long CheckedEpoch { get; private set; }
            public string AcceptRequest(string line) {
                if(failed || waiting || boundary >= 7) { failed=true; throw new UsbFailure("MENU_BOUNDARY_ORDER"); }
                Match match=Regex.Match(line ?? "", "\\AX2DII_BOUNDARY_REQUEST:"+file+":"+boundary+":([0-9a-f]{64})\\z");
                if(!match.Success) { failed=true; throw new UsbFailure("MENU_BOUNDARY_REQUEST"); }
                pendingHash=match.Groups[1].Value; waiting=true;
                return pendingHash;
            }
            public string AcceptAcknowledgement(string line) {
                if(failed || !waiting) { failed=true; throw new UsbFailure("MENU_BOUNDARY_ORDER"); }
                // The host must have validated the complete maintenance reply.
                // This check binds its compact response to the waiting stream.
                Match match=Regex.Match(line ?? "", "\\AX2DII_BOUNDARY_ACK:"+pendingHash+":([1-9][0-9]{0,9}):([1-9][0-9]{0,9})\\z");
                if(!match.Success) { failed=true; throw new UsbFailure("MENU_BOUNDARY_ACK"); }
                long started=long.Parse(match.Groups[1].Value, CultureInfo.InvariantCulture);
                long checkedAt=long.Parse(match.Groups[2].Value, CultureInfo.InvariantCulture);
                if(started<OriginalObservedEpoch || started>checkedAt || checkedAt>OriginalSessionDeadline) { failed=true; throw new UsbFailure("MENU_BOUNDARY_TIME"); }
                try { CheckMaintenanceTime(checkedAt); }
                catch { failed=true; throw; }
                CheckedEpoch=checkedAt;
                waiting=false; boundary++;
                return line+"\n";
            }
            public void Finish() {
                if(failed || waiting || boundary!=7) { failed=true; throw new UsbFailure("MENU_BOUNDARY_INCOMPLETE"); }
            }
        }
        private static long SupervisionNow() {
            return (long)(DateTime.UtcNow-new DateTime(1970,1,1,0,0,0,DateTimeKind.Utc)).TotalSeconds;
        }
        private static void CheckSupervisionTime(Stopwatch batch,int reserveMs=0) {
            long now=SupervisionNow();
            if(batch==null || now<OriginalWindowLaunch || now>OriginalSessionDeadline ||
               now*1000+reserveMs>=OriginalWindowDeadline*1000 ||
               batch.ElapsedMilliseconds+reserveMs>=supervisionRemainingMs)
                throw new UsbFailure("MENU_SUPERVISION_DEADLINE");
        }
        private static void CheckMaintenanceTime(long checkedAt) {
            long now=SupervisionNow();
            if(checkedAt<OriginalObservedEpoch || checkedAt>now || now-checkedAt>8)
                throw new UsbFailure("MENU_BOUNDARY_TIME");
        }
        private static string ReadBoundedHostLine() {
            var pending=System.Threading.Tasks.Task<string>.Factory.StartNew(delegate {
                var line=new StringBuilder();
                for(int i=0;i<160;i++) {
                    int value=Console.In.Read();
                    if(value<0) throw new UsbFailure("MENU_HOST_EOF");
                    if(value==10) return line.ToString();
                    if(value<32 || value>126) throw new UsbFailure("MENU_HOST_CHARACTER");
                    line.Append((char)value);
                }
                throw new UsbFailure("MENU_HOST_LINE_LIMIT");
            });
            if(!pending.Wait(7500)) throw new UsbFailure("MENU_HOST_REPLY_TIMEOUT");
            return pending.Result;
        }
        private static string RunFixedWorker(int file, Stopwatch batch) {
            using(AdbUsbCheck stream=new AdbUsbCheck()) {
                stream.connectionLimitMs=45000;
                ReadResult actual=new ReadResult();
                stream.Open(actual);
                stream.Send("CNXN",0x01000000,4096,Encoding.ASCII.GetBytes("host::\0"));
                Packet packet=stream.Receive();
                ValidateHandshakePacket(packet.Command,packet.A,packet.B,packet.Data.Length);
                string marker="X2DII_WORKER_"+FixedSession.Substring(0,24)+"_"+file+"_RC=";
                string wire="("+FixedWorkerCommands[file]+"); r=$?; printf '\\n"+marker+"%s\\n' \"$r\"";
                stream.Send("OPEN",1,0,Encoding.ASCII.GetBytes("shell:"+wire+"\0"));
                uint remote=0;
                bool stdinWritePending=false;
                var text=new StringBuilder();
                var pendingLine=new StringBuilder();
                var dialogue=new BoundaryDialogue(file);
                for(int packets=0;packets<512;packets++) {
                    CheckSupervisionTime(batch);
                    packet=stream.Receive();
                    if(packet.B!=1) throw new UsbFailure("ADB_STREAM_ID");
                    if((packet.Command==Cmd("OKAY") || packet.Command==Cmd("CLSE")) && packet.Data.Length!=0)
                        throw new UsbFailure("MENU_CONTROL_PAYLOAD");
                    if(packet.Command==Cmd("OKAY")) {
                        if(remote==0) remote=AcceptRemoteId(remote,packet.A);
                        else if(packet.A!=remote || !stdinWritePending) throw new UsbFailure("MENU_UNEXPECTED_OKAY");
                        else stdinWritePending=false;
                        continue;
                    }
                    if(remote==0 || packet.A!=remote) throw new UsbFailure("ADB_REMOTE_ID");
                    if(packet.Command==Cmd("WRTE")) {
                        if(text.Length+packet.Data.Length>32768) throw new UsbFailure("MENU_OUTPUT_LIMIT");
                        foreach(byte value in packet.Data) if(value!=10 && value!=13 && (value<32 || value>126))
                            throw new UsbFailure("MENU_OUTPUT_CHARACTER");
                        string chunk=Encoding.ASCII.GetString(packet.Data);
                        text.Append(chunk);
                        // ACK incoming data before a potentially slow maintenance call.
                        stream.Send("OKAY",1,remote,new byte[0]);
                        Console.WriteLine("X2DII_WORKER_OUTPUT:"+file+":"+Convert.ToBase64String(packet.Data));
                        Console.Out.Flush();
                        foreach(char value in chunk) {
                            if(value!='\n') {
                                if(pendingLine.Length>=4096) throw new UsbFailure("MENU_OUTPUT_LINE_LIMIT");
                                pendingLine.Append(value); continue;
                            }
                            string line=pendingLine.ToString(); pendingLine.Clear();
                            if(line.EndsWith("\r",StringComparison.Ordinal)) line=line.Substring(0,line.Length-1);
                            if(!line.StartsWith("X2DII_BOUNDARY_REQUEST:",StringComparison.Ordinal)) continue;
                            if(stdinWritePending) throw new UsbFailure("MENU_STDIN_UNACKNOWLEDGED");
                            string hash=dialogue.AcceptRequest(line);
                            Console.WriteLine("X2DII_HOST_BOUNDARY:"+file+":"+dialogue.CompletedBoundaries+":"+hash);
                            Console.Out.Flush();
                            string response=ReadBoundedHostLine();
                            CheckSupervisionTime(batch);
                            string ack=dialogue.AcceptAcknowledgement(response);
                            stream.ackCheckedEpoch=dialogue.CheckedEpoch;
                            stream.sendingMaintenanceAck=true;
                            try { stream.Send("WRTE",1,remote,Encoding.ASCII.GetBytes(ack)); }
                            finally { stream.sendingMaintenanceAck=false; }
                            stdinWritePending=true;
                        }
                        continue;
                    }
                    if(packet.Command==Cmd("CLSE")) {
                        stream.Send("CLSE",1,remote,new byte[0]);
                        if(stdinWritePending || pendingLine.Length!=0) throw new UsbFailure("MENU_UNFINISHED_STREAM");
                        dialogue.Finish();
                        string output=text.ToString().Replace("\r\n","\n");
                        if(!output.EndsWith("\n"+marker+"0\n",StringComparison.Ordinal) ||
                           output.IndexOf(marker,StringComparison.Ordinal)!=output.LastIndexOf(marker,StringComparison.Ordinal))
                            throw new UsbFailure("MENU_WORKER_STATUS");
                        if(!output.Contains("\ncandidate_sha256="+FixedCandidate+"\n") ||
                           !output.Contains("\nfile_index="+file+"\n") ||
                           !output.Contains("\nmaintenance_boundaries=HOST_MEDIATED_SEVEN_MATCHED\n") ||
                           !output.Contains("\nX2DII_ONE_FILE_PREPLACED_NOT_RUNTIME_VALIDATED\n"))
                            throw new UsbFailure("MENU_WORKER_RECEIPT");
                        CheckSupervisionTime(batch);
                        return output;
                    }
                    throw new UsbFailure("ADB_STREAM_PACKET");
                }
                throw new UsbFailure("ADB_PACKET_LIMIT");
            }
        }
        public static string RunFourFiles() {
            if(!SupervisionQualified) throw new UsbFailure("MENU_SUPERVISION_NOT_QUALIFIED");
            if(System.Threading.Interlocked.Exchange(ref supervisionAttempted,1)!=0)
                throw new UsbFailure("MENU_SUPERVISION_ALREADY_ATTEMPTED");
            supervisionClock=Stopwatch.StartNew();
            supervisionRemainingMs=(OriginalWindowDeadline-SupervisionNow())*1000;
            var batch=supervisionClock;
            CheckSupervisionTime(batch);
            RunShell(); // Existing fixed su identity query, not arbitrary execution.
            for(int file=0;file<4;file++) {
                CheckSupervisionTime(batch);
                string output=RunFixedWorker(file,batch);
                Console.WriteLine("X2DII_HOST_FILE_COMPLETE:"+file+":"+Convert.ToBase64String(Encoding.ASCII.GetBytes(output)));
                Console.Out.Flush();
                // Host verifies the full receipt, including stat identity and
                // session/metadata/hash, before a later worker can be started.
                string fileAck=ReadBoundedHostLine();
                string outputHash;
                using(var hasher=System.Security.Cryptography.SHA256.Create()) {
                    outputHash=BitConverter.ToString(hasher.ComputeHash(Encoding.ASCII.GetBytes(output))).Replace("-","").ToLowerInvariant();
                }
                if(fileAck!="X2DII_HOST_FILE_ACK:"+file+":"+outputHash)
                    throw new UsbFailure("MENU_FILE_ACK_MISMATCH");
                CheckSupervisionTime(batch);
            }
            return "X2DII_FOUR_FILES_PREPLACED_NOT_MENU_OR_INSTALLATION_VALIDATION";
        }
'''
    if boot_profile is not None:
        action, first_boundary = boot_profile
        if action not in ("activate", "restore") or first_boundary not in ((0,) if action == "activate" else (0, 6)):
            raise ValueError("invalid fixed boot dialogue")
        count = 12 if action == "activate" else 8
        # Only fixed, reviewed protocol differences. Receiver implementation
        # and deadline checks above remain identical to the four-file route.
        replacements = (
            ("private int boundary;", f"private int boundary={first_boundary};"),
            ("fileIndex > 3", "fileIndex > 0"),
            ("boundary >= 7", f"boundary >= {count}"),
            ("boundary!=7", f"boundary!={count}"),
            ('"\\\\AX2DII_BOUNDARY_REQUEST:"+file+":"+boundary+',
             f'"\\\\AX2DII_BOOT_BOUNDARY_REQUEST:{action}:"+boundary+'),
            ('"\\\\AX2DII_BOUNDARY_ACK:"+pendingHash+', '"\\\\AX2DII_BOOT_BOUNDARY_ACK:"+pendingHash+'),
            ('"X2DII_WORKER_"+FixedSession.Substring(0,24)+"_"+file+"_RC="',
             f'"X2DII_BOOT_WORKER_"+FixedSession.Substring(0,24)+"_{action}_RC="'),
            ('"X2DII_WORKER_OUTPUT:"+file+":"+', f'"X2DII_BOOT_WORKER_OUTPUT:{action}:"+'),
            ('line.StartsWith("X2DII_BOUNDARY_REQUEST:"', 'line.StartsWith("X2DII_BOOT_BOUNDARY_REQUEST:"'),
            ('"X2DII_HOST_BOUNDARY:"+file+":"+', f'"X2DII_HOST_BOOT_BOUNDARY:{action}:"+'),
            ('!output.Contains("\\nfile_index="+file+"\\n")', f'!output.Contains("\\naction={action}\\n")'),
            ('!output.Contains("\\nmaintenance_boundaries=HOST_MEDIATED_SEVEN_MATCHED\\n")',
             '!output.Contains("\\nmaintenance_boundaries=HOST_MEDIATED_FIXED_BOOT_MATCHED\\n")'),
            ('!output.Contains("\\nX2DII_ONE_FILE_PREPLACED_NOT_RUNTIME_VALIDATED\\n")',
             '!output.Contains("\\nX2DII_RC_FILE_COMMITTED_NOT_LIFECYCLE_VALIDATED\\n")'),
            ("public static string RunFourFiles()", "public static string RunBoot()"),
            ("for(int file=0;file<4;file++)", "for(int file=0;file<1;file++)"),
            ('"X2DII_HOST_FILE_COMPLETE:"+file+":"+', f'"X2DII_HOST_BOOT_COMPLETE:{action}:"+'),
            ('"X2DII_HOST_FILE_ACK:"+file+":"+', f'"X2DII_HOST_BOOT_ACK:{action}:"+'),
            ('"X2DII_FOUR_FILES_PREPLACED_NOT_MENU_OR_INSTALLATION_VALIDATION"',
             '"X2DII_BOOT_FILE_TRANSACTION_NOT_LIFECYCLE_VALIDATION"'),
        )
        for before, after in replacements:
            additions = usb.replace_once(additions, before, after)
    if cleanup_profile is not None:
        # Only protocol names and the four-boundary count differ. Reuse the
        # original byte receiver, ACK timing, bounds and deadline checks.
        replacements = (
            ("boundary >= 7", "boundary >= 4"),
            ("boundary!=7", "boundary!=4"),
            ("X2DII_BOUNDARY_REQUEST:", "X2DII_CLEANUP_BOUNDARY_REQUEST:"),
            ("X2DII_BOUNDARY_ACK:", "X2DII_CLEANUP_BOUNDARY_ACK:"),
            ("X2DII_WORKER_", "X2DII_CLEANUP_WORKER_"),
            ("X2DII_HOST_BOUNDARY:", "X2DII_HOST_CLEANUP_BOUNDARY:"),
            ("HOST_MEDIATED_SEVEN_MATCHED", "HOST_MEDIATED_FOUR_CLEANUP_MATCHED"),
            ("X2DII_ONE_FILE_PREPLACED_NOT_RUNTIME_VALIDATED", "X2DII_ONE_OWNED_FILE_REMOVED_NOT_FUNCTION_VALIDATED"),
            ("public static string RunFourFiles()", "public static string RunCleanup()"),
            ("X2DII_HOST_FILE_COMPLETE:", "X2DII_HOST_CLEANUP_COMPLETE:"),
            ("X2DII_HOST_FILE_ACK:", "X2DII_HOST_CLEANUP_ACK:"),
            ("X2DII_FOUR_FILES_PREPLACED_NOT_MENU_OR_INSTALLATION_VALIDATION", "X2DII_FOUR_OWNED_FILES_REMOVED_NOT_FUNCTION_VALIDATED"),
        )
        for before, after in replacements:
            # Request and worker prefixes intentionally occur twice: regex plus
            # line recognition, and shell status plus chunk output respectively.
            expected = 2 if before in ("X2DII_BOUNDARY_REQUEST:", "X2DII_WORKER_") else 1
            if additions.count(before) != expected:
                raise ValueError("fixed cleanup codec template changed: " + before)
            additions = additions.replace(before, after)
    for token, value in {"@COMMANDS@": ",".join(json.dumps(x) for x in commands),
                         "@HASHES@": ",".join(json.dumps(x) for x in program_hashes),
                         "@CANDIDATE@": json.dumps(manifest["candidate_sha256"]),
                         "@SESSION@": json.dumps(_sha(raw_session)),
                         "@DEADLINE@": str(context["observed_epoch"] + 600),
                         "@OBSERVED@": str(context["observed_epoch"]),
                         "@LAUNCH@": str(int(launch_started_utc.timestamp())),
                         "@WINDOW_DEADLINE@": str(int(window_deadline))}.items():
        additions = additions.replace(token, value)
    return usb.replace_once(source, "        private static string RunShell()", additions + "\n        private static string RunShell()")
