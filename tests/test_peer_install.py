"""Peer script source tests; shell writes only to guarded host fixtures.

The fixture uses real file bytes and shell copies/renames/deletes. UID, SELinux,
mounts, service control and sync are mocked and do not qualify device behavior.
"""
from datetime import datetime, timedelta, timezone
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from tools import prepare_peer_install as peer
from tools.output_guard import output_directory

SH = Path("C:/Program Files/Git/bin/sh.exe")


def test_source_only_publication_has_exact_inventory_representation():
    """The public source-only emitter adds one empty field; not a package."""
    current = peer.inventory()
    with tempfile.TemporaryDirectory(prefix="source-only-contract-", dir=peer.ROOT / "build") as folder:
        destination = Path(folder) / "source-only"
        emitted = peer.prepare(destination)
        saved = json.loads((destination / "peer-install-source.json").read_bytes())
        assert emitted == saved == {**current, "script_hashes": {}}
        assert saved["installable"] is False and saved["package_created"] is False
        assert sorted(path.name for path in destination.iterdir()) == ["peer-install-source.json"]


class PeerInstallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = peer.inventory()
        output_directory(peer.ROOT / "build")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="peer-source-test-", dir=peer.ROOT / "build")
        self.root = Path(self.temp.name)
        self.q = {"candidate_sha256": self.manifest["candidate_sha256"], "synthetic": True,
                  # Identity shape only: no real archive and never publication authority.
                  "delivery_identity": {"package_sha256": "d" * 64, "package_bytes": 16384,
                                        "format_version": "x2dii-delivery-content-ustar-v1",
                                        "member_manifest_sha256": "e" * 64},
                  "session_nonce": "b" * 32,
                  "observed_utc": datetime.now(timezone.utc).isoformat(), "boot_id": "11111111-2222-3333-4444-555555555555",
                  "uid": 0, "domain": "u:r:su:s0", "active_slot": "slot_2", "official_slot": "slot_1",
                  "mount_namespace": "mnt:[4026531840]", "init_mount_namespace": "mnt:[4026531840]",
                  "observer": {"pid": 100, "start_ticks": "12345", "exe_target": "/system/bin/adbd",
                               "exe_sha256": peer.sha(b"observer"), "domain": "u:r:su:s0",
                               "mount_namespace": "mnt:[4026531840]"},
                  "system_mount": {"device": "/dev/block/current-attested-slot", "filesystem": "ext4", "options": "ro,seclabel,relatime"},
                  "slot_readback": {slot + ".status_" + field: ("0" if slot == "slot_1" and field == "active" else "1")
                                    for slot in ("slot_1", "slot_2") for field in ("active", "bootable", "successful")},
                  "metadata": {path: {"uid": 0, "gid": 0, "mode": "644", "label": "u:object_r:system_file:s0", "xattr_names": ["security.selinux"]}
                               for path in [peer.boot.TARGET, *(f["target"] for f in self.manifest["candidate"]["files"])]},
                  "init_scan_roots": ["/system/etc/init"], "init_scan_roots_complete": True, "gates": {},
                  "final_installation_approval": {"approved": True, "purpose": "final_camera_installation",
                                                  "candidate_sha256": self.manifest["candidate_sha256"],
                                                  "boot_id": "11111111-2222-3333-4444-555555555555", "session_nonce": "b" * 32}}
        from tests.test_runtime_observation import synthetic_observation
        self.q["runtime_observation"] = synthetic_observation(self.q, self.manifest["candidate"]["gui_sha256"])
        self.scripts = peer._render(self.manifest, self.q)

    def tearDown(self):
        self.temp.cleanup()

    def validated_shape_fixture(self):
        """Structural fixtures only; never sent to prepare() to publish scripts."""
        self.q["synthetic"] = False
        subject = peer.execution_subject_sha256(self.manifest, self.q)
        build = peer.build_subject_sha256(self.manifest)
        runtime = peer.runtime_subject_sha256(self.manifest, self.q)
        self.q.update(build_subject_sha256=build, runtime_subject_sha256=runtime)
        self.q["execution_subject_sha256"] = subject
        self.q["final_installation_approval"]["execution_subject_sha256"] = subject
        for gate in peer.GATES:
            self.q["gates"][gate] = {}
            for phase in peer.GATE_PHASES[gate]:
                path = self.root / (gate + "-" + phase + ".json")
                bindings = peer.release_identity.gate_bindings(
                    phase, candidate_sha256=self.q["candidate_sha256"], build_subject_sha256=build,
                    runtime_subject_sha256=runtime, boot_id=self.q["boot_id"],
                    delivery_identity=self.q["delivery_identity"])
                proof = dict(bindings, result="PASS", synthetic=False, gate=gate, test_fixture_only=True)
                path.write_text(json.dumps(proof))
                self.q["gates"][gate][phase] = dict(bindings, status="PASS",
                    evidence_file=str(path.relative_to(peer.ROOT)), evidence_sha256=peer.sha(path.read_bytes()))
        return self.q

    def shell_fixture(self, *, stage_inputs=True):
        for directory in ("system/etc/init", "system/lib64", "system/bin", "blackbox", "tmp", "proc/self/attr",
                          "proc/sys/kernel/random", "proc/123", "proc/100/attr"):
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        (self.root / "system/etc/init/camera-gui.rc").write_bytes(peer.boot.STOCK.read_bytes())
        (self.root / "system/bin/camera-gui").write_bytes(b"mock GUI; exact hash supplied by mock sha256sum")
        # Generate Linux kernel model text as LF, even on Windows. This is not
        # a decoder/normalizer for actual camera bytes or malformed controls.
        (self.root / "proc/self/attr/current").write_text("u:r:su:s0\n", newline="\n")
        (self.root / "proc/sys/kernel/random/boot_id").write_text(self.q["boot_id"] + "\n", newline="\n")
        (self.root / "proc/123/maps").write_text("unrelated-library\n", newline="\n")
        (self.root / "proc/100/exe").write_bytes(b"observer")
        (self.root / "proc/100/attr/current").write_text("u:r:su:s0\n", newline="\n")
        (self.root / "proc/100/stat").write_text("100 (adbd) S " + "0 " * 18 + "12345 0\n", newline="\n")
        # Model the observed core files and process identities. These are inert
        # host bytes; hash mappings below substitute only their exact originals.
        self.core_hashes, self.core_links = {}, {}
        observation = self.q["runtime_observation"]
        for name in ("gui", "service", "capture_owner", "sensor"):
            record = observation[name]
            artifact = record if name == "sensor" else record["artifact"]
            path = self.root / artifact["path"].lstrip("/")
            path.parent.mkdir(parents=True, exist_ok=True)
            raw = ("SYNTHETIC CORE FILE " + artifact["path"]).encode().ljust(artifact["bytes"], b"\0")
            path.write_bytes(raw)
            self.core_hashes[path] = (peer.sha(raw), artifact["sha256"])
            if name != "sensor":
                process = record["process"]
                proc = self.root / "proc" / str(process["pid"])
                (proc / "attr").mkdir(parents=True, exist_ok=True)
                (proc / "stat").write_text(str(process["pid"]) + " (synthetic) S " + "0 " * 18 + process["start_ticks"] + " 0\n", newline="\n")
                (proc / "attr/current").write_text(process["domain"] + "\n", newline="\n")
                (proc / "exe").write_bytes(raw)
                self.core_hashes[proc / "exe"] = (peer.sha(raw), process["exe_sha256"])
                self.core_links[proc / "exe"] = process["exe_target"]
        (self.root / "gui-service-state").write_text(observation["gui"]["service_state"])
        (self.root / "core-service-state").write_text(observation["service"]["service_state"])
        self.posix = subprocess.run([str(SH), "-c", 'cygpath -u "$1"', "fixture", str(self.root)],
                                    capture_output=True, text=True, check=True).stdout.strip()
        self.mount_line = "/dev/block/current-attested-slot " + self.posix + "/system ext4 ro,seclabel,relatime 0 0\n"
        (self.root / "proc/mounts").write_text(self.mount_line, newline="\n")
        source = self.root / "blackbox/x2dii-menu-stage" / self.manifest["candidate_sha256"][:24]
        if stage_inputs:
            source.mkdir(parents=True)
            for entry in self.manifest["candidate"]["files"]:
                (source / Path(entry["source"]).name).write_bytes((peer.ROOT / entry["source"]).read_bytes())
            (source / "camera-gui.rc.proposed").write_bytes(peer.boot.activate(peer.boot.STOCK.read_bytes()))
        return source

    def run_script(self, name, *, mode="normal", fail_move=0, boundary_hook="", process_runner=None):
        # Substitute only fixed absolute filesystem roots and executable PATH;
        # the generated operation ordering and checks execute as rendered.
        source = self.scripts[name].replace("export PATH=/system/bin:/system/xbin:/sbin", "export PATH=/usr/bin:/bin")
        head, parser = source.split("# SESSION_DATA_PARSER_BEGIN\n", 1)
        parser, tail = parser.split("# SESSION_DATA_PARSER_END\n", 1)
        source = head + "# HOST_PARSER_PLACEHOLDER\n" + tail
        for prefix in ("/system", "/blackbox", "/tmp", "/proc"):
            source = source.replace(prefix, self.posix + prefix)
        # This artifact address comes from data, not a rendered path literal.
        # Root only the filesystem argument in the host fixture; leave the
        # observed session and executable-link comparison unchanged.
        source = source.replace('core_artifact "$X2DII_SESSION_CORE_CAPTURE_EXE_TARGET"',
                                'core_artifact "$fixture$X2DII_SESSION_CORE_CAPTURE_EXE_TARGET"')
        source = source.replace("# HOST_PARSER_PLACEHOLDER\n", parser)
        data = peer.session_data(self.manifest, self.q)
        (self.root / "session-context.data").write_bytes(data)
        core_hash_cases = "\n".join(
            f'  "$fixture/{path.relative_to(self.root).as_posix()}:{original}") printf \'{digest}  %s\\n\' "$1"; return;;'
            for path, (original, digest) in self.core_hashes.items())
        core_hash_paths = "|".join([
            f'"$fixture/{path.relative_to(self.root).as_posix()}"'
            for path in self.core_hashes] + ["-*"])
        core_link_cases = "\n".join(
            f'  "$fixture/{path.relative_to(self.root).as_posix()}") echo {target};;'
            for path, target in self.core_links.items())
        wrapper = f'''
fixture={peer.shlex.quote(self.posix)}
mode={peer.shlex.quote(mode)}
moves=0
boundary() {{ :; }}
id() {{ printf '0\\n'; }}
fixture_getprop() {{
 case "$1" in
  init.svc.camera-service) cat "$fixture/core-service-state";;
  init.svc.camera-gui) if [ "$mode" = running ]; then echo running; else cat "$fixture/gui-service-state"; fi;;
  *) return 1;;
 esac
}}
getprop() {{ fixture_getprop "$@"; }}
pidof() {{
 [ "$mode" != pidof_error ] || return 2
 case "$1" in
  camera-service) echo {self.q['runtime_observation']['service']['process']['pid']};;
  camera-gui)
   if [ "$mode" != running ]; then
    fixture_gui_state=$(cat "$fixture/gui-service-state") || return $?
    [ "$fixture_gui_state" = running ] || return 1
   fi
   echo {self.q['runtime_observation']['gui']['process']['pid']};;
  *) return 1;;
 esac
}}
stop() {{ printf 'stop:%s\\n' "$*" >> "$fixture/operations"; printf stopped > "$fixture/gui-service-state"; boundary stop; }}
sleep() {{ :; }}
unrd() {{ case "$1" in slot_1.status_active) echo 0;; *) echo 1;; esac; }}
sha256sum() {{
 if [ "$#" = 1 ]; then
  case "$1" in
 {core_hash_paths}) ;;
   *) /usr/bin/sha256sum "$1" || return 1
      return;;
  esac
  fixture_digest=$(/usr/bin/sha256sum "$1") || return 1
  case "$1:${{fixture_digest%% *}}" in
{core_hash_cases}
  esac
  # The first real hash already proved the queried bytes did not match any
  # synthetic core mapping. Return that exact output once, including its LF.
  printf '%s\\n' "$fixture_digest"
  return
 fi
 /usr/bin/sha256sum "$@"
}}
fixture_stat() {{ if [ "$2" = '%u:%g:%a' ]; then if [ -d "$3" ]; then echo '0:0:700'; else echo '0:0:600'; fi; elif [ "$2" = '%u %g %a' ]; then if [ -d "$3" ]; then echo '0 0 700'; elif [ "${{3##*/}}" = session-context.data ]; then echo '0 0 600'; elif [ "$mode" = bad_metadata ]; then echo '0 0 600'; else echo '0 0 644'; fi; else /usr/bin/stat "$@"; fi; }}
stat() {{ fixture_stat "$@"; }}
fixture_ls() {{ printf 'u:object_r:system_file:s0 %s\\n' "$2"; }}
ls() {{ fixture_ls "$@"; }}
fixture_readlink() {{
 case "$1" in
  */ns/mnt) [ "$mode" != wrong_namespace ] || {{ echo 'mnt:[9]'; return; }}; echo 'mnt:[4026531840]';;
  */100/exe)
   if [ "$mode" = observer_reused_midquery ]; then printf '100 (adbd) S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 99999 0\\n' > "$fixture/proc/100/stat"; fi
   echo /system/bin/adbd;;
{core_link_cases}
  *) /usr/bin/readlink "$@";;
 esac
}}
readlink() {{ fixture_readlink "$@"; }}
chcon() {{ printf 'chcon:%s\\n' "$*" >> "$fixture/operations"; }}
chown() {{ printf 'chown:%s\\n' "$*" >> "$fixture/operations"; }}
sync() {{ printf 'sync\\n' >> "$fixture/operations"; }}
grep() {{ [ "$mode" != maps_error ] || return 2; /usr/bin/grep "$@"; }}
mkdir() {{
 if [ "$mode" = lock_contended ] && [ "$1" = "$fixture/tmp/x2dii-menu-install.lock" ]; then
  /usr/bin/mkdir "$1"
  printf '/dev/block/current-attested-slot %s/system ext4 rw,seclabel,relatime 0 0\\n' "$fixture" > "$fixture/proc/mounts"
  return 1
 fi
 /usr/bin/mkdir "$@" || return $?
 [ "$1" != "$fixture/tmp/x2dii-menu-install.lock" ] || boundary lock
}}
mount() {{
 printf 'mount:%s\\n' "$*" >> "$fixture/operations"
 case "$2" in remount,rw) state=rw;; remount,ro) state=ro;; *) return 9;; esac
 printf '/dev/block/current-attested-slot %s/system ext4 %s,seclabel,relatime 0 0\\n' "$fixture" "$state" > "$fixture/proc/mounts"
 [ "$state" != rw ] || boundary remount
}}
mv() {{
 moves=$((moves+1))
 printf 'mv:%s\\n' "$*" >> "$fixture/operations"
 [ "$moves" != {fail_move} ] || return 75
 /usr/bin/mv "$@" || return $?
 boundary move
}}
rm() {{ printf 'rm:%s\\n' "$*" >> "$fixture/operations"; /usr/bin/rm "$@"; }}
'''
        if process_runner is not None:
            return process_runner(wrapper + boundary_hook + source,
                                  [self.posix + "/session-context.data", peer.sha(data)])
        # Same-Popen install diagnostic completed at 122.469 s after the
        # original 120 s deadline. User approved 160 s for this host test
        # alone; activate/restore and every camera deadline remain unchanged.
        timeout = 160 if name == "install-files.sh" else 120
        return subprocess.run([str(SH), "-s", "--", self.posix + "/session-context.data", peer.sha(data)],
                              # Windows process startup is paid on every disk /
                              # process recheck. The unchanged distinct-owner
                              # install completed in 61.594s without tracing
                              # (build/host-shell-timeout-20261005), exceeding
                              # the former 60s host limit. Allow bounded host
                              # headroom; device leases/checks stay unchanged.
                              input=(wrapper + boundary_hook + source).encode("ascii"), capture_output=True, timeout=timeout)

    def test_host_script_wait_extends_only_install_files(self):
        self.shell_fixture()
        for name, expected_timeout in (("install-files.sh", 160),
                                       ("activate-boot.sh", 120),
                                       ("restore-boot.sh", 120)):
            with self.subTest(name=name):
                reply = subprocess.CompletedProcess([str(SH)], 0, b"actual host reply\n", b"")
                with mock.patch.object(subprocess, "run", return_value=reply) as process:
                    self.assertIs(self.run_script(name), reply)
                process.assert_called_once()
                self.assertEqual(process.call_args.kwargs["timeout"], expected_timeout)

    def test_host_script_timeout_propagates_without_retry(self):
        self.shell_fixture()
        for name, expected_timeout in (("install-files.sh", 160),
                                       ("activate-boot.sh", 120),
                                       ("restore-boot.sh", 120)):
            with self.subTest(name=name):
                failure = subprocess.TimeoutExpired([str(SH)], expected_timeout,
                                                    output=b"partial\n", stderr=b"native error\n")
                with mock.patch.object(subprocess, "run", side_effect=failure) as process:
                    with self.assertRaises(subprocess.TimeoutExpired) as caught:
                        self.run_script(name)
                self.assertIs(caught.exception, failure)
                process.assert_called_once()
                self.assertEqual(process.call_args.kwargs["timeout"], expected_timeout)
                self.assertEqual(caught.exception.output, b"partial\n")
                self.assertEqual(caught.exception.stderr, b"native error\n")

    def test_current_unresolved_generation_writes_only_manifest(self):
        result = peer.prepare(self.root / "output")
        self.assertFalse(result["scripts_emitted"])
        self.assertFalse(result["installable"])
        self.assertEqual(set((self.root / "output").iterdir()), {self.root / "output/peer-install-source.json"})
        self.assertEqual(set(result["required_gates"].values()), {"PENDING"})
        self.assertEqual(len(result["candidate"]["files"]), 4)
        self.assertIsNone(result["execution_subject_sha256"])
        self.assertEqual(result["renderer_source_sha256"], peer.sha(Path(peer.__file__).read_bytes()))

    def test_local_shell_syntax_all_three_scripts(self):
        for name, script in self.scripts.items():
            with self.subTest(name=name):
                result = subprocess.run([str(SH), "-n"], input=script.encode(), capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.assertNotIn("mmcblk0p17", script)
                self.assertNotIn("preview-loader", script)
                self.assertNotRegex(script, r"(?m)^\s*(start|reboot|adb|scp)\s")

    def test_hash_adapter_computes_once_and_preserves_actual_output_mapping_and_errors(self):
        self.shell_fixture()
        first = self.root / "hash-control.data"
        second = self.root / "hash-second.data"
        first.write_bytes(b"abc\n")
        second.write_bytes(b"other real bytes\n")
        (self.root / "hash-directory").mkdir()
        gui = self.root / "system/bin/camera-gui"
        mapped_digest = self.core_hashes[gui][1]
        header = "#!/system/bin/sh\n# SESSION_DATA_PARSER_BEGIN\n# SESSION_DATA_PARSER_END\n"
        for case in ("mapped", "unmapped", "missing", "directory", "multiple", "changed_mapped"):
            with self.subTest(case=case):
                if case == "mapped":
                    arguments = '"/system/bin/camera-gui"'
                elif case == "changed_mapped":
                    gui.write_bytes(gui.read_bytes() + b"changed source bytes")
                    arguments = '"/system/bin/camera-gui"'
                elif case == "missing":
                    arguments = '"$fixture/missing-hash-control.data"'
                elif case == "directory":
                    arguments = '"$fixture/hash-directory"'
                elif case == "multiple":
                    arguments = '"$fixture/hash-control.data" "$fixture/hash-second.data"'
                else:
                    arguments = '"$fixture/hash-control.data"'
                self.scripts["hash-reference"] = header + '/usr/bin/sha256sum ' + arguments + '\n'
                reference = self.run_script("hash-reference")
                self.scripts["hash-control"] = (header + "PS4='+HOST_HASH:'\nset -x\nsha256sum " +
                    arguments + '\nhash_status=$?\nset +x\nexit "$hash_status"\n')
                actual = self.run_script("hash-control")
                self.assertEqual(actual.returncode, reference.returncode)
                expected = ((mapped_digest + "  " + self.posix + "/system/bin/camera-gui\n").encode()
                            if case == "mapped" else reference.stdout)
                self.assertEqual(actual.stdout, expected)
                if case in ("missing", "directory"):
                    self.assertEqual(actual.returncode, 1)
                    self.assertIn(reference.stderr.strip(), actual.stderr)
                # Real shell trace at the OS boundary counts computations;
                # no source-string assertion or synthetic digest substitutes
                # for hashing the actual bytes, including changed/missing data.
                calls = [line for line in actual.stderr.splitlines()
                         if line.lstrip(b"+").startswith(b"HOST_HASH:/usr/bin/sha256sum ")]
                self.assertEqual(len(calls), 1, actual.stderr.decode(errors="replace"))

    def test_host_native_cat_preserves_fresh_bytes_including_nul_and_incomplete_lines(self):
        self.shell_fixture()
        header = "#!/system/bin/sh\n# SESSION_DATA_PARSER_BEGIN\n# SESSION_DATA_PARSER_END\n"
        target = self.root / "proc/234/stat"
        for raw in (b"", b"no newline", b"a\nb\n\n", b"a\nb",
                    b"back\\slash\r\n", "camera \u76f8\u673a\n".encode(),
                    b"\0first\0last\0", b"prefix\0suffix", b"x" * 65536 + b"\n"):
            with self.subTest(raw_prefix=raw[:20], bytes=len(raw)):
                target.write_bytes(raw)
                argument = '"/proc/234/stat"'
                self.scripts["cat-reference"] = header + '/usr/bin/cat ' + argument + '\n'
                reference = self.run_script("cat-reference")
                self.scripts["cat-control"] = (header + "PS4='+HOST_CAT:'\nset -x\ncat " +
                    argument + '\ncat_status=$?\nset +x\nexit "$cat_status"\n')
                actual = self.run_script("cat-control")
                self.assertEqual((actual.returncode, actual.stdout),
                                 (reference.returncode, reference.stdout))
                self.assertEqual(actual.stdout, raw)
                # No read/EOF fast path: a failed builtin read can have the
                # same status as EOF and must not replace native cat errors.
                self.assertFalse(any(line.lstrip(b"+").startswith(b"HOST_CAT:fixture_cat ")
                                     for line in actual.stderr.splitlines()))
        self.assertFalse((self.root / "operations").exists())

    def test_host_native_cat_does_not_confuse_failed_read_with_eof(self):
        self.shell_fixture()
        header = "#!/system/bin/sh\n# SESSION_DATA_PARSER_BEGIN\n# SESSION_DATA_PARSER_END\n"
        target = self.root / "proc/234/stat"
        target.write_bytes(b"complete expected text\n")
        self.scripts["cat-read-failure"] = header + 'cat "/proc/234/stat"\n'
        for hook in ('read() { builtin read -u 99 "$@"; }\n',
                     'read() { return 1; }\n', 'read() { return 2; }\n'):
            with self.subTest(hook=hook):
                actual = self.run_script("cat-read-failure", boundary_hook=hook)
                self.assertEqual(actual.returncode, 0, actual.stderr)
                self.assertEqual(actual.stdout, target.read_bytes())
                self.assertEqual(actual.stderr, b"")

    def test_generated_kernel_text_uses_linux_lf_without_rewriting_raw_inputs(self):
        self.shell_fixture()
        header = "#!/system/bin/sh\n# SESSION_DATA_PARSER_BEGIN\n# SESSION_DATA_PARSER_END\n"
        paths = ("/proc/self/attr/current", "/proc/100/attr/current", "/proc/100/stat",
                 "/proc/sys/kernel/random/boot_id", "/proc/123/maps", "/proc/mounts")
        for path in paths:
            with self.subTest(path=path):
                self.scripts["kernel-text-control"] = header + '/usr/bin/cat "' + path + '"\n'
                result = self.run_script("kernel-text-control")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(result.stdout.endswith(b"\n"), result.stdout)
                self.assertNotIn(b"\r", result.stdout)
        for record in (self.q["runtime_observation"][component]["process"]
                       for component in ("gui", "service", "capture_owner")):
            for leaf in ("stat", "attr/current"):
                with self.subTest(pid=record["pid"], leaf=leaf):
                    self.scripts["kernel-text-control"] = (header +
                        '/usr/bin/cat "/proc/' + str(record["pid"]) + '/' + leaf + '"\n')
                    result = self.run_script("kernel-text-control")
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertTrue(result.stdout.endswith(b"\n"), result.stdout)
                    self.assertNotIn(b"\r", result.stdout)
        self.assertFalse((self.root / "operations").exists())

    def test_host_native_cat_preserves_missing_directory_and_unknown_path_errors(self):
        self.shell_fixture()
        header = "#!/system/bin/sh\n# SESSION_DATA_PARSER_BEGIN\n# SESSION_DATA_PARSER_END\n"
        (self.root / "cat-unknown.data").write_bytes(b"unknown\0bytes\n")
        for arguments in ('"/proc/234/missing"', '"/proc/234"',
                          '"$fixture/cat-unknown.data"',
                          '-n "$fixture/cat-unknown.data"',
                          '"$fixture/cat-unknown.data" "/proc/234/missing"'):
            with self.subTest(arguments=arguments):
                self.scripts["cat-native-reference"] = header + '/usr/bin/cat ' + arguments + '\n'
                self.scripts["cat-native-control"] = header + 'cat ' + arguments + '\n'
                expected = self.run_script("cat-native-reference")
                actual = self.run_script("cat-native-control")
                # The same executable formats argv[0] as cat vs /usr/bin/cat.
                # Normalize only that exact leading program name; retain all
                # queried paths, diagnostic text, bytes and nonzero statuses.
                diagnostic = expected.stderr
                if diagnostic.startswith(b"/usr/bin/cat: "):
                    diagnostic = diagnostic[len(b"/usr/bin/"):]
                self.assertEqual((actual.returncode, actual.stdout, actual.stderr),
                                 (expected.returncode, expected.stdout, diagnostic))

    def test_complete_gate_shapes_validate_but_missing_stale_or_synthetic_evidence_does_not(self):
        q = self.validated_shape_fixture()
        original_observed = q["observed_utc"]
        peer.validate_qualification(self.manifest, q)
        q["synthetic"] = True
        with self.assertRaisesRegex(ValueError, "synthetic"):
            peer.validate_qualification(self.manifest, q)
        q["synthetic"] = False
        q["observed_utc"] = (datetime.now(timezone.utc) - timedelta(minutes=11)).isoformat()
        with self.assertRaisesRegex(ValueError, "fresh"):
            peer.validate_qualification(self.manifest, q)
        q["observed_utc"] = original_observed
        q["gates"][peer.GATES[0]]["build"]["status"] = "PENDING"
        with self.assertRaisesRegex(ValueError, "unpassed"):
            peer.validate_qualification(self.manifest, q)

    def test_maintenance_domain_extra_xattrs_and_missing_final_approval_refused(self):
        q = self.validated_shape_fixture()
        q["domain"] = "u:r:hbl_camera_service:s0"
        with self.assertRaisesRegex(ValueError, "actual su"):
            peer.validate_qualification(self.manifest, q)
        q["domain"] = "u:r:su:s0"
        q["metadata"][peer.boot.TARGET]["xattr_names"].append("user.unknown")
        with self.assertRaisesRegex(ValueError, "xattrs"):
            peer.validate_qualification(self.manifest, q)
        q["metadata"][peer.boot.TARGET]["xattr_names"].pop()
        q["final_installation_approval"]["approved"] = False
        with self.assertRaisesRegex(ValueError, "final installation approval"):
            peer.validate_qualification(self.manifest, q)

    def test_slot_flags_must_match_declared_active_and_official_slots(self):
        original = self.validated_shape_fixture()
        changes = (
            {"slot_1.status_active": "1", "slot_2.status_active": "0"},
            {"slot_1.status_active": "1"},
            {"slot_2.status_active": "0"},
            *({slot + ".status_" + flag: "0"} for slot in ("slot_1", "slot_2")
              for flag in ("bootable", "successful")),
            *({"slot_1.status_active": value} for value in ("false", "00", " 0", "0 ", "0\n", "status_active=0")),
        )
        for change in changes:
            q = deepcopy(original)
            q["slot_readback"].update(change)
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "slot"):
                peer.validate_qualification(self.manifest, q)

    def test_changed_mount_or_metadata_cannot_reuse_same_evidence_and_approval(self):
        original = self.validated_shape_fixture()
        for field in ("mount_device", "metadata_label"):
            q = deepcopy(original)
            if field == "mount_device":
                q["system_mount"]["device"] = "/dev/block/another-attested-slot"
            else:
                q["metadata"][peer.boot.TARGET]["label"] = "u:object_r:changed_file:s0"
            self.assertEqual(peer._render(self.manifest, original), peer._render(self.manifest, q))
            self.assertNotEqual(peer.session_data(self.manifest, original), peer.session_data(self.manifest, q))
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "execution subject"):
                peer.validate_qualification(self.manifest, q)

    def test_slot_flags_cannot_replace_independent_official_slot_evidence(self):
        q = self.validated_shape_fixture()
        q["gates"]["independent_recovery_official_slot"]["runtime"]["status"] = "PENDING"
        with self.assertRaisesRegex(ValueError, "unpassed.*independent_recovery_official_slot"):
            peer.validate_qualification(self.manifest, q)

    def test_all_four_binding_layers_reject_mismatched_execution_subject(self):
        gate = peer.GATES[0]
        for layer in ("qualification", "proof", "evidence", "approval"):
            q = deepcopy(self.validated_shape_fixture())
            target = q if layer == "qualification" else q["gates"][gate]["build"]
            if layer == "approval":
                target = q["final_installation_approval"]
            if layer == "evidence":
                path = peer.ROOT / q["gates"][gate]["build"]["evidence_file"]
                target = json.loads(path.read_text())
            target["execution_subject_sha256" if layer in ("qualification", "approval") else "build_subject_sha256"] = "a" * 64
            if layer == "evidence":
                path.write_text(json.dumps(target))
                q["gates"][gate]["build"]["evidence_sha256"] = peer.sha(path.read_bytes())
            with self.subTest(layer=layer), self.assertRaisesRegex(ValueError, "subject"):
                peer.validate_qualification(self.manifest, q)

    def test_execution_subject_covers_renderer_source_and_each_rendered_script(self):
        q = self.validated_shape_fixture()
        with mock.patch.object(peer, "renderer_source_sha256", return_value="a" * 64):
            with self.assertRaisesRegex(ValueError, "execution subject"):
                peer.validate_qualification(self.manifest, q)
        current_programs = peer.render_role_programs(self.manifest)
        for name in current_programs:
            scripts = dict(current_programs)
            scripts[name] += "# changed rendered source\n"
            with self.subTest(script=name), mock.patch.object(peer, "render_role_programs", return_value=scripts):
                with self.assertRaisesRegex(ValueError, "execution subject"):
                    peer.validate_qualification(self.manifest, q)

    def test_execution_subject_has_no_proof_or_approval_self_reference(self):
        q = self.validated_shape_fixture()
        expected = q["execution_subject_sha256"]
        q["execution_subject_sha256"] = "changed"
        q["gates"] = {"changed": "not executed"}
        q["final_installation_approval"] = {"changed": "not authority"}
        self.assertEqual(peer.execution_subject_sha256(self.manifest, q), expected)
        q["init_scan_roots"].append("/vendor/etc/init")
        self.assertNotEqual(peer.execution_subject_sha256(self.manifest, q), expected)

    def test_mocked_shell_exact_four_payload_install_rc_last_and_restore_first(self):
        self.shell_fixture()
        for name in ("install-files.sh", "activate-boot.sh", "restore-boot.sh"):
            result = self.run_script(name)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            if name == "install-files.sh":
                self.assertEqual((self.root / "system/etc/init/camera-gui.rc").read_bytes(), peer.boot.STOCK.read_bytes())
                for entry in self.manifest["candidate"]["files"]:
                    self.assertEqual(peer.sha((self.root / entry["target"].lstrip("/")).read_bytes()), entry["sha256"])
            if name == "activate-boot.sh":
                self.assertEqual(peer.sha((self.root / "system/etc/init/camera-gui.rc").read_bytes()), self.manifest["candidate"]["rc"]["after"])
        self.assertEqual((self.root / "system/etc/init/camera-gui.rc").read_bytes(), peer.boot.STOCK.read_bytes())
        self.assertTrue(all(not (self.root / f["target"].lstrip("/")).exists() for f in self.manifest["candidate"]["files"]))
        operations = (self.root / "operations").read_text().splitlines()
        rc_moves = [i for i, line in enumerate(operations) if line.startswith("mv:") and line.endswith("/init/camera-gui.rc")]
        removals = [i for i, line in enumerate(operations) if line.startswith("rm:")]
        self.assertEqual(len(rc_moves), 2)
        self.assertTrue(all(i > rc_moves[-1] for i in removals))
        self.assertEqual((self.root / "proc/mounts").read_text(), self.mount_line)

    def test_partial_payload_move_failure_restores_mount_and_companion_removes_only_owned_files(self):
        self.shell_fixture()
        result = self.run_script("install-files.sh", fail_move=2)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.root / "system/etc/init/camera-gui.rc").read_bytes(), peer.boot.STOCK.read_bytes())
        self.assertEqual((self.root / "proc/mounts").read_text(), self.mount_line)
        result = self.run_script("restore-boot.sh")
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertTrue(all(not (self.root / f["target"].lstrip("/")).exists() for f in self.manifest["candidate"]["files"]))

    def test_bad_source_is_refused_before_service_stop_or_mount_write(self):
        source = self.shell_fixture()
        (source / "libx2dii_menu.so").write_bytes(b"changed")
        result = self.run_script("install-files.sh")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "operations").exists())

    def test_query_errors_cannot_be_mistaken_for_unmapped_or_stopped(self):
        self.shell_fixture()
        for mode in ("pidof_error", "maps_error", "running"):
            with self.subTest(mode=mode):
                result = self.run_script("install-files.sh", mode=mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.root / "system/lib64/libx2dii_menu.so").exists())
                self.assertEqual((self.root / "proc/mounts").read_text(), self.mount_line)

    def test_failed_lock_acquisition_does_not_remount_or_remove_another_owner_lock(self):
        self.shell_fixture()
        result = self.run_script("install-files.sh", mode="lock_contended")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "operations").exists(), "non-owner performed cleanup or service control")
        self.assertTrue((self.root / "tmp/x2dii-menu-install.lock").is_dir())
        self.assertIn(" ext4 rw,", (self.root / "proc/mounts").read_text())

    def test_shell_rejects_shared_or_wrong_metadata_payload_before_activation(self):
        self.shell_fixture()
        self.assertEqual(self.run_script("install-files.sh").returncode, 0)
        target = self.root / "system/lib64/libx2dii_menu.so"
        alias = self.root / "preserved-native"
        os.link(target, alias)
        result = self.run_script("activate-boot.sh")
        self.assertNotEqual(result.returncode, 0, "hardlinked payload was accepted")
        alias.unlink()
        result = self.run_script("activate-boot.sh", mode="bad_metadata")
        self.assertNotEqual(result.returncode, 0, "wrong owner/mode was accepted")
        self.assertEqual((self.root / "system/etc/init/camera-gui.rc").read_bytes(), peer.boot.STOCK.read_bytes())

    def test_shell_rejects_native_symlinked_payload_before_activation(self):
        self.shell_fixture()
        self.assertEqual(self.run_script("install-files.sh").returncode, 0)
        target = self.root / "system/lib64/libx2dii_menu.so"
        alias = self.root / "preserved-native"
        target.rename(alias)
        try:
            os.symlink(alias, target)
        except OSError as error:
            if getattr(error, "winerror", None) == 1314:
                self.skipTest("Windows denies native symlink creation (WinError 1314); actual symlink rejection remains unverified")
            raise
        self.assertTrue(target.is_symlink(), "fixture is not a native symlink")
        link = subprocess.run([str(SH), "-c", 'test -L "$1"', "fixture",
                               self.posix + "/system/lib64/libx2dii_menu.so"], capture_output=True, timeout=10)
        self.assertEqual(link.returncode, 0, link.stderr.decode())
        result = self.run_script("activate-boot.sh")
        self.assertNotEqual(result.returncode, 0, "symlinked payload was accepted")
        self.assertEqual((self.root / "system/etc/init/camera-gui.rc").read_bytes(), peer.boot.STOCK.read_bytes())

    def test_complete_vendor_odm_scan_set_is_allowed_only_when_stage_and_backup_are_outside(self):
        self.q["init_scan_roots"] = ["/system/etc/init", "/vendor/etc/init", "/odm/etc/init"]
        q = self.validated_shape_fixture()
        peer.validate_qualification(self.manifest, q)
        for forbidden in ("/system", "/system/etc", "/system/.x2dii-menu-stage"):
            q["init_scan_roots"] = ["/system/etc/init", forbidden]
            with self.subTest(root=forbidden), self.assertRaisesRegex(ValueError, "scan"):
                peer.validate_qualification(self.manifest, q)

    def test_unexpected_rc_corruption_is_an_explicit_independent_recovery_gap(self):
        self.shell_fixture()
        self.assertEqual(self.run_script("install-files.sh").returncode, 0)
        target = self.root / "system/etc/init/camera-gui.rc"
        target.write_bytes(b"unknown corrupt configuration")
        result = self.run_script("restore-boot.sh")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(target.read_bytes(), b"unknown corrupt configuration")
        backup = self.root / "system/etc/x2dii-menu-backup" / self.manifest["candidate_sha256"][:24] / "camera-gui.rc.original"
        self.assertEqual(backup.read_bytes(), peer.boot.STOCK.read_bytes())
        self.assertIn("independent", self.manifest["recovery_limitations"])

    def test_unqualified_output_rejects_existing_script_or_hardlinked_report(self):
        output = self.root / "output"
        output.mkdir()
        (output / "activate-boot.sh").write_text("preserve existing work")
        with self.assertRaisesRegex(ValueError, "runnable script"):
            peer.prepare(output)
        (output / "activate-boot.sh").unlink()
        source = self.root / "preserve"
        source.write_bytes(b"existing evidence")
        os.link(source, output / "peer-install-source.json")
        with self.assertRaisesRegex(ValueError, "hard-linked"):
            peer.prepare(output)
        self.assertEqual(source.read_bytes(), b"existing evidence")


if __name__ == "__main__":
    unittest.main()
