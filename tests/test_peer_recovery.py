"""Filesystem-only recovery specification; no fixture is camera qualification.

Real copies/renames/removals operate only inside a temporary build directory.
Credentials, labels, namespaces, device tools and service state are simulated.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import importlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

from tools import prepare_peer_install as peer
from tools.output_guard import output_directory

SH = Path("C:/Program Files/Git/bin/sh.exe")
# Host-only Git-shell observation bound, matching the install fixture. The
# retained rg509 failure-0011 same-source diagnostic took 38.000 s traced and
# 38.234 s untraced with every original assertion intact; 30 s cut off removal.
# This does not change the rendered recovery lease or stopped-GUI polling.
HOST_RECOVERY_SCRIPT_WAIT_SECONDS = 120
OLD_BOOT = "11111111-2222-3333-4444-555555555555"
NEW_BOOT = "22222222-3333-4444-5555-666666666666"


class PeerRecoveryTests(unittest.TestCase):
    def setUp(self):
        output_directory(peer.ROOT / "build")
        self.temp = tempfile.TemporaryDirectory(prefix="recovery-test-", dir=peer.ROOT / "build")
        self.root = Path(self.temp.name)
        self.original = b"service camera-gui /system/bin/camera-gui\n"
        self.proposed = self.original + b"    setenv LD_PRELOAD /system/lib64/libx2dii_menu.so\n"
        self.payloads = {target: ("saved payload " + target).encode() for _, target in peer.FILES}
        candidate = {"gui_sha256": peer.GUI_SHA256,
                     "files": [{"source": (self.root / "mutable-source" / Path(target).name).relative_to(peer.ROOT).as_posix(),
                                "target": target, "sha256": peer.sha(raw), "bytes": len(raw)}
                               for target, raw in self.payloads.items()],
                     "rc": {"target": peer.boot.TARGET, "before": peer.sha(self.original),
                            "after": peer.sha(self.proposed), "source": "missing-proposed.rc"}}
        self.manifest = {"schema": "x2dii-peer-script-source-v2", "candidate": candidate,
                         "candidate_sha256": peer.sha(peer.canonical(candidate)),
                         "status": "QUALIFIED_SCRIPT_SOURCE_NOT_EXECUTED", "scripts_emitted": True,
                         "renderer_source_sha256": "a" * 64, "qualification_sha256": "b" * 64,
                         "execution_subject_sha256": "c" * 64,
                         "script_hashes": {name: "d" * 64 for name in
                                           ("install-files.sh", "activate-boot.sh", "restore-boot.sh")}}
        self.saved = self.root / "saved-installed-candidate.json"
        self.saved.write_bytes(peer.canonical(self.manifest))
        self.saved_sha = peer.sha(self.saved.read_bytes())
        self.backup = "/system/etc/x2dii-menu-backup/" + self.manifest["candidate_sha256"][:24]
        meta = {"uid": 0, "gid": 0, "mode": "644", "label": "u:object_r:system_file:s0",
                "xattr_names": ["security.selinux"]}
        self.q = {"candidate_sha256": self.manifest["candidate_sha256"], "saved_manifest_sha256": self.saved_sha,
                  "session_nonce": "e" * 32,
                  "synthetic": True, "observed_utc": datetime.now(timezone.utc).isoformat(),
                  "boot_id": NEW_BOOT, "uid": 0, "domain": "u:r:su:s0",
                  "active_slot": "slot_2", "official_slot": "slot_1",
                  "system_mount": {"device": "/dev/block/current-attested-slot", "filesystem": "ext4",
                                   "options": "ro,seclabel,relatime"},
                  "mount_namespace": "mnt:[4026531840]", "init_mount_namespace": "mnt:[4026531840]",
                  "observer": {"pid": 100, "start_ticks": "12345", "exe_target": "/system/bin/adbd",
                               "exe_sha256": peer.sha(b"observer"), "domain": "u:r:su:s0",
                               "mount_namespace": "mnt:[4026531840]"},
                  "gui": {"state": "absent", "service_state": "stopped"},
                  "slot_readback": {slot + ".status_" + field: ("0" if slot == "slot_1" and field == "active" else "1")
                                    for slot in ("slot_1", "slot_2") for field in ("active", "bootable", "successful")},
                  "metadata": {path: deepcopy(meta) for path in (peer.boot.TARGET, *self.payloads)},
                  "backup_metadata": {"official": deepcopy(meta), "owner": dict(meta, mode="600")},
                  "payload_presence": {path: True for path in self.payloads},
                  "rc_sha256": peer.sha(self.proposed), "recovery_nonce": "e" * 32,
                  "init_scan_roots": ["/system/etc/init", "/vendor/etc/init", "/odm/etc/init"],
                  "init_scan_roots_complete": True, "gates": {}, "recovery_authorization": {}}
        from tests.test_runtime_observation import synthetic_observation
        self.q["runtime_observation"] = synthetic_observation(self.q, candidate["gui_sha256"], recovery=True)
        self.posix = subprocess.run([str(SH), "-c", 'cygpath -u "$1"', "fixture", str(self.root)],
                                    capture_output=True, text=True, check=True).stdout.strip()
        for directory in ("system/etc/init", "system/lib64", "system/bin", "tmp", "proc/self/attr",
                          "proc/sys/kernel/random", "proc/100/attr", "proc/1/ns", "proc/self/ns"):
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        self.path(peer.boot.TARGET).write_bytes(self.proposed)
        for target, raw in self.payloads.items():
            self.path(target).write_bytes(raw)
        self.path("/system/bin/camera-gui").write_bytes(b"GUI identity is mocked")
        self.path("/system/bin/adbd").write_bytes(b"observer")
        self.path("/proc/100/exe").write_bytes(b"observer")
        self.path("/proc/100/stat").write_text("100 (adbd) S " + "0 " * 18 + "12345 0\n")
        self.path("/proc/100/maps").write_text("unrelated-library\n")
        self.path("/proc/100/attr/current").write_text("u:r:su:s0\n")
        self.path("/proc/self/attr/current").write_text("u:r:su:s0\n")
        self.path("/proc/sys/kernel/random/boot_id").write_text(NEW_BOOT + "\n")
        self.path(self.backup).mkdir(parents=True)
        self.path(self.backup + "/owner").write_bytes((self.manifest["candidate_sha256"] + "\n").encode())
        self.path(self.backup + "/camera-gui.rc.original").write_bytes(self.original)
        self.mount_line = "/dev/block/current-attested-slot " + self.posix + "/system ext4 ro,seclabel,relatime 0 0\n"
        self.path("/proc/mounts").write_text(self.mount_line)

    def tearDown(self):
        self.temp.cleanup()

    def path(self, path):
        return self.root / path.lstrip("/")

    def recovery(self):
        return importlib.import_module("tools.prepare_peer_recovery")

    def run_script(self, source, *, mode="normal", data=None, boundary_hook=""):
        source = source.replace("export PATH=/system/bin:/system/xbin:/sbin", "export PATH=/usr/bin:/bin")
        head, parser = source.split("# SESSION_DATA_PARSER_BEGIN\n", 1)
        parser, tail = parser.split("# SESSION_DATA_PARSER_END\n", 1)
        source = head + "# HOST_PARSER_PLACEHOLDER\n" + tail
        for prefix in ("/system", "/blackbox", "/tmp", "/proc"):
            source = source.replace(prefix, self.posix + prefix)
        source = source.replace("# HOST_PARSER_PLACEHOLDER\n", parser)
        if data is None:
            data = self.recovery().session_data(self.manifest, self.q)
        (self.root / "session-context.data").write_bytes(data)
        wrapper = f'''
fixture={shlex.quote(self.posix)}
mode={shlex.quote(mode)}
gui_stopped=0
sync_count=0
boundary() {{ :; }}
fixture_id() {{ echo 0; }}
id() {{ fixture_id "$@"; }}
fixture_getprop() {{ if [ "$mode" = gui_present ] && [ "$gui_stopped" = 0 ]; then echo running; else echo stopped; fi; }}
getprop() {{ fixture_getprop "$@"; }}
pidof() {{ case "$mode" in gui_present) if [ "$gui_stopped" = 0 ]; then echo 234; return 0; else return 1; fi;; pidof_error) return 2;; running) echo 234; return 0;; multi_pid) echo '234 235'; return 0;; *) return 1;; esac; }}
stop() {{ printf 'stop:%s\\n' "$*" >> "$fixture/operations"; [ "$mode" != stop_failure ] || return 79; gui_stopped=1; boundary stop; }}
sleep() {{ :; }}
fixture_unrd() {{ case "$1:$mode" in *:wrong_slot) echo 0;; slot_1.status_active:*) echo 0;; *) echo 1;; esac; }}
unrd() {{ fixture_unrd "$@"; }}
fixture_sha256sum() {{ case "${{1-}}" in "$fixture/system/bin/camera-gui"|"$fixture/proc/234/exe") [ "$mode" != bad_gui_exe ] || {{ echo 'bad  gui'; return; }}; printf '{peer.GUI_SHA256}  %s\\n' "$1";; *) /usr/bin/sha256sum "$@";; esac; }}
sha256sum() {{ fixture_sha256sum "$@"; }}
fixture_stat() {{
 if [ "$2" = '%u:%g:%a' ]; then
  if [ -d "$3" ]; then echo '0:0:700'; else echo '0:0:600'; fi
 elif [ "$2" = '%u %g %a' ]; then
  if [ -d "$3" ]; then echo '0 0 700'; elif [ "${{3##*/}}" = session-context.data ]; then echo '0 0 600'; elif [ "$mode" = bad_metadata ]; then echo '1 0 644'; elif [ "${{3##*/}}" = owner ]; then echo '0 0 600'; else echo '0 0 644'; fi
 elif [ "$2" = %d ] && [ "$mode" = wrong_device ] && [ "$3" = "$fixture/system/etc/init" ]; then echo 99
 else /usr/bin/stat "$@"; fi
}}
stat() {{ fixture_stat "$@"; }}
fixture_ls() {{ printf 'u:object_r:system_file:s0 %s\\n' "$2"; }}
ls() {{ fixture_ls "$@"; }}
fixture_readlink() {{
 case "$1" in
  */ns/mnt) [ "$mode" != wrong_namespace ] || {{ echo 'mnt:[9]'; return; }}; echo 'mnt:[4026531840]';;
  */100/exe)
   if [ "$mode" = observer_reused_midquery ]; then printf '100 (adbd) S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 99999 0\\n' > "$fixture/proc/100/stat"; fi
   echo /system/bin/adbd;;
  */234/exe) echo /system/bin/camera-gui;;
  *) /usr/bin/readlink "$@";;
 esac
}}
readlink() {{ fixture_readlink "$@"; }}
chcon() {{ printf 'chcon:%s\\n' "$*" >> "$fixture/operations"; }}
sync() {{
 sync_count=$((sync_count+1))
 printf 'sync\\n' >> "$fixture/operations"
 case "$mode:$sync_count" in sync_before_rename:1|sync_after_rename:2) return 76;; esac
}}
cp() {{
 printf 'cp:%s\\n' "$*" >> "$fixture/operations"
 if [ "$mode" = cp_failure ]; then printf 'partial copy' > "$3"; return 77; fi
 /usr/bin/cp "$@"
}}
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
mv() {{ printf 'mv:%s\\n' "$*" >> "$fixture/operations"; [ "$mode" != move_failure ] || return 75; /usr/bin/mv "$@"; }}
rm() {{ printf 'rm:%s\\n' "$*" >> "$fixture/operations"; /usr/bin/rm "$@"; }}
rmdir() {{
 printf 'rmdir:%s\\n' "$*" >> "$fixture/operations"
 if [ "$mode" = lock_cleanup_failure ] && [ "$1" = "$fixture/tmp/x2dii-menu-install.lock" ]; then return 78; fi
 /usr/bin/rmdir "$@"
}}
'''
        return subprocess.run([str(SH), "-s", "--", self.posix + "/session-context.data", peer.sha(data)],
                              input=(wrapper + boundary_hook + source).encode("ascii"), capture_output=True,
                              timeout=HOST_RECOVERY_SCRIPT_WAIT_SECONDS)

    def assert_intact(self):
        self.assertEqual(self.path(peer.boot.TARGET).read_bytes(), self.proposed)
        for target, raw in self.payloads.items():
            self.assertEqual(self.path(target).read_bytes(), raw)

    def test_old_restore_stays_refused_after_synthetic_reboot(self):
        from tests.test_runtime_observation import synthetic_observation
        from tools.session_context import decode_session, INSTALL_SCHEMA

        # Reconstruct a labelled old INSTALL observation from common execution
        # fields, not the recovery fixture's absent GUI or recovery-only data.
        old = {key: deepcopy(self.q[key]) for key in peer.EXECUTION_CONTEXT_FIELDS}
        old.update(boot_id=OLD_BOOT, synthetic=True)
        old["runtime_observation"] = synthetic_observation(old, self.manifest["candidate"]["gui_sha256"])
        data = peer.session_data(self.manifest, old)
        self.assertTrue(data.startswith(("schema=" + INSTALL_SCHEMA + "\nkind=install\n").encode()))
        self.assertEqual(decode_session(data)["boot_id"], OLD_BOOT)
        self.assertEqual(self.path("/proc/sys/kernel/random/boot_id").read_text().strip(), NEW_BOOT)
        hook = '''
cat() {
 if [ "$1" = "$fixture/proc/sys/kernel/random/boot_id" ]; then
  printf 'read\\n' > "$fixture/old-install-boot-read"
 fi
 command cat "$@"
}
'''
        result = self.run_script(peer._render(self.manifest, old)["restore-boot.sh"],
                                 data=data, boundary_hook=hook)
        self.assertEqual(result.returncode, 32)
        self.assertEqual(self.path("/old-install-boot-read").read_text(), "read\n")
        self.assertFalse(self.path("/operations").exists())
        self.assert_intact()

    def test_new_public_recovery_restores_saved_bytes_after_reboot_without_old_stages(self):
        recovery = self.recovery()
        source = recovery.render_recovery(self.saved, self.saved_sha, self.q)
        result = self.run_script(source)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(self.path(peer.boot.TARGET).read_bytes(), self.original)
        for target in self.payloads:
            self.assertFalse(self.path(target).exists())
        self.assertEqual(self.path(self.backup + "/camera-gui.rc.original").read_bytes(), self.original)
        self.assertEqual(self.path("/proc/mounts").read_text(), self.mount_line)
        operations = self.path("/operations").read_text().splitlines()
        restored = next(i for i, line in enumerate(operations) if line.startswith("mv:") and line.endswith("/init/camera-gui.rc"))
        self.assertTrue(all(i > restored for i, line in enumerate(operations) if line.startswith("rm:")))
        self.assertFalse(self.path("/tmp/x2dii-menu-install.lock").exists())
        self.assertFalse(list(self.path("/system").glob(".x2dii-menu-recovery-*")))
        self.assertNotIn("/blackbox", source)
        self.assertNotIn("/system/.x2dii-menu-stage", source)
        self.assertNotRegex(source, r"(?m)^\s*(start|reboot|adb|scp)\s")

    def structural_qualification(self):
        """Contrived format fixtures only: NEVER used to publish or qualify a camera."""
        recovery = self.recovery()
        q = deepcopy(self.q)
        q["synthetic"] = False
        subject = recovery.execution_subject_sha256(self.saved, self.saved_sha, q)
        build = recovery.build_subject_sha256(self.saved, self.saved_sha)
        runtime = recovery.runtime_subject_sha256(self.saved, self.saved_sha, q)
        q.update(build_subject_sha256=build, runtime_subject_sha256=runtime)
        q["execution_subject_sha256"] = subject
        bindings = {"candidate_sha256": q["candidate_sha256"], "saved_manifest_sha256": self.saved_sha,
                    "boot_id": q["boot_id"], "execution_subject_sha256": subject}
        q["recovery_authorization"] = dict(bindings, approved=True, session_nonce=q["recovery_nonce"],
                                          purpose="restore_official_boot_remove_owned_extension")
        for gate in recovery.GATES:
            q["gates"][gate] = {}
            for phase in recovery.GATE_PHASES[gate]:
                phase_bindings = peer.release_identity.gate_bindings(
                    phase, candidate_sha256=q["candidate_sha256"], build_subject_sha256=build,
                    runtime_subject_sha256=runtime, boot_id=q["boot_id"],
                    retained={"saved_manifest_sha256": self.saved_sha})
                evidence = dict(phase_bindings, result="PASS", synthetic=False, gate=gate, test_fixture_only=True)
                path = self.root / (gate + "-" + phase + ".json")
                path.write_bytes(peer.canonical(evidence))
                q["gates"][gate][phase] = dict(phase_bindings, status="PASS",
                    evidence_file=path.relative_to(peer.ROOT).as_posix(), evidence_sha256=peer.sha(path.read_bytes()))
        return q

    def test_default_publication_is_nonexecuting_and_install_gates_are_not_reused(self):
        recovery = self.recovery()
        report = recovery.prepare(self.root / "output", self.saved, self.saved_sha)
        self.assertEqual({p.name for p in (self.root / "output").iterdir()}, {"peer-recovery-source.json"})
        self.assertFalse(report["scripts_emitted"])
        self.assertFalse(report["installable"])
        self.assertEqual(set(report["required_gates"].values()), {"PENDING"})
        self.assertNotIn("actual_menu_keys_capture", recovery.GATES)
        with self.assertRaisesRegex(ValueError, "synthetic"):
            recovery.prepare(self.root / "refused", self.saved, self.saved_sha, self.q)
        self.assertFalse((self.root / "refused").exists())
        for name in ("install-files.sh", "activate-boot.sh", "restore-boot.sh", "recover-boot.sh"):
            collision = self.root / name
            collision.mkdir()
            (collision / name).write_bytes(b"existing work")
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "forbidden executable"):
                recovery.prepare(collision, self.saved, self.saved_sha)
            self.assertEqual((collision / name).read_bytes(), b"existing work")

    def test_saved_candidate_recovery_ignores_disappeared_or_changed_source_files(self):
        recovery = self.recovery()
        before = recovery.render_recovery(self.saved, self.saved_sha, self.q)
        for entry in self.manifest["candidate"]["files"]:
            path = peer.ROOT / entry["source"]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"different current payload")
        self.assertEqual(recovery.render_recovery(self.saved, self.saved_sha, self.q), before)
        for entry in self.manifest["candidate"]["files"]:
            (peer.ROOT / entry["source"]).unlink()
        self.assertEqual(recovery.render_recovery(self.saved, self.saved_sha, self.q), before)

    def test_saved_hash_candidate_targets_and_source_publication_remain_bound(self):
        recovery = self.recovery()
        raw = self.saved.read_bytes()
        with self.assertRaisesRegex(ValueError, "manifest hash"):
            recovery.render_recovery(self.saved, "0" * 64, self.q)
        corrupt = deepcopy(self.manifest)
        corrupt["candidate"]["files"][0]["sha256"] = "0" * 64
        self.saved.write_bytes(peer.canonical(corrupt))
        with self.assertRaisesRegex(ValueError, "candidate digest"):
            recovery.render_recovery(self.saved, peer.sha(self.saved.read_bytes()), self.q)
        corrupt["candidate"]["files"][0]["target"] = "/system/bin/camera-gui"
        corrupt["candidate_sha256"] = peer.sha(peer.canonical(corrupt["candidate"]))
        self.saved.write_bytes(peer.canonical(corrupt))
        with self.assertRaisesRegex(ValueError, "four owned"):
            recovery.render_recovery(self.saved, peer.sha(self.saved.read_bytes()), self.q)
        self.saved.write_bytes(raw)

    def test_fresh_recovery_evidence_and_separate_authorization_are_required(self):
        recovery = self.recovery()
        q = self.structural_qualification()
        recovery.validate_qualification(self.saved, self.saved_sha, q)
        cases = ("stale", "synthetic", "old_boot", "install_authority", "no_authority", "gate", "proof", "evidence")
        for case in cases:
            changed = deepcopy(q)
            gate = recovery.GATES[0]
            if case == "stale":
                changed["observed_utc"] = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
            elif case == "synthetic":
                changed["synthetic"] = True
            elif case == "old_boot":
                changed["boot_id"] = OLD_BOOT
            elif case == "install_authority":
                changed["recovery_authorization"]["purpose"] = "final_camera_installation"
            elif case == "no_authority":
                changed["recovery_authorization"] = {}
            elif case == "gate":
                changed["gates"][gate]["build"]["status"] = "PENDING"
            elif case == "proof":
                changed["gates"][gate]["build"]["build_subject_sha256"] = "0" * 64
            else:
                changed["gates"][gate]["build"]["evidence_sha256"] = "0" * 64
            with self.subTest(case=case), self.assertRaises(ValueError):
                recovery.validate_qualification(self.saved, self.saved_sha, changed)

    def test_context_edits_require_new_subject_proofs_and_authorization(self):
        recovery = self.recovery()
        q = self.structural_qualification()
        changes = (("observer", "start_ticks", "54321"), ("observer", "exe_sha256", "0" * 64),
                   ("system_mount", "device", "/dev/block/different-slot"),
                   ("metadata", peer.boot.TARGET, dict(q["metadata"][peer.boot.TARGET], label="u:object_r:other:s0")))
        for field, key, value in changes:
            changed = deepcopy(q)
            changed[field][key] = value
            if field == "metadata":
                changed["backup_metadata"]["official"] = deepcopy(value)
            with self.subTest(field=field, key=key), self.assertRaisesRegex(ValueError, "execution subject"):
                recovery.validate_qualification(self.saved, self.saved_sha, changed)
        changed = deepcopy(q)
        changed["execution_subject_sha256"] = "ignored-self-reference"
        changed["gates"] = {}
        changed["recovery_authorization"] = {}
        self.assertEqual(recovery.execution_subject_sha256(self.saved, self.saved_sha, changed), q["execution_subject_sha256"])

    def test_invalid_domain_metadata_and_init_root_context_is_refused(self):
        recovery = self.recovery()
        for case in ("domain", "namespace", "owner", "extra_xattr", "backup_metadata", "scan_root", "unknown_rc", "slot"):
            q = deepcopy(self.q)
            if case == "domain": q["domain"] = "u:r:maintenance:s0"
            elif case == "namespace": q["mount_namespace"] = "mnt:[99]"
            elif case == "owner": q["metadata"][peer.boot.TARGET]["uid"] = 1
            elif case == "extra_xattr": q["metadata"][peer.boot.TARGET]["xattr_names"].append("user.unknown")
            elif case == "backup_metadata": q["backup_metadata"]["official"]["mode"] = "600"
            elif case == "scan_root": q["init_scan_roots"].append("/system")
            elif case == "unknown_rc": q["rc_sha256"] = "0" * 64
            else: q["slot_readback"]["slot_1.status_active"] = "1"
            with self.subTest(case=case), self.assertRaises(ValueError):
                recovery.render_recovery(self.saved, self.saved_sha, q)

    def test_runtime_boot_domain_mount_lifetime_executable_and_backup_refused_before_writes(self):
        source = self.recovery().render_recovery(self.saved, self.saved_sha, self.q)
        cases = (("/proc/sys/kernel/random/boot_id", (OLD_BOOT + "\n").encode()),
                 ("/proc/self/attr/current", b"u:r:maintenance:s0\n"),
                 ("/proc/mounts", self.mount_line.replace("current-attested-slot", "wrong-slot").encode()),
                 ("/proc/100/stat", b"100 (adbd) S " + b"0 " * 18 + b"99999 0\n"),
                 ("/proc/100/exe", b"different executable"),
                 ("/proc/100/attr/current", b"u:r:other:s0\n"),
                 (self.backup + "/owner", b"another-candidate\n"),
                 (self.backup + "/camera-gui.rc.original", b"corrupt backup"),
                 (self.backup + "/camera-gui.rc.original", None),
                 (peer.boot.TARGET, b"unknown rc"),
                 *((target, b"unknown payload") for target in self.payloads))
        for path, replacement in cases:
            original = self.path(path).read_bytes()
            if replacement is None:
                self.path(path).unlink()
            else:
                self.path(path).write_bytes(replacement)
            result = self.run_script(source)
            with self.subTest(path=path, missing=replacement is None):
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.path("/operations").exists(), "mutation occurred before refusal")
                self.assertEqual(self.path(path).read_bytes() if self.path(path).exists() else None, replacement)
            self.path(path).write_bytes(original)
        self.assert_intact()

    def test_runtime_namespace_slot_metadata_queries_and_absent_gui_are_strict(self):
        source = self.recovery().render_recovery(self.saved, self.saved_sha, self.q)
        for mode in ("wrong_namespace", "wrong_slot", "bad_metadata", "bad_gui_exe", "wrong_device",
                     "pidof_error", "running", "multi_pid"):
            result = self.run_script(source, mode=mode)
            with self.subTest(mode=mode):
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.path("/operations").exists())
                self.assert_intact()

    def test_hardlinked_owned_payload_and_backup_refused_before_writes(self):
        source = self.recovery().render_recovery(self.saved, self.saved_sha, self.q)
        for target in (peer.boot.TARGET, *self.payloads, self.backup + "/owner", self.backup + "/camera-gui.rc.original"):
            alias = self.root / "preserved-alias"
            os.link(self.path(target), alias)
            result = self.run_script(source)
            with self.subTest(target=target):
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.path("/operations").exists())
            alias.unlink()
        self.assert_intact()

    def test_symlinked_payload_refused_before_writes_when_host_permits(self):
        target = self.path(next(iter(self.payloads)))
        alias = self.root / "preserved-original"
        target.rename(alias)
        try:
            os.symlink(alias, target)
        except OSError as error:
            if getattr(error, "winerror", None) == 1314:
                self.skipTest("Windows denies native symlink creation; real target symlink behavior remains unverified")
            raise
        result = self.run_script(self.recovery().render_recovery(self.saved, self.saved_sha, self.q))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.path("/operations").exists())

    def test_failed_lock_acquisition_performs_no_cleanup_or_mount_change(self):
        result = self.run_script(self.recovery().render_recovery(self.saved, self.saved_sha, self.q), mode="lock_contended")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.path("/operations").exists())
        self.assertTrue(self.path("/tmp/x2dii-menu-install.lock").is_dir())
        self.assertIn(" ext4 rw,", self.path("/proc/mounts").read_text())
        self.assert_intact()

    def test_failed_atomic_rc_restore_restores_readonly_mount_and_preserves_payloads(self):
        result = self.run_script(self.recovery().render_recovery(self.saved, self.saved_sha, self.q), mode="move_failure")
        self.assertNotEqual(result.returncode, 0)
        self.assert_intact()
        self.assertEqual(self.path("/proc/mounts").read_text(), self.mount_line)
        self.assertFalse(self.path("/tmp/x2dii-menu-install.lock").exists())
        self.assertFalse(list(self.path("/system").glob(".x2dii-menu-recovery-*")))

    def test_missing_owned_payload_requires_attested_absence_and_recovery_is_idempotent(self):
        target = next(iter(self.payloads))
        self.path(target).unlink()
        source = self.recovery().render_recovery(self.saved, self.saved_sha, self.q)
        refused = self.run_script(source)
        self.assertNotEqual(refused.returncode, 0)
        self.assertFalse(self.path("/operations").exists())
        self.q["payload_presence"][target] = False
        result = self.run_script(self.recovery().render_recovery(self.saved, self.saved_sha, self.q))
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.q["payload_presence"] = {path: False for path in self.payloads}
        self.q["rc_sha256"] = peer.sha(self.original)
        result = self.run_script(self.recovery().render_recovery(self.saved, self.saved_sha, self.q))
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(self.path(peer.boot.TARGET).read_bytes(), self.original)

    def test_present_gui_lifetime_checked_before_stop_and_stale_pid_refused(self):
        self.path("/proc/234/attr").mkdir(parents=True)
        self.path("/proc/234/attr/current").write_bytes(b"u:r:camera_gui:s0\n")
        self.path("/proc/234/stat").write_bytes(b"234 (camera gui) S " + b"0 " * 18 + b"54321 0\n")
        self.q["gui"] = {"state": "present", "service_state": "running",
                         "process": {"pid": 234, "start_ticks": "54321", "exe_target": "/system/bin/camera-gui",
                                     "exe_sha256": peer.GUI_SHA256, "domain": "u:r:camera_gui:s0",
                                     "mount_namespace": self.q["mount_namespace"]}}
        source = self.recovery().render_recovery(self.saved, self.saved_sha, self.q)
        self.path("/proc/234/stat").write_bytes(b"234 (camera gui) S " + b"0 " * 18 + b"54322 0\n")
        refused = self.run_script(source, mode="gui_present")
        self.assertNotEqual(refused.returncode, 0)
        self.assertFalse(self.path("/operations").exists())
        self.path("/proc/234/stat").write_bytes(b"234 (camera gui) S " + b"0 " * 18 + b"54321 0\n")
        result = self.run_script(source, mode="gui_present")
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(self.path(peer.boot.TARGET).read_bytes(), self.original)

    def test_old_rendered_recovery_expires_even_without_another_reboot(self):
        self.q["observed_utc"] = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        result = self.run_script(self.recovery().render_recovery(self.saved, self.saved_sha, self.q))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.path("/operations").exists())
        self.assert_intact()

    def test_partial_copy_failure_keeps_unknown_work_file_and_originals_and_restores_ro(self):
        result = self.run_script(self.recovery().render_recovery(self.saved, self.saved_sha, self.q), mode="cp_failure")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(b"X2DII_OFFICIAL_RC_RESTORED_OWNED_FILES_REMOVED", result.stdout)
        self.assert_intact()
        self.assertEqual(self.path(self.backup + "/camera-gui.rc.original").read_bytes(), self.original)
        self.assertEqual(self.path("/proc/mounts").read_text(), self.mount_line)
        self.assertFalse(self.path("/tmp/x2dii-menu-install.lock").exists())
        work = self.path("/system/.x2dii-menu-recovery-" + self.q["recovery_nonce"])
        self.assertEqual((work / "camera-gui.rc.restore").read_bytes(), b"partial copy")

    def test_sync_failures_before_and_after_rc_rename_preserve_backup_and_payloads(self):
        source = self.recovery().render_recovery(self.saved, self.saved_sha, self.q)
        for mode in ("sync_before_rename", "sync_after_rename"):
            result = self.run_script(source, mode=mode)
            with self.subTest(mode=mode):
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(b"X2DII_OFFICIAL_RC_RESTORED_OWNED_FILES_REMOVED", result.stdout)
                self.assertEqual(self.path(peer.boot.TARGET).read_bytes(), self.original if mode == "sync_after_rename" else self.proposed)
                self.assertEqual(self.path(self.backup + "/camera-gui.rc.original").read_bytes(), self.original)
                for target, raw in self.payloads.items():
                    self.assertEqual(self.path(target).read_bytes(), raw)
                self.assertEqual(self.path("/proc/mounts").read_text(), self.mount_line)
                self.assertFalse(self.path("/tmp/x2dii-menu-install.lock").exists())
                self.assertFalse(list(self.path("/system").glob(".x2dii-menu-recovery-*")))

    def test_unreadable_mapping_query_cannot_count_as_stopped_or_unmapped(self):
        result = self.run_script(self.recovery().render_recovery(self.saved, self.saved_sha, self.q), mode="maps_error")
        self.assertNotEqual(result.returncode, 0)
        self.assert_intact()
        operations = self.path("/operations").read_text()
        self.assertNotIn("mount:", operations)
        self.assertNotIn("mv:", operations)
        self.assertEqual(self.path("/proc/mounts").read_text(), self.mount_line)

    def test_failed_lock_cleanup_cannot_emit_a_recovery_success_marker(self):
        result = self.run_script(self.recovery().render_recovery(self.saved, self.saved_sha, self.q), mode="lock_cleanup_failure")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(b"X2DII_OFFICIAL_RC_RESTORED_OWNED_FILES_REMOVED", result.stdout)
        self.assertEqual(self.path("/proc/mounts").read_text(), self.mount_line)

    def test_observer_pid_reuse_during_identity_read_is_refused_before_lock_mutation(self):
        result = self.run_script(self.recovery().render_recovery(self.saved, self.saved_sha, self.q), mode="observer_reused_midquery")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.path("/operations").exists())
        self.assert_intact()

    def test_failure_diagnostics_do_not_claim_gui_was_stopped(self):
        source = self.recovery().render_recovery(self.saved, self.saved_sha, self.q)
        for mode in ("bad_gui_exe", "stop_failure", "maps_error"):
            result = self.run_script(source, mode=mode)
            with self.subTest(mode=mode):
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(b"GUI left stopped", result.stderr)
                self.assertIn(b"GUI state unverified", result.stderr)


if __name__ == "__main__":
    unittest.main()
