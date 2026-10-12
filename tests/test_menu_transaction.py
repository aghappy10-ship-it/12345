"""Fault matrix for an in-memory contract, not device/filesystem qualification."""
from dataclasses import replace
import json
from pathlib import Path
import unittest

from tools import boot_config as boot
from tools import menu_transaction as tx


class MenuTransactionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = boot.STOCK.read_bytes()
        # Actual current local artifact bytes, explicitly synthetic metadata.
        cls.metadata = tx.Metadata(0, 0, 0o644, (("security.selinux", b"synthetic-test-label"),
                                                ("user.test", b"preserve-all-xattrs")))
        paths = [boot.ROOT / "build/native/libx2dii_menu.so",
                 *(boot.ROOT / "qml" / Path(p).name for p in tx.PAYLOAD_PATHS[1:])]
        cls.payloads = tuple(tx.Payload(target, path.read_bytes(), tx.sha(path.read_bytes()), cls.metadata)
                             for target, path in zip(tx.PAYLOAD_PATHS, paths))

    def fixture(self, *, read_only=True):
        candidate = tx.Candidate("synthetic-transaction", self.original, self.metadata, self.payloads)
        mount = tx.MountIdentity("synthetic-active", "synthetic-device", "synthetic-filesystem", "synthetic-namespace",
                                ("nosuid", "nodev", "relatime"))
        qualification = tx.ModelQualification(candidate.digest, mount, "synthetic-official", "a" * 64,
                                              ("/system/etc/init",), True, True, True, True, True, True, True)
        fs = tx.ModelFilesystem(mount, read_only=read_only, official_slot=qualification.official_slot,
                                official_snapshot_sha256=qualification.official_snapshot_sha256)
        fs.seed(boot.TARGET, self.original, self.metadata)
        fs.seed("/system/etc/unrelated", b"preserve this unrelated official file", self.metadata)
        return fs, candidate, qualification

    def engine(self, fixture):
        return tx.Transaction(*fixture)

    def assert_official(self, fixture, *, read_only=True):
        fs, candidate, qualification = fixture
        node = fs.files[boot.TARGET]
        self.assertEqual(node.data, self.original)
        self.assertEqual(node.metadata, self.metadata)
        self.assertIsNone(node.owner)
        self.assertEqual(fs.durable(boot.TARGET), node)
        for path in tx.PAYLOAD_PATHS:
            self.assertNotIn(path, fs.files)
            self.assertIsNone(fs.durable(path))
        self.assertEqual(fs.files["/system/etc/unrelated"].data, b"preserve this unrelated official file")
        self.assertEqual(fs.read_only, read_only)
        self.assertEqual(fs.mount, qualification.mount)
        self.assertEqual(fs.official_slot, qualification.official_slot)
        self.assertEqual(fs.official_snapshot_sha256, "a" * 64)
        self.assertIsNone(fs.lock_owner)

    def fault_at(self, index, exception=tx.SimulatedCrash):
        def inject(label, fs):
            if len(fs.events) == index + 1:
                raise exception("injected " + label)
        return inject

    def finish_recovery(self, fixture):
        fs, _, _ = fixture
        result = self.engine(fixture).recover()
        if result["status"] == "INSTALLED":
            self.engine(fixture).remove()
        self.assert_official(fixture)
        journal = fs.journal
        files = dict(fs.files)
        self.engine(fixture).recover()
        self.assertEqual(fs.journal, journal)
        self.assertEqual(fs.files, files)

    def partial_install(self):
        fixture = self.fixture()
        fs = fixture[0]

        def stop_after_first_durable_dependency(label, state):
            if label == "after:activate-directory-sync:" + boot.LIBRARY:
                raise tx.SimulatedCrash(label)

        fs.fault = stop_after_first_durable_dependency
        with self.assertRaises(tx.SimulatedCrash):
            self.engine(fixture).install()
        fs.crash()
        fs.events.clear()
        self.assertIn(boot.LIBRARY, fs.files)
        self.assertEqual(fs.files[boot.TARGET].data, self.original)
        return fixture

    def test_exact_inventory_rc_last_restore_first_metadata_and_mount_roundtrip(self):
        for read_only in (True, False):
            with self.subTest(read_only=read_only):
                fixture = self.fixture(read_only=read_only)
                fs, candidate, _ = fixture
                result = self.engine(fixture).install()
                self.assertEqual(result["status"], "INSTALLED")
                self.assertFalse(result["installable"])
                self.assertEqual(result["actual_durability"], "PENDING")
                self.assertEqual(fs.files[boot.TARGET].data, boot.activate(self.original))
                self.assertEqual(fs.files[boot.TARGET].metadata, self.metadata)
                self.assertEqual(fs.read_only, read_only)
                activations = [event for event in fs.events if event.startswith("before:activate:")]
                self.assertEqual(activations, ["before:activate:" + p for p in (*tx.PAYLOAD_PATHS, boot.TARGET)])
                verify = fs.events.index("after:verify-staged")
                self.assertLess(verify, fs.events.index(activations[0]))
                self.assertEqual(fs.durable(candidate.backup).data, self.original)
                fs.events.clear()
                self.engine(fixture).remove()
                restored = fs.events.index("after:official-rc-directory-sync")
                self.assertTrue(all(restored < fs.events.index("before:remove:" + p) for p in tx.PAYLOAD_PATHS))
                self.assert_official(fixture, read_only=read_only)
                self.assertTrue(fs.restart_inhibited)
                self.assertFalse(fs.gui_running)

    def test_crash_reconstruction_at_every_install_boundary(self):
        golden = self.fixture()
        self.engine(golden).install()
        boundaries = list(golden[0].events)
        self.assertGreater(len(boundaries), 200)
        for index, label in enumerate(boundaries):
            with self.subTest(index=index, boundary=label):
                fixture = self.fixture()
                fs = fixture[0]
                fs.fault = self.fault_at(index)
                with self.assertRaises(tx.SimulatedCrash):
                    self.engine(fixture).install()
                fs.crash()
                self.finish_recovery(fixture)

    def test_crash_reconstruction_at_every_removal_boundary(self):
        golden = self.fixture()
        self.engine(golden).install()
        golden[0].events.clear()
        self.engine(golden).remove()
        boundaries = list(golden[0].events)
        self.assertGreater(len(boundaries), 100)
        for index, label in enumerate(boundaries):
            with self.subTest(index=index, boundary=label):
                fixture = self.fixture()
                self.engine(fixture).install()
                fs = fixture[0]
                fs.events.clear()
                fs.fault = self.fault_at(index)
                with self.assertRaises(tx.SimulatedCrash):
                    self.engine(fixture).remove()
                fs.crash()
                self.finish_recovery(fixture)

    def test_crash_during_every_recovery_boundary_is_recoverable_again(self):
        golden = self.partial_install()
        self.engine(golden).recover()
        boundaries = list(golden[0].events)
        for index, label in enumerate(boundaries):
            with self.subTest(index=index, boundary=label):
                fixture = self.partial_install()
                fixture[0].fault = self.fault_at(index)
                with self.assertRaises(tx.SimulatedCrash):
                    self.engine(fixture).recover()
                fixture[0].crash()
                self.finish_recovery(fixture)

    def test_io_error_at_every_install_operation_is_recoverable_without_process_crash(self):
        golden = self.fixture()
        self.engine(golden).install()
        for index, label in enumerate(golden[0].events):
            if not label.startswith("before:"):
                continue
            with self.subTest(index=index, boundary=label):
                fixture = self.fixture()
                fixture[0].fault = self.fault_at(index, OSError)
                with self.assertRaises(OSError):
                    self.engine(fixture).install()
                fixture[0].fault = None
                self.finish_recovery(fixture)

    def test_resume_after_each_install_crash_replays_from_verified_state(self):
        golden = self.fixture()
        self.engine(golden).install()
        for index, label in enumerate(golden[0].events):
            with self.subTest(index=index, boundary=label):
                fixture = self.fixture()
                fs = fixture[0]
                fs.fault = self.fault_at(index)
                with self.assertRaises(tx.SimulatedCrash):
                    self.engine(fixture).install()
                fs.crash()
                result = self.engine(fixture).install() if fs.journal is None else self.engine(fixture).resume()
                self.assertEqual(result["status"], "INSTALLED")
                journal, files = fs.journal, dict(fs.files)
                self.engine(fixture).install()
                self.assertEqual((fs.journal, fs.files), (journal, files))
                self.engine(fixture).remove()
                self.assert_official(fixture)

    def test_qualification_recovery_slot_and_exact_inventory_are_mandatory(self):
        flags = ("official_slot_verified", "independent_recovery_verified", "complete_release_verified",
                 "final_installation_approved", "metadata_verified", "filesystem_contract_verified", "init_scan_roots_verified")
        for flag in flags:
            fixture = self.fixture()
            with self.subTest(flag=flag), self.assertRaisesRegex(tx.TransactionError, "qualification required"):
                tx.Transaction(fixture[0], fixture[1], replace(fixture[2], **{flag: False}))
            self.assertIsNone(fixture[0].journal)
        fs, candidate, q = self.fixture()
        with self.assertRaisesRegex(tx.TransactionError, "exact ordered four-payload"):
            tx.Transaction(fs, replace(candidate, payloads=candidate.payloads[:-1]), q)
        with self.assertRaisesRegex(tx.TransactionError, "slot/mount/recovery"):
            tx.Transaction(fs, candidate, replace(q, official_slot=q.mount.active_slot))
        with self.assertRaisesRegex(tx.TransactionError, "init scan root"):
            tx.Transaction(fs, candidate, replace(q, init_scan_roots=("/system",)))

    def test_source_hash_and_metadata_mismatch_refused_before_journal(self):
        fs, candidate, q = self.fixture()
        first = replace(candidate.payloads[0], data=candidate.payloads[0].data + b"changed")
        with self.assertRaisesRegex(tx.TransactionError, "source hash mismatch"):
            tx.Transaction(fs, replace(candidate, payloads=(first, *candidate.payloads[1:])), q)
        self.assertIsNone(fs.journal)
        fs.files[boot.TARGET] = replace(fs.files[boot.TARGET], metadata=replace(self.metadata, mode=0o666))
        with self.assertRaisesRegex(tx.TransactionError, "unknown rc"):
            tx.Transaction(fs, candidate, q).install()
        self.assertIsNone(fs.journal)

    def test_existing_unknown_target_or_matching_unowned_file_is_never_adopted(self):
        for path in tx.PAYLOAD_PATHS:
            for same_content in (False, True):
                fixture = self.fixture()
                fs, candidate, _ = fixture
                data = next(p.data for p in candidate.payloads if p.target == path) if same_content else b"unknown file"
                fs.seed(path, data, self.metadata, owner="different-owner")
                before = dict(fs.files)
                with self.subTest(path=path, same_content=same_content), \
                        self.assertRaisesRegex(tx.TransactionError, "unknown target"):
                    self.engine(fixture).install()
                self.assertEqual(fs.files, before)
                self.assertIsNone(fs.journal)

    def test_mapped_library_and_gui_restart_race_block_each_active_mutation(self):
        for boundary in [*("activate:" + p for p in (*tx.PAYLOAD_PATHS, boot.TARGET)),
                         "activate-directory-sync:" + boot.LIBRARY]:
            for race in ("gui_running", "library_mapped", "restart_inhibited"):
                with self.subTest(boundary=boundary, race=race):
                    fixture = self.fixture()
                    fs = fixture[0]

                    def inject(label, state):
                        if label == "before:" + boundary:
                            setattr(state, race, race != "restart_inhibited")

                    fs.fault = inject
                    with self.assertRaisesRegex(tx.TransactionError, "GUI still running|restart inhibition"):
                        self.engine(fixture).install()
                    self.assertEqual(fs.files[boot.TARGET].data, self.original)
                    fs.fault = None
                    fs.gui_running, fs.library_mapped, fs.restart_inhibited = False, False, True
                    self.finish_recovery(fixture)

    def test_library_mapping_blocks_removal_and_never_replaces_the_inode(self):
        fixture = self.fixture()
        self.engine(fixture).install()
        fs = fixture[0]
        inode = fs.files[boot.LIBRARY].inode
        fs.library_mapped = True
        with self.assertRaisesRegex(tx.TransactionError, "library mapped"):
            self.engine(fixture).remove()
        self.assertEqual(fs.files[boot.LIBRARY].inode, inode)
        fs.library_mapped = False
        self.finish_recovery(fixture)

    def test_unknown_dependency_during_removal_restores_rc_then_preserves_unknown_file(self):
        fixture = self.fixture()
        self.engine(fixture).install()
        fs = fixture[0]
        path = tx.PAYLOAD_PATHS[1]
        unknown = replace(fs.files[path], data=b"external change", owner="unknown")
        fs.files[path] = unknown
        fs.sync_file(path)
        fs.sync_directory(path.rsplit("/", 1)[0])
        with self.assertRaisesRegex(tx.TransactionError, "unknown/non-owned"):
            self.engine(fixture).remove()
        self.assertEqual(fs.files[boot.TARGET].data, self.original)
        self.assertEqual(fs.durable(boot.TARGET).data, self.original)
        self.assertEqual(fs.files[path], unknown)
        self.assertTrue(fs.restart_inhibited)
        self.assertTrue(fs.read_only)

    def test_terminal_calls_detect_mount_lock_and_runtime_drift_without_mutation(self):
        for state in ("installed", "removed"):
            for field, value in (("read_only", False), ("lock_owner", object()),
                                 ("restart_inhibited", False), ("gui_running", True), ("library_mapped", True)):
                with self.subTest(state=state, field=field):
                    fixture = self.fixture()
                    fs = fixture[0]
                    stale_engine = self.engine(fixture)
                    self.engine(fixture).install()
                    if state == "removed":
                        self.engine(fixture).remove()
                    setattr(fs, field, value)
                    journal, files = fs.journal, dict(fs.files)
                    for caller in (stale_engine, self.engine(fixture)):
                        for operation in ("resume", "recover", "report", "install" if state == "installed" else "remove"):
                            with self.assertRaisesRegex(tx.TransactionError, "terminal"):
                                getattr(caller, operation)()
                            self.assertEqual((fs.journal, fs.files), (journal, files))
                            self.assertEqual(getattr(fs, field), value)

    def test_parallel_same_identity_engine_is_rejected_before_journal_or_file_change(self):
        fixture = self.fixture()
        fs = fixture[0]
        second = self.engine(fixture)
        observations = []

        def competing_engine(label, state):
            if label in ("before:journal:begin-install", "before:activate:" + boot.LIBRARY):
                before = state.journal, dict(state.files), state.read_only
                with self.assertRaisesRegex(tx.TransactionError, "another engine"):
                    second.install()
                self.assertEqual((state.journal, state.files, state.read_only), before)
                observations.append(label)

        fs.fault = competing_engine
        self.engine(fixture).install()
        self.assertEqual(len(observations), 2)
        fs.fault = None
        self.engine(fixture).remove()
        self.assert_official(fixture)

    def test_slot_or_mount_drift_before_rc_commit_cannot_activate(self):
        for field, value in (("official_snapshot_sha256", "b" * 64),
                             ("mount", tx.MountIdentity("other", "device", "fs", "ns"))):
            fixture = self.fixture()
            fs = fixture[0]

            def change_identity(label, state):
                if label == "before:activate:" + boot.TARGET:
                    setattr(state, field, value)

            fs.fault = change_identity
            with self.subTest(field=field), self.assertRaisesRegex(tx.TransactionError, "slot/mount/recovery"):
                self.engine(fixture).install()
            self.assertEqual(fs.files[boot.TARGET].data, self.original)

    def test_journal_corruption_or_other_candidate_is_rejected(self):
        fixture = self.partial_install()
        fs, candidate, qualification = fixture
        before = dict(fs.files)
        envelope = json.loads(fs.journal)
        envelope["record"]["step"] = "forged"
        fs.journal = tx.encoded(envelope)
        with self.assertRaisesRegex(tx.TransactionError, "checksum"):
            self.engine(fixture)
        self.assertEqual(fs.files, before)
        fs, candidate, qualification = self.partial_install()
        other = replace(candidate, transaction_id="other-transaction")
        with self.assertRaisesRegex(tx.TransactionError, "journal candidate"):
            tx.Transaction(fs, other, replace(qualification, candidate_digest=other.digest))

    def test_durable_model_discards_unsynced_file_and_directory_changes(self):
        fs, _, _ = self.fixture()
        fs.create("/system/test", b"new", self.metadata, "test")
        fs.crash()
        self.assertNotIn("/system/test", fs.files)
        fs.create("/system/test", b"new", self.metadata, "test")
        fs.sync_file("/system/test")
        fs.crash()
        self.assertNotIn("/system/test", fs.files)
        fs.create("/system/test", b"new", self.metadata, "test")
        fs.sync_file("/system/test")
        fs.sync_directory("/system")
        fs.crash()
        self.assertEqual(fs.files["/system/test"].data, b"new")


if __name__ == "__main__":
    unittest.main()
