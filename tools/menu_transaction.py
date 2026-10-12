"""Finite, local-only installation/removal model. NO device or OS backend.

File fsync, directory fsync, atomic rename, journal durability, locks and init
restart inhibition below are simulated contracts, not verified camera behavior.
The four payloads and exact two-line rc delta are the only active-file scope.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
import re
from typing import Callable

from . import boot_config as boot

PAYLOAD_PATHS = (boot.LIBRARY, "/system/etc/X2d2MenuBootstrap.qml",
                 "/system/etc/X2d2MenuModel.qml", "/system/etc/X2d2MenuPage.qml")
SCHEMA = "x2dii-simulated-transaction-v1"


class TransactionError(ValueError):
    pass


class SimulatedCrash(RuntimeError):
    pass


def need(condition, message):
    if not condition:
        raise TransactionError(message)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encoded(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class Metadata:
    uid: int
    gid: int
    mode: int
    xattrs: tuple[tuple[str, bytes], ...]
    file_type: str = "regular"
    link_count: int = 1

    def describe(self):
        need(self.file_type == "regular" and self.link_count == 1, "regular unshared file required")
        need(self.uid >= 0 and self.gid >= 0 and 0 <= self.mode <= 0o7777, "invalid metadata")
        names = [name for name, _ in self.xattrs]
        need(len(names) == len(set(names)), "duplicate xattr")
        return {"uid": self.uid, "gid": self.gid, "mode": self.mode,
                "xattrs": [[name, value.hex()] for name, value in self.xattrs],
                "file_type": self.file_type, "link_count": self.link_count}


@dataclass(frozen=True)
class Payload:
    target: str
    data: bytes
    digest: str
    metadata: Metadata

    def describe(self):
        need(type(self.data) is bytes and 0 < len(self.data) <= 1024 * 1024, "invalid payload size/type")
        need(sha(self.data) == self.digest, "source hash mismatch: " + self.target)
        return {"target": self.target, "sha256": self.digest, "bytes": len(self.data),
                "metadata": self.metadata.describe()}


@dataclass(frozen=True)
class Candidate:
    transaction_id: str
    original_rc: bytes
    rc_metadata: Metadata
    payloads: tuple[Payload, ...]

    @property
    def proposed_rc(self):
        return boot.activate(self.original_rc)

    def describe(self):
        need(re.fullmatch(r"[a-z0-9][a-z0-9-]{0,47}", self.transaction_id) is not None,
             "invalid transaction identity")
        need(tuple(p.target for p in self.payloads) == PAYLOAD_PATHS, "exact ordered four-payload inventory required")
        return {"schema": SCHEMA, "transaction_id": self.transaction_id,
                "original_rc_sha256": sha(self.original_rc), "proposed_rc_sha256": sha(self.proposed_rc),
                "rc_metadata": self.rc_metadata.describe(), "payloads": [p.describe() for p in self.payloads]}

    @property
    def digest(self):
        return sha(encoded(self.describe()))

    @property
    def backup(self):
        return "/system/etc/x2dii-menu-backup/" + self.transaction_id + "/camera-gui.rc.original"

    @property
    def stage_root(self):
        return "/system/.x2dii-menu-stage/" + self.transaction_id

    def stage(self, target):
        need(target in (*PAYLOAD_PATHS, boot.TARGET), "undeclared target")
        return self.stage_root + "/" + target.rsplit("/", 1)[1]


@dataclass(frozen=True)
class MountIdentity:
    active_slot: str
    block_device: str
    filesystem: str
    namespace: str
    options: tuple[str, ...] = ()

    def describe(self):
        need(all((self.active_slot, self.block_device, self.filesystem, self.namespace)), "incomplete mount identity")
        need(len(self.options) == len(set(self.options)) and all(self.options), "invalid mount options")
        return dict(active_slot=self.active_slot, block_device=self.block_device,
                    filesystem=self.filesystem, namespace=self.namespace, options=list(self.options))


@dataclass(frozen=True)
class ModelQualification:
    """Synthetic evidence supplied explicitly by a test, never a live approval."""
    candidate_digest: str
    mount: MountIdentity
    official_slot: str
    official_snapshot_sha256: str
    init_scan_roots: tuple[str, ...]
    official_slot_verified: bool = False
    independent_recovery_verified: bool = False
    complete_release_verified: bool = False
    final_installation_approved: bool = False
    metadata_verified: bool = False
    filesystem_contract_verified: bool = False
    init_scan_roots_verified: bool = False


@dataclass(frozen=True)
class File:
    data: bytes
    metadata: Metadata
    owner: str | None
    inode: int


class ModelFilesystem:
    """In-memory inode and directory persistence with crash reconstruction.

    owner models the trusted transaction ledger, not an invented device xattr.
    Events execute serially; runner tokens reject reentry but are not an OS or
    multithreaded locking implementation. A process crash drops unsynced directory entries and file data. Remount and
    service state remain observable; this does not model a whole-camera reboot.
    """
    def __init__(self, mount: MountIdentity, *, read_only: bool, official_slot: str,
                 official_snapshot_sha256: str):
        self.mount, self.read_only = mount, read_only
        self.official_slot, self.official_snapshot_sha256 = official_slot, official_snapshot_sha256
        self.files: dict[str, File] = {}
        self.synced_inodes: dict[int, File] = {}
        self.durable_names: dict[str, tuple[int, str | None]] = {}
        self.next_inode = 1
        self.journal: bytes | None = None
        self.lock_owner: object | None = None
        self.runner: object | None = None
        self.gui_running = True
        self.library_mapped = False
        self.restart_inhibited = False
        self.events: list[str] = []
        self.fault: Callable[[str, ModelFilesystem], None] | None = None

    def event(self, name, operation):
        for prefix in ("before:", "after:"):
            label = prefix + name
            self.events.append(label)
            if self.fault is not None:
                self.fault(label, self)
            if prefix == "before:":
                operation()

    def seed(self, path, data, metadata, owner=None):
        """Test-only initial state; never called by the transaction engine."""
        need(path not in self.files, "duplicate fixture path")
        node = File(data, metadata, owner, self.next_inode)
        self.next_inode += 1
        self.files[path] = self.synced_inodes[node.inode] = node
        self.durable_names[path] = (node.inode, node.owner)

    def create(self, path, data, metadata, owner):
        need(path not in self.files, "exclusive create found an existing target")
        self.files[path] = File(data, metadata, owner, self.next_inode)
        self.next_inode += 1

    def sync_file(self, path):
        need(path in self.files, "file absent at fsync")
        self.synced_inodes[self.files[path].inode] = self.files[path]

    def sync_directory(self, parent):
        children = {p: node for p, node in self.files.items() if p.rsplit("/", 1)[0] == parent}
        need(all(self.synced_inodes.get(n.inode) is not None and
                 replace(self.synced_inodes[n.inode], owner=n.owner) == n for n in children.values()),
             "directory contains a file not durably synced")
        for path in list(self.durable_names):
            if path.rsplit("/", 1)[0] == parent:
                del self.durable_names[path]
        self.durable_names.update({p: (n.inode, n.owner) for p, n in children.items()})

    def durable(self, path):
        identity = self.durable_names.get(path)
        return replace(self.synced_inodes[identity[0]], owner=identity[1]) if identity is not None else None

    def crash(self):
        self.files = {p: self.durable(p) for p in self.durable_names}
        self.lock_owner = None
        self.runner = None
        self.fault = None


class Transaction:
    def __init__(self, fs: ModelFilesystem, candidate: Candidate, qualification: ModelQualification):
        need(type(fs) is ModelFilesystem, "only the explicit in-memory model is supported; device backend PENDING")
        self.fs, self.candidate, self.qualification = fs, candidate, qualification
        self.owner_token = object()
        self.manifest = candidate.describe()
        self.binding = sha(encoded(self.manifest))
        self.record = self._read_journal()
        self._context()

    def _context(self):
        q, f, c = self.qualification, self.fs, self.candidate
        need(c.digest == self.binding == q.candidate_digest, "candidate/evidence identity changed")
        need(f.mount == q.mount and f.official_slot == q.official_slot and
             f.official_snapshot_sha256 == q.official_snapshot_sha256, "slot/mount/recovery identity changed")
        need(q.official_slot != q.mount.active_slot and re.fullmatch(r"[0-9a-f]{64}", q.official_snapshot_sha256),
             "distinct hash-bound official rollback slot required")
        need(all((q.official_slot_verified, q.independent_recovery_verified, q.complete_release_verified,
                  q.final_installation_approved, q.metadata_verified, q.filesystem_contract_verified,
                  q.init_scan_roots_verified)), "complete independent recovery/official-slot qualification required")
        need(q.init_scan_roots, "init scan roots unknown")
        q.mount.describe()
        for root in q.init_scan_roots:
            need(root.startswith("/") and ".." not in root.split("/"), "invalid init scan root")
            for location in (c.backup, c.stage_root):
                need(not (location == root.rstrip("/") or location.startswith(root.rstrip("/") + "/")),
                     "backup/staging overlaps an init scan root")
        if self.record is not None:
            need(self.record["mount"] == q.mount.describe() and self.record["official_slot"] == q.official_slot
                 and self.record["official_snapshot_sha256"] == q.official_snapshot_sha256,
                 "journal live identity mismatch")

    def _read_journal(self):
        if self.fs.journal is None:
            return None
        try:
            envelope = json.loads(self.fs.journal)
            record = envelope["record"]
            need(envelope["sha256"] == sha(encoded(record)), "journal checksum mismatch")
            need(record["schema"] == SCHEMA and record["candidate_digest"] == self.binding
                 and record["manifest"] == self.manifest, "journal candidate mismatch")
            need(record["action"] in ("install", "remove", "recover") and
                 record["status"] in ("ACTIVE", "INSTALLED", "REMOVED", "ROLLED_BACK"), "journal state invalid")
            need(type(record["original_read_only"]) is bool, "journal mount state invalid")
            return record
        except (KeyError, TypeError, json.JSONDecodeError) as error:
            raise TransactionError("invalid durable journal") from error

    def _journal(self, name, **updates):
        def write():
            self._context()
            self.record = {**self.record, **updates}
            self.fs.journal = encoded({"record": self.record, "sha256": sha(encoded(self.record))})
        self.fs.event("journal:" + name, write)

    def _matches(self, node, data, metadata, owner):
        return node is not None and node.data == data and node.metadata == metadata and node.owner == owner

    def _expected(self, target):
        if target == boot.TARGET:
            return self.candidate.proposed_rc, self.candidate.rc_metadata
        payload = next(p for p in self.candidate.payloads if p.target == target)
        return payload.data, payload.metadata

    def _official(self, node):
        c = self.candidate
        return self._matches(node, c.original_rc, c.rc_metadata, None)

    def _owned(self, target, node):
        data, metadata = self._expected(target)
        return self._matches(node, data, metadata, self.candidate.transaction_id)

    def _inventory(self, allow_owned, recovery=False):
        f, c = self.fs, self.candidate
        rc = f.files.get(boot.TARGET)
        need(self._official(rc) or (allow_owned and self._owned(boot.TARGET, rc)), "unknown rc bytes/metadata/ownership")
        if not recovery:
            for target in PAYLOAD_PATHS:
                node = f.files.get(target)
                need(node is None or (allow_owned and self._owned(target, node)), "unknown target bytes/metadata/ownership: " + target)
        if self._owned(boot.TARGET, rc):
            if not recovery:
                need(all(self._owned(p, f.files.get(p)) for p in PAYLOAD_PATHS), "active rc has incomplete dependencies")
            need(self._matches(f.durable(c.backup), c.original_rc, c.rc_metadata, c.transaction_id),
                 "activated rc lacks durable official backup")

    def _active(self):
        self._context()
        f = self.fs
        need(f.lock_owner is self.owner_token and f.restart_inhibited,
             "exclusive update lock and restart inhibition required")
        need(not f.gui_running and not f.library_mapped, "GUI still running or library mapped")
        need(not f.read_only, "target mount is read-only")

    def _stage(self, path, data, metadata):
        self._context()
        need(not self.fs.read_only, "target mount is read-only")
        node = self.fs.files.get(path)
        if node is not None:
            need(self._matches(node, data, metadata, self.candidate.transaction_id), "unknown staging/backup file")
        else:
            self.fs.create(path, data, metadata, self.candidate.transaction_id)

    def _sync(self, path):
        self.fs.sync_file(path)

    def _directory(self, path):
        if path in (*PAYLOAD_PATHS, boot.TARGET):
            self._active()
        self.fs.sync_directory(path.rsplit("/", 1)[0])

    def _lock(self):
        self._context()
        need(self.fs.lock_owner in (None, self.owner_token), "another transaction holds the lock")
        self.fs.lock_owner = self.owner_token
        self.fs.restart_inhibited = True

    def _remount(self, read_only):
        self._context()
        need(self.fs.lock_owner is self.owner_token, "mount change without lock")
        self.fs.read_only = read_only

    def _stop(self):
        self._context()
        need(self.fs.lock_owner is self.owner_token and self.fs.restart_inhibited,
             "cannot stop GUI without restart inhibition and lock")
        # A modeled stop does not assert that another process unmapped the .so.
        self.fs.gui_running = False

    def _backup(self):
        c, f = self.candidate, self.fs
        need(self._official(f.files.get(boot.TARGET)) or
             self._matches(f.durable(c.backup), c.original_rc, c.rc_metadata, c.transaction_id),
             "official backup unavailable")
        self._stage(c.backup, c.original_rc, c.rc_metadata)

    def _verify_staged(self):
        c, f = self.candidate, self.fs
        for target in (*PAYLOAD_PATHS, boot.TARGET):
            data, metadata = self._expected(target)
            need(self._matches(f.durable(c.stage(target)), data, metadata, c.transaction_id),
                 "staged file not durable or mismatched")
        need(self._matches(f.durable(c.backup), c.original_rc, c.rc_metadata, c.transaction_id),
             "official backup not durable")

    def _activate(self, target):
        self._active()
        self._inventory(True)
        f, c = self.fs, self.candidate
        if target == boot.TARGET:
            need(all(self._owned(p, f.durable(p)) for p in PAYLOAD_PATHS), "dependencies not durable before rc activation")
        node = f.files.get(target)
        staged = f.files.get(c.stage(target))
        need(self._owned(target, staged) and f.durable(c.stage(target)) == staged, "staged source changed")
        if node is not None and self._owned(target, node):
            # Replaying a rename never replaces an already verified inode.
            del f.files[c.stage(target)]
            return
        need(node is None if target != boot.TARGET else self._official(node), "target changed before atomic activation")
        f.files[target] = f.files.pop(c.stage(target))

    def _restore_rc(self):
        self._active()
        c, f = self.candidate, self.fs
        need(self._matches(f.durable(c.backup), c.original_rc, c.rc_metadata, c.transaction_id),
             "verified durable original backup required")
        node = f.files.get(boot.TARGET)
        need(self._official(node) or self._owned(boot.TARGET, node), "unknown rc cannot be restored")
        stage = c.stage_root + "/restore/camera-gui.rc"
        staged = f.files.get(stage)
        need(self._matches(staged, c.original_rc, c.rc_metadata, c.transaction_id) and f.durable(stage) == staged,
             "restoration source not durable")
        if self._official(node):
            del f.files[stage]
            return
        f.files[boot.TARGET] = replace(f.files.pop(stage), owner=None)
        # Provenance is per pathname in the simulated journal, not a device
        # xattr or an alteration to the staged inode's bytes or metadata.

    def _remove(self, target):
        self._active()
        need(self._official(self.fs.durable(boot.TARGET)), "rc must be durably restored before dependency removal")
        node = self.fs.files.get(target)
        need(node is None or self._owned(target, node), "refusing unknown/non-owned dependency removal")
        if node is not None:
            del self.fs.files[target]

    def _verify(self, installed):
        self._context()
        f, c = self.fs, self.candidate
        if installed:
            need(all(self._owned(p, f.files.get(p)) and self._owned(p, f.durable(p))
                     for p in (*PAYLOAD_PATHS, boot.TARGET)), "installed state not exact/durable")
        else:
            need(self._official(f.files.get(boot.TARGET)) and self._official(f.durable(boot.TARGET)),
                 "official rc not exactly restored/durable")
            need(all(p not in f.files and f.durable(p) is None for p in PAYLOAD_PATHS), "dependency removal not durable")

    def _steps(self, action):
        c = self.candidate
        steps = [("lock-and-inhibit", self._lock), ("mount-writable", lambda: self._remount(False)),
                 ("backup", self._backup), ("backup-file-sync", lambda: self._sync(c.backup)),
                 ("backup-directory-sync", lambda: self._directory(c.backup))]
        if action == "install":
            for target in (*PAYLOAD_PATHS, boot.TARGET):
                data, metadata = self._expected(target)
                path = c.stage(target)
                steps += [("stage:" + target, lambda p=path, d=data, m=metadata: self._stage(p, d, m)),
                          ("stage-file-sync:" + target, lambda p=path: self._sync(p))]
            steps += [("stage-directory-sync", lambda: self._directory(c.stage(boot.TARGET))),
                      ("verify-staged", self._verify_staged)]
        else:
            # A failed candidate file-sync may leave dirty staging siblings.
            # Restore in a separate directory, without persisting those siblings.
            restore = c.stage_root + "/restore/camera-gui.rc"
            steps += [("stage-restore", lambda: self._stage(restore, c.original_rc, c.rc_metadata)),
                      ("restore-file-sync", lambda: self._sync(restore)),
                      ("restore-directory-sync", lambda: self._directory(restore))]
        steps += [("stop-gui", self._stop), ("prove-quiescent", self._active)]
        if action == "install":
            for target in (*PAYLOAD_PATHS, boot.TARGET):
                steps += [("activate:" + target, lambda p=target: self._activate(p)),
                          ("activate-directory-sync:" + target, lambda p=target: self._directory(p)),
                          ("stage-rename-directory-sync:" + target, lambda p=c.stage(target): self._directory(p))]
        else:
            steps += [("restore-rc-first", self._restore_rc),
                      ("official-rc-directory-sync", lambda: self._directory(boot.TARGET)),
                      ("restore-rename-directory-sync", lambda: self._directory(restore))]
            for target in PAYLOAD_PATHS:
                steps += [("remove:" + target, lambda p=target: self._remove(p)),
                          ("remove-directory-sync:" + target, lambda p=target: self._directory(p))]
        steps += [("verify-final-files", lambda: self._verify(action == "install")),
                  ("restore-mount", self._restore_mount),
                  ("unlock-keep-restart-inhibited", self._unlock)]
        return steps

    def _unlock(self):
        self._active_without_mount()
        need(self.fs.read_only == self.record["original_read_only"], "mount restoration failed")
        self.fs.lock_owner = None

    def _restore_mount(self):
        self._active_without_mount()
        self._remount(self.record["original_read_only"])

    def _active_without_mount(self):
        self._context()
        need(self.fs.lock_owner is self.owner_token and self.fs.restart_inhibited
             and not self.fs.gui_running and not self.fs.library_mapped, "quiescence/lock lost before completion")

    def _begin(self, action):
        self._context()
        self._inventory(self.record is not None, recovery=action != "install")
        if self.record is None:
            need(action == "install", "no owned installation to remove")
            self.record = {"schema": SCHEMA, "candidate_digest": self.binding, "manifest": self.manifest,
                           "mount": self.fs.mount.describe(), "official_slot": self.fs.official_slot,
                           "official_snapshot_sha256": self.fs.official_snapshot_sha256,
                           "original_read_only": self.fs.read_only}
        self._journal("begin-" + action, action=action, status="ACTIVE", step="begin", intent=False)

    def _execute(self, action):
        self._begin(action)
        # Replay all idempotent steps after restart: an acknowledged create may
        # precede file/directory fsync and can disappear in a modeled crash.
        for name, operation in self._steps(action):
            self._journal("intent:" + name, step=name, intent=True)
            self.fs.event(name, operation)
            self._journal("done:" + name, step=name, intent=False)
        self._verify(action == "install")
        status = {"install": "INSTALLED", "remove": "REMOVED", "recover": "ROLLED_BACK"}[action]
        self._journal("complete", status=status, step="complete", intent=False)

    def _run(self, action):
        need(self.fs.runner is None and self.fs.lock_owner is None, "another engine is executing this transaction")
        self.fs.runner = self.owner_token
        try:
            # An object created earlier cannot reuse a stale in-memory journal.
            self.record = self._read_journal()
            self._execute(action)
        except TransactionError:
            # A blocked cleanup keeps its journal ACTIVE and its unknown files.
            # Restore mount state only while the exact qualified identity and
            # our exclusive ownership still hold; no guessed recovery on drift.
            if self.record is not None and self.fs.lock_owner is self.owner_token:
                self._context()
                self.fs.event("blocked-restore-mount", lambda: self._remount(self.record["original_read_only"]))
            raise
        finally:
            # Abstract process-owned locks release on return/error/crash. The
            # independent restart inhibitor stays asserted until real lifecycle
            # qualification exists. This is not an OS locking implementation.
            if self.fs.lock_owner is self.owner_token:
                self.fs.lock_owner = None
            self.fs.runner = None
        return self.report()

    def _terminal(self):
        self._verify(self.record["status"] == "INSTALLED")
        need(self.fs.read_only == self.record["original_read_only"], "terminal mount state drift")
        need(self.fs.lock_owner is None and self.fs.runner is None, "terminal update lock not released")
        need(self.fs.restart_inhibited and not self.fs.gui_running and not self.fs.library_mapped,
             "terminal service/restart state drift; model has no authorized restart")

    def _refresh(self):
        self.record = self._read_journal()
        self._context()

    def install(self):
        self._refresh()
        if self.record is not None:
            if self.record["status"] == "INSTALLED":
                self._verify(True)
                return self.report()
            need(self.record["status"] == "ACTIVE" and self.record["action"] == "install",
                 "transaction identity cannot be reused after removal/recovery")
        return self._run("install")

    def remove(self):
        self._refresh()
        need(self.record is not None, "no transaction journal")
        if self.record["status"] in ("REMOVED", "ROLLED_BACK"):
            self._verify(False)
            return self.report()
        return self._run("remove")

    def resume(self):
        self._refresh()
        need(self.record is not None, "no transaction journal")
        if self.record["status"] != "ACTIVE":
            self._verify(self.record["status"] == "INSTALLED")
            return self.report()
        return self._run(self.record["action"])

    def recover(self):
        self._refresh()
        if self.record is None:
            self._inventory(False)
            return self.report()
        if self.record["status"] != "ACTIVE":
            return self.resume()
        return self._run("recover")

    def report(self):
        self._refresh()
        if self.record is not None and self.record["status"] != "ACTIVE":
            self._terminal()
        return {"schema": SCHEMA, "status": self.record["status"] if self.record else "NO_TRANSACTION",
                "candidate_sha256": self.binding, "journal_sha256": sha(self.fs.journal) if self.fs.journal else None,
                "local_model_only": True, "installable": False, "camera_accesses": 0,
                "actual_filesystem_backend": "PENDING", "actual_durability": "PENDING",
                "actual_service_lock_and_recovery": "PENDING", "restart_inhibited": self.fs.restart_inhibited,
                "limitations": ["in-memory process-crash model; no OS/device operations or camera reboot model",
                                "fsync, rename, metadata, init inhibition and qualification are synthetic contracts",
                                "no package, deployment backend, actual recovery proof or authorized GUI restart"]}
