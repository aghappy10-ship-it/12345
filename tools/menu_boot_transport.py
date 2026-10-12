"""Fixed activation/restoration dialogues, never installation authorization."""
from copy import deepcopy
import hashlib
import re
import time

from . import boot_config, menu_boot_boundary as boundary, menu_boot_file as boot_file


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _identity(value, size):
    if type(value) is not str:
        return False
    match = re.fullmatch(r"(0|[1-9][0-9]{0,19}):([1-9][0-9]{0,19}):81a4:1:" + str(size) + r":0:0", value)
    return bool(match and int(match[1]) <= 2**64 - 1 and int(match[2]) <= 2**64 - 1)


def _completed_boot_receipt(manifest, raw_session, *, action, decoded_output, backup_identity=None):
    """Parse retained completed bytes only; no observation or authority claim.

    Live finish still separately requires every real boundary response. Saved
    recovery consumers can check the same receipt grammar without fabricating
    responses or advancing a coordinator's observation state.
    """
    context = boundary.context_for_action(manifest, raw_session, action)
    def need(ok, message):
        if not ok:
            raise ValueError("boot coordinator: " + message)
    need(type(decoded_output) is bytes and len(decoded_output) <= 32768 and decoded_output.isascii(),
        "bounded ASCII boot output required")
    raw = decoded_output.replace(b"\r\n", b"\n")
    marker = f"X2DII_BOOT_WORKER_{_sha(raw_session)[:24]}_{action}_RC=".encode()
    need(raw.endswith(b"\n" + marker + b"0\n") and raw.count(marker) == 1, "boot shell completion differs")
    pieces = raw.split(b"schema=x2dii-rc-file-transaction-v1\n")
    need(len(pieces) == 2, "unique boot receipt required")
    lines = pieces[1].splitlines()
    fixed = (f"action={action}", f"candidate_sha256={manifest['candidate_sha256']}",
        f"session_data_sha256={_sha(raw_session)}", f"session_nonce={context['session_nonce']}")
    need(len(lines) == 11 and all(lines[i] == value.encode() for i, value in enumerate(fixed)),
        "boot receipt context differs")
    need(lines[4].startswith(b"backup_identity=") and lines[5].startswith(b"identity="),
        "boot receipt identity fields differ")
    backup = lines[4][len(b"backup_identity="):].decode("ascii")
    identity = lines[5][len(b"identity="):].decode("ascii")
    original = boot_config.STOCK.read_bytes()
    size = len(boot_config.activate(original)) if action == "activate" else len(original)
    expected = manifest["candidate"]["rc"]["after" if action == "activate" else "before"]
    need(_identity(backup, len(original)) and _identity(identity, size) and
        (action == "activate" or backup == backup_identity), "boot file ownership differs")
    need(lines[6:] == [f"sha256={expected}".encode(), b"maintenance_boundaries=HOST_MEDIATED_FIXED_BOOT_MATCHED",
        b"X2DII_RC_FILE_COMMITTED_NOT_LIFECYCLE_VALIDATED", b"", marker + b"0"], "boot result differs")
    return {"candidate_sha256": manifest["candidate_sha256"], "session_data_sha256": _sha(raw_session),
        "action": action, "backup_identity": backup, "identity": identity, "sha256": expected,
        "output_sha256": _sha(decoded_output)}


class BootCoordinator:
    """Consume only this fixed action's current observations and final receipt.

    Actual transport completion belongs to the existing native receiver. The
    returned receipt identifies a file transaction, not live menu/reboot health.
    """
    def __init__(self, manifest, raw_session, *, action, payload_identities=None, backup_identity=None):
        self.manifest = deepcopy(manifest)
        self.raw_session = raw_session
        self.action = action
        self.context = boundary.context_for_action(self.manifest, raw_session, action)
        self.sequence = boundary.stages(action)
        self._index = (6 if action == "restore" and self.context["rc_sha256"] ==
                       self.manifest["candidate"]["rc"]["before"] else 0)
        self.first_boundary = self._index
        self._waiting = None
        self._receipt = None
        self.failed = False
        self.backup_identity = backup_identity
        self.payload_data = None
        original = boot_config.STOCK.read_bytes()
        if action == "activate":
            if backup_identity is not None:
                raise ValueError("activation cannot adopt an existing backup")
            self.payload_data = boot_file.encode_payload_identities(self.manifest, payload_identities)
        elif payload_identities is not None or not _identity(backup_identity, len(original)):
            raise ValueError("restore requires exact saved backup identity, not payload health")
        program = boot_file.render_supervised_boot_transaction(self.manifest, action=action,
            original_rc=original, metadata={"uid": 0, "gid": 0, "mode": "644",
                "label": "u:object_r:system_file:s0", "xattr_names": ["security.selinux"]},
            init_scan_roots=["/system/etc/init"])
        self.program_sha256 = _sha(program.encode("ascii"))

    def _need(self, ok, message):
        if self.failed or not ok:
            self.failed = True
            raise ValueError("boot coordinator: " + message)

    @property
    def next_boundary(self):
        return (self._index if not self.failed and self._waiting is None and
                self._receipt is None and self._index < len(self.sequence) else None)

    @property
    def completed_receipt(self):
        return deepcopy(self._receipt)

    def begin_boundary(self, line):
        self._need(self.next_boundary is not None, "no next boot boundary")
        match = re.fullmatch(r"X2DII_HOST_BOOT_BOUNDARY:" + self.action + ":" +
                            str(self._index) + r":([0-9a-f]{64})", line) if type(line) is str else None
        self._need(match is not None, "wrong or replayed boot boundary")
        self._waiting = match[1]
        fixed = boundary.paths(self.manifest, self.action, self._index,
                               session_nonce=self.context["session_nonce"],
                               session_data_sha256=_sha(self.raw_session))
        command = f"sh {fixed['program']} {_sha(self.raw_session)} {self.action} {self._index} {self._waiting}"
        from .stage_peer_usb_access import envelope
        envelope(command, "123456abcdef")
        return command

    def accept_reply(self, raw_response, *, received_epoch):
        self._need(self._waiting is not None, "no outstanding boot observation")
        try:
            self._need(type(raw_response) is bytes and len(raw_response) <= 4096,
                       "bounded boot observation required")
            times = re.findall(rb"(?m)^issued_epoch=([1-9][0-9]{0,9})$", raw_response)
            self._need(len(times) == 1 and type(received_epoch) is int, "unique issued time required")
            issued = int(times[0])
            self._need(0 <= received_epoch - issued <= 8, "boot observation is stale or future")
            challenge = _sha((f"{self.context['boot_id']}:{self.context['session_nonce']}:"
                              f"{self.action}:{self._index}:{self.program_sha256}\n").encode("ascii"))
            request = boundary.make_request(self.manifest, self.raw_session, action=self.action,
                worker_session_sha256=_sha(self.raw_session), worker_program_sha256=self.program_sha256,
                boundary_index=self._index, challenge=challenge, issued_epoch=issued)
            self._need(_sha(request) == self._waiting, "boot request differs from fixed program/session")
            response = boundary.decode_response(raw_response, request, received_epoch=received_epoch)
            ack = (f"X2DII_BOOT_BOUNDARY_ACK:{self._waiting}:{response['started_epoch']}:"
                   f"{response['checked_epoch']}\n").encode("ascii")
            self._waiting = None
            self._index += 1
            return ack
        except Exception:
            self.failed = True
            raise

    def finish(self, *, decoded_output, stream_completed):
        self._need(self._waiting is None and self._index == len(self.sequence) and self._receipt is None and
                   stream_completed is True, "boot stream ended without all observations")
        try:
            self._receipt = _completed_boot_receipt(self.manifest, self.raw_session, action=self.action,
                decoded_output=decoded_output, backup_identity=self.backup_identity)
        except Exception:
            self.failed = True
            raise
        return f"X2DII_HOST_BOOT_ACK:{self.action}:{_sha(decoded_output)}\n".encode("ascii")


def review_boot_host_source(manifest, raw_session, *, action, launch_started_utc,
                            payload_identities=None, backup_identity=None):
    """One fixed activation/restoration stream; no publication or USB access.

    Recovery is validated as recovery and never cast to an install session.
    The dependency file for activation must be staged separately and bound to
    the exact four existing final-placement receipts.
    """
    from .menu_preplacement_transport import _review_fixed_host_source
    from .menu_maintenance_boundary import session_path
    coordinator = BootCoordinator(manifest, raw_session, action=action,
        payload_identities=payload_identities, backup_identity=backup_identity)
    stage = "/blackbox/x2dii-menu-stage/" + manifest["candidate_sha256"][:24]
    path = stage + "/" + action + "-boot.sh"
    dependency = _sha(coordinator.payload_data) if action == "activate" else backup_identity
    command = ('set -eu; x=$(sha256sum ' + path + '); [ "${x%% *}" = ' + coordinator.program_sha256 +
               ' ]; sh ' + path + ' ' + session_path(manifest, _sha(raw_session)) + ' ' + _sha(raw_session) +
               ' ' + dependency)
    return _review_fixed_host_source(manifest, raw_session, launch_started_utc=launch_started_utc,
        commands=[command], program_hashes=[coordinator.program_sha256],
        boot_profile=(action, coordinator.first_boundary))


def drive_boot_process(process, manifest, raw_session, maintenance_session, *, action,
                       payload_identities=None, backup_identity=None, clock=time.time):
    """Connect an already launched fixed boot sender to the maintenance role.

    No child launch, device discovery, GUI stop/restart or installation grant.
    Original-backup ownership and received bytes survive any later host error.
    """
    from .menu_preplacement_transport import _drive_fixed_worker_process
    coordinator = BootCoordinator(manifest, raw_session, action=action,
        payload_identities=payload_identities, backup_identity=backup_identity)
    return _drive_fixed_worker_process(process, manifest, raw_session, maintenance_session,
        coordinator=coordinator, clock=clock, boot_action=action)
