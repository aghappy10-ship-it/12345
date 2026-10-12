"""Fixed legacy/review staging and complete-final-qualified v2 content source.

This bridges reviewed content to prepare_peer_install's exact source directory.
The Python module only checks archive identity in memory; it never publishes an
archive, connects, sends or executes. The review
host source refuses its execution entry before USB access. FixedStagingExchange
separates the maintenance observations from su writes. The final-qualified
adapter returns only the fixed dual-route source after all existing gates and
approval; it does not publish files or start a child. No first-validation
exception or general permission flag is provided.
Compilation is inert. Source hashes bind bytes, not provenance or permission. Session
data stays outside stable content. V1 retains its historical session upload;
v2's first window stages stable content only, leaving fresh session data for a
separate second window. Neither local plan executes an installer.

Path/type/owner checks detect observed changes. Separate shell commands cannot
prove resistance to a concurrent privileged directory replacement. The eventual
sender must hold the existing exclusive maintenance session for the whole plan.
"""
from __future__ import annotations

import base64
import ast
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import gzip
import io
import json
import math
from pathlib import Path
import re
import secrets
import shlex
import tarfile
import time

from .delivery_content import (MEMBER_NAMES, ROLE_MEMBER_NAMES, MANIFEST_NAME,
                               encode_content, encode_role_content, verify_content)
from .delivery_plan import plan_delivery, plan_role_delivery


PARENT = "/blackbox/x2dii-menu-stage"
CHUNK_CHARS = 2048
MAX_COMMAND_BYTES = 3900  # Leaves framing room in a 4096-byte standard ADB OPEN.


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _need(ok, reason):
    if not ok:
        raise ValueError("menu staging: " + reason)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


@dataclass(frozen=True)
class StageStep:
    label: str
    command: str
    expected_stdout: str


@dataclass(frozen=True)
class StagingPlan:
    candidate_sha256: str
    renderer_source_sha256: str
    stage_root: str
    member_names: tuple[str, ...]
    steps: tuple[StageStep, ...]
    plan_sha256: str
    include_session_file: bool = True
    phase: str = "stable-content"
    installable: bool = field(default=False, init=False)
    transport_invocation_available: bool = field(default=False, init=False)


@dataclass(frozen=True)
class SessionStaging:
    """Separate current execution data; never part of stable eight-member content."""
    plan_sha256: str
    data: bytes
    data_sha256: str
    path: str
    context: tuple[tuple[str, str], ...]
    session_nonce: str
    observed_utc: str
    observed_epoch: int
    steps: tuple[StageStep, ...]
    binding_sha256: str
    binding_schema: str = "x2dii-current-stage-session-v1"
    worker_preparation_included: bool = field(default=False, init=False)
    installable: bool = field(default=False, init=False)


@dataclass(frozen=True)
class BoundPreparation:
    """Only the temporary workers or four boot dependencies, never a publisher."""
    purpose: str
    plan_sha256: str
    session_data_sha256: str
    session_binding_sha256: str
    files: tuple[tuple[str, bytes], ...]
    steps: tuple[StageStep, ...]
    binding_sha256: str
    installable: bool = field(default=False, init=False)


@dataclass(frozen=True)
class StageExchangeStep:
    role: str
    index: int
    label: str
    command: str
    expected_stdout: str


@dataclass(frozen=True)
class StagingObserver:
    """One fixed program and one inert index table, staged once per exchange."""
    root: str
    program: bytes
    data: bytes
    program_sha256: str
    data_sha256: str
    preparation: tuple[StageStep, ...]
    observations: tuple[StageStep, ...]


class StagingReadback:
    """Sequential decoded-result check, not a sender or installation decision.

    The external caller must already validate transport completion and retain
    raw replies. A supplied bool is a caller assertion, not wire verification.
    Even all_results_validated says nothing about runtime feature behavior.
    """

    def __init__(self, plan: StagingPlan):
        _need(type(plan) is StagingPlan, "fixed staging plan required")
        self.plan = plan
        self._index = 0
        self.failed = False

    @property
    def next_step(self):
        return None if self.failed or self._index == len(self.plan.steps) else self.plan.steps[self._index]

    @property
    def all_results_validated(self):
        return not self.failed and self._index == len(self.plan.steps)

    def accept(self, *, index, command, exit_code, stdout, completion_validated):
        try:
            step = self.next_step
            _need(step is not None, "sequence already stopped or complete")
            _need(type(index) is int and index == self._index and command == step.command,
                  "out-of-order or different command")
            _need(completion_validated is True, "transport completion not validated")
            _need(type(exit_code) is int and exit_code == 0, "command failed")
            _need(type(stdout) is str and stdout.replace("\r\n", "\n") == step.expected_stdout,
                  "unexpected readback")
        except ValueError:
            self.failed = True
            raise
        self._index += 1


def _directory(path):
    return f"[ -d {path} ] && [ ! -L {path} ] && " + _equals(f"stat -c '%u %g %a' {path}", "0 0 700")


def _regular(path):
    return f"[ -f {path} ] && [ ! -L {path} ] && " + _equals(f"stat -c '%u %g %a %h' {path}", "0 0 600 1")


def _equals(command, expected):
    # A command may print the expected value and still fail. Never discard its status.
    return f"x2dii_stage_value=$({command}) && [ \"$x2dii_stage_value\" = {shlex.quote(expected)} ]"


def plan_staging(*, members, candidate, candidate_sha256, script_hashes,
                 renderer_source, renderer_source_sha256, delivery_identity=None):
    """Plan only supplied fixed bytes; even a valid plan has no sending authority."""
    _need(type(renderer_source) is bytes and 0 < len(renderer_source) <= 1024 * 1024,
          "bounded immutable renderer source required")
    _need(type(renderer_source_sha256) is str and
          re.fullmatch(r"[0-9a-f]{64}", renderer_source_sha256) is not None and
          _sha(renderer_source) == renderer_source_sha256, "renderer source hash mismatch")
    content = plan_delivery(members, candidate=candidate,
                            candidate_sha256=candidate_sha256, script_hashes=script_hashes)
    if delivery_identity is not None:
        actual_identity = verify_content(encode_content(members, candidate_sha256), content)
        _need(type(delivery_identity) is dict and actual_identity == delivery_identity,
              "delivery archive identity differs from the approved content")
    root = PARENT + "/" + candidate_sha256[:24]
    parent_guard = "[ -d /blackbox ] && [ ! -L /blackbox ] && " + _directory(PARENT)
    guard = parent_guard + " && " + _directory(root)
    steps = []

    def add(label, body, stdout="", *, guarded=True):
        command = "set -eu;export PATH=/system/bin:/system/xbin:/sbin;" + (
            guard + " && " if guarded else "") + body
        _need(len(command.encode("ascii")) <= MAX_COMMAND_BYTES, "fixed command too long")
        steps.append(StageStep(label, command, stdout))

    add("create-private-stage",
        "[ -d /blackbox ] && [ ! -L /blackbox ] && "
        f"if [ ! -e {PARENT} ] && [ ! -L {PARENT} ]; then "
        f"(umask 077;mkdir -m 700 {PARENT}); fi && "
        f"{parent_guard} && (umask 077;mkdir -m 700 {root}) && {_directory(root)}",
        guarded=False)
    upload = root + "/.upload.b64"
    for name in MEMBER_NAMES:
        path, raw = root + "/" + name, members[name]
        encoded = base64.b64encode(raw).decode("ascii")
        add("begin-" + name,
            f"[ ! -e {upload} ] && [ ! -L {upload} ] && "
            f"[ ! -e {path} ] && [ ! -L {path} ] && "
            f"(set -C;umask 077;: >{upload}) && {_regular(upload)}")
        for offset in range(0, len(encoded), CHUNK_CHARS):
            part = encoded[offset:offset + CHUNK_CHARS]
            add(f"chunk-{name}-{offset}",
                f"{_regular(upload)} && {_equals(f'stat -c %s {upload}', str(offset))} && "
                f"printf %s '{part}' >>{upload}")
        add("readback-" + name,
            f"{_regular(upload)} && {_equals(f'stat -c %s {upload}', str(len(encoded)))} && "
            f"[ ! -e {path} ] && [ ! -L {path} ] && "
            f"(set -C;umask 077;base64 -d {upload} >{path}) && {_regular(path)} && "
            f"sha256sum {path} && stat -c %s {path}",
            f"{_sha(raw)}  {path}\n{len(raw)}\n")
        add("finish-" + name, f"{_regular(upload)} && rm {upload}")
    paths = [root + "/" + name for name in MEMBER_NAMES]
    # A fixed list and loop preserve every per-file check without duplicating
    # long paths beyond ADB's frame budget after role/lease guards are added.
    add("verify-all-members", "for x2dii_member in " + " ".join(paths) + "; do " +
        _regular('"$x2dii_member"') + " || exit 31; done && sha256sum " + " ".join(paths),
        "".join(f"{_sha(members[name])}  {root}/{name}\n" for name in MEMBER_NAMES))
    identity = {"schema": "x2dii-fixed-menu-stage-plan-v1", "content": content,
                "renderer_source_sha256": renderer_source_sha256,
                "stage_root": root, "steps": [step.__dict__ for step in steps]}
    return StagingPlan(candidate_sha256, renderer_source_sha256, root, tuple(MEMBER_NAMES),
                       tuple(steps), _sha(_canonical(identity)))


def plan_compressed_role_staging(*, members, candidate, candidate_sha256, script_hashes,
                                 renderer_source, renderer_source_sha256, delivery_identity=None):
    """Reference-style fixed tar/gzip transfer, never arbitrary archive extraction.

    Content is constructed and independently verified here from exactly eleven
    bound inputs, not supplied as an archive/path. The first USB window stages
    only stable bytes; a second fresh window must create its own session file.
    Command counts are not a measured time budget or execution qualification.
    """
    _need(type(renderer_source) is bytes and 0 < len(renderer_source) <= 1024 * 1024 and
          type(renderer_source_sha256) is str and _sha(renderer_source) == renderer_source_sha256,
          "bounded immutable renderer source/hash required")
    content = plan_role_delivery(members, candidate=candidate,
                                 candidate_sha256=candidate_sha256, script_hashes=script_hashes)
    archive = encode_role_content(members, candidate_sha256)
    actual_identity = verify_content(archive, content)
    if delivery_identity is not None:
        _need(type(delivery_identity) is dict and actual_identity == delivery_identity,
              "delivery archive identity differs from the approved content")
    compressed = gzip.compress(archive, mtime=0)
    _need(gzip.decompress(compressed) == archive, "compressed role content roundtrip differs")
    encoded = base64.b64encode(compressed).decode("ascii")
    root = PARENT + "/" + candidate_sha256[:24]
    parent_guard = "[ -d /blackbox ] && [ ! -L /blackbox ] && " + _directory(PARENT)
    guard = parent_guard + " && " + _directory(root)
    steps = []

    def add(label, body, stdout="", *, guarded=True):
        command = "set -eu;export PATH=/system/bin:/system/xbin:/sbin;" + (
            guard + " && cd " + root + " && " if guarded else "") + body
        _need(len(command.encode("ascii")) <= MAX_COMMAND_BYTES, "fixed command too long")
        steps.append(StageStep(label, command, stdout))

    def absent(path):
        return f"[ ! -e {path} ] && [ ! -L {path} ]"

    def bound_file(path, raw):
        return (_regular(path) + " && " + _equals(f"stat -c %s {path}", str(len(raw))) + " && " +
                _equals(f"sha256sum {path}", f"{_sha(raw)}  {path}"))

    add("create-private-stage", "[ -d /blackbox ] && [ ! -L /blackbox ] && "
        f"if [ ! -e {PARENT} ] && [ ! -L {PARENT} ]; then "
        f"(umask 077;mkdir -m 700 {PARENT}); fi && "
        f"{parent_guard} && (umask 077;mkdir -m 700 {root}) && {_directory(root)}", guarded=False)
    chunk_names = tuple(f".content-chunk-{offset}.b64" for offset in range(0, len(encoded), CHUNK_CHARS))
    add("begin-fixed-compressed-content", "for x2dii_new in .content.b64 " + " ".join(chunk_names) +
        '; do [ ! -e "$x2dii_new" ] && [ ! -L "$x2dii_new" ] || exit 31; done')
    for offset in range(0, len(encoded), CHUNK_CHARS):
        name = f".content-chunk-{offset}.b64"
        chunk = encoded[offset:offset + CHUNK_CHARS].encode("ascii")
        add(f"compressed-chunk-{offset}", absent(name) +
            f" && (set -C;umask 077;printf %s '{chunk.decode('ascii')}' >{name}) && " +
            _regular(name) + " && " + _equals(f"stat -c %s {name}", str(len(chunk))))
    chunk_check = f"x2dii_offset=0 && while [ \"$x2dii_offset\" -lt {len(encoded)} ]; do " + (
        'x2dii_part=.content-chunk-$x2dii_offset.b64; ' + _regular('"$x2dii_part"') +
        f' || exit 31; x2dii_offset=$((x2dii_offset+{CHUNK_CHARS})); done')
    join_chunks = (chunk_check + " && " + absent(".content.b64") +
        f" && (set -C;umask 077;x2dii_offset=0;while [ \"$x2dii_offset\" -lt {len(encoded)} ]; do " +
        f'cat .content-chunk-$x2dii_offset.b64 || exit 31; x2dii_offset=$((x2dii_offset+{CHUNK_CHARS})); '
        'done >.content.b64) && ' + bound_file(".content.b64", encoded.encode("ascii")))
    add("decode-fixed-compressed-content", join_chunks + " && " + absent(".content.gz") +
        " && (set -C;umask 077;base64 -d .content.b64 >.content.gz) && " + bound_file(".content.gz", compressed))
    add("inflate-fixed-content", bound_file(".content.gz", compressed) + " && " + absent(".content.tar") +
        " && (set -C;umask 077;gzip -dc .content.gz >.content.tar) && " + bound_file(".content.tar", archive))
    names = (*ROLE_MEMBER_NAMES, MANIFEST_NAME)
    fixed_names = " ".join(names)
    all_bytes = {**members, MANIFEST_NAME: _canonical(content)}
    expected_hashes = "".join(f"{_sha(all_bytes[name])}  {name}\n" for name in names)
    expected_sizes = "".join(f"{len(all_bytes[name])}\n" for name in names)
    extract = ("x2dii_files=" + shlex.quote(fixed_names) + " && " + bound_file(".content.tar", archive) +
        " && for x2dii_member in $x2dii_files; do " + absent('"$x2dii_member"') +
        " || exit 31; done && for x2dii_member in $x2dii_files; do "
        '(set -C;umask 077;tar -xOf .content.tar "$x2dii_member" >"$x2dii_member") || exit 31; done')
    # Pinned stock toybox b62d2767... contains O(to-stdout) and its help.
    # Tar never opens the destinations: shell noclobber creates each inode
    # exclusively at mode 0600. A late new member cannot be overwritten, and
    # replacing a member after OPEN cannot redirect the already-open stdout.
    # Exact bytes are checked afterwards; no chmod touches a replacement.
    normalize = "for x2dii_member in $x2dii_files; do " + (
        _regular('"$x2dii_member"') + " || exit 31; done")
    normalize += " && " + _equals("sha256sum $x2dii_files", expected_hashes.rstrip("\n"))
    normalize += " && " + _equals("stat -c %s $x2dii_files", expected_sizes.rstrip("\n"))
    add("extract-normalize-fixed-content", extract + " && " + normalize)
    add("verify-all-members", f"for x2dii_member in {fixed_names}; do " + _regular('"$x2dii_member"') +
        " || exit 31; done && sha256sum " + fixed_names + " && stat -c %s " + fixed_names,
        expected_hashes + expected_sizes)
    # Retain the three bounded transfer intermediates. A later separate shell
    # cannot prove they are still the original inodes merely from mode/hash;
    # automatic cleanup could delete a replaced, unknown object (RG427).
    identity = {"schema": "x2dii-compressed-role-stage-plan-v2", "content": content,
                "renderer_source_sha256": renderer_source_sha256, "stage_root": root,
                "delivery_identity": actual_identity, "compressed_sha256": _sha(compressed),
                "compressed_bytes": len(compressed), "include_session_file": False,
                "steps": [step.__dict__ for step in steps]}
    return StagingPlan(candidate_sha256, renderer_source_sha256, root, tuple(ROLE_MEMBER_NAMES),
                       tuple(steps), _sha(_canonical(identity)), include_session_file=False)


def plan_session_staging(plan, manifest, qualification):
    """Pure source from the renderer's session data; caller must qualify before use."""
    from . import prepare_peer_install as installer
    _need(type(plan) is StagingPlan, "fixed staging plan required")
    manifest, q = deepcopy(manifest), deepcopy(qualification)
    _need(q.get("candidate_sha256") == manifest.get("candidate_sha256") == plan.candidate_sha256 and
          _sha(_canonical(manifest["candidate"])) == plan.candidate_sha256,
          "session candidate differs from fixed plan")
    observed = datetime.fromisoformat(q["observed_utc"])
    _need(observed.tzinfo is not None, "session observation timestamp lacks timezone")
    data = installer.session_data(manifest, q)
    epoch = int(observed.timestamp())
    context = tuple((key, q[key]) for key in ("boot_id", "mount_namespace", "init_mount_namespace"))
    path, upload = plan.stage_root + "/session-context.data", plan.stage_root + "/.session.b64"
    encoded = base64.b64encode(data).decode("ascii")
    guard = "[ -d /blackbox ] && [ ! -L /blackbox ] && " + _directory(PARENT) + " && " + _directory(plan.stage_root)
    # Match the renderer's original integer epoch; this never renews its lease.
    fresh = ("x2dii_stage_now=$(date -u +%s) && case \"$x2dii_stage_now\" in ''|*[!0-9]*) false;; "
             "*) [ \"${#x2dii_stage_now}\" -le 10 ];; esac && "
             f'[ "$x2dii_stage_now" -ge {epoch} ] && [ "$x2dii_stage_now" -le {epoch + 600} ]')
    steps = []

    def add(label, body, stdout=""):
        command = "set -eu;export PATH=/system/bin:/system/xbin:/sbin;" + guard + " && " + fresh + " && " + body
        _need(len(command.encode("ascii")) <= MAX_COMMAND_BYTES, "fixed session command too long")
        steps.append(StageStep(label, command, stdout))

    add("begin-session-context.data", f"[ ! -e {upload} ] && [ ! -L {upload} ] && "
        f"[ ! -e {path} ] && [ ! -L {path} ] && (set -C;umask 077;: >{upload}) && {_regular(upload)}")
    for offset in range(0, len(encoded), CHUNK_CHARS):
        add(f"chunk-session-context.data-{offset}", f"{_regular(upload)} && "
            f"{_equals(f'stat -c %s {upload}', str(offset))} && printf %s '{encoded[offset:offset + CHUNK_CHARS]}' >>{upload}")
    readback = f"{_sha(data)}  {path}\n{len(data)}\n"
    add("readback-session-context.data", f"{_regular(upload)} && "
        f"{_equals(f'stat -c %s {upload}', str(len(encoded)))} && [ ! -e {path} ] && [ ! -L {path} ] && "
        f"(set -C;umask 077;base64 -d {upload} >{path}) && {_regular(path)} && sha256sum {path} && stat -c %s {path}", readback)
    add("finish-session-context.data", f"{_regular(upload)} && rm {upload}")
    add("verify-session-context.data", f"{_regular(path)} && sha256sum {path} && stat -c %s {path}", readback)
    binding = {"schema": "x2dii-current-stage-session-v1", "plan_sha256": plan.plan_sha256,
               "data_sha256": _sha(data), "path": path, "context": dict(context), "session_nonce": q["session_nonce"],
               "observed_utc": q["observed_utc"], "observed_epoch": epoch,
               "steps": [step.__dict__ for step in steps]}
    return SessionStaging(plan.plan_sha256, data, _sha(data), path, context, q["session_nonce"],
                          q["observed_utc"], epoch, tuple(steps), _sha(_canonical(binding)))


def _lease_guard(epoch, variable="x2dii_stage_now"):
    return (f"{variable}=$(date -u +%s) && case \"${variable}\" in ''|*[!0-9]*) false;; "
            f"*) [ \"${{#{variable}}}\" -le 10 ];; esac && "
            f'[ "${variable}" -ge {epoch} ] && [ "${variable}" -le {epoch + 600} ]')


def plan_raw_session_staging(plan, manifest, raw_session):
    """Two absent-only steps for an immutable fresh second-window context.

    This prepares data, NOT a worker. A menu-validation worker and an install
    worker can have different names/hashes; their source preparation and exact
    program/session compatibility remain the caller's separate responsibility.
    Original observations are preserved. Historical contexts and transfer
    intermediates are never overwritten, rotated or deleted.
    """
    from . import menu_maintenance_boundary as boundary, session_context as sc
    _need(type(plan) is StagingPlan and plan.member_names == tuple(ROLE_MEMBER_NAMES) and
          plan.include_session_file is False, "stable-only role plan required")
    manifest = deepcopy(manifest)
    _need(type(manifest) is dict and type(manifest.get("candidate")) is dict and
          manifest.get("candidate_sha256") == plan.candidate_sha256 == _sha(_canonical(manifest["candidate"])) and
          plan.stage_root == PARENT + "/" + plan.candidate_sha256[:24],
          "session candidate differs from fixed plan")
    values = sc.decode_session(raw_session)
    schema = raw_session.split(b"\n", 1)[0].decode("ascii").removeprefix("schema=")
    _need((schema, values["kind"]) in ((sc.INSTALL_SCHEMA, "install"),
          (sc.MENU_VALIDATION_SCHEMA, "menu_validation"), (sc.SCHEMA, "recovery")),
          "current install/menu-validation or recovery session required")
    _need("candidate_sha256" not in values or values["candidate_sha256"] == plan.candidate_sha256,
          "raw session candidate differs")
    digest = _sha(raw_session)
    path = boundary.session_path(manifest, digest)
    compressed = gzip.compress(raw_session, mtime=0)
    _need(gzip.decompress(compressed) == raw_session, "session compression roundtrip differs")
    encoded = base64.b64encode(compressed).decode("ascii")
    basename = path.rsplit("/", 1)[1]
    epoch = values["observed_epoch"]
    context = tuple((key, values[key]) for key in ("boot_id", "mount_namespace", "init_mount_namespace"))
    observed_utc = datetime.fromtimestamp(epoch, timezone.utc).isoformat()
    guard = "[ -d /blackbox ] && [ ! -L /blackbox ] && " + _directory(PARENT) + " && " + _directory(plan.stage_root)

    def bound(path_variable, raw):
        return (_regular(path_variable) + " && " + _equals(f"stat -c %s {path_variable}", str(len(raw))) +
                f" && x2dii_raw_hash=$(sha256sum {path_variable}) && " +
                f'[ "${{x2dii_raw_hash%% *}}" = {_sha(raw)} ]')

    names = f'x2s_f={basename} && x2s_b="$x2s_f.b64" && x2s_g="$x2s_f.gz" && '
    upload_body = (names +
            'for x2dii_new in "$x2s_f" "$x2s_b" "$x2s_g"; do '
            '[ ! -e "$x2dii_new" ] && [ ! -L "$x2dii_new" ] || exit 31; done && '
            f'(set -C;umask 077;printf %s \'{encoded}\' >"$x2s_b") && ' +
            _regular('"$x2s_b"') + " && " + _equals('stat -c %s "$x2s_b"', str(len(encoded))) +
            ' && (set -C;umask 077;base64 -d "$x2s_b" >"$x2s_g") && ' +
            bound('"$x2s_g"', compressed))
    inflate_body = (names + bound('"$x2s_g"', compressed) +
            ' && [ ! -e "$x2s_f" ] && [ ! -L "$x2s_f" ] && '
            '(set -C;umask 077;gzip -dc "$x2s_g" >"$x2s_f") && ' +
            bound('"$x2s_f"', raw_session) + f" && printf '%s\\n' '{digest}  {path}' {len(raw_session)}")
    # Include the actual role/lease wrapper and a conservative completion tag,
    # not merely the unframed body. Oversized data is refused, never split into
    # a partially guarded append/replace route.
    su_guard = _equals("id -u", "0") + " && " + _equals("cat /proc/self/attr/current", "u:r:su:s0")
    for key, cmd in (("boot_id", "cat /proc/sys/kernel/random/boot_id"),
                     ("mount_namespace", "readlink /proc/self/ns/mnt")):
        su_guard += " && " + _equals(cmd, values[key])
    su_guard += " && " + _lease_guard(epoch)
    steps = []
    for label, body, stdout in (("upload-immutable-session-context", upload_body, ""),
                               ("create-immutable-session-context", inflate_body, f"{digest}  {path}\n{len(raw_session)}\n")):
        command = ("set -eu;export PATH=/system/bin:/system/xbin:/sbin;" + guard + " && " +
                   _lease_guard(epoch) + " && cd " + plan.stage_root + " && " + body)
        framed = ("shell:(" + su_guard + " && (" + command + "));r=$?;printf '\\nX2DII_STAGE_" +
                  "0" * 64 + "_999_RC=%s\\n' \"$r\"\0")
        _need(len(command.encode("ascii")) <= MAX_COMMAND_BYTES and len(framed.encode("ascii")) <= 4096,
              "fixed raw session command exceeds ADB frame")
        steps.append(StageStep(label, command, stdout))
    binding_schema = "x2dii-current-stage-session-v2"
    binding = {"schema": binding_schema, "plan_sha256": plan.plan_sha256,
               "data_sha256": digest, "path": path, "context": dict(context),
               "session_nonce": values["session_nonce"], "observed_utc": observed_utc,
               "observed_epoch": epoch, "steps": [step.__dict__ for step in steps],
               "worker_preparation_included": False}
    return SessionStaging(plan.plan_sha256, raw_session, digest, path, context, values["session_nonce"],
                          observed_utc, epoch, tuple(steps), _sha(_canonical(binding)), binding_schema=binding_schema)


def _validate_execution_session(plan, context, session):
    from .session_context import decode_session
    _need(type(session) is SessionStaging and session.plan_sha256 == plan.plan_sha256 and
          dict(session.context) == context, "session plan or execution context differs")
    _need(session.binding_schema in ("x2dii-current-stage-session-v1", "x2dii-current-stage-session-v2"),
          "session binding schema differs")
    v2 = session.binding_schema == "x2dii-current-stage-session-v2"
    expected_path = plan.stage_root + ("/session-context-" + session.data_sha256 + ".data"
                                       if v2 else "/session-context.data")
    _need(type(session.data) is bytes and _sha(session.data) == session.data_sha256 and
          session.path == expected_path, "session bytes or fixed path differ")
    original = decode_session(session.data)
    observed = datetime.fromisoformat(session.observed_utc)
    _need(observed.tzinfo is not None and type(session.observed_epoch) is int and
          int(observed.timestamp()) == original["observed_epoch"] == session.observed_epoch and
          original["session_nonce"] == session.session_nonce and
          all(original[key] == value for key, value in context.items()),
          "session identity or original observation epoch was relabelled")
    _need(type(session.steps) is tuple and all(type(step) is StageStep for step in session.steps),
          "fixed session steps required")
    if v2:
        _need(plan.include_session_file is False and plan.member_names == tuple(ROLE_MEMBER_NAMES) and
              ("candidate_sha256" not in original or original["candidate_sha256"] == plan.candidate_sha256),
              "immutable raw session requires matching stable-only role plan")
    binding = {"schema": session.binding_schema, "plan_sha256": plan.plan_sha256,
               "data_sha256": session.data_sha256, "path": session.path, "context": context,
               "session_nonce": session.session_nonce, "observed_utc": session.observed_utc,
               "observed_epoch": session.observed_epoch,
               "steps": [step.__dict__ for step in session.steps]}
    if v2:
        binding["worker_preparation_included"] = session.worker_preparation_included
    _need(_sha(_canonical(binding)) == session.binding_sha256, "session execution binding differs")


def _bound_preparation(plan, session, purpose, files, steps):
    _validate_execution_session(plan, dict(session.context), session)
    _need(purpose in ("menu_validation_workers", "boot_payload_identities", "menu_support_programs", "boot_observer_program", "owned_cleanup_programs", "install_observer_program"),
          "fixed preparation required")
    binding = {"schema": "x2dii-bound-menu-preparation-v1", "purpose": purpose,
               "plan_sha256": plan.plan_sha256, "session_data_sha256": session.data_sha256,
               "session_binding_sha256": session.binding_sha256,
               "files": [{"path": path, "sha256": _sha(raw), "bytes": len(raw)} for path, raw in files],
               "steps": [step.__dict__ for step in steps]}
    return BoundPreparation(purpose, plan.plan_sha256, session.data_sha256, session.binding_sha256,
                            tuple(files), tuple(steps), _sha(_canonical(binding)))


def _preparation_step(plan, session, label, body, stdout=""):
    guard = "[ -d /blackbox ] && [ ! -L /blackbox ] && " + _directory(PARENT) + " && " + _directory(plan.stage_root)
    command = ("set -eu;export PATH=/system/bin:/system/xbin:/sbin;" + guard + " && " +
               _lease_guard(session.observed_epoch) + " && cd " + plan.stage_root + " && " + body)
    context = dict(session.context)
    role = _equals("id -u", "0") + " && " + _equals("cat /proc/self/attr/current", "u:r:su:s0")
    for key, cmd in (("boot_id", "cat /proc/sys/kernel/random/boot_id"),
                     ("mount_namespace", "readlink /proc/self/ns/mnt")):
        role += " && " + _equals(cmd, context[key])
    role += " && " + _lease_guard(session.observed_epoch)
    frame = "shell:(" + role + " && (" + command + "));r=$?;printf '\\nX2DII_STAGE_" + "0" * 64 + "_999_RC=%s\\n' \"$r\"\0"
    _need(len(command.encode("ascii")) <= MAX_COMMAND_BYTES and len(frame.encode("ascii")) <= 4096,
          "fixed preparation command exceeds ADB frame")
    return StageStep(label, command, stdout)


def plan_menu_validation_worker_staging(plan, manifest, raw_session):
    """Prepare exactly four production temporary workers at their own names.

    The formal eleven-member package is untouched. The private four-member
    archive exists only in memory and is fully checked before compressed upload.
    No caller-supplied files, archive, source substitutions or paths are accepted.
    """
    from . import session_context as sc, temporary_menu_files as workers
    session = plan_raw_session_staging(plan, manifest, raw_session)
    _need(sc.decode_session(raw_session)["kind"] == "menu_validation", "temporary worker session required")
    files = tuple((workers.worker_path(manifest, i, session_kind="menu_validation"),
                   workers.render_supervised_preplacement(manifest, file_index=i,
                       session_kind="menu_validation").encode("ascii")) for i in range(4))
    names = tuple(path.rsplit("/", 1)[1] for path, _ in files)
    _need(names == tuple(f"menu-validation-preplace-{i}.sh" for i in range(4)) and
          all(path == plan.stage_root + "/" + name for (path, _), name in zip(files, names)),
          "temporary worker fixed paths differ")
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:", format=tarfile.USTAR_FORMAT) as writer:
        for name, (_, raw) in zip(names, files):
            item = tarfile.TarInfo(name)
            item.mode, item.size, item.uid, item.gid, item.mtime = 0o600, len(raw), 0, 0, 0
            writer.addfile(item, io.BytesIO(raw))
    archive = output.getvalue()
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as reader:
        entries = reader.getmembers()
        _need(tuple(item.name for item in entries) == names, "temporary worker archive names differ")
        for item, (_, raw) in zip(entries, files):
            _need(item.isfile() and item.type == tarfile.REGTYPE and item.mode == 0o600 and
                  item.uid == item.gid == item.mtime == 0 and item.uname == item.gname == item.linkname == "" and
                  item.size == len(raw) and reader.extractfile(item).read() == raw,
                  "temporary worker archive member differs")
    compressed = gzip.compress(archive, mtime=0)
    _need(gzip.decompress(compressed) == archive, "temporary worker compression differs")
    encoded = base64.b64encode(compressed).decode("ascii")
    prefix = ".menu-validation-workers-" + session.session_nonce
    upload, packed, unpacked = prefix + ".b64", prefix + ".gz", prefix + ".tar"
    steps = []

    def add(label, body, stdout=""):
        steps.append(_preparation_step(plan, session, label, body, stdout))

    def bound(name, raw):
        return (_regular(name) + " && " + _equals(f"stat -c %s {name}", str(len(raw))) + " && " +
                _equals(f"sha256sum {name}", _sha(raw) + "  " + name))

    chunk_names = tuple(prefix + f"-{offset}.b64" for offset in range(0, len(encoded), CHUNK_CHARS))
    add("begin-temporary-workers", "for x2dii_new in " + " ".join((*names, upload, packed, unpacked)) +
        '; do [ ! -e "$x2dii_new" ] && [ ! -L "$x2dii_new" ] || exit 31; done')
    for offset in range(0, len(encoded), CHUNK_CHARS):
        name = prefix + f"-{offset}.b64"
        chunk = encoded[offset:offset + CHUNK_CHARS]
        add(f"temporary-worker-chunk-{offset}", f'x2p={name} && [ ! -e "$x2p" ] && [ ! -L "$x2p" ] && ' +
            f'(set -C;umask 077;printf %s \'{chunk}\' >"$x2p") && ' + _regular('"$x2p"') +
            " && " + _equals('stat -c %s "$x2p"', str(len(chunk))))
    # A bounded numeric loop keeps the complete 20+ chunk names from exceeding
    # the native frame. Each fragment is read-only after exclusive creation.
    chunk_check = f"x2dii_offset=0 && while [ \"$x2dii_offset\" -lt {len(encoded)} ]; do " + (
        f'x2dii_part={prefix}-$x2dii_offset.b64; ' + _regular('"$x2dii_part"') +
        f' || exit 31; x2dii_offset=$((x2dii_offset+{CHUNK_CHARS})); done')
    join_chunks = (f"[ ! -e {upload} ] && [ ! -L {upload} ] && " +
        f"(set -C;umask 077;x2dii_offset=0;while [ \"$x2dii_offset\" -lt {len(encoded)} ]; do " +
        f'cat {prefix}-$x2dii_offset.b64 || exit 31; x2dii_offset=$((x2dii_offset+{CHUNK_CHARS})); done >{upload})')
    add("decode-temporary-workers", chunk_check + " && " + join_chunks + " && " + bound(upload, encoded.encode("ascii")) +
        f" && [ ! -e {packed} ] && [ ! -L {packed} ] && " +
        f"(set -C;umask 077;base64 -d {upload} >{packed}) && " + bound(packed, compressed))
    add("inflate-temporary-workers", bound(packed, compressed) +
        f" && [ ! -e {unpacked} ] && [ ! -L {unpacked} ] && " +
        f"(set -C;umask 077;gzip -dc {packed} >{unpacked}) && " + bound(unpacked, archive))
    hashes = "".join(f"{_sha(raw)}  {name}\n" for name, (_, raw) in zip(names, files))
    sizes = "".join(f"{len(raw)}\n" for _, raw in files)
    fixed = " ".join(names)
    add("extract-verify-temporary-workers", bound(unpacked, archive) +
        " && for x2dii_new in " + fixed + '; do [ ! -e "$x2dii_new" ] && [ ! -L "$x2dii_new" ] || exit 31; done' +
        " && for x2dii_new in " + fixed + "; do " +
        f'(set -C;umask 077;tar -xOf {unpacked} "$x2dii_new" >"$x2dii_new") || exit 31; done' +
        " && for x2dii_new in " + fixed + "; do " +
        _regular('"$x2dii_new"') + " || exit 31; done && " +
        _equals("sha256sum " + fixed, hashes.rstrip("\n")) + " && " +
        _equals("stat -c %s " + fixed, sizes.rstrip("\n")) + f" && sha256sum {fixed} && stat -c %s {fixed}",
        hashes + sizes)
    return _bound_preparation(plan, session, "menu_validation_workers", files, steps)


def plan_boot_payload_identity_staging(plan, manifest, raw_session, identities):
    """Prepare only the four original placement identities for boot activation.

    Identities must come from completed placement receipts. Encoding and local
    file checks do not establish that provenance or qualify persistent loading.
    A fresh install session selects an absent-only nonce file; recovery never
    requires this dependency and cannot use this preparation entry.
    """
    from . import session_context as sc, menu_boot_file as boot_file
    session = plan_raw_session_staging(plan, manifest, raw_session)
    _need(sc.decode_session(raw_session)["kind"] == "install", "boot dependencies require current install session")
    raw = boot_file.encode_payload_identities(manifest, identities)
    _need(boot_file.decode_payload_identities(manifest, raw) == tuple(identities),
          "boot dependency roundtrip differs")
    name = ".payload-identities-" + session.session_nonce + ".data"
    path, upload = plan.stage_root + "/" + name, name + ".b64"
    encoded = base64.b64encode(raw).decode("ascii")
    body = (f"[ ! -e {name} ] && [ ! -L {name} ] && [ ! -e {upload} ] && [ ! -L {upload} ] && " +
            f"(set -C;umask 077;printf %s '{encoded}' >{upload}) && " + _regular(upload) + " && " +
            _equals(f"stat -c %s {upload}", str(len(encoded))) +
            f" && (set -C;umask 077;base64 -d {upload} >{name}) && " + _regular(name) + " && " +
            _equals(f"stat -c %s {name}", str(len(raw))) + " && " +
            _equals(f"sha256sum {name}", _sha(raw) + "  " + name) +
            f" && printf '%s\\n' '{_sha(raw)}  {path}' {len(raw)}")
    steps = (_preparation_step(plan, session, "create-boot-payload-identities", body,
                              f"{_sha(raw)}  {path}\n{len(raw)}\n"),)
    return _bound_preparation(plan, session, "boot_payload_identities", ((path, raw),), steps)


def menu_support_files(manifest):
    """Only sources consumed by temporary validation; boot stages its own observer."""
    from . import menu_lifecycle_transport as lifecycle, menu_maintenance_boundary as file_boundary
    digest = file_boundary._candidate(manifest)
    menu_root = "/tmp/x2mb-" + digest[:12]
    programs = lifecycle.render_programs(manifest)
    _need(set(programs) == {"l", "w", "t", "q", "s"}, "fixed lifecycle programs differ")
    files = tuple((menu_root + "/" + name, programs[name].encode("ascii")) for name in ("l", "w", "t", "q", "s"))
    files += ((menu_root + "/v", file_boundary.render_observer(manifest, session_kind="menu_validation").encode("ascii")),)
    return files


def plan_boot_observer_staging(plan, manifest, raw_session, *, action):
    """Make the one fixed observer available in this boot, including empty /tmp.

    An already exact observer is read-only. Unknown existing targets are never
    adopted, chmodded or replaced. Only gzip stdout plus an exclusive shell
    destination is used when absent; no previous boot's temporary files are
    required and no boot/recovery transaction is executed here.
    """
    from . import session_context as sc, menu_boot_boundary as boundary
    session = plan_raw_session_staging(plan, manifest, raw_session)
    values = sc.decode_session(raw_session)
    _need(action in ("activate", "restore") and
          values["kind"] == ("install" if action == "activate" else "recovery"),
          "fixed boot observer action/session differs")
    path = boundary.paths(manifest, action, 0, session_nonce=values["session_nonce"],
        session_data_sha256=_sha(raw_session))["program"]
    raw = boundary.render_observer(manifest, action=action).encode("ascii")
    return _plan_current_observer_staging(plan, session, path, raw,
        prefix=".boot-observer-" + action + "-" + session.session_nonce,
        label="boot-observer", purpose="boot_observer_program")


def plan_install_observer_staging(plan, manifest, raw_session):
    """Prepare the formal install/v2 /o observer, not temporary /v or a worker.

    The same current-boot absent-or-exact rules used by boot observers apply.
    The fixed producer is selected here; callers cannot supply source or path.
    """
    from . import menu_maintenance_boundary as boundary
    session = plan_raw_session_staging(plan, manifest, raw_session)
    _need(boundary.session_kind_for_context(manifest, raw_session) == "install",
          "formal observer requires install/v2 session")
    path = boundary.paths(manifest, 0, 0, session_data_sha256=_sha(raw_session), session_kind="install")["program"]
    raw = boundary.render_observer(manifest, session_kind="install").encode("ascii")
    return _plan_current_observer_staging(plan, session, path, raw,
        prefix=".install-observer-" + session.session_nonce,
        label="install-observer", purpose="install_observer_program")


def _plan_current_observer_staging(plan, session, path, raw, *, prefix, label, purpose):
    """Private transfer mechanics for the two fixed observer producers above."""
    root = path.rsplit("/", 1)[0]
    compressed = gzip.compress(raw, mtime=0)
    _need(gzip.decompress(compressed) == raw, "fixed observer gzip roundtrip differs")
    encoded = base64.b64encode(compressed).decode("ascii")
    upload, packed = prefix + ".b64", prefix + ".gz"
    # The existing-source branch also binds one full path/hash in each frame.
    chunk_chars = 1024
    steps = []

    def bound(name, data):
        return (_regular(name) + " && " + _equals(f"stat -c %s {name}", str(len(data))) + " && " +
                _equals(f"sha256sum {name}", _sha(data) + "  " + name))

    guard = "[ -d /tmp ] && [ ! -L /tmp ] && " + _directory(root)
    existing = f"[ -e {path} ] || [ -L {path} ]"
    create = ("[ -d /tmp ] && [ ! -L /tmp ] && " +
        f"if [ ! -e {root} ] && [ ! -L {root} ]; then (umask 077;mkdir -m 700 {root}); fi && " +
        _directory(root) + f" && if {existing}; then " + bound(path, raw) + "; fi")
    steps.append(_preparation_step(plan, session, "prepare-current-" + label + "-root", create))

    def add(label, body, *, final=False):
        command = guard + f" && if {existing}; then " + bound(path, raw) + "; else " + body + "; fi"
        stdout = ""
        if final:
            command += " && " + bound(path, raw) + f" && sha256sum {path} && stat -c %s {path}"
            stdout = f"{_sha(raw)}  {path}\n{len(raw)}\n"
        steps.append(_preparation_step(plan, session, label, command, stdout))

    for offset in range(0, len(encoded), chunk_chars):
        name, part = prefix + f"-{offset}.b64", encoded[offset:offset + chunk_chars]
        add(f"{label}-chunk-{offset}", f"[ ! -e {name} ] && [ ! -L {name} ] && " +
            f"(set -C;umask 077;printf %s '{part}' >{name}) && " + _regular(name) + " && " +
            _equals(f"stat -c %s {name}", str(len(part))))
    parts_check = f"x2dii_offset=0 && while [ \"$x2dii_offset\" -lt {len(encoded)} ]; do " + (
        f'x2dii_part={prefix}-$x2dii_offset.b64; ' + _regular('"$x2dii_part"') +
        f' || exit 31; x2dii_offset=$((x2dii_offset+{chunk_chars})); done')
    join = (f"[ ! -e {upload} ] && [ ! -L {upload} ] && " +
        f"(set -C;umask 077;x2dii_offset=0;while [ \"$x2dii_offset\" -lt {len(encoded)} ]; do " +
        f'cat {prefix}-$x2dii_offset.b64 || exit 31; x2dii_offset=$((x2dii_offset+{chunk_chars})); done >{upload})')
    add("assemble-current-" + label, parts_check + " && " + join + " && " + bound(upload, encoded.encode("ascii")))
    add("decode-current-" + label, bound(upload, encoded.encode("ascii")) +
        f" && [ ! -e {packed} ] && [ ! -L {packed} ] && (set -C;umask 077;base64 -d {upload} >{packed}) && " +
        bound(packed, compressed))
    add("create-current-" + label, bound(packed, compressed) +
        f" && (set -C;umask 077;gzip -dc {packed} >{path})", final=True)
    return _bound_preparation(plan, session, purpose, ((path, raw),), steps)


def plan_menu_support_staging(plan, manifest, raw_session):
    """Prepare only l/w/t/q/s/v; defer a/r to each independent boot preparation.

    The /tmp parent may be absent or an exact private directory. No existing
    target is adopted, deleted, chmodded or overwritten. No lifecycle action is
    run. A later fresh ready window must read back these exact source bytes.
    """
    from . import session_context as sc
    session = plan_raw_session_staging(plan, manifest, raw_session)
    _need(sc.decode_session(raw_session)["kind"] == "menu_validation", "menu support requires temporary session")
    files = menu_support_files(manifest)
    roots = tuple(dict.fromkeys(path.rsplit("/", 1)[0] for path, _ in files))
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:", format=tarfile.USTAR_FORMAT) as writer:
        for path, raw in files:
            entry = tarfile.TarInfo(path.removeprefix("/tmp/"))
            entry.mode, entry.size, entry.uid, entry.gid, entry.mtime = 0o600, len(raw), 0, 0, 0
            writer.addfile(entry, io.BytesIO(raw))
    archive = output.getvalue()
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as reader:
        entries = reader.getmembers()
        _need(tuple(item.name for item in entries) == tuple(path.removeprefix("/tmp/") for path, _ in files),
              "fixed support archive names differ")
        for item, (_, raw) in zip(entries, files):
            _need(item.type == tarfile.REGTYPE and item.mode == 0o600 and item.size == len(raw) and
                  item.uid == item.gid == item.mtime == 0 and item.uname == item.gname == item.linkname == "" and
                  reader.extractfile(item).read() == raw, "fixed support archive member differs")
    compressed = gzip.compress(archive, mtime=0)
    _need(gzip.decompress(compressed) == archive, "support archive roundtrip differs")
    encoded = base64.b64encode(compressed).decode("ascii")
    prefix = ".menu-support-" + session.session_nonce
    upload, packed, unpacked = prefix + ".b64", prefix + ".gz", prefix + ".tar"
    steps = []

    def add(label, body, stdout=""):
        steps.append(_preparation_step(plan, session, label, body, stdout))

    def bound(path, raw):
        return (_regular(path) + " && " + _equals(f"stat -c %s {path}", str(len(raw))) + " && " +
                _equals(f"sha256sum {path}", _sha(raw) + "  " + path))

    parent_check = '[ -d /tmp ] && [ ! -L /tmp ]'
    create = parent_check
    for root in roots:
        create += (f" && if [ ! -e {root} ] && [ ! -L {root} ]; then (umask 077;mkdir -m 700 {root}); fi && " +
                   _directory(root))
    targets = " ".join(path for path, _ in files)
    create += " && for x2dii_new in " + targets + " " + " ".join((upload, packed, unpacked)) + (
        '; do [ ! -e "$x2dii_new" ] && [ ! -L "$x2dii_new" ] || exit 31; done')
    add("prepare-private-menu-support-roots", create)
    for offset in range(0, len(encoded), CHUNK_CHARS):
        name, part = prefix + f"-{offset}.b64", encoded[offset:offset + CHUNK_CHARS]
        add(f"menu-support-chunk-{offset}", f'x2p={name} && [ ! -e "$x2p" ] && [ ! -L "$x2p" ] && ' +
            f'(set -C;umask 077;printf %s \'{part}\' >"$x2p") && ' + _regular('"$x2p"') + " && " +
            _equals('stat -c %s "$x2p"', str(len(part))))
    check = f"x2dii_offset=0 && while [ \"$x2dii_offset\" -lt {len(encoded)} ]; do " + (
        f'x2dii_part={prefix}-$x2dii_offset.b64; ' + _regular('"$x2dii_part"') +
        f' || exit 31; x2dii_offset=$((x2dii_offset+{CHUNK_CHARS})); done')
    join = (f"[ ! -e {upload} ] && [ ! -L {upload} ] && " +
        f"(set -C;umask 077;x2dii_offset=0;while [ \"$x2dii_offset\" -lt {len(encoded)} ]; do " +
        f'cat {prefix}-$x2dii_offset.b64 || exit 31; x2dii_offset=$((x2dii_offset+{CHUNK_CHARS})); done >{upload})')
    add("decode-menu-support", check + " && " + join + " && " + bound(upload, encoded.encode("ascii")) +
        f" && [ ! -e {packed} ] && [ ! -L {packed} ] && (set -C;umask 077;base64 -d {upload} >{packed}) && " +
        bound(packed, compressed))
    add("inflate-menu-support", bound(packed, compressed) +
        f" && [ ! -e {unpacked} ] && [ ! -L {unpacked} ] && (set -C;umask 077;gzip -dc {packed} >{unpacked}) && " +
        bound(unpacked, archive))
    before = parent_check + " && " + " && ".join(_directory(root) for root in roots)
    before += " && for x2dii_new in " + targets + (
        '; do [ ! -e "$x2dii_new" ] && [ ! -L "$x2dii_new" ] || exit 31; done')
    # The archive is fixed and checked immediately before extraction. Final
    # exact file readback is deliberately grouped by parent to fit the frame.
    add("extract-menu-support", before + " && " + bound(unpacked, archive) +
        " && for x2dii_new in " + targets + "; do " +
        f'(set -C;umask 077;tar -xOf {unpacked} "${{x2dii_new#/tmp/}}" >"$x2dii_new") || exit 31; done')
    for index, root in enumerate(roots):
        subset = tuple((path, raw) for path, raw in files if path.rsplit("/", 1)[0] == root)
        names = " ".join(path for path, _ in subset)
        hashes = "".join(f"{_sha(raw)}  {path}\n" for path, raw in subset)
        sizes = "".join(f"{len(raw)}\n" for _, raw in subset)
        add(f"verify-menu-support-{index}", parent_check + " && " + _directory(root) +
            " && for x2dii_file in " + names + "; do " + _regular('"$x2dii_file"') +
            f" || exit 31; done && sha256sum {names} && stat -c %s {names}", hashes + sizes)
    return _bound_preparation(plan, session, "menu_support_programs", files, steps)


def plan_owned_cleanup_staging(plan, manifest, raw_session, original_identities, stock_readback, restore_receipt):
    """Stage only the four exact-owned cleanup workers and their fixed observer.

    Inputs and every source byte come from the specific cleanup renderer. This
    does not run cleanup, change its original session lease, or accept caller
    file/archive/command lists. All five destinations must be absent.
    """
    from . import menu_owned_cleanup as cleanup
    session = plan_raw_session_staging(plan, manifest, raw_session)
    programs = cleanup.render_programs(manifest, raw_session, original_identities, stock_readback, restore_receipt)
    paths = tuple(cleanup.worker_path(manifest, raw_session, i) for i in range(4)) + (
        cleanup.observer_path(manifest, raw_session),)
    _need(type(programs) is dict and set(programs) == set(paths) and
          all(type(programs[path]) is bytes and programs[path] for path in paths), "fixed five cleanup sources required")
    files = tuple((path, programs[path]) for path in paths)
    names = ("cleanup-0", "cleanup-1", "cleanup-2", "cleanup-3", "cleanup-o")
    _need(all(path.rsplit("/", 1)[0] == plan.stage_root for path in paths[:4]), "cleanup worker stage differs")
    observer_root = paths[4].rsplit("/", 1)[0]
    _need(observer_root == "/tmp/xc-" + session.data_sha256[:16], "fixed cleanup observer directory differs")
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:", format=tarfile.USTAR_FORMAT) as writer:
        for name, (_, raw) in zip(names, files):
            entry = tarfile.TarInfo(name)
            entry.mode, entry.size, entry.uid, entry.gid, entry.mtime = 0o600, len(raw), 0, 0, 0
            writer.addfile(entry, io.BytesIO(raw))
    archive = output.getvalue()
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as reader:
        entries = reader.getmembers()
        _need(tuple(item.name for item in entries) == names, "cleanup archive names differ")
        for item, (_, raw) in zip(entries, files):
            _need(item.type == tarfile.REGTYPE and item.mode == 0o600 and item.size == len(raw) and
                  item.uid == item.gid == item.mtime == 0 and item.uname == item.gname == item.linkname == "" and
                  reader.extractfile(item).read() == raw, "cleanup archive member differs")
    compressed = gzip.compress(archive, mtime=0)
    _need(gzip.decompress(compressed) == archive, "cleanup compression roundtrip differs")
    encoded = base64.b64encode(compressed).decode("ascii")
    prefix = ".cleanup-sources-" + session.data_sha256[:16]
    upload, packed, unpacked = prefix + ".b64", prefix + ".gz", prefix + ".tar"
    steps = []

    def add(label, body, stdout=""):
        steps.append(_preparation_step(plan, session, label, body, stdout))

    def bound(path, raw):
        return (_regular(path) + " && " + _equals(f"stat -c %s {path}", str(len(raw))) + " && " +
                _equals(f"sha256sum {path}", _sha(raw) + "  " + path))

    guard = "[ -d /tmp ] && [ ! -L /tmp ] && " + _directory(observer_root)
    absent = "for x2dii_new in " + " ".join((*paths, upload, packed, unpacked)) + (
        '; do [ ! -e "$x2dii_new" ] && [ ! -L "$x2dii_new" ] || exit 31; done')
    add("begin-fixed-cleanup-sources", "[ -d /tmp ] && [ ! -L /tmp ] && " +
        f"if [ ! -e {observer_root} ] && [ ! -L {observer_root} ]; then (umask 077;mkdir -m 700 {observer_root}); fi && " +
        _directory(observer_root) + " && " + absent)
    for offset in range(0, len(encoded), CHUNK_CHARS):
        name, part = prefix + f"-{offset}.b64", encoded[offset:offset + CHUNK_CHARS]
        add(f"cleanup-source-chunk-{offset}", f'x2p={name} && [ ! -e "$x2p" ] && [ ! -L "$x2p" ] && ' +
            f'(set -C;umask 077;printf %s \'{part}\' >"$x2p") && ' + _regular('"$x2p"') + " && " +
            _equals('stat -c %s "$x2p"', str(len(part))))
    check = f"x2dii_offset=0 && while [ \"$x2dii_offset\" -lt {len(encoded)} ]; do " + (
        f'x2dii_part={prefix}-$x2dii_offset.b64; ' + _regular('"$x2dii_part"') +
        f' || exit 31; x2dii_offset=$((x2dii_offset+{CHUNK_CHARS})); done')
    join = (f"[ ! -e {upload} ] && [ ! -L {upload} ] && " +
        f"(set -C;umask 077;x2dii_offset=0;while [ \"$x2dii_offset\" -lt {len(encoded)} ]; do " +
        f'cat {prefix}-$x2dii_offset.b64 || exit 31; x2dii_offset=$((x2dii_offset+{CHUNK_CHARS})); done >{upload})')
    add("decode-fixed-cleanup-sources", check + " && " + join + " && " + bound(upload, encoded.encode("ascii")) +
        f" && [ ! -e {packed} ] && [ ! -L {packed} ] && (set -C;umask 077;base64 -d {upload} >{packed}) && " + bound(packed, compressed))
    add("inflate-fixed-cleanup-sources", bound(packed, compressed) +
        f" && [ ! -e {unpacked} ] && [ ! -L {unpacked} ] && (set -C;umask 077;gzip -dc {packed} >{unpacked}) && " + bound(unpacked, archive))
    targets_absent = "for x2dii_new in " + " ".join(paths) + (
        '; do [ ! -e "$x2dii_new" ] && [ ! -L "$x2dii_new" ] || exit 31; done')
    add("extract-fixed-cleanup-sources", guard + " && " + targets_absent + " && " + bound(unpacked, archive) +
        " && for x2dii_index in 0 1 2 3 o; do case $x2dii_index in o) x2dii_target=" + paths[4] +
        f";; *) x2dii_target=cleanup-{session.data_sha256[:12]}-$x2dii_index.sh;; esac; " +
        f'(set -C;umask 077;tar -xOf {unpacked} "cleanup-$x2dii_index" >"$x2dii_target") || exit 31; done')
    for index, subset in enumerate((files[:4], files[4:])):
        targets = " ".join(path for path, _ in subset)
        expected = "".join(f"{_sha(raw)}  {path}\n" for path, raw in subset)
        expected += "".join(f"{len(raw)}\n" for _, raw in subset)
        add(f"verify-fixed-cleanup-sources-{index}", guard + " && for x2dii_file in " + targets + "; do " +
            _regular('"$x2dii_file"') + f" || exit 31; done && sha256sum {targets} && stat -c %s {targets}", expected)
    return _bound_preparation(plan, session, "owned_cleanup_programs", files, steps)


def execution_steps(plan, context, *, session=None, role="su", request_nonce=None):
    """Render inert role-specific sources; FixedStagingExchange releases sends.

    Only maintenance can inspect init's namespace. Session-less su source is
    retained for offline compilation, never accepted by the supervised adapter.
    Rendering either role does not execute it or establish a checked boundary.
    """
    _need(type(plan) is StagingPlan, "fixed staging plan required")
    _need(role in ("su", "maintenance"), "fixed execution role required")
    _need(type(context) is dict and set(context) == {"boot_id", "mount_namespace", "init_mount_namespace"},
          "exact current execution context required")
    _need(type(context["boot_id"]) is str and re.fullmatch(r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}",
                                                           context["boot_id"]) is not None, "invalid boot identity")
    _need(all(type(context[key]) is str and re.fullmatch(r"mnt:\[[0-9]+\]", context[key]) is not None
              for key in ("mount_namespace", "init_mount_namespace")) and
          context["mount_namespace"] == context["init_mount_namespace"], "namespace identity differs")
    steps = plan.steps
    if session is not None:
        _validate_execution_session(plan, context, session)
        if plan.include_session_file:
            steps += session.steps
    checks = (
        ("boot_id", "cat /proc/sys/kernel/random/boot_id"),
        ("mount_namespace", "readlink /proc/self/ns/mnt"))
    domain = "u:r:su:s0" if role == "su" else "u:r:hbl_camera_service:s0"
    identity = _equals("id -u", "0") + " && " + _equals("cat /proc/self/attr/current", domain)
    su_guard = identity + " && " + " && ".join(_equals(command, context[key]) for key, command in checks)
    if session is not None:
        su_guard += " && " + _lease_guard(session.observed_epoch)
    if role == "su":
        return tuple(StageStep(step.label, su_guard + " && (" + step.command + ")", step.expected_stdout)
                     for step in steps)
    _need(type(session) is SessionStaging, "maintenance needs original current session")
    _need(type(request_nonce) is str and re.fullmatch(r"[0-9a-f]{32}", request_nonce) is not None,
          "fresh fixed maintenance request nonce required")
    return plan_maintenance_staging(plan, context, session=session,
                                    request_nonce=request_nonce).observations


def plan_maintenance_staging(plan, context, *, session, request_nonce):
    """Fixed local sources using exclusive 96-character maintenance blocks.

    This does not call the old staging CLI or transmit anything. The script is
    uploaded once; per-step invocations only carry index and bound data hash.
    The table contains digests/identity, never shell commands or sourced text.
    """
    from .stage_peer_usb_access import envelope
    _need(type(request_nonce) is str and re.fullmatch(r"[0-9a-f]{32}", request_nonce) is not None,
          "fresh fixed maintenance request nonce required")
    _need(type(session) is SessionStaging, "maintenance needs original current session")
    su_steps = execution_steps(plan, context, session=session)
    root = "/tmp/x2st-" + session.binding_sha256[:12]
    program = r'''#!/system/bin/sh
set -eu
export PATH=/system/bin:/system/xbin:/sbin
root='@ROOT@'
[ "$#" = 2 ] && [ "$0" = "$root/o" ] || exit 32
index=$1
data_sha=$2
equals() { expected=$1; shift; reply=$("$@") || return 1; [ "$reply" = "$expected" ]; }
hex() { [ "${#1}" = "$2" ] || return 1; case "$1" in *[!0-9a-f]*) return 1;; esac; }
integer() {
 [ "${#1}" -le 10 ] || return 1
 case "$1" in ''|*[!0-9]*) return 1;; 0|[1-9]*) return 0;; *) return 1;; esac
}
integer "$index" && hex "$data_sha" 64 || exit 32
[ -d /tmp ] && [ ! -L /tmp ] && [ -d "$root" ] && [ ! -L "$root" ] || exit 32
equals 0:0:700 stat -c '%u:%g:%a' "$root" || exit 32
regular() {
 [ -f "$1" ] && [ ! -L "$1" ] &&
 equals 0:0:600:1 stat -c '%u:%g:%a:%h' "$1"
}
hashok() { actual=$(sha256sum "$1") || return 1; [ "${actual%% *}" = "$2" ]; }
regular "$root/o" && regular "$root/d" && hashok "$root/d" "$data_sha" || exit 32
size=$(stat -c %s "$root/d") || exit 32
integer "$size" && [ "$size" -gt 0 ] && [ "$size" -le 1048576 ] || exit 32
data_identity=$(stat -c '%d:%i:%s:%h' "$root/d") || exit 32
exec 4<"$root/d"
field() {
 IFS= read -r line <&4 || exit 32
 case "$line" in "$1="*) value=${line#*=};; *) exit 32;; esac
}
field schema; [ "$value" = x2dii-stage-observer-index-v1 ] || exit 32
field plan_sha256; plan_sha=$value; hex "$plan_sha" 64 || exit 32
field execution_sha256; execution_sha=$value; hex "$execution_sha" 64 || exit 32
field program_sha256; program_sha=$value; hex "$program_sha" 64 || exit 32
hashok "$root/o" "$program_sha" || exit 32
field request_nonce; nonce=$value; hex "$nonce" 32 || exit 32
field boot_id; boot=$value
case "$boot" in ????????-????-????-????-????????????) ;; *) exit 32;; esac
case "$boot" in *[!0-9a-f-]*) exit 32;; esac
field mount_namespace; namespace=$value
case "$namespace" in 'mnt:['*']') ns=${namespace#'mnt:['}; ns=${ns%']'};; *) exit 32;; esac
integer "$ns" || exit 32
field init_mount_namespace; [ "$value" = "$namespace" ] || exit 32
field observed_epoch; observed=$value; integer "$observed" && [ "$observed" -gt 0 ] || exit 32
field count; count=$value; integer "$count" && [ "$count" -gt 0 ] && [ "$index" -lt "$count" ] || exit 32
i=0; selected=''
while [ "$i" -lt "$count" ]; do
 field "command_$i"; hex "$value" 64 || exit 32
 if [ "$i" = "$index" ]; then selected=$value; fi
 i=$((i+1))
done
extra=''
if IFS= read -r extra <&4; then exit 32
else [ "$?" = 1 ] && [ -z "$extra" ] || exit 32; fi
exec 4<&-
hex "$selected" 64 || exit 32
fresh() {
 now=$(date -u +%s) || return 1
 integer "$now" && [ "$now" -ge "$observed" ] && [ "$now" -le "$((observed+600))" ]
}
fresh || exit 32
started=$now
equals 0 id -u && equals u:r:hbl_camera_service:s0 cat /proc/self/attr/current || exit 31
equals "$boot" cat /proc/sys/kernel/random/boot_id &&
equals "$namespace" readlink /proc/self/ns/mnt &&
equals "$namespace" readlink /proc/1/ns/mnt || exit 32
regular "$root/o" && regular "$root/d" && hashok "$root/o" "$program_sha" && hashok "$root/d" "$data_sha" || exit 32
equals "$data_identity" stat -c '%d:%i:%s:%h' "$root/d" || exit 32
fresh && [ "$now" -ge "$started" ] || exit 32
printf 'X2DII_STAGE_MAINTENANCE:%s:%s:%s:%s:%s:%s:%s\n' "$plan_sha" "$execution_sha" "$index" "$selected" "$nonce" "$started" "$now"
'''.replace("@ROOT@", root).encode("ascii")
    program_sha = _sha(program)
    header = (("schema", "x2dii-stage-observer-index-v1"), ("plan_sha256", plan.plan_sha256),
              ("execution_sha256", session.binding_sha256), ("program_sha256", program_sha),
              ("request_nonce", request_nonce), ("boot_id", context["boot_id"]),
              ("mount_namespace", context["mount_namespace"]),
              ("init_mount_namespace", context["init_mount_namespace"]),
              ("observed_epoch", session.observed_epoch), ("count", len(su_steps)))
    command_hashes = tuple(_sha(step.command.encode("ascii")) for step in su_steps)
    data = ("".join(f"{key}={value}\n" for key, value in header) +
            "".join(f"command_{index}={value}\n" for index, value in enumerate(command_hashes))).encode("ascii")
    _need(len(data) <= 1048576, "fixed staging index exceeds bounded observer input")
    data_sha = _sha(data)
    preparation = []

    def add(label, command, stdout=""):
        envelope(command, "123456abcdef")
        preparation.append(StageStep("prepare-observer-" + label, command, stdout))

    add("directory", f'umask 077;[ -d /tmp ] && [ ! -L /tmp ] && mkdir -m 700 {root}')
    for name, raw in (("o", program), ("d", data)):
        encoded = base64.b64encode(raw).decode("ascii")
        upload, target = root + "/p" + name, root + "/" + name
        add("begin-" + name, f'cd {root} && [ ! -e p{name} ] && [ ! -L p{name} ] && [ ! -e {name} ] && [ ! -L {name} ]')
        chunks = [encoded[offset:offset + 96] for offset in range(0, len(encoded), 96)]
        _need(len(chunks) <= 1000, "observer exceeds fixed three-digit block layout")
        for index, part in enumerate(chunks):
            add(f"chunk-{name}-{index * 96}", f"(set -C;umask 077;printf %s '{part}' >{root}/{name}{index:03d})")
        # Never append to or chmod an earlier pathname. Fixed-width block order
        # plus final exact program/index readback binds bytes; every cat status
        # is checked without a pipeline that could hide an upstream failure.
        add("assemble-" + name, f'(set -C;umask 077;cd {root} && for f in {name}???; do '
            '[ -f "$f" ] && [ ! -L "$f" ] || exit 31;cat "$f" || exit 31;'
            f'done >p{name})')
        add("decode-" + name, f'(set -C;umask 077;base64 -d {upload} >{target})')
        if name == "o":
            add("syntax", f"sh -n {target}")
        add("readback-" + name, f"sha256sum {target}", f"{_sha(raw)}  {target}\n")
    observations = []
    for index, (step, command_sha) in enumerate(zip(su_steps, command_hashes)):
        command = f"sh {root}/o {index} {data_sha}"
        envelope(command, "123456abcdef")
        prefix = (f"X2DII_STAGE_MAINTENANCE:{plan.plan_sha256}:{session.binding_sha256}:"
                  f"{index}:{command_sha}:{request_nonce}:")
        observations.append(StageStep("observe-" + step.label, command, prefix))
    return StagingObserver(root, program, data, program_sha, data_sha, tuple(preparation), tuple(observations))


class FixedStagingExchange:
    """Fixed maintenance/readback -> su -> readback sequence, without any I/O.

    A real dual-route sender must validate wire completion and retain raw bytes
    before accept(). The role comes from the selected route, not returned text.
    It must recheck freshness immediately before sending: accepting a timely
    receipt here cannot establish when an external sender actually wrote it.
    Caller assertions here are not live evidence or installation authorization.
    The older independent C# Stage entry cannot use this unsent local adapter.
    """

    def __init__(self, plan, context, *, session, clock=time.time):
        _need(type(session) is SessionStaging, "supervised staging needs original current session")
        self._steps = execution_steps(plan, context, session=session)
        self.observer = plan_maintenance_staging(plan, context, session=session,
                                                 request_nonce=secrets.token_hex(16))
        self._observations = self.observer.observations
        self._preparation_index = 0
        self._session = session
        self._clock = clock
        self._index = 0
        self._role = "maintenance"
        self._issued = None
        self._checked = None
        self._released_role = None
        self._released_preparation = False
        self.failed = False

    def _now(self):
        value = self._clock()
        _need(type(value) in (int, float) and 0 <= value < 10**10, "invalid host observation time")
        value = int(value)
        _need(self._session.observed_epoch <= value <= self._session.observed_epoch + 600,
              "original staging observation lease expired or future")
        return value

    @property
    def all_results_validated(self):
        return not self.failed and self._index == len(self._steps)

    @property
    def next_step(self):
        if self.failed or self.all_results_validated:
            return None
        try:
            now = self._now()
            if self._preparation_index < len(self.observer.preparation):
                step = self.observer.preparation[self._preparation_index]
                self._released_preparation = True
                return StageExchangeStep("maintenance", self._preparation_index - len(self.observer.preparation),
                                         step.label, step.command, step.expected_stdout)
            if self._role == "maintenance":
                if self._issued is None:
                    self._issued = now
                _need(0 <= now - self._issued <= 8, "maintenance request expired")
                step = self._observations[self._index]
            else:
                _need(self._checked is not None and 0 <= now - self._checked <= 8,
                      "maintenance response expired before su send")
                step = self._steps[self._index]
            self._released_role = self._role
            return StageExchangeStep(self._role, self._index, step.label, step.command, step.expected_stdout)
        except ValueError:
            self.failed = True
            raise

    def accept(self, *, role=None, index, command, exit_code, stdout, completion_validated):
        try:
            _need(not self.failed and not self.all_results_validated, "sequence already stopped or complete")
            if self._preparation_index < len(self.observer.preparation):
                _need(self._released_preparation, "observer preparation was not released")
                expected_index = self._preparation_index - len(self.observer.preparation)
                step = self.observer.preparation[self._preparation_index]
                _need(role == "maintenance" and type(index) is int and index == expected_index and
                      command == step.command, "wrong role, index or fixed observer preparation command")
                _need(completion_validated is True and type(exit_code) is int and exit_code == 0,
                      "observer preparation completion not validated")
                _need(type(stdout) is str and stdout.replace("\r\n", "\n") == step.expected_stdout,
                      "observer preparation readback differs")
                self._now()
                self._preparation_index += 1
                self._released_preparation = False
                return
            # The response must follow a released request; unsolicited old data
            # cannot cause next_step to initialize a new observation timestamp.
            _need(self._issued is not None, "maintenance request was not issued")
            _need(role == self._role and type(index) is int and index == self._index,
                  "wrong role or out-of-order staging result")
            _need(role == self._released_role, "role command was not released")
            step = self._observations[index] if role == "maintenance" else self._steps[index]
            _need(command == step.command, "different role command")
            _need(completion_validated is True, "transport completion not validated")
            _need(type(exit_code) is int and exit_code == 0, "role command failed")
            _need(type(stdout) is str and len(stdout) <= 8192, "invalid bounded role readback")
            output = stdout.replace("\r\n", "\n")
            now = self._now()
            if role == "maintenance":
                match = re.fullmatch(re.escape(step.expected_stdout) + r"([0-9]{1,10}):([0-9]{1,10})\n", output)
                _need(match is not None, "maintenance receipt identity or framing differs")
                started, checked = map(int, match.groups())
                _need(self._issued <= started <= checked <= now and now - self._issued <= 8,
                      "maintenance receipt is stale or future")
                self._checked = checked
                self._role = "su"
            else:
                _need(self._checked is not None and 0 <= now - self._checked <= 8,
                      "maintenance response expired before su receipt")
                _need(output == step.expected_stdout, "unexpected su readback")
                self._index += 1
                self._role = "maintenance"
                self._issued = self._checked = None
            self._released_role = None
        except ValueError:
            self.failed = True
            raise


def _host_source(plan, reference_source, *, admitted=False, deadline=None, context=None, session=None):
    """Fixed derivative of the reviewed WinUSB core; never an arbitrary shell API."""
    from . import peer_usb_access as usb
    _need(not admitted, "actual dual-domain staging sender not connected; review-only source")
    source = usb.host_source(reference_source)
    execution_hash = session.binding_sha256 if session is not None else plan.plan_sha256
    namespace = "X2d2MenuStage_" + execution_hash[:16]
    replace = usb.replace_once
    source = replace(source, "namespace X2d2PeerAdb", "namespace " + namespace)
    source = replace(source, "// X2D II stock USB ADB, fixed read-only query only; local source candidate.",
                     "// Fixed X2D II staging only. Compilation performs no USB operations.")
    source = replace(source, "        public static ProbeResult Probe() { return new ProbeResult { MatchingInterfaces = Enumerate().Count }; }",
                     "        // No independent public USB enumeration entry.")
    commands, expected = [], []
    context = context or (dict(session.context) if session is not None else {
        "boot_id": "00000000-0000-0000-0000-000000000000",
        "mount_namespace": "mnt:[0]", "init_mount_namespace": "mnt:[0]"})
    for index, step in enumerate(execution_steps(plan, context, session=session)):
        marker = "X2DII_STAGE_" + execution_hash[:24] + "_" + str(index) + "_RC="
        wire = "(" + step.command + ");r=$?;printf '\\n" + marker + "%s\\n' \"$r\""
        _need(len(("shell:" + wire + "\0").encode("ascii")) <= 4096, "framed command exceeds ADB limit")
        commands.append(wire)
        expected.append(step.expected_stdout + "\n" + marker + "0\n")
    deadline = deadline or datetime(2000, 1, 1, tzinfo=timezone.utc)
    _need(deadline.tzinfo is not None, "timezone-aware execution deadline required")
    literal = lambda value: json.dumps(value, ensure_ascii=True)
    helpers = r'''
        public const string PlanSha256 = PLAN_LITERAL;
        public const string ExecutionSha256 = EXECUTION_LITERAL;
        public const int FixedCommandCount = COUNT_LITERAL;
        private static readonly bool QualifiedSource = QUALIFIED_LITERAL;
        private static readonly DateTime ExecutionDeadline = DateTime.Parse(DEADLINE_LITERAL,
            CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind).ToUniversalTime();
        private static readonly string[] StageCommands = new string[] { COMMANDS_LITERAL };
        private static readonly string[] ExpectedStageOutputs = new string[] { OUTPUTS_LITERAL };
        private static int stagingAttempted;
        private static Stopwatch batchClock;
        // Pure checks never enumerate/open USB. Public for offline boundary tests.
        public static void ValidateStageOutput(int index, string output) {
            if(index<0 || index>=ExpectedStageOutputs.Length) throw new UsbFailure("STAGE_INDEX");
            if(output==null || output.Replace("\r\n","\n")!=ExpectedStageOutputs[index]) {
                byte[] raw=Encoding.UTF8.GetBytes(output ?? "");
                throw new UsbFailure("STAGE_REPLY_MISMATCH",0,
                    "index="+index+"; outputUtf8Base64="+Convert.ToBase64String(raw,0,Math.Min(raw.Length,8192))+
                    "; outputBytes="+raw.Length+"; outputTruncated="+(raw.Length>8192 ? "true" : "false"));
            }
        }
        private static void StageTime(int reserveMilliseconds) {
            if(!QualifiedSource) throw new UsbFailure("STAGE_SOURCE_NOT_QUALIFIED");
            if(batchClock==null || batchClock.ElapsedMilliseconds+reserveMilliseconds>45000 ||
               DateTime.UtcNow.AddMilliseconds(reserveMilliseconds)>ExecutionDeadline)
                throw new UsbFailure("STAGE_BATCH_DEADLINE");
        }
        private static void RequireMaintenanceSupervision() {
            // This old independent ADB entry cannot supply the maintenance
            // receipts required by FixedStagingExchange. It never silently
            // falls back to su-only checks, even with a future admitted flag.
            throw new UsbFailure("STAGE_DUAL_DOMAIN_SUPERVISION_REQUIRED");
        }
        public static string Stage() {
            // One attempt per loaded class; a later process still cannot overwrite the private stage.
            if(System.Threading.Interlocked.Exchange(ref stagingAttempted,1)!=0)
                throw new UsbFailure("STAGE_ALREADY_ATTEMPTED");
            batchClock=Stopwatch.StartNew();
            StageTime(17000); // 15-second transport limit plus one 2-second in-flight IO margin.
            RequireMaintenanceSupervision();
            RunShell(-1); // The unchanged, fixed UID/domain/USB identity check precedes writes.
            for(int index=0;index<StageCommands.Length;index++) {
                StageTime(17000);
                try {
                    string reply=RunShell(index);
                    Console.WriteLine("X2DII_STAGE_REPLY "+index+" "+Convert.ToBase64String(Encoding.UTF8.GetBytes(reply)));
                    StageTime(0);
                } catch(Exception error) {
                    Console.WriteLine("X2DII_STAGE_STOPPED "+index+" "+ExecutionSha256+" "+error.Message);
                    throw; // No retries, resume, installer execution or cleanup of uncertain files.
                }
            }
            return SUCCESS_LITERAL;
        }
'''
    for token, value in {"PLAN_LITERAL": literal(plan.plan_sha256), "EXECUTION_LITERAL": literal(execution_hash),
                         "COUNT_LITERAL": str(len(commands)),
                         "SUCCESS_LITERAL": literal("X2DII_STAGE_CONTENT_AND_SESSION_READBACK_ONLY_NOT_INSTALLED" if session else
                                                    "X2DII_STAGE_CONTENT_READBACK_ONLY_NOT_INSTALLED"),
                         "QUALIFIED_LITERAL": "true" if admitted else "false",
                         "DEADLINE_LITERAL": literal(deadline.isoformat()),
                         "COMMANDS_LITERAL": ",\n".join(map(literal, commands)),
                         "OUTPUTS_LITERAL": ",\n".join(map(literal, expected))}.items():
        helpers = helpers.replace(token, value)
    source = replace(source, "        public static string Query() { return RunShell(); }", helpers)
    source = replace(source, "        private static string RunShell() {", "        private static string RunShell(int index) {")
    source = replace(source, 'string command="shell:"+IdentityScript+"\\0";',
                     'string command="shell:"+(index<0 ? IdentityScript : StageCommands[index])+"\\0";')
    source = replace(source, '''                        ValidateIdentity(identity);
                        return "ADB_CONNECTED_READONLY_SU\\nINTERFACE="+observed.InterfaceNumber+
                            "\\nPIPE_IN="+observed.PipeIn+"\\nPIPE_OUT="+observed.PipeOut+"\\n"+identity;''',
                     '''                        if(index<0) ValidateIdentity(identity); else ValidateStageOutput(index,identity);
                        return identity;''')
    source = replace(source, "        private void CheckDeadline() {",
                     "        private void CheckDeadline() {\n            StageTime(0);")
    source = replace(source, "ReadResult observed=new ReadResult();s.Open(observed);s.Send",
                     "ReadResult observed=new ReadResult();StageTime(17000);s.Open(observed);s.Send")
    source = replace(source, "uint remote=0;StringBuilder result=new StringBuilder();",
                     "uint remote=0;StringBuilder result=new StringBuilder();\n"
                     "                List<byte> retainedPayload=new List<byte>();int receivedPayloadBytes=0;\n                try {")
    source = replace(source, 'if(result.Length+p.Data.Length>8192)throw new UsbFailure("ADB_OUTPUT_LIMIT");',
                     '''receivedPayloadBytes+=p.Data.Length;
                        int retainedCount=Math.Min(p.Data.Length,8192-retainedPayload.Count);
                        for(int j=0;j<retainedCount;j++) retainedPayload.Add(p.Data[j]);
                        if(receivedPayloadBytes>8192)throw new UsbFailure("ADB_OUTPUT_LIMIT");''')
    source = replace(source, '}throw new UsbFailure("ADB_PACKET_LIMIT");',
                     '''}throw new UsbFailure("ADB_PACKET_LIMIT");
                } catch(Exception error) {
                    UsbFailure original=error as UsbFailure;
                    if(original==null) original=new UsbFailure("STAGE_TRANSPORT_EXCEPTION",0,error.GetType().Name+": "+error.Message);
                    throw new UsbFailure(original.Code,original.Win32,original.Details+
                        "; stageIndex="+index+"; receivedPayloadBase64="+Convert.ToBase64String(retainedPayload.ToArray())+
                        "; receivedPayloadBytes="+receivedPayloadBytes+
                        "; payloadTruncated="+(receivedPayloadBytes>retainedPayload.Count ? "true" : "false"));
                }''')
    return namespace, source


def review_host_source(plan, reference_source, *, session=None):
    """Compile/pure-check source whose Stage entry always refuses before USB access."""
    return _host_source(plan, reference_source, session=session)[1]


def _require_maintenance_budget(deadline, *, now, remaining_commands):
    """Reject a known-impossible schedule; this cannot prove camera throughput.

    The caller is one of the two fixed qualified paths, using its actual pending
    operations. Read the pinned host transport's cadence as data only: do not
    import it, create its lock, connect, shorten its gap or extend a USB window.
    N sequential observations require at least N-1 gaps even if every other
    operation took zero time. Retain the existing 17s floor and 2s native I/O
    reserve; startup, execution and storage overhead remain unproven additions.
    """
    from . import live_readout
    _need(type(remaining_commands) is int and remaining_commands > 0,
          "fixed remaining maintenance command count required")
    raw = live_readout.TRANSPORT.read_bytes()
    _need(_sha(raw) == live_readout.TRANSPORT_SHA, "pinned maintenance transport cadence source changed")
    values = [node.value.value for node in ast.parse(raw).body
              if isinstance(node, ast.Assign) and len(node.targets) == 1
              and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "MIN_COMMAND_GAP_SECONDS"
              and isinstance(node.value, ast.Constant)]
    _need(len(values) == 1 and type(values[0]) in (int, float) and math.isfinite(values[0]) and values[0] > 0,
          "pinned maintenance transport cadence missing")
    minimum_seconds = max(17, (remaining_commands - 1) * values[0] + 2)
    # Match the generated native sender's integer epoch, not the slightly
    # later fractional authorization timestamp from which it was derived.
    native_deadline = datetime.fromtimestamp(int(deadline.timestamp()), timezone.utc)
    _need(now + timedelta(seconds=minimum_seconds) < native_deadline,
          "remaining maintenance window cannot meet its fixed minimum budget")


def validate_staging_window(window, plan, qualification, *, now, session=None):
    """Validate supplied scope/lifetime bindings, never invent or grant authority."""
    _need(type(window) is dict and window.get("approved") is True and
          window.get("purpose") == "temporary_adb_fixed_menu_staging",
          "separate current staging USB window authorization required")
    for key, expected in (("candidate_sha256", plan.candidate_sha256), ("plan_sha256", plan.plan_sha256),
                          ("boot_id", qualification["boot_id"]), ("session_nonce", qualification["session_nonce"])):
        _need(window.get(key) == expected, "window authorization binding differs: " + key)
    if session is not None:
        _need(type(session) is SessionStaging, "fixed window session required")
        observed_matches = session.observed_utc == qualification["observed_utc"]
        if session.binding_schema == "x2dii-current-stage-session-v2":
            # Raw v2 retains the renderer's integer epoch, not an invented
            # fractional timestamp. The full qualification/approval remains
            # bound to its original timestamp; this cannot renew the raw lease.
            observed = datetime.fromisoformat(qualification["observed_utc"])
            observed_matches = (observed.tzinfo is not None and
                session.observed_epoch == int(observed.timestamp()) and
                session.observed_utc == datetime.fromtimestamp(session.observed_epoch, timezone.utc).isoformat())
        _need(type(session) is SessionStaging and session.plan_sha256 == plan.plan_sha256 and
              window.get("session_data_sha256") == session.data_sha256 and
              session.session_nonce == qualification["session_nonce"] and
              observed_matches and
              dict(session.context) == {key: qualification[key] for key in dict(session.context)},
              "window session-data binding differs")
    _need(type(window.get("launch_session_sha256")) is str and
          re.fullmatch(r"[0-9a-f]{64}", window["launch_session_sha256"]) is not None,
          "reviewed current window launch evidence required")
    _need(type(window.get("launch_started_utc")) is str, "window launch timestamp required")
    launched = datetime.fromisoformat(window["launch_started_utc"])
    _need(now.tzinfo is not None and launched.tzinfo is not None and
          0 <= (now - launched).total_seconds() < 43,
          "window launch is stale/future or leaves insufficient transport time")
    observed = datetime.fromisoformat(qualification["observed_utc"])
    _need(observed.tzinfo is not None, "qualification timestamp lacks timezone")
    # Launch-start predates the worker's ADB enable. Do not renew its 90 seconds.
    deadline = min(launched + timedelta(seconds=60), observed + timedelta(seconds=600))
    if session is not None:
        deadline = min(deadline, datetime.fromtimestamp(session.observed_epoch + 600, timezone.utc))
    _need(now + timedelta(seconds=17) < deadline, "qualification lease leaves insufficient transport time")
    return deadline


def qualified_host_source(*, members, manifest, qualification, window_authorization, saved_launch_report=None):
    """Bind the existing complete final admission to the fixed dual-role sender.

    No files are published and nothing is connected or sent. Window approval is
    caller-supplied, independently reviewed authority, not a hash-derived fact.
    This is not a first temporary menu-validation exception. All existing final
    gates and approval are mandatory. The original report is exact saved bytes,
    and the returned source must be driven through ContentStageCoordinator and
    drive_content_process, never an independent unobserved ADB batch.
    """
    from . import prepare_peer_install as installer
    from . import peer_usb_access as usb, stage_peer_usb_access as launch_stage
    from . import menu_content_transport as transport
    from .regression_manifest import strict_json
    manifest, q, window = deepcopy(manifest), deepcopy(qualification), deepcopy(window_authorization)
    installer.validate_qualification(manifest, q, for_publication=True)
    _need(type(saved_launch_report) is bytes and 0 < len(saved_launch_report) <= 1024 * 1024,
          "exact bounded saved launch report bytes required")
    _need(type(window) is dict and window.get("launch_session_sha256") == _sha(saved_launch_report),
          "saved launch report byte hash differs")
    report = strict_json(saved_launch_report)
    _need(type(report) is dict and report.get("status") == "LAUNCH_REQUESTED_AWAITING_REAL_USB_EVIDENCE"
          and "error" not in report, "successful original USB launch record required")
    launched = launch_stage.recorded_launch_start(report)
    _need(report.get("stagerSha256") == _sha(Path(launch_stage.__file__).read_bytes()) and
          report.get("replySources") == launch_stage.live.source_hashes(), "saved launch source attribution differs")
    _need(report.get("bootId") == q["boot_id"] and window.get("launch_started_utc") == launched.isoformat(),
          "saved original launch boot/time differs")
    renderer = Path(installer.__file__).read_bytes()
    _need(manifest["renderer_source_sha256"] == _sha(renderer), "current installer renderer changed")
    scripts = installer.render_role_programs(manifest)
    hashes = {name: _sha(text.encode("ascii")) for name, text in scripts.items()}
    plan = plan_compressed_role_staging(members=members, candidate=manifest["candidate"],
                        candidate_sha256=manifest["candidate_sha256"], script_hashes=hashes,
                        renderer_source=renderer, renderer_source_sha256=_sha(renderer),
                        delivery_identity=q["delivery_identity"])
    session = plan_raw_session_staging(plan, manifest, installer.session_data(manifest, q))
    deadline = validate_staging_window(window, plan, q, now=datetime.now(timezone.utc), session=session)
    remaining = len(execution_steps(plan, dict(session.context), session=session))
    _require_maintenance_budget(deadline, now=datetime.now(timezone.utc), remaining_commands=remaining)
    source = transport.review_content_host_source(plan, session, launched)
    original_deadline = int(transport.original_window_deadline(session.observed_epoch, launched))
    deadline_epoch = min(original_deadline, int(deadline.timestamp()))
    source = usb.replace_once(source, f"private const long ContentDeadlineEpoch = {original_deadline};",
                              f"private const long ContentDeadlineEpoch = {deadline_epoch};")
    namespaces = re.findall(r"(?m)^namespace (X2d2ContentStage_[0-9a-f]{16}) \{$", source)
    _need(len(namespaces) == 1, "fixed content source namespace differs")
    namespace = namespaces[0]
    installer.validate_qualification(manifest, q, for_publication=True)
    _need(datetime.now(timezone.utc) + timedelta(seconds=17) < deadline, "window expired during source qualification")
    _require_maintenance_budget(deadline, now=datetime.now(timezone.utc), remaining_commands=remaining)
    # This exact final-admission branch is the only changed native guard. The
    # public review renderer and historical independent sender remain closed.
    source = usb.replace_once(source, "private static readonly bool ContentQualified = false;",
                              "private static readonly bool ContentQualified = true;")
    source_hash = _sha(source.encode("utf-8"))
    return {"status": "QUALIFIED_STAGING_SOURCE_NOT_EXECUTED", "candidate_sha256": plan.candidate_sha256,
            "plan_sha256": plan.plan_sha256, "source_sha256": source_hash,
            "execution_sha256": session.binding_sha256, "session_data_sha256": session.data_sha256,
            "session_data_path": session.path, "session_data_uploaded": False,
            "namespace": namespace, "entry_point": namespace + ".AdbUsbCheck.RunContentStage",
            "launch_started_utc": launched.isoformat(), "launch_report_sha256": _sha(saved_launch_report),
            "window_authorization_sha256": _sha(_canonical(window)), "deadline_utc": deadline.isoformat(),
            "sources": {"X2d2MenuStage.cs": source},
            "camera_accesses": 0, "installation_executed": False}
