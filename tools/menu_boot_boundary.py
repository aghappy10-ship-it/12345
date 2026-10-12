"""Read-only, fixed-action boot boundary observations; no transport or authority.

Activation observes the original live components. Recovery observes its own
fresh recovery context and does not depend on extension or capture health.
The caller owns single-use sequencing and the same blocked worker channel.
"""
from __future__ import annotations

import re

from . import menu_maintenance_boundary as base
from . import session_context as session


STAGES = {
    "activate": tuple(enumerate((
        "remount_rw", "backup_create", "backup_write", "backup_chmod", "backup_timestamp",
        "temporary_create", "temporary_write", "temporary_chmod", "temporary_timestamp",
        "commit_rename", "final_identity", "final_receipt"))),
    "restore": tuple(enumerate((
        "remount_rw", "temporary_create", "temporary_write", "temporary_chmod", "temporary_timestamp",
        "commit_rename", "final_identity", "final_receipt"))),
}
REQUEST_SCHEMA = "x2dii-boot-maintenance-request-v1"
RESPONSE_SCHEMA = "x2dii-boot-maintenance-response-v1"
REQUEST_FIELDS = tuple("action" if key == "file_index" else key for key in base.REQUEST_FIELDS)
RESPONSE_FIELDS = REQUEST_FIELDS + base.RESPONSE_FIELDS[len(base.REQUEST_FIELDS):]
SCOPE = base.SCOPE


def stages(action):
    base._need(type(action) is str and action in STAGES, "unsupported fixed boot action")
    entries = STAGES[action]
    return tuple((index, name, "ro" if index == 0 or index >= len(entries) - 2 else "rw")
                 for index, name in entries)


def paths(manifest, action, boundary_index, *, session_nonce, session_data_sha256):
    sequence = stages(action)
    base._need(type(boundary_index) is int and 0 <= boundary_index < len(sequence), "invalid boot boundary")
    digest = base._candidate(manifest)
    base._need(type(session_nonce) is str and re.fullmatch("[0-9a-f]{32}", session_nonce) is not None,
               "boot request session nonce required")
    stage = "/blackbox/x2dii-menu-stage/" + digest[:24]
    return {"program": "/tmp/x2bb-" + digest[:12] + ("/a" if action == "activate" else "/r"),
            "session": base.session_path(manifest, session_data_sha256),
            "request": stage + f"/.boot-{action}-{session_nonce}-{boundary_index}.data"}


def _validate(values):
    base._need(type(values) is dict and set(values) == set(REQUEST_FIELDS), "boot request fields differ")
    base._need(values["schema"] == REQUEST_SCHEMA, "boot request schema differs")
    sequence = stages(values["action"])
    index = values["boundary_index"]
    base._need(type(index) is int and 0 <= index < len(sequence), "invalid boot boundary")
    _, name, access = sequence[index]
    base._need(values["boundary_name"] == name and values["mount_access"] == access, "boot stage differs")
    # Reuse scalar/time/session-binding validation, without treating a boot
    # action as a payload file index in the encoded protocol.
    check = dict(values)
    check.pop("action")
    check.update(schema=base.REQUEST_SCHEMA, file_index=0, boundary_index=0,
                 boundary_name="remount_rw", mount_access="ro")
    base._validate_request(check)


def decode_request(raw):
    values = base._decode(raw, REQUEST_FIELDS)
    _validate(values)
    return values


def context_for_action(manifest, raw_session, action):
    stages(action)
    values = session.decode_session(raw_session)
    if action == "activate":
        base._need(base.session_kind_for_context(manifest, raw_session) == "install", "activation needs install v2")
    else:
        base._candidate(manifest)
        base._need(raw_session.startswith(("schema=" + session.SCHEMA + "\n").encode()) and
                   values["kind"] == "recovery" and
                   values["observer_domain"] == "u:r:hbl_camera_service:s0", "restoration needs recovery v1")
    return values


def make_request(manifest, raw_session, *, action, worker_session_sha256,
                 worker_program_sha256, boundary_index, challenge, issued_epoch):
    values = context_for_action(manifest, raw_session, action)
    paths(manifest, action, boundary_index, session_nonce=values["session_nonce"], session_data_sha256=base._sha(raw_session))
    _, name, access = stages(action)[boundary_index]
    request = dict(schema=REQUEST_SCHEMA, candidate_sha256=base._candidate(manifest),
        boot_id=values["boot_id"], session_nonce=values["session_nonce"], action=action,
        boundary_index=boundary_index, boundary_name=name, mount_access=access,
        worker_program_sha256=worker_program_sha256, worker_session_sha256=worker_session_sha256,
        maintenance_program_sha256=base._sha(render_observer(manifest, action=action).encode("ascii")),
        maintenance_session_sha256=base._sha(raw_session), challenge=challenge,
        observed_epoch=values["observed_epoch"], issued_epoch=issued_epoch,
        deadline_epoch=values["observed_epoch"] + 600)
    _validate(request)
    return base._encode(request, REQUEST_FIELDS)


def decode_response(raw, expected_request, *, received_epoch):
    request = decode_request(expected_request)
    response = base._decode(raw, RESPONSE_FIELDS)
    base._need(response["schema"] == RESPONSE_SCHEMA, "boot response schema differs")
    base._need(all(response[key] == request[key] for key in REQUEST_FIELDS[1:]), "boot response binding differs")
    base._need(response["request_sha256"] == base._sha(expected_request), "boot request digest differs")
    base._need(response["result"] == "OBSERVED_MATCH" and response["scope"] == SCOPE, "boot observation scope differs")
    base._need(all(base._integer(value, low=1) for value in
                   (response["started_epoch"], response["checked_epoch"], received_epoch)), "boot response time invalid")
    base._need(request["issued_epoch"] <= response["started_epoch"] <= response["checked_epoch"] <=
               received_epoch <= request["deadline_epoch"], "boot observation expired or predates request")
    return response


def render_observer(manifest, *, action):
    """Fixed action argv: SESSION_SHA ACTION BOUNDARY_INDEX REQUEST_SHA.

    Reuses the audited kernel/session observation implementation, with exact
    counted replacements. Recovery replaces the installation-only predicates;
    it never treats missing extension payload or unhealthy capture as a reason
    to prevent restoring the official rc.
    """
    sequence = stages(action)
    fixed = paths(manifest, action, 0, session_nonce="0" * 32, session_data_sha256="0" * 64)
    old_fixed = base.paths(manifest, 0, 0, session_data_sha256="0" * 64, session_kind="install")
    source = base.render_observer(manifest, session_kind="install")

    def replace_once(old, new):
        nonlocal source
        if source.count(old) != 1:
            raise ValueError("fixed boot observer boundary changed")
        source = source.replace(old, new, 1)

    source = source.replace("file_index", "action")
    source = source.replace(base.REQUEST_SCHEMA, REQUEST_SCHEMA).replace(base.RESPONSE_SCHEMA, RESPONSE_SCHEMA)
    replace_once('case "$2" in 0|1|2|3) ;; *) exit 32;; esac', f'[ "$2" = {action} ] || exit 32')
    replace_once('case "$3" in 0|1|2|3|4|5|6) ;; *) exit 32;; esac',
                 'case "$3" in ' + "|".join(str(i) for i, _, _ in sequence) + ') ;; *) exit 32;; esac')
    source = source.replace(old_fixed["program"], fixed["program"])
    # The nonce is available only after strict session parsing. Defer request
    # path construction until then; no caller can supply a path component.
    old_path = f'mb_request="{fixed["session"].rsplit("/", 1)[0]}/.boundary-$mb_action_arg-$mb_boundary_index_arg.data"\n'
    replace_once(old_path, '')
    replace_once('x2dii_load_session "$mb_session" "$mb_session_sha" || exit 32\n',
        'x2dii_load_session "$mb_session" "$mb_session_sha" || exit 32\n' +
        f'mb_request="{fixed["session"].rsplit("/", 1)[0]}/.boot-{action}-$X2DII_SESSION_SESSION_NONCE-$mb_boundary_index_arg.data"\n')
    old_case = 'case "$mb_boundary_index" in\n' + "".join(
        f' {i}) [ "$mb_boundary_name" = {name} ] && [ "$mb_mount_access" = {access} ] || exit 33;;\n'
        for i, name, access in base.STAGES) + 'esac\n'
    new_case = 'case "$mb_boundary_index" in\n' + "".join(
        f' {i}) [ "$mb_boundary_name" = {name} ] && [ "$mb_mount_access" = {access} ] || exit 33;;\n'
        for i, name, access in sequence) + 'esac\n'
    replace_once(old_case, new_case)
    if action == "restore":
        replace_once('[ "$X2DII_SESSION_SCHEMA" = x2dii-session-context-v2 ] &&\n[ "$X2DII_SESSION_KIND" = install ]',
                     '[ "$X2DII_SESSION_SCHEMA" = x2dii-session-context-v1 ] &&\n[ "$X2DII_SESSION_KIND" = recovery ]')
        start = source.index(' mb_process "$X2DII_SESSION_CORE_GUI_PID"')
        end = source.index('\nx2dii_sc_private "$mb_program"', start)
        source = source[:start] + ''' # Restoring the rc does not delete loaded libraries or restart services.
 # Do not require absent GUI/capture or healthy extension payloads here.
 return 0
}
mb_runtime || exit 35
''' + source[end:]
    return source
