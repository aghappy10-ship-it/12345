"""Fixed read-only original-GUI observation after an independent rc recovery.

No reboot, service control, file removal, upload or capture command exists here.
The saved inputs are bindings, not proof of installation or physical usability.
The caller supplies its already held, completion-validating maintenance Session.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import re
import time

from . import boot_config, menu_boot_boundary, menu_boot_transport, session_context as sc
from .stage_peer_usb_access import envelope


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _need(ok, reason):
    if not ok:
        raise ValueError("stock boot readback: " + reason)


def _domain(raw, expected):
    # Kernel files can have one terminal NUL. Never strip arbitrary bytes.
    return raw in (expected.encode("ascii"), expected.encode("ascii") + b"\0",
                   expected.encode("ascii") + b"\n")


def _environment(raw):
    _need(raw and raw.endswith(b"\0"), "GUI environment is incomplete")
    for entry in raw[:-1].split(b"\0"):
        key, separator, value = entry.partition(b"=")
        _need(separator and re.fullmatch(rb"[A-Za-z_][A-Za-z0-9_]*", key) is not None,
              "GUI environment has malformed entries")
        _need(key not in (b"LD_PRELOAD", b"X2DII_MENU_EXTENSION"), "extension environment remains")


def _maps(raw):
    _need(raw and raw.endswith(b"\n"), "GUI maps are incomplete")
    original = False
    for line in raw.splitlines():
        parts = line.split(None, 5)
        _need(len(parts) >= 5 and re.fullmatch(rb"[0-9a-f]+-[0-9a-f]+", parts[0]) and
              re.fullmatch(rb"[r-][w-][x-][ps]", parts[1]) and
              re.fullmatch(rb"[0-9a-f]+", parts[2]) and
              re.fullmatch(rb"[0-9a-f]+:[0-9a-f]+", parts[3]) and parts[4].isdigit(),
              "GUI maps contain malformed rows")
        if len(parts) == 6:
            _need(b"libx2dii_menu.so" not in parts[5], "extension mapping remains")
            original |= parts[5] == b"/system/bin/camera-gui"
    _need(original, "original GUI mapping was not observed")


def observe_stock_boot(saved_manifest_raw, saved_manifest_sha256, previous_recovery_raw,
                       restore_receipt, fresh_recovery_raw, maintenance_session, *, clock=time.time):
    """Bind retained recovery inputs to two current, fully read GUI observations.

    Namespace inode numbers may legitimately repeat across a reboot. They are
    freshly queried and compared with this boot's context, never required to
    differ numerically from the prior boot. Capture health is not a prerequisite.
    """
    _need(type(saved_manifest_raw) is bytes and 0 < len(saved_manifest_raw) <= 1024 * 1024 and
          _sha(saved_manifest_raw) == saved_manifest_sha256, "saved manifest hash differs")
    manifest = json.loads(saved_manifest_raw)
    previous = menu_boot_boundary.context_for_action(manifest, previous_recovery_raw, "restore")
    fresh = menu_boot_boundary.context_for_action(manifest, fresh_recovery_raw, "restore")
    proof = deepcopy(restore_receipt)
    expected_keys = {"candidate_sha256", "session_data_sha256", "action", "backup_identity",
                     "identity", "sha256", "output_sha256"}
    _need(type(proof) is dict and set(proof) == expected_keys, "exact completed restore receipt required")
    _need(proof["candidate_sha256"] == manifest["candidate_sha256"] and
          proof["session_data_sha256"] == _sha(previous_recovery_raw) and proof["action"] == "restore" and
          proof["sha256"] == manifest["candidate"]["rc"]["before"] and
          re.fullmatch(r"[0-9a-f]{64}", proof["output_sha256"]), "restore receipt binding differs")
    size = len(boot_config.STOCK.read_bytes())
    _need(menu_boot_transport._identity(proof["backup_identity"], size) and
          menu_boot_transport._identity(proof["identity"], size), "saved rc identities differ")
    _need(fresh["boot_id"] != previous["boot_id"] and
          fresh["session_nonce"] != previous["session_nonce"], "different new boot and fresh session required")
    _need(fresh["active_slot"] == previous["active_slot"] and
          fresh["official_slot"] == previous["official_slot"], "saved recovery slot roles differ")
    _need(fresh["gui_state"] == "present" and fresh["gui_service_state"] == "running" and
          fresh["gui_exe_sha256"] == manifest["candidate"]["gui_sha256"] and
          fresh["gui_domain"] == "u:r:hbl_camera_service:s0" and
          fresh["rc_sha256"] == manifest["candidate"]["rc"]["before"],
          "fresh original GUI and official rc context required")
    base = {"status": "UNKNOWN_RETAIN_FILES", "candidate_sha256": manifest["candidate_sha256"],
        "saved_manifest_sha256": saved_manifest_sha256, "previous_boot_id": previous["boot_id"],
        "boot_id": fresh["boot_id"], "session_data_sha256": _sha(fresh_recovery_raw),
        "restore_receipt_sha256": _sha(json.dumps(proof, sort_keys=True, separators=(",", ":")).encode()),
        "menu_function_verified": False, "capture_function_verified": False,
        "all_process_mappings_verified": False, "removal_authorized": False, "installable": False,
        "queries": []}
    pid = fresh["gui_pid"]
    proc = "/proc/" + str(pid)

    def lease():
        now = clock()
        _need(type(now) in (int, float) and fresh["observed_epoch"] <= now <= fresh["observed_epoch"] + 600,
              "fresh recovery readback lease expired or future")

    def query(name, command, *, limit=1024):
        lease()
        envelope(command, "123456abcdef")
        # Session.command validates complete framing and every command's status.
        text = maintenance_session.command("stock-boot-" + name, command)
        _need(type(text) is str, "readback must retain decoded bytes")
        raw = text.encode("utf-8")
        _need(len(raw) <= limit, "bounded complete readback required")
        base["queries"].append({"name": name, "command": command, "sha256": _sha(raw), "bytes": len(raw)})
        lease()
        return text

    def expect(name, command, value):
        _need(query(name, command) == str(value) + "\n", name + " differs")

    def byte_query(name, path, *, maximum):
        text = query(name, "od -An -v -tx1 " + path, limit=maximum * 4 + 16)
        _need(re.fullmatch(r"[ \t\r\n0-9a-f]*", text) is not None, name + " hex output malformed")
        tokens = text.split()
        _need(len(tokens) <= maximum and all(re.fullmatch(r"[0-9a-f]{2}", token) for token in tokens),
              name + " byte output malformed")
        return bytes(int(token, 16) for token in tokens)

    def identity(phase):
        expect(phase + "-pid", "pidof camera-gui", pid)
        stat = query(phase + "-stat", "cat " + proc + "/stat", limit=4096)
        head, separator, tail = stat.rpartition(") ")
        fields = tail.split()
        _need(separator and head == str(pid) + " (camera-gui" and len(fields) >= 20 and
              fields[0] not in ("Z", "X", "x") and fields[19] == fresh["gui_start_ticks"],
              "GUI lifetime changed")
        expect(phase + "-exe", "readlink " + proc + "/exe", fresh["gui_exe_target"])
        expect(phase + "-exe-hash", "sha256sum " + proc + "/exe", fresh["gui_exe_sha256"] + "  " + proc + "/exe")
        expect(phase + "-namespace", "readlink " + proc + "/ns/mnt", fresh["gui_mount_namespace"])
        _need(_domain(byte_query(phase + "-domain", proc + "/attr/current", maximum=128), fresh["gui_domain"]),
              "GUI domain differs")

    try:
        environments = []
        for index in (0, 1):
            phase = str(index)
            expect(phase + "-boot", "cat /proc/sys/kernel/random/boot_id", fresh["boot_id"])
            expect(phase + "-uid", "id -u", 0)
            _need(_domain(byte_query(phase + "-observer-domain", "/proc/self/attr/current", maximum=128),
                          fresh["observer_domain"]), "observer domain differs")
            expect(phase + "-self-namespace", "readlink /proc/self/ns/mnt", fresh["mount_namespace"])
            expect(phase + "-init-namespace", "readlink /proc/1/ns/mnt", fresh["init_mount_namespace"])
            for slot in (1, 2):
                for flag in ("active", "bootable", "successful"):
                    expect(f"{phase}-slot{slot}-{flag}", f"unrd slot_{slot}.status_{flag}", fresh[f"slot{slot}_{flag}"])
            expect(phase + "-rc", "sha256sum /system/etc/init/camera-gui.rc",
                   fresh["rc_sha256"] + "  /system/etc/init/camera-gui.rc")
            expect(phase + "-service", "getprop init.svc.camera-gui", "running")
            identity(phase + "-before")
            environment = byte_query(phase + "-environment", proc + "/environ", maximum=65536)
            _environment(environment)
            environments.append(environment)
            _maps(byte_query(phase + "-maps", proc + "/maps", maximum=131072))
            identity(phase + "-after")
            expect(phase + "-boot-after", "cat /proc/sys/kernel/random/boot_id", fresh["boot_id"])
            expect(phase + "-service-after", "getprop init.svc.camera-gui", "running")
            expect(phase + "-rc-after", "sha256sum /system/etc/init/camera-gui.rc",
                   fresh["rc_sha256"] + "  /system/etc/init/camera-gui.rc")
        _need(environments[0] == environments[1], "GUI environment changed between observations")
        lease()
        base["status"] = "OBSERVED_STOCK_GUI_NOT_FUNCTION_VERIFIED"
    except (ValueError, OSError, TimeoutError) as error:
        base["reason"] = str(error)
    return base
