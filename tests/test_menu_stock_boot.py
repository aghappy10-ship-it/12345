"""Fixed post-recovery boot readback; device observations are modeled, no camera."""
import json

import pytest

from tests.test_release_lifecycle import installer
from tests.test_menu_boot_file import recovery_data
from tools import prepare_peer_install as peer, session_context as sc


def fixture_inputs(installer):
    installer.q["observer"].update(domain="u:r:hbl_camera_service:s0", exe_target="/system/bin/camera-test")
    previous = recovery_data(installer)
    current = sc.decode_session(previous)
    current.update(boot_id="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", session_nonce="d" * 32,
        recovery_nonce="d" * 32, gui_state="present", gui_service_state="running", gui_pid=234,
        gui_start_ticks="4567", gui_exe_target="/system/bin/camera-gui",
        gui_exe_sha256=installer.manifest["candidate"]["gui_sha256"],
        gui_domain="u:r:hbl_camera_service:s0", gui_mount_namespace=current["mount_namespace"],
        rc_sha256=installer.manifest["candidate"]["rc"]["before"])
    fresh = sc.encode_session(current)
    manifest = json.dumps(installer.manifest, sort_keys=True).encode()
    size = len(peer.boot.STOCK.read_bytes())
    receipt = dict(candidate_sha256=installer.manifest["candidate_sha256"],
        session_data_sha256=peer.sha(previous), action="restore", backup_identity=f"1:2:81a4:1:{size}:0:0",
        identity=f"1:3:81a4:1:{size}:0:0", sha256=installer.manifest["candidate"]["rc"]["before"],
        output_sha256="a" * 64)
    return manifest, previous, receipt, fresh, current


class DeviceBoundary:
    def __init__(self, manifest, current):
        self.manifest, self.current, self.commands = manifest, current, []

    def command(self, label, command):
        from tools.stage_peer_usb_access import envelope
        envelope(command, "123456abcdef")
        self.commands.append((label, command))
        c = self.current
        scalar = {
            "id -u": "0\n", "cat /proc/sys/kernel/random/boot_id": c["boot_id"] + "\n",
            "readlink /proc/self/ns/mnt": c["mount_namespace"] + "\n",
            "readlink /proc/1/ns/mnt": c["init_mount_namespace"] + "\n",
            "getprop init.svc.camera-gui": "running\n", "pidof camera-gui": "234\n",
            "readlink /proc/234/exe": c["gui_exe_target"] + "\n",
            "readlink /proc/234/ns/mnt": c["gui_mount_namespace"] + "\n",
            "cat /proc/234/stat": "234 (camera-gui) S " + "0 " * 18 + "4567 0\n",
            "sha256sum /proc/234/exe": c["gui_exe_sha256"] + "  /proc/234/exe\n",
            "sha256sum /system/etc/init/camera-gui.rc": c["rc_sha256"] + "  /system/etc/init/camera-gui.rc\n",
        }
        for slot in (1, 2):
            for flag in ("active", "bootable", "successful"):
                scalar[f"unrd slot_{slot}.status_{flag}"] = c[f"slot{slot}_{flag}"] + "\n"
        if command in scalar:
            return scalar[command]
        raw = {
            "/proc/self/attr/current": b"u:r:hbl_camera_service:s0\0",
            "/proc/234/attr/current": b"u:r:hbl_camera_service:s0\0",
            "/proc/234/environ": b"XDG_RUNTIME_DIR=/tmp\0XDG_CACHE_HOME=/data\0",
            "/proc/234/maps": b"1000-2000 r-xp 00000000 08:01 123 /system/bin/camera-gui\n",
        }
        prefix = "od -An -v -tx1 "
        if command.startswith(prefix) and command[len(prefix):] in raw:
            return " ".join(f"{value:02x}" for value in raw[command[len(prefix):]]) + "\n"
        raise AssertionError("unexpected or non-read-only device command: " + command)


def test_fresh_new_boot_reads_complete_gui_twice_without_backend_health_or_tmp_worker(installer):
    from tools import menu_stock_boot as stock
    raw, previous, receipt, fresh, values = fixture_inputs(installer)
    boundary = DeviceBoundary(installer.manifest, values)
    result = stock.observe_stock_boot(raw, peer.sha(raw), previous, receipt, fresh, boundary,
        clock=lambda: values["observed_epoch"])
    assert result["status"] == "OBSERVED_STOCK_GUI_NOT_FUNCTION_VERIFIED"
    assert result["boot_id"] == values["boot_id"]
    assert result["previous_boot_id"] != result["boot_id"]
    assert result["saved_manifest_sha256"] == peer.sha(raw)
    assert result["menu_function_verified"] is False and result["capture_function_verified"] is False
    assert result["removal_authorized"] is False and result["installable"] is False
    commands = [command for label, command in boundary.commands]
    assert commands.count("od -An -v -tx1 /proc/234/environ") == 2
    assert commands.count("od -An -v -tx1 /proc/234/maps") == 2
    assert not any("camera-service" in command or "/tmp/" in command for command in commands)


@pytest.mark.parametrize("fault", ("same_boot", "same_session", "wrong_manifest_hash", "wrong_restore_sha"))
def test_stale_or_misattributed_recovery_inputs_are_rejected_before_device_reads(installer, fault):
    from tools import menu_stock_boot as stock
    raw, previous, receipt, fresh, values = fixture_inputs(installer)
    expected_hash = peer.sha(raw)
    if fault == "same_boot":
        values["boot_id"] = sc.decode_session(previous)["boot_id"]
    elif fault == "same_session":
        values["session_nonce"] = values["recovery_nonce"] = sc.decode_session(previous)["session_nonce"]
    elif fault == "wrong_manifest_hash":
        expected_hash = "0" * 64
    else:
        receipt["session_data_sha256"] = "0" * 64
    fresh = sc.encode_session(values)
    boundary = DeviceBoundary(installer.manifest, values)
    with pytest.raises(ValueError):
        stock.observe_stock_boot(raw, expected_hash, previous, receipt, fresh, boundary,
            clock=lambda: values["observed_epoch"])
    assert boundary.commands == []


@pytest.mark.parametrize("fault", ("expired", "future", "env_unreadable", "maps_unreadable",
    "second_maps_unreadable", "env_incomplete", "maps_incomplete", "extension_env", "extension_map",
    "domain_embedded_nul", "changed_pid_lifetime", "changed_namespace", "rc_during_last_maps"))
def test_missing_or_changed_live_observation_stays_unknown_with_no_delete_authority(installer, fault):
    from tools import menu_stock_boot as stock
    raw, previous, receipt, fresh, values = fixture_inputs(installer)

    def hex_bytes(value):
        return " ".join(f"{item:02x}" for item in value) + "\n"

    class Changed(DeviceBoundary):
        def command(self, label, command):
            output = super().command(label, command)
            if (fault == "env_unreadable" and command.endswith("/environ") or
                fault == "maps_unreadable" and command.endswith("/maps") or
                fault == "second_maps_unreadable" and label == "stock-boot-1-maps"):
                raise ValueError("fixed query returned status 1: unreadable file")
            if command.endswith("/environ"):
                if fault == "env_incomplete":
                    return hex_bytes(b"XDG_RUNTIME_DIR=/tmp")
                if fault == "extension_env":
                    return hex_bytes(b"XDG_RUNTIME_DIR=/tmp\0LD_PRELOAD=/system/lib64/libx2dii_menu.so\0")
            if command.endswith("/maps"):
                if fault == "maps_incomplete":
                    return hex_bytes(b"1000-2000 r-xp 0 08:01 123 /system/bin/camera-gui")
                if fault == "extension_map":
                    return output + hex_bytes(b"2000-3000 r-xp 00000000 08:01 124 /system/lib64/libx2dii_menu.so\n")
                if fault == "rc_during_last_maps" and label == "stock-boot-1-maps":
                    self.current["rc_sha256"] = "f" * 64
            if fault == "domain_embedded_nul" and command.endswith("/234/attr/current"):
                return hex_bytes(b"u:r:hbl_camera\0_service:s0\0")
            if fault == "changed_pid_lifetime" and label == "stock-boot-1-after-stat":
                return output.replace("4567", "4568")
            if fault == "changed_namespace" and label == "stock-boot-1-init-namespace":
                return "mnt:[999]\n"
            return output

    boundary = Changed(installer.manifest, values)
    now = values["observed_epoch"] + (601 if fault == "expired" else -1 if fault == "future" else 0)
    result = stock.observe_stock_boot(raw, peer.sha(raw), previous, receipt, fresh, boundary, clock=lambda: now)
    assert result["status"] == "UNKNOWN_RETAIN_FILES", fault
    assert result["removal_authorized"] is False and result["installable"] is False
    if fault in ("expired", "future"):
        assert boundary.commands == []
