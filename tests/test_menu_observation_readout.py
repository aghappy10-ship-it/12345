"""Fixed menu readout through an external Session model, never camera evidence."""
from datetime import datetime, timezone
import hashlib
import json
import re

import pytest

from tests.test_release_lifecycle import installer

EPOCH = 1791198000
BOOT = "11111111-2222-4333-8444-555555555555"
NS = "mnt:[4026531840]"
GUI = "b1b643cb36176cd5a49129dd9bb2be480aa045a96ed1c35c30a779ab5af0801b"
SERVICE = "51b9e02f8bfebf388be8dfa163c8e512bee19aeb8ae37a6712727ccc6f26a52d"
SENSOR = "4d1db41c60d3eac1f989110de15335c91798bcca972e475558365d1989e49f6e"
RC = "b237e080a60bda4765c1834592d410956931e7d453f33cfa55bc01c5f5d58f1d"


class ModelSession:
    """Explicit synthetic external shell boundary; no camera or socket exists."""
    def __init__(self):
        self.calls = []
        self.processes = {
            101: ("camera-test", "111", "d018fee011426aefef1ded0bd2554ec6f4d31ea0b2529b63f9d5baddc44c42e0"),
            201: ("camera-gui", "222", GUI),
            301: ("camera-service", "333", SERVICE),
        }
        self.files = {"/system/bin/camera-gui": (GUI, 1024),
                      "/system/bin/camera-service": (SERVICE, 2048),
                      "/system/etc/imx861bqr_hb722.conf": (SENSOR, 4096),
                      "/system/etc/init/camera-gui.rc": (RC, 1388),
                      "/init": ("a" * 64, 8192), "/init.rc": ("b" * 64, 4096)}

    def command(self, label, command):
        self.calls.append((label, command))
        fixed = {"cat /proc/sys/kernel/random/boot_id": BOOT + "\n", "date -u +%s": str(EPOCH) + "\n",
                 "id -u": "0\n", "cat /proc/self/attr/current": "u:r:hbl_camera_service:s0\0",
                 "readlink /proc/self/ns/mnt": NS + "\n", "readlink /proc/1/ns/mnt": NS + "\n",
                 "readlink /proc/1/exe": "/init\n", "cat /proc/mounts": "/dev/block/mmcblk0p17 /system ext4 ro,seclabel,relatime 0 0\n"}
        if command in fixed:
            return fixed[command]
        if command.startswith("pidof "):
            return next(str(pid) + "\n" for pid, values in self.processes.items() if values[0] == command[6:])
        if command.startswith("unrd "):
            return ("0" if command == "unrd slot_1.status_active" else "1") + "\n"
        if command.startswith("getprop init.svc."):
            return "running\n"
        match = re.fullmatch(r"(cat|readlink|sha256sum) /proc/([0-9]+)/(attr/current|ns/mnt|exe|stat)", command)
        if match:
            method, pid, field = match.groups()
            name, ticks, digest = self.processes[int(pid)]
            return {"attr/current": "u:r:hbl_camera_service:s0\0", "ns/mnt": NS + "\n",
                    "stat": f"{pid} ({name}) S " + "0 " * 18 + ticks + " 0\n",
                    "exe": (digest + "  /proc/" + pid + "/exe\n") if method == "sha256sum" else "/system/bin/" + name + "\n"}[field]
        if command.startswith("sha256sum "):
            path = command[10:]
            return self.files[path][0] + "  " + path + "\n"
        if command.startswith("stat -c %s "):
            return str(self.files[command[11:]][1]) + "\n"
        if command.startswith("stat -c %n "):
            path = command[11:]
            assert path in self.files
            return path + "\n"
        if command.startswith("stat -c %f "):
            assert command[11:] in self.files
            return "81a4\n"
        if command.startswith("stat -c '%u %g %a' "):
            path = command.split(" ")[-1]
            return "0 0 " + ("755" if path in ("/system", "/system/etc", "/system/lib64", "/system/etc/init") else "644") + "\n"
        if command.startswith("ls -Zd "):
            return "u:object_r:system_file:s0 " + command[7:] + "\n"
        if command.startswith("/system/bin/toybox getfattr "):
            path = command.split()[-1]
            return "# file: " + path + "\nsecurity.selinux" + ('="u:object_r:system_file:s0"' if " -d " in command else "") + "\n\n"
        if command.startswith("[ ! -e ") and " ] && [ ! -L " in command:
            return ""
        if command.startswith("[ -d ") and " ] && [ ! -L " in command:
            return ""
        if command.startswith("[ -f ") and command.endswith(" && printf 'present\\n'"):
            return "present\n"
        if command.startswith("[ -d /proc/") and command.endswith(" && printf 'present\\n'"):
            return "present\n"
        raise AssertionError("unmodeled fixed query: " + command)


def complete_case(manifest, *, synthetic=True):
    """Supplied shape example only, including the explicitly untrusted marker.

    synthetic=False exercises the normal data adapter using modeled external
    I/O. It does not make this fabricated example a real camera observation.
    All results must remain non-authorizing even when every shape matches.
    """
    owner = {"pid": 301, "start_ticks": "333", "exe_target": "/system/bin/camera-service",
             "exe_sha256": SERVICE, "domain": "u:r:hbl_camera_service:s0", "mount_namespace": NS}
    payloads = {
        "su_identity": {"schema": "x2dii-supplied-su-identity-v1", "boot_id": BOOT,
            "test_fixture_only": synthetic, "uid": 0, "domain": "u:r:su:s0", "mount_namespace": NS},
        "official_recovery": {"schema": "x2dii-supplied-official-recovery-v1", "boot_id": BOOT,
            "test_fixture_only": synthetic, "official_slot": "slot_1", "gui_sha256": GUI,
            "rc_sha256": RC, "recovery_route": "SYNTHETIC_SHAPE_ONLY_NOT_A_CAMERA_RECOVERY"},
        "capture_route": {"schema": "x2dii-supplied-capture-route-v1", "boot_id": BOOT,
            "test_fixture_only": synthetic, "owner": owner, "identity": "SYNTHETIC_CAPTURE_ROUTE_NOT_CAMERA_EVIDENCE"},
        "init_scan_roots": {"schema": "x2dii-supplied-init-roots-v1", "boot_id": BOOT,
            "test_fixture_only": synthetic, "roots": ["/system/etc/init", "/vendor/etc/init", "/odm/etc/init"],
            "complete": True, "init_exe_path": "/init", "init_exe_sha256": "a" * 64,
            "configuration_sha256": {"/init.rc": "b" * 64}},
    }
    evidence = {}
    for kind, payload in payloads.items():
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        evidence[kind] = {"evidence_file": "build/synthetic-menu-observation/" + kind + ".json",
            "evidence_sha256": hashlib.sha256(raw.encode()).hexdigest(), "raw_utf8": raw,
            "observed_utc": datetime.fromtimestamp(EPOCH - 5, timezone.utc).isoformat()}
    return ModelSession(), evidence


def test_unknown_collection_scope_refuses_before_existing_session_is_used(installer):
    from tools.menu_observation_readout import collect_menu_observation

    class Forbidden:
        def command(self, *args):
            pytest.fail("unknown observation scope reached a device boundary")

    with pytest.raises(ValueError, match="scope"):
        collect_menu_observation(installer.manifest, Forbidden(), external_evidence={},
                                 collection_scope="install", clock=lambda: 1791198000)


def test_real_queries_populate_partial_data_without_guessing_independent_roles(installer):
    from tools.menu_observation_readout import collect_menu_observation
    model = ModelSession()
    result = collect_menu_observation(installer.manifest, model, external_evidence={},
        collection_scope="synthetic-menu-first-validation-readonly", clock=lambda: EPOCH)
    assert result["status"] == "PARTIAL_MENU_CONTEXT_NOT_QUALIFICATION"
    assert result["raw_observation"] is None and result["raw_session"] is None
    assert {"su_identity", "official_recovery", "capture_route", "init_scan_roots"} <= set(result["missing"])
    recorded = result["supplied_observation"]["queries"]
    assert any(row["record"]["field"] == "gui.process.pid" and row["value"] == 201 for row in recorded.values())
    assert not result["installable"] and not result["feature_validated"]
    assert result["deployment_constraints"]["kind"] == "EXPECTED_NEW_FILE_METADATA_NOT_EXISTING_TARGET_OBSERVATION"
    assert len(model.calls) > 15


@pytest.mark.parametrize("synthetic", (True, False))
def test_complete_context_runs_existing_assembler_and_saved_converter_without_authority(installer, synthetic):
    from tools.menu_observation_readout import collect_menu_observation
    from tools.session_context import decode_session
    model, evidence = complete_case(installer.manifest, synthetic=synthetic)
    result = collect_menu_observation(installer.manifest, model, external_evidence=evidence,
        collection_scope=("synthetic-" if synthetic else "") + "menu-first-validation-readonly", clock=lambda: EPOCH)
    assert result["missing"] == [] and result["errors"] == []
    assert result["supplied_observation"]["runtime_observation"]["capture_owner"]["process"]["pid"] == 301
    q = json.loads(result["raw_observation"])
    assert q["observer"]["pid"] == 101 and q["domain"] == "u:r:su:s0"
    assert q["metadata"]["/system/etc/init/camera-gui.rc"]["xattr_names"] == ["security.selinux"]
    assert q["metadata"]["/system/etc/X2d2MenuPage.qml"]["mode"] == "644"
    assert q["observed_utc"] == datetime.fromtimestamp(EPOCH - 5, timezone.utc).isoformat()
    assert q["synthetic"] is synthetic
    assert not result["installable"] and not result["feature_validated"]
    assert result["raw_observation_sha256"] == hashlib.sha256(result["raw_observation"]).hexdigest()
    if synthetic:
        assert result["raw_session"] is None and result["conversion_refusal"]
    else:
        assert result["raw_session_sha256"] == hashlib.sha256(result["raw_session"]).hexdigest()
        values = decode_session(result["raw_session"])
        assert values["kind"] == "menu_validation" and values["observed_epoch"] == EPOCH - 5
    assert all("raw_utf8" in source for source in result["external_sources"].values())


def test_changed_payload_layout_refuses_before_reading_even_with_recomputed_candidate_hash(installer):
    from copy import deepcopy
    from tools.menu_observation_readout import collect_menu_observation
    from tools.prepare_peer_install import canonical
    manifest = deepcopy(installer.manifest)
    manifest["candidate"]["files"][0]["target"] = "/system/lib64/other.so"
    manifest["candidate_sha256"] = hashlib.sha256(canonical(manifest["candidate"])).hexdigest()
    model = ModelSession()
    with pytest.raises(ValueError):
        collect_menu_observation(manifest, model, external_evidence={},
            collection_scope="synthetic-menu-first-validation-readonly", clock=lambda: EPOCH)
    assert model.calls == []


@pytest.mark.parametrize("fault", ("hash", "stale", "future", "naive", "fixture", "path-injection", "unknown-kind"))
def test_invalid_independent_evidence_is_not_a_reason_to_contact_camera(installer, fault):
    from tools.menu_observation_readout import collect_menu_observation
    model, evidence = complete_case(installer.manifest)
    record = evidence["capture_route"]
    if fault == "hash":
        record["evidence_sha256"] = "0" * 64
    elif fault in ("stale", "future", "naive"):
        stamp = EPOCH - 601 if fault == "stale" else EPOCH + 1
        record["observed_utc"] = datetime.fromtimestamp(stamp, timezone.utc).isoformat() if fault != "naive" else "2026-10-05T12:00:00"
    elif fault in ("fixture", "path-injection"):
        data = json.loads(record["raw_utf8"])
        if fault == "fixture":
            data["test_fixture_only"] = False
        else:
            data["owner"]["exe_target"] = "/system/bin/camera-service;id"
        record["raw_utf8"] = json.dumps(data)
        record["evidence_sha256"] = hashlib.sha256(record["raw_utf8"].encode()).hexdigest()
    else:
        evidence["free_command"] = record
    with pytest.raises(ValueError):
        collect_menu_observation(installer.manifest, model, external_evidence=evidence,
            collection_scope="synthetic-menu-first-validation-readonly", clock=lambda: EPOCH)
    assert model.calls == []


@pytest.mark.parametrize("fault", ("denied", "double-null", "embedded-null", "reused-pid", "extra-xattr", "target-exists", "init-changed"))
def test_query_failure_or_identity_drift_retains_sources_and_never_emits_session(installer, fault):
    from tools.menu_observation_readout import collect_menu_observation
    model, evidence = complete_case(installer.manifest, synthetic=False)
    original = model.command
    stats = [0]
    failure_call = []

    def command(label, command):
        output = original(label, command)
        if command == "cat /proc/201/stat":
            stats[0] += 1
            if fault == "denied":
                failure_call.append(len(model.calls))
                raise OSError("EACCES existing GUI process")
            if fault == "reused-pid" and stats[0] == 2:
                return output.replace("222", "999")
        if command == "cat /proc/201/attr/current" and fault in ("double-null", "embedded-null"):
            return output + "\0" if fault == "double-null" else "u:r:hbl_camera_\0service:s0"
        if command == "/system/bin/toybox getfattr /system/etc/init/camera-gui.rc" and fault == "extra-xattr":
            return output.replace("\n\n", "\nuser.extra\n\n")
        if command.startswith("[ ! -e /system/lib64/libx2dii_menu.so") and fault == "target-exists":
            raise ValueError("camera command returned 1")
        if command == "sha256sum /init" and fault == "init-changed":
            return "c" * 64 + "  /init\n"
        return output

    model.command = command
    result = collect_menu_observation(installer.manifest, model, external_evidence=evidence,
        collection_scope="menu-first-validation-readonly", clock=lambda: EPOCH)
    assert result["raw_session"] is None and result["raw_observation"] is None
    assert result["missing"] and result["errors"]
    assert result["queries"] and not result["installable"]
    if failure_call:
        assert len(model.calls) == failure_call[0]  # No retries after loss/denial.


def test_commands_fit_original_wire_budget_and_source_bytes_are_not_normalized_away(installer):
    from tools.menu_observation_readout import collect_menu_observation
    from tools.stage_peer_usb_access import envelope
    model, evidence = complete_case(installer.manifest)
    result = collect_menu_observation(installer.manifest, model, external_evidence=evidence,
        collection_scope="synthetic-menu-first-validation-readonly", clock=lambda: EPOCH)
    assert result["errors"] == []
    for _, command in model.calls:
        wire, _, _ = envelope(command, "123456abcdef")
        assert len(wire.encode()) < 232
        assert not any(term in command for term in ("remount", "setprop", "chcon", "mkdir", "su 0", " >", "stop ", "start "))
    domains = [q for q in result["queries"] if q["command"] == "cat /proc/201/attr/current"]
    assert len(domains) == 2 and all(q["stdout"].endswith("\0") for q in domains)
    assert all(q["stdout_sha256"] == hashlib.sha256(q["stdout"].encode()).hexdigest() for q in domains)


def test_expired_collection_keeps_original_interval_and_does_not_retry(installer):
    from tools.menu_observation_readout import collect_menu_observation
    model, evidence = complete_case(installer.manifest, synthetic=False)
    original = model.command
    now = [EPOCH]

    def command(label, command):
        output = original(label, command)
        now[0] += 601
        return output

    model.command = command
    result = collect_menu_observation(installer.manifest, model, external_evidence=evidence,
        collection_scope="menu-first-validation-readonly", clock=lambda: now[0])
    assert len(model.calls) == 1
    assert result["raw_session"] is None and result["missing"] and result["errors"]


def test_external_fact_projection_is_not_fabricated_remote_query_or_refreshed_time(installer):
    from tools.menu_observation_readout import collect_menu_observation
    model, evidence = complete_case(installer.manifest)
    result = collect_menu_observation(installer.manifest, model, external_evidence=evidence,
        collection_scope="synthetic-menu-first-validation-readonly", clock=lambda: EPOCH)
    projected = result["derived_sources"]
    official = [value for value in projected.values() if value["kind"] == "external_fact_projection"]
    assert len(official) == 2
    assert all(value["field"] == "official_slot" and value["observed_utc"] == evidence["official_recovery"]["observed_utc"] for value in official)
    assert all(value["remote_query_executed"] is False for value in official)
    actual = {row["source_id"]: row for row in result["queries"]}
    active = [value for value in projected.values() if value["kind"] == "two_observed_active_flags_projection"]
    assert len(active) == 2
    for value in active:
        assert len(value["query_ids"]) == 2
        assert {actual[key]["command"] for key in value["query_ids"]} == {"unrd slot_1.status_active", "unrd slot_2.status_active"}
        assert all(actual[key]["exit_code"] == 0 and actual[key]["stdout"] in ("0\n", "1\n") for key in value["query_ids"])


@pytest.mark.parametrize("fault", ("malformed-stat", "wrong-label-path", "changed-stat", "changed-label"))
def test_parent_metadata_requires_exact_path_shape_and_matching_samples(installer, fault):
    from tools.menu_observation_readout import collect_menu_observation
    model, evidence = complete_case(installer.manifest, synthetic=False)
    original = model.command
    counts = {}

    def command(label, command):
        output = original(label, command)
        counts[command] = counts.get(command, 0) + 1
        if command == "stat -c '%u %g %a' /system/lib64":
            if fault == "malformed-stat":
                return "root writable apparently\n"
            if fault == "changed-stat" and counts[command] == 2:
                return "0 0 777\n"
        if command == "ls -Zd /system/lib64":
            if fault == "wrong-label-path":
                return "u:object_r:system_file:s0 /system/unrelated\n"
            if fault == "changed-label" and counts[command] == 2:
                return "u:object_r:other_file:s0 /system/lib64\n"
        return output

    model.command = command
    result = collect_menu_observation(installer.manifest, model, external_evidence=evidence,
        collection_scope="menu-first-validation-readonly", clock=lambda: EPOCH)
    assert result["raw_session"] is None and result["errors"]


def test_fixed_deployment_expectations_name_the_adapter_that_defines_them(installer):
    from tools.menu_observation_readout import collect_menu_observation
    model = ModelSession()
    result = collect_menu_observation(installer.manifest, model, external_evidence={},
        collection_scope="synthetic-menu-first-validation-readonly", clock=lambda: EPOCH)
    assert result["deployment_constraints"]["source"] == "tools/menu_observation_readout.py"
    assert result["deployment_constraints"]["actual_creation_permissions_verified"] is False


def test_existing_session_packet_source_is_preserved_without_opening_or_reinterpreting_it(installer):
    from tools.menu_observation_readout import collect_menu_observation
    from tools.prepare_peer_install import ROOT
    model = ModelSession()
    original = model.command
    model.folder = ROOT / "build/synthetic-existing-session"
    model.report = {"commands": []}

    def command(label, command):
        value = original(label, command)
        model.report["commands"].append({"label": label, "command": command, "exit": 0, "text": value,
            "utc": datetime.fromtimestamp(EPOCH, timezone.utc).isoformat(), "rawSha256": "a" * 64,
            "receive": {"synthetic": True}})
        return value

    model.command = command
    result = collect_menu_observation(installer.manifest, model, external_evidence={},
        collection_scope="synthetic-menu-first-validation-readonly", clock=lambda: EPOCH)
    first = result["queries"][0]
    assert first["session_record"]["receive"] == {"synthetic": True}
    source = first["received_bytes_source"]
    assert source["evidence_file"].startswith("build/synthetic-existing-session/001-menu-")
    assert source["evidence_file"].endswith(".received.bin")
    assert source["evidence_sha256"] == "a" * 64
    assert result["raw_session"] is None


def test_official_dotted_init_filenames_are_collectable_without_relaxing_paths(installer):
    from tools.menu_observation_readout import collect_menu_observation
    model, evidence = complete_case(installer.manifest, synthetic=False)
    record = evidence["init_scan_roots"]
    payload = json.loads(record["raw_utf8"])
    # Names observed in the preserved official 1.3.16.2 system tree; model
    # content/digests below are deliberately synthetic, not official evidence.
    names = ("init.services.rc", "init.log.rc", "init.eagle2.usb.rc", "init.eagle2.rc", "init.coredump.rc")
    for name in names:
        path = "/system/etc/init/" + name
        payload["configuration_sha256"][path] = "c" * 64
        model.files[path] = ("c" * 64, 100)
    record["raw_utf8"] = json.dumps(payload)
    record["evidence_sha256"] = hashlib.sha256(record["raw_utf8"].encode()).hexdigest()
    result = collect_menu_observation(installer.manifest, model, external_evidence=evidence,
        collection_scope="menu-first-validation-readonly", clock=lambda: EPOCH)
    assert result["missing"] == [] and result["errors"] == []
    assert result["raw_session"] is not None and not result["installable"]
    for name in names:
        assert sum(command == "sha256sum /system/etc/init/" + name for _, command in model.calls) == 2


@pytest.mark.parametrize("fault", ("unhashable-root", "traversal", "control-character", "outside-root"))
def test_malformed_init_sources_refuse_cleanly_before_any_query(installer, fault):
    from tools.menu_observation_readout import collect_menu_observation
    model, evidence = complete_case(installer.manifest)
    record = evidence["init_scan_roots"]
    payload = json.loads(record["raw_utf8"])
    if fault == "unhashable-root":
        payload["roots"].append({"not": "a path"})
    else:
        path = {"traversal": "/system/etc/init/../init.rc",
                "control-character": "/system/etc/init/init.rc;id",
                "outside-root": "/data/etc/init/init.log.rc"}[fault]
        payload["configuration_sha256"][path] = "c" * 64
    record["raw_utf8"] = json.dumps(payload)
    record["evidence_sha256"] = hashlib.sha256(record["raw_utf8"].encode()).hexdigest()
    with pytest.raises(ValueError, match="init"):
        collect_menu_observation(installer.manifest, model, external_evidence=evidence,
            collection_scope="synthetic-menu-first-validation-readonly", clock=lambda: EPOCH)
    assert model.calls == []


@pytest.mark.parametrize("root", ("/system//etc", "//system", "/system/etc/init/", "/"))
def test_noncanonical_init_roots_refuse_before_any_query(installer, root):
    from tools.menu_observation_readout import collect_menu_observation
    model, evidence = complete_case(installer.manifest, synthetic=False)
    record = evidence["init_scan_roots"]
    payload = json.loads(record["raw_utf8"])
    payload["roots"].append(root)
    record["raw_utf8"] = json.dumps(payload)
    record["evidence_sha256"] = hashlib.sha256(record["raw_utf8"].encode()).hexdigest()
    with pytest.raises(ValueError, match="init roots"):
        collect_menu_observation(installer.manifest, model, external_evidence=evidence,
            collection_scope="menu-first-validation-readonly", clock=lambda: EPOCH)
    assert model.calls == []


@pytest.mark.parametrize("fault", ("wrong-label", "wrong-text", "extra-record", "missing-hash", "outside-build", "original-error"))
def test_uncertain_native_session_source_is_partial_and_original_transport_error_survives(installer, fault):
    from tools.menu_observation_readout import collect_menu_observation
    from tools.prepare_peer_install import ROOT
    model, evidence = complete_case(installer.manifest, synthetic=False)
    original = model.command
    model.folder = ROOT / ("work/outside-evidence" if fault == "outside-build" else "build/synthetic-existing-session")
    model.report = {"commands": []}

    def command(label, command):
        value = original(label, command)
        row = {"label": label, "command": command, "exit": 0, "text": value,
               "utc": datetime.fromtimestamp(EPOCH, timezone.utc).isoformat(), "rawSha256": "a" * 64,
               "receive": {"synthetic": True}}
        if fault == "wrong-label":
            row["label"] = "unrelated"
        elif fault == "wrong-text":
            row["text"] = "other value"
        elif fault in ("missing-hash", "original-error"):
            del row["rawSha256"]
        model.report["commands"].append(row)
        if fault == "extra-record":
            model.report["commands"].append(dict(row))
        if fault == "original-error":
            raise OSError("ORIGINAL transport failure")
        return value

    model.command = command
    result = collect_menu_observation(installer.manifest, model, external_evidence=evidence,
        collection_scope="menu-first-validation-readonly", clock=lambda: EPOCH)
    assert result["raw_session"] is None and result["raw_observation"] is None
    assert result["missing"] and result["errors"] and len(model.calls) == 1
    assert result["queries"][0]["session_record_error"]
    if fault == "original-error":
        assert result["errors"][0] == "ORIGINAL transport failure"
        assert result["queries"][0]["error"] == "ORIGINAL transport failure"
