"""Public recovery readout seam with synthetic external I/O, never a camera."""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json

import pytest

from tests.test_release_lifecycle import installer
from tests.test_menu_observation_readout import ModelSession, complete_case, EPOCH
from tools import boot_config, prepare_peer_install as peer
from tools.menu_recovery_readout import collect_menu_recovery_observation
from tools.session_context import decode_session


class RecoverySession(ModelSession):
    """The only mock is the external shell/retained Session boundary."""
    def __init__(self, manifest):
        super().__init__()
        self.folder = peer.ROOT / "build/synthetic-recovery-session"
        self.report = {"commands": []}
        self.backup = "/system/etc/.x2dii-boot-" + manifest["candidate_sha256"][:24] + ".original"
        size = len(boot_config.STOCK.read_bytes())
        activated_size = len(boot_config.activate(boot_config.STOCK.read_bytes()))
        self.backup_identity = f"1:900:81a4:1:{size}:0:0"
        self.identities = {self.backup: self.backup_identity, boot_config.TARGET: f"1:901:81a4:1:{activated_size}:0:0"}
        self.files[self.backup] = (manifest["candidate"]["rc"]["before"], size)
        self.files[boot_config.TARGET] = (manifest["candidate"]["rc"]["after"], activated_size)
        for f in manifest["candidate"]["files"]:
            self.files[f["target"]] = (f["sha256"], f["bytes"])

    def command(self, label, command):
        value = self.answer(label, command)
        self.report["commands"].append({"label": label, "command": command, "exit": 0, "text": value,
            "utc": datetime.fromtimestamp(EPOCH, timezone.utc).isoformat(), "rawSha256": "a" * 64,
            "receive": {"synthetic": True}})
        return value

    def answer(self, label, command):
        if command == "getprop init.svc.camera-gui" and 201 not in self.processes:
            self.calls.append((label, command))
            return "stopped\n"
        if command.startswith("stat -c '%d:%i:%f:%h:%s:%u:%g' "):
            self.calls.append((label, command))
            return self.identities[command.split()[-1]] + "\n"
        if command.startswith("[ -f ") and " ] && [ ! -L " in command:
            self.calls.append((label, command))
            assert command.split()[2] in self.files
            return ""
        if command.startswith("ls -a "):
            self.calls.append((label, command))
            parent = command[6:]
            return ".\n..\n" + "".join(p.rsplit("/", 1)[1] + "\n" for p in sorted(self.files)
                if p.rsplit("/", 1)[0] == parent)
        if command == "ps -A -o PID,NAME":
            self.calls.append((label, command))
            return "PID NAME\n" + "".join(f"{pid} {v[0]}\n" for pid, v in self.processes.items())
        return super().command(label, command)


def case(installer, synthetic=False):
    from tools.delivery_content import ROLE_FORMAT_VERSION
    manifest = deepcopy(installer.manifest)
    # Readout needs the fixed role format, not a falsely qualified delivery.
    manifest["delivery_identity"] = {"format_version": ROLE_FORMAT_VERSION}
    raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    model = RecoverySession(manifest)
    _, evidence = complete_case(manifest, synthetic=synthetic)
    evidence.pop("capture_route")
    return manifest, raw, model, evidence


def collect(raw, model, evidence, *, synthetic=False):
    return collect_menu_recovery_observation(raw, hashlib.sha256(raw).hexdigest(), model,
        backup_identity=model.backup_identity, external_evidence=evidence,
        collection_scope=("synthetic-" if synthetic else "") + "menu-recovery-readonly", clock=lambda: EPOCH)


def test_current_recovery_reads_preserve_sources_and_produce_only_non_authorizing_context(installer):
    manifest, raw, model, evidence = case(installer)
    result = collect(raw, model, evidence)
    assert result["errors"] == [] and result["missing"] == []
    assert result["raw_session"] is not None, result
    values = decode_session(result["raw_session"])
    q = json.loads(result["raw_observation"])
    assert values["kind"] == "recovery" and values["gui_state"] == "present"
    assert q["backup_identity"] == model.backup_identity
    assert q["rc_sha256"] == manifest["candidate"]["rc"]["after"]
    assert all(q["payload_presence"].values())
    assert all(row["session_record"]["exit"] == 0 and row["received_bytes_source"] for row in result["queries"])
    assert all(source["raw_utf8"] for source in result["external_sources"].values())
    assert result["installable"] is False and result["feature_validated"] is False


def test_observed_absent_payloads_and_gui_need_no_fabricated_labels_or_processes(installer):
    manifest, raw, model, evidence = case(installer)
    for f in manifest["candidate"]["files"]:
        del model.files[f["target"]]
    del model.processes[201]
    result = collect(raw, model, evidence)
    assert result["errors"] == [] and result["missing"] == []
    values = decode_session(result["raw_session"])
    q = json.loads(result["raw_observation"])
    assert q["gui"] == {"state": "absent", "service_state": "stopped"}
    assert values["gui_pid"] == "-" and values["gui_state"] == "absent"
    for f, wire in zip(manifest["candidate"]["files"], ("library", "bootstrap", "model", "page")):
        assert q["payload_presence"][f["target"]] is False
        assert q["metadata"][f["target"]] == {"state": "absent", "label": None}
        assert values[wire + "_label"] == "-" and values["present_" + wire] == "0"


@pytest.mark.parametrize("command", ("ls -a /system/etc", "ps -A -o PID,NAME"))
def test_truncated_success_output_never_becomes_absent_observation(installer, command):
    manifest, raw, model, evidence = case(installer)
    original = model.answer
    def truncated(label, current):
        value = original(label, current)
        return value.removesuffix("\n") if current == command else value
    model.answer = truncated
    result = collect(raw, model, evidence)
    assert result["raw_session"] is None and result["raw_observation"] is None
    assert result["errors"] and result["queries"]


def test_current_rc_hash_and_inode_byte_length_must_describe_same_known_file(installer):
    manifest, raw, model, evidence = case(installer)
    parts = model.identities[boot_config.TARGET].split(":")
    parts[4] = "1"
    model.identities[boot_config.TARGET] = ":".join(parts)
    result = collect(raw, model, evidence)
    assert result["raw_session"] is None and result["errors"]


@pytest.mark.parametrize("fault", ("backup-inode", "backup-hash", "unknown-rc", "rc-label", "backup-label",
    "directory-query-error", "process-query-error", "payload-label-error", "native-exit", "native-record-missing",
    "no-retained-records", "boot-drift", "backup-drift", "gui-lifetime-drift", "process-hash-wrong-path",
    "running-without-gui", "namespace-mismatch", "init-input-drift", "observer-domain",
    "observer-long-domain", "observer-long-ticks", "gui-long-domain"))
def test_current_read_failures_and_drift_retain_raw_sources_without_a_recovery_session(installer, fault):
    manifest, raw, model, evidence = case(installer)
    original = model.answer
    if fault == "backup-inode":
        model.identities[model.backup] = model.backup_identity.replace(":900:", ":999:")
    elif fault == "backup-hash":
        model.files[model.backup] = ("9" * 64, model.files[model.backup][1])
    elif fault == "unknown-rc":
        model.files[boot_config.TARGET] = ("9" * 64, model.files[boot_config.TARGET][1])
    elif fault == "no-retained-records":
        del model.report
        model.command = original

    def altered(label, command):
        if fault == "directory-query-error" and command == "ls -a /system/etc":
            raise RuntimeError("permission denied; absence unknown")
        if fault == "process-query-error" and command == "ps -A -o PID,NAME":
            raise RuntimeError("ps unavailable; GUI unknown")
        if fault == "payload-label-error" and command == "ls -Zd /system/etc/X2d2MenuPage.qml":
            raise RuntimeError("payload label unreadable")
        value = original(label, command)
        if fault in ("rc-label", "backup-label") and command == "ls -Zd " + (boot_config.TARGET if fault == "rc-label" else model.backup):
            return value.replace("system_file", "different_type")
        if fault == "boot-drift" and "-after-" in label and command == "cat /proc/sys/kernel/random/boot_id":
            return "99999999-2222-4333-8444-555555555555\n"
        if fault == "backup-drift" and "-after-" in label and command.endswith(model.backup) and command.startswith("stat -c '%d:"):
            return value.replace(":900:", ":999:")
        if fault == "gui-lifetime-drift" and "-after-" in label and command == "cat /proc/201/stat":
            return value.replace(" 222 ", " 444 ")
        if fault == "process-hash-wrong-path" and command == "sha256sum /proc/201/exe":
            return value.replace("/proc/201/exe", "/proc/202/exe")
        if fault == "running-without-gui" and command == "ps -A -o PID,NAME":
            return value.replace("201 camera-gui\n", "")
        if fault == "namespace-mismatch" and command == "readlink /proc/1/ns/mnt":
            return "mnt:[999]\n"
        if fault == "init-input-drift" and command == "sha256sum /init.rc":
            return "9" * 64 + "  /init.rc\n"
        if fault == "observer-domain" and command == "cat /proc/101/attr/current":
            return "u:r:su:s0\0"
        if fault in ("observer-long-domain", "gui-long-domain") and command == (
            "cat /proc/101/attr/current" if fault.startswith("observer") else "cat /proc/201/attr/current"):
            return "u:r:" + "a" * 97 + ":s0\0"
        if fault == "observer-long-ticks" and command == "cat /proc/101/stat":
            return value.replace(" 111 ", " " + "1" * 21 + " ")
        return value
    model.answer = altered
    if fault in ("native-exit", "native-record-missing"):
        native = model.command
        def bad_record(label, command):
            value = native(label, command)
            if fault == "native-exit":
                model.report["commands"][-1]["exit"] = 23
            else:
                model.report["commands"].pop()
            return value
        model.command = bad_record
    result = collect(raw, model, evidence)
    assert result["raw_session"] is None and result["raw_observation"] is None
    assert result["errors"] and result["queries"] and result["installable"] is False


@pytest.mark.parametrize("fault", ("scope", "saved-hash", "saved-bytes", "backup-identity", "candidate-path", "future-source"))
def test_invalid_saved_inputs_refuse_before_external_io(installer, fault):
    manifest, raw, model, evidence = case(installer)
    kwargs = dict(backup_identity=model.backup_identity, external_evidence=evidence,
                  collection_scope="menu-recovery-readonly", clock=lambda: EPOCH)
    digest = hashlib.sha256(raw).hexdigest()
    if fault == "scope":
        kwargs["collection_scope"] = "restore-now"
    elif fault == "saved-hash":
        digest = "0" * 64
    elif fault == "saved-bytes":
        raw = raw.decode()
    elif fault == "backup-identity":
        kwargs["backup_identity"] = "unobserved"
    elif fault == "candidate-path":
        manifest["candidate"]["files"][0]["target"] = "/system/lib64/other.so"
        manifest["candidate_sha256"] = peer.sha(peer.canonical(manifest["candidate"]))
        raw = peer.canonical(manifest)
        digest = peer.sha(raw)
    elif fault == "future-source":
        evidence["su_identity"]["observed_utc"] = datetime.fromtimestamp(EPOCH + 1, timezone.utc).isoformat()
    with pytest.raises(ValueError):
        collect_menu_recovery_observation(raw, digest, model, **kwargs)
    assert model.calls == []


def test_synthetic_or_missing_external_evidence_cannot_yield_usable_session(installer):
    manifest, raw, model, evidence = case(installer, synthetic=True)
    result = collect(raw, model, evidence, synthetic=True)
    assert result["errors"] == [] and result["raw_observation"] is not None
    assert result["raw_session"] is None and result["conversion_refusal"]
    manifest, raw, model, evidence = case(installer)
    del evidence["su_identity"]
    result = collect(raw, model, evidence)
    assert result["missing"] == ["su_identity"] and result["raw_session"] is None


def test_known_stock_rc_and_corrupt_present_payload_do_not_require_capture_health(installer):
    manifest, raw, model, evidence = case(installer)
    original = boot_config.STOCK.read_bytes()
    model.files[boot_config.TARGET] = (manifest["candidate"]["rc"]["before"], len(original))
    model.identities[boot_config.TARGET] = f"1:901:81a4:1:{len(original)}:0:0"
    model.files[manifest["candidate"]["files"][0]["target"]] = ("f" * 64, 1)
    del model.processes[301]
    result = collect(raw, model, evidence)
    assert result["errors"] == [] and result["raw_session"] is not None
    q = json.loads(result["raw_observation"])
    assert q["runtime_observation"]["service"]["state"] == "unknown"
    assert q["runtime_observation"]["capture_owner"]["state"] == "unknown"
    assert q["rc_sha256"] == manifest["candidate"]["rc"]["before"]


def test_collection_expiry_cannot_issue_a_session_from_previously_fresh_sources(installer):
    manifest, raw, model, evidence = case(installer)
    now = [EPOCH]
    original = model.command
    def slow(label, command):
        value = original(label, command)
        now[0] = EPOCH + 601
        return value
    model.command = slow
    result = collect_menu_recovery_observation(raw, peer.sha(raw), model, backup_identity=model.backup_identity,
        external_evidence=evidence, collection_scope="menu-recovery-readonly", clock=lambda: now[0])
    assert result["raw_session"] is None and result["raw_observation"] is None
    assert "expired" in result["errors"][0]
    assert result["queries"][0]["session_record"]["exit"] == 0


@pytest.mark.parametrize("phase", ("before", "after"))
@pytest.mark.parametrize("suffix", ("\0\n", "\n\n", "\r\n", "\n\0", "\0\0"),
                         ids=("nul-lf", "lf-lf", "crlf", "lf-nul", "nul-nul"))
def test_recovery_domain_rejects_mixed_or_repeated_raw_terminators(installer, phase, suffix):
    manifest, raw, model, evidence = case(installer)
    original = model.answer
    actual = "u:r:hbl_camera_service:s0" + suffix
    def malformed(label, command):
        if command == "cat /proc/self/attr/current" and "-" + phase + "-" in label:
            return actual
        return original(label, command)
    model.answer = malformed
    result = collect(raw, model, evidence)
    assert result["raw_session"] is None and result["raw_observation"] is None
    assert result["errors"] and "domain" in result["errors"][0]
    retained = [row for row in result["queries"] if row["command"] == "cat /proc/self/attr/current"
                and "-" + phase + "-" in row["source_id"]]
    assert len(retained) == 1
    assert retained[0]["stdout"] == actual and retained[0]["session_record"]["text"] == actual


@pytest.mark.parametrize("suffix", ("", "\0", "\n"), ids=("none", "nul", "lf"))
def test_recovery_domain_accepts_exact_raw_value_or_one_legal_terminator(installer, suffix):
    manifest, raw, model, evidence = case(installer)
    original = model.answer
    actual = "u:r:hbl_camera_service:s0" + suffix
    model.answer = lambda label, command: actual if command == "cat /proc/self/attr/current" else original(label, command)
    result = collect(raw, model, evidence)
    assert result["errors"] == [] and result["raw_session"] is not None
    assert decode_session(result["raw_session"])["observer_domain"] == "u:r:hbl_camera_service:s0"
    retained = [row for row in result["queries"] if row["command"] == "cat /proc/self/attr/current"]
    assert len(retained) == 2 and all(row["stdout"] == actual for row in retained)


@pytest.mark.parametrize("field", ("library", "bootstrap", "model", "page"))
def test_absent_label_wire_sentinel_is_bounded_in_python_and_real_shell_parser(tmp_path, field):
    from tests.test_session_context import recovery, shell_read, changed_bytes, INSTALL
    from tools.session_context import encode_session, SessionContextError
    values = {**recovery(), field + "_label": "-", "present_" + field: "0"}
    raw = encode_session(values)
    assert decode_session(raw)[field + "_label"] == "-"
    run, _ = shell_read(tmp_path, raw)
    assert run.returncode == 0, run.stderr
    changed = changed_bytes(raw, {"present_" + field: "1"})
    with pytest.raises(SessionContextError):
        decode_session(changed)
    run, _ = shell_read(tmp_path, changed)
    assert run.returncode == 42
    with pytest.raises(SessionContextError):
        encode_session({**INSTALL, field + "_label": "-"})
