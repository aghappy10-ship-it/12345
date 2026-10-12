"""Local-only, reversible X2D II camera-gui init configuration proposal.

No device connection, service control, installer, package or executable shell
script is generated. Syntax validation covers the pinned file's init subset;
it is not a substitute for the target init parser or live qualification.
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

if __package__:
    from .output_guard import guard_output, output_directory, write_output
else:
    from output_guard import guard_output, output_directory, write_output


ROOT = Path(__file__).resolve().parents[1]
STOCK = ROOT.parent / "x2d2/work/reverse/vendor/x2dii_1_3_16_2_system_root/etc/init/camera-gui.rc"
STOCK_SHA256 = "b237e080a60bda4765c1834592d410956931e7d453f33cfa55bc01c5f5d58f1d"
REFERENCE = ROOT / "reference/x2d/CodeTests/temporary_af_speed_probe/original-menu-candidate/prepare_persistent_config.py"
REFERENCE_SHA256 = "c9957bc957b6fa1721befcc3ecdfb97b296961d35c580717179ae9e369638ae0"
REFERENCE_COMMIT = "9f6c9baffeaf30ac805905f8052973f60b11acf6"
TARGET = "/system/etc/init/camera-gui.rc"
LIBRARY = "/system/lib64/libx2dii_menu.so"
HEADER = b"service camera-gui /system/bin/camera-gui -platform wayland-egl --fullscreen\n"
ADDITIONS = (b"    setenv X2DII_MENU_EXTENSION 1\n"
             b"    setenv LD_PRELOAD /system/lib64/libx2dii_menu.so\n")
MAX_BYTES = 64 * 1024
SERVICE_NAMES = ("camera-gui", "camera-touchtest", "camera-sutest-gui", "camera-lenstest")


class BootConfigError(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise BootConfigError(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class Section:
    kind: str
    name: str
    start: int
    end: int
    raw: bytes
    commands: tuple[tuple[str, ...], ...]


def parse_config(raw: bytes) -> list[Section]:
    """Conservative recognizer for this exact init file's syntax, preserving bytes."""
    require(0 < len(raw) <= MAX_BYTES and raw.endswith(b"\n"), "configuration size/final newline")
    require(b"\r" not in raw and b"\0" not in raw and b"\\" not in raw, "unsupported control/continuation syntax")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise BootConfigError("configuration must be ASCII") from error
    lines = text.splitlines(keepends=True)
    require("".join(lines) == text and not any(ord(c) < 32 and c not in "\n\t" for c in text), "invalid control byte")
    headers, bodies, services = [], [], set()
    for ix, line in enumerate(lines):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        tokens = tuple(line.split())
        require(all(re.fullmatch(r"[A-Za-z0-9_./:=+@,-]+", t) for t in tokens), "unsupported init token")
        if not line[0].isspace():
            require(tokens[0] in ("service", "on"), "unknown init section")
            if tokens[0] == "service":
                require(len(tokens) >= 3 and tokens[2].startswith("/"), "service declaration syntax")
                require(tokens[1] not in services, "duplicate service")
                services.add(tokens[1])
            else:
                require(len(tokens) == 2 and re.fullmatch(r"property:[A-Za-z0-9_.]+=[A-Za-z0-9_.]+", tokens[1]), "property trigger syntax")
            headers.append((tokens[0], tokens[1], ix))
            bodies.append([])
            continue
        require(headers, "command outside section")
        command, args = tokens[0], tokens[1:]
        if headers[-1][0] == "service":
            if command == "setenv":
                require(len(args) == 2 and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", args[0]), "setenv syntax")
                require(not any(c[0] == "setenv" and c[1] == args[0] for c in bodies[-1]), "duplicate service environment")
            elif command in ("shutdown", "class", "user", "group"):
                require(len(args) == 1, "service option arity")
            elif command in ("priority", "oom_score_adjust"):
                require(len(args) == 1 and re.fullmatch(r"-?[0-9]+", args[0]), "numeric service option")
            else:
                require(command == "disabled" and not args, "unsupported service option")
        else:
            require(command in ("start", "stop", "enable", "disable") and len(args) == 1, "unsupported action command")
        bodies[-1].append(tokens)
    require(headers, "no init sections")
    result = []
    for ix, (kind, name, start) in enumerate(headers):
        end = headers[ix + 1][2] if ix + 1 < len(headers) else len(lines)
        require(bodies[ix], "empty init section")
        result.append(Section(kind, name, start, end, "".join(lines[start:end]).encode("ascii"), tuple(bodies[ix])))
    return result


def validate_original(raw):
    sections = parse_config(raw)
    for section in sections:
        for command in section.commands:
            if command[0] == "setenv":
                require(command[1] != "LD_PRELOAD", "existing LD_PRELOAD is not composable")
                require(command[1] != "X2DII_MENU_EXTENSION", "existing extension environment")
    require(sha256(raw) == STOCK_SHA256, "unknown original configuration SHA256")
    require(tuple(s.name for s in sections if s.kind == "service") == SERVICE_NAMES, "original services mismatch")
    require(raw.count(HEADER) == 1 and sections[0].raw.startswith(HEADER), "camera-gui service header mismatch")
    return sections


def activate(original: bytes) -> bytes:
    """Produce proposed bytes only; repeated/changed input is rejected, never merged."""
    before = validate_original(original)
    candidate = original.replace(HEADER, HEADER + ADDITIONS, 1)
    after = parse_config(candidate)
    require([(s.kind, s.name) for s in before] == [(s.kind, s.name) for s in after], "section layout changed")
    for stock, proposed in zip(before, after):
        if stock.kind == "service" and stock.name == "camera-gui":
            require(proposed.raw == HEADER + ADDITIONS + stock.raw[len(HEADER):], "unexpected camera-gui modification")
        else:
            require(stock.raw == proposed.raw, "non-camera-gui section modified")
    require(candidate.count(ADDITIONS) == 1, "extension options must occur once")
    return candidate


def deactivate(candidate: bytes, original: bytes) -> bytes:
    """Require an exact original/candidate pair and recover the complete original."""
    expected = activate(original)
    parse_config(candidate)
    require(candidate == expected, "unknown candidate configuration")
    restored = candidate.replace(HEADER + ADDITIONS, HEADER, 1)
    require(restored == original and sha256(restored) == STOCK_SHA256, "restore round-trip mismatch")
    return restored


def required_live_gates():
    descriptions = {
        "slot_mount_identity": "Fresh read-only active/official rollback slot, block device, mount identity, filesystem, read-only state and rc/library hashes; never assume an old slot number.",
        "original_metadata": "Read target uid/gid/mode, file type, link count, symlinks, all xattrs and SELinux label; preserve verified values, do not invent metadata defaults.",
        "dependency_inventory_and_ownership": "Bind the complete candidate dependency/path/hash inventory and reject existing unknown or non-transaction-owned files at proposed targets; library and package identities remain unresolved here.",
        "volatile_tmpfs_runtime_paths": "Prove /tmp is the same tmpfs in the exact GUI mount namespace, root:root mode 1777 with sticky-bit protection, SELinux type tmpfs, expected capacity and reboot volatility; bind active policy identity and prove this GUI domain can exclusively create mode-0600 marker/diagnostic files with the expected hbl_camera_service_tmpfs transition. Other users may precreate leaf names, so every existing inode must cause safe refusal. Pinned CIL support and read-only mount metadata alone are not live-create or restart/reboot proof. The previous /dev proposal is rejected: observed devtmpfs/device is not tmpfs, and pinned GUI-to-device ordinary-file permissions omit create.",
        "root_selinux_loader_and_memory": "Prove the GUI root identity and actual SELinux domain/policy permit this exact library load and the native module's /proc/self/mem access; root alone is insufficient.",
        "init_parser_and_scan_roots": "Verify target init parser accepts the two service options; derive every scanned init directory so backups/staging are never parsed as configuration.",
        "independent_disable_and_rollback": "Verify a maintenance/recovery route independent of camera-gui can restore the exact official rc plus metadata and the official slot before any reboot or GUI restart.",
        "gui_exit_and_unmapped_library": "Only after final approval: stop camera-gui, inhibit concurrent restart, prove all GUI processes exited and no process maps the extension library before any library replacement/removal.",
        "storage_durability_and_rename": "Verify free space, same-filesystem staging, durable file/directory synchronization, metadata restoration, atomic rename and mount-state recovery on the exact target filesystem.",
        "complete_release_qualification": "Fresh complete UI/backend/persistence/package/rollback/capture-preservation and historical regression results bound to the exact candidate and live state; separate final user installation approval.",
    }
    return [{"id": key, "status": "PENDING", "required_evidence": value} for key, value in descriptions.items()]


def plan(original, candidate, upstream_bytes):
    require(sha256(upstream_bytes) == REFERENCE_SHA256, "reference source SHA256 mismatch")
    require(deactivate(candidate, original) == original, "unverified conversion pair")
    steps = [
        ("qualify_and_approve", "Complete every release/live gate and obtain explicit final installation approval. This plan provides no execution authority."),
        ("attest_and_lock", "Re-attest exact slot/mount, target hashes and metadata; acquire an exclusive update lock and preserve the official rollback slot. Abort on drift."),
        ("backup_official", "Create and durably verify an exclusive exact official rc backup plus metadata outside all init scan roots; an existing backup must match, never overwrite it."),
        ("stage_all_new_files", "Stage every declared candidate dependency and proposed rc without modifying active files, on the destination filesystem and outside init scan roots."),
        ("verify_all_staged_durable", "Verify all staged bytes, hashes, dependencies, ownership, modes, xattrs, SELinux labels; durably sync files and parent directories and verify readback before activation."),
        ("stop_gui_and_prove_exit", "After approval only, quiesce capture and stop camera-gui with restarts inhibited; prove process exit and absence of any mappings of the library. If proof fails, abort without replacing active files."),
        ("activate_dependencies", "Atomically place the complete verified dependency set and durably verify it. Never truncate, overwrite, remove or replace a mapped shared library."),
        ("commit_rc_last_atomic", "Recheck target/slot identity, then atomically rename the staged proposed rc over the exact original rc as the final activation switch; preserve metadata, durably sync directories and verify readback."),
        ("verify_post_commit", "Verify the complete hash/metadata set and restore the original mount state before any authorized restart. Target lifecycle checks are required and not supplied by this local proposal."),
    ]
    return {
        "schema": "x2dii-local-boot-config-plan-v1", "local_only": True, "installable": False,
        "installation_authorized": False, "device_access_performed": False, "executable_installer_generated": False,
        "scope": "Only two environment options in the official camera-gui service; no capture/service topology or diagnostic-service change.",
        "bindings": {"baseline_rc_sha256": STOCK_SHA256, "proposed_rc_sha256": sha256(candidate),
                     "generator_sha256": sha256(Path(__file__).read_bytes()), "native_library_sha256": None,
                     "package_sha256": None, "active_camera_slot": None, "live_components": None},
        "reference": {"commit": REFERENCE_COMMIT, "path": str(REFERENCE.relative_to(ROOT)).replace("\\", "/"),
                      "sha256": REFERENCE_SHA256, "executed": False,
                      "adaptation": "Retain exact-input and inverse planning only; discard old slot constants, preview-loader edits, in-place writes and generated deployment scripts."},
        "configuration": {"target": TARGET, "before_file": "camera-gui.rc.original", "after_file": "camera-gui.rc.proposed",
                          "preserved_services": list(SERVICE_NAMES[1:]), "action_sections_unchanged": True,
                          "changes": [{"service": "camera-gui", "option": "setenv", "key": "X2DII_MENU_EXTENSION", "value": "1"},
                                      {"service": "camera-gui", "option": "setenv", "key": "LD_PRELOAD", "value": LIBRARY}]},
        "path_plan": {"library_target": LIBRARY,
                      "volatile_runtime_directory": "/tmp",
                      "attempt_marker": "/tmp/x2dii-menu.attempt",
                      "diagnostic_template": "/tmp/x2dii-menu.status-<positive-pid>",
                      "volatile_runtime_qualified": False,
                      "rejected_previous_volatile_directory": {"path": "/dev", "original_gate": "dev_is_tmpfs",
                          "reason": "Observed devtmpfs with device label; pinned hbl_camera_service-to-device file permissions lack create. Volatility does not establish SELinux creation permission. Preserve this failed design; do not mark its old gate PASS."},
                      "backup_template": "/system/etc/x2dii-menu-backup/<transaction-id>/camera-gui.rc.original",
                      "staging_template": "/system/.x2dii-menu-stage/<transaction-id>/",
                      "templates_are_unverified": True, "backup_and_staging_must_be_outside_all_init_scan_roots": True,
                      "other_candidate_dependencies": "PENDING complete hash-bound candidate inventory; this plan does not assert the .so alone is sufficient"},
        "transaction": {"implemented": False, "steps": [{"id": key, "requirement": value} for key, value in steps],
                        "failure_priority": "Restore the exact official rc atomically with verified metadata and durability first; do not start the GUI with a partial candidate. Then undo only transaction-owned dependencies when unmapped; preserve official backup and restore mount state. If restoration cannot be verified, retain the independent recovery path and do not restart.",
                        "power_loss_requirement": "Durable journal and recovery must distinguish pre-commit and post-commit states; a staged file or successful rename alone is not recovery qualification.",
                        "removal": "Restore and verify the exact official rc first to disable future preloading, then stop GUI/prove exit before removing only hash-matched transaction-owned artifacts. Preserve the official slot and backup.",
                        "failure_injection": "NOT_RUN: this module tests byte conversion, not target filesystem transactions or crash recovery"},
        "required_live_gates": required_live_gates(),
        "offline_checks": {"conversion_syntax": "pinned conservative subset only", "exact_inverse": True,
                           "only_camera_gui_changed": True, "target_init_parser": "NOT_RUN"},
        "status": "LOCAL_ONLY_UNQUALIFIED",
    }


def write_proposal(original, upstream_bytes, destination):
    candidate = activate(original)
    document = plan(original, candidate, upstream_bytes)
    difference = "".join(difflib.unified_diff(original.decode("ascii").splitlines(keepends=True),
                                             candidate.decode("ascii").splitlines(keepends=True),
                                             fromfile="camera-gui.rc.original", tofile="camera-gui.rc.proposed"))
    outputs = {"camera-gui.rc.original": original, "camera-gui.rc.proposed": candidate,
               "before-after.diff": difference.encode("ascii"),
               "boot-plan.json": (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode("utf-8")}
    trusted_root = ROOT / "build"
    destination = guard_output(destination, trusted_root)
    for name, content in outputs.items():
        target = guard_output(destination / name, trusted_root)
        require(not target.exists() or (target.is_file() and target.read_bytes() == content), "refusing to overwrite changed local proposal: " + name)
    output_directory(destination, trusted_root)
    for name, content in outputs.items():
        target = destination / name
        if not target.exists():
            write_output(target, content, trusted_root)
        else:
            guard_output(target, trusted_root)
        require(target.read_bytes() == content, "local proposal readback mismatch")
    return document


def read_bounded(path):
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    require(len(data) <= MAX_BYTES, "input exceeds size limit")
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--original", type=Path, default=STOCK)
    parser.add_argument("--output", type=Path, default=ROOT / "build/boot-config")
    args = parser.parse_args()
    document = write_proposal(read_bounded(args.original), read_bounded(REFERENCE), args.output)
    print(json.dumps({"status": document["status"], "output": str(args.output.resolve()),
                      "installable": False, "device_access_performed": False,
                      "proposed_rc_sha256": document["bindings"]["proposed_rc_sha256"]}))


if __name__ == "__main__":
    main()
