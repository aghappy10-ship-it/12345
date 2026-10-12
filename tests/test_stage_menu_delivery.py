"""Fixed staging contract tests. Inert bytes only; no camera or transport calls."""
from copy import deepcopy
from dataclasses import replace
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import importlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

import pytest

from tests.test_delivery_plan import fixture


RENDERER = b"# SYNTHETIC renderer source; never executable camera evidence\n"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def make_plan(**overrides):
    stage = importlib.import_module("tools.stage_menu_delivery")
    members, candidate, scripts = fixture()
    options = dict(members=members, candidate=candidate,
                   candidate_sha256=sha(json.dumps(candidate, sort_keys=True,
                                                   separators=(",", ":")).encode()),
                   script_hashes=scripts, renderer_source=RENDERER,
                   renderer_source_sha256=sha(RENDERER))
    options.update(overrides)
    return stage.plan_staging(**options)


def session_fixture(plan):
    """Invented observations only; this never qualifies host-source publication."""
    from tests.test_runtime_observation import synthetic_observation
    from tests.test_session_context import INSTALL
    from tools import prepare_peer_install as peer
    _, candidate, _ = fixture()
    manifest = {"candidate": candidate, "candidate_sha256": plan.candidate_sha256}
    q = {"candidate_sha256": plan.candidate_sha256, "synthetic": True,
         "observed_utc": datetime.fromtimestamp(INSTALL["observed_epoch"], timezone.utc).isoformat(),
         **{key: INSTALL[key] for key in ("boot_id", "session_nonce", "active_slot", "official_slot",
                                         "mount_namespace", "init_mount_namespace")},
         "system_mount": {key: INSTALL["mount_" + key] for key in ("device", "filesystem", "options")},
         "observer": {key: INSTALL["observer_" + key] for key in ("pid", "start_ticks", "exe_target",
                                                                "exe_sha256", "domain", "mount_namespace")},
         "slot_readback": {f"slot_{slot}.status_{flag}": INSTALL[f"slot{slot}_{flag}"]
                           for slot in (1, 2) for flag in ("active", "bootable", "successful")},
         "metadata": {path: {"label": INSTALL[field]} for path, field in peer.LABEL_FIELDS.items()}}
    q["runtime_observation"] = synthetic_observation(q, candidate["gui_sha256"])
    return manifest, q


def test_session_staging_is_the_renderers_exact_separate_data_not_a_ninth_member():
    from tools import prepare_peer_install as peer, session_context as sc, stage_menu_delivery as stage
    plan = make_plan()
    before = deepcopy(plan)
    manifest, q = session_fixture(plan)
    session = stage.plan_session_staging(plan, manifest, q)
    assert session.data == peer.session_data(manifest, q)
    assert session.data_sha256 == sha(session.data)
    assert session.path == plan.stage_root + "/session-context.data"
    assert session.plan_sha256 == plan.plan_sha256
    assert sc.decode_session(session.data)["session_nonce"] == q["session_nonce"]
    assert sc.decode_session(session.data)["boot_id"] == q["boot_id"]
    assert sc.decode_session(session.data)["observed_epoch"] == 1791040000
    assert plan == before == make_plan() and "session-context.data" not in plan.member_names
    assert session.steps[-1].label == "verify-session-context.data"
    assert not session.installable
    with pytest.raises(ValueError, match="synthetic qualification"):
        stage.qualified_host_source(members=fixture()[0], manifest=manifest,
                                    qualification=q, window_authorization={})


def test_session_steps_append_to_original_plan_and_reject_another_boot_or_namespace():
    from tools import stage_menu_delivery as stage
    plan = make_plan()
    manifest, q = session_fixture(plan)
    session = stage.plan_session_staging(plan, manifest, q)
    context = dict(session.context)
    before = stage.execution_steps(plan, context)
    combined = stage.execution_steps(plan, context, session=session)
    assert tuple(step.label for step in combined[:len(before)]) == tuple(step.label for step in before)
    assert all(step.command.endswith("(" + original.command + ")") and
               step.expected_stdout == original.expected_stdout
               for step, original in zip(combined, plan.steps))
    assert tuple(step.label for step in combined[len(before):]) == tuple(step.label for step in session.steps)
    for key in ("boot_id", "mount_namespace", "init_mount_namespace"):
        changed = dict(context)
        changed[key] = "00000000-0000-0000-0000-000000000000" if key == "boot_id" else "mnt:[9]"
        with pytest.raises(ValueError, match="session.*context|namespace identity"):
            stage.execution_steps(plan, changed, session=session)


def test_new_nonce_changes_execution_and_reply_binding_but_not_content_identity():
    from tools import stage_menu_delivery as stage, peer_usb_access as usb
    plan = make_plan()
    manifest, q = session_fixture(plan)
    original = stage.plan_session_staging(plan, manifest, q)
    q["session_nonce"] = "c" * 32
    changed = stage.plan_session_staging(plan, manifest, q)
    assert original.session_nonce == "b" * 32 and b"session_nonce=" + b"b" * 32 in original.data
    assert changed.data_sha256 != original.data_sha256
    assert changed.binding_sha256 != original.binding_sha256
    assert changed.path == original.path
    assert changed.plan_sha256 == original.plan_sha256 == plan.plan_sha256
    old_source = stage.review_host_source(plan, usb.REFERENCE.read_bytes(), session=original)
    new_source = stage.review_host_source(plan, usb.REFERENCE.read_bytes(), session=changed)
    assert "X2DII_STAGE_" + changed.binding_sha256[:24] in new_source
    assert "X2DII_STAGE_" + original.binding_sha256[:24] not in new_source
    assert old_source != new_source
    assert make_plan() == plan


@pytest.mark.parametrize("damage", ("qualification-candidate", "manifest-candidate", "candidate-content", "timezone"))
def test_session_plan_cannot_relabel_other_candidates_or_unzoned_observations(damage):
    from tools import stage_menu_delivery as stage
    plan = make_plan()
    manifest, q = session_fixture(plan)
    if damage == "qualification-candidate":
        q["candidate_sha256"] = "f" * 64
    elif damage == "manifest-candidate":
        manifest["candidate_sha256"] = "f" * 64
    elif damage == "candidate-content":
        manifest["candidate"]["gui_sha256"] = "f" * 64
    else:
        q["observed_utc"] = datetime.fromisoformat(q["observed_utc"]).replace(tzinfo=None).isoformat()
    with pytest.raises(ValueError, match="candidate|timezone"):
        stage.plan_session_staging(plan, manifest, q)


@pytest.mark.parametrize("damage", (None, "missing-data-hash", "wrong-data-hash", "nonce", "observed_utc"))
def test_session_staging_window_binds_exact_data_and_original_lease(damage):
    from tools import stage_menu_delivery as stage
    plan = make_plan()
    manifest, q = session_fixture(plan)
    session = stage.plan_session_staging(plan, manifest, q)
    now = datetime.fromisoformat(q["observed_utc"])
    window = {"approved": True, "purpose": "temporary_adb_fixed_menu_staging",
              "candidate_sha256": plan.candidate_sha256, "plan_sha256": plan.plan_sha256,
              "boot_id": q["boot_id"], "session_nonce": q["session_nonce"],
              "session_data_sha256": session.data_sha256,
              "launch_session_sha256": "a" * 64, "launch_started_utc": now.isoformat()}
    if damage is None:
        assert stage.validate_staging_window(window, plan, q, now=now, session=session) == now + timedelta(seconds=60)
        # The integer-epoch expiry used by the original data consumer must not
        # gain the fractional second in the observation timestamp.
        q["observed_utc"] = (now + timedelta(microseconds=800000)).isoformat()
        later_session = stage.plan_session_staging(plan, manifest, q)
        near_expiry = now + timedelta(seconds=570)
        window["launch_started_utc"] = near_expiry.isoformat()
        assert stage.validate_staging_window(window, plan, q, now=near_expiry,
                                             session=later_session) == now + timedelta(seconds=600)
        return
    if damage == "missing-data-hash":
        del window["session_data_sha256"]
    elif damage == "wrong-data-hash":
        window["session_data_sha256"] = "f" * 64
    elif damage == "nonce":
        q["session_nonce"] = window["session_nonce"] = "c" * 32
    else:
        q["observed_utc"] = (now + timedelta(seconds=1)).isoformat()
    with pytest.raises(ValueError, match="session"):
        stage.validate_staging_window(window, plan, q, now=now, session=session)


@pytest.mark.parametrize("fault", (None, "existing", "expired", "future", "date-status", "boot-status"))
def test_session_steps_execute_and_original_parser_accepts_exact_data_in_local_shell(tmp_path, fault):
    """Real files/hash/codec with modeled Android metadata, boot, namespace and clock."""
    from tools import stage_menu_delivery as stage, session_context as sc
    plan = make_plan()
    manifest, q = session_fixture(plan)
    session = stage.plan_session_staging(plan, manifest, q)
    blackbox = tmp_path / "blackbox"
    destination = blackbox / "x2dii-menu-stage" / plan.candidate_sha256[:24]
    destination.mkdir(parents=True)
    data_path = destination / "session-context.data"
    if fault == "existing":
        data_path.write_bytes(b"existing data must not be replaced")
    shell = "C:/Program Files/Git/bin/sh.exe"
    mapped = subprocess.run([shell, "-c", 'cygpath -u "$1"', "fixture", str(blackbox)],
                            capture_output=True, text=True, check=True).stdout.strip()
    epoch = session.observed_epoch + (601 if fault == "expired" else -1 if fault == "future" else 0)
    model = r'''
sha256sum() { value=$(command sha256sum "$@") || return $?; printf '%s\n' "$value" | sed 's/ \*/  /'; }
stat() {
 case "$2" in
  '%u %g %a') printf '0 0 700\n';;
  '%u %g %a %h') printf '0 0 600 %s\n' "$(command stat -c %h "$3")";;
  '%u:%g:%a') if [ -d "$3" ]; then printf '0:0:700\n'; else printf '0:0:600\n'; fi;;
  *) command stat "$@";;
 esac
}
''' + f'''id() {{ printf '0\\n'; }}
date() {{ printf '%s\\n' '{epoch}'; return {1 if fault == 'date-status' else 0}; }}
cat() {{ case "$1" in /proc/self/attr/current) printf 'u:r:su:s0\\n';; /proc/sys/kernel/random/boot_id) printf '%s\\n' '{q['boot_id']}'; return {1 if fault == 'boot-status' else 0};; *) command cat "$@";; esac; }}
readlink() {{ case "$1" in /proc/self/ns/mnt|/proc/1/ns/mnt) printf '%s\\n' '{q['mount_namespace']}';; *) command readlink "$@";; esac; }}
'''
    steps = stage.execution_steps(plan, dict(session.context), session=session)[len(plan.steps):]
    for step in steps:
        command = step.command.replace("/blackbox", shlex.quote(mapped)).replace(
            "export PATH=/system/bin:/system/xbin:/sbin;", "export PATH=/usr/bin:/bin;")
        result = subprocess.run([shell, "-s"], input=model + command, capture_output=True,
                                text=True, encoding="utf-8", timeout=10)
        if fault is not None:
            assert step == steps[0] and result.returncode != 0
            assert list(destination.iterdir()) == ([data_path] if fault == "existing" else [])
            if fault == "existing":
                assert data_path.read_bytes() == b"existing data must not be replaced"
            return
        assert result.returncode == 0 and result.stderr == "", (step.label, result.stderr)
        assert result.stdout.replace(mapped, "/blackbox") == step.expected_stdout
    assert data_path.read_bytes() == session.data and list(destination.iterdir()) == [data_path]
    actual_path = session.path.replace("/blackbox", mapped)
    # Exercise the same parser used at the first two arguments of all three
    # installers, without ever invoking an installer or loading camera code.
    parser = model + sc.shell_parser() + f'\nx2dii_load_session {shlex.quote(actual_path)} {session.data_sha256} || exit 42\n'
    parser += 'printf "%s|%s|%s|%s|%s\\n" "$X2DII_SESSION_SCHEMA" "$X2DII_SESSION_KIND" "$X2DII_SESSION_BOOT_ID" "$X2DII_SESSION_SESSION_NONCE" "$X2DII_SESSION_OBSERVED_EPOCH"\n'
    checked = subprocess.run([shell, "-s"], input=parser, capture_output=True,
                             text=True, encoding="utf-8", timeout=10)
    assert checked.returncode == 0 and checked.stderr == "", checked.stderr
    assert checked.stdout == f"x2dii-session-context-v2|install|{q['boot_id']}|{q['session_nonce']}|{session.observed_epoch}\n"


def test_fixed_delivery_connects_to_installers_exact_source_directory_without_authority():
    plan = make_plan()
    assert plan.stage_root == "/blackbox/x2dii-menu-stage/" + plan.candidate_sha256[:24]
    assert plan.member_names == (
        "libx2dii_menu.so", "X2d2MenuBootstrap.qml", "X2d2MenuModel.qml",
        "X2d2MenuPage.qml", "camera-gui.rc.proposed", "install-files.sh",
        "activate-boot.sh", "restore-boot.sh",
    )
    assert plan.installable is False
    assert plan.transport_invocation_available is False
    assert "session-context.data" not in plan.member_names
    assert plan.steps[0].label == "create-private-stage"
    assert plan.steps[-1].label == "verify-all-members"


def test_failed_return_stops_the_sequence_before_any_later_step_can_be_offered():
    stage = importlib.import_module("tools.stage_menu_delivery")
    review = stage.StagingReadback(make_plan())
    step = review.next_step
    with pytest.raises(ValueError, match="command failed"):
        review.accept(index=0, command=step.command, exit_code=1, stdout="",
                      completion_validated=True)
    assert review.next_step is None
    assert review.all_results_validated is False
    assert review.failed is True


def test_generated_steps_stage_exact_bytes_and_reject_reuse_in_a_local_shell(tmp_path):
    """Real shell/base64/files; root metadata is modeled, never camera proof."""
    stage = importlib.import_module("tools.stage_menu_delivery")
    members, candidate, scripts = fixture()
    raw = bytes(range(256)) * 19 + b"\x00\r\nSYNTHETIC END"
    members["libx2dii_menu.so"] = raw
    candidate["files"][0].update(sha256=sha(raw), bytes=len(raw))
    plan = make_plan(members=members, candidate=candidate, script_hashes=scripts,
                     candidate_sha256=sha(json.dumps(candidate, sort_keys=True,
                                                     separators=(",", ":")).encode()))
    blackbox = tmp_path / "blackbox"
    blackbox.mkdir()
    mapped = blackbox.as_posix()
    shell = Path("C:/Program Files/Git/bin/sh.exe")
    assert shell.is_file(), "existing local shell required; do not silently skip staging execution"
    metadata_model = """# Model Android metadata and SHA display, not file contents or hashing.
sha256sum() {
 value=$(command sha256sum "$@") || return $?
 printf '%s\\n' "$value" | sed 's/ \\*/  /'
}
stat() {
 case "$2" in
  '%u %g %a') printf '0 0 700\\n';;
  '%u %g %a %h') printf '0 0 600 %s\\n' "$(command stat -c %h "$3")";;
  *) command stat "$@";;
 esac
}
"""

    def execute(step):
        # Only the OS boundary is relocated; the actual generated commands run.
        command = step.command.replace("/blackbox", shlex.quote(mapped)).replace(
            "export PATH=/system/bin:/system/xbin:/sbin;", "export PATH=/usr/bin:/bin;")
        return subprocess.run([str(shell), "-s"], input=metadata_model + command,
                              capture_output=True, text=True, encoding="utf-8", timeout=10)

    review = stage.StagingReadback(plan)
    for index, step in enumerate(plan.steps):
        result = execute(step)
        assert result.returncode == 0, (step.label, result.stderr)
        assert result.stderr == "", (step.label, result.stderr)
        assert result.stdout.replace(mapped, "/blackbox") == step.expected_stdout, (step.label, result.stdout)
        review.accept(index=index, command=step.command, exit_code=result.returncode,
                      stdout=result.stdout.replace(mapped, "/blackbox"), completion_validated=True)
    assert review.all_results_validated and review.next_step is None
    destination = blackbox / "x2dii-menu-stage" / plan.candidate_sha256[:24]
    assert {p.name: p.read_bytes() for p in destination.iterdir()} == members
    original = {p.name: p.read_bytes() for p in destination.iterdir()}
    repeated = execute(plan.steps[0])
    assert repeated.returncode != 0
    assert {p.name: p.read_bytes() for p in destination.iterdir()} == original


@pytest.mark.parametrize("field,value,reason", [
    ("index", 1, "out-of-order"), ("index", True, "out-of-order"),
    ("command", "echo different", "different command"),
    ("exit_code", False, "command failed"),
    ("completion_validated", False, "completion"),
    ("stdout", "unexpected", "readback"),
])
def test_unmatched_or_failed_returns_latch_the_review_closed(field, value, reason):
    stage = importlib.import_module("tools.stage_menu_delivery")
    review = stage.StagingReadback(make_plan())
    record = dict(index=0, command=review.next_step.command, exit_code=0,
                  stdout="", completion_validated=True)
    record[field] = value
    with pytest.raises(ValueError, match=reason):
        review.accept(**record)
    assert review.failed and review.next_step is None and not review.all_results_validated
    with pytest.raises(ValueError, match="already stopped"):
        review.accept(index=0, command=make_plan().steps[0].command, exit_code=0,
                      stdout="", completion_validated=True)


@pytest.mark.parametrize("member", (
    "libx2dii_menu.so", "X2d2MenuBootstrap.qml", "X2d2MenuModel.qml",
    "X2d2MenuPage.qml", "camera-gui.rc.proposed", "install-files.sh",
    "activate-boot.sh", "restore-boot.sh",
))
def test_changed_member_cannot_borrow_prior_candidate_or_rendered_program_binding(member):
    members, _, _ = fixture()
    members[member] += b" DIFFERENT"
    with pytest.raises(ValueError):
        make_plan(members=members)


def test_source_change_invalidates_prior_pin_and_plan_identity_without_mutating_inputs():
    members, candidate, scripts = fixture()
    before = deepcopy((members, candidate, scripts))
    original = make_plan(members=members, candidate=candidate, script_hashes=scripts)
    with pytest.raises(ValueError, match="renderer source hash"):
        make_plan(renderer_source=RENDERER + b"changed")
    changed = make_plan(renderer_source=RENDERER + b"changed",
                        renderer_source_sha256=sha(RENDERER + b"changed"))
    assert changed.plan_sha256 != original.plan_sha256
    assert (members, candidate, scripts) == before


@pytest.mark.parametrize("damage", (None, "package_sha256", "package_bytes", "format_version",
                                    "member_manifest_sha256", "extra-field"))
def test_fixed_plan_binds_complete_formal_archive_identity_before_publication(damage):
    # Fixed synthetic content has this recorded canonical identity.
    # It is not a camera candidate, qualification or deployment authorization.
    expected = {"package_sha256": "46726c0eba3791f1577aafff769e9b955fd6810416389890b00104a2211fa101",
                "package_bytes": 11264, "format_version": "x2dii-delivery-content-ustar-v1",
                "member_manifest_sha256": "ee5e5d7938602c345f54fbb6688cee3d2e1b850673eec9445bc755b295304d2f"}
    if damage is None:
        assert make_plan(delivery_identity=expected).installable is False
        return
    if damage == "package_bytes":
        expected[damage] += 512
    elif damage == "format_version":
        expected[damage] += "-old"
    else:
        expected[damage] = "f" * 64
    with pytest.raises(ValueError, match="delivery archive identity"):
        make_plan(delivery_identity=expected)


def test_missing_extra_and_session_members_are_not_stable_delivery_inputs():
    members, _, _ = fixture()
    for altered in ({k: v for k, v in members.items() if k != "restore-boot.sh"},
                    dict(members, **{"session-context.data": b"unreviewed session"}),
                    dict(members, **{"../escape": b"bad"})):
        with pytest.raises(ValueError):
            make_plan(members=altered)


def test_complete_crlf_readback_is_only_content_validation_not_installation_authority():
    stage = importlib.import_module("tools.stage_menu_delivery")
    plan = make_plan()
    review = stage.StagingReadback(plan)
    for index, step in enumerate(plan.steps):
        assert len(step.command.encode("ascii")) <= 3900
        review.accept(index=index, command=step.command, exit_code=0,
                      stdout=step.expected_stdout.replace("\n", "\r\n"), completion_validated=True)
    assert review.all_results_validated
    assert plan.installable is False and plan.transport_invocation_available is False


def test_unqualified_host_publication_is_rejected_before_any_source_is_returned():
    stage = importlib.import_module("tools.stage_menu_delivery")
    members, candidate, scripts = fixture()
    plan = make_plan()
    manifest = {"candidate": candidate, "candidate_sha256": plan.candidate_sha256,
                "renderer_source_sha256": sha(RENDERER)}
    with pytest.raises(ValueError, match="synthetic qualification"):
        stage.qualified_host_source(members=members, manifest=manifest,
                                    qualification={"candidate_sha256": plan.candidate_sha256,
                                                   "synthetic": True},
                                    window_authorization={})


@pytest.mark.parametrize("with_session", (False, True))
def test_review_host_compiles_and_validates_replies_but_refuses_all_usb_execution(tmp_path, with_session):
    from tools import peer_usb_access as usb
    stage = importlib.import_module("tools.stage_menu_delivery")
    plan = make_plan()
    session = stage.plan_session_staging(plan, *session_fixture(plan)) if with_session else None
    source = stage.review_host_source(plan, usb.REFERENCE.read_bytes(), session=session)
    path = tmp_path / "review-only.cs"
    path.write_text(source, encoding="utf-8")
    namespace = re.search(r"namespace (X2d2MenuStage_[0-9a-f]+)", source)[1]
    execution_hash = session.binding_sha256 if with_session else plan.plan_sha256
    first_reply = "\nX2DII_STAGE_" + execution_hash[:24] + "_0_RC=0\n"
    steps = plan.steps + (session.steps if with_session else ())
    last_reply = steps[-1].expected_stdout + "\nX2DII_STAGE_" + execution_hash[:24] + "_" + str(len(steps)-1) + "_RC=0\n"
    encoded = base64.b64encode(first_reply.encode()).decode()
    last_encoded = base64.b64encode(last_reply.encode()).decode()
    script = r'''
$ErrorActionPreference='Stop'
Add-Type -Path '__SOURCE_PATH__'
$type=[__NAMESPACE__.AdbUsbCheck]
function Reject([scriptblock]$Call,[string]$Code) {
 try { & $Call } catch {
  $errorObject=$_.Exception
  while($errorObject.InnerException){$errorObject=$errorObject.InnerException}
  if($errorObject.Code -ne $Code){throw "Wrong rejection: $errorObject"}
  return
 }
 throw 'Expected rejection'
}
$good=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__REPLY_BASE64__'))
$type::ValidateStageOutput(0,$good)
$type::ValidateStageOutput(0,$good.Replace("`n","`r`n"))
if($type::FixedCommandCount -ne __COUNT__){throw 'Missing execution commands'}
$type::ValidateStageOutput(__LAST__,[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__LAST_REPLY__')))
$lastBad=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__LAST_REPLY__'))
Reject { $type::ValidateStageOutput(__LAST__,'f'+$lastBad.Substring(1)) } 'STAGE_REPLY_MISMATCH'
Reject { $type::ValidateStageOutput(0,$good.Replace('RC=0','RC=1')) } 'STAGE_REPLY_MISMATCH'
Reject { $type::ValidateStageOutput(0,$good+'unexpected') } 'STAGE_REPLY_MISMATCH'
Reject { $type::ValidateStageOutput(-1,$good) } 'STAGE_INDEX'
Reject { $type::Stage() } 'STAGE_SOURCE_NOT_QUALIFIED'
Reject { $type::Stage() } 'STAGE_ALREADY_ATTEMPTED'
$methods=$type.GetMethods([Reflection.BindingFlags]'Public,Static,DeclaredOnly')
if($methods.Name -contains 'Query' -or $methods.Name -contains 'RunShell' -or $methods.Name -contains 'RunShellBatch' -or $methods.Name -contains 'Probe') {
 throw 'Unexpected public shell/query entry'
}
'FIXED_STAGE_PURE_CHECKS_NO_USB'
'''.replace("__SOURCE_PATH__", str(path).replace("'", "''")).replace("__NAMESPACE__", namespace).replace("__REPLY_BASE64__", encoded).replace(
    "__COUNT__", str(len(steps))).replace("__LAST__", str(len(steps)-1)).replace("__LAST_REPLY__", last_encoded)
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "FIXED_STAGE_PURE_CHECKS_NO_USB" in result.stdout


@pytest.mark.parametrize("change", ("old-scope", "not-approved", "candidate_sha256", "plan_sha256",
                                    "boot_id", "session_nonce", "launch-evidence", "old", "future",
                                    "no-zone", "no-time", "lease-expiry"))
def test_window_requires_new_scope_same_candidate_session_and_remaining_time(change):
    stage = importlib.import_module("tools.stage_menu_delivery")
    plan = make_plan()
    now = datetime(2026, 10, 4, 20, 0, tzinfo=timezone.utc)
    q = {"boot_id": "11111111-2222-3333-4444-555555555555", "session_nonce": "b" * 32,
         "observed_utc": now.isoformat()}
    window = {"approved": True, "purpose": "temporary_adb_fixed_menu_staging",
              "candidate_sha256": plan.candidate_sha256, "plan_sha256": plan.plan_sha256,
              "boot_id": q["boot_id"], "session_nonce": q["session_nonce"],
              "launch_session_sha256": "a" * 64, "launch_started_utc": now.isoformat()}
    assert stage.validate_staging_window(window, plan, q, now=now) == now + timedelta(seconds=60)
    if change == "old-scope":
        window = {"scope": "One identity-only query; no extension installation."}
    elif change == "not-approved":
        window["approved"] = False
    elif change in ("candidate_sha256", "plan_sha256", "boot_id", "session_nonce"):
        window[change] = "different"
    elif change == "launch-evidence":
        window.pop("launch_session_sha256")
    elif change == "old":
        window["launch_started_utc"] = (now - timedelta(seconds=43)).isoformat()
    elif change == "future":
        window["launch_started_utc"] = (now + timedelta(seconds=1)).isoformat()
    elif change == "no-zone":
        window["launch_started_utc"] = "2026-10-04T20:00:00"
    elif change == "no-time":
        window.pop("launch_started_utc")
    elif change == "lease-expiry":
        q["observed_utc"] = (now - timedelta(seconds=590)).isoformat()
    with pytest.raises(ValueError):
        stage.validate_staging_window(window, plan, q, now=now)


def test_correct_metadata_stdout_with_failed_stat_does_not_create_candidate_stage(tmp_path):
    plan = make_plan()
    blackbox = tmp_path / "blackbox"
    (blackbox / "x2dii-menu-stage").mkdir(parents=True)
    command = plan.steps[0].command.replace("/blackbox", shlex.quote(blackbox.as_posix())).replace(
        "export PATH=/system/bin:/system/xbin:/sbin;", "export PATH=/usr/bin:/bin;")
    failed_stat = "stat() { printf '0 0 700\\n'; return 1; }\n"
    result = subprocess.run(["C:/Program Files/Git/bin/sh.exe", "-c", failed_stat + command],
                            capture_output=True, timeout=10)
    assert result.returncode != 0
    assert not (blackbox / "x2dii-menu-stage" / plan.candidate_sha256[:24]).exists()


def test_su_staging_succeeds_without_read_permission_on_init_namespace(tmp_path):
    """Real staging shell with the actual su/init permission boundary modelled."""
    from tools import stage_menu_delivery as stage
    plan = make_plan()
    session = stage.plan_session_staging(plan, *session_fixture(plan))
    blackbox = tmp_path / "blackbox"
    blackbox.mkdir()
    context = dict(session.context)
    model = f'''id() {{ printf '0\\n'; }}
date() {{ printf '%s\\n' '{session.observed_epoch}'; }}
cat() {{ case "$1" in
 /proc/sys/kernel/random/boot_id) printf '%s\\n' '{context['boot_id']}';;
 /proc/self/attr/current) printf 'u:r:su:s0\\n';;
 *) command cat "$@";; esac; }}
readlink() {{ case "$1" in
 /proc/self/ns/mnt) printf '%s\\n' '{context['mount_namespace']}';;
 /proc/1/ns/mnt) printf 'DENIED_INIT_NAMESPACE\\n' >&2; return 93;;
 *) command readlink "$@";; esac; }}
stat() {{ printf '0 0 700\\n'; }}
'''
    command = stage.execution_steps(plan, context, session=session)[0].command
    command = command.replace("/blackbox", shlex.quote(blackbox.as_posix())).replace(
        "export PATH=/system/bin:/system/xbin:/sbin;", "export PATH=/usr/bin:/bin;")
    result = subprocess.run(["C:/Program Files/Git/bin/sh.exe", "-s"],
                            input=model + command, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert "DENIED_INIT_NAMESPACE" not in result.stderr
    assert (blackbox / "x2dii-menu-stage" / plan.candidate_sha256[:24]).is_dir()


def complete_observer_preparation(exchange):
    """Upload-receipt fixture for protocol-only cases; full upload executes below."""
    while (step := exchange.next_step) is not None and step.index < 0:
        exchange.accept(role=step.role, index=step.index, command=step.command,
                        exit_code=0, stdout=step.expected_stdout, completion_validated=True)


def maintenance_result(operation, session, *, observer, domain="u:r:hbl_camera_service:s0", init_ns=None,
                       epoch=None, directory=None, data_override=None, program_override=None,
                       failed_metadata=False):
    """Execute the one fixed program and index. Android OS facts/path are modelled.

    The disk program/data bytes stay exact; only the executed source's absolute
    OS path is relocated. This is not target shell/metadata/transport evidence.
    """
    context = dict(session.context)
    model = r'''
sha256sum() { value=$(command sha256sum "$@") || return $?; printf '%s\n' "$value" | sed 's/ \*/  /'; }
stat() { case "$2" in
 '%u:%g:%a') printf '0:0:700\n'; return METADATA_STATUS;;
 '%u:%g:%a:%h') printf '0:0:600:%s\n' "$(command stat -c %h "$3")";;
 *) command stat "$@";; esac; }
'''.replace("METADATA_STATUS", "1" if failed_metadata else "0") + f'''id() {{ printf '0\\n'; }}
date() {{ printf '%s\\n' '{session.observed_epoch if epoch is None else epoch}'; }}
cat() {{ case "$1" in
 /proc/sys/kernel/random/boot_id) printf '%s\\n' '{context['boot_id']}';;
 /proc/self/attr/current) printf '%s\\n' '{domain}';;
 *) return 99;; esac; }}
readlink() {{ case "$1" in
 /proc/self/ns/mnt) printf '%s\\n' '{context['mount_namespace']}';;
 /proc/1/ns/mnt) printf '%s\\n' '{init_ns or context['init_mount_namespace']}';;
 *) return 99;; esac; }}
'''
    def run(root):
        root.mkdir(exist_ok=True)
        if directory is None:
            (root / "o").write_bytes(observer.program if program_override is None else program_override)
            (root / "d").write_bytes(observer.data if data_override is None else data_override)
        args = shlex.split(operation.command)
        assert len(args) == 4 and args[:2] == ["sh", observer.root + "/o"]
        relocated = (root / "o").read_text("ascii").replace(observer.root, root.as_posix()).replace(
            "export PATH=/system/bin:/system/xbin:/sbin", "export PATH=/usr/bin:/bin")
        return subprocess.run(["C:/Program Files/Git/bin/sh.exe", "-c", model + relocated,
                               (root / "o").as_posix(), *args[2:]],
                              capture_output=True, text=True, timeout=10)
    if directory is not None:
        return run(directory)
    with tempfile.TemporaryDirectory(prefix="stage-observer-fixture-") as temporary:
        return run(Path(temporary))


def test_only_matching_maintenance_result_releases_the_next_su_staging_command():
    from tools import stage_menu_delivery as stage
    plan = make_plan()
    session = stage.plan_session_staging(plan, *session_fixture(plan))
    exchange = stage.FixedStagingExchange(plan, dict(session.context), session=session,
                                          clock=lambda: session.observed_epoch)
    complete_observer_preparation(exchange)
    observe = exchange.next_step
    assert observe.role == "maintenance" and observe.index == 0
    result = maintenance_result(observe, session, observer=exchange.observer)
    assert result.returncode == 0 and result.stderr == ""
    exchange.accept(role=observe.role, index=observe.index, command=observe.command,
                    exit_code=result.returncode, stdout=result.stdout, completion_validated=True)
    write = exchange.next_step
    assert write.role == "su" and write.index == 0
    assert "/proc/1/" not in write.command
    assert write.command == stage.execution_steps(plan, dict(session.context), session=session)[0].command
    exchange.accept(role="su", index=0, command=write.command, exit_code=0,
                    stdout=write.expected_stdout, completion_validated=True)
    assert exchange.next_step.role == "maintenance" and exchange.next_step.index == 1
    assert not exchange.all_results_validated


@pytest.mark.parametrize("fault", ("role", "missing-role", "index", "command", "not-completed",
                                 "failed", "old-exchange", "old-session", "missing", "extra"))
def test_unbound_maintenance_result_never_releases_su_staging(fault):
    from tools import stage_menu_delivery as stage
    plan = make_plan()
    manifest, q = session_fixture(plan)
    session = stage.plan_session_staging(plan, manifest, q)
    exchange = stage.FixedStagingExchange(plan, dict(session.context), session=session,
                                          clock=lambda: session.observed_epoch)
    complete_observer_preparation(exchange)
    observe = exchange.next_step
    result = maintenance_result(observe, session, observer=exchange.observer)
    record = dict(role="maintenance", index=0, command=observe.command,
                  exit_code=result.returncode, stdout=result.stdout, completion_validated=True)
    if fault == "role":
        record["role"] = "su"
    elif fault == "missing-role":
        record.pop("role")
    elif fault == "index":
        record["index"] = 1
    elif fault == "command":
        record["command"] += ";:"
    elif fault == "not-completed":
        record["completion_validated"] = False
    elif fault == "failed":
        record["exit_code"] = 1
    elif fault in ("old-exchange", "old-session"):
        if fault == "old-session":
            q["session_nonce"] = "c" * 32
            session = stage.plan_session_staging(plan, manifest, q)
        old = stage.FixedStagingExchange(plan, dict(session.context), session=session,
                                        clock=lambda: session.observed_epoch)
        complete_observer_preparation(old)
        record["stdout"] = maintenance_result(old.next_step, session, observer=old.observer).stdout
    elif fault == "missing":
        record["stdout"] = ""
    else:
        record["stdout"] += "unexpected\n"
    with pytest.raises(ValueError):
        exchange.accept(**record)
    assert exchange.failed and exchange.next_step is None and not exchange.all_results_validated


def test_a_staging_result_cannot_be_accepted_before_that_role_was_released():
    from tools import stage_menu_delivery as stage
    plan = make_plan()
    session = stage.plan_session_staging(plan, *session_fixture(plan))
    exchange = stage.FixedStagingExchange(plan, dict(session.context), session=session,
                                          clock=lambda: session.observed_epoch)
    complete_observer_preparation(exchange)
    observe = exchange.next_step
    result = maintenance_result(observe, session, observer=exchange.observer)
    exchange.accept(role="maintenance", index=0, command=observe.command,
                    exit_code=0, stdout=result.stdout, completion_validated=True)
    # Constructing offline source is not a request released by this exchange.
    offline = stage.execution_steps(plan, dict(session.context), session=session)[0]
    with pytest.raises(ValueError, match="released"):
        exchange.accept(role="su", index=0, command=offline.command,
                        exit_code=0, stdout=offline.expected_stdout, completion_validated=True)
    assert exchange.failed and exchange.next_step is None


@pytest.mark.parametrize("fault", ("old-boot", "self-namespace", "init-namespace", "boot-status", "namespace-status"))
def test_current_execution_guard_stops_before_private_stage_creation(tmp_path, fault):
    stage = importlib.import_module("tools.stage_menu_delivery")
    plan = make_plan()
    session = stage.plan_session_staging(plan, *session_fixture(plan))
    context = dict(session.context)
    blackbox = tmp_path / "blackbox"
    blackbox.mkdir()
    role = "maintenance" if fault == "init-namespace" else "su"
    step = stage.execution_steps(plan, context, session=session, role=role, request_nonce="a" * 32)[0]
    if role == "maintenance":
        observer = stage.plan_maintenance_staging(plan, context, session=session, request_nonce="a" * 32)
        result = maintenance_result(step, session, observer=observer, init_ns="mnt:[9]")
        assert result.returncode != 0 and list(blackbox.iterdir()) == []
        return
    actual_boot = "00000000-0000-0000-0000-000000000000" if fault == "old-boot" else context["boot_id"]
    self_ns = "mnt:[9]" if fault == "self-namespace" else context["mount_namespace"]
    init_ns = "mnt:[9]" if fault == "init-namespace" else context["init_mount_namespace"]
    domain = "u:r:hbl_camera_service:s0" if role == "maintenance" else "u:r:su:s0"
    model = (f"id() {{ printf '0\\n'; }}\ndate() {{ printf '{session.observed_epoch}\\n'; }}\n"
             f"cat() {{ case \"$1\" in /proc/self/attr/current) printf '{domain}\\n';; "
             f"*) printf '%s\\n' '{actual_boot}'; return {1 if fault == 'boot-status' else 0};; esac; }}\n"
             f"readlink() {{ case \"$1\" in /proc/self/ns/mnt) printf '%s\\n' '{self_ns}';; "
             f"/proc/1/ns/mnt) printf '%s\\n' '{init_ns}';; *) return 99;; esac; "
             f"return {1 if fault == 'namespace-status' else 0}; }}\n")
    command = step.command.replace("/blackbox", shlex.quote(blackbox.as_posix()))
    result = subprocess.run(["C:/Program Files/Git/bin/sh.exe", "-c", model + command],
                            capture_output=True, timeout=10)
    assert result.returncode != 0
    assert list(blackbox.iterdir()) == []


@pytest.mark.parametrize("fault", ("domain", "init", "expired", "future"))
def test_maintenance_observer_itself_rejects_wrong_role_namespace_and_original_lease(fault):
    from tools import stage_menu_delivery as stage
    plan = make_plan()
    session = stage.plan_session_staging(plan, *session_fixture(plan))
    step = stage.execution_steps(plan, dict(session.context), session=session,
                                 role="maintenance", request_nonce="a" * 32)[0]
    observer = stage.plan_maintenance_staging(plan, dict(session.context), session=session, request_nonce="a" * 32)
    changes = {"domain": {"domain": "u:r:su:s0"}, "init": {"init_ns": "mnt:[9]"},
               "expired": {"epoch": session.observed_epoch + 601},
               "future": {"epoch": session.observed_epoch - 1}}
    result = maintenance_result(step, session, observer=observer, **changes[fault])
    assert result.returncode != 0
    assert "X2DII_STAGE_MAINTENANCE:" not in result.stdout


@pytest.mark.parametrize("when", ("request", "release", "lease", "receipt"))
def test_old_observation_or_expired_original_lease_cannot_release_any_more_staging(when):
    from tools import stage_menu_delivery as stage
    plan = make_plan()
    session = stage.plan_session_staging(plan, *session_fixture(plan))
    now = [session.observed_epoch]
    exchange = stage.FixedStagingExchange(plan, dict(session.context), session=session, clock=lambda: now[0])
    complete_observer_preparation(exchange)
    observe = exchange.next_step
    result = maintenance_result(observe, session, observer=exchange.observer)
    record = dict(role="maintenance", index=0, command=observe.command, exit_code=0,
                  stdout=result.stdout, completion_validated=True)
    if when == "request":
        now[0] += 9
        with pytest.raises(ValueError, match="stale"):
            exchange.accept(**record)
    else:
        exchange.accept(**record)
        if when == "receipt":
            write = exchange.next_step
            now[0] += 9
            with pytest.raises(ValueError, match="expired"):
                exchange.accept(role="su", index=write.index, command=write.command,
                                exit_code=0, stdout=write.expected_stdout, completion_validated=True)
            assert exchange.failed and exchange.next_step is None
            return
        now[0] += 9 if when == "release" else 601
        with pytest.raises(ValueError, match="expired"):
            _ = exchange.next_step
    assert exchange.failed and exchange.next_step is None


def test_missing_session_never_creates_a_supervised_staging_exchange():
    from tools import stage_menu_delivery as stage
    plan = make_plan()
    with pytest.raises(ValueError, match="original current session"):
        stage.FixedStagingExchange(plan, {}, session=None)


def test_every_staging_maintenance_observation_fits_the_existing_tcp_frame():
    from tools import stage_menu_delivery as stage, stage_peer_usb_access as transport
    plan = make_plan()
    session = stage.plan_session_staging(plan, *session_fixture(plan))
    observer = stage.plan_maintenance_staging(plan, dict(session.context), session=session, request_nonce="a" * 32)
    for step in observer.preparation + observer.observations:
        wire, _, _ = transport.envelope(step.command, "123456abcdef")
        assert len(wire.encode("ascii")) < 232
    for step in observer.observations:
        assert len(shlex.split(step.command)) == 4  # sh, fixed program, index, data hash


def test_one_observer_program_and_inert_index_are_reused_for_all_fixed_staging_chunks():
    from tools import stage_menu_delivery as stage
    plan = make_plan()
    session = stage.plan_session_staging(plan, *session_fixture(plan))
    first = stage.plan_maintenance_staging(plan, dict(session.context), session=session, request_nonce="a" * 32)
    second = stage.plan_maintenance_staging(plan, dict(session.context), session=session, request_nonce="b" * 32)
    assert first.program == second.program and first.program_sha256 == second.program_sha256
    assert first.data_sha256 != second.data_sha256
    assert sum(step.label == "prepare-observer-begin-o" for step in first.preparation) == 1
    assert sum(step.label == "prepare-observer-begin-d" for step in first.preparation) == 1
    assert len(first.observations) == len(plan.steps) + len(session.steps)
    assert "printf %s" not in first.data.decode("ascii")
    assert all(shlex.split(step.command)[1] == first.root + "/o" for step in first.observations)


@pytest.mark.parametrize("damage", ("old-nonce", "index-hash", "program", "argument-hash", "metadata-status"))
def test_fixed_observer_program_refuses_changed_index_program_or_unbound_nonce(damage):
    from tools import stage_menu_delivery as stage
    plan = make_plan()
    session = stage.plan_session_staging(plan, *session_fixture(plan))
    observer = stage.plan_maintenance_staging(plan, dict(session.context), session=session, request_nonce="a" * 32)
    step = observer.observations[0]
    changes = {}
    if damage == "old-nonce":
        changes["data_override"] = observer.data.replace(b"request_nonce=" + b"a" * 32,
                                                         b"request_nonce=" + b"b" * 32)
    elif damage == "index-hash":
        changes["data_override"] = re.sub(rb"command_0=[0-9a-f]{64}", b"command_0=" + b"f" * 64, observer.data)
    elif damage == "program":
        changes["program_override"] = observer.program + b"# altered bytes\n"
    elif damage == "metadata-status":
        changes["failed_metadata"] = True
    else:
        step = replace(step, command=step.command.replace(observer.data_sha256, "f" * 64))
    result = maintenance_result(step, session, observer=observer, **changes)
    assert result.returncode != 0 and "X2DII_STAGE_MAINTENANCE:" not in result.stdout


@pytest.mark.parametrize("field", ("observed_epoch", "session_nonce", "data_sha256", "binding_sha256", "steps"))
def test_session_data_cannot_be_relabelled_to_release_new_staging_or_renew_its_lease(field):
    from tools import stage_menu_delivery as stage
    plan = make_plan()
    session = stage.plan_session_staging(plan, *session_fixture(plan))
    values = {"observed_epoch": session.observed_epoch + 1000,
              "session_nonce": "d" * 32, "data_sha256": "e" * 64,
              "binding_sha256": "f" * 64,
              "steps": (stage.StageStep("substituted", "echo NOT_A_FIXED_STEP", ""),)}
    changed = replace(session, **{field: values[field]})
    with pytest.raises(ValueError, match="session"):
        stage.FixedStagingExchange(plan, dict(session.context), session=changed,
                                   clock=lambda: changed.observed_epoch)


def test_both_actual_role_scripts_stage_all_exact_members_and_session_in_sequence(tmp_path):
    """The fixed adapter drives real shell/file results, not canned su success."""
    from tools import stage_menu_delivery as stage
    plan = make_plan()
    session = stage.plan_session_staging(plan, *session_fixture(plan))
    exchange = stage.FixedStagingExchange(plan, dict(session.context), session=session,
                                          clock=lambda: session.observed_epoch)
    blackbox = tmp_path / "blackbox"
    blackbox.mkdir()
    observer_directory = tmp_path / "observer"
    shell = "C:/Program Files/Git/bin/sh.exe"
    mapped = subprocess.run([shell, "-c", 'cygpath -u "$1"', "fixture", str(blackbox)],
                            capture_output=True, text=True, check=True).stdout.strip()
    observer_mapped = subprocess.run([shell, "-c", 'cygpath -u "$1"', "fixture", str(observer_directory)],
                                     capture_output=True, text=True, check=True).stdout.strip()
    su_model = r'''
id() { printf '0\n'; }
sha256sum() { value=$(command sha256sum "$@") || return $?; printf '%s\n' "$value" | sed 's/ \*/  /'; }
stat() { case "$2" in
 '%u %g %a') printf '0 0 700\n';;
 '%u %g %a %h') printf '0 0 600 %s\n' "$(command stat -c %h "$3")";;
 *) command stat "$@";; esac; }
''' + f'''date() {{ printf '{session.observed_epoch}\\n'; }}
cat() {{ case "$1" in
 /proc/self/attr/current) printf 'u:r:su:s0\\n';;
 /proc/sys/kernel/random/boot_id) printf '{dict(session.context)['boot_id']}\\n';;
 *) command cat "$@";; esac; }}
readlink() {{ case "$1" in
 /proc/self/ns/mnt) printf '{dict(session.context)['mount_namespace']}\\n';;
 /proc/1/ns/mnt) printf 'DENIED_INIT_NAMESPACE\\n' >&2; return 93;;
 *) command readlink "$@";; esac; }}
'''
    roles = []
    while (step := exchange.next_step) is not None:
        roles.append(step.role)
        if step.index < 0:
            command = step.command.replace(exchange.observer.root, shlex.quote(observer_mapped))
            result = subprocess.run([shell, "-s"], input=su_model + command,
                                    capture_output=True, text=True, timeout=10)
        elif step.role == "maintenance":
            result = maintenance_result(step, session, observer=exchange.observer, directory=observer_directory)
        else:
            command = step.command.replace("/blackbox", shlex.quote(mapped)).replace(
                "export PATH=/system/bin:/system/xbin:/sbin;", "export PATH=/usr/bin:/bin;")
            result = subprocess.run([shell, "-s"], input=su_model + command,
                                    capture_output=True, text=True, timeout=10)
        assert result.returncode == 0 and result.stderr == "", (step.role, step.index, result.stderr)
        exchange.accept(role=step.role, index=step.index, command=step.command,
                        exit_code=result.returncode, stdout=result.stdout.replace(mapped, "/blackbox").replace(
                            observer_mapped, exchange.observer.root),
                        completion_validated=True)
    assert roles == ["maintenance"] * len(exchange.observer.preparation) + ["maintenance", "su"] * (
        len(plan.steps) + len(session.steps))
    assert exchange.all_results_validated
    destination = blackbox / "x2dii-menu-stage" / plan.candidate_sha256[:24]
    assert {p.name: p.read_bytes() for p in destination.iterdir()} == {
        **fixture()[0], "session-context.data": session.data}
    assert (observer_directory / "o").read_bytes() == exchange.observer.program
    assert (observer_directory / "d").read_bytes() == exchange.observer.data


def test_stream_failure_retains_prior_received_bytes_without_any_native_usb_call(tmp_path):
    """Inject failure at OS transport boundary; execute the generated receiver loop."""
    from tools import peer_usb_access as usb
    stage = importlib.import_module("tools.stage_menu_delivery")
    source = stage.review_host_source(make_plan(), usb.REFERENCE.read_bytes())
    namespace = re.search(r"namespace (X2d2MenuStage_[0-9a-f]+)", source)[1]
    # Every remaining native import is disabled as a second barrier in this
    # explicit synthetic receiver test; no production caller uses this source.
    source = re.sub(r'\[DllImport\("[^"]+"', '[DllImport("NO_DEVICE_TEST_BOUNDARY.dll"', source)

    def replace_method(text, signature, body):
        assert text.count(signature) == 1
        start = text.index(signature)
        opening = text.index("{", start)
        depth = 1
        end = opening + 1
        while depth:
            depth += (text[end] == "{") - (text[end] == "}")
            end += 1
        return text[:opening] + "{" + body + "}" + text[end:]

    source = replace_method(source, "private void Open(ReadResult result)",
                            "result.Opened=true;file=null;usb=IntPtr.Zero;pipeIn=0x81;pipeOut=1;")
    # This test models an admitted/time-valid caller only to exercise the
    # transport-failure path. Every native import remains disabled above.
    source = replace_method(source, "private static void StageTime(int reserveMilliseconds)",
                            "GC.KeepAlive(QualifiedSource);GC.KeepAlive(ExecutionDeadline);GC.KeepAlive(batchClock);")
    source = replace_method(source, "private void Send(string command,uint a,uint b,byte[] payload)", "")
    source = source.replace("private Packet Receive()", "private int fixtureReceiveIndex;\n        private Packet Receive()", 1)
    source = replace_method(source, "private Packet Receive()", r'''
        fixtureReceiveIndex++;
        if(fixtureReceiveIndex==1) return new Packet {Command=Cmd("CNXN"),A=0x01000000,B=4096,Data=new byte[144]};
        if(fixtureReceiveIndex==2) return new Packet {Command=Cmd("OKAY"),A=7,B=1,Data=new byte[0]};
        if(fixtureReceiveIndex==3) return new Packet {Command=Cmd("WRTE"),A=7,B=1,Data=Encoding.UTF8.GetBytes("partial reply\n")};
        throw new UsbFailure("ADB_READ",123,"INJECTED_RECEIVE_FAILURE");
''')
    path = tmp_path / "synthetic-stream-failure.cs"
    path.write_text(source, encoding="utf-8")
    script = r'''
$ErrorActionPreference='Stop'
Add-Type -Path '__PATH__'
$method=[__NS__.AdbUsbCheck].GetMethod('RunShell',[Reflection.BindingFlags]'NonPublic,Static')
try { $method.Invoke($null,@([int]0)); throw 'Expected stream failure' } catch {
 $e=$_.Exception
 while($e.InnerException){$e=$e.InnerException}
 if($e.Code -ne 'ADB_READ' -or $e.Win32 -ne 123){throw "Original failure lost: $e"}
 if($e.Details -notmatch 'cGFydGlhbCByZXBseQo=' -or $e.Details -notmatch 'receivedPayloadBytes=14' -or $e.Details -notmatch 'stageIndex=0') {
  throw "Partial reply evidence missing: $e"
 }
}
'SYNTHETIC_STREAM_FAILURE_RETAINED_NO_USB'
'''.replace("__PATH__", str(path).replace("'", "''")).replace("__NS__", namespace)
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "SYNTHETIC_STREAM_FAILURE_RETAINED_NO_USB" in result.stdout


def test_expired_host_lease_refuses_before_open_even_with_counterfactual_admission(tmp_path):
    """A test-only admitted flag must not bypass the independently expired deadline."""
    from tools import peer_usb_access as usb
    stage = importlib.import_module("tools.stage_menu_delivery")
    source = stage.review_host_source(make_plan(), usb.REFERENCE.read_bytes())
    assert source.count("QualifiedSource = false;") == 1
    source = source.replace("QualifiedSource = false;", "QualifiedSource = true;")
    source = re.sub(r'\[DllImport\("[^"]+"', '[DllImport("NO_DEVICE_TEST_BOUNDARY.dll"', source)
    namespace = re.search(r"namespace (X2d2MenuStage_[0-9a-f]+)", source)[1]
    path = tmp_path / "counterfactual-expired-only.cs"
    path.write_text(source, encoding="utf-8")
    script = r'''
$ErrorActionPreference='Stop'
Add-Type -Path '__PATH__'
try { [__NS__.AdbUsbCheck]::Stage(); throw 'Expected deadline rejection' } catch {
 $e=$_.Exception
 while($e.InnerException){$e=$e.InnerException}
 if($e.Code -ne 'STAGE_BATCH_DEADLINE'){throw "Wrong failure or native IO attempted: $e"}
}
'EXPIRED_BEFORE_OPEN_NO_USB'
'''.replace("__PATH__", str(path).replace("'", "''")).replace("__NS__", namespace)
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "EXPIRED_BEFORE_OPEN_NO_USB" in result.stdout


def test_independent_adb_stage_cannot_skip_dual_role_supervision_with_valid_time_and_admission(tmp_path):
    from tools import peer_usb_access as usb, stage_menu_delivery as stage
    source = stage.review_host_source(make_plan(), usb.REFERENCE.read_bytes())
    assert source.count("QualifiedSource = false;") == 1
    assert source.count('DateTime.Parse("2000-01-01T00:00:00+00:00"') == 1
    source = source.replace("QualifiedSource = false;", "QualifiedSource = true;").replace(
        'DateTime.Parse("2000-01-01T00:00:00+00:00"', 'DateTime.Parse("2099-01-01T00:00:00+00:00"')
    source = re.sub(r'\[DllImport\("[^"]+"', '[DllImport("NO_DEVICE_TEST_BOUNDARY.dll"', source)
    namespace = re.search(r"namespace (X2d2MenuStage_[0-9a-f]+)", source)[1]
    path = tmp_path / "counterfactual-admitted-needs-supervision.cs"
    path.write_text(source, encoding="utf-8")
    script = r'''
$ErrorActionPreference='Stop'
Add-Type -Path '__PATH__'
try { [__NS__.AdbUsbCheck]::Stage(); throw 'Expected supervision refusal' } catch {
 $e=$_.Exception
 while($e.InnerException){$e=$e.InnerException}
 if($e.Code -ne 'STAGE_DUAL_DOMAIN_SUPERVISION_REQUIRED'){throw "Wrong failure or native IO attempted: $e"}
}
'UNSUPERVISED_STAGE_REFUSED_BEFORE_USB'
'''.replace("__PATH__", str(path).replace("'", "''")).replace("__NS__", namespace)
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "UNSUPERVISED_STAGE_REFUSED_BEFORE_USB" in result.stdout


def test_temporary_support_stages_only_consumed_six_sources_with_complete_readback():
    """Actual renderers with synthetic session/payloads, no target execution."""
    from tests.test_menu_preparation_transport import preparation_fixture
    from tools import stage_menu_delivery as stage, menu_lifecycle_transport as lifecycle
    from tools import menu_maintenance_boundary as boundary, menu_content_transport as content
    parent, manifest, raw, code = preparation_fixture("menu_validation")
    root = "/tmp/x2mb-" + manifest["candidate_sha256"][:12]
    programs = lifecycle.render_programs(manifest)
    expected = tuple((root + "/" + name, programs[name].encode("ascii")) for name in ("l", "w", "t", "q", "s"))
    expected += ((root + "/v", boundary.render_observer(manifest, session_kind="menu_validation").encode("ascii")),)
    support = stage.plan_menu_support_staging(parent, manifest, raw)
    assert support.files == expected
    assert len(support.files) == 6
    assert all("/x2bb-" not in step.command for step in code.plan.steps)
    readbacks = tuple(step for step in support.steps if step.label.startswith("verify-menu-support-"))
    assert len(readbacks) == 1
    hashes = "".join(f"{sha(data)}  {path}\n" for path, data in expected)
    sizes = "".join(f"{len(data)}\n" for _, data in expected)
    assert readbacks[0].expected_stdout == hashes + sizes
    values = content.session_context.decode_session(raw)
    values.update(session_nonce="c" * 32, observed_epoch=values["observed_epoch"] + 200)
    fresh = content.session_context.encode_session(values, schema=content.session_context.MENU_VALIDATION_SCHEMA)
    ready = content.plan_temporary_ready(code, fresh)
    assert len(ready.plan.steps) == 4
    assert all("/x2bb-" not in step.command for step in ready.plan.steps)
    assert ready.plan.steps[-1].expected_stdout == hashes + sizes
    assert not support.installable and not code.installable and not ready.installable


def test_temporary_code_preparation_budget_accepts_ten_second_delay_without_extending_window():
    """A cadence lower bound only; USB enumeration/execution overhead is unknown."""
    from tests.test_menu_preparation_transport import preparation_fixture
    from tools import stage_menu_delivery as stage, menu_content_transport as content
    _, _, _, code = preparation_fixture("menu_validation")
    launched = datetime.fromtimestamp(code.session.observed_epoch, timezone.utc)
    deadline = datetime.fromtimestamp(content.original_window_deadline(code.session.observed_epoch, launched), timezone.utc)
    assert deadline == launched + timedelta(seconds=80)
    operations = stage.execution_steps(code.plan, dict(code.session.context), session=code.session)
    stage._require_maintenance_budget(deadline, now=launched + timedelta(seconds=10),
                                      remaining_commands=len(operations))
    source = content.review_preparation_host_source(code, launched)
    assert "private static readonly bool ContentQualified = false;" in source
    assert f"private const long ContentDeadlineEpoch = {int(deadline.timestamp())};" in source
    for index, operation in enumerate(operations):
        marker = f"X2DII_CONTENT_{code.session.binding_sha256[:24]}_{index}_RC="
        command = "(" + operation.command + ");r=$?;printf '\\n" + marker + "%s\\n' \"$r\""
        assert len(("shell:" + command + "\0").encode("ascii")) <= 4096
