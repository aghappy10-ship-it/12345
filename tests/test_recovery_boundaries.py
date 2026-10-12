"""Host-only recovery boundary tests; these are not camera qualification.

The public fixture substitutes credentials, service state, namespaces, labels,
device tools and the clock. Real file operations stay in its temporary build
directory. Dependency faults are injected at read_bytes, never on disk.
"""
from datetime import datetime
from pathlib import Path

import pytest

from tools import prepare_peer_install as peer


@pytest.fixture
def recovery_fixture():
    from tests.test_peer_recovery import PeerRecoveryTests

    fixture = PeerRecoveryTests()
    fixture.setUp()
    try:
        yield fixture
    finally:
        fixture.tearDown()


def clock_hook(fixture):
    observed = int(datetime.fromisoformat(fixture.q["observed_utc"]).timestamp())
    return f'''
date() {{
 if [ -e "$fixture/expired" ]; then echo {observed + 601}; else echo {observed}; fi
}}
'''


def assert_failed_without_success(fixture, result):
    assert fixture.path("/expired").is_file(), "the intended read did not expire the lease"
    assert result.returncode != 0, result.stdout
    assert b"X2DII_RECOVERY_FAILED:" in result.stderr
    assert b"X2DII_OFFICIAL_RC_RESTORED_OWNED_FILES_REMOVED" not in result.stdout
    assert fixture.path(fixture.backup + "/camera-gui.rc.original").read_bytes() == fixture.original
    assert fixture.path(fixture.backup + "/owner").read_bytes() == (
        fixture.manifest["candidate_sha256"] + "\n"
    ).encode()


def assert_owned_mount_and_lock_released(fixture):
    assert fixture.path("/proc/mounts").read_text() == fixture.mount_line
    assert not fixture.path("/tmp/x2dii-menu-install.lock").exists()
    assert fixture.path("/proc/sys/kernel/random/boot_id").read_text().strip() == fixture.q["boot_id"]


@pytest.mark.parametrize("target", [target for _, target in peer.FILES])
@pytest.mark.parametrize("slow_read", ("payload_hash", "payload_label"))
def test_expiration_during_final_payload_reads_prevents_that_removal(
    recovery_fixture, target, slow_read
):
    fixture = recovery_fixture
    module = fixture.recovery()
    hook = clock_hook(fixture) + f'''
mv() {{
 printf 'mv:%s\\n' "$*" >> "$fixture/operations"
 /usr/bin/mv "$@" || return $?
 printf committed > "$fixture/rc-committed"
}}
sha256sum() {{
 if [ -e "$fixture/rc-committed" ] && [ "${{1-}}" = "$fixture{target}" ] && [ {slow_read} = payload_hash ]; then
  printf expired > "$fixture/expired"
 fi
 case "${{1-}}" in
  "$fixture/system/bin/camera-gui") printf '{peer.GUI_SHA256}  %s\\n' "$1";;
  *) /usr/bin/sha256sum "$@";;
 esac
}}
ls() {{
 if [ -e "$fixture/rc-committed" ] && [ "$2" = "$fixture{target}" ] && [ {slow_read} = payload_label ]; then
  printf expired > "$fixture/expired"
 fi
 printf 'u:object_r:system_file:s0 %s\\n' "$2"
}}
'''
    result = fixture.run_script(
        module.render_recovery(fixture.saved, fixture.saved_sha, fixture.q), boundary_hook=hook
    )
    assert_failed_without_success(fixture, result)
    assert_owned_mount_and_lock_released(fixture)
    assert fixture.path(peer.boot.TARGET).read_bytes() == fixture.original
    targets = list(fixture.payloads)
    boundary = targets.index(target)
    for index, path in enumerate(targets):
        if index < boundary:
            assert not fixture.path(path).exists()
        else:
            assert fixture.path(path).read_bytes() == fixture.payloads[path]
    operations = fixture.path("/operations").read_text().splitlines()
    assert [line for line in operations if line.startswith("rm:")] == [
        "rm:" + fixture.posix + path for path in targets[:boundary]
    ]
    work_path = "/system/.x2dii-menu-recovery-" + fixture.q["recovery_nonce"]
    work = fixture.path(work_path)
    assert work.is_dir(), "expired identity must not authorize workspace removal"
    assert not (work / "camera-gui.rc.restore").exists()
    assert "rmdir:" + fixture.posix + work_path not in operations
    assert operations[-2:] == [
        "mount:-o remount,ro " + fixture.posix + "/system",
        "rmdir:" + fixture.posix + "/tmp/x2dii-menu-install.lock",
    ]


@pytest.mark.parametrize("gui_read", (1, 2), ids=("before-lock", "before-stop"))
def test_identity_tail_rechecks_lease_after_final_executable_hash(recovery_fixture, gui_read):
    fixture = recovery_fixture
    module = fixture.recovery()
    hook = clock_hook(fixture) + f'''
boundary() {{ [ "$1" != lock ] || printf acquired > "$fixture/lock-acquired"; }}
getprop() {{
 n=0
 [ ! -e "$fixture/gui-read-count" ] || n=$(cat "$fixture/gui-read-count")
 n=$((n+1))
 printf '%s\\n' "$n" > "$fixture/gui-read-count"
 [ "$n" != {gui_read} ] || printf armed > "$fixture/expire-on-gui-hash"
 printf 'stopped\\n'
}}
sha256sum() {{
 case "${{1-}}" in
  "$fixture/system/bin/camera-gui")
   [ ! -e "$fixture/expire-on-gui-hash" ] || printf expired > "$fixture/expired"
   printf '{peer.GUI_SHA256}  %s\\n' "$1";;
  *) /usr/bin/sha256sum "$@";;
 esac
}}
'''
    result = fixture.run_script(
        module.render_recovery(fixture.saved, fixture.saved_sha, fixture.q), boundary_hook=hook
    )
    assert_failed_without_success(fixture, result)
    fixture.assert_intact()
    assert_owned_mount_and_lock_released(fixture)
    assert fixture.path("/lock-acquired").exists() is (gui_read == 2)
    operations_path = fixture.path("/operations")
    operations = operations_path.read_text().splitlines() if operations_path.exists() else []
    assert operations == (
        ["rmdir:" + fixture.posix + "/tmp/x2dii-menu-install.lock"] if gui_read == 2 else []
    )


def test_expired_lease_keeps_same_runtime_safety_cleanup_available(recovery_fixture):
    fixture = recovery_fixture
    module = fixture.recovery()
    hook = clock_hook(fixture) + '''
boundary() { [ "$1" != remount ] || printf expired > "$fixture/expired"; }
'''
    result = fixture.run_script(
        module.render_recovery(fixture.saved, fixture.saved_sha, fixture.q), boundary_hook=hook
    )
    assert_failed_without_success(fixture, result)
    fixture.assert_intact()
    assert_owned_mount_and_lock_released(fixture)
    assert fixture.path("/operations").read_text().splitlines() == [
        "stop:camera-gui",
        "mount:-o remount,rw " + fixture.posix + "/system",
        "mount:-o remount,ro " + fixture.posix + "/system",
        "rmdir:" + fixture.posix + "/tmp/x2dii-menu-install.lock",
    ]
    assert not list(fixture.path("/system").glob(".x2dii-menu-recovery-*"))


@pytest.mark.parametrize(
    "relative_dependency", ("tools/boot_config.py", "tools/qt_unit.py", "tests/test_peer_install.py")
)
def test_recovery_build_subject_binds_dependency_read_bytes(
    recovery_fixture, monkeypatch, relative_dependency
):
    fixture = recovery_fixture
    module = fixture.recovery()
    dependency = module.ROOT / relative_dependency
    original_read = Path.read_bytes
    original_bytes = dependency.read_bytes()
    baseline = module.build_subject_sha256(fixture.saved, fixture.saved_sha)
    mutated_reads = []

    def read_with_fault(path):
        raw = original_read(path)
        if path == dependency:
            mutated_reads.append(path)
            return raw + b"\n# host-only read-boundary fault\n"
        return raw

    with monkeypatch.context() as patch:
        patch.setattr(Path, "read_bytes", read_with_fault)
        changed = module.build_subject_sha256(fixture.saved, fixture.saved_sha)
    assert mutated_reads == [dependency]
    assert changed != baseline
    assert dependency.read_bytes() == original_bytes
    assert module.build_subject_sha256(fixture.saved, fixture.saved_sha) == baseline
