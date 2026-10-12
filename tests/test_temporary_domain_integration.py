"""Real local file handoff between the two rendered roles, not USB execution.

The same guarded filesystem carries all four worker outputs into the maintenance
renderer. OS identities, labels, mounts and services remain explicit fixtures.
No transport, permission grant, removal qualification or camera result is implied.
"""
from tests.test_release_lifecycle import installer
from tests.test_temporary_menu_files import run_worker
from tests.test_temporary_menu_session import (
    prepare_maintenance, run_temporary, temporary_os_boundary,
)
from tools import prepare_peer_install as peer


def payload_snapshot(instance, *, count=4):
    result = {}
    for entry in instance.manifest["candidate"]["files"][:count]:
        path = instance.root / entry["target"].lstrip("/")
        observed = path.stat()
        result[entry["target"]] = (
            observed.st_ino, observed.st_size, observed.st_mtime_ns,
            peer.sha(path.read_bytes()),
        )
    return result


def test_su_written_four_files_reach_maintenance_without_fixture_replacement(installer):
    for index in range(4):
        outcome = run_worker(installer, index=index, setup=index == 0)
        assert outcome.returncode == 0, (index, outcome.stdout, outcome.stderr)
        assert f"file_index={index}\n".encode() in outcome.stdout
        assert b"maintenance_boundaries=UNCONNECTED" in outcome.stdout
        assert (installer.root / "gui-service-state").read_text() == "running"
    before = payload_snapshot(installer)
    for entry in installer.manifest["candidate"]["files"]:
        assert before[entry["target"]][-1] == entry["sha256"]
    # Only switch the modelled calling identity/proc surface. Re-creating the
    # payload here would conceal an incompatible source-to-target handoff.
    prepare_maintenance(installer, preplace=False)
    assert payload_snapshot(installer) == before
    outcome = run_temporary(installer, temporary_os_boundary(installer))
    assert outcome.returncode == 0, (outcome.stdout, outcome.stderr)
    assert b"X2DII_TEMPORARY_CHILD_LOADED_NOT_FEATURE_VERIFIED" in outcome.stdout
    assert b"X2DII_ORIGINAL_GUI_RESTORED_EXTENSION_FILES_RETAINED_PENDING_SU_REMOVAL" in outcome.stdout
    assert b"COVERAGE_UNVERIFIED_NOT_REMOVAL_AUTHORITY" in outcome.stdout
    assert payload_snapshot(installer) == before
    assert (installer.root / "gui-service-state").read_text() == "running"
    assert (installer.root / "proc/mounts").read_text() == installer.mount_line
    assert (installer.root / "system/etc/init/camera-gui.rc").read_bytes() == peer.boot.STOCK.read_bytes()
    assert "rm:" not in (installer.root / "operations").read_text()


def test_incomplete_fourth_file_handoff_does_not_stop_original_gui(installer):
    for index in range(3):
        outcome = run_worker(installer, index=index, setup=index == 0)
        assert outcome.returncode == 0, (index, outcome.stdout, outcome.stderr)
    before = payload_snapshot(installer, count=3)
    for entry in installer.manifest["candidate"]["files"][:3]:
        assert before[entry["target"]][-1] == entry["sha256"]
    original_rc = installer.root / "system/etc/init/camera-gui.rc"
    rc_before = original_rc.read_bytes()
    assert rc_before == peer.boot.STOCK.read_bytes()
    hook = r'''
cat() {
 case "$1" in
  */X2d2MenuPage.qml) printf partial; return 9;;
  *) /usr/bin/cat "$@";;
 esac
}
'''
    outcome = run_worker(installer, index=3, setup=False, hook=hook)
    assert outcome.returncode != 0, (outcome.stdout, outcome.stderr)
    assert b"schema=x2dii-one-file-preplacement-v1" not in outcome.stdout
    assert payload_snapshot(installer, count=3) == before
    assert original_rc.read_bytes() == rc_before
    assert (installer.root / "gui-service-state").read_text() == "running"
    assert not (installer.root / "system/etc/X2d2MenuPage.qml").exists()
    partials = list((installer.root / "system/etc").glob(".x2dii-preplace-*-3"))
    assert len(partials) == 1 and partials[0].read_bytes() == b"partial"
    prepare_maintenance(installer, preplace=False)
    assert payload_snapshot(installer, count=3) == before
    assert original_rc.read_bytes() == rc_before
    outcome = run_temporary(installer, temporary_os_boundary(installer))
    assert outcome.returncode == 33, (outcome.stdout, outcome.stderr)
    assert b"CHILD_LOADED" not in outcome.stdout
    assert not (installer.root / "operations").exists()
    assert (installer.root / "gui-service-state").read_text() == "running"
    assert (installer.root / "proc/mounts").read_text() == installer.mount_line
    assert partials[0].read_bytes() == b"partial"
    assert payload_snapshot(installer, count=3) == before
    assert original_rc.read_bytes() == rc_before
