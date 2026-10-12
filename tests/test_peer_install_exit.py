"""Actual rendered phase results cannot succeed before owned cleanup completes."""
import pytest


PHASES = (
    ('install-files.sh', 'X2DII_FILES_INSTALLED_NOT_ACTIVATED'),
    ('activate-boot.sh', 'X2DII_BOOT_CONFIG_ACTIVATED_GUI_LEFT_STOPPED'),
    ('restore-boot.sh', 'X2DII_OFFICIAL_RC_RESTORED_OWNED_FILES_REMOVED'),
)


@pytest.mark.parametrize('phase,marker', PHASES)
@pytest.mark.parametrize('cleanup_fails', [False, True])
def test_phase_success_marker_requires_completed_owned_cleanup(phase, marker, cleanup_fails):
    # Reuse existing real shell/filesystem seam, without collecting its class
    # twice. Device identity, service, labels and mount operations are substitutes.
    from tests.test_peer_install import PeerInstallTests
    PeerInstallTests.setUpClass()
    fixture = PeerInstallTests()
    fixture.setUp()
    try:
        fixture.shell_fixture()
        for prior, _ in PHASES:
            if prior == phase:
                break
            result = fixture.run_script(prior)
            assert result.returncode == 0, result.stderr
        if cleanup_fails:
            # Only the external rmdir operation fails; production phase body,
            # EXIT trap, writes and ordering execute unchanged.
            fixture.scripts[phase] = 'rmdir() { return 73; }\n' + fixture.scripts[phase]
        result = fixture.run_script(phase)
        if cleanup_fails:
            assert result.returncode == 73
            assert marker.encode() not in result.stdout
            assert b'X2DII_SCRIPT_FAILED:73' in result.stderr
            assert (fixture.root / 'tmp/x2dii-menu-install.lock').is_dir()
        else:
            assert result.returncode == 0, result.stderr
            assert result.stdout.splitlines().count(marker.encode()) == 1
            assert not (fixture.root / 'tmp/x2dii-menu-install.lock').exists()
        assert (fixture.root / 'proc/mounts').read_text() == fixture.mount_line
    finally:
        fixture.tearDown()
