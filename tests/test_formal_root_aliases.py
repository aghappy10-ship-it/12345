"""Public formal root checks with existing offline fixtures, never authority."""
from copy import deepcopy

import pytest

from tests.test_role_deployment_entry import formal_context
from tests.test_release_lifecycle import installer, recovery_fixture
from tests.test_recovery_role_v2 import role_recovery_context
from tools import prepare_peer_install as peer, prepare_peer_recovery as recovery


NONCANONICAL_ROOTS = ("/system//etc", "//system", "/system/etc/init/", "/")


@pytest.mark.parametrize("root", NONCANONICAL_ROOTS)
def test_formal_qualification_rejects_noncanonical_init_roots(formal_context, installer, root):
    manifest, context = formal_context
    context["init_scan_roots"].append(root)
    # Bind the existing structural proofs to this exact context so an unrelated
    # later subject mismatch cannot masquerade as successful root rejection.
    installer.q = deepcopy(context)
    qualification = installer.validated_shape_fixture()
    with pytest.raises(ValueError, match="invalid init scan root"):
        peer.validate_qualification(manifest, qualification)


def test_formal_qualification_accepts_legitimate_vendor_init_root(formal_context, installer):
    manifest, context = formal_context
    context["init_scan_roots"].append("/vendor/etc/init")
    installer.q = deepcopy(context)
    qualification = installer.validated_shape_fixture()
    peer.validate_qualification(manifest, qualification)


@pytest.mark.parametrize("root", NONCANONICAL_ROOTS)
def test_formal_recovery_rejects_noncanonical_init_roots(recovery_fixture, root):
    _, digest, context = role_recovery_context(recovery_fixture)
    context["init_scan_roots"].append(root)
    with pytest.raises(ValueError, match="invalid init scan root"):
        recovery.render_recovery(recovery_fixture.saved, digest, context)


def test_formal_recovery_accepts_legitimate_vendor_init_root(recovery_fixture):
    _, digest, context = role_recovery_context(recovery_fixture)
    context["init_scan_roots"] = ["/system/etc/init", "/vendor/etc/init"]
    source = recovery.render_recovery(recovery_fixture.saved, digest, context)
    assert "X2DII_BOOT_BOUNDARY_REQUEST:restore" in source
