"""Saved observation conversion, not a live record or permission fixture."""
from copy import deepcopy
from datetime import datetime
import json

import pytest

from tests.test_release_lifecycle import installer
from tools import prepare_peer_install as peer, session_context as sc


def saved_observation(installer):
    # Explicit shape fixture; changing this marker does not authenticate it.
    q = deepcopy(installer.q)
    q["runtime_observation"]["test_fixture_only"] = False
    q.pop("synthetic", None)
    q["observer"].update(domain="u:r:hbl_camera_service:s0", exe_target="/system/bin/camera-test")
    return q


def convert(installer, q):
    from tools.menu_first_validation import saved_menu_session
    raw = json.dumps(q).encode()
    return saved_menu_session(installer.manifest, raw, expected_sha256=peer.sha(raw))


def test_saved_conversion_uses_existing_exact_fields_without_renewing_time(installer):
    q = saved_observation(installer)
    result = convert(installer, q)
    values = sc.decode_session(result.raw_session)
    expected = sc.decode_session(peer.session_data(installer.manifest, q))
    expected.update(kind="menu_validation", purpose="temporary_menu_validation",
                    action="run_and_restore", candidate_sha256=installer.manifest["candidate_sha256"])
    assert values == expected
    assert values["observed_epoch"] == int(datetime.fromisoformat(q["observed_utc"]).timestamp())
    assert result.saved_observation_sha256 == peer.sha(json.dumps(q).encode())
    assert result.raw_session_sha256 == peer.sha(result.raw_session)
    assert result.installable is False and result.authorization_granted is False


@pytest.mark.parametrize("field", ("runtime_observation", "observed_utc", "metadata", "observer", "slot_readback"))
def test_saved_conversion_reports_missing_input_without_filling_it(installer, field):
    q = saved_observation(installer)
    del q[field]
    with pytest.raises(ValueError, match=field):
        convert(installer, q)


@pytest.mark.parametrize("fault", ("fixture", "synthetic", "su-observer", "naive-time", "context-mismatch", "bad-candidate", "bad-hash", "duplicate-json"))
def test_saved_conversion_rejects_unusable_or_changed_record(installer, fault):
    from tools.menu_first_validation import saved_menu_session
    q = saved_observation(installer)
    manifest = deepcopy(installer.manifest)
    if fault == "fixture":
        q["runtime_observation"]["test_fixture_only"] = True
    elif fault == "synthetic":
        q["synthetic"] = True
    elif fault == "su-observer":
        q["observer"]["domain"] = "u:r:su:s0"
    elif fault == "naive-time":
        q["observed_utc"] = "2026-10-05T12:00:00"
    elif fault == "context-mismatch":
        q["boot_id"] = "33333333-4444-4555-8666-777777777777"
    elif fault == "bad-candidate":
        manifest["candidate_sha256"] = "f" * 64
    raw = json.dumps(q).encode()
    if fault == "duplicate-json":
        raw = b'{"observed_utc":"discarded",' + raw[1:]
    digest = "0" * 64 if fault == "bad-hash" else peer.sha(raw)
    with pytest.raises(ValueError):
        saved_menu_session(manifest, raw, expected_sha256=digest)
