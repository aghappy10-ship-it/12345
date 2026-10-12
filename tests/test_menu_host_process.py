"""Real closed C# entry compilation; no native entry is admitted or replaced."""
from datetime import datetime, timezone
import subprocess
from unittest import mock

import pytest

from tests.test_release_lifecycle import installer
from tests.test_prepared_menu_transport import ready_case
from tools import menu_content_transport as content, menu_preplacement_transport as placement


@pytest.mark.parametrize("kind", ("code", "ready"))
def test_fixed_preparation_child_compiles_and_refuses_before_native_io(installer, kind):
    from tools.menu_host_process import FixedPreparedHost
    ready, _, epoch, _ = ready_case(installer)
    preparation = ready.code_preparation if kind == "code" else ready
    launch = datetime.fromtimestamp(preparation.session.observed_epoch, timezone.utc)
    source = content.review_preparation_host_source(preparation, launch)
    host = FixedPreparedHost(preparation, launch)
    child = host.start("preparation", source)
    path = child.source_path
    try:
        assert child.stdin is not None and child.stdout is not None and child.stderr is not None
        stdout, stderr = child.communicate(timeout=30)
        assert type(stdout) is bytes and type(stderr) is bytes
        assert child.returncode != 0
        assert b"CONTENT_SOURCE_NOT_QUALIFIED" in stderr
        assert b"X2DII_CONTENT_NEED:" not in stdout
        assert not path.exists()
    finally:
        child.close()
    with pytest.raises(ValueError, match="repeated|sequence"):
        host.start("preparation", source)


def test_fixed_adapter_rejects_changed_or_admitted_source_before_popen(installer):
    from tools.menu_host_process import FixedPreparedHost
    ready, _, epoch, _ = ready_case(installer)
    launch = datetime.fromtimestamp(epoch, timezone.utc)
    original = content.review_preparation_host_source(ready, launch)
    for source in (original + "\n// changed", original.replace("ContentQualified = false", "ContentQualified = true")):
        host = FixedPreparedHost(ready, launch)
        with mock.patch("tools.menu_host_process.subprocess.Popen", side_effect=AssertionError("child started")):
            with pytest.raises(ValueError, match="fixed generated source"):
                host.start("preparation", source)


def test_fixed_adapter_refuses_wrong_phase_and_preserves_single_attempt(installer):
    from tools.menu_host_process import FixedPreparedHost
    ready, _, epoch, _ = ready_case(installer)
    launch = datetime.fromtimestamp(epoch, timezone.utc)
    host = FixedPreparedHost(ready, launch)
    with mock.patch("tools.menu_host_process.subprocess.Popen", side_effect=OSError("spawn failed")):
        with pytest.raises(ValueError, match="sequence"):
            host.start("menu-preplacement", placement.review_host_source(installer.manifest,
                ready.raw_session, launch_started_utc=launch))
        with pytest.raises(OSError, match="spawn failed"):
            host.start("preparation", content.review_preparation_host_source(ready, launch))
        with pytest.raises(ValueError, match="repeated|sequence|failed"):
            host.start("preparation", content.review_preparation_host_source(ready, launch))


def test_stable_content_adapter_accepts_only_its_exact_source(installer):
    from tools.menu_host_process import FixedContentHost
    ready, _, epoch, _ = ready_case(installer)
    launch = datetime.fromtimestamp(epoch, timezone.utc)
    plan, session = ready.parent_plan, content.stage.plan_raw_session_staging(
        ready.parent_plan, installer.manifest, ready.raw_session)
    host = FixedContentHost(plan, session, launch)
    source = content.review_content_host_source(plan, session, launch)
    child = host.start("stable-content", source)
    try:
        out, err = child.communicate(timeout=30)
        assert child.returncode != 0 and b"CONTENT_SOURCE_NOT_QUALIFIED" in err
        assert not out
    finally:
        child.close()
