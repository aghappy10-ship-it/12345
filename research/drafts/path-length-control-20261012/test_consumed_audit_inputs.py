"""Replay the existing public identity test for the newly consumed files.

No test body is substituted and no native audit or camera is executed.
Formal source remains frozen; missing dependencies must remain RED until the
reviewed explicit-input patch is actually applied after original diagnostics.
"""
import pytest

from tests.test_current_audit_lifetime import (
    test_actual_host_model_copy_bytes_participate_in_public_build_identity as original_body,
)


@pytest.mark.parametrize("relative", (
    "build/peer-route-review-20261011-host-fixed/run_audit.py",
    "build/peer-route-review-20261011-host-fixed/launch_admin_audit_once.py",
    "build/peer-route-review-20261012-short-root/run_audit.py",
), ids=("actual-host-fixed-runner", "actual-host-fixed-launcher", "successor-short-root-runner"))
def test_consumed_entry_bytes_participate_in_public_build_identity(monkeypatch, relative):
    original_body(monkeypatch, relative)
