"""Independent recovery publication keeps its own lease and local boundary."""
from datetime import datetime, timedelta

import pytest

from tests.test_release_lifecycle import recovery_fixture


def test_recovery_lease_expiring_during_checks_is_refused_at_completion(recovery_fixture, monkeypatch):
    fixture = recovery_fixture
    recovery = fixture.recovery()
    q = fixture.structural_qualification()
    observed = datetime.fromisoformat(q["observed_utc"])

    class SteppedClock(datetime):
        calls = 0

        @classmethod
        def now(cls, tz=None):
            cls.calls += 1
            return observed + timedelta(seconds=0 if cls.calls == 1 else 601)

    monkeypatch.setattr(recovery, "datetime", SteppedClock)
    with pytest.raises(ValueError, match="expired during recovery qualification"):
        recovery.validate_qualification(fixture.saved, fixture.saved_sha, q)


def test_same_render_recovery_identity_uses_the_actual_program_bytes(recovery_fixture):
    fixture = recovery_fixture
    recovery = fixture.recovery()
    source = recovery.render_recovery(fixture.saved, fixture.saved_sha, fixture.q)
    default = recovery.build_subject_sha256(fixture.saved, fixture.saved_sha)
    assert recovery.build_subject_sha256(fixture.saved, fixture.saved_sha, rendered_script=source) == default
    assert recovery.build_subject_sha256(fixture.saved, fixture.saved_sha,
                                        rendered_script=source + "\n# changed source\n") != default


def test_recovery_build_identity_binds_v2_session_test_bytes(recovery_fixture, monkeypatch):
    from pathlib import Path

    fixture = recovery_fixture
    recovery = fixture.recovery()
    target = recovery.ROOT / "tests/test_session_context_v2.py"
    original_read = Path.read_bytes
    preserved = original_read(target)
    before = recovery.build_subject_sha256(fixture.saved, fixture.saved_sha)

    def changed_input(path):
        raw = original_read(path)
        return raw + b"\n# changed session v2 test input\n" if path == target else raw

    # Filesystem-boundary fault only; never edit the actual shared test source.
    monkeypatch.setattr(Path, "read_bytes", changed_input)
    assert recovery.build_subject_sha256(fixture.saved, fixture.saved_sha) != before
    assert original_read(target) == preserved


@pytest.mark.parametrize("name", ("session-context.data", "x2dii-menu-content.tar", "members.json"))
def test_unqualified_recovery_directory_cannot_mix_retained_delivery_files(recovery_fixture, name):
    fixture = recovery_fixture
    recovery = fixture.recovery()
    output = fixture.root / "source-with-stale-files"
    output.mkdir()
    raw = b"SYNTHETIC STALE OUTPUT; NOT A CANDIDATE"
    (output / name).write_bytes(raw)
    with pytest.raises(ValueError, match="recovery output contains forbidden"):
        recovery.prepare(output, fixture.saved, fixture.saved_sha)
    assert (output / name).read_bytes() == raw
    assert not (output / "peer-recovery-source.json").exists()
