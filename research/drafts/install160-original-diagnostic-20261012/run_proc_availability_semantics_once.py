"""NOT_RUN: tiny native shell controls confined to PeerInstallTests temp roots.

Never run during the fixed complete audit. Natural audit completion, its exact
collection/XML/source and four Windows lifetimes must first pass the existing
gate. That gate's original-actor sampler is explicitly NOT EXECUTED here: this
control only executes the captured sampler after every /proc root is remapped
by the existing OS fixture seam. No real PID stat is read, actor is signalled,
original diagnostic is run, or camera behavior/installation is qualified.
"""
import hashlib
import json
from pathlib import Path
import subprocess
from unittest import mock


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SHARED = ROOT / "build/receipt360-original-diagnostic-20261012/run_original_sender_once.py"
SHARED_SHA = "59c31985f48fab2723cacc5c6f3996c6aa36d2e48a0fb5f9abd4ecae1eddecbf"
RESULT = HERE / "native-proc-availability-result-20261012.json"
CASES = ("all-absent", "root-missing", "self-stat-missing",
         "pid-directory-stat-missing", "pid-directory-symlink")


class SamplerCaptured(RuntimeError):
    pass


def main():
    shared_raw = SHARED.read_bytes()
    if hashlib.sha256(shared_raw).hexdigest() != SHARED_SHA:
        raise ValueError("native control shared source differs")
    context = {"__name__": "_native_proc_semantic_control", "__file__": str(SHARED)}
    exec(compile(shared_raw, str(SHARED), "exec"), context)
    if RESULT.exists():
        raise FileExistsError("native semantic result already exists")
    runner = context["load_reviewed_runner"]()
    # Exact existing completion checks, but no original actor stop execution.
    context["require_original_actor_stop"] = lambda failure: {
        "scope": "NOT_EXECUTED_ORIGINAL_ACTOR_SAMPLE_NATIVE_CONTROL_ONLY"}
    admission, _, _, failure_raw = context["require_completed_audit"](runner)
    # Reuse the exact verified bytes, not a second mutable path read.
    context = {"__name__": "_capture_remap_only", "__file__": str(SHARED)}
    exec(compile(shared_raw, str(SHARED), "exec"), context)
    captured = []

    def capture(command, **options):
        captured.append((command, options))
        raise SamplerCaptured("captured before any real /proc command execution")

    with mock.patch.object(subprocess, "run", side_effect=capture):
        try:
            context["require_original_actor_stop"](json.loads(failure_raw))
        except SamplerCaptured:
            pass
        else:
            raise AssertionError("sampler capture boundary not reached")
    if len(captured) != 1:
        raise AssertionError("not exactly one captured sampler")
    command, options = captured[0]
    if options != {"capture_output": True, "text": True, "timeout": 8}:
        raise AssertionError("captured sampler contract differs")

    from tests.test_peer_install import PeerInstallTests, SH
    PeerInstallTests.setUpClass()
    observations = []
    for case in CASES:
        fixture = PeerInstallTests(methodName="runTest")
        fixture.setUp()
        try:
            fixture.posix = subprocess.run([str(SH), "-c", 'cygpath -u "$1"',
                "proc-semantic-fixture", str(fixture.root)], capture_output=True,
                text=True, check=True, timeout=8).stdout.strip()
            fixture.core_hashes, fixture.core_links = {}, {}
            setup = ""
            if case != "root-missing":
                setup = 'mkdir -p "/proc/$$" || exit 88\n'
                if case != "self-stat-missing":
                    # Synthetic self stat uses only runtime $$; no real stat read.
                    setup += ('builtin printf \'%s (sampler) S ' + "0 " * 18 +
                              '1 0\\n\' "$$" > "/proc/$$/stat" || exit 88\n')
                if case == "pid-directory-stat-missing":
                    setup += 'mkdir "/proc/1696" || exit 88\n'
                elif case == "pid-directory-symlink":
                    setup += ('mkdir "/proc/symlink-target" || exit 88\n'
                              '/usr/bin/ln -s "/proc/symlink-target" "/proc/1696" || exit 88\n'
                              '[ -L "/proc/1696" ] || exit 88\n')
            fixture.scripts["proc-control"] = (
                "# SESSION_DATA_PARSER_BEGIN\n# SESSION_DATA_PARSER_END\n" + setup +
                'set -- 1696 803676787 2414 803702039 8389 803908014\n' + command[2])

            def execute_remapped(source, args):
                # The fixture seam must have rewritten all literal /proc roots.
                if '"/proc/' in source or " /proc" in source:
                    raise AssertionError("real /proc root remained in control source")
                return subprocess.run([str(SH), "-s", "--", *args],
                    input=source.encode("ascii"), capture_output=True, timeout=8)

            result = fixture.run_script("proc-control", process_runner=execute_remapped)
            stdout, stderr = result.stdout.decode("ascii"), result.stderr.decode("ascii")
            rows = stdout.splitlines()
            if stderr:
                raise AssertionError("native control stderr: " + stderr)
            if case in ("root-missing", "self-stat-missing"):
                if result.returncode != 87 or any("status=absent" in row for row in rows):
                    raise AssertionError("unavailable proc/self promoted absence: " + case)
            else:
                expected = {"all-absent": "absent", "pid-directory-stat-missing": "read_failed",
                            "pid-directory-symlink": "path_unknown"}[case]
                if (result.returncode != 0 or len(rows) != 10
                        or not rows[3].endswith("status=" + expected)
                        or not rows[1].startswith("PROC_ANCHOR ")
                        or not rows[-2].startswith("PROC_ANCHOR ")):
                    raise AssertionError("native exact-name branch differs: " + case)
                if any(not rows[index].endswith("status=absent") for index in (5, 7)):
                    raise AssertionError("unmatched exact PID-name patterns counted as members")
            observations.append({"case": case, "returncode": result.returncode,
                                 "stdout_text": stdout, "stderr_text": stderr})
        finally:
            fixture.tearDown()
    report = {"scope": "native_host_fixture_semantics_not_actor_stop_or_camera_proof",
              "status": "PASS", "installable": False, "shared_sha256": SHARED_SHA,
              "audit_completion_admission": admission, "cases": observations}
    runner["write_output"](RESULT, (json.dumps(report, indent=2) + "\n").encode())
    print("Five native remapped fixture semantics controls passed; not real actor-stop proof.")


if __name__ == "__main__":
    main()
