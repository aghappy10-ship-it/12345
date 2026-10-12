"""Mutation checks for immutable inheritance and non-release inventory claims."""
from __future__ import annotations

import copy
import json

import pytest

from tools import regression_manifest as registry


@pytest.fixture(scope="module")
def source_bytes():
    return registry.SOURCE_PATH.read_bytes()


@pytest.fixture
def manifest(source_bytes):
    return registry.build_manifest(source_bytes)


def test_real_saved_inventory_preserves_every_historical_goal(source_bytes):
    original = registry.load_frozen(source_bytes)
    saved = registry.strict_json(registry.MANIFEST_PATH.read_bytes())
    assert saved["goals"][:352] == original["goals"]
    expected_count = registry.SOURCE_COUNT + len(registry.NEW_GOALS)
    assert [goal["id"] for goal in saved["goals"]] == [f"X2D-RG-{i:03d}" for i in range(1, expected_count + 1)]
    result = registry.validate_manifest(saved, source_bytes)
    assert result["inventory_valid"] is True
    assert result["goal_count"] == expected_count
    assert result["pass_count"] == 0
    assert result["installable"] is False
    assert result["package_eligible"] is False
    # Schema v2 preserves the original seed while separately applying the
    # reviewed effective classification; this does not erase seed history.
    assert result["seed_applicability_counts"]["PENDING_REVIEW"] > 0
    assert result["applicability_counts"]["PENDING_REVIEW"] == 0
    assert result["machine_evidence_gaps"]


def test_generated_inventory_requires_paired_process_continuity_evidence(manifest):
    # Pin the actual saved registry before RG382 was appended, including its
    # per-goal applicability/evidence state; this is not live qualification.
    assert registry.digest(registry.canonical(manifest["goals"][:381])) == "acb041e302ff9d2e5978e121e6456e5bea851532732769490ffaf1c188c6cc84"
    prior_rows = {goal["id"]: manifest["applicability"][goal["id"]] for goal in manifest["goals"][:381]}
    assert registry.digest(registry.canonical(prior_rows)) == "c7128e0c694c232454104648537ff40545969b2c1d8934844be39fff08fb3ba4"
    goals = {goal["id"]: goal for goal in manifest["goals"]}
    assert "X2D-RG-382" in goals, "Process-continuity evidence requirement is missing"
    goal = goals["X2D-RG-382"]
    required = goal["required_behavior"] + " " + " ".join(goal["required_evidence"])
    for term in ("same-session pre/post", "process start", "after-only", "same numeric PID",
                 "reused PID", "unchanged binary", "changed boot", "paired exact lifetime"):
        assert term in required
    row = manifest["applicability"]["X2D-RG-382"]
    assert row["applicability"] == "APPLICABLE"
    assert row["evidence_status"] == "NOT_RUN"
    assert row["counts_as_pass"] is False and row["evidence_refs"] == []
    assert manifest["qualification"]["installable"] is False


@pytest.mark.parametrize('number,terms', [
    (386, ['600', 'same boot', 'start_ticks', 'cleanup', 'success marker', 'gui state unverified']),
    (387, ['hblloader', 'asynchronous', 'gil', 'missing', 'malformed', 'measured', 'supervisor']),
])
def test_recovery_and_async_fault_findings_remain_permanent(manifest, number, terms):
    assert registry.digest(registry.canonical(manifest['goals'][:385])) == '421e06344eabc31b699bb001c38faf4afbe7b93d2612954d0e458197354d45f0'
    previous = {goal['id']: manifest['applicability'][goal['id']] for goal in manifest['goals'][:385]}
    assert registry.digest(registry.canonical(previous)) == '6ed36dda3a62b7e5de1cfb3a2f4339412ee76c95f0ec8c35ed9f9c598ad140c8'
    goals = {goal['id']: goal for goal in manifest['goals']}
    key = f'X2D-RG-{number}'
    assert key in goals, 'Discovered defect lacks a permanent regression goal'
    text = registry.canonical(goals[key]).decode().lower()
    assert all(term in text for term in terms)
    assert len(goals[key]['required_evidence']) >= 5
    assert manifest['applicability'][key]['evidence_status'] == 'NOT_RUN'
    assert manifest['applicability'][key]['counts_as_pass'] is False


@pytest.mark.parametrize('number,terms', [
    (388, ['teardown', 'runtime', 'after', 'addition', 'perf_counter', 'gettickcount64']),
    (389, ['five', 'roundtrip', 'elf', 'self-consistent', 'partial', 'pending']),
    (390, ['install-files', 'activate-boot', 'restore-boot', 'cleanup', 'success', '73']),
])
def test_exit_evidence_and_payload_findings_are_append_only(manifest, number, terms):
    assert registry.digest(registry.canonical(manifest['goals'][:387])) == 'ca8751df350fc1a4e98938737b459f223ba3592085ef1a9d286d55707e6bc50e'
    previous = {goal['id']: manifest['applicability'][goal['id']] for goal in manifest['goals'][:387]}
    assert registry.digest(registry.canonical(previous)) == '25609bc64db25cd70d41adb09a25bfdfdf7bfce3e2a26e5c9db48ed757bb7e27'
    goals = {goal['id']: goal for goal in manifest['goals']}
    key = f'X2D-RG-{number}'
    assert key in goals, 'Discovered defect lacks a permanent regression goal'
    assert all(term in registry.canonical(goals[key]).decode().lower() for term in terms)
    assert len(goals[key]['required_evidence']) >= 5
    assert manifest['applicability'][key]['evidence_status'] == 'NOT_RUN'
    assert manifest['applicability'][key]['counts_as_pass'] is False


@pytest.mark.parametrize("change", ["space", "content", "truncation"])
def test_changed_frozen_bytes_fail_exact_pin(source_bytes, change):
    damaged = source_bytes + b" " if change == "space" else (source_bytes[:-1] if change == "truncation" else source_bytes.replace(b"Continuous-rate semantics", b"Changed semantics", 1))
    with pytest.raises(registry.RegistryError, match="SHA-256"):
        registry.build_manifest(damaged)


@pytest.mark.parametrize('number,terms', [
    (391, ['controlDrawer', 'visual tree', 'shortcut', 'pointer', 'preventSwipe', 'unload', 'failure']),
    (392, ['publication', 'run', 'global', 'preimage', 'retract', 'unknown', 'observations']),
    (393, ['600', 'runtime', 'namespace', 'start_ticks', 'stop', 'install-files', 'activate-boot', 'restore-boot']),
])
def test_outer_menu_publication_and_runtime_identity_findings_preserve_390(manifest, number, terms):
    assert registry.digest(registry.canonical(manifest['goals'][:390])) == 'eb048c78bb33304b9f8071fff91cad2d95120e18cef1e09efd904028cca7a982'
    previous = {goal['id']: manifest['applicability'][goal['id']] for goal in manifest['goals'][:390]}
    assert registry.digest(registry.canonical(previous)) == '9ded0cad9f50ba4318074c512a383f40b37d12670a33f5da7dbec552f2e8462d'
    goals = {goal['id']: goal for goal in manifest['goals']}
    key = f'X2D-RG-{number}'
    assert key in goals, 'Discovered gap lacks a permanent regression goal'
    text = registry.canonical(goals[key]).decode().lower()
    assert all(term.lower() in text for term in terms)
    assert len(goals[key]['required_evidence']) >= 5
    assert manifest['applicability'][key]['evidence_status'] == 'NOT_RUN'
    assert manifest['applicability'][key]['counts_as_pass'] is False
    assert manifest['applicability'][key]['evidence_refs'] == []


def test_host_static_exit_lifetime_finding_preserves_393(manifest):
    assert registry.digest(registry.canonical(manifest['goals'][:393])) == 'be1d133ef40ba538593da5f0001c542b14bffeac7723ca5f2d18958503a82c2d'
    previous = {goal['id']: manifest['applicability'][goal['id']] for goal in manifest['goals'][:393]}
    assert registry.digest(registry.canonical(previous)) == '29b34c7103bc872bccd21e85d58ffc61e1e1e3b5df5647d0571b6033255d7e84'
    goals = {goal['id']: goal for goal in manifest['goals']}
    assert 'X2D-RG-394' in goals
    text = registry.canonical(goals['X2D-RG-394']).decode().lower()
    for term in ('0x404eb', 'compilationunit', 'ctypes', 'qmlcleartyperegistrations',
                 'all engines', 'static exit', 'qquickwindow', 'not a candidate'):
        assert term in text
    assert len(goals['X2D-RG-394']['required_evidence']) >= 5
    assert manifest['applicability']['X2D-RG-394']['evidence_status'] == 'NOT_RUN'
    assert manifest['applicability']['X2D-RG-394']['counts_as_pass'] is False


def test_long_audit_short_lease_conflict_is_a_permanent_requirement(manifest):
    goals = {goal["id"]: goal for goal in manifest["goals"]}
    assert "X2D-RG-395" in goals
    text = registry.canonical(goals["X2D-RG-395"]).decode().lower()
    for term in ("865.99", "600", "build", "runtime", "lease", "data", "mixed", "nonce"):
        assert term in text
    row = manifest["applicability"]["X2D-RG-395"]
    assert row["evidence_status"] == "NOT_RUN" and row["counts_as_pass"] is False


@pytest.mark.parametrize("field", ["title", "origin", "required_behavior", "required_evidence"])
def test_weakening_any_inherited_field_fails(manifest, source_bytes, field):
    manifest["goals"][8][field] = [] if field == "required_evidence" else "not required"
    with pytest.raises(registry.RegistryError, match="goals"):
        registry.validate_manifest(manifest, source_bytes)


@pytest.mark.parametrize("change", ["missing", "duplicate", "reordered", "id", "extra"])
def test_no_goal_can_be_omitted_reordered_or_invented(manifest, source_bytes, change):
    if change == "missing":
        del manifest["goals"][15]
    elif change == "duplicate":
        manifest["goals"][15] = copy.deepcopy(manifest["goals"][14])
    elif change == "reordered":
        manifest["goals"][15], manifest["goals"][16] = manifest["goals"][16], manifest["goals"][15]
    elif change == "id":
        manifest["goals"][15]["id"] = "X2D-RG-999"
    else:
        manifest["goals"].append(copy.deepcopy(manifest["goals"][-1]))
    with pytest.raises(registry.RegistryError, match="goals"):
        registry.validate_manifest(manifest, source_bytes)


@pytest.mark.parametrize("field,value", [("pending_is_release_blocking", False), ("pass_reuse_across_hashes", True), ("append_only", 1)])
def test_policy_cannot_be_weakened_or_bool_retyped(manifest, source_bytes, field, value):
    manifest["policy"][field] = value
    with pytest.raises(registry.RegistryError, match="policy"):
        registry.validate_manifest(manifest, source_bytes)


@pytest.mark.parametrize("field", ["sha256", "goal_count", "last_id", "bytes"])
def test_source_binding_cannot_be_relearned_from_manifest(manifest, source_bytes, field):
    manifest["inherited_source"][field] = "untrusted"
    with pytest.raises(registry.RegistryError, match="inherited_source"):
        registry.validate_manifest(manifest, source_bytes)


def test_every_goal_has_an_independent_exact_hash_and_requirement_binding(manifest, source_bytes):
    assert set(manifest["applicability"]) == {goal["id"] for goal in manifest["goals"]}
    for goal in manifest["goals"]:
        row = manifest["applicability"][goal["id"]]
        assert row["goal_sha256"] == registry.digest(registry.canonical(goal))
        assert row["requirement_sha256"] == manifest["requirement_sha256"]
    del manifest["applicability"]["X2D-RG-200"]
    with pytest.raises(registry.RegistryError, match="applicability"):
        registry.validate_manifest(manifest, source_bytes)


@pytest.mark.parametrize("field,value", [("applicability", "OUT_OF_SCOPE"), ("evidence_status", "PASS"), ("counts_as_pass", True), ("goal_sha256", "0" * 64), ("requirement_sha256", "0" * 64), ("evidence_refs", ["old/pass.json"])])
def test_pending_cannot_be_promoted_or_excluded_in_manifest(manifest, source_bytes, field, value):
    assert manifest["applicability"]["X2D-RG-047"]["applicability"] == "PENDING_REVIEW"
    manifest["applicability"]["X2D-RG-047"][field] = value
    with pytest.raises(registry.RegistryError, match="applicability"):
        registry.validate_manifest(manifest, source_bytes)


def test_out_of_scope_is_never_a_capture_pass(manifest, source_bytes):
    for identifier in ("X2D-RG-001", "X2D-RG-019", "X2D-RG-023"):
        row = manifest["applicability"][identifier]
        assert row["applicability"] == "OUT_OF_SCOPE"
        assert row["evidence_status"] == "NOT_RUN"
        assert row["counts_as_pass"] is False
        assert row["evidence_refs"] == []
    assert registry.validate_manifest(manifest, source_bytes)["pass_count"] == 0


def test_rg047_scope_change_preserves_full_original_requirement(manifest, source_bytes):
    original = registry.load_frozen(source_bytes)
    assert manifest["goals"][46] == original["goals"][46]
    row = manifest["applicability"]["X2D-RG-047"]
    assert "Explicit scope change" in row["scope_reason"]
    assert "do not delete RG047" in row["scope_reason"]
    assert row["evidence_status"] == "NOT_RUN"


@pytest.mark.parametrize("field,value", [("installable", True), ("package_created", True), ("authorization_implemented", True), ("machine_evidence_gaps", []), ("out_of_scope_is_pass", True)])
def test_inventory_cannot_self_authorize_or_hide_live_gaps(manifest, source_bytes, field, value):
    manifest["qualification"][field] = value
    with pytest.raises(registry.RegistryError, match="qualification"):
        registry.validate_manifest(manifest, source_bytes)


@pytest.mark.parametrize("raw", [b'{"x":1,"x":2}', b'{"x":{"a":1,"a":2}}', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}', b'{'])
def test_ambiguous_json_is_rejected(raw):
    with pytest.raises(registry.RegistryError):
        registry.strict_json(raw)


def test_builder_does_not_mutate_shared_source_or_definitions(source_bytes):
    first = registry.build_manifest(source_bytes)
    first["goals"][0]["required_evidence"].clear()
    first["goals"][-1]["required_evidence"].clear()
    first["requirement_contract"]["features"].clear()
    second = registry.build_manifest(source_bytes)
    assert second["goals"][0]["required_evidence"]
    assert second["goals"][-1]["required_evidence"]
    assert second["requirement_contract"]["features"]


def test_new_menu_requirements_are_explicit_and_local_only(manifest):
    new = {goal["id"]: goal for goal in manifest["goals"][352:]}
    assert set(new) == {f"X2D-RG-{i}" for i in range(353, registry.SOURCE_COUNT + len(registry.NEW_GOALS) + 1)}
    assert "count" in new["X2D-RG-353"]["required_behavior"]
    assert "6.8.2" in new["X2D-RG-354"]["required_behavior"]
    assert "66" in new["X2D-RG-354"]["required_behavior"]
    assert "byte-identical" in new["X2D-RG-355"]["required_behavior"]
    assert "physical keys" in new["X2D-RG-356"]["required_behavior"]
    assert "installation approval" in new["X2D-RG-357"]["required_behavior"]
    assert all(manifest["applicability"][identifier]["evidence_status"] == "NOT_RUN" for identifier in new)


def test_native_tcp_record_goal_preserves_prior_382_and_requires_terminal_evidence(manifest):
    assert registry.digest(registry.canonical(manifest['goals'][:382])) == 'ba09f0240acc9ac684f55ce926118d7c69c7952a43dce47277465fa90ead2d78'
    previous = {key: value for key, value in manifest['applicability'].items()
                if int(key.rsplit('-', 1)[1]) <= 382}
    assert registry.digest(registry.canonical(previous)) == '3619262d0b3eb3732db0963b8186e65e927a64076c23ae75bc1fd6438f94a962'
    goals = {goal['id']: goal for goal in manifest['goals']}
    assert 'X2D-RG-383' in goals
    goal = goals['X2D-RG-383']
    text = registry.canonical(goal).decode('utf-8').lower()
    for term in ('1024', '260', '236', 'function 1', 'body', 'padding',
                 'active', 'nonce', 'truncation', '3944', 'no automatic retry'):
        assert term in text
    assert len(goal['required_evidence']) >= 6
    row = manifest['applicability']['X2D-RG-383']
    assert row['applicability'] == 'APPLICABLE'
    assert row['evidence_status'] == 'NOT_RUN' and row['counts_as_pass'] is False
    assert row['evidence_refs'] == []


@pytest.mark.parametrize('number,terms', [
    (384, ('cleanup', 'validated prefix', 'receive-limit', 'source attribution', 'reopening', 'independently revalidate')),
    (385, ('cold boot', 'recovery-only', 'saved candidate', 'current boot', 'original backup', 'no installation approval')),
])
def test_evidence_and_cold_boot_recovery_goals_preserve_previous_383(manifest, number, terms):
    assert registry.digest(registry.canonical(manifest['goals'][:383])) == 'db4f04208b0bcd4e21f2224fa90077b3d81e476bf665363e221f3ac745b3f2ea'
    prior = {goal['id']: manifest['applicability'][goal['id']] for goal in manifest['goals'][:383]}
    assert registry.digest(registry.canonical(prior)) == '760c69354a43f64f92a625d4dfa8a782d4c63c437f2671eb6209cb2c4318a784'
    goals = {goal['id']: goal for goal in manifest['goals']}
    key = f'X2D-RG-{number}'
    assert key in goals, 'Discovered defect lacks a permanent regression goal'
    text = registry.canonical(goals[key]).decode('utf-8').lower()
    assert all(term in text for term in terms)
    assert len(goals[key]['required_evidence']) >= 5
    assert manifest['applicability'][key]['evidence_status'] == 'NOT_RUN'
    assert manifest['applicability'][key]['counts_as_pass'] is False
    assert manifest['applicability'][key]['evidence_refs'] == []


def test_previous_menu_goals_are_preserved_exactly(manifest):
    pinned = {
        "X2D-RG-353": "daad6ece5966235cb148da6c93b21744e547cf4ddbda1812d1b8d186f00a45a0",
        "X2D-RG-354": "2815a0f289bcb327f9a44ccaafdabb7101a6ce12666a0f92a32bec1ebf129e5a",
        "X2D-RG-355": "32fed385417b345b74d8de71f5ccc53f24c0042182f19c4616a934c1d138a27d",
        "X2D-RG-356": "9e8f4fa8b36cb9a0571347c0a8d790b861aa35a59d7907c1ec794ea1d260dd6b",
        "X2D-RG-357": "8d05b8e9e422d2c4e52c1d7fc9a1db7c5019808aacd98bc349b11faed31779cd",
        "X2D-RG-358": "9d98b5bb52f24162d7e336987580ed0cec8b901859d76a0a74fc61611bc2b807",
        "X2D-RG-359": "9a293a0a5de6a830e1b5ac37ce0e548580586685a8f28bc80bd60594c9436cfd",
        "X2D-RG-360": "0db6fe88393c0dc5317041e37cec4c1b9f8f9054bee49090a48298448bae6bd7",
        "X2D-RG-361": "7db2d5d55fb440c90a5e2aeba44b60953939569393fe4c553f27779d50f17acc",
        "X2D-RG-362": "7a9da3743f4f90654d99040cc9c147024c8b343efbbe33a9dbac8f0c185ab8bc",
        "X2D-RG-363": "a7c908df408c104eea471b9240fb04774a0621365a753597df14b2a63aec39d3",
        "X2D-RG-364": "c44f31203c352d558f503df560ec06a8f9343dd5439c58aafa5daf743029593c",
        "X2D-RG-365": "92af702362c840fbdbf44de30f1f5e07a5d5e65030ab5bd34f810972f85ec252",
        "X2D-RG-366": "5d8aa24c9a594a087265e1637f654c78a4906b69dbe42626fa25c6a5a8959343",
        "X2D-RG-368": "cc447da893676fb2a8c62ff3c51ee0e5533103ef46d1d6852d9cb6c9599fcd9f",
    }
    for goal in manifest["goals"][352:368]:
        if goal['id'] in pinned:
            assert registry.digest(registry.canonical(goal)) == pinned[goal["id"]]


def test_rg367_publication_requirement_only_adds_to_previous_contract(manifest):
    goal = copy.deepcopy(manifest['goals'][366])
    original, separator, addition = goal['required_behavior'].partition(' Before batch publication,')
    assert separator and 'non-regular' in addition and 'fixture-manifest.json' in addition
    assert len(goal['required_evidence']) == 8
    assert 'late fixture-manifest.json directory' in goal['required_evidence'][-2]
    assert 'write/replace/readback faults' in goal['required_evidence'][-1]
    goal['required_behavior'] = original
    goal['required_evidence'] = goal['required_evidence'][:-2]
    assert registry.digest(registry.canonical(goal)) == 'e32228d7de35dc1dd91731f570288f0175cdf0caca02f0692ba33cee8c6d4a30'


def test_rg371_sticky_directory_requirement_only_adds_to_previous_contract(manifest):
    goal = copy.deepcopy(manifest['goals'][370])
    original, separator, addition = goal['required_behavior'].partition(' For a sticky root-owned /tmp,')
    assert separator and 'collision' in addition and '1777' in addition
    assert len(goal['required_evidence']) == 7
    assert 'active policy or enforcement state is unreadable' in goal['required_evidence'][-1]
    goal['required_behavior'] = original
    goal['required_evidence'] = goal['required_evidence'][:-1]
    assert registry.digest(registry.canonical(goal)) == '5b8ab127b409fb258ea01914fd3b5f7b21785176c30d2f75184af006af793c30'


def test_stopped_applicability_draft_is_not_registry_authority(manifest):
    from tools import inherited_applicability as draft
    assert draft.DRAFT_STATUS == 'STOPPED_UNINTEGRATED_NO_RELEASE_AUTHORITY'
    assert draft.REVIEWED_THROUGH == 170
    assert draft.READ_THROUGH == 185
    expected = {int(identifier.rsplit('-', 1)[1]) for identifier, row in manifest['applicability'].items()
                if row['applicability'] == 'PENDING_REVIEW' and int(identifier.rsplit('-', 1)[1]) <= draft.REVIEWED_THROUGH}
    assert set(draft.REVIEWED) == expected
    for number, (status, reason) in draft.REVIEWED.items():
        assert status in {'APPLICABLE', 'OUT_OF_SCOPE', 'PENDING_REVIEW'}
        assert reason.strip()
        row = manifest['applicability'][f'X2D-RG-{number:03d}']
        assert row['applicability'] == 'PENDING_REVIEW'
        assert row['evidence_status'] == 'NOT_RUN' and row['counts_as_pass'] is False


def test_rg376_append_preserves_every_preceding_goal(manifest):
    assert registry.digest(registry.canonical(manifest['goals'][:375])) == '947894b7ce8c691a0cafad2d98c03068205ba281c19e46603fe2a59fa5dc2bd0'
    goal = manifest['goals'][375]
    assert goal['id'] == 'X2D-RG-376'
    assert 'shellLastExitCode' in ' '.join(goal['required_evidence'])
    assert 'last command' in goal['required_behavior']
    assert 'run-y81rka4s/002-su_identity.packets.bin' in goal['origin']
    assert 'run-3oifuux3' in goal['origin']


def test_host_shell_timeout_append_preserves_all_482_goals(manifest):
    prior = manifest["goals"][:482]
    seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "ee35cd9d2094b750e0ed09f8741efd18bf71d9c5b891a629de3cd193cc137fe0"
    assert registry.digest(registry.canonical(seed)) == "2f365eb750f94838b15e1c260c610d3b3291db0d59cae18226f96cc52ccae52c"
    assert registry.canonical(seed) == registry.canonical(registry.initial_applicability(prior))


@pytest.mark.parametrize("number,terms", [
    (358, ["attached=false", "dying extension context", "after unload"]),
    (359, ["activeFocusItem", "popup", "no manual focus reset"]),
    (360, ["zero and twelve", "autoAttach=false", "event-driven"]),
    (361, ["Loader is Ready", "onLoaded", "disconnect-before-connect"]),
    (362, ["qrc:/qt/qml/app/qml/scripts/Keys.js", "image://svg/ic_menu_general", "old resource prefix"]),
    (363, ["_exit(78)", "zero through seven", "actual runtime versions", "x18"]),
    (364, ["0x201", "0x223", "0x22", "before any mutation", "Python -O"]),
    (365, ["Qt/PySide 6.8.2", "worker-thread", "complete explicit destruction", "callback"]),
    (366, ["same-basename", "QT_QUICK_BACKEND=software", "failed round", "process exit"]),
    (367, ["fixed literal", "hard-linked", "preflight every", "atomically", "read back", "src/work"]),
    (368, ["does not load Qt", "status zero", "3221225477", "delete the engine", "parent-observed failure"]),
    (369, ["FIFO", "hardlink", "nonblocking", "_exit(78)", "diagnostic", "PID reuse"]),
    (370, ["self-consistent", "exact Loader URLs", "before and after", "wrong bridge path", "Python -O"]),
    (371, ["devtmpfs", "device:file", "type transition", "create", "read-only", "SELinux"]),
    (372, ["testpaths=tests", "norecursedirs=reference build", "five", "missing-input invalidation", "collect-only"]),
    (373, ["never overwrite", "raw received", "retained packets", "sequential", "read-only"]),
    (374, ["64-bit", "mksh", "0x100000000", "process lifetime", "boot identity", "read-only"]),
    (375, ["verified source bytes", ".pyc", "compile", "no evidence", "-B", "hash"]),
    (376, ["no trailing LF", "leading separator", "empty output", "nonzero", "UID", "actual SELinux domain", "read-only", "Permission denied"]),
    (377, ["AND-list", "lock owner", "WinError 1314", "unknown or corrupt", "vendor/odm"]),
    (378, ["one dedicated", "sys.usb.state", "property equality", "90-second", "authorization", "authentication"]),
])
def test_discovered_regressions_have_explicit_required_evidence(manifest, number, terms):
    goal = manifest["goals"][number - 1]
    all_text = registry.canonical(goal).decode("utf-8").lower()
    assert all(term.lower() in all_text for term in terms)
    assert len(goal["required_evidence"]) >= 4
    assert manifest["applicability"][goal["id"]]["applicability"] == "APPLICABLE"
    assert manifest["applicability"][goal["id"]]["evidence_status"] == "NOT_RUN"
    assert manifest["applicability"][goal["id"]]["counts_as_pass"] is False
    assert manifest["applicability"][goal["id"]]["evidence_refs"] == []


@pytest.mark.parametrize("number", range(358, registry.SOURCE_COUNT + len(registry.NEW_GOALS) + 1))
def test_newly_discovered_goals_cannot_be_dropped_or_claimed_pass(manifest, source_bytes, number):
    changed = copy.deepcopy(manifest)
    changed["goals"][number - 1]["required_evidence"].clear()
    with pytest.raises(registry.RegistryError, match="goals"):
        registry.validate_manifest(changed, source_bytes)
    row = manifest["applicability"][f"X2D-RG-{number}"]
    row["evidence_status"] = "PASS"
    row["counts_as_pass"] = True
    row["evidence_refs"] = ["build/local-component-only.json"]
    with pytest.raises(registry.RegistryError, match="applicability"):
        registry.validate_manifest(manifest, source_bytes)


def test_first_395_goal_and_seed_hashes_remain_exact_after_lifecycle_safety_append(manifest):
    previous_goals = manifest["goals"][:395]
    assert registry.digest(registry.canonical(previous_goals)) == "86f02abbd2c2344bbd60c552d63917bb93120e8ddf149e1ae303378de3394990"
    # A reviewed applicability overlay may differ from this original seed;
    # preserving the seed must not mistake it for current classification.
    previous_seed = registry.initial_applicability(previous_goals)
    assert registry.digest(registry.canonical(previous_seed)) == "a814487a25015f525e896287258d69bdd3deef72ec991961a01f996b9545b183"


def test_first_399_goal_and_seed_hashes_survive_audit_and_effective_api_append(manifest):
    previous_goals = manifest["goals"][:399]
    assert registry.digest(registry.canonical(previous_goals)) == "216983140254615cb1cbb3a60e76414b4f40eeccd0ec438509af16a231f19de8"
    previous_seed = registry.initial_applicability(previous_goals)
    assert registry.digest(registry.canonical(previous_seed)) == "177133163d306127ad19e8683cf0b7a7ac935703e69daaa7e50b5412faa3e5d3"


@pytest.mark.parametrize("number,terms", [
    (396, ["root:root", "0600", "0700", "canonical", "permission", "14", "nul", "symlink", "1314", "non-executable"]),
    (397, ["boot", "namespace", "cleanup", "lock owner", "slow", "600", "stop", "atomic", "different runtime"]),
    (398, ["test_fixture", "publication", "install", "recovery", "same byte buffer", "hash", "parse", "second read"]),
    (399, ["host", "device", "19", "stock qml", "manifest", "transitive", "actual loaded", "runtime inventory", "missing"]),
    (400, ["base nodeids", "start", "finish", "junit", "historical", "subset", "subtest", "attributeerror",
           "981d162ea2b424d7227c0d59e6ab4ee485c225b7d34a9e6c8c9aac75809c4d53"]),
    (401, ["effective_applicability", "new_goals", "initial_applicability", "rg353", "rg399",
           "out_of_scope", "pass", "recomputed", "validate_manifest"]),
])
def test_new_lifecycle_safety_goals_are_explicit_permanent_and_not_pass(manifest, source_bytes, number, terms):
    goals = {goal["id"]: goal for goal in manifest["goals"]}
    identifier = f"X2D-RG-{number}"
    assert identifier in goals, "Discovered lifecycle safety defect lacks a permanent goal"
    assert manifest["goals"][number - 1]["id"] == identifier
    assert set(goals[identifier]) == registry.GOAL_FIELDS
    text = registry.canonical(goals[identifier]).decode("utf-8").lower()
    assert all(term in text for term in terms)
    assert len(goals[identifier]["required_evidence"]) >= 6
    row = manifest["applicability"][identifier]
    assert row["applicability"] == "APPLICABLE"
    assert row["evidence_status"] == "NOT_RUN"
    assert row["counts_as_pass"] is False and row["evidence_refs"] == []
    assert row["goal_sha256"] == registry.digest(registry.canonical(goals[identifier]))
    assert manifest["qualification"]["installable"] is False
    changed = copy.deepcopy(manifest)
    del changed["goals"][number - 1]
    with pytest.raises(registry.RegistryError, match="goals"):
        registry.validate_manifest(changed, source_bytes)
    changed = copy.deepcopy(manifest)
    changed["applicability"][identifier]["evidence_status"] = "PASS"
    with pytest.raises(registry.RegistryError, match="applicability"):
        registry.validate_manifest(changed, source_bytes)


def test_runtime_observation_requirement_preserves_401_and_cannot_claim_live_truth(manifest):
    previous_goals = manifest["goals"][:401]
    assert registry.digest(registry.canonical(previous_goals)) == "e33e25f8c6b02c50f83f731bb94b7622b3e5ec5805ca2cbf5e834d4d43b80c68"
    assert registry.digest(registry.canonical(registry.initial_applicability(previous_goals))) == "383bb93cd6e064c1e3de4f35d0822ba0c85234d585c4caadbeafac5ee10b9258"
    goals = {goal["id"]: goal for goal in manifest["goals"]}
    assert "X2D-RG-402" in goals, "Current core observation gap lacks a permanent requirement"
    goal = goals["X2D-RG-402"]
    assert set(goal) == registry.GOAL_FIELDS
    text = registry.canonical(goal).decode("utf-8").lower()
    for term in ("runtime_observation", "expected", "observed", "gui", "service", "sensor",
                 "capture-owner", "boot", "slot", "namespace", "process lifetime",
                 "present/absent/unknown", "rg385", "synthetic", "data shape",
                 "each write boundary", "unimplemented", "did not raise"):
        assert term in text
    assert len(goal["required_evidence"]) >= 6
    row = manifest["applicability"]["X2D-RG-402"]
    assert row["applicability"] == "APPLICABLE"
    assert row["evidence_status"] == "NOT_RUN"
    assert row["counts_as_pass"] is False and row["evidence_refs"] == []
    assert row["goal_sha256"] == registry.digest(registry.canonical(goal))
    assert manifest["qualification"]["installable"] is False


def test_runtime_review_findings_preserve_402_and_keep_observation_separate_from_authority(manifest, source_bytes):
    previous_goals = manifest["goals"][:402]
    assert registry.digest(registry.canonical(previous_goals)) == "b728b3ff35d57876e995d1286d96b81756b6b4bc6e60f39e564bc790a6378540"
    assert registry.digest(registry.canonical(registry.initial_applicability(previous_goals))) == "6f3b82528d127d3579ad8f1bc3189d4440c76a8ccaac3377f056c6c9d58b9539"
    goals = {goal["id"]: goal for goal in manifest["goals"]}
    identifier = "X2D-RG-403"
    assert identifier in goals, "Independent runtime review findings lack a permanent requirement"
    goal = goals[identifier]
    assert manifest["goals"][402] == goal
    assert set(goal) == registry.GOAL_FIELDS
    text = registry.canonical(goal).decode("utf-8").lower()
    for term in ("runtime_subject_sha256", "unknown", "changed gui", "execution", "unsupported",
                 "runtime observation", "gate fixture", "independently", "publication",
                 "counterfactual", "guard reachability", "gate reports", "no output",
                 "same artifact path", "sha256", "bytes", "present/absent/unknown",
                 "distinct", "2", "6", "did not raise", "pending", "not_run",
                 "runtime-observation-recovery-separation-20261004-red.xml",
                 "runtime-observation-duplicate-artifact-red.xml"):
        assert term in text
    assert len(goal["required_evidence"]) >= 7
    row = manifest["applicability"][identifier]
    assert row["applicability"] == "APPLICABLE"
    assert row["evidence_status"] == "NOT_RUN"
    assert row["counts_as_pass"] is False and row["evidence_refs"] == []
    assert row["goal_sha256"] == registry.digest(registry.canonical(goal))
    assert manifest["qualification"]["installable"] is False
    changed = copy.deepcopy(manifest)
    del changed["goals"][402]
    with pytest.raises(registry.RegistryError, match="goals"):
        registry.validate_manifest(changed, source_bytes)
    changed = copy.deepcopy(manifest)
    changed["applicability"][identifier]["evidence_status"] = "PASS"
    with pytest.raises(registry.RegistryError, match="applicability"):
        registry.validate_manifest(changed, source_bytes)


@pytest.mark.parametrize("number,terms", [
    (404, ["8+1", "ustar", "members.json", "independent", "standard-library",
           "duplicate", "traversal", "links", "metadata", "padding", "two zero blocks",
           "64", "128", "8192", "detached", "session", "synthetic", "not_run",
           "transient", "keyerror", "18", "7", "5", "magic/version", "devmajor",
           "devminor", "checksum helper", "no saved red xml"]),
    (405, ["four", "source/target", "gui", "baseline", "candidate_sha256", "bytes", "sha256",
           "install-files.sh", "activate-boot.sh", "restore-boot.sh", "script_hashes",
           "provenance", "freshness", "9", "13", "did not raise", "synthetic", "not_run",
           "delivery-plan-20261004-red-02.xml", "delivery-plan-20261004-red-03.xml",
           "delivery-plan-20261004-red-06.xml", "strictly less than 8 mib", "8 mib minus one",
           "exactly 8 mib", "64 mib"]),
])
def test_delivery_requirements_preserve_403_without_granting_packaging_authority(manifest, source_bytes, number, terms):
    previous_goals = manifest["goals"][:403]
    assert registry.digest(registry.canonical(previous_goals)) == "1ccf8c5bd75dceb097efeda32e377f9cc430c5196319e39953f7fa33b5afb141"
    assert registry.digest(registry.canonical(registry.initial_applicability(previous_goals))) == "c81b645b5a4aa66969c6c3efda4b59176c8f7a8114548b55b0921f32e4675a2c"
    goals = {goal["id"]: goal for goal in manifest["goals"]}
    identifier = f"X2D-RG-{number}"
    assert identifier in goals, "Delivery content requirement is not permanently recorded"
    goal = goals[identifier]
    assert manifest["goals"][number - 1] == goal
    assert set(goal) == registry.GOAL_FIELDS
    text = registry.canonical(goal).decode("utf-8").lower()
    assert all(term in text for term in terms)
    assert len(goal["required_evidence"]) >= 8
    row = manifest["applicability"][identifier]
    assert row["applicability"] == "APPLICABLE"
    assert row["evidence_status"] == "NOT_RUN"
    assert row["counts_as_pass"] is False and row["evidence_refs"] == []
    assert row["goal_sha256"] == registry.digest(registry.canonical(goal))
    assert manifest["qualification"]["installable"] is False
    assert manifest["qualification"]["package_created"] is False
    changed = copy.deepcopy(manifest)
    del changed["goals"][number - 1]
    with pytest.raises(registry.RegistryError, match="goals"):
        registry.validate_manifest(changed, source_bytes)
    changed = copy.deepcopy(manifest)
    changed["applicability"][identifier]["evidence_status"] = "PASS"
    with pytest.raises(registry.RegistryError, match="applicability"):
        registry.validate_manifest(changed, source_bytes)


def test_delivery_integration_append_preserves_every_405_goal_and_seed_field(manifest):
    prior = manifest["goals"][:405]
    prior_seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "b1bb63edbce74305585a551007e32ca8ae48b0be6b4b1b35d6c56f5743c4fbea"
    assert registry.digest(registry.canonical(prior_seed)) == "925962e8d33db760db1710235a4a5af9a3727a6a6f0a823dd757d9d2fb2770c9"
    assert registry.canonical(prior_seed) == registry.canonical(registry.initial_applicability(prior))
    unchanged = {key: value for key, value in manifest.items()
                 if key not in ("goals", "applicability", "applicability_review")}
    assert registry.digest(registry.canonical(unchanged)) == "e15170b78fef616c1b0b6b9f42bbce7dc844f847c153eb5e22f5304e536b93c7"


@pytest.mark.parametrize("number,terms", [
    (406, ["fixed five", "same-render", "source/target", "single-handle", "limit + 1",
           "strictly less than 8 mib", "64 kib", "hardlink", "reparse", "inode", "ascii",
           "delivery-files-20261004-red-script-contract.xml",
           "delivery-files-20261004-red-bounded-read.xml",
           "delivery-files-20261004-red-cross-read-change.xml",
           "4", "2", "did not raise", "windows", "atomic parent", "not_run"]),
    (407, ["delivery_identity", "package_sha256", "package_bytes", "format_version", "member_manifest_sha256",
           "build", "runtime", "lease", "session-context.data", "source-only",
           "qualified_delivery_not_executed", "qualified_script_source_not_executed",
           "tools/delivery_content.py", "tests/test_delivery_binding.py", "mutable", "600",
           "after", "current time", "delivery-binding-20261004-red-01.xml",
           "delivery-binding-20261004-red-02.xml", "delivery-binding-20261004-red-04.xml",
           "delivery-binding-20261004-red-05.xml", "recovery-delivery-20261004-red-01.xml",
           "rendered_script", "same-render", "qualification snapshot", "not_run"]),
    (408, ["publish_output_set", "before_commit", "all-member", "readback", "precommit",
           "read-only", "idempotent", "partial", "exact", "inode", "unknown", "retract",
           "output-set-20261004-red-01.xml", "output-set-20261004-red-02.xml",
           "output-set-20261004-red-03.xml", "output-set-20261004-red-04-boundary.xml",
           "output-set-20261004-red-05-short-commit.xml", "output-set-20261004-red-06-callback.xml",
           ".pending", "parseable", "short write", "windows", "non-windows", "rename",
           "regex", "hard power loss", "concurrent parent", "not_run"]),
])
def test_delivery_integration_requirements_are_permanent_not_execution_pass(manifest, source_bytes, number, terms):
    identifier = f"X2D-RG-{number}"
    goals = {goal["id"]: goal for goal in manifest["goals"]}
    assert identifier in goals, "Observed delivery integration defect lacks a permanent requirement"
    goal = goals[identifier]
    assert manifest["goals"][number - 1] == goal
    assert set(goal) == registry.GOAL_FIELDS
    text = registry.canonical(goal).decode("utf-8").lower()
    assert all(term in text for term in terms)
    assert len(goal["required_evidence"]) >= 8
    row = manifest["applicability"][identifier]
    assert row["applicability"] == "APPLICABLE"
    assert row["evidence_status"] == "NOT_RUN"
    assert row["counts_as_pass"] is False and row["evidence_refs"] == []
    assert row["goal_sha256"] == registry.digest(registry.canonical(goal))
    effective = registry.effective_applicability(manifest)
    assert effective[identifier] == row
    for field, value in (("evidence_status", "PASS"), ("counts_as_pass", True),
                         ("evidence_refs", ["build/component-only.json"]), ("applicability", "OUT_OF_SCOPE")):
        changed = copy.deepcopy(manifest)
        changed["applicability"][identifier][field] = value
        with pytest.raises(registry.RegistryError, match="applicability"):
            registry.validate_manifest(changed, source_bytes)
        with pytest.raises(registry.RegistryError, match="seed"):
            registry.effective_applicability(changed)
    changed = copy.deepcopy(manifest)
    del changed["goals"][number - 1]
    with pytest.raises(registry.RegistryError, match="goals"):
        registry.validate_manifest(changed, source_bytes)
    assert manifest["qualification"]["installable"] is False
    assert manifest["qualification"]["package_created"] is False


def test_saved_delivery_integration_inventory_matches_the_complete_generator(source_bytes):
    saved = registry.strict_json(registry.MANIFEST_PATH.read_bytes())
    generated = registry.build_manifest(source_bytes)
    assert registry.canonical(saved) == registry.canonical(generated)
    assert registry.effective_applicability(saved) == registry.effective_applicability(generated)


def test_leaf_race_record_preserves_every_408_goal_seed_and_stronger_withdrawal_requirement(manifest):
    prior = manifest["goals"][:408]
    prior_seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "9a48d545fe262023933511d1d265086f758b3a0ed584a5ab6ff826f52fd2482e"
    assert registry.digest(registry.canonical(prior_seed)) == "70467d7a0eacd948c5208657456b789ec593ee6b7b91bbe6df5c73d394dcaa4a"
    assert registry.digest(registry.canonical(prior[-1])) == "344a23d86777e9ca86c6820adde91ee4c1cebb35284ebb07635b82ba1e19d361"
    assert registry.canonical(prior_seed) == registry.canonical(registry.initial_applicability(prior))
    assert "never delete an unknown replacement" in prior[-1]["required_behavior"]
    row = manifest["applicability"]["X2D-RG-408"]
    assert row["applicability"] == "APPLICABLE"
    assert row["evidence_status"] == "NOT_RUN"
    assert row["counts_as_pass"] is False and row["evidence_refs"] == []


def test_leaf_replacement_race_is_permanent_boundary_evidence_not_safety_pass(manifest, source_bytes):
    identifier = "X2D-RG-409"
    goals = {goal["id"]: goal for goal in manifest["goals"]}
    assert identifier in goals, "Independently demonstrated leaf replacement race lacks a permanent goal"
    goal = goals[identifier]
    assert manifest["goals"][408] == goal
    assert set(goal) == registry.GOAL_FIELDS
    text = registry.canonical(goal).decode("utf-8").lower()
    for term in ("publish_output_set", "no other writer", "entire call", "exclusive creation",
                 "final stat/inode check", "pathname unlink", "without replacing any parent",
                 "different inode", "different bytes", "same parent", "test_only",
                 "out-of-contract", "not a p2", "atomic retraction", "adversarial",
                 "rg408", "stronger", "unmet", "not_run", "safety pass",
                 "leaf-race-demonstration.py", "leaf-race-demonstration.json",
                 "278094e3a2fff52954597fca03f12d3be289a3c3a86eb31c7af6b02b4f38e4c8",
                 "5537c773580aac984d5aad4b86889eab3e034cbb80a2291fd7c56ef73dfa8d0e",
                 "edb53871e9a6dd564d75ec5bcd19562e25999e3446958dd6490c367feee3f6be"):
        assert term in text
    assert len(goal["required_evidence"]) >= 6
    row = manifest["applicability"][identifier]
    assert row["applicability"] == "APPLICABLE"
    assert row["evidence_status"] == "NOT_RUN"
    assert row["counts_as_pass"] is False and row["evidence_refs"] == []
    assert row["goal_sha256"] == registry.digest(registry.canonical(goal))
    assert registry.effective_applicability(manifest)[identifier] == row
    for field, value in (("evidence_status", "PASS"), ("counts_as_pass", True),
                         ("evidence_refs", ["build/peer-delivery-review-20261004/leaf-race-demonstration.json"]),
                         ("applicability", "OUT_OF_SCOPE")):
        changed = copy.deepcopy(manifest)
        changed["applicability"][identifier][field] = value
        with pytest.raises(registry.RegistryError, match="applicability"):
            registry.validate_manifest(changed, source_bytes)
        with pytest.raises(registry.RegistryError, match="seed"):
            registry.effective_applicability(changed)
    changed = copy.deepcopy(manifest)
    del changed["goals"][408]
    with pytest.raises(registry.RegistryError, match="goals"):
        registry.validate_manifest(changed, source_bytes)
    assert manifest["qualification"]["installable"] is False
    assert manifest["qualification"]["package_created"] is False


def test_core_consumer_append_preserves_every_409_goal_and_seed(manifest):
    prior = manifest["goals"][:409]
    prior_seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "b2b4793997e11a5c298b353cca855bec94c31a22aa5fd5d2824894e48be6a019"
    assert registry.digest(registry.canonical(prior_seed)) == "6e504780b5d2d714158c82e0199c4dedd11b944878561affbfbe9bb4477011a9"
    assert registry.digest(registry.canonical(prior[-1])) == "1a828b9f446a5316336ca09296cdbae2d7d137472dc9fa427b618fe1d49702c4"
    assert registry.canonical(prior_seed) == registry.canonical(registry.initial_applicability(prior))


def test_core_consumer_and_host_fixture_findings_remain_requirements_not_live_pass(manifest, source_bytes):
    identifier = "X2D-RG-410"
    goals = {goal["id"]: goal for goal in manifest["goals"]}
    assert identifier in goals, "Core consumer and fixture regressions lack a permanent goal"
    goal = goals[identifier]
    assert manifest["goals"][409] == goal
    assert set(goal) == registry.GOAL_FIELDS
    text = registry.canonical(goal).decode("utf-8").lower()
    for term in ("session_data", "x2dii-session-context-v2", "start_ticks", "capture-owner",
                 "gui stop", "before mount", "each write", "distinct", "same-pid", "transition",
                 "applied sensor", "actual capture route", "unknown", "v1", "stdin",
                 "frozen original bytes", "false positive", "trigger", "timeout", "unreached",
                 "tests/test_session_context_v2.py", "build_subject_sha256", "closure",
                 "execution_context_fields", "old restore", "boot_id differs", "winerror 1314",
                 "install-core-runtime-20261004-red-01.xml",
                 "install-core-runtime-20261004-red-03-fixture.xml",
                 "install-core-runtime-20261004-green-03-fixture.xml",
                 "install-core-runtime-20261004-red-04-old-hooks.xml",
                 "install-core-runtime-20261004-red-05-expiry-not-reached.xml",
                 "install-core-runtime-20261004-final-green.xml",
                 "install-core-runtime-20261004-trigger-proof.xml",
                 "recovery-session-v2-closure-20261004-red-01.xml",
                 "recovery-session-v2-closure-20261004-investigate-install.xml",
                 "recovery-session-v2-closure-20261004-final-green-02.xml",
                 "cc206f6483f6c865ce7a437b4846ca24389043f152339bbaadb888f9ab301346",
                 "bda2ddb0a6834df27e3ca14fbb5651383a51e5050643b201bc0671693c31bbdf",
                 "82968d761af5cae8151363ed2950809fa5e7d67c3119907648d31df4ad3cbf34",
                 "25e0d33dcc3137303eb17d9b0faad4b5f53c4c3ed08f2366e2e106f6a50e871e",
                 "d4d9f1548e697d93a4a9b4ffadee0f3fbd249b32adf2894a22fb010a72c5f4c4",
                 "26", "53", "58", "not_run", "synthetic"):
        assert term in text
    assert len(goal["required_evidence"]) >= 10
    row = manifest["applicability"][identifier]
    assert row["applicability"] == "APPLICABLE"
    assert row["evidence_status"] == "NOT_RUN"
    assert row["counts_as_pass"] is False and row["evidence_refs"] == []
    assert row["goal_sha256"] == registry.digest(registry.canonical(goal))
    assert registry.effective_applicability(manifest)[identifier] == row
    for field, value in (("evidence_status", "PASS"), ("counts_as_pass", True),
                         ("evidence_refs", ["build/install-core-runtime-20261004-final-green.xml"]),
                         ("applicability", "OUT_OF_SCOPE")):
        changed = copy.deepcopy(manifest)
        changed["applicability"][identifier][field] = value
        with pytest.raises(registry.RegistryError, match="applicability"):
            registry.validate_manifest(changed, source_bytes)
        with pytest.raises(registry.RegistryError, match="seed"):
            registry.effective_applicability(changed)
    changed = copy.deepcopy(manifest)
    del changed["goals"][409]
    with pytest.raises(registry.RegistryError, match="goals"):
        registry.validate_manifest(changed, source_bytes)
    assert manifest["qualification"]["installable"] is False
    assert manifest["qualification"]["package_created"] is False


def test_query_status_append_preserves_every_410_goal_and_seed(manifest):
    prior = manifest["goals"][:410]
    prior_seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "d795f5fb78c8c5b68a27bbd533022585cd16e4d5f5a01876a5eb71bbe10fbc82"
    assert registry.digest(registry.canonical(prior_seed)) == "f5aa1c7d8b002c51bdeb1592d9179ae6e9d66b225749a32fa7847608ecc34633"
    assert registry.digest(registry.canonical(prior[-1])) == "7090d9487039694e29534f26427a020993d7dc5da183ea41576df0146d6609b1"
    assert registry.canonical(prior_seed) == registry.canonical(registry.initial_applicability(prior))


def test_expected_query_output_never_overrides_failure_status_or_grants_release_pass(manifest, source_bytes):
    identifier = "X2D-RG-411"
    goals = {goal["id"]: goal for goal in manifest["goals"]}
    assert identifier in goals, "Correct query output with failing status lacks a permanent requirement"
    goal = goals[identifier]
    assert manifest["goals"][410] == goal
    assert set(goal) == registry.GOAL_FIELDS
    text = registry.canonical(goal).decode("utf-8").lower()
    for term in ("stdout", "exit 2", "exit status", "both", "empty", "assignment",
                 "link count", "owner", "namespace", "unrd", "getprop", "readlink",
                 "read > 1", "read == 1", "eof", "i/o", "cannot distinguish",
                 "v1", "v2", "public", "clear", "stdin", "trigger", "no camera",
                 "27", "28", "33", "36", "winerror 1314", "not_run",
                 "install-core-runtime-20261004-red-02-query.xml",
                 "install-core-runtime-20261004-red-06-link-count.xml",
                 "install-core-runtime-20261004-red-07-metadata-query.xml",
                 "install-core-runtime-20261004-red-08-mount-read.xml",
                 "install-core-runtime-20261004-green-07-mount-read.xml",
                 "session-stat-status-20261004-red-link.xml",
                 "session-stat-status-20261004-red-final-identity.xml",
                 "session-stat-status-20261004-post-review.xml",
                 "recovery-query-status-20261004-red-01.xml",
                 "recovery-query-status-20261004-red-02-state-read.xml",
                 "recovery-query-status-20261004-red-03-output-closure.xml",
                 "recovery-query-status-20261004-final-green-02.xml",
                 "tests/test_recovery_query_status.py", "tests/test_output_withdrawal.py",
                 "separate red", "541", "58"):
        assert term in text
    assert len(goal["required_evidence"]) >= 10
    row = manifest["applicability"][identifier]
    assert row["applicability"] == "APPLICABLE"
    assert row["evidence_status"] == "NOT_RUN"
    assert row["counts_as_pass"] is False and row["evidence_refs"] == []
    assert row["goal_sha256"] == registry.digest(registry.canonical(goal))
    assert registry.effective_applicability(manifest)[identifier] == row
    for field, value in (("evidence_status", "PASS"), ("counts_as_pass", True),
                         ("evidence_refs", ["build/recovery-query-status-20261004-final-green-02.xml"]),
                         ("applicability", "OUT_OF_SCOPE")):
        changed = copy.deepcopy(manifest)
        changed["applicability"][identifier][field] = value
        with pytest.raises(registry.RegistryError, match="applicability"):
            registry.validate_manifest(changed, source_bytes)
        with pytest.raises(registry.RegistryError, match="seed"):
            registry.effective_applicability(changed)
    changed = copy.deepcopy(manifest)
    del changed["goals"][410]
    with pytest.raises(registry.RegistryError, match="goals"):
        registry.validate_manifest(changed, source_bytes)
    assert manifest["qualification"]["installable"] is False
    assert manifest["qualification"]["package_created"] is False


def test_handle_withdrawal_append_preserves_every_411_goal_and_seed(manifest):
    prior = manifest["goals"][:411]
    prior_seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "b4a8686d75deac92196904c792d151a139ae6b9a46538fc5316fa6184305d853"
    assert registry.digest(registry.canonical(prior_seed)) == "d6edfa1cc0d397a096466167b8f63f3cd90aa6516d25c25e2147618844cb9bfe"
    assert registry.digest(registry.canonical(prior[-1])) == "6ca104da80e0c54062d94b72f585bf86a3a0341cc64d348fc01d1497b3eca53c"
    assert registry.canonical(prior_seed) == registry.canonical(registry.initial_applicability(prior))
    assert registry.digest(registry.canonical(prior[407])) == "344a23d86777e9ca86c6820adde91ee4c1cebb35284ebb07635b82ba1e19d361"
    assert registry.digest(registry.canonical(prior[408])) == "1a828b9f446a5316336ca09296cdbae2d7d137472dc9fa427b618fe1d49702c4"


def test_handle_bound_withdrawal_records_both_protection_and_residual_uncertainty(manifest, source_bytes):
    identifier = "X2D-RG-412"
    goals = {goal["id"]: goal for goal in manifest["goals"]}
    assert identifier in goals, "Pinned-handle withdrawal and close-diagnostic defects lack a permanent requirement"
    goal = goals[identifier]
    assert manifest["goals"][411] == goal
    assert set(goal) == registry.GOAL_FIELDS
    text = registry.canonical(goal).decode("utf-8").lower()
    for term in ("same handle", "original creating writer", "metadata-only", "reopenfile",
                 "128-bit", "file-id reuse", "share mode zero", "open_reparse_point",
                 "setfileinformationbyhandle", "same-byte", "rename-aside", "vacant",
                 "winerror 5", "stale fault", "missing pin interface", "not a demonstrated",
                 "sys.exception", "publication_error", "caller", "nested", "close",
                 "formal marker may remain", "unverified", "do not reuse", "no pathname",
                 "no other writer", "entire call", "parent replacement", "power loss",
                 "rg408", "rg409", "historical", "not_run", "84", "14", "65",
                 "output-withdrawal-20261004-red-01.xml",
                 "output-withdrawal-20261004-red-02-pin.xml",
                 "output-withdrawal-20261004-first-integration.xml",
                 "output-withdrawal-20261004-green-02-pin.xml",
                 "output-withdrawal-20261004-green-03-pin.xml",
                 "output-withdrawal-20261004-red-03-close.xml",
                 "output-withdrawal-20261004-red-04-nested-close.xml",
                 "output-withdrawal-20261004-red-05-outer-exception.xml",
                 "output-withdrawal-20261004-post-review.xml",
                 "9560281596ae6861d66f50372ca49e37ea95007b2b691923c8661444bdf52353",
                 "f5eb690f362eeb2a02a0732546d7cece308a511f7a24b1d0a71301d6266d3522",
                 "44c11aa0d47d42866969062fdcdd66a60e6e9be448b72680927d765b627c3a8d"):
        assert term in text
    assert len(goal["required_evidence"]) >= 10
    row = manifest["applicability"][identifier]
    assert row["applicability"] == "APPLICABLE"
    assert row["evidence_status"] == "NOT_RUN"
    assert row["counts_as_pass"] is False and row["evidence_refs"] == []
    assert row["goal_sha256"] == registry.digest(registry.canonical(goal))
    assert registry.effective_applicability(manifest)[identifier] == row
    for field, value in (("evidence_status", "PASS"), ("counts_as_pass", True),
                         ("evidence_refs", ["build/output-withdrawal-20261004-post-review.xml"]),
                         ("applicability", "OUT_OF_SCOPE")):
        changed = copy.deepcopy(manifest)
        changed["applicability"][identifier][field] = value
        with pytest.raises(registry.RegistryError, match="applicability"):
            registry.validate_manifest(changed, source_bytes)
        with pytest.raises(registry.RegistryError, match="seed"):
            registry.effective_applicability(changed)
    changed = copy.deepcopy(manifest)
    del changed["goals"][411]
    with pytest.raises(registry.RegistryError, match="goals"):
        registry.validate_manifest(changed, source_bytes)
    assert manifest["qualification"]["installable"] is False
    assert manifest["qualification"]["package_created"] is False


def test_partial_mount_append_preserves_every_412_goal_and_seed(manifest):
    prior = manifest["goals"][:412]
    prior_seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "5f138a16843dc0dd189bf914037505fc20efd225ccbcec84f54f00fdcd9e4f63"
    assert registry.digest(registry.canonical(prior_seed)) == "fbce18b15fa4a0dc78cd8ee49c167089df90b24edbcc9db195455aac2d2483e6"
    assert registry.digest(registry.canonical(prior[-1])) == "9852df6565f1c22a934799549debed74ed58de67cdc75c53a57e5b132cb8a6e7"
    assert registry.canonical(prior_seed) == registry.canonical(registry.initial_applicability(prior))


def test_unterminated_mount_records_and_reader_isolation_are_permanent_requirements(manifest, source_bytes):
    identifier = "X2D-RG-413"
    goals = {goal["id"]: goal for goal in manifest["goals"]}
    assert identifier in goals, "Accepted unterminated mount records lack a permanent requirement"
    goal = goals[identifier]
    assert manifest["goals"][412] == goal
    assert set(goal) == registry.GOAL_FIELDS
    text = registry.canonical(goal).decode("utf-8").lower()
    for term in ("unterminated", "nonempty", "whitespace", "partial-system", "partial-other",
                 "ifs= read -r", "state()", "set -f", "subshell", "six fields",
                 "glob", "positional", "read == 1", "read > 1", "i/o", "eof",
                 "core_equals", "checked_equals", "before stop", "no operations",
                 "93", "39", "58", "not_run", "rg411", "rg412",
                 "install-core-runtime-20261004-red-09-partial-mount.xml",
                 "install-core-runtime-20261004-green-08-partial-mount.xml",
                 "recovery-query-status-20261004-red-04-partial-mount.xml",
                 "recovery-query-status-20261004-green-03-partial-mount.xml",
                 "recovery-query-status-20261004-final-green-03-partial-mount.xml",
                 "53c286a6521e2353972bebdd3e9f32b45aa6e129ab9efa328326e7d48348596a",
                 "5a10b27b2903f79624d2092519780077c028621414b07aeef3729f7e423bcc00",
                 "3f0f4e4ad17e228f920db52792888b84fc323ad8ffd51a1eda9d32d0d4aecb0b",
                 "545d98c5f0f860887d2e479c6f34039e95e3a1f8010413a44f64e45c3134d73a"):
        assert term in text
    assert len(goal["required_evidence"]) >= 8
    row = manifest["applicability"][identifier]
    assert row["applicability"] == "APPLICABLE"
    assert row["evidence_status"] == "NOT_RUN"
    assert row["counts_as_pass"] is False and row["evidence_refs"] == []
    assert row["goal_sha256"] == registry.digest(registry.canonical(goal))
    assert registry.effective_applicability(manifest)[identifier] == row
    for field, value in (("evidence_status", "PASS"), ("counts_as_pass", True),
                         ("evidence_refs", ["build/install-core-runtime-20261004-green-08-partial-mount.xml"]),
                         ("applicability", "OUT_OF_SCOPE")):
        changed = copy.deepcopy(manifest)
        changed["applicability"][identifier][field] = value
        with pytest.raises(registry.RegistryError, match="applicability"):
            registry.validate_manifest(changed, source_bytes)
        with pytest.raises(registry.RegistryError, match="seed"):
            registry.effective_applicability(changed)
    changed = copy.deepcopy(manifest)
    del changed["goals"][412]
    with pytest.raises(registry.RegistryError, match="goals"):
        registry.validate_manifest(changed, source_bytes)
    assert manifest["qualification"]["installable"] is False
    assert manifest["qualification"]["package_created"] is False


def test_saved_observation_append_preserves_every_413_goal_and_seed(manifest):
    prior = manifest["goals"][:413]
    prior_seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "9e54978703323bf84e06000e52cdeb3f61b28976874dab151904c40ad44a6294"
    assert registry.digest(registry.canonical(prior_seed)) == "2828afebf0118831e6207f54d6f2a4f6660189f3dd4c476597451d5dd5a929b0"
    assert registry.digest(registry.canonical(prior[-1])) == "80959d0b263befb11210ccdae669fd1c1fa99c6dd4f8c62d5ab25a336d69697e"
    assert registry.canonical(prior_seed) == registry.canonical(registry.initial_applicability(prior))


def test_saved_observation_summary_cannot_invent_current_state_or_qualification(manifest, source_bytes):
    identifier = "X2D-RG-414"
    goals = {goal["id"]: goal for goal in manifest["goals"]}
    assert identifier in goals, "Saved-readout adaptation and provenance gaps lack a permanent requirement"
    goal = goals[identifier]
    assert manifest["goals"][413] == goal
    assert set(goal) == registry.GOAL_FIELDS
    text = registry.canonical(goal).decode("utf-8").lower()
    for term in ("offline", "immutable bytes", "last shell command", "multi-command",
                 "source", "conflict", "unknown", "no i/o", "duplicate", "1 mib",
                 "128", "96 kib", "64 kib", "module", "development", "17", "33",
                 "113", "22", "168", "6793", "six", "43", "not_run",
                 "observation-bundle-20261004-red-01.xml",
                 "observation-bundle-20261004-red-02-inputs.xml",
                 "observation-bundle-20261004-red-03-conflicts.xml",
                 "observation-bundle-20261004-red-04-record-status.xml",
                 "observation-bundle-20261004-post-review.xml",
                 "observation-bundle-20261004-independent-review.xml",
                 "77df0aa909cf66e0dd94eace6d7c560ef4f2705100efc64d3d9df24e29e8677a",
                 "6d50f4f77872336a17560cf682ac115aff55f5e0990beda720a2a1ef277fe77e"):
        assert term in text
    assert len(goal["required_evidence"]) >= 6
    row = manifest["applicability"][identifier]
    assert row["applicability"] == "APPLICABLE"
    assert row["evidence_status"] == "NOT_RUN"
    assert row["counts_as_pass"] is False and row["evidence_refs"] == []
    assert row["goal_sha256"] == registry.digest(registry.canonical(goal))
    assert registry.effective_applicability(manifest)[identifier] == row
    for field, value in (("evidence_status", "PASS"), ("counts_as_pass", True),
                         ("evidence_refs", ["build/observation-bundle-20261004-post-review.xml"]),
                         ("applicability", "OUT_OF_SCOPE")):
        changed = copy.deepcopy(manifest)
        changed["applicability"][identifier][field] = value
        with pytest.raises(registry.RegistryError, match="applicability"):
            registry.validate_manifest(changed, source_bytes)
        with pytest.raises(registry.RegistryError, match="seed"):
            registry.effective_applicability(changed)
    changed = copy.deepcopy(manifest)
    del changed["goals"][413]
    with pytest.raises(registry.RegistryError, match="goals"):
        registry.validate_manifest(changed, source_bytes)
    assert manifest["qualification"]["installable"] is False
    assert manifest["qualification"]["package_created"] is False


def test_bridge_preflight_append_preserves_every_414_goal_and_seed(manifest):
    prior = manifest["goals"][:414]
    prior_seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "7669661691a0d7319a1440c95d032925d19747cf351f6b05a47eac05f598396b"
    assert registry.digest(registry.canonical(prior_seed)) == "75621980dab84c0a01ff7b90bcc47783d193be091d31e8bb97d9d5027a686e7e"
    assert registry.digest(registry.canonical(prior[-1])) == "e687b15871ab6ea741fd5cb02a2164f7d400af939fd366c84d5e7dacfdfcea8c"
    assert registry.canonical(prior_seed) == registry.canonical(registry.initial_applicability(prior))


def test_stale_host_bridge_build_must_be_rejected_before_the_full_audit(manifest, source_bytes):
    identifier = "X2D-RG-415"
    goals = {goal["id"]: goal for goal in manifest["goals"]}
    assert identifier in goals, "Stale host bridge bindings and missing audit preflight lack a permanent requirement"
    goal = goals[identifier]
    assert manifest["goals"][414] == goal
    assert set(goal) == registry.GOAL_FIELDS
    text = registry.canonical(goal).decode("utf-8").lower()
    for term in ("seven", "preflight", "source binding", "before", "runtime", "compiler",
                 "build/host-bridge/native/build.json", "tools/output_guard.py", "hostcache",
                 "tools/audit_build_preflight.py", "tests/test_audit_build_preflight.py",
                 "1724", "3074", "five", "read-only", "fresh", "not_run",
                 "peer-route-review-20261004-rg408", "full-offline-suite.xml",
                 "direct --suite", "must_be_new", "leftover", "old xml",
                 "collect-preflight-failed.json", "suite-preflight-failed.json",
                 "passing_subtest_count", "main_testcase_count", "42", "27",
                 "audit-build-preflight-20261004-red-missing.xml",
                 "red-input-contract.xml", "red-dll.xml", "red-runner.xml",
                 "red-runner-guard.xml", "red-subtest-count.xml", "red-output-reuse.xml",
                 "red-real-xml-reuse.xml", "green-cross-mode.xml",
                 "ae56b0d26016f512c9e60bf230b5f527c62950586856cce19f29251fe0593f03",
                 "f4060b88563272321145ea4311ad8134902202e0183eb56506382b42b8535fbb",
                 "6077564b1092e6fe6a7be6c497ff83d51da81210d7b4ac731ba7a19f7960f6d0",
                 "7342e64cdb2b6a29ef76f177826ad7e3b16a2bd2c7d73799d3ca5f55ba99040e",
                 "68c80c67f861b19ccae4b920a424fd4cc82acfff778e01881322fb3cd95b8594"):
        assert term in text
    assert len(goal["required_evidence"]) >= 6
    row = manifest["applicability"][identifier]
    assert row["applicability"] == "APPLICABLE"
    assert row["evidence_status"] == "NOT_RUN"
    assert row["counts_as_pass"] is False and row["evidence_refs"] == []
    assert row["goal_sha256"] == registry.digest(registry.canonical(goal))
    assert registry.effective_applicability(manifest)[identifier] == row
    for field, value in (("evidence_status", "PASS"), ("counts_as_pass", True),
                         ("evidence_refs", ["build/peer-route-review-20261004-rg408/full-offline-suite.xml"]),
                         ("applicability", "OUT_OF_SCOPE")):
        changed = copy.deepcopy(manifest)
        changed["applicability"][identifier][field] = value
        with pytest.raises(registry.RegistryError, match="applicability"):
            registry.validate_manifest(changed, source_bytes)
        with pytest.raises(registry.RegistryError, match="seed"):
            registry.effective_applicability(changed)
    changed = copy.deepcopy(manifest)
    del changed["goals"][414]
    with pytest.raises(registry.RegistryError, match="goals"):
        registry.validate_manifest(changed, source_bytes)
    assert manifest["qualification"]["installable"] is False
    assert manifest["qualification"]["package_created"] is False


def test_supplied_producer_append_preserves_every_415_goal_and_seed(manifest):
    prior = manifest["goals"][:415]
    prior_seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "6be113edf4fbed9dfa1fb8cf8be40d951743a534d6cb9ed72983189e345491dc"
    assert registry.digest(registry.canonical(prior_seed)) == "1d598af52f5d50ca28f3c16e0c20e1d532287236182855e9b2ea20223187aa4f"
    assert registry.digest(registry.canonical(prior[-1])) == "ca40d74de301aaec6704a0b8523a659d8b3a8a52c40fd48562d684d4c5bb0a08"
    assert registry.canonical(prior_seed) == registry.canonical(registry.initial_applicability(prior))


def test_supplied_observation_assembly_retains_provenance_gaps_and_cross_role_identity_guards(manifest, source_bytes):
    identifier = "X2D-RG-416"
    goals = {goal["id"]: goal for goal in manifest["goals"]}
    assert identifier in goals, "Supplied-observation assembly and cross-role PID drift lack a permanent requirement"
    goal = goals[identifier]
    assert manifest["goals"][415] == goal
    assert set(goal) == registry.GOAL_FIELDS
    text = registry.canonical(goal).decode("utf-8").lower()
    for term in ("supplied", "assembler", "stdout", "independent", "exit", "source",
                 "before", "after", "artifact", "size", "95", "128", "missing",
                 "official_slot", "capture_owner", "route", "raw", "hash", "fixture",
                 "same-pid", "cross-role", "100", "101", "collection", "error",
                 "not_run", "no i/o", "not a collector", "freshness", "50",
                 "tools/observation_producer.py", "tests/test_observation_producer.py",
                 "red-cross-role-pid-samples.xml", "green-cross-role-pid-samples.xml",
                 "independent-final-review-50.xml",
                 "integration-red-public-import.xml", "integration-green-related.xml", "196",
                 "772bf3a87d549e39ddec521f74cf59f511b17da1320f3edb81bb0a5b4da055e3",
                 "f4b750babade963701fd37c99558133c30c4635b5592db4cbbb2a6802f0dbec2",
                 "8bc2794c9769558d22ec27ec86ef94081af286478a53a584cc3abe53e0665f8c",
                 "e74a73a9477bc092c4380ac00ae2f0289cdae3388a2a612d068c591832bb93c6",
                 "21c9a15c192e62c81cd77fba9a3a702cc9cdae63aed4362907b59bc16255b2b4",
                 "d011ba049ef12c25bdbea0b71489b99b21e3aa4988e4eb1d99784136228b546f"):
        assert term in text
    assert len(goal["required_evidence"]) >= 6
    row = manifest["applicability"][identifier]
    assert row["applicability"] == "APPLICABLE"
    assert row["evidence_status"] == "NOT_RUN"
    assert row["counts_as_pass"] is False and row["evidence_refs"] == []
    assert row["goal_sha256"] == registry.digest(registry.canonical(goal))
    assert registry.effective_applicability(manifest)[identifier] == row
    for field, value in (("evidence_status", "PASS"), ("counts_as_pass", True),
                         ("evidence_refs", ["build/observation-producer-development-20261004/independent-final-review-50.xml"]),
                         ("applicability", "OUT_OF_SCOPE")):
        changed = copy.deepcopy(manifest)
        changed["applicability"][identifier][field] = value
        with pytest.raises(registry.RegistryError, match="applicability"):
            registry.validate_manifest(changed, source_bytes)
        with pytest.raises(registry.RegistryError, match="seed"):
            registry.effective_applicability(changed)
    changed = copy.deepcopy(manifest)
    del changed["goals"][415]
    with pytest.raises(registry.RegistryError, match="goals"):
        registry.validate_manifest(changed, source_bytes)
    assert manifest["qualification"]["installable"] is False
    assert manifest["qualification"]["package_created"] is False


def test_dependency_completion_append_preserves_every_416_goal_and_seed(manifest):
    prior = manifest["goals"][:416]
    prior_seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "dc9befd3a7b91f80a3d55e001e5991cffb7af967b5eac383641d750347aeaf1a"
    assert registry.digest(registry.canonical(prior_seed)) == "108f049fad106d61c93e431e5a4a0aaec063bb83818a9ef32cd3b60d54380a36"
    assert registry.digest(registry.canonical(prior[-1])) == "2849b8cd2ab7586bcfb2a7221f4608ebb0b39d3363cba459a07600702c808655"
    assert registry.canonical(prior_seed) == registry.canonical(registry.initial_applicability(prior))


def test_running_dependency_session_is_not_completed_stage_or_audit_evidence(manifest, source_bytes):
    identifier = "X2D-RG-417"
    goals = {goal["id"]: goal for goal in manifest["goals"]}
    assert identifier in goals, "Premature dependent-stage launch lacks a permanent workflow requirement"
    goal = goals[identifier]
    assert manifest["goals"][416] == goal
    assert set(goal) == registry.GOAL_FIELDS
    text = registry.canonical(goal).decode("utf-8").lower()
    for term in ("workflow", "session", "44541", "completion", "exit", "await",
                 "artifact", "filenotfounderror", "exact-stage/payload-stage.json",
                 "local_payload_roundtrip_pass", "rg416", "rg417", "no tests",
                 "not a product", "no backfill", "not_run", "transcript",
                 "root_launch_failure.json", "not a reconstructed raw process log",
                 "f377e3dc2e88a4af97d3417c46fbb9d0fd328013dd0e1c1298c21b975d8c6516",
                 "b429ce53b80bed79805f3e4ebce9a8b78374da48b767b16c3e46507daff5a63a"):
        assert term in text
    assert len(goal["required_evidence"]) >= 4
    row = manifest["applicability"][identifier]
    assert row["applicability"] == "APPLICABLE"
    assert row["evidence_status"] == "NOT_RUN"
    assert row["counts_as_pass"] is False and row["evidence_refs"] == []
    assert row["goal_sha256"] == registry.digest(registry.canonical(goal))
    assert registry.effective_applicability(manifest)[identifier] == row
    for field, value in (("evidence_status", "PASS"), ("counts_as_pass", True),
                         ("evidence_refs", ["build/peer-route-review-20261004-rg416/exact-stage/payload-stage.json"]),
                         ("applicability", "OUT_OF_SCOPE")):
        changed = copy.deepcopy(manifest)
        changed["applicability"][identifier][field] = value
        with pytest.raises(registry.RegistryError, match="applicability"):
            registry.validate_manifest(changed, source_bytes)
        with pytest.raises(registry.RegistryError, match="seed"):
            registry.effective_applicability(changed)
    changed = copy.deepcopy(manifest)
    del changed["goals"][416]
    with pytest.raises(registry.RegistryError, match="goals"):
        registry.validate_manifest(changed, source_bytes)
    assert manifest["qualification"]["installable"] is False
    assert manifest["qualification"]["package_created"] is False


def test_fixed_query_bridge_append_preserves_every_417_goal_and_seed(manifest):
    prior = manifest["goals"][:417]
    prior_seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "1dae97bb1d71e786f2b8f78f825f02092eeba64e1486cc9417e64274a3cd877f"
    assert registry.digest(registry.canonical(prior_seed)) == "c141a1d25a79cf1822bdb181304e0f2126cc34ba66ccbea7ce113f8c2d7a5313"
    assert registry.digest(registry.canonical(prior[-1])) == "07beedaf549cda546710568802e5ff5ad7896917eb192d72383451b94cccc39a"
    assert registry.canonical(prior_seed) == registry.canonical(registry.initial_applicability(prior))


def test_fixed_query_bridge_preserves_per_query_provenance_without_collection_authority(manifest, source_bytes):
    identifier = "X2D-RG-418"
    goals = {goal["id"]: goal for goal in manifest["goals"]}
    assert identifier in goals, "Fixed independent-query bridge lacks a permanent local requirement"
    goal = goals[identifier]
    assert manifest["goals"][417] == goal
    assert set(goal) == registry.GOAL_FIELDS
    text = registry.canonical(goal).decode("utf-8").lower()
    for term in ("six", "15", "single-command", "composite", "shelllastexitcode",
                 "name", "command", "exit_code", "source_id", "sha256", "partial",
                 "missing", "failed", "raw", "no i/o", "not a collector", "not_run",
                 "rg229", "rg260", "factory_reply", "adb", "freshness", "95",
                 "81", "single_boot_id", "single_gui_pid", "single_service_pid",
                 "single_gui_hash", "single_service_hash", "single_sensor_hash",
                 "incomplete", "transport_or_validation_failure", "finishedutc",
                 "fixed_readout_complete_not_qualification", "fifteenth", "completion",
                 "red-report-completion.xml", "green-report-completion.xml", "did not raise",
                 "7bcfa8c2fa35849287cc09db06c829229bb602821d2b961e90cd7845039acc94",
                 "6d13a1c7c4c3a22c22e017a284ae387cc3fe546294bafea460792a94b80f1b60",
                 "tools/observation_query_bridge.py", "tests/test_observation_query_bridge.py",
                 "tools/live_readout.py", "not a live-camera defect"):
        assert term in text
    assert len(goal["required_evidence"]) >= 5
    row = manifest["applicability"][identifier]
    assert row["applicability"] == "APPLICABLE"
    assert row["evidence_status"] == "NOT_RUN"
    assert row["counts_as_pass"] is False and row["evidence_refs"] == []
    assert row["goal_sha256"] == registry.digest(registry.canonical(goal))
    assert registry.effective_applicability(manifest)[identifier] == row
    for field, value in (("evidence_status", "PASS"), ("counts_as_pass", True),
                         ("evidence_refs", ["build/local-fixed-query-bridge-result.json"]),
                         ("applicability", "OUT_OF_SCOPE")):
        changed = copy.deepcopy(manifest)
        changed["applicability"][identifier][field] = value
        with pytest.raises(registry.RegistryError, match="applicability"):
            registry.validate_manifest(changed, source_bytes)
        with pytest.raises(registry.RegistryError, match="seed"):
            registry.effective_applicability(changed)
    changed = copy.deepcopy(manifest)
    del changed["goals"][417]
    with pytest.raises(registry.RegistryError, match="goals"):
        registry.validate_manifest(changed, source_bytes)
    assert manifest["qualification"]["installable"] is False
    assert manifest["qualification"]["package_created"] is False


def test_symlink_capability_append_preserves_every_418_goal_and_seed(manifest):
    prior = manifest["goals"][:418]
    prior_seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "e8ef4668a70c0536e8becaf99e61a49a3d832cae9eec0474c5074131b71b797c"
    assert registry.digest(registry.canonical(prior_seed)) == "b4acec1a1e5f68449403b6b3a0221c75f768f77287986012913a54f98146b94e"
    assert registry.digest(registry.canonical(prior[-1])) == "fcdf92c3c2e6e2dcd14a2c13243dcb2edbfb113f794ce626af16035f6ed59db9"
    assert registry.canonical(prior_seed) == registry.canonical(registry.initial_applicability(prior))
    other_fields = {key: value for key, value in manifest.items() if key not in ("goals", "applicability")}
    other_fields = copy.deepcopy(other_fields)
    for binding in ("input_seed_sha256", "input_goals_sha256", "effective_rows_sha256"):
        del other_fields["applicability_review"][binding]
    assert registry.digest(registry.canonical(other_fields)) == "a7f45fda5c5408faf13f6aeadcb2a472d47ef39f9f25aa331cd909ae01fcbd00"


def test_deployment_lifecycle_gap_preserves_prior_goals_and_final_gates(manifest):
    prior = manifest["goals"][:420]
    rows = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "5c4cb28ce2468ed61202d98420c558bfbcd4a63b2eb6ca0a8ba8b2f450645973"
    assert registry.digest(registry.canonical(rows)) == "79e1dfa41f6f2836aeaaecaea7b8ab0872b5728619c5e7a43853c24cd4f0216e"
    goal = manifest["goals"][420]
    assert goal["id"] == "X2D-RG-421"
    required = registry.canonical(goal).decode("utf-8").lower()
    for term in ("purpose/action", "eight-member", "pid/start_ticks", "attempt marker",
                 "photos", "calibration", "independent official recovery", "not_run",
                 "first observed birth", "partial stage", "matching stdout", "delivery_identity",
                 "stdin", "real candidate", "backend drift", "session-context.data"):
        assert term in required
    row = registry.effective_applicability(manifest)[goal["id"]]
    assert row["applicability"] == "APPLICABLE"
    assert row["evidence_status"] == "NOT_RUN"
    assert not row["counts_as_pass"] and row["evidence_refs"] == []


def test_reference_domain_split_preserves_prior_goals_and_rejects_inferred_permissions(manifest):
    prior = manifest["goals"][:421]
    rows = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "d62409d39c4d18f77e47209baf024dbb29a2f3c09a3b225f02da8835ddbf4230"
    assert registry.digest(registry.canonical(rows)) == "c3edc77363503edeae3d3ec14b63163ab33c0f0cd301914fc9bf42d26e63f661"
    goal = manifest["goals"][421]
    assert goal["id"] == "X2D-RG-422"
    required = registry.canonical(goal).decode("utf-8").lower()
    for term in ("u:r:su:s0", "u:r:hbl_camera_service:s0", "system_file", "chcon",
                 "maps", "eacces", "nonce", "600", "current loaded policy",
                 "not_run", "gui recovery", "file removal", "identity-only",
                 "explicitly interrupted", "fixtures", "permissive", "runcon"):
        assert term in required
    row = registry.effective_applicability(manifest)[goal["id"]]
    assert row["applicability"] == "APPLICABLE"
    assert row["evidence_status"] == "NOT_RUN"
    assert row["counts_as_pass"] is False and row["evidence_refs"] == []


def test_role_integration_findings_preserve_all_422_goals_and_no_inferred_pass(manifest):
    prior = manifest["goals"][:422]
    rows = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "b80127194954d1d80fcaedc2102756f737680dfe352a04cd3a5dcbbc85e8db44"
    assert registry.digest(registry.canonical(rows)) == "5e352df16d54478832c74ffb058b5bd36f5a116d00083b50cfae99566d846cc4"
    expected = {
        423: ("exact requested path", "ls -zd"),
        424: ("after the ack", "temporary inode", "same open-descriptor"),
        425: ("status 1", "status 2", "2147483047", "2147483647"),
        426: ("81a4", "native shell completion", "output-hash-bound"),
        427: ("backup inode", "getfattr", "official rc first"),
        428: ("okay", "clse", "receiveexact", "counterfactual"),
        429: ("198", "90-second", "600-second", "send-time"),
        430: ("197609", "exit 32", "without recreating payloads"),
        431: ("stable", "runtime data", "combined-su", "final installation approval"),
    }
    effective = registry.effective_applicability(manifest)
    for number, terms in expected.items():
        goal = manifest["goals"][number - 1]
        assert goal["id"] == f"X2D-RG-{number}"
        text = registry.canonical(goal).decode().lower()
        assert all(term in text for term in terms)
        row = effective[goal["id"]]
        assert row["applicability"] == "APPLICABLE" and row["evidence_status"] == "NOT_RUN"
        assert row["counts_as_pass"] is False and row["evidence_refs"] == []


def test_domain_terminator_requirement_preserves_prior_goals_and_identity_values(manifest):
    prior = manifest["goals"][:419]
    rows = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "9da63ec0a9bc41db1f82e0c4273b584758c512e7c00bfbc3de693bf650826f82"
    assert registry.digest(registry.canonical(rows)) == "af62ccf5dcf131d22c2e95affd99de77e71b10ced363eaf9580e102fbb69c297"
    goal = manifest["goals"][419]
    assert goal["id"] == "X2D-RG-420"
    text = registry.canonical(goal).decode("utf-8").lower()
    for term in ("147-byte", "rg381", "single terminal nul", "embedded", "repeated", "wrong-field",
                 "without camera access", "historical failed reports unchanged", "not_run"):
        assert term in text
    row = registry.effective_applicability(manifest)[goal["id"]]
    assert row["applicability"] == "APPLICABLE"
    assert row["evidence_status"] == "NOT_RUN"
    assert row["counts_as_pass"] is False and row["evidence_refs"] == []


def test_formal_recovery_and_compressed_review_append_preserves_all_431_goals(manifest):
    prior = manifest["goals"][:431]
    seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "23f0f5b4ee97b2c3634a6b41255dd1dc4759c090af38cafe524cb5f7f18f532d"
    assert registry.digest(registry.canonical(seed)) == "80bc259dbdac9d88d0e9205820056d63e502b7b62d5609775bd37541712d8d54"
    assert registry.canonical(seed) == registry.canonical(registry.initial_applicability(prior))


@pytest.mark.parametrize("number,terms", [
    (432, ("system_file", "hbl_camera_service", ".original", "activate.stage", "restore.stage", "init scan roots")),
    (433, ("eleven", "six", "combined-su", "official rc first", "maps", "exact owned", "same-content")),
    (434, (".content.b64", ".content.gz", ".content.tar", "replacement inode", "three", "retained", "independent-red")),
    (435, ("x2dii-session-context-v2", "x2dii-session-context-v3", "install", "menu_validation", "standalone", "197609", "fixture")),
])
def test_formal_recovery_and_staging_findings_cannot_be_weakened_or_claimed_pass(manifest, source_bytes, number, terms):
    identifier = f"X2D-RG-{number}"
    goals = {goal["id"]: goal for goal in manifest["goals"]}
    assert identifier in goals, "Independent integration finding lacks a permanent requirement"
    goal = goals[identifier]
    assert manifest["goals"][number - 1] == goal and set(goal) == registry.GOAL_FIELDS
    text = registry.canonical(goal).decode().lower()
    assert all(term in text for term in terms)
    assert len(goal["required_evidence"]) >= 3
    row = manifest["applicability"][identifier]
    assert row["applicability"] == "APPLICABLE" and row["evidence_status"] == "NOT_RUN"
    assert row["counts_as_pass"] is False and row["evidence_refs"] == []
    assert registry.effective_applicability(manifest)[identifier] == row
    for field, value in (("evidence_status", "PASS"), ("counts_as_pass", True),
                         ("evidence_refs", ["build/local-only-review.xml"]),
                         ("applicability", "OUT_OF_SCOPE")):
        changed = copy.deepcopy(manifest)
        changed["applicability"][identifier][field] = value
        with pytest.raises(registry.RegistryError, match="applicability"):
            registry.validate_manifest(changed, source_bytes)
        with pytest.raises(registry.RegistryError, match="seed"):
            registry.effective_applicability(changed)
    changed = copy.deepcopy(manifest)
    changed["goals"][number - 1]["required_behavior"] = "Requirement weakened by caller"
    with pytest.raises(registry.RegistryError, match="goals"):
        registry.validate_manifest(changed, source_bytes)
    with pytest.raises(registry.RegistryError, match="goals"):
        registry.effective_applicability(changed)
    assert not manifest["qualification"]["installable"]
    assert not manifest["qualification"]["package_created"]


def test_native_symlink_skip_requires_an_actual_capability_attempt_without_audit_pass_transfer(manifest, source_bytes):
    identifier = "X2D-RG-419"
    goals = {goal["id"]: goal for goal in manifest["goals"]}
    assert identifier in goals, "Unconditional Windows symlink skip lacks a permanent test-capability requirement"
    goal = goals[identifier]
    assert manifest["goals"][418] == goal
    assert set(goal) == registry.GOAL_FIELDS
    text = registry.canonical(goal).decode("utf-8").lower()
    for term in ("windows", "unconditional", "skipif", "symlink", "1314", "four",
                 "one", "five", "permission", "attempt", "propagate", "modeled",
                 "not_run", "rg418", "snapshot", "not a camera", "no permission escalation",
                 "tests/test_delivery_files.py", "test_real_symlinked_payload_is_rejected",
                 "build/symlink-skip-review-20261004/", "fresh", "full audit",
                 "5b1175a530c0e8e4a15525fb24a483bc12ca1779f6b996f049a202be15ea5e7b"):
        assert term in text
    assert len(goal["required_evidence"]) >= 5
    row = manifest["applicability"][identifier]
    assert row["applicability"] == "APPLICABLE"
    assert row["evidence_status"] == "NOT_RUN"
    assert row["counts_as_pass"] is False and row["evidence_refs"] == []
    assert row["goal_sha256"] == registry.digest(registry.canonical(goal))
    assert registry.effective_applicability(manifest)[identifier] == row
    for field, value in (("evidence_status", "PASS"), ("counts_as_pass", True),
                         ("evidence_refs", ["build/peer-route-review-20261004-rg418/AUDIT.json"]),
                         ("applicability", "OUT_OF_SCOPE")):
        changed = copy.deepcopy(manifest)
        changed["applicability"][identifier][field] = value
        with pytest.raises(registry.RegistryError, match="applicability"):
            registry.validate_manifest(changed, source_bytes)
        with pytest.raises(registry.RegistryError, match="seed"):
            registry.effective_applicability(changed)
    changed = copy.deepcopy(manifest)
    del changed["goals"][418]
    with pytest.raises(registry.RegistryError, match="goals"):
        registry.validate_manifest(changed, source_bytes)
    assert manifest["qualification"]["installable"] is False
    assert manifest["qualification"]["package_created"] is False


def test_runtime_lifecycle_review_append_preserves_all_435_goals(manifest):
    prior = manifest["goals"][:435]
    seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "722935f3d5e247cd234368ea72686781d00a8946e0947f5f804f272c764facd3"
    assert registry.digest(registry.canonical(seed)) == "e2ff43cde93887462c73ab8f390b023b5589675c90890da9e47ce879c4395a78"
    assert registry.canonical(seed) == registry.canonical(registry.initial_applicability(prior))


def test_staging_reuse_review_append_preserves_all_447_goals(manifest):
    prior = manifest["goals"][:447]
    seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "36e09b0feea7170ca79fdc7289b471945eefed910884ca639e2f68ef226b281d"
    assert registry.digest(registry.canonical(seed)) == "410fd3e42196154eebc292d2844c43ba6b96fb8d464949fc1835a3bb591ea46b"
    assert registry.canonical(seed) == registry.canonical(registry.initial_applicability(prior))


def test_boot_receipt_review_append_preserves_all_442_goals(manifest):
    prior = manifest["goals"][:442]
    seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "fc44bd0f41eeb43e9ade134bd81f4a1006156330c8a02dbbab7b6668f54eb774"
    assert registry.digest(registry.canonical(seed)) == "2bbe37fa470c469acb0efed3d959bd621d7105768d29faaa1d1f3a9aa6abf57a"
    assert registry.canonical(seed) == registry.canonical(registry.initial_applicability(prior))


def test_ready_window_review_append_preserves_all_458_goals(manifest):
    prior = manifest["goals"][:458]
    seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "0151a16345b644e59109f17ff79f9c0ce2afc71ca1a97966a0ae6c0ddad68eca"
    assert registry.digest(registry.canonical(seed)) == "11b7339b4ebfd5025deba17d319c42ffe6e340e72873f0596cfd6e12ee3a5486"
    assert registry.canonical(seed) == registry.canonical(registry.initial_applicability(prior))


def test_target_dependency_append_preserves_all_467_goals(manifest):
    prior = manifest["goals"][:467]
    seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "1bab2fd88c8d5f12dc1c748d857272ec1ba6161ab1eee28f4e04aba467e9b199"
    assert registry.digest(registry.canonical(seed)) == "81d15fc51fa6fbf42ca58173214a2ec49b7a399584894f6c5749cacba8f4c021"
    assert registry.canonical(seed) == registry.canonical(registry.initial_applicability(prior))


def test_formal_install_append_preserves_all_468_goals(manifest):
    prior = manifest["goals"][:468]
    seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "31fda8eb1dfcefa46e93ae7b1bef31315efeee283118332ea8fe2db5bd537372"
    assert registry.digest(registry.canonical(seed)) == "8500a3966bf5db6cd3d46f6c4ab1ca48bb0e760427b38e043c1f381ec45800d2"
    assert registry.canonical(seed) == registry.canonical(registry.initial_applicability(prior))


def test_qualified_route_append_preserves_all_469_goals(manifest):
    prior = manifest["goals"][:469]
    seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "38b7c7fa843c7996b7910d04084dded09e3443f92620159287a38ef68266b08c"
    assert registry.digest(registry.canonical(seed)) == "8547ecb144c11e510b21f51b9a564be55a3042afb9e9d78e952f47e5627dad1a"
    assert registry.canonical(seed) == registry.canonical(registry.initial_applicability(prior))


def test_budget_and_first_validation_append_preserves_all_471_goals(manifest):
    prior = manifest["goals"][:471]
    seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "803caa7eafac1d39134f00b05d5dd56eccc32134bbce63f03e7270ed8eefeb96"
    assert registry.digest(registry.canonical(seed)) == "eb55619f78878e65ee8dc0a3c8dbfe08018289c46bb75caf53b824dd0dde9122"
    assert registry.canonical(seed) == registry.canonical(registry.initial_applicability(prior))


def test_public_entry_and_collector_append_preserves_all_473_goals(manifest):
    prior = manifest["goals"][:473]
    seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "8b5e5d90f23cae563664ff825e10229bbb5bab9fe37c35ecea54ba3f04a4f28b"
    assert registry.digest(registry.canonical(seed)) == "82fbaf5f99bfb2a827c65de78770c4d891bf6553aab044a10d17d2d9c50ac500"
    assert registry.canonical(seed) == registry.canonical(registry.initial_applicability(prior))


def test_signal_cleanup_append_preserves_all_485_goals(manifest):
    prior = manifest["goals"][:485]
    seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "ecbec44b1c668cdd234846afca9526d09b4980f972401d682c99a6748d72ebeb"
    assert registry.digest(registry.canonical(seed)) == "9be0961ad4b5eab65722f90ced26bb84683713c2a94f34d8d796b139f63c0039"
    assert registry.canonical(seed) == registry.canonical(registry.initial_applicability(prior))


def test_shell_fault_boundary_append_preserves_all_486_goals(manifest):
    prior = manifest["goals"][:486]
    seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "a4b24f75d3d5053296e2dd40ccfcc5f7e0a4f2c3f0562359865e494db88f68de"
    assert registry.digest(registry.canonical(seed)) == "6e624aae83cadf6f9ef960620731207fb563c4299e340967233a22366670dfa4"
    assert registry.canonical(seed) == registry.canonical(registry.initial_applicability(prior))


def test_exec_transition_append_preserves_all_487_goals(manifest):
    prior = manifest["goals"][:487]
    seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "ad7256fbcc557061856cbaf048c3cfc7057790c6f0e2565bb5ded68c7bd65e46"
    assert registry.digest(registry.canonical(seed)) == "e91e760fd3e05420efa4fced78dec83d3005d8daac42a761f235766b8ad299e3"
    assert registry.canonical(seed) == registry.canonical(registry.initial_applicability(prior))


def test_stage_budget_and_known_child_exit_append_preserve_all_488_goals(manifest):
    prior = manifest["goals"][:488]
    seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "c293dded220d01df34d88aebe67feabe181973bdef0529429f37d4cfd758a85d"
    assert registry.digest(registry.canonical(seed)) == "908d81a5acbdfd27b60e09eccbc2a7bbde582fa9b16dacdb8a7a0601bdc177ff"
    assert registry.canonical(seed) == registry.canonical(registry.initial_applicability(prior))


def test_same_file_failure_retention_append_preserves_all_490_goals(manifest):
    prior = manifest["goals"][:490]
    seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "ae804b4cd8f818713af938046e1ca88e80a53f50cc590a16bee06e3adc5a2701"
    assert registry.digest(registry.canonical(seed)) == "12841eb9d2e116328ea21dcbf7f99324cf4b0e14832f13617ada2e37f46685b5"
    assert registry.canonical(seed) == registry.canonical(registry.initial_applicability(prior))


def test_controller_exit_append_preserves_all_491_goals(manifest):
    prior = manifest["goals"][:491]
    seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "c3cf6afa8baf2dcba377950c753f0adde252ba306cd627960986c1df4c0045c2"
    assert registry.digest(registry.canonical(seed)) == "c5fb48b6e217704490beb6a84cfe8a92a12fd0de37807f1b9d6e8a3038443ea6"
    assert registry.canonical(seed) == registry.canonical(registry.initial_applicability(prior))


def test_cancel_writer_loss_append_preserves_all_492_goals(manifest):
    prior = manifest["goals"][:492]
    seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "927492e627f8c45111674e659dae120c8239bfc1637c58bcf89522fd70435df6"
    assert registry.digest(registry.canonical(seed)) == "072dc40cbb360f42ecaf0c58c316960b9b59279aaeea6a76ed63cfab90999895"
    assert registry.canonical(seed) == registry.canonical(registry.initial_applicability(prior))


def test_fault_boundary_and_diagnostic_append_preserves_all_493_goals(manifest):
    prior = manifest["goals"][:493]
    seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "fd92357be5e42204d73518f6c00163c69a15bad10762937c4fefdde955073be0"
    assert registry.digest(registry.canonical(seed)) == "9c09736bba2866f648c5d3ba76b4edddced236828a1b46d823716784779c5768"
    assert registry.canonical(seed) == registry.canonical(registry.initial_applicability(prior))


def test_host_observation_append_preserves_all_495_goals(manifest):
    prior = manifest["goals"][:495]
    seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "54c4d1278c5bebb36f735fc63d776b6183ced71c9e63d8509603b564e7fa80fd"
    assert registry.digest(registry.canonical(seed)) == "d90f329e3bff4f3ecd7685dcaf8b0d0890e7d57088bd9d8f7cea0c21bb4c6697"
    assert registry.canonical(seed) == registry.canonical(registry.initial_applicability(prior))


def test_launch_wait_and_host_birth_append_preserve_all_496_goals(manifest):
    prior = manifest["goals"][:496]
    seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "0cb67e151ea8bad2580433fb5de37ef464207ac89b5b118f9846424956ee3bb8"
    assert registry.digest(registry.canonical(seed)) == "0754e94a6992169eecf2fccd22bc2e73832f20ad44b56e9753cb10536f942c83"
    assert registry.canonical(seed) == registry.canonical(registry.initial_applicability(prior))


def test_stop_timeout_append_preserves_all_498_goals(manifest):
    prior = manifest["goals"][:498]
    seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "6ef608e3e83a67a7ddafbdcc6edce30bf111e78d347205f75810dfcaf93aa1c4"
    assert registry.digest(registry.canonical(seed)) == "a2e235faf2f4d546bd6b8b8a249b56ed339e5bb208e79cf1823b16b89efb2bea"
    assert registry.canonical(seed) == registry.canonical(registry.initial_applicability(prior))


def test_shared_clock_append_preserves_all_499_goals(manifest):
    prior = manifest["goals"][:499]
    seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "eaa200b5271ecd08449361f897a5d20bffc30ea049d647c0c72791936cfa15bb"
    assert registry.digest(registry.canonical(seed)) == "b66fa8530024dcd002f788982339fc16583fc6db92331cad3f85f2f7449d4b2c"
    assert registry.canonical(seed) == registry.canonical(registry.initial_applicability(prior))


def test_boot_observer_host_wait_append_preserves_all_500_goals(manifest):
    prior = manifest["goals"][:500]
    seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "c2cdec81a82b3b5bfd26abea076743cccdfd676586624a065199457f0d04dda5"
    assert registry.digest(registry.canonical(seed)) == "a47c1568868fa92d536be7ef6c5d6f75c44605ec7e6eab0a9b28faa637352c7d"
    assert registry.canonical(seed) == registry.canonical(registry.initial_applicability(prior))


def test_controller_loss_and_cache_append_preserve_all_483_goals(manifest):
    prior = manifest["goals"][:483]
    seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "d64b40f86931f6c713a1373c9c52f7b18ca3149dc29461827f947d0b3fff85e2"
    assert registry.digest(registry.canonical(seed)) == "7d7071d49a8d8f8fddf24068246da787226cfb33722aa423f0e411b3d1d114b4"
    assert registry.canonical(seed) == registry.canonical(registry.initial_applicability(prior))


def test_boot_acceptance_append_preserves_all_475_goals(manifest):
    prior = manifest["goals"][:475]
    seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "1e9f1163af6540660eff40cc27ea11040de4f254c1121786dbcba71fc8cef030"
    assert registry.digest(registry.canonical(seed)) == "7e593f1e09971457f3ecd6d35d84037979454fec2e4997904d02904200248de1"
    assert registry.canonical(seed) == registry.canonical(registry.initial_applicability(prior))


def test_recovery_domain_review_append_preserves_all_480_goals(manifest):
    prior = manifest["goals"][:480]
    seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "71cf06b2b592d072b658fbedaf7cba8afa3254dd8c5ecbdc856e4756f31cbc68"
    assert registry.digest(registry.canonical(seed)) == "c56ea1303a67cab8fba8b1976ec9b9a6f370b8a26dbef565d04e072879077b0a"
    assert registry.canonical(seed) == registry.canonical(registry.initial_applicability(prior))


def test_boot_provenance_review_append_preserves_all_481_goals(manifest):
    prior = manifest["goals"][:481]
    seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "83dc60a240ee3ff3e6bf559d46ca4437486fc9127a3d8291ef36d6348f4b51ce"
    assert registry.digest(registry.canonical(seed)) == "0d64b80128c3d46e2ae023d583f58ff88b82b2e03781c11c7bb910d91108d0bb"
    assert registry.canonical(seed) == registry.canonical(registry.initial_applicability(prior))


@pytest.mark.parametrize("number,terms", [
    (436, ("normalization", "replacement", "chmod", "&&", "semicolon", "privileged")),
    (437, ("partial_evidence", "cleanup_errors", "original", "receipt", "host", "watchdog")),
    (438, ("session-context-", "sha", "nonce", "already-official", "immutable", "fresh")),
    (439, ("menu-validation-preplace-", "preplace-", "/v", "/o", "four", "reuse", "absent-only")),
    (440, ("nul", "1024", "canonical", "read", "four", "input hash")),
    (441, ("collection", "27", "7", "sha-session", "frozen", "zero tests")),
    (442, ("pre-command", "90-second", "600-second", "10-second", "pid", "watchdog")),
    (443, ("non-ascii", "unicodedecodeerror", "failed", "ack", "four", "public")),
    (444, ("append", "replacement inode", "2048", "4096", "absent-only", "hash")),
    (445, ("4096", "actual", "v3", "frame", "fixture", "limits")),
    (446, ("metadata", "root", "644", "official", "label", "unhealthy", "unknown")),
    (447, ("eight-second", "120", "maintenance", "short", "receipt", "recovery")),
    (448, ("stage_peer_usb_access", "pnnn", "96", "unknown", "append", "hash")),
    (449, ("observer", "po", "chmod", "replacement", "absent-only", "prepare")),
    (450, ("directory.identity", "inode", "stop_requested", "77310", "6544", "modeled")),
    (451, ("final.pending", "partially", "33", "34641", "mv -n", "atomic")),
    (452, ("final.pending", "replacement inode", "74", "0", "same-content", "promote")),
    (453, ("failed_or_uncertain", "preparedbootoperation", "start_process", "pre-command", "error")),
    (454, ("_drive_stage_process", "partial_evidence", "terminate", "original", "prefix", "cleanup_errors")),
    (455, ("97", "96", "80", "69", "ready", "static", "minimum_command_gap")),
    (456, ("/v", "/a", "/r", "l/w/t/q/s", "staging table", "source-level")),
    (457, ("tar -xf", "unknown", "exclusive", "stdout", "13.10", "overwrite")),
    (458, ("/tmp", "plan_boot_observer_staging", "cold", "source-level", "read-only", "action")),
    (459, ("preparedmenuplacementoperation", "same-window", "preflight", "90-second", "retained", "baseline", "physical")),
    (460, ("/tmp/", "-c /tmp", "host", "eight", "fixture", "467", "retained")),
    (461, ("174", "233", "232", "envelope", "cleanup", "fixed", "hash")),
    (462, ("nul", "maps", "command substitution", "observed_match", "complete", "count")),
    (463, ("extra_xattr", "metadata", "unlink", "toybox", "names", "values")),
    (464, ("current", "environ", "ld_preload", "x2dii_menu_extension", "hex", "nul", "identity")),
    (465, ("8.359", "30-second", "eight-second", "80-second", "removed=0", "model")),
    (466, ("launch_started_utc", "600", "original", "payload", "different-launch", "missing-launch")),
    (467, ("stagersha256", "replysources", "source attribution", "authenticity", "start_process", "three")),
    (468, ("awk", "toybox", "host", "not establish", "runtime provider", "eight-second", "80-second")),
    (469, ("/o", "install_preparation", "stable", "parent", "steps=()", "start_process", "namespace", "not authenticity")),
    (470, ("run_qualified", "60-second", "for_publication", "commit-last", "official_rc_only_owned_files_retained", "counterfactual", "first temporary", "closure")),
    (471, ("stderr", "65536", "100000", "concurrent", "drain", "original", "windows", "deadline", "200-byte")),
    (472, ("49", "48", "40", "min_command_gap_seconds", "integer", "17", "60", "remaining", "lower bound")),
    (473, ("first", "v3", "stop", "nan", "infinity", "no independent red", "single-attempt", "send_message", "not a camera")),
    (474, ("public", "default", "each new write", "approval", "final", "33", "78", "120", "canonical", "not installation")),
    (475, ("15", "partial", "session", "received.bin", "dotted", "canonical", "before any", "expected", "independent", "unknown")),
    (476, ("formal", "canonical", "six", "two", "//system", "/vendor/etc/init", "overlap", "not_run")),
    (477, ("activation", "four", "two", "install", "v2", "maintenance", "received.bin", "not_run")),
    (478, ("circular", "first", "boot", "default", "retained", "independent", "recovery", "not_run")),
    (479, ("recovery", "collector", "absent", "label", "partial", "not_run")),
    (480, ("interrupted", "4294967295", "failures=[]", "longrepr", "unknown", "not_run")),
    (481, ("double", "raw", "nul", "lf", "crlf", "before", "after", "six", "seven", "not_run")),
    (482, ("prepared", "subtype", "worker phase", "raw", "grammar", "six-field", "restore_attempt",
           "previous_restore_evidence", "saved predecessor", "failed lock", "not observation", "not_run")),
    (483, ("windows", "fixture", "60", "120", "180", "1072", "transient", "capture-owner",
           "refusal", "leases", "not_run")),
    (484, ("sigkill", "first stop", "guardian", "spawn", "admission", "lifetime", "readonly",
           "receipt", "unknown", "not_run")),
    (485, ("unsigned", "64", "alignment", "24-byte", "mapping", "overflow", "checked",
           "loader", "not_run")),
    (486, ("disconnect", "connect", "pre-operation", "exactly one", "immediate", "persistent",
           "destruction", "flags", "not_run")),
    (487, ("redirection", "printf", "empty", "first byte", "before_offer", "123.00",
           "fixture", "not_run")),
    (488, ("exec", "env", "intermediate", "116.73", "offer", "admit", "start ticks",
           "direct", "unchanged", "not_run")),
    (489, ("76", "77", "80", "1.0", "a/r", "plan_boot_observer_staging", "six",
           "elapsed", "complete", "not_run")),
    (490, ("child_exited", "child_owned", "125.53", "reused", "unknown", "uncertain",
           "actual", "nonzero", "not_run")),
    (491, ("same-file", "35", "teardown", "730.58", "unknown", "crossed", "before",
           "retain", "unchanged", "not_run")),
    (492, ("mg_dead", "mg_role_process", "72.59", "controller", "start ticks", "unknown",
           "reused", "restore", "not_run")),
    (493, ("child.cancel.pending", "100.64", "writer", "subshell", "child_recorded", "admission",
           "neither", "before", "not_run")),
    (494, ("unrecorded", "marker", "wait", "still_live", "unknown_stat", "reused_lifetime",
           "z/x", "ticks", "earlier", "not_run")),
    (495, ("term", "finally", "copytree", "add_note", "cleanup", "original exception",
           "339.59", "212", "unknown", "not_run")),
    (496, ("35", "183.125", "187.109", "240", "24", "120", "170", "600",
           "80", "host", "same-file", "fail", "not_run")),
    (497, ("35", "child_loaded", "final-write-started", "pending-replaced", "five",
           "before", "after", "negative", "240", "not_run")),
    (498, ("host-stat", "host-shell", "456", "model", "original", "missing",
           "ticks", "finally", "not_run")),
    (499, ("143.77", "8", "stop", "timeoutexpired", "same", "popen", "30",
            "no retry", "unknown", "not_run")),
    (500, ("validation-started", "worker_first", "controller_first", "held", "release",
            "binary", "resume", "120", "170", "600", "80", "clock-owner-red-bs",
            "93", "bq", "gate", "$0", "mg_mode", "second", "not_run")),
    (502, ("supervision.dialogue", "dual_role_flow", "read8", "8.022480200", "11.297", "142", "30",
            "diagnostic k", "errno22", "wrapper", "nonstaged", "popen", "epoch", "$0", "default",
            "four", "not_run")),
    (501, ("boot_dialogue", "host_wait_seconds", "10.469", "8.766", "142", "30",
            "read8-diagnostic-b", "epoch", "nonstaged", "explicit", "$0", "default",
            "original", "restore", "not_run")),
    (503, ("guardian_transfer_fault_hook", "ml_run", "mg_controller_pid", "mg_controller_ticks",
            "offer_visible", "before_ready", "worker", "unset", "empty", "six", "failure-0003",
            "failure-0004", "read8", "recovery30", "untraced", "unchanged", "not_run")),
    (504, ("backrequested", "activeerror", "popup", "external", "forceactivefocus", "dismiss",
            "3858caa2f7e3021cdae7746bfaff9f194dfcfd336bbf4a7d1edd070e0d6d2e81",
            "a30968e8fc53286797e2db09bc748d43e80a925e7797b61f1894b63212a27990",
            "return", "release", "camera", "not_run")),
    (505, ("rg012", "for_publication", "pre_rollback_failure_bundle", "failure window", "bounded",
            "recovery_historical_regressions", "read_bytes", "guardian", "counterfactual", "22", "113", "120",
            "afeb7ae500909f4a1122beec72a4dc405125246c9853df286d4c1eff76df21d6",
            "9a0d678d2b8cf910c17d94f7443ba3fa34a29e34ef0a359ea75887adb043be34", "not_run")),
    (506, ("script_hashes", "inventory", "prepare", "representation", "preserve", "in-memory", "not_run")),
    (507, ("runner", "dependency", "source_inputs", "3449", "705", "frozen", "complete", "not_run")),
    (508, ("admin-launch-output.log", "final", "launcher", "digest", "retained", "public", "not_run")),
    (509, ("closed-log", "pipe", "pid", "birth", "parent", "command", "hash", "timeout",
            "terminal", "unknown", "independent execution host", "not_run")),
])
def test_runtime_lifecycle_findings_cannot_be_weakened_or_claimed_pass(manifest, source_bytes, number, terms):
    identifier = f"X2D-RG-{number}"
    goals = {goal["id"]: goal for goal in manifest["goals"]}
    assert identifier in goals, "Independent runtime finding lacks a permanent requirement"
    goal = goals[identifier]
    assert manifest["goals"][number - 1] == goal and set(goal) == registry.GOAL_FIELDS
    text = registry.canonical(goal).decode().lower()
    assert all(term in text for term in terms)
    assert len(goal["required_evidence"]) >= 3
    row = manifest["applicability"][identifier]
    assert row["applicability"] == "APPLICABLE" and row["evidence_status"] == "NOT_RUN"
    assert row["counts_as_pass"] is False and row["evidence_refs"] == []
    assert registry.effective_applicability(manifest)[identifier] == row
    for field, value in (("evidence_status", "PASS"), ("counts_as_pass", True),
                         ("evidence_refs", ["build/local-only-review.xml"]),
                         ("applicability", "OUT_OF_SCOPE")):
        changed = copy.deepcopy(manifest)
        changed["applicability"][identifier][field] = value
        with pytest.raises(registry.RegistryError, match="applicability"):
            registry.validate_manifest(changed, source_bytes)
        with pytest.raises(registry.RegistryError, match="seed"):
            registry.effective_applicability(changed)
    changed = copy.deepcopy(manifest)
    changed["goals"][number - 1]["required_behavior"] = "Requirement weakened by caller"
    with pytest.raises(registry.RegistryError, match="goals"):
        registry.validate_manifest(changed, source_bytes)
    with pytest.raises(registry.RegistryError, match="goals"):
        registry.effective_applicability(changed)
    assert not manifest["qualification"]["installable"]
    assert not manifest["qualification"]["package_created"]


def test_preplacement_observer_append_preserves_all_501_goals(manifest):
    prior = manifest["goals"][:501]
    seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "3085eb74850953d53bd4cabf55e0b7f3d735ce6236f8820c3c10a200a298ef3f"
    assert registry.digest(registry.canonical(seed)) == "500501ab727d412c0295c0840b49d184bce72e9724034264edb367d063f025dc"
    assert registry.canonical(seed) == registry.canonical(registry.initial_applicability(prior))


def test_guardian_transfer_hook_append_preserves_all_502_goals(manifest):
    prior = manifest["goals"][:502]
    seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "505fd652857a76f170eced3018c8a077144873da59202f34a94f76c7e90ad1f5"
    assert registry.digest(registry.canonical(seed)) == "d9ae2d50d9fffbe3f588524559646c7f7d9eb0f8f6a869e6f2d1fadd8eaf2e33"
    assert registry.canonical(seed) == registry.canonical(registry.initial_applicability(prior))


def test_back_focus_append_preserves_all_503_goals(manifest):
    prior = manifest["goals"][:503]
    seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "8a6321f314f0238f2f79f3d44eb441434dee127d9a72e45c2851782766593a68"
    assert registry.digest(registry.canonical(seed)) == "027b852f7f83dd6d660ce15873e857d00e82a3409d53dbb00462374025886369"
    assert registry.canonical(seed) == registry.canonical(registry.initial_applicability(prior))


def test_formal_recovery_bundle_append_preserves_all_504_goals(manifest):
    prior = manifest["goals"][:504]
    seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "8756fdc416780e7f80031dbe1da9661da5b314bf0bdd85ce8b8e0f6f704b01ff"
    assert registry.digest(registry.canonical(seed)) == "f8aafb7a70017b789403416eaa70fccda91b99e3389d4b66efa96e9346549030"
    assert registry.canonical(seed) == registry.canonical(registry.initial_applicability(prior))


def test_content_verifier_append_preserves_all_505_goals(manifest):
    prior = manifest["goals"][:505]
    seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "8b5a4c11fcaa1db5c1a087d9f097c650a4e6b46e2a7f5920c046c4724df4ee7a"
    assert registry.digest(registry.canonical(seed)) == "527ae5398dbb27f4004ddb181251f79f5b3aea7d61187a864a124a3fd8775c8e"
    assert registry.canonical(seed) == registry.canonical(registry.initial_applicability(prior))


def test_consumed_runner_append_preserves_all_506_goals(manifest):
    prior = manifest["goals"][:506]
    seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "96894e2be5c57672943954d1ecfe2a3da52cdd2550e11ebf0ccd6aad5b57be5e"
    assert registry.digest(registry.canonical(seed)) == "d807987952deb3609575b1536e215e979cbff69905ca081e97b8130402620376"
    assert registry.canonical(seed) == registry.canonical(registry.initial_applicability(prior))


def test_parent_log_binding_append_preserves_all_507_goals(manifest):
    prior = manifest["goals"][:507]
    seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "54e5511e615412f0a3614f1f236fa113fad7880345c8cd05136539e996e60830"
    assert registry.digest(registry.canonical(seed)) == "6c5bb43b2962613ae7d24d3f7345aafc3b4de16eb8dd2d36d5b9b43df47e98c6"
    assert registry.canonical(seed) == registry.canonical(registry.initial_applicability(prior))


def test_missing_terminal_receipt_append_preserves_all_508_goals(manifest):
    prior = manifest["goals"][:508]
    seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "b9eec038c92b8f1f3c4edc9c6a83d03959320644c7fb8de3c8194644332c62b9"
    assert registry.digest(registry.canonical(seed)) == "6ffdc631ec70773a8dd1e80da0a00e450fd290a50d0f6d862fef8c35321994aa"
    assert registry.canonical(seed) == registry.canonical(registry.initial_applicability(prior))
    goals = {goal["id"]: goal for goal in manifest["goals"]}
    assert "X2D-RG-509" in goals, "Lost audit execution lacks a permanent receipt requirement"
    text = registry.canonical(goals["X2D-RG-509"]).decode().lower()
    for term in ("closed-log", "pipe", "immediate", "pid", "birth", "parent", "command",
                 "hash", "existing output", "timeout", "terminal", "unknown",
                 "independent execution host", "not_run", "empty evidence"):
        assert term in text
    row = manifest["applicability"]["X2D-RG-509"]
    assert row["applicability"] == "APPLICABLE" and row["evidence_status"] == "NOT_RUN"
    assert row["counts_as_pass"] is False and row["evidence_refs"] == []
    assert not manifest["qualification"]["installable"]
    assert not manifest["qualification"]["package_created"]


def test_publisher_refusal_fixture_append_preserves_all_509_goals(manifest):
    prior = manifest["goals"][:509]
    seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "2dde755372a0abadbcc99785961711abb4a1b3f0ffbb3a23f1d8b4d337d69feb"
    assert registry.digest(registry.canonical(seed)) == "5b311f9a1bb64a74ba8b57b589d6874635edbcc6549db13c53ecd677621b0bcc"
    assert registry.canonical(seed) == registry.canonical(registry.initial_applicability(prior))
    goals = {goal["id"]: goal for goal in manifest["goals"]}
    assert "X2D-RG-510" in goals, "Obsolete public negative fixtures lack a permanent requirement"
    text = registry.canonical(goals["X2D-RG-510"]).decode().lower()
    for term in ("role-aware", "failure bundle", "exact", "refusal", "fixture",
                 "before", "unchanged", "not_run", "empty evidence"):
        assert term in text
    row = manifest["applicability"]["X2D-RG-510"]
    assert row["applicability"] == "APPLICABLE" and row["evidence_status"] == "NOT_RUN"
    assert row["counts_as_pass"] is False and row["evidence_refs"] == []
    assert not manifest["qualification"]["installable"]
    assert not manifest["qualification"]["package_created"]


def test_host_time_model_append_preserves_all_510_goals(manifest):
    prior = manifest["goals"][:510]
    seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "b51b1b894bf6a4de0d6e67ce9bfa0cfad2bd5ea3d6b5fd354a7d16b46e2af3e0"
    assert registry.digest(registry.canonical(seed)) == "fdd1e385d6d04368b03ed03fc10a97a5bbf7a30eff7077527dfebc57148dad95"
    assert registry.canonical(seed) == registry.canonical(registry.initial_applicability(prior))
    goals = {goal["id"]: goal for goal in manifest["goals"]}
    assert "X2D-RG-511" in goals, "Measured host timing defects lack a permanent requirement"
    text = registry.canonical(goals["X2D-RG-511"]).decode().lower()
    for term in ("30", "120", "38.234", "8.719", "12", "240", "170",
                 "role-local", "helper", "same process", "fault marker",
                 "original assertions", "single-file", "single computation", "no cached hash",
                 "unchanged", "not_run", "empty evidence"):
        assert term in text
    row = manifest["applicability"]["X2D-RG-511"]
    assert row["applicability"] == "APPLICABLE" and row["evidence_status"] == "NOT_RUN"
    assert row["counts_as_pass"] is False and row["evidence_refs"] == []
    assert not manifest["qualification"]["installable"]
    assert not manifest["qualification"]["package_created"]


def test_host_proc_retirement_append_preserves_all_511_goals(manifest):
    prior = manifest["goals"][:511]
    seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "8de5eb3a68b76a888a6307bf0f3302e3b3b660ca80dadd2718400eca7fd7ba4e"
    assert registry.digest(registry.canonical(seed)) == "86dcded295d6f793851dfa84d80406776bbc64ec7c7163706749bf19fcbf5375"
    assert registry.canonical(seed) == registry.canonical(registry.initial_applicability(prior))
    goals = {goal["id"]: goal for goal in manifest["goals"]}
    goal = goals["X2D-RG-512"]
    text = registry.canonical(goal).decode().lower()
    for term in ("l/q/s", "unknown", "nonzero", "subshell", "t/w", "unchanged",
                 "120", "12", "not_run", "no recursive", "not proof"):
        assert term in text
    row = manifest["applicability"]["X2D-RG-512"]
    assert row["applicability"] == "APPLICABLE" and row["evidence_status"] == "NOT_RUN"
    assert row["counts_as_pass"] is False and row["evidence_refs"] == []
    assert not manifest["qualification"]["installable"]
    assert not manifest["qualification"]["package_created"]


def test_host_read_error_goal_preserves_every_prior_requirement(manifest):
    prior = manifest["goals"][:512]
    seed = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == "eb00d0d8eb17cb33e7099c6a3abf6f58436ef3a1284d338420fdc48a92e92d4a"
    assert registry.digest(registry.canonical(seed)) == "1bd8af00af0806aae88ef7e6d35e91a8f362049fc3170c48ed510f67e71e3e42"
    goal = next(goal for goal in manifest["goals"] if goal["id"] == "X2D-RG-513")
    assert goal["id"] == "X2D-RG-513"
    text = registry.canonical(goal).decode().lower()
    for term in ("closed-fd", "status1", "native cat", "noncanonical", "14.828",
                 "original timeout", "user decision", "not_run", "pending"):
        assert term in text
    row = manifest["applicability"][goal["id"]]
    assert row["applicability"] == "APPLICABLE" and row["evidence_status"] == "NOT_RUN"
    assert row["counts_as_pass"] is False and row["evidence_refs"] == []
    assert not manifest["qualification"]["installable"]


def test_menu_observation_and_host_query_append_preserves_all_513_requirements(manifest):
    prior = manifest['goals'][:513]
    seed = {goal['id']: manifest['applicability'][goal['id']] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == 'ac5b59544bd20c6a51ec651149ac6e7c1c1db8ddb2c26026f2988eaccc79283f'
    assert registry.digest(registry.canonical(seed)) == '4ab55cbd24dce1e3f089240f81db80bc24cb196d15f002512b292c26c3366174'
    goals = {goal['id']: goal for goal in manifest['goals']}
    for identifier in ('X2D-RG-514', 'X2D-RG-515', 'X2D-RG-516'):
        assert identifier in goals, 'discovered menu/host defect has no permanent release goal: ' + identifier
        row = manifest['applicability'][identifier]
        assert row['applicability'] == 'APPLICABLE' and row['evidence_status'] == 'NOT_RUN'
        assert row['counts_as_pass'] is False and row['evidence_refs'] == []
    assert not manifest['qualification']['installable'] and not manifest['qualification']['package_created']


def test_final_log_read_identity_and_writer_fixture_goal_preserves_all_516_requirements(manifest):
    prior = manifest['goals'][:516]
    seed = {goal['id']: manifest['applicability'][goal['id']] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == '8245e2e2be908526808bd34e4d25f4a8c8af4c5401940813ef3bf7f2eaaabd51'
    assert registry.digest(registry.canonical(seed)) == '251c1320d78705d57f4459348941cbad4338de95b6401be6d439a552eaf0507a'
    goals = {goal['id']: goal for goal in manifest['goals']}
    assert 'X2D-RG-517' in goals, 'last bounded read replacement must remain a permanent goal'
    row = manifest['applicability']['X2D-RG-517']
    assert row['applicability'] == 'APPLICABLE' and row['evidence_status'] == 'NOT_RUN'
    assert row['counts_as_pass'] is False and row['evidence_refs'] == []


def test_host_capture_execution_goal_preserves_all_517_requirements(manifest):
    prior = manifest['goals'][:517]
    seed = {goal['id']: manifest['applicability'][goal['id']] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == 'ec0c6cede86b8e1d803d8fe8b87a4ffb085de565943b5eb8ed041d451ad29654'
    assert registry.digest(registry.canonical(seed)) == '664d89417822b0c7896401d94bb9d7f2021ee88e013589deecfab19d36568eea'
    goals = {goal['id']: goal for goal in manifest['goals']}
    assert 'X2D-RG-518' in goals, 'host rewrite must have actual transformed capture evidence'
    row = manifest['applicability']['X2D-RG-518']
    assert row['applicability'] == 'APPLICABLE' and row['evidence_status'] == 'NOT_RUN'
    assert row['counts_as_pass'] is False and row['evidence_refs'] == []


def test_post_failure_observation_preserves_original_gate_and_all_518_requirements(manifest):
    prior = manifest['goals'][:518]
    seed = {goal['id']: manifest['applicability'][goal['id']] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == '6a6ca6916e49fbc9774dffd0367ab666dfe8d289ebd318fbb638751b9fc86dd8'
    assert registry.digest(registry.canonical(seed)) == 'dff550ebd7aa1e22a3b8888b204f980a0ef3c6fa52e21e26474ef63ffba483c3'
    goals = {goal['id']: goal for goal in manifest['goals']}
    assert 'X2D-RG-519' in goals, 'post-failure replies must never promote the original failed gate'
    goal = goals['X2D-RG-519']
    required = goal['required_behavior'] + ' ' + ' '.join(goal['required_evidence'])
    for term in ('original FAIL', 'same lifecycle', 'actual item.module', 'before cleanup',
                 'at most one', '20/240', 'polling load', 'not a timing comparison',
                 'independent review', 'source_inputs', 'final installation approval'):
        assert term in required
    row = manifest['applicability']['X2D-RG-519']
    assert row['applicability'] == 'APPLICABLE' and row['evidence_status'] == 'NOT_RUN'
    assert row['counts_as_pass'] is False and row['evidence_refs'] == []
    assert manifest['qualification']['installable'] is False


def test_same_object_boot_handoff_goal_preserves_all_first546_rows(manifest):
    prior = manifest["goals"][:546]
    previous = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == (
        "db3f4a010d48e845430ed0e6819d3785b3c8e7b360218994d80cf11caeeaa2a6")
    assert registry.digest(registry.canonical(previous)) == (
        "86f4b88b981233bf65f3602751fadb46a276ff8446865b9d5f07f6cf9d8acade")
    goals = {goal["id"]: goal for goal in manifest["goals"]}
    key = "X2D-RG-547"
    assert set(goals[key]) == registry.GOAL_FIELDS
    # Literal pin is independent of mutable build descriptors at test runtime.
    assert registry.digest(registry.canonical(goals[key])) == (
        "1c206bad555639cfd53ae2f59e261204eca82bf879ea8669efef6352751943d6")
    row = manifest["applicability"][key]
    assert row["applicability"] == "APPLICABLE" and row["evidence_status"] == "NOT_RUN"
    assert row["counts_as_pass"] is False and row["evidence_refs"] == []
    assert row["goal_sha256"] == "1c206bad555639cfd53ae2f59e261204eca82bf879ea8669efef6352751943d6"
    assert row["requirement_sha256"] == "19ef0e5bb2bb2f63394869553dc8e08a01693e031727e376fddffbde0a0fb220"
    assert manifest["qualification"]["installable"] is False
    assert manifest["qualification"]["package_created"] is False


def test_host_native_fork_flattening_goal_preserves_all_first545_rows(manifest):
    prior = manifest["goals"][:545]
    previous = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == (
        "0ccd9762a02f7263c19026ffde08b20641d7778c7fbae2c4c88f129da05385ed")
    assert registry.digest(registry.canonical(previous)) == (
        "56482b585b1364c2a1e4ea25d336323e703e58251801c8bd35a43edf2924ca31")
    goals = {goal["id"]: goal for goal in manifest["goals"]}
    key = "X2D-RG-546"
    assert set(goals[key]) == registry.GOAL_FIELDS
    # Literal pin comes from the frozen independently reviewed five-field v2
    # descriptor, never from a mutable build descriptor at test runtime.
    assert registry.digest(registry.canonical(goals[key])) == (
        "1a9f7fea4bdc73d96c66fc265e3055555864f5da1f799da2cfe9046b47964bf3")
    row = manifest["applicability"][key]
    assert row["applicability"] == "APPLICABLE" and row["evidence_status"] == "NOT_RUN"
    assert row["counts_as_pass"] is False and row["evidence_refs"] == []
    assert row["goal_sha256"] == "1a9f7fea4bdc73d96c66fc265e3055555864f5da1f799da2cfe9046b47964bf3"
    assert manifest["qualification"]["installable"] is False
    assert manifest["qualification"]["package_created"] is False

@pytest.mark.parametrize("number,reviewed_goal_sha256", (
    (526, "a44cc88c305fd3f5863bac1cd6b0aeb412ff3b5fcc3c23d7a830a30e59b0eadf"),
    (527, "1053ac17646871d8c3d7b95491a9f0ae5e41498806db7b3a85f5862a11fe2fc1"),
    (528, "953e6deb43f842466c4cce7850a09e0cd02692c734d779243f4ce6db8ae0bc39"),
    (529, "ea49991f4cd3c13258544444670ce9308ec75e565b8f6b14c15d6439348f5de3"),
    (530, "28088efeef1242a22e97b041d2569b41a72e86ecf66557e7129bea54fbbfc250"),
    (531, "8dc369304da97a35f74e23a7710d2cf1ff833fbf39b23a1327b2628bdc1eb978"),
    (532, "bcc7fe1f1fa01963b655ab9084d73c0224fcaddd3a787040c19baa455106cc00"),
    (533, "d116c767cebeb2be5d69ad0a3e344f5d7ec11d6f0eeec4a68269dbf4ddba1336"),
    (534, "01650a04be1a711176748d5d2522af25e72376aaa4bb07d639b2e8a5f9920e88"),
    (535, "320efc10b26ec0c9d15a102d54cb8230ecc6546c22d8a2b63d706052d0b4200b"),
    (536, "6b53e73a83c787e6bcd2f782ac12359c6fe18bfc16ae716fa60fc0f3e6438be8"),
    (537, "290bd7770d1a9b9fd0261d53b2a0f130e6a208ba245af2663bb2378ef0757500"),
    (538, "c8bac399a860bb700675fc8ba7bdc521e9e8aba0249836caeebe3617176bf602"),
))
def test_reviewed_20261011_defects_remain_registered_and_unqualified(manifest, number, reviewed_goal_sha256):
    # Literal pins come from the independently reviewed pending requirements,
    # not from NEW_GOALS or a mutable build/supplemental input at test runtime.
    key = f"X2D-RG-{number}"
    goals = {goal["id"]: goal for goal in manifest["goals"]}
    assert key in goals, "Discovered defect lacks a permanent goal"
    assert registry.digest(registry.canonical(goals[key])) == reviewed_goal_sha256
    row = manifest["applicability"][key]
    assert row["applicability"] == "APPLICABLE"
    assert row["evidence_status"] == "NOT_RUN"
    assert row["counts_as_pass"] is False and row["evidence_refs"] == []
    assert manifest["qualification"]["installable"] is False


def test_reviewed_20261011_append_preserves_all_first525_goals_and_seeds(manifest):
    assert registry.digest(registry.canonical(manifest["goals"][:525])) == (
        "448fae9258ca770522a9b3a596e49652bc3675a9507fc3d71d08c7b018237616")
    previous = {goal["id"]: manifest["applicability"][goal["id"]]
                for goal in manifest["goals"][:525]}
    assert registry.digest(registry.canonical(previous)) == (
        "33ca62a121861100a6e70fa55deb006c024b90e3e2dd575dd54438c09fcbdc6f")

@pytest.mark.parametrize("number,reviewed_sha256", (
    (540, "ee5f0ac904d89eb2366ffe4bae11ee53294804a5f01ad00a2c0192bbae29197f"),
    (541, "00eb0c4b8ce6b8fbb69d11f798ed933e3af45bcf5f7c3058fdc2a663db2aa95c"),
    (542, "f523af0f3e5d84e7044700daaec689eeb4e307fd31744f5d181581ac0d996e75"),
    (543, "1936170cbfe00fd6eedae8499445424da9e93ccae54ad3503addcf93494c487d"),
))
def test_postterminal_host_errors_are_permanent_unqualified_goals(manifest, number, reviewed_sha256):
    key = f"X2D-RG-{number}"
    goals = {goal["id"]: goal for goal in manifest["goals"]}
    assert registry.digest(registry.canonical(goals[key])) == reviewed_sha256
    assert manifest["applicability"][key]["applicability"] == "APPLICABLE"
    assert manifest["applicability"][key]["evidence_status"] == "NOT_RUN"
    assert manifest["applicability"][key]["counts_as_pass"] is False
    assert manifest["applicability"][key]["evidence_refs"] == []
    assert manifest["qualification"]["installable"] is False


def test_saved_registry_matches_current_builder_without_inferred_pass():
    saved = registry.strict_json(registry.MANIFEST_PATH.read_bytes())
    result = registry.validate_manifest(saved, registry.SOURCE_PATH.read_bytes())
    assert result["inventory_valid"] is True and result["pass_count"] == 0
    assert result["installable"] is False and result["package_eligible"] is False


def test_guarded_test_invocation_defect_is_registered_without_changing_prior_rows(manifest):
    prior = manifest["goals"][:543]
    previous = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == (
        "4115111f746e9602c8ddffa8698c73291fde43b36266352b5af8927036fcad41")
    assert registry.digest(registry.canonical(previous)) == (
        "ac7c1c1aa882e2c2ed105331434b095b4c4b34be0936123f67a19e9b5c8e86a9")
    goals = {goal["id"]: goal for goal in manifest["goals"]}
    key = "X2D-RG-544"
    assert registry.digest(registry.canonical(goals[key])) == (
        "89d42d88fbc44b211d84f01fb01bea8e504faf41ad6011085efd4702f33b73e4")
    row = manifest["applicability"][key]
    assert row["applicability"] == "APPLICABLE" and row["evidence_status"] == "NOT_RUN"
    assert row["counts_as_pass"] is False and row["evidence_refs"] == []
    assert manifest["qualification"]["installable"] is False


def test_audit_output_publication_goal_preserves_all_first544_rows(manifest):
    prior = manifest["goals"][:544]
    previous = {goal["id"]: manifest["applicability"][goal["id"]] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == (
        "f22be343d02fa3a9b169f70084ea4358a3e95dadc5b057bc5d96e19586df5a42")
    assert registry.digest(registry.canonical(previous)) == (
        "4dca3691454aaa3b1f850493c888c3905aa33eb71fc0094abba35937c1cced23")
    goals = {goal["id"]: goal for goal in manifest["goals"]}
    key = "X2D-RG-545"
    assert registry.digest(registry.canonical(goals[key])) == (
        "74babbf267ac3ad3cc3dea0787a4be00eeaab86e498815bdbcd0b388432b6020")
    row = manifest["applicability"][key]
    assert row["applicability"] == "APPLICABLE" and row["evidence_status"] == "NOT_RUN"
    assert row["counts_as_pass"] is False and row["evidence_refs"] == []
    assert manifest["qualification"]["installable"] is False


def test_cleanup_observer_failure_is_registered_with_unchanged_prior_goals(manifest):
    goals = {goal["id"]: goal for goal in manifest["goals"]}
    assert "X2D-RG-539" in goals, "The discovered cleanup observer defect is not registered"
    assert registry.digest(registry.canonical(goals["X2D-RG-539"])) == (
        "bbf00da29b9d66f956482b4a81311f95cc141a17128002738914ddcc7b61df79")
    row = manifest["applicability"]["X2D-RG-539"]
    assert row["applicability"] == "APPLICABLE" and row["evidence_status"] == "NOT_RUN"
    assert row["counts_as_pass"] is False and row["evidence_refs"] == []
    assert manifest["qualification"]["installable"] is False
    assert registry.digest(registry.canonical(manifest["goals"][:525])) == (
        "448fae9258ca770522a9b3a596e49652bc3675a9507fc3d71d08c7b018237616")
    previous = {goal["id"]: manifest["applicability"][goal["id"]]
                for goal in manifest["goals"][:525]}
    assert registry.digest(registry.canonical(previous)) == (
        "33ca62a121861100a6e70fa55deb006c024b90e3e2dd575dd54438c09fcbdc6f")


def test_actual_child_menu_evidence_preserves_all_520_requirements(manifest):
    prior = manifest['goals'][:520]
    seed = {goal['id']: manifest['applicability'][goal['id']] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == '20841bfad9df69e23b9553a8ba993b7545c781071cbbb7b36b63ac536932660e'
    assert registry.digest(registry.canonical(seed)) == '2df0d7396dcf8e701b05d93f7ff1f496fc27051fc6d6cee3309bd78ef9469c0d'
    goals = {goal['id']: goal for goal in manifest['goals']}
    assert 'X2D-RG-521' in goals, 'actual child menu failures and draft mistakes must remain permanent'
    goal = goals['X2D-RG-521']
    required = goal['required_behavior'] + ' ' + ' '.join(goal['required_evidence'])
    for term in ('child.identity', 'not child.admit', 'actual child', 'native FD',
                 'modeled reports', 'menu20', 'original FAIL', 'same Popen',
                 'no retry', 'retirement', 'independent review', 'final installation approval'):
        assert term in required
    row = manifest['applicability']['X2D-RG-521']
    assert row['applicability'] == 'APPLICABLE' and row['evidence_status'] == 'NOT_RUN'
    assert row['counts_as_pass'] is False and row['evidence_refs'] == []
    assert manifest['qualification']['installable'] is False


def test_shared_native_menu_route_goal_preserves_all_519_requirements(manifest):
    prior = manifest['goals'][:519]
    seed = {goal['id']: manifest['applicability'][goal['id']] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == 'fe3fea0a505a2abc3dff68fbc86e8b0d0a9308962e244c50ee008853507677c6'
    assert registry.digest(registry.canonical(seed)) == 'a225241477ba4be88a7c0305911eee907cee2061f194e9567ad8c1dabb827bb9'
    goals = {goal['id']: goal for goal in manifest['goals']}
    assert 'X2D-RG-520' in goals, 'shared host route must execute the real fixed menu command'
    goal = goals['X2D-RG-520']
    required = goal['required_behavior'] + ' ' + ' '.join(goal['required_evidence'])
    for term in ('four tokens', 'real q', 'same lifecycle', 'NOT_READY', 'read20',
                 'no retry', 'actual child', 'not Qt', '120/240/90',
                 'independent review', 'final installation approval'):
        assert term in required
    row = manifest['applicability']['X2D-RG-520']
    assert row['applicability'] == 'APPLICABLE' and row['evidence_status'] == 'NOT_RUN'
    assert row['counts_as_pass'] is False and row['evidence_refs'] == []
    assert manifest['qualification']['installable'] is False


def test_install_prefix_observation_preserves_failure_binding_and_all_521_requirements(manifest):
    prior = manifest['goals'][:521]
    seed = {goal['id']: manifest['applicability'][goal['id']] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == '9b3af5ba86e762c7fbfccd700c7f801257fe68e61e0366eaf60df89285d2eee7'
    assert registry.digest(registry.canonical(seed)) == '7732bf75840c93e102139b633bed375ec651638479394d306d30e25c64566b30'
    goals = {goal['id']: goal for goal in manifest['goals']}
    assert 'X2D-RG-522' in goals, 'install diagnostics must not lose or promote original failures'
    goal = goals['X2D-RG-522']
    required = goal['required_behavior'] + ' ' + ' '.join(goal['required_evidence'])
    for term in ('same Popen', 'original120', 'cumulative bytes', 'never concatenate',
                 'primary exception', 'independent result save', 'must_be_new',
                 'actual stage', 'session bytes', 'source_inputs', 'not the original restore node',
                 'independent review', 'normal polling', 'final installation approval'):
        assert term in required
    row = manifest['applicability']['X2D-RG-522']
    assert row['applicability'] == 'APPLICABLE' and row['evidence_status'] == 'NOT_RUN'
    assert row['counts_as_pass'] is False and row['evidence_refs'] == []
    assert manifest['qualification']['installable'] is False


def test_generated_kernel_text_and_interpreter_findings_preserve_all_522_requirements(manifest):
    prior = manifest['goals'][:522]
    seed = {goal['id']: manifest['applicability'][goal['id']] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == '7b15b7e55ba6ee18b9c44c20ba52d8296adcae9b8873a2d3f303afd5eb74900e'
    assert registry.digest(registry.canonical(seed)) == '06e7ff044ac774d5291c403df977164fa9fc81480ed241a9d0c7f4a46106fd6a'
    goals = {goal['id']: goal for goal in manifest['goals']}
    assert 'X2D-RG-523' in goals, 'host model text and interpreter mistakes must remain permanent'
    goal = goals['X2D-RG-523']
    required = goal['required_behavior'] + ' ' + ' '.join(goal['required_evidence'])
    for term in ('generated proc', 'explicit LF', 'native cat', 'raw bytes',
                 'missing PATH', 'Unicode payload', 'Bash-only hook', 'original120',
                 'no performance benefit', 'after kill', 'not causal proof',
                 'independent review', 'final installation approval'):
        assert term in required
    row = manifest['applicability']['X2D-RG-523']
    assert row['applicability'] == 'APPLICABLE' and row['evidence_status'] == 'NOT_RUN'
    assert row['counts_as_pass'] is False and row['evidence_refs'] == []
    assert manifest['qualification']['installable'] is False


def test_approved_host_wait_scopes_preserve_all_523_requirements(manifest):
    prior = manifest['goals'][:523]
    seed = {goal['id']: manifest['applicability'][goal['id']] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == '8bfb28cce95479655a747e84b7f97d66747bb9f906bd9ca1e85887ba6d83adf8'
    assert registry.digest(registry.canonical(seed)) == '89fb76f221e97d464e44c5b200fb417160ead6dc474d7e91868fce2ef4bf768b'
    goals = {goal['id']: goal for goal in manifest['goals']}
    assert 'X2D-RG-524' in goals, 'host wait authorization must not leak into fault recovery'
    required = goals['X2D-RG-524']['required_behavior'] + ' ' + ' '.join(goals['X2D-RG-524']['required_evidence'])
    for term in ('launch-origin TERM240', 'preparation plus recovery',
                 'not a post-fault240 observation', 'prior FAIL remains',
                 'must_be_new', 'after.json', 'not installation qualification'):
        assert term in required, 'original TERM timing and evidence protections must remain explicit'
    row = manifest['applicability']['X2D-RG-524']
    assert row['applicability'] == 'APPLICABLE' and row['evidence_status'] == 'NOT_RUN'
    assert row['counts_as_pass'] is False and row['evidence_refs'] == []
    assert manifest['qualification']['installable'] is False


def test_term_split_authorization_preserves_all_524_requirements(manifest):
    prior = manifest['goals'][:524]
    seed = {goal['id']: manifest['applicability'][goal['id']] for goal in prior}
    assert registry.digest(registry.canonical(prior)) == '78289a0b92bdcdd18f5215e0d0f778c6314e08a893f6696635792af83126c75c'
    assert registry.digest(registry.canonical(seed)) == '92015815b460b4c637410bf779af315cdc3bbedfccdcdea8331140377037974c'
    goals = {goal['id']: goal for goal in manifest['goals']}
    assert 'X2D-RG-525' in goals, 'TERM preparation must not consume fault recovery allowance'
    required = goals['X2D-RG-525']['required_behavior'] + ' ' + ' '.join(goals['X2D-RG-525']['required_evidence'])
    for term in ('current run', 'LOADED', '360', '240', 'observation',
                 'missing marker', 'original FAIL', 'independent review', 'final installation approval'):
        assert term in required
    row = manifest['applicability']['X2D-RG-525']
    assert row['applicability'] == 'APPLICABLE' and row['evidence_status'] == 'NOT_RUN'
    assert row['counts_as_pass'] is False and row['evidence_refs'] == []
    assert manifest['qualification']['installable'] is False
