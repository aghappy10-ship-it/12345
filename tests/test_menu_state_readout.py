"""Fixed menu snapshot boundary; modeled replies are not camera qualification."""
from tools import menu_lifecycle_transport as lifecycle, prepare_peer_install as peer, session_context as sc
from tests.test_release_lifecycle import installer
from tests.test_temporary_menu_session import temporary_values
from tests.test_temporary_menu_session import prepare_maintenance
from unittest import mock
import pytest


class MaintenanceReplies:
    def __init__(self, raw, reply):
        self.raw, self.reply, self.calls = raw, reply, []

    def command(self, label, command):
        self.calls.append((label, command))
        if label == 'lifecycle-launch':
            return 'X2DII_LIFECYCLE_STARTED_NOT_VALIDATED:' + peer.sha(self.raw) + '\n'
        assert label == 'lifecycle-menu'
        return self.reply


def test_fixed_menu_snapshot_reuses_held_route_and_never_becomes_feature_pass(installer):
    values = temporary_values(installer)
    values.update(observer_domain='u:r:hbl_camera_service:s0', observer_exe_target='/system/bin/camera-test')
    raw = sc.encode_session(values, schema=sc.MENU_VALIDATION_SCHEMA)
    log_sha = 'c' * 64  # External boundary fixture, not actual Qt/device evidence.
    route = MaintenanceReplies(raw, 'X2DII_MENU_SNAPSHOT:' + peer.sha(raw) +
        ':456:77700:' + log_sha + ':1:3:1:1:1:1:1:12:11\n')
    reader = lifecycle.TemporaryLifecycle(installer.manifest, raw, route)
    with pytest.raises(ValueError, match='unfinished|attempted'):
        reader.read_menu()
    assert not route.calls
    reader.launch()
    result = reader.read_menu()
    assert result['status'] == 'MENU_SNAPSHOT_NOT_FEATURE_VALIDATED'
    assert result['candidate_sha256'] == installer.manifest['candidate_sha256']
    assert result['session_sha256'] == peer.sha(raw)
    assert result['boot_id'] == sc.decode_session(raw)['boot_id']
    assert result['pid'] == 456 and result['start_ticks'] == '77700'
    assert result['log_sha256'] == log_sha
    assert result['generation'] == 1 and result['sequence'] == 3
    assert result['ready'] and result['visible'] and result['eligible']
    assert result['grid_count'] == 12 and result['extension_index'] == 11
    assert not result['feature_validated'] and reader.final is None
    fixed = lifecycle.paths(installer.manifest, raw)
    assert route.calls[-1] == ('lifecycle-menu', 'sh ' + fixed['q'] + ' ' + peer.sha(raw) + ' menu')


def menu_snapshot_case(installer, log):
    """Use the existing real file/hash/shell harness with named OS identities."""
    installer.shell_fixture()
    prepare_maintenance(installer)
    raw = sc.encode_session(temporary_values(installer), schema=sc.MENU_VALIDATION_SCHEMA)
    values, digest = sc.decode_session(raw), peer.sha(raw)
    fixed = lifecycle.paths(installer.manifest, raw)
    for name in ('root', 'run', 'transaction'):
        (installer.root / fixed[name].lstrip('/')).mkdir(parents=True, exist_ok=True)
    run_dir = installer.root / fixed['run'].lstrip('/')
    transaction = installer.root / fixed['transaction'].lstrip('/')
    (run_dir / 'attempt').write_bytes((digest + '\n').encode())
    (run_dir / 'worker.identity').write_bytes(b'100:12345\n')
    for name in ('child.offer', 'child.admit'):
        (run_dir / name).write_bytes(b'456:77700\n')
    (transaction / 'attempt').write_bytes((f"candidate={installer.manifest['candidate_sha256']}\n"
        f"nonce={values['session_nonce']}\npurpose=temporary_menu_validation\naction=run_and_restore\n").encode())
    child = installer.root / 'proc/456'
    (child / 'attr').mkdir(parents=True)
    (child / 'stat').write_bytes(b'456 (camera-gui) S ' + b'0 ' * 18 + b'77700 0\n')
    (child / 'attr/current').write_bytes((values['core_gui_domain'] + '\n').encode())
    child_exe = child / 'exe'
    child_exe.write_bytes((installer.root / 'system/bin/camera-gui').read_bytes())
    installer.core_hashes[child_exe] = (peer.sha(child_exe.read_bytes()), values['core_gui_exe_sha256'])
    installer.core_links[child_exe] = values['core_gui_exe_target']
    (transaction / 'child.identity').write_bytes((f"pid=456\nstart_ticks=77700\n"
        f"exe={values['core_gui_exe_target']}\nsha256={values['core_gui_exe_sha256']}\n"
        f"domain={values['core_gui_domain']}\nnamespace={values['core_gui_mount_namespace']}\n").encode())
    log_path = transaction / 'gui.log'
    log_path.write_bytes(log)
    # Model /proc descriptors at the existing OS boundary. A hard-link fixture
    # would change gui.log's link count and incorrectly fail ml_regular first.
    (child / 'fd').mkdir()
    for descriptor in ('1', '2'):
        target = child / 'fd' / descriptor
        target.write_bytes(b'modeled open GUI descriptor')
        installer.core_links[target] = installer.posix + fixed['transaction'] + '/gui.log'
    data = installer.root / fixed['session'].lstrip('/')
    data.parent.mkdir(parents=True, exist_ok=True)
    data.write_bytes(raw)
    hook = f'''\nset -- {digest} menu
date() {{ printf '%s\\n' {values['observed_epoch']}; }}
printf '%s\\n' "$(stat -c '%d:%i' "$fixture{fixed['run']}")" > "$fixture{fixed['run']}/directory.identity"
printf '%s\\n' "$(stat -c '%d:%i' "$fixture{fixed['transaction']}")" > "$fixture{fixed['transaction']}/directory.identity"
test_writer_identity=$(/usr/bin/stat -c '%d:%i' "$fixture{fixed['transaction']}/gui.log")
stat() {{
 if [ "$#" = 3 ] && [ "$1" = -Lc ] && [ "$2" = '%d:%i' ]; then
  case "$3" in "$fixture/proc/456/fd/1"|"$fixture/proc/456/fd/2")
   builtin printf '%s\\n' "$test_writer_identity"; return;;
  esac
 fi
 fixture_stat "$@"
}}
'''

    def read(extra=''):
        installer.scripts['menu-query'] = lifecycle.render_programs(installer.manifest)['q']
        with mock.patch.object(peer, 'session_data', return_value=raw):
            return installer.run_script('menu-query', boundary_hook=hook + extra)
    return raw, fixed, read


def test_native_fixed_query_reads_actual_log_bytes_from_the_admitted_gui_lifetime(installer):
    log = (b'ordinary GUI message\n'
           b'qml: X2DII_MENU_STATE_V1:1:0:0:0:0:0:-1:-1\n'
           b'qml: X2DII_MENU_STATE_V1:2:1:1:1:1:1:12:11\n')
    raw, fixed, read = menu_snapshot_case(installer, log)
    result = read()
    assert result.returncode == 0, result.stderr
    assert result.stdout == ('X2DII_MENU_SNAPSHOT:' + peer.sha(raw) +
        ':456:77700:' + peer.sha(log) + ':1:2:1:1:1:1:1:12:11\n').encode()
    assert not (installer.root / 'operations').exists()


def test_seen_unavailable_state_cannot_regress_to_an_older_ready_log(installer):
    values = temporary_values(installer)
    values.update(observer_domain='u:r:hbl_camera_service:s0', observer_exe_target='/system/bin/camera-test')
    raw = sc.encode_session(values, schema=sc.MENU_VALIDATION_SCHEMA)
    prefix = 'X2DII_MENU_SNAPSHOT:' + peer.sha(raw) + ':456:77700:' + 'c' * 64 + ':1:'
    route = MaintenanceReplies(raw, prefix + '3:0:0:0:0:0:-1:-1\n')
    reader = lifecycle.TemporaryLifecycle(installer.manifest, raw, route)
    reader.launch()
    assert not reader.read_menu()['ready']
    route.reply = prefix + '2:1:1:1:1:1:12:11\n'
    with pytest.raises(ValueError, match='regressed|sequence'):
        reader.read_menu()


def test_native_menu_reader_refuses_log_not_owned_by_gui_stdout(installer):
    log = (b'qml: X2DII_MENU_STATE_V1:1:0:0:0:0:0:-1:-1\n'
           b'qml: X2DII_MENU_STATE_V1:2:1:1:1:1:1:12:11\n')
    raw, fixed, read = menu_snapshot_case(installer, log)
    installer.core_links[installer.root / 'proc/456/fd/1'] = '/tmp/unrelated-output'
    result = read()
    assert result.returncode == 0, result.stderr
    assert result.stdout == ('X2DII_MENU_UNKNOWN:' + peer.sha(raw) + ':IDENTITY_CHANGED\n').encode()
    assert not (installer.root / 'operations').exists()


@pytest.mark.parametrize('change', ('same_sequence', 'generation_backwards', 'pid', 'birth', 'overflow', 'unknown_then_backwards'))
def test_menu_watermark_rejects_old_or_changed_state_after_observation(installer, change):
    values = temporary_values(installer)
    values.update(observer_domain='u:r:hbl_camera_service:s0', observer_exe_target='/system/bin/camera-test')
    raw = sc.encode_session(values, schema=sc.MENU_VALIDATION_SCHEMA)
    prefix = 'X2DII_MENU_SNAPSHOT:' + peer.sha(raw) + ':456:77700:' + 'c' * 64 + ':'
    route = MaintenanceReplies(raw, prefix + '2:3:1:1:1:1:1:12:11\n')
    reader = lifecycle.TemporaryLifecycle(installer.manifest, raw, route)
    reader.launch()
    assert reader.read_menu()['ready']
    if change in ('overflow', 'unknown_then_backwards'):
        route.reply = 'X2DII_MENU_UNKNOWN:' + peer.sha(raw) + (':OVERFLOW\n' if change == 'overflow' else ':NOT_READY\n')
        assert not reader.read_menu()['ready']
    route.reply = {
        'same_sequence': prefix + '2:3:0:0:0:0:0:-1:-1\n',
        'generation_backwards': prefix + '1:4:1:1:1:1:1:12:11\n',
        'pid': prefix.replace(':456:', ':457:') + '2:4:1:1:1:1:1:12:11\n',
        'birth': prefix.replace(':77700:', ':77701:') + '2:4:1:1:1:1:1:12:11\n',
        'overflow': prefix + '2:4:1:1:1:1:1:12:11\n',
        'unknown_then_backwards': prefix + '2:2:1:1:1:1:1:12:11\n',
    }[change]
    with pytest.raises(ValueError, match='changed|regressed|overflow'):
        reader.read_menu()


@pytest.mark.parametrize('fault', ('nul', 'missing_lf', 'prefix', 'field', 'gap', 'reset', 'overflow'))
def test_native_menu_query_never_promotes_invalid_or_exhausted_records(installer, fault):
    initial = b'qml: X2DII_MENU_STATE_V1:1:0:0:0:0:0:-1:-1\n'
    ready = b'qml: X2DII_MENU_STATE_V1:2:1:1:1:1:1:12:11\n'
    log = {
        'nul': initial + ready.replace(b':2:', b':2:\0', 1),
        'missing_lf': initial + ready[:-1],
        'prefix': initial + b'unrelated ' + ready,
        'field': initial + ready.replace(b':12:11', b':12:12'),
        'gap': initial + ready.replace(b':2:', b':3:', 1),
        'reset': initial + ready + initial,
        'overflow': initial + ready + b'qml: X2DII_MENU_STATE_V1:OVERFLOW\n' + ready,
    }[fault]
    raw, _, read = menu_snapshot_case(installer, log)
    result = read()
    reason = 'OVERFLOW' if fault == 'overflow' else 'INVALID_LOG'
    assert result.returncode == 0, result.stderr
    assert result.stdout == ('X2DII_MENU_UNKNOWN:' + peer.sha(raw) + ':' + reason + '\n').encode()
    assert not (installer.root / 'operations').exists()


@pytest.mark.parametrize('fault', ('claim', 'child_identity', 'stderr', 'writer_inode'))
def test_native_menu_query_rejects_changed_owner_or_writer(installer, fault):
    log = (b'qml: X2DII_MENU_STATE_V1:1:0:0:0:0:0:-1:-1\n'
           b'qml: X2DII_MENU_STATE_V1:2:1:1:1:1:1:12:11\n')
    raw, fixed, read = menu_snapshot_case(installer, log)
    if fault == 'claim':
        (installer.root / fixed['run'].lstrip('/') / 'attempt').write_bytes(b'0' * 64 + b'\n')
    elif fault == 'child_identity':
        path = installer.root / fixed['transaction'].lstrip('/') / 'child.identity'
        path.write_bytes(path.read_bytes().replace(b'start_ticks=77700', b'start_ticks=77701'))
    elif fault == 'stderr':
        # The legacy link-map emits unquoted echo arguments. Inject literal
        # kernel-style deleted-path text at its OS seam, not into shell source.
        pass
    extra = 'test_writer_identity=0:1\n' if fault == 'writer_inode' else ''
    if fault == 'stderr':
        extra = r'''
readlink() {
 if [ "$#" = 1 ] && [ "$1" = "$fixture/proc/456/fd/2" ]; then
  builtin printf '%s (deleted)\n' "$fixtureLOG_PATH"
 else fixture_readlink "$@"; fi
}
'''.replace('LOG_PATH', fixed['transaction'] + '/gui.log')
    result = read(extra)
    # A changed outer claim rejects the request before the menu reply protocol;
    # it must not be confused with a usable snapshot or an ordinary no-menu.
    if fault == 'claim':
        assert result.returncode != 0 and not result.stdout, result.stderr
    else:
        assert result.returncode == 0, result.stderr
        assert result.stdout == ('X2DII_MENU_UNKNOWN:' + peer.sha(raw) + ':IDENTITY_CHANGED\n').encode()
    assert not (installer.root / 'operations').exists()


@pytest.mark.parametrize('phase', ('snapshot', 'hash', 'final_hash'))
def test_native_menu_query_preserves_failed_bounded_reader_status(installer, phase):
    log = (b'qml: X2DII_MENU_STATE_V1:1:0:0:0:0:0:-1:-1\n'
           b'qml: X2DII_MENU_STATE_V1:2:1:1:1:1:1:12:11\n')
    raw, fixed, read = menu_snapshot_case(installer, log)
    extra = r'''
head() {
 if [ "$#" = 3 ] && [ "$3" = "$fixtureLOG_PATH" ]; then
  test_head_count=0
  [ ! -f "$fixture/test-head-count" ] || test_head_count=$(/usr/bin/cat "$fixture/test-head-count")
  test_head_count=$((test_head_count+1))
  builtin printf '%s\n' "$test_head_count" > "$fixture/test-head-count"
  if [ "$test_head_count" = FAIL_READ_NUMBER ]; then
   /usr/bin/head "$@"; builtin printf 'native bounded read failed\n' >&2; return 79
  fi
 fi
 /usr/bin/head "$@"
}
'''.replace('LOG_PATH', fixed['transaction'] + '/gui.log').replace('FAIL_READ_NUMBER', {'snapshot': '1', 'hash': '2', 'final_hash': '3'}[phase])
    result = read(extra)
    if phase == 'snapshot':
        assert result.returncode != 0 and not result.stdout
    else:
        reason = 'INVALID_LOG' if phase == 'hash' else 'SNAPSHOT_CHANGED'
        assert result.returncode == 0 and result.stdout == ('X2DII_MENU_UNKNOWN:' + peer.sha(raw) + ':' + reason + '\n').encode()
    assert b'native bounded read failed' in result.stderr
    assert not (installer.root / 'operations').exists()


def test_native_menu_query_accepts_detach_then_a_real_new_report_generation(installer):
    log = (b'qml: X2DII_MENU_STATE_V1:1:0:0:0:0:0:-1:-1\n'
           b'qml: X2DII_MENU_STATE_V1:2:1:1:1:1:1:12:11\n'
           b'qml: X2DII_MENU_STATE_V1:3:0:0:0:0:0:-1:-1\n'
           b'qml: X2DII_MENU_STATE_V1:1:0:0:0:0:0:-1:-1\n'
           b'qml: X2DII_MENU_STATE_V1:2:1:1:1:0:0:12:11\n')
    raw, _, read = menu_snapshot_case(installer, log)
    result = read()
    assert result.returncode == 0, result.stderr
    assert result.stdout == ('X2DII_MENU_SNAPSHOT:' + peer.sha(raw) +
        ':456:77700:' + peer.sha(log) + ':2:2:1:1:1:0:0:12:11\n').encode()


def test_native_menu_query_rejects_log_replacement_during_final_hash(installer):
    log = (b'qml: X2DII_MENU_STATE_V1:1:0:0:0:0:0:-1:-1\n'
           b'qml: X2DII_MENU_STATE_V1:2:1:1:1:1:1:12:11\n')
    raw, fixed, read = menu_snapshot_case(installer, log)
    extra = r'''
head() {
 /usr/bin/head "$@" || return $?
 if [ "$#" = 3 ] && [ "$3" = "$fixtureLOG_PATH" ]; then
  test_head_count=0
  [ ! -f "$fixture/test-head-count" ] || test_head_count=$(/usr/bin/cat "$fixture/test-head-count")
  test_head_count=$((test_head_count+1))
  builtin printf '%s\n' "$test_head_count" > "$fixture/test-head-count"
  if [ "$test_head_count" = 3 ]; then
   /usr/bin/cp "$3" "$fixture/replacement.log" && /usr/bin/mv "$fixture/replacement.log" "$3" || return $?
  fi
 fi
}
'''.replace('LOG_PATH', fixed['transaction'] + '/gui.log')
    result = read(extra)
    assert result.returncode == 0, result.stderr
    assert result.stdout == ('X2DII_MENU_UNKNOWN:' + peer.sha(raw) + ':SNAPSHOT_CHANGED\n').encode()
    assert not (installer.root / 'operations').exists()


def test_log_growth_after_size_check_never_reads_more_than_the_bounded_prefix(installer):
    log = (b'qml: X2DII_MENU_STATE_V1:1:0:0:0:0:0:-1:-1\n'
           b'qml: X2DII_MENU_STATE_V1:2:1:1:1:1:1:12:11\n')
    raw, fixed, read = menu_snapshot_case(installer, log)
    path = fixed['transaction'] + '/gui.log'
    hook = r'''
test_growth_stat=$(declare -f stat)
eval "${test_growth_stat/stat/test_before_growth_stat}"
stat() {
 test_before_growth_stat "$@"
 test_status=$?
 if [ "$#" = 3 ] && [ "$2" = %s ] && [ "$3" = "$fixtureLOG_PATH" ] && [ ! -e "$fixture/grew-log" ]; then
  builtin printf '%65538s' '' >> "$3"
  builtin printf grew > "$fixture/grew-log"
 fi
 return "$test_status"
}
test_log_read() {
 test_program=$1; shift
 "$test_program" "$@" > "$fixture/last-log-read"
 test_status=$?
 /usr/bin/stat -c %s "$fixture/last-log-read" >> "$fixture/log-read-sizes"
 /usr/bin/cat "$fixture/last-log-read"
 return "$test_status"
}
cat() {
 if [ "$#" = 1 ] && [ "$1" = "$fixtureLOG_PATH" ]; then test_log_read /usr/bin/cat "$@"
 else /usr/bin/cat "$@"; fi
}
head() {
 if [ "$#" = 3 ] && [ "$3" = "$fixtureLOG_PATH" ]; then test_log_read /usr/bin/head "$@"
 else /usr/bin/head "$@"; fi
}
'''.replace('LOG_PATH', path)
    result = read(hook)
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith(('X2DII_MENU_UNKNOWN:' + peer.sha(raw) + ':').encode())
    sizes = (installer.root / 'log-read-sizes').read_text().splitlines()
    assert sizes and max(map(int, sizes)) <= 65537, sizes
    assert not (installer.root / 'operations').exists()
