"""Real compiled Loader dependency failures; isolated desktop Qt, no camera."""
import json
from pathlib import Path
import subprocess
import sys


PROJECT = Path(__file__).resolve().parents[1]


def test_failed_extension_dependency_keeps_real_stock_menu_operable_and_tears_down():
    result = subprocess.run(
        [sys.executable, '-B', str(PROJECT / 'tools/check_stock_load_failure.py')],
        capture_output=True, text=True, encoding='utf-8', timeout=90)
    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads(result.stdout)
    assert report['result'] == 'PASS'
    assert report['processExitVerified'] is True
    assert report['sourceInputsUnchanged'] is True
    assert report['completeQtTeardown'] is True
    assert report['qmlTypeRegistrationsCleared'] is True
    assert report['installable'] is False and report['cameraAccesses'] == 0
    from tools.build_host_bridge import HOST, CORE_HASHES
    for relative, digest in CORE_HASHES.items():
        path = str(HOST / relative)
        assert report['inputsBefore'][path]['sha256'] == digest
        assert report['inputsAfter'][path]['sha256'] == digest
    assert [case['scenario'] for case in report['cases']] == ['missing-page', 'malformed-page']
    for case in report['cases']:
        assert case['compiledCacheHits'] > 0
        assert case['injectedUrlHits'] > 0
        assert case['loaderStatus'] == 3  # QtQuick.Loader.Error
        assert case['stockTouchRoutes'] == 11
        assert case['stockKeyboardRoute'] is True
        assert case['originalBindingsRemainLive'] is True
        assert case['extensionInstantiated'] is False
        assert case['unexpectedWarnings'] == []
        assert case['parentLoaderEvidence'] == {
            'internalObjectName': 'HblLoader_internal_loader',
            'wrapperObjectName': 'HblLoader', 'asynchronous': True}
        assert 'noSpontaneousRetry' not in case
        observation = case['retryObservation']
        assert observation['requestedMs'] == 150
        assert observation['elapsedMs'] >= 150
        assert observation['clock'] == 'perf_counter'
        assert 0 < observation['clockResolutionSeconds'] < 0.001
        assert observation['urlHitsBefore'] == observation['urlHitsAfter']
        assert observation['warningsBefore'] == observation['warningsAfter']
        assert observation['scope'] == 'no retry observed within measured window only'
