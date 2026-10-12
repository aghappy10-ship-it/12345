import json
import hashlib
import subprocess
import sys
import unittest
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]


class StockMenuTests(unittest.TestCase):
    def test_menu_state_receipts_follow_the_actual_rendered_entry_and_unload(self):
        completed = subprocess.run([sys.executable, '-B', str(PROJECT / 'tools/check_stock_menu.py')],
                                   capture_output=True, text=True, encoding='utf-8', timeout=60)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        summary = json.loads(completed.stdout)
        run = Path(summary['runDirectory'])
        rows = []
        for line in (run / 'stderr.txt').read_text(encoding='utf-8').splitlines():
            if line.startswith('qml: X2DII_MENU_STATE_V1:'):
                rows.append(line.removeprefix('qml: X2DII_MENU_STATE_V1:'))
        self.assertTrue(rows, 'No actual QML rendered-menu receipt was emitted')
        evidence = json.loads((run / 'RESULT.json').read_text(encoding='utf-8'))
        observations = evidence['menuStateObservations']
        self.assertEqual([row['phase'] for row in observations],
                         ['rendered', 'page-open', 'page-return', 'source-reset',
                          'full-grid', 'source-restored', 'detached'])
        for row in observations:
            self.assertEqual(rows[row['emittedIndex']], row['wire'])
            fields = row['wire'].split(':')
            self.assertEqual(len(fields), 8)
            sequence, ready, model, button, visible, eligible, count, index = map(int, fields)
            self.assertGreater(sequence, 0)
            self.assertLessEqual(sequence, 256)
            self.assertEqual((ready, model, button, visible, eligible, count, index),
                             tuple(row['expected']))
        self.assertEqual(observations[0]['expected'], [1, 1, 1, 1, 1, 12, 11])
        self.assertEqual(observations[1]['expected'], [1, 1, 1, 0, 0, 12, 11])
        self.assertEqual(observations[3]['expected'], [1, 1, 1, 1, 1, 11, 10])
        self.assertEqual(observations[4]['expected'][:5], [0, 1, 0, 0, 0])
        self.assertEqual(observations[-1]['expected'], [0, 0, 0, 0, 0, -1, -1])
        self.assertEqual([row['emittedIndex'] for row in observations],
                         sorted({row['emittedIndex'] for row in observations}))
        instances = evidence['menuInstanceObservations']
        self.assertEqual([row['generation'] for row in instances], [1, 2, 3, 4])
        for row in instances:
            self.assertEqual(row['unloadedReceipts'][-1].split(':')[1:],
                             ['0', '0', '0', '0', '0', '-1', '-1'])
            self.assertEqual(row['reloadedReceipts'][0], '1:0:0:0:0:0:-1:-1')
            self.assertEqual(row['reloadedReceipts'][-1].split(':')[1:],
                             ['1', '1', '1', '1', '1', '12', '11'])
        self.assertTrue(evidence['processExitVerified'])
        self.assertFalse(evidence['installable'])

    def test_menu_receipt_budget_deduplicates_and_never_keeps_ready_after_overflow(self):
        completed = subprocess.run([sys.executable, '-B', str(PROJECT / 'tools/check_stock_menu.py')],
                                   capture_output=True, text=True, encoding='utf-8', timeout=60)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        summary = json.loads(completed.stdout)
        run = Path(summary['runDirectory'])
        evidence = json.loads((run / 'RESULT.json').read_text(encoding='utf-8'))
        budget = evidence['menuReportBudget']
        self.assertEqual(budget['repeatedStateReceiptCount'], 0)
        self.assertEqual(budget['lastNormalSequence'], 256)
        self.assertEqual(budget['overflowReceipts'], ['OVERFLOW'])
        self.assertEqual(budget['afterOverflowReceiptCount'], 0)
        self.assertEqual(budget['afterDetachReceiptCount'], 0)
        self.assertEqual(budget['afterOverflowLastWire'], 'OVERFLOW')
        self.assertEqual(budget['afterDetachLastWire'], 'OVERFLOW')
        self.assertTrue(evidence['processExitVerified'])
        self.assertFalse(evidence['installable'])

    def test_real_compiled_stock_menu_in_isolated_process(self):
        completed = subprocess.run([sys.executable, '-B', str(PROJECT / 'tools/check_stock_menu.py')],
                                   capture_output=True, text=True, encoding='utf-8', timeout=60)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn('"result": "PASS"', completed.stdout)
        summary = json.loads(completed.stdout)
        evidence = json.loads((Path(summary['runDirectory']) / 'RESULT.json').read_text())
        self.assertTrue(evidence['qmlTypeRegistrationsCleared'])
        self.assertIn('direct-unload-original-stock-keyboard-route-once', evidence['cases'])
        self.assertEqual(evidence['originalStockResources'].get('components/HblLoader.qml'),
                         'ca926381b76dd968b4aa3283d268a7d32160a07f9dea1bf5e919be9a45e3688d')
        self.assertTrue(evidence['parentLoaderEvidence']['asynchronous'])
        self.assertEqual(evidence['parentLoaderEvidence']['internalObjectName'], 'HblLoader_internal_loader')
        self.assertEqual(evidence['parentLoaderEvidence']['wrapperObjectName'], 'HblLoader')
        focus_rows = evidence['externalFocusObservations']
        self.assertEqual([row['role'] for row in focus_rows], ['activeError', 'popup'])
        for row in focus_rows:
            with self.subTest(external_focus=row['role']):
                self.assertTrue(row['focusedBeforeBlock'])
                self.assertTrue(row['focusedAfterDismiss'])
                self.assertTrue(row['focusedAfterRejectedDispatch'])
                self.assertTrue(row['focusedAfterBackSignal'])
                self.assertEqual(row['receivedKeys'], 1)
                self.assertEqual(row['stockRouteDeltaWhileBlocked'], 0)
                self.assertTrue(row['pageHiddenWhileBlocked'])
                self.assertTrue(row['stockFocusAfterExternalRelease'])
                self.assertEqual(row['stockRouteDeltaAfterRelease'], 1)
        from tools.build_host_bridge import HOST, CORE_HASHES
        for relative, digest in CORE_HASHES.items():
            path = str(HOST / relative)
            self.assertEqual(evidence['inputsBefore'][path]['sha256'], digest)
            self.assertEqual(evidence['inputsAfter'][path]['sha256'], digest)

    def test_late_engine_warning_is_rejected_before_worker_observations(self):
        from tools.qt_supervisor import supervise_worker
        report = supervise_worker(PROJECT / 'tests/fixtures/LateQtWarning.py',
                                  'late-qt-warning-validation.json', 'late-qt-warning-runs',
                                  timeout=60, input_paths=[PROJECT / 'tools/check_stock_menu.py'])
        self.assertEqual(report['result'], 'FAIL')
        self.assertEqual(report['failure'], 'WORKER_NONZERO_EXIT')
        run = Path(report['runDirectory'])
        self.assertIn('TEST_LATE_ENGINE_WARNING', (run / 'stderr.txt').read_text())
        self.assertFalse((run / 'observations.json').exists())

    def _detach_fault_evidence(self):
        completed = subprocess.run(
            [sys.executable, '-B', str(PROJECT / 'tests/fixtures/BootstrapDetachFault.py')],
            capture_output=True, text=True, encoding='utf-8', timeout=60)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        summary = json.loads(completed.stdout)
        run = Path(summary['runDirectory'])
        evidence = json.loads((run / 'RESULT.json').read_text())
        self.assertEqual(evidence['result'], 'PASS')  # Supervised execution, not routing qualification.
        self.assertTrue(evidence['processExitVerified'])
        self.assertTrue(evidence['completeQtTeardown'])
        self.assertTrue(evidence['sourceInputsUnchanged'])
        self.assertFalse(evidence['installable'])
        self.assertEqual(evidence['cameraAccesses'], 0)
        source = str(PROJECT / 'qml/X2d2MenuBootstrap.qml')
        digest = evidence['productionBootstrapSha256']
        self.assertEqual(digest, evidence['inputsBefore'][source]['sha256'])
        self.assertEqual(digest, evidence['inputsAfter'][source]['sha256'])
        self.assertEqual(hashlib.sha256((run / 'production-Bootstrap.qml').read_bytes()).hexdigest(), digest)
        return evidence

    def test_detach_one_shot_signal_faults_preserve_original_route_once(self):
        evidence = self._detach_fault_evidence()
        self.assertEqual([row['mode'] for row in evidence['routeObservations']],
                         ['none', 'disconnect', 'stock-connect', 'sequential'])
        for row in evidence['routeObservations']:
            self.assertEqual(row['baseline']['routeDelta'], 1)
            self.assertEqual(row['injected'], row['mode'] != 'none')
            self.assertEqual(row['disconnectInjected'], row['mode'] in ('disconnect', 'sequential'))
            self.assertEqual(row['connectInjected'], row['mode'] in ('stock-connect', 'sequential'))
            for phase in ('firstDetach', 'secondDetach'):
                with self.subTest(mode=row['mode'], phase=phase):
                    self.assertEqual(row[phase]['routeDelta'], 1,
                                     f"{row['mode']}/{phase}: original stock route must deliver exactly once")
                    self.assertIs(row[phase]['cleanupResult'], True)
                    self.assertEqual(row[phase]['attachmentState'], 'detached')
                    self.assertFalse(row[phase]['routeConnected'])
                    self.assertFalse(row[phase]['stockRouteRemoved'])
                    self.assertFalse(row[phase]['attached'])
                    self.assertFalse(row[phase]['restoring'])
                    self.assertFalse(row[phase]['autoAttach'])
            self.assertLessEqual(row['firstDetach']['disconnectCalls'], 2)
            self.assertLessEqual(row['firstDetach']['connectCalls'], 2)
            self.assertEqual(row['firstDetach']['disconnectCalls'], row['secondDetach']['disconnectCalls'])
            self.assertEqual(row['firstDetach']['connectCalls'], row['secondDetach']['connectCalls'])

    def test_detach_persistent_signal_faults_refuse_until_explicit_retry(self):
        evidence = self._detach_fault_evidence()
        self.assertEqual([row['mode'] for row in evidence['pendingObservations']],
                         ['persistent-disconnect', 'persistent-stock-connect'])
        for row in evidence['pendingObservations']:
            release_fault = row['mode'] == 'persistent-disconnect'
            self.assertEqual(row['baseline']['routeDelta'], 1)
            self.assertTrue(row['injected'])
            for phase in ('firstDetach', 'secondDetach'):
                with self.subTest(mode=row['mode'], phase=phase):
                    state = row[phase]
                    self.assertIs(state['cleanupResult'], False)
                    self.assertEqual(state['attachmentState'], 'detach-pending')
                    self.assertEqual(state['routeConnected'], release_fault)
                    self.assertTrue(state['stockRouteRemoved'])
                    self.assertFalse(state['restoring'])
                    self.assertFalse(state['attached'])
                    self.assertFalse(state['autoAttach'])
                    self.assertEqual(state['routeDelta'], 1 if release_fault else 0)
            first, second = row['firstDetach'], row['secondDetach']
            if release_fault:
                self.assertEqual((first['disconnectCalls'], first['connectCalls']), (2, 0))
                self.assertEqual((second['disconnectCalls'], second['connectCalls']), (4, 0))
            else:
                self.assertEqual((first['disconnectCalls'], first['connectCalls']), (1, 2))
                self.assertEqual((second['disconnectCalls'], second['connectCalls']), (1, 4))
            recovery, repeated = row['faultClearedExplicitRetry'], row['repeatedSuccess']
            for state in (recovery, repeated):
                self.assertIs(state['cleanupResult'], True)
                self.assertEqual(state['attachmentState'], 'detached')
                self.assertEqual(state['routeDelta'], 1)
                self.assertFalse(state['routeConnected'])
                self.assertFalse(state['stockRouteRemoved'])
                self.assertFalse(state['autoAttach'])
            self.assertEqual(recovery['disconnectCalls'], repeated['disconnectCalls'])
            self.assertEqual(recovery['connectCalls'], repeated['connectCalls'])

    def test_detach_missing_signal_owner_refuses_until_owner_is_restored(self):
        evidence = self._detach_fault_evidence()
        self.assertEqual([row['mode'] for row in evidence['missingOwnerObservations']],
                         ['missing-screen', 'missing-menu'])
        for row in evidence['missingOwnerObservations']:
            screen_missing = row['mode'] == 'missing-screen'
            self.assertEqual(row['baseline']['routeDelta'], 1)
            for phase in ('firstDetach', 'secondDetach'):
                with self.subTest(mode=row['mode'], phase=phase):
                    state = row[phase]
                    self.assertIs(state['cleanupResult'], False)
                    self.assertEqual(state['attachmentState'], 'detach-pending')
                    self.assertEqual(state['routeConnected'], screen_missing)
                    self.assertTrue(state['stockRouteRemoved'])
                    self.assertEqual(state['routeDelta'], 1 if screen_missing else 0)
                    self.assertEqual(state['disconnectCalls'], 0 if screen_missing else 1)
                    self.assertEqual(state['connectCalls'], 0)
                    self.assertFalse(state['attached'])
                    self.assertFalse(state['restoring'])
                    self.assertFalse(state['autoAttach'])
            recovery, repeated = row['ownerRestoredExplicitRetry'], row['repeatedSuccess']
            for state in (recovery, repeated):
                self.assertIs(state['cleanupResult'], True)
                self.assertEqual(state['attachmentState'], 'detached')
                self.assertEqual(state['routeDelta'], 1)
                self.assertFalse(state['routeConnected'])
                self.assertFalse(state['stockRouteRemoved'])
                self.assertFalse(state['attached'])
                self.assertFalse(state['restoring'])
                self.assertFalse(state['autoAttach'])
                self.assertEqual((state['disconnectCalls'], state['connectCalls']), (1, 1))

    def test_detach_delegate_restore_fault_refuses_despite_recovered_signal_route(self):
        evidence = self._detach_fault_evidence()
        self.assertEqual(len(evidence['delegateObservations']), 1)
        row = evidence['delegateObservations'][0]
        self.assertEqual(row['mode'], 'delegate-restore')
        self.assertTrue(row['injected'])
        self.assertEqual(row['baseline']['routeDelta'], 1)
        self.assertFalse(row['baseline']['delegateRestored'])
        for call_number, phase in enumerate(('firstDetach', 'secondDetach'), 1):
            with self.subTest(phase=phase):
                state = row[phase]
                self.assertIs(state['cleanupResult'], False)
                self.assertEqual(state['attachmentState'], 'detach-pending')
                self.assertFalse(state['delegateRestored'])
                self.assertEqual(state['delegateRestoreCalls'], call_number)
                self.assertEqual(state['routeDelta'], 1)
                self.assertEqual((state['disconnectCalls'], state['connectCalls']), (1, 1))
                self.assertFalse(state['routeConnected'])
                self.assertFalse(state['stockRouteRemoved'])
                self.assertFalse(state['attached'])
                self.assertFalse(state['restoring'])
                self.assertFalse(state['autoAttach'])
        for call_number, phase in enumerate(('faultClearedExplicitRetry', 'repeatedSuccess'), 3):
            state = row[phase]
            self.assertIs(state['cleanupResult'], True)
            self.assertEqual(state['attachmentState'], 'detached')
            self.assertTrue(state['delegateRestored'])
            self.assertEqual(state['delegateRestoreCalls'], call_number)
            self.assertEqual(state['routeDelta'], 1)
            self.assertEqual((state['disconnectCalls'], state['connectCalls']), (1, 1))
            self.assertFalse(state['attached'])
            self.assertFalse(state['restoring'])
            self.assertFalse(state['autoAttach'])

    def test_actual_bootstrap_destruction_restores_surviving_stock_route_once(self):
        evidence = self._detach_fault_evidence()
        self.assertEqual([row['mode'] for row in evidence['destructionObservations']],
                         ['none', 'disconnect', 'stock-connect', 'sequential'])
        for row in evidence['destructionObservations']:
            with self.subTest(mode=row['mode']):
                self.assertEqual(row['baseline']['routeDelta'], 1)
                self.assertTrue(row['subjectDestroyed'])
                self.assertTrue(row['emitterSurvived'])
                self.assertTrue(row['stockReceiverSurvived'])
                after, repeated = row['afterActualDestruction'], row['repeatedEmission']
                self.assertEqual(after['routeDelta'], 1)
                self.assertEqual(repeated['routeDelta'], 1)
                self.assertEqual(after['injected'], row['mode'] != 'none')
                self.assertEqual(after['disconnectCalls'], 2 if row['mode'] in ('disconnect', 'sequential') else 1)
                self.assertEqual(after['connectCalls'], 2 if row['mode'] in ('stock-connect', 'sequential') else 1)
                self.assertEqual(after['disconnectCalls'], repeated['disconnectCalls'])
                self.assertEqual(after['connectCalls'], repeated['connectCalls'])

    def test_exact_attach_catch_preserves_cleanup_pending_until_explicit_detach(self):
        evidence = self._detach_fault_evidence()
        self.assertEqual([row['mode'] for row in evidence['attachmentObservations']],
                         ['cleanup-succeeds', 'pending-cleanup'])
        for row in evidence['attachmentObservations']:
            pending = row['mode'] == 'pending-cleanup'
            self.assertEqual(row['baseline']['routeDelta'], 1)
            for phase in ('afterAttachCatch', 'refusedAutomaticRetry'):
                with self.subTest(mode=row['mode'], phase=phase):
                    state = row[phase]
                    self.assertEqual(state['attachmentState'], 'detach-pending' if pending else 'attach-failed')
                    self.assertEqual(state['routeDelta'], 0 if pending else 1)
                    self.assertTrue(state['delegateRestored'])
                    self.assertFalse(state['routeConnected'])
                    self.assertEqual(state['stockRouteRemoved'], pending)
                    self.assertFalse(state['attached'])
                    self.assertFalse(state['restoring'])
                    self.assertFalse(state['autoAttach'])
                    self.assertEqual(state['attachAttempts'], 1)
                    self.assertEqual(state['reconcileCalls'], 1)
                    self.assertEqual(state['disconnectCalls'], 1)
                    self.assertEqual(state['dispatchConnectCalls'], 1)
                    self.assertEqual(state['stockConnectCalls'], 2 if pending else 1)
            for phase in ('faultClearedExplicitDetach', 'repeatedSuccess'):
                state = row[phase]
                self.assertIs(state['cleanupResult'], True)
                self.assertEqual(state['attachmentState'], 'detached')
                self.assertEqual(state['routeDelta'], 1)
                self.assertFalse(state['routeConnected'])
                self.assertFalse(state['stockRouteRemoved'])
                self.assertFalse(state['attached'])
                self.assertFalse(state['restoring'])
                self.assertFalse(state['autoAttach'])
                self.assertEqual(state['attachAttempts'], 1)
                self.assertEqual(state['reconcileCalls'], 1)
                self.assertEqual(state['disconnectCalls'], 1)
                self.assertEqual(state['dispatchConnectCalls'], 1)
                self.assertEqual(state['stockConnectCalls'], 3 if pending else 1)


if __name__ == '__main__': unittest.main()
