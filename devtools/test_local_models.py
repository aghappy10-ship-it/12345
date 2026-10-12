import json
from pathlib import Path
import tempfile
import unittest
from local_models import LocalModels, endpoint_url, NoRedirect
from app import atomic_json


class ModelTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.source = dict(name='menu.qml', sha256='source1', text='Item {}')
        self.calls = []
        def request(endpoint, route, body=None, timeout=5):
            self.calls.append((endpoint, route, body))
            if route == 'models':
                return {'data': [{'id': 'local-test-model'}]}
            return {'model': 'local-test-model', 'choices': [{'message': {'content': 'suggested change, not executed'}}]}
        self.models = LocalModels(Path(self.temp.name), lambda key: dict(self.source), atomic_json,
                                 request=request, start_worker=False)
    def tearDown(self):
        self.models.close()
        self.temp.cleanup()
    def test_loopback_only_and_redirects_rejected(self):
        self.assertEqual('http://127.0.0.1:18107/v1', endpoint_url('http://127.0.0.1:18107/v1/'))
        for value in ('https://example.com/v1', 'http://localhost:1234/v1', 'http://127.0.0.1:1/v1?q=x',
                      'http://user:pass@127.0.0.1:1/v1', 'file:///v1', 'http://127.0.0.1/v1'):
            with self.assertRaises(ValueError):
                endpoint_url(value)
        with self.assertRaises(ValueError):
            NoRedirect().redirect_request(None)
    def test_unknown_model_cannot_run(self):
        with self.assertRaises(ValueError):
            self.models.submit('review menu')
        self.assertEqual([], self.calls)
    def test_job_output_persists_and_never_becomes_installed_or_reviewed(self):
        self.models.probe()
        job = self.models.submit('review menu')
        self.models.run_one(job['id'])
        result = self.models.detail(job['id'])
        self.assertEqual('awaiting-review', result['state'])
        self.assertEqual('pending-codex', result['reviewState'])
        self.assertEqual('Codex', self.models.snapshot()['reviewer'])
        self.assertNotIn('reviewModel', self.models.snapshot())
        self.assertTrue(result['sourceStillMatched'])
        self.assertEqual(0, result['sourceWrites'])
        self.assertEqual(0, result['cameraWrites'])
        self.assertFalse(result['installable'])
        self.assertNotIn('sourceText', self.models.snapshot()['jobs'][0])
        saved = json.loads(self.models.path.read_text())
        self.assertIn('suggested change', saved[0]['output'])
        with self.assertRaises(ValueError):
            self.models.run_one(job['id'])
    def test_source_changes_are_marked_and_restart_does_not_duplicate_work(self):
        self.models.probe()
        job = self.models.submit('review menu')
        self.source['sha256'] = 'changed'
        self.models.run_one(job['id'])
        self.assertFalse(self.models.detail(job['id'])['sourceStillMatched'])
        queued = self.models.submit('next task')
        other = LocalModels(Path(self.temp.name), lambda key: self.source, atomic_json, start_worker=False)
        self.assertEqual('interrupted', other.detail(queued['id'])['state'])
        other.close()
    def test_model_identity_mismatch_fails(self):
        self.models.probe()
        job = self.models.submit('review menu')
        self.models.request = lambda *args, **kwargs: {'model': 'wrong', 'choices': [{'message': {'content': 'text'}}]}
        self.models.run_one(job['id'])
        self.assertEqual('failed', self.models.detail(job['id'])['state'])
    def test_closed_worker_cannot_publish_over_restarted_service(self):
        self.models.probe()
        job = self.models.submit('review menu')
        def closing_request(*args, **kwargs):
            self.models.close()
            return {'choices': [{'message': {'content': 'late result'}}]}
        self.models.request = closing_request
        self.models.run_one(job['id'])
        self.assertNotIn('late result', self.models.path.read_text())
    def test_closed_worker_cannot_start_and_overwrite_restarted_queue(self):
        self.models.probe()
        job = self.models.submit('queued before close')
        before = self.models.path.read_bytes()
        call_count = len(self.calls)
        self.models.close()
        self.models.run_one(job['id'])
        self.assertEqual(before, self.models.path.read_bytes())
        self.assertEqual(call_count, len(self.calls))
    def test_closed_service_cannot_append_new_jobs(self):
        self.models.probe()
        self.models.submit('first task')
        before = self.models.path.read_bytes()
        self.models.close()
        with self.assertRaises(ValueError):
            self.models.submit('late task')
        self.assertEqual(before, self.models.path.read_bytes())


if __name__ == '__main__':
    unittest.main()
