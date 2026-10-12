import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import prepare_host_fixture as fixture
from tools.output_guard import output_directory, write_output


class HostFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='fixture-test-', dir=fixture.PROJECT / 'build')
        self.root = Path(self.temp.name)
        self.extracted = self.root / 'extracted'
        self.out = self.root / 'out'
        baseline = fixture.PROJECT / 'build/stock-qml'
        manifest = json.loads((baseline / 'manifest.json').read_text(encoding='utf-8'))
        for name in fixture.FILES:
            resource = 'qt/qml/app/qml/' + name
            write_output(self.extracted / resource, (baseline / resource).read_bytes())
        write_output(self.extracted / 'manifest.json', json.dumps(manifest).encode())

    def tearDown(self): self.temp.cleanup()

    def test_exact_sources_reproducible_rcc(self):
        first = fixture.prepare(self.extracted, self.out)
        second = fixture.prepare(self.extracted, self.out)
        self.assertTrue(first['verifiedAgainstPinnedElf'])
        self.assertEqual(first['rccSha256'], second['rccSha256'])

    def test_forged_but_self_consistent_manifest_and_resource_rejected(self):
        relative = 'qt/qml/app/qml/mainmenu/MainScreen.qml'
        changed = (self.extracted / relative).read_bytes() + b'\n// changed source\n'
        write_output(self.extracted / relative, changed)
        manifest_path = self.extracted / 'manifest.json'
        manifest = json.loads(manifest_path.read_text())
        manifest['files'][relative]['sha256'] = hashlib.sha256(changed).hexdigest()
        write_output(manifest_path, json.dumps(manifest).encode())
        with self.assertRaisesRegex(ValueError, 'pinned official GUI'):
            fixture.prepare(self.extracted, self.out)
        self.assertFalse(self.out.exists())

    def test_wrong_manifest_identity_rejected(self):
        path = self.extracted / 'manifest.json'
        manifest = json.loads(path.read_text()); manifest['qt_version'] = '6.4.1'
        write_output(path, json.dumps(manifest).encode())
        with self.assertRaisesRegex(ValueError, 'manifest identity'):
            fixture.prepare(self.extracted, self.out)
        self.assertFalse(self.out.exists())

    def test_late_rcc_hardlink_rejected_before_any_source_write(self):
        old_source = self.out / 'stock/mainmenu/MainScreen.qml'
        write_output(old_source, b'previous fixture')
        original = self.root / 'do-not-touch'; write_output(original, b'keep')
        alias = self.out / 'keys.rcc'; os.link(original, alias)
        try:
            with self.assertRaisesRegex(ValueError, 'hard-linked'):
                fixture.prepare(self.extracted, self.out)
            self.assertEqual(old_source.read_bytes(), b'previous fixture')
            self.assertEqual(original.read_bytes(), b'keep')
        finally: alias.unlink()

    def test_compiler_failure_preserves_previous_fixture(self):
        old_source = self.out / 'stock/mainmenu/MainScreen.qml'
        write_output(old_source, b'previous fixture')
        with patch.object(fixture.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'rcc')):
            with self.assertRaises(subprocess.CalledProcessError): fixture.prepare(self.extracted, self.out)
        self.assertEqual(old_source.read_bytes(), b'previous fixture')
        self.assertFalse((self.out / 'fixture-manifest.json').exists())

    def test_late_report_directory_rejected_before_any_source_write(self):
        old_source = self.out / 'stock/mainmenu/MainScreen.qml'
        write_output(old_source, b'previous fixture')
        output_directory(self.out / 'fixture-manifest.json')
        with self.assertRaisesRegex(ValueError, 'not a regular file'):
            fixture.prepare(self.extracted, self.out)
        self.assertEqual(old_source.read_bytes(), b'previous fixture')

    def test_unknown_import_in_existing_fixture_rejected(self):
        write_output(self.out / 'stock/mainmenu/qmldir', b'module Wrong\n')
        with self.assertRaisesRegex(ValueError, 'unexpected fixture'):
            fixture.prepare(self.extracted, self.out)


if __name__ == '__main__': unittest.main()
