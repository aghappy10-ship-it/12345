"""The public catalog/editor API, using tiny fixtures and no camera access."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
import unittest
from unittest.mock import patch

if __package__:
    from .system_code import CodeConflict, SystemCode
else:
    from system_code import CodeConflict, SystemCode


class SystemCodeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.project = root / 'x2d2-reference-restart'
        self.stock = root / 'x2d2'
        self.data = self.project / 'devtools' / 'data'
        self.original = '\ufeff  Item {\r\n    property string name: "原文"\r\n}\r\n'
        sources = {
            self.project / 'qml/X2d2MenuPage.qml': self.original,
            self.project / 'src/menu_preload.c': '/* local extension */\n',
        }
        for name in ('init.eagle2.usb.rc', 'camera-service.rc', 'camera-storage.rc',
                     'init.eagle2.rc', 'camera-upgrade.rc'):
            sources[self.stock / 'work/reverse/vendor/x2dii_1_3_16_2_system_root/etc/init' / name] = 'service fixture /system/bin/fixture\n'
        sources[self.stock / 'work/reverse/camera_gui_1_3_16_2_menu_feature_xrefs.json'] = '{"analysis":true}\n'
        config_root = self.stock / 'work/reverse/vendor/x2dii_1_3_16_2_system_root/etc'
        sources[config_root / 'lensdb/lens.fbs'] = 'namespace Hbl; table Lens {}\n'
        sources[config_root / 'lensdb/stroke.fbs'] = 'namespace Hbl; table Stroke {}\n'
        sources[config_root / 'lensdb/pdaf.fbs'] = 'namespace Hbl; table Pdaf {}\n'
        sources[config_root / 'trace_sql/af_libaf_run_dur.sql'] = 'SELECT AVG(dur) FROM slice;\n'
        for path, text in sources.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(text.encode('utf-8'))
        self.code = SystemCode(self.project, self.data)

    def test_seven_layer_catalog_and_exact_original_text_are_not_deployment(self):
        catalog = self.code.catalog()
        self.assertEqual([section['id'] for section in catalog['sections']],
                         ['ui', 'control', 'hardware', 'imaging', 'storage', 'platform', 'maintenance'])
        for section in catalog['sections']:
            self.assertTrue(any(file['available'] and file['kind'] != 'binary-metadata'
                                for file in section['files']), section['id'])
        self.assertFalse(catalog['deploymentQualified'])
        document = self.code.read('ui-page')
        self.assertEqual(document['text'], self.original)
        self.assertEqual(document['originalText'], self.original)
        self.assertEqual(document['sha256'], hashlib.sha256(self.original.encode('utf-8')).hexdigest())
        self.assertEqual(document['revision'], 0)
        self.assertEqual(document['diff'], '')
        self.assertFalse(document['draft'])

    def test_agreed_layer_names_and_actual_schema_roles_do_not_drift(self):
        catalog = self.code.catalog()
        self.assertEqual([section['title'] for section in catalog['sections']], [
            '界面与菜单', '拍摄控制', '硬件采集与控制', '图像与算法',
            '保存与持久化', '基础系统', '通信与维护'])
        self.assertEqual(self.code.read('ui-preload')['section'], 'ui')
        self.assertIn('不是拍摄', self.code.read('ui-preload')['description'])
        self.assertEqual(self.code.read('control-service-init')['section'], 'control')
        self.assertEqual(self.code.read('maintenance-usb-init')['section'], 'maintenance')
        self.assertEqual(self.code.read('hardware-lens-schema')['kind'], 'fbs-schema')
        self.assertEqual(self.code.read('imaging-pdaf-schema')['kind'], 'fbs-schema')
        self.assertIn('不是算法实现', self.code.read('imaging-pdaf-schema')['description'])

    def test_save_and_reset_preserve_sources_and_round_trip_exact_draft(self):
        before = self.code.read('ui-page')
        edited = self.original.replace('原文', '本地草稿') + '\n  '
        saved = self.code.save('ui-page', edited, before['baseSha256'], before['revision'])
        self.assertEqual(saved['text'], edited)
        self.assertEqual(saved['originalText'], self.original)
        self.assertEqual(saved['revision'], 1)
        self.assertTrue(saved['draft'])
        self.assertIn('-    property string name: "原文"', saved['diff'])
        self.assertIn('+    property string name: "本地草稿"', saved['diff'])
        self.assertEqual((self.project / 'qml/X2d2MenuPage.qml').read_bytes(), self.original.encode('utf-8'))
        reloaded = SystemCode(self.project, self.data).read('ui-page')
        self.assertEqual(reloaded['text'], edited)
        reset = self.code.reset('ui-page', saved['baseSha256'], saved['revision'])
        self.assertEqual(reset['text'], self.original)
        self.assertFalse(reset['draft'])
        self.assertEqual(reset['revision'], 2)
        self.assertEqual(reset['diff'], '')
        self.assertFalse(reset['deploymentQualified'])

    def save_page(self, text='local draft\n'):
        current = self.code.read('ui-page')
        return self.code.save('ui-page', text, current['baseSha256'], current['revision'])

    def test_stale_base_and_revision_never_overwrite_a_newer_draft(self):
        original = self.code.read('ui-page')
        saved = self.save_page()
        with self.assertRaises(CodeConflict):
            self.code.save('ui-page', 'stale', original['baseSha256'], original['revision'])
        with self.assertRaises(CodeConflict):
            self.code.reset('ui-page', '0' * 64, saved['revision'])
        with self.assertRaises(CodeConflict):
            self.code.save('ui-page', 'bool revision', saved['baseSha256'], True)
        self.assertEqual(self.code.read('ui-page')['text'], saved['text'])

    def test_utf8_byte_limit_and_invalid_text_are_rejected_without_creation(self):
        original = self.code.read('ui-page')
        for text in ('汉' * 10667, 'x' * 32001, 'has\x00binary', '\ud800', None):
            with self.assertRaises(ValueError):
                self.code.save('ui-page', text, original['baseSha256'], original['revision'])
        self.assertFalse((self.data / 'code-drafts').exists())
        exact = self.code.save('ui-page', 'x' * 32000, original['baseSha256'], 0)
        self.assertEqual(len(exact['text'].encode('utf-8')), 32000)

    def test_unknown_ids_paths_and_readonly_analysis_are_rejected(self):
        for file_id in ('../qml/X2d2MenuPage.qml', str(self.project / 'qml/X2d2MenuPage.qml'), 'missing', None):
            with self.assertRaises(ValueError):
                self.code.read(file_id)
        analysis = self.code.read('ui-stock-analysis')
        self.assertFalse(analysis['editable'])
        self.assertIsNone(analysis['provenance']['stockVersion'])
        with self.assertRaises(ValueError):
            self.code.save(analysis['id'], 'edited', analysis['baseSha256'], 0)
        self.assertFalse((self.data / 'code-drafts').exists())

    def test_stock_config_edit_is_only_a_local_copy(self):
        before = self.code.read('maintenance-usb-init')
        saved = self.code.save(before['id'], before['text'] + '# local only\n', before['baseSha256'], 0)
        self.assertTrue(saved['draft'])
        self.assertEqual(Path(before['sourcePath']).read_bytes(), before['text'].encode('utf-8'))
        self.assertEqual(saved['provenance']['scope'], 'frozen-stock-extraction')
        self.assertFalse(saved['deploymentQualified'])

    def test_source_change_and_source_loss_preserve_draft_and_block_save_reset(self):
        saved = self.save_page()
        metadata_path = self.data / 'code-drafts/ui-page/record.json'
        metadata = metadata_path.read_bytes()
        source = self.project / 'qml/X2d2MenuPage.qml'
        source.write_bytes(b'externally changed\n')
        for operation in (lambda: self.code.read('ui-page'),
                          lambda: self.code.save('ui-page', 'overwrite', saved['baseSha256'], saved['revision']),
                          lambda: self.code.reset('ui-page', saved['baseSha256'], saved['revision'])):
            with self.assertRaises(CodeConflict):
                operation()
        source.unlink()
        with self.assertRaises(ValueError):
            self.code.save('ui-page', 'overwrite missing', saved['baseSha256'], saved['revision'])
        self.assertEqual(metadata_path.read_bytes(), metadata)
        catalog = self.code.catalog()
        page = next(file for section in catalog['sections'] for file in section['files'] if file['id'] == 'ui-page')
        self.assertFalse(page['available'])
        self.assertFalse(page['editable'])

    def test_corrupt_missing_or_path_injected_metadata_is_never_overwritten(self):
        saved = self.save_page()
        path = self.data / 'code-drafts/ui-page/record.json'
        valid = path.read_bytes()
        record = json.loads(valid)
        record['textFile'] = '../../outside.txt'
        for invalid in (b'{broken', json.dumps(record).encode('utf-8')):
            path.write_bytes(invalid)
            for operation in (lambda: self.code.read('ui-page'),
                              lambda: self.code.save('ui-page', 'replacement', saved['baseSha256'], saved['revision']),
                              lambda: self.code.reset('ui-page', saved['baseSha256'], saved['revision'])):
                with self.assertRaises(ValueError):
                    operation()
            self.assertEqual(path.read_bytes(), invalid)
        path.unlink()
        with self.assertRaises(ValueError):
            self.code.save('ui-page', 'replacement', saved['baseSha256'], saved['revision'])
        self.assertFalse(path.exists())

    def test_damaged_text_copy_is_preserved_and_cannot_be_saved_over(self):
        saved = self.save_page()
        path = self.data / 'code-drafts/ui-page/record.json'
        metadata = path.read_bytes()
        record = json.loads(metadata)
        draft = path.parent / record['textFile']
        draft.write_bytes(b'external damage')
        with self.assertRaises(ValueError):
            self.code.save('ui-page', 'replacement', saved['baseSha256'], saved['revision'])
        self.assertEqual(path.read_bytes(), metadata)
        self.assertEqual(draft.read_bytes(), b'external damage')

    def test_atomic_pointer_failure_keeps_the_previous_revision_readable(self):
        saved = self.save_page()
        native_replace = os.replace
        def fail_record_replace(source, destination):
            if Path(destination).name == 'record.json':
                raise OSError('synthetic commit failure')
            return native_replace(source, destination)
        with patch('devtools.system_code.os.replace', side_effect=fail_record_replace):
            with self.assertRaises(OSError):
                self.code.save('ui-page', 'uncommitted edit', saved['baseSha256'], saved['revision'])
        after = SystemCode(self.project, self.data).read('ui-page')
        self.assertEqual(after['text'], saved['text'])
        self.assertEqual(after['revision'], saved['revision'])

    def test_failed_first_record_commit_is_safe_to_retry_after_restart(self):
        original = self.code.read('ui-page')
        native_replace = os.replace
        def fail_record_replace(source, destination):
            if Path(destination).name == 'record.json':
                raise OSError('synthetic first-record commit failure')
            return native_replace(source, destination)
        with patch('devtools.system_code.os.replace', side_effect=fail_record_replace):
            with self.assertRaises(OSError):
                self.code.save('ui-page', 'not committed', original['baseSha256'], 0)
        restarted = SystemCode(self.project, self.data)
        after = restarted.read('ui-page')
        self.assertEqual(after['text'], self.original)
        self.assertEqual(after['revision'], 0)
        retry = restarted.save('ui-page', 'safe retry', after['baseSha256'], after['revision'])
        self.assertEqual(retry['revision'], 1)
        self.assertEqual(retry['text'], 'safe retry')

    def test_failed_first_generation_publication_is_retryable_without_using_uncommitted_text(self):
        original = self.code.read('ui-page')
        native_replace = os.replace
        destination = self.data / 'code-drafts/ui-page'
        def fail_generation_replace(source, target):
            if Path(target) == destination:
                raise OSError('synthetic generation publication failure')
            return native_replace(source, target)
        with patch('devtools.system_code.os.replace', side_effect=fail_generation_replace):
            with self.assertRaises(OSError):
                self.code.save('ui-page', 'unpublished text', original['baseSha256'], 0)
        self.assertFalse(destination.exists())
        restarted = SystemCode(self.project, self.data)
        self.assertEqual(restarted.read('ui-page')['text'], self.original)
        retry = restarted.save('ui-page', 'committed retry', original['baseSha256'], 0)
        self.assertEqual(retry['text'], 'committed retry')
        self.assertEqual(retry['revision'], 1)

    def test_single_instance_concurrent_saves_have_one_winner(self):
        original = self.code.read('ui-page')
        def submit(index):
            try:
                return self.code.save('ui-page', f'edit {index}', original['baseSha256'], 0)
            except CodeConflict:
                return None
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(submit, range(8)))
        winners = [result for result in results if result is not None]
        self.assertEqual(len(winners), 1)
        self.assertEqual(self.code.read('ui-page')['text'], winners[0]['text'])

    def test_windows_reparse_attributes_block_source_and_draft_roots(self):
        original = self.code.read('ui-page')
        native_lstat = Path.lstat
        targets = [self.project / 'qml', self.data]
        self.data.mkdir(parents=True)
        for target in targets:
            def flagged_lstat(path, *args, **kwargs):
                information = native_lstat(path, *args, **kwargs)
                if path == target:
                    return SimpleNamespace(st_mode=information.st_mode, st_file_attributes=0x400)
                return information
            with patch.object(Path, 'lstat', flagged_lstat):
                with self.assertRaisesRegex(ValueError, 'links|reparse'):
                    self.code.save('ui-page', 'unsafe', original['baseSha256'], 0)
        self.assertFalse((self.data / 'code-drafts').exists())

    def test_binary_metadata_is_not_full_binary_source_or_editable(self):
        binary = self.stock / 'work/reverse/vendor/x2dii_1_3_16_2_system_root/bin/camera-gui'
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b'\x7fELF' + b'\x00' * 100000)
        document = self.code.read('ui-camera-gui-binary')
        metadata = json.loads(document['text'])
        self.assertEqual(metadata['headerBytesRead'], 64)
        self.assertEqual(metadata['sizeBytes'], 100004)
        self.assertIsNone(metadata['fullBinarySha256'])
        self.assertFalse(metadata['fullBinaryRead'])
        self.assertFalse(document['editable'])
        self.assertEqual(document['sha256Scope'], 'metadata-view-not-full-binary')
        with self.assertRaises(ValueError):
            self.code.reset(document['id'], document['baseSha256'], 0)

    def test_oversized_invalid_utf8_or_binary_masquerading_as_source_is_unavailable(self):
        source = self.project / 'qml/X2d2MenuPage.qml'
        for raw in (b'x' * 32001, b'\xff', b'\x7fELFopaque'):
            source.write_bytes(raw)
            with self.assertRaises(ValueError):
                self.code.read('ui-page')
            files = [file for section in self.code.catalog()['sections'] for file in section['files']]
            page = next(file for file in files if file['id'] == 'ui-page')
            self.assertFalse(page['available'])
            self.assertFalse(page['editable'])
            self.assertEqual(source.read_bytes(), raw)
        self.assertFalse((self.data / 'code-drafts').exists())

    def test_large_sensor_config_is_stat_only_information_not_editable_full_text(self):
        path = self.stock / 'work/reverse/vendor/x2dii_1_3_16_2_system_root/etc/imx861bqr_hb722.conf'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'x' * 138519)
        native_open = Path.open
        def guarded_open(candidate, *args, **kwargs):
            if candidate == path:
                raise AssertionError('Large config must not be opened/read')
            return native_open(candidate, *args, **kwargs)
        with patch.object(Path, 'open', guarded_open):
            document = self.code.read('hardware-sensor-config-info')
        metadata = json.loads(document['text'])
        self.assertEqual(metadata['sizeBytes'], 138519)
        self.assertFalse(metadata['fullTextRead'])
        self.assertIsNone(metadata['fullSourceSha256'])
        self.assertFalse(document['editable'])
        self.assertEqual(document['sha256Scope'], 'metadata-view-not-source-content')
        with self.assertRaises(ValueError):
            self.code.save(document['id'], 'edit', document['baseSha256'], 0)


if __name__ == '__main__':
    unittest.main()
