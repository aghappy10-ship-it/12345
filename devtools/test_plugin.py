import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch, Mock

ROOT = Path(__file__).parent
spec = importlib.util.spec_from_file_location('studio_plugin', ROOT / 'plugin/server.py')
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)


class PluginTests(unittest.TestCase):
    def test_manifest_paths_and_marketplace_bind_to_actual_plugin(self):
        manifest = json.loads((ROOT / 'plugin/.codex-plugin/plugin.json').read_text(encoding='utf-8'))
        self.assertTrue((ROOT / 'plugin' / manifest['mcpServers']).is_file())
        market = json.loads((ROOT.parent / '.agents/plugins/marketplace.json').read_text(encoding='utf-8'))
        self.assertEqual((ROOT / 'plugin').resolve(), (ROOT.parent / market['plugins'][0]['source']['path']).resolve())
        mcp = json.loads((ROOT / 'plugin/.mcp.json').read_text())['mcpServers']['x2dii-studio']
        self.assertTrue(Path(mcp['command']).is_file())
        self.assertEqual(['-B', 'server.py'], mcp['args'])
    def test_stdio_actual_initialize_and_tool_listing(self):
        inputs = [dict(jsonrpc='2.0', id=1, method='initialize', params={'protocolVersion': '2025-06-18'}),
                  dict(jsonrpc='2.0', method='notifications/initialized'), dict(jsonrpc='2.0', id=2, method='tools/list')]
        process = subprocess.run([sys.executable, '-B', str(ROOT / 'plugin/server.py')],
            input='\n'.join(json.dumps(r) for r in inputs) + '\n', capture_output=True, text=True, encoding='utf-8', timeout=10)
        self.assertEqual(0, process.returncode, process.stderr)
        rows = [json.loads(row) for row in process.stdout.splitlines()]
        self.assertEqual(2, len(rows))
        self.assertEqual('2025-06-18', rows[0]['result']['protocolVersion'])
        names = [t['name'] for t in rows[1]['result']['tools']]
        self.assertIn('scan_camera', names)
        self.assertIn('submit_local_task', names)
        self.assertNotIn('flash', names)
    def test_arbitrary_tools_paths_and_commands_rejected(self):
        for name, args in [('shell', {'command': 'test'}), ('read_menu_source', {'source': '../../secret'}),
                           ('get_local_task', {'id': 'bad&path=secret'}), ('scan_camera', {'command': 'write'})]:
            with patch.object(plugin, 'call_api') as api:
                result = plugin.respond(dict(jsonrpc='2.0', id=1, method='tools/call', params={'name': name, 'arguments': args}))
                self.assertTrue(result['result']['isError'])
                api.assert_not_called()
    def test_invalid_protocol_params_are_explicit(self):
        self.assertEqual(-32602, plugin.respond(dict(jsonrpc='2.0', id=1, method='tools/list', params=[]))['error']['code'])
        self.assertIsNone(plugin.respond(dict(jsonrpc='2.0', method='notifications/initialized')))
    def test_backend_routes_are_bounded(self):
        with patch.object(plugin, 'call_api', return_value={'devices': []}) as api:
            plugin.invoke('scan_camera', {})
            api.assert_called_once_with('/api/camera/scan', {})
    def test_session_token_never_reaches_mcp_results(self):
        secret = 'test-only-private-session-token'
        opener = Mock()
        opener.open.return_value = io.BytesIO(json.dumps({'project': str(plugin.PROJECT), 'sessionToken': secret}).encode())
        with patch.object(Path, 'read_text', return_value=json.dumps({'url': plugin.URL, 'token': secret})), patch.object(plugin, 'build_opener', return_value=opener):
            result = plugin.respond(dict(jsonrpc='2.0', id=1, method='tools/call', params={'name': 'get_workbench'}))
        self.assertFalse(result['result']['isError'])
        self.assertNotIn(secret, json.dumps(result))
        self.assertNotIn('sessionToken', json.dumps(result))


if __name__ == '__main__':
    unittest.main()
