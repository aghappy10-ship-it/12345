"""Small stdio MCP bridge for this user's local X2D II workbench."""
import json
from pathlib import Path
import re
import sys
from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler

PROJECT = Path('F:/Codex/2026-08-19/x2d2-reference-restart')
URL = 'http://127.0.0.1:8765'
TOOLS = [
    ('get_workbench', '查看开发工作台的真实状态和面板地址；不是机身验收。', {}, True),
    ('scan_camera', '只读查询 Windows 当前 X2D II USB 设备；不切模式，不开ADB，不写机身。', {}, True),
    ('list_local_models', '查询指定回环地址实际可用模型；不接受外网地址。', {'endpoint': {'type': 'string'}}, True),
    ('submit_local_task', '把一个明确菜单代码任务交给本地模型后台分析；建议等待 Codex 审查，不执行生成代码。',
     {'prompt': {'type': 'string', 'minLength': 1, 'maxLength': 8000}, 'source': {'type': 'string', 'enum': ['bootstrap', 'model', 'page', 'candidate']}, 'model': {'type': 'string'}}, False),
    ('get_local_task', '读取后台模型任务及真实输出；待审查不等于完成开发。', {'id': {'type': 'string'}}, True),
    ('read_menu_source', '读取允许的菜单源码和哈希，不读取照片、密钥或任意文件。', {'source': {'type': 'string', 'enum': ['bootstrap', 'model', 'page', 'candidate']}}, True),
]


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('workbench redirect forbidden')


def call_api(path, body=None):
    info = json.loads((PROJECT / 'devtools/data/connection.json').read_text(encoding='utf-8'))
    if info.get('url') != URL:
        raise ValueError('工作台地址不匹配；仅支持固定本地项目')
    headers = {'Content-Type': 'application/json'}
    if body is not None:
        headers['X-Session-Token'] = info['token']
    request = Request(URL + path, data=json.dumps(body).encode('utf-8') if body is not None else None, headers=headers)
    with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=40) as response:
        raw = response.read(4_000_001)
    if len(raw) > 4_000_000:
        raise ValueError('工作台响应超过上限')
    value = json.loads(raw)
    if isinstance(value, dict):
        value.pop('sessionToken', None)
    return value


def invoke(name, arguments):
    spec = next((t for t in TOOLS if t[0] == name), None)
    if spec is None or not isinstance(arguments, dict) or set(arguments) - set(spec[2]):
        raise ValueError('未知工具或参数')
    for key, value in arguments.items():
        if not isinstance(value, str) or len(value) > 8000:
            raise ValueError('参数类型或长度错误')
        choices = spec[2][key].get('enum')
        if choices and value not in choices:
            raise ValueError('参数不在允许项中')
    if name == 'get_workbench':
        value = call_api('/api/state')
        if value.get('project') != str(PROJECT):
            raise ValueError('工作台工程身份不匹配')
        return {'dashboardUrl': URL, 'state': value, 'cameraWrites': False}
    if name == 'scan_camera':
        return call_api('/api/camera/scan', {})
    if name == 'list_local_models':
        return call_api('/api/models/probe', arguments)
    if name == 'submit_local_task':
        return call_api('/api/models/submit', arguments)
    if name == 'get_local_task':
        key = arguments.get('id', '')
        if not re.fullmatch('[0-9a-f]{24}', key):
            raise ValueError('任务ID不合法')
        return call_api('/api/model-task?id=' + key)
    if name == 'read_menu_source':
        return call_api('/api/source?id=' + arguments.get('source', 'candidate'))


def respond(request):
    if not isinstance(request, dict) or request.get('jsonrpc') != '2.0':
        return {'jsonrpc': '2.0', 'id': None, 'error': {'code': -32600, 'message': 'Invalid Request'}}
    if 'id' not in request:
        return None
    method, params = request.get('method'), request.get('params', {})
    output = {'jsonrpc': '2.0', 'id': request['id']}
    if not isinstance(method, str) or not isinstance(params, dict):
        output['error'] = {'code': -32602, 'message': 'Invalid params'}
        return output
    if method == 'initialize':
        protocol = params.get('protocolVersion')
        if protocol not in ('2024-11-05', '2025-03-26', '2025-06-18', '2025-11-25'):
            protocol = '2025-06-18'
        output['result'] = {'protocolVersion': protocol, 'capabilities': {'tools': {}},
            'serverInfo': {'name': 'x2dii-dev-studio', 'version': '0.1.0'},
            'instructions': '本地 X2D II 开发助手。打开 dashboardUrl 可看实时面板。USB枚举不是调试连接；桌面 Qt 不是机身；本地模型输出等待Codex当前所选模型审查。不得刷机或把未验证建议当成固件。'}
    elif method == 'ping':
        output['result'] = {}
    elif method == 'tools/list':
        output['result'] = {'tools': [{'name': name, 'description': desc,
            'inputSchema': {'type': 'object', 'properties': fields, 'additionalProperties': False,
                            'required': ['prompt'] if name == 'submit_local_task' else ['id'] if name == 'get_local_task' else []},
            'annotations': {'readOnlyHint': readonly, 'destructiveHint': False, 'openWorldHint': False}}
            for name, desc, fields, readonly in TOOLS]}
    elif method == 'tools/call':
        try:
            value = invoke(params.get('name'), params.get('arguments', {}))
            output['result'] = {'content': [{'type': 'text', 'text': json.dumps(value, ensure_ascii=False)}], 'isError': False}
        except Exception as error:
            output['result'] = {'content': [{'type': 'text', 'text': '本地工具未完成：' + str(error) + '。服务未启动时请打开 devtools/Launch.cmd。'}], 'isError': True}
    else:
        output['error'] = {'code': -32601, 'message': 'Method not found'}
    return output


def main():
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stdin.reconfigure(encoding='utf-8')
    for line in sys.stdin:
        try:
            if len(line) > 100_000:
                raise ValueError('request too large')
            result = respond(json.loads(line))
        except Exception:
            result = {'jsonrpc': '2.0', 'id': None, 'error': {'code': -32700, 'message': 'Parse error'}}
        if result is not None:
            print(json.dumps(result, ensure_ascii=False), flush=True)


if __name__ == '__main__':
    main()
