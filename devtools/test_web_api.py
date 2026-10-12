"""Execute the shipped shared API function against local HTTP fixture servers."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import subprocess
import threading
import unittest


class WebApiTests(unittest.TestCase):
    def setUp(self):
        self.requests = []
        self.outside_requests = []
        owner = self

        class Outside(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                owner.outside_requests.append(dict(self.headers))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{}')

        self.outside = ThreadingHTTPServer(('127.0.0.1', 0), Outside)
        self.outside_url = f'http://127.0.0.1:{self.outside.server_port}'

        class Local(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def respond(self, code, value):
                raw = json.dumps(value, ensure_ascii=False).encode('utf-8')
                self.send_response(code)
                self.send_header('Content-Type', 'application/json; charset=utf-8')
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                owner.requests.append({'path': self.path, 'method': 'GET', 'headers': dict(self.headers)})
                if self.path == '/api/state':
                    self.respond(200, {'sessionToken': 'fixture-session-token', 'camera': {},
                        'board': {'revision': 0, 'tasks': [], 'notes': []},
                        'evidence': {'receipt': None, 'audit': {'state': 'unknown',
                            'progress': None, 'failuresObserved': 0}, 'remaining': []},
                        'preview': {'state': 'not_started'}, 'jobs': {'allowed': [], 'current': None}})
                elif self.headers.get('X-Session-Token') != 'fixture-session-token':
                    self.respond(403, {'error': '缺少当前会话授权'})
                elif self.path.endswith('redirect=1'):
                    self.send_response(302)
                    self.send_header('Location', owner.outside_url + '/api/device/history')
                    self.send_header('Content-Length', '0')
                    self.end_headers()
                elif self.path.endswith('error=1'):
                    self.respond(503, {'error': '历史记录暂时不可用'})
                else:
                    self.respond(200, {'sessionId': 'aabb', 'events': [], 'eventCount': 0,
                        'nextBefore': None, 'hasMore': False})

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
                owner.requests.append({'path': self.path, 'method': 'POST',
                    'headers': dict(self.headers), 'body': json.loads(body.decode('utf-8'))})
                if self.headers.get('X-Session-Token') != 'fixture-session-token':
                    self.respond(403, {'error': '缺少当前会话授权'})
                else:
                    self.respond(200, {'accepted': True})

        self.local = ThreadingHTTPServer(('127.0.0.1', 0), Local)
        self.local_url = f'http://127.0.0.1:{self.local.server_port}'
        self.threads = [threading.Thread(target=server.serve_forever, daemon=True)
                        for server in (self.local, self.outside)]
        for thread in self.threads:
            thread.start()

    def tearDown(self):
        for server in (self.local, self.outside):
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=2)

    def run_app(self, assertions):
        script = r"""
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const origin=process.argv[2],outside=process.argv[3],nodes=new Map(),requests=[];
function node(id){if(!nodes.has(id))nodes.set(id,{textContent:'',className:'',dataset:{},disabled:false,
  handlers:{},options:[],classList:{add(){},remove(){}},append(){},replaceChildren(){},
  setAttribute(){},addEventListener(event,handler){this.handlers[event]=handler;}});return nodes.get(id);}
const context={document:{getElementById:node,createElement:()=>node('new'+nodes.size),
  querySelectorAll:()=>[],addEventListener(){}},setTimeout(){},clearTimeout(){},setInterval(){},
  EventSource:class{addEventListener(){}},fetch:(path,options)=>{
    requests.push({path,options});return fetch(new URL(path,origin),options);
  }};
vm.createContext(context);
const source=fs.readFileSync(process.argv[1],'utf8');
assert.match(source,/\nconnect\(\);\s*$/);
vm.runInContext(source.replace(/\nconnect\(\);\s*$/,''),context);
(async()=>{
await context.connect();
assert.equal(node('live-status').textContent,'● 工作台已连接');
""" + assertions + r"""
})().catch(error=>{console.error(error);process.exitCode=1;});
"""
        result = subprocess.run(['node', '-e', script,
            str(Path(__file__).parent / 'web/app.js'), self.local_url, self.outside_url],
            capture_output=True, text=True, encoding='utf-8', timeout=15)
        self.assertEqual(0, result.returncode, result.stderr)

    def test_history_get_uses_bootstrapped_session_token_with_real_http(self):
        self.run_app(r"""
const page=await context.api('/api/device/history?sessionId=aabb&limit=200');
assert.equal(page.sessionId,'aabb');
assert.equal(requests.at(-1).options.headers['X-Session-Token'],'fixture-session-token');
assert.equal(requests.at(-1).options.body,undefined);
""")
        self.assertEqual('GET', self.requests[-1]['method'])
        self.assertEqual('fixture-session-token', self.requests[-1]['headers'].get('X-Session-Token'))

    def test_existing_post_preserves_json_session_header_and_backend_errors(self):
        self.run_app(r"""
assert.equal((await context.api('/api/device/action',{operation:'monitor-stop'})).accepted,true);
assert.equal((await context.api('/api/system/save',{id:'draft',text:'中文修改'})).accepted,true);
assert.equal((await context.api('/api/tasks/entry',{revision:0,state:'doing'})).accepted,true);
await assert.rejects(context.api('/api/device/history?sessionId=aabb&error=1'),/历史记录暂时不可用/);
""")
        posts = [request for request in self.requests if request['method'] == 'POST']
        self.assertEqual(3, len(posts))
        self.assertEqual({'operation': 'monitor-stop'}, posts[0]['body'])
        self.assertEqual({'id': 'draft', 'text': '中文修改'}, posts[1]['body'])
        for request in posts:
            self.assertEqual('fixture-session-token', request['headers'].get('X-Session-Token'))
            self.assertEqual('application/json', request['headers'].get('Content-Type'))

    def test_token_never_goes_to_absolute_external_or_unlisted_paths(self):
        self.run_app(r"""
const count=requests.length;
for(const path of [outside+'/api/device/history',origin+'/api/device/history',
  outside.replace('http:','')+'/api/device/history','\\\\127.0.0.1/api/device/history',
  '/api/device/../private','/api/device/history/../../private','/api/private',
  '/api/device/%68istory','/api/device/history\n','/api/device/history#outside']){
  await assert.rejects(context.api(path,{private:'must stay local'}),/固定本地接口/);
}
assert.equal(requests.length,count,'Rejected destinations must not reach fetch');
""")
        self.assertEqual([], self.outside_requests)
        self.assertEqual(['/api/state'], [request['path'] for request in self.requests])

    def test_authenticated_local_request_cannot_redirect_token_to_another_origin(self):
        self.run_app(r"""
await assert.rejects(context.api('/api/device/history?sessionId=aabb&redirect=1'));
assert.equal(requests.at(-1).options.redirect,'error');
""")
        self.assertEqual([], self.outside_requests)


if __name__ == '__main__':
    unittest.main()
