"""Execute the shipped timeline JavaScript; fixtures are not camera evidence."""
from pathlib import Path
import subprocess
import unittest


class TimelineWebTests(unittest.TestCase):
    def run_page_script(self, assertions):
        """Use the real page code with only DOM/network/time boundary substitutes."""
        harness = r"""
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const html=fs.readFileSync(require('node:path').join(require('node:path').dirname(process.argv[1]),'index.html'),'utf8');
const htmlIds=Array.from(html.matchAll(/\bid="([^"]+)"/g),match=>match[1]);
assert.equal(new Set(htmlIds).size,htmlIds.length,'Shipped page has duplicate control IDs');
const nodes=new Map();
function makeNode(){return {children:[],_text:'',value:'',dataset:{},disabled:false,handlers:{},
  append(...items){this.children.push(...items);},replaceChildren(...items){this._text='';this.children=items;},
  addEventListener(name,callback){this.handlers[name]=callback;},
  set textContent(v){this._text=String(v);this.children=[];},
  get textContent(){return this._text+this.children.map(x=>x.textContent).join('');}};}
function node(id){assert.ok(htmlIds.includes(id),'Shipped page is missing control '+id);if(!nodes.has(id))nodes.set(id,makeNode());return nodes.get(id);}
node('capture-window').value='all';node('capture-component').value='all';
const now=Date.parse('2026-10-08T04:00:10Z');
class FixedDate extends Date {static now(){return now;}}
let requests=[],pending=[],toasts=[];
const context={document:{getElementById:node,createElement:makeNode},Date:FixedDate,
  fmtTime:t=>t,toast:(text,error)=>toasts.push({text,error}),
  api:(path,body)=>{requests.push({path,body});return new Promise((resolve,reject)=>pending.push({resolve,reject}));}};
vm.createContext(context);vm.runInContext(fs.readFileSync(process.argv[1],'utf8'),context);
const event=(id,section,label)=>({id,section,label,phase:'observed',raw:'raw '+label,
  deviceTime:'10-08 12:00:00',receivedUtc:'2026-10-08T04:00:00Z',evidencePath:'local/raw-'+id,
  bootId:'boot',logWindowId:1,correlation:'uncorrelated'});
const bridge=(sessionId='aabb')=>({closed:false,workerActive:true,
  current:{id:sessionId,operation:'monitor-start',state:'running'},
  monitor:{active:true,state:'running',sessionId,maxSeconds:28800,maxEvidenceBytes:2147483648,
    elapsedSeconds:10,retainedBytes:1024,sourceKind:'manual-live-fixed-byte-range',
    timeline:{events:[],captures:[],samples:1,eventCount:0,retainedEventCount:0,
      sectionCountScope:'session',sections:[],gaps:[],recentRaw:[]}}});
"""
        script = harness + "\n(async()=>{\n" + assertions + r"""
})().catch(error=>{console.error(error);process.exitCode=1;});
"""
        result = subprocess.run(["node", "-e", script, str(Path(__file__).parent / "web/timeline.js")],
                                capture_output=True, text=True, encoding="utf-8", timeout=10)
        self.assertEqual(0, result.returncode, result.stderr)

    def test_session_cards_survive_recent_event_eviction_and_window_counts_are_explicit(self):
        self.run_page_script(r"""
const value=bridge(),timeline=value.monitor.timeline;
timeline.events=Array.from({length:200},(_,index)=>event(index+202,'control','拍摄请求 '+(index+202)));
timeline.eventCount=401;timeline.retainedEventCount=200;
timeline.sections=[{id:'storage',count:9,lastEvent:event(100,'storage','较早写入回执')},
  {id:'control',count:392,lastEvent:timeline.events.at(-1)}];
timeline.captures=[{id:1,startEventId:395,label:'当前窗口',bootId:'boot',logWindowId:1}];
context.renderCameraTimeline(value);
assert.match(node('capture-sections').children[4].textContent,/会话累计 9 条事件/);
assert.match(node('capture-sections').children[4].textContent,/较早写入回执/);
assert.doesNotMatch(node('capture-sections').children[4].textContent,/未观测/);
assert.match(node('capture-log-count').textContent,/会话累计 401 条事件/);
assert.match(node('capture-event-total').textContent,/当前显示 200 条/);
assert.equal(node('capture-events').children.length,200);
node('capture-window').value='1';node('capture-window').handlers.change();
assert.match(node('capture-sections').children[4].textContent,/当前窗口 0 条事件/);
assert.doesNotMatch(node('capture-sections').textContent,/会话累计|未观测/);
assert.match(node('capture-sections').children[1].textContent,/当前窗口 7 条事件/);
assert.match(node('capture-event-total').textContent,/当前窗口显示 7 条/);
""")

    def test_reconnect_keeps_stop_available_and_health_dates_actual_reads(self):
        self.run_page_script(r"""
const value=bridge();
Object.assign(value.monitor,{state:'reconnecting',lastTransportError:'USB disconnected',
  reconnectAttempts:3,totalReconnects:2,bytesRead:4096,readBytesPerSecond:1024,
  backlogBytes:2048,backlogTrend:'growing',lastSuccessfulReadUtc:'2026-10-08T04:00:06Z',historyEventCount:5});
value.monitor.timeline.eventCount=7;value.monitor.timeline.lastReadUtc='2026-10-08T04:00:09Z';
context.renderCameraTimeline(value);
assert.equal(node('capture-status').textContent,'通道断开，正在重连');
assert.equal(node('capture-start').disabled,true);assert.equal(node('capture-stop').disabled,false);
assert.match(node('capture-reason').textContent,/USB disconnected/);
assert.match(node('capture-health').textContent,/累计读取 4 KiB.*当前读取速度 1 KiB\/秒/);
assert.match(node('capture-health').textContent,/积压增长.*本轮重试 3 次.*累计重连 2 次/);
assert.match(node('capture-sample-time').textContent,/04:00:06Z.*距今4秒/);
assert.doesNotMatch(node('capture-sample-time').textContent,/04:00:09Z/);
assert.match(node('capture-log-count').textContent,/会话累计 7 条事件.*已存 5 条/);
value.monitor.stopRequested=true;context.renderCameraTimeline(value);
assert.equal(node('capture-status').textContent,'正在停止读取');assert.equal(node('capture-stop').disabled,true);
value.monitor.stopRequested=false;value.monitor.state='running';value.monitor.backlogTrend='draining';
context.renderCameraTimeline(value);assert.match(node('capture-health').textContent,/积压减少/);
value.monitor.state='failed';value.monitor.active=false;value.workerActive=false;value.current.state='failed';
context.renderCameraTimeline(value);
assert.equal(node('capture-status').textContent,'读取失败');assert.equal(node('capture-stop').disabled,true);
assert.match(node('capture-sample-time').textContent,/最后成功读取.*距今4秒/);
value.monitor.lastSuccessfulReadUtc='invalid';context.renderCameraTimeline(value);
assert.match(node('capture-sample-time').textContent,/无法判断新鲜度/);
""")

    def test_history_pages_preserve_filters_and_live_updates_do_not_replace_them(self):
        self.run_page_script(r"""
const value=bridge();value.monitor.timeline.events=[event(901,'control','实时事件')];
value.monitor.timeline.eventCount=901;value.monitor.historyEventCount=900;
context.renderCameraTimeline(value);
const latest=node('capture-history-start').handlers.click();
assert.equal(requests[0].path,'/api/device/history?sessionId=aabb&limit=200');
assert.equal(requests[0].body,undefined);
assert.equal(node('capture-window').disabled,true);
assert.equal(node('capture-history-live').disabled,false);
pending.shift().resolve({sessionId:'aabb',eventCount:900,
  events:Array.from({length:200},(_,i)=>event(701+i,'storage','历史事件 '+(701+i))),nextBefore:701,hasMore:true});
await latest;
assert.equal(node('capture-events').children.length,200);
assert.match(node('capture-events').textContent,/历史事件 900/);
assert.doesNotMatch(node('capture-events').textContent,/实时事件/);
assert.match(node('capture-sections').children[4].textContent,/本页 200 条事件/);
assert.match(node('capture-sections').children[1].textContent,/本页 0 条事件/);
assert.doesNotMatch(node('capture-sections').textContent,/未观测|会话累计/);
assert.match(node('capture-history-status').textContent,/已存 900 条.*本页 200 条/);
value.monitor.timeline.events=[event(902,'control','随后实时事件')];value.monitor.timeline.samples++;
context.renderCameraTimeline(value);
assert.match(node('capture-events').textContent,/历史事件 900/);
assert.doesNotMatch(node('capture-events').textContent,/随后实时事件/);
node('capture-component').value='control';node('capture-component').handlers.change();
assert.match(node('capture-event-total').textContent,/本页筛选后显示 0 条/);
node('capture-component').value='all';node('capture-component').handlers.change();
const older=node('capture-history-older').handlers.click();
assert.equal(requests[1].path,'/api/device/history?sessionId=aabb&before=701&limit=200');
pending.shift().resolve({sessionId:'aabb',eventCount:900,events:[event(500,'ui','更早界面事件')],nextBefore:null,hasMore:false});
await older;
assert.match(node('capture-events').textContent,/更早界面事件/);
assert.equal(node('capture-history-older').disabled,true);
assert.equal(node('capture-history-newer').disabled,false);
const newer=node('capture-history-newer').handlers.click();
assert.equal(requests[2].path,'/api/device/history?sessionId=aabb&limit=200');
pending.shift().resolve({sessionId:'aabb',eventCount:900,events:[event(900,'storage','返回较新记录')],nextBefore:900,hasMore:true});
await newer;assert.match(node('capture-events').textContent,/返回较新记录/);
node('capture-component').value='control';node('capture-history-live').handlers.click();
assert.equal(node('capture-window').disabled,false);
assert.equal(node('capture-component').value,'control');
assert.match(node('capture-events').textContent,/随后实时事件/);
assert.equal(node('capture-history-live').disabled,true);
""")

    def test_history_failure_preserves_valid_page_and_does_not_invent_zero_stored_records(self):
        self.run_page_script(r"""
const value=bridge();value.monitor.historyEventCount=800;
context.renderCameraTimeline(value);
let task=node('capture-history-start').handlers.click();
assert.match(node('capture-event-total').textContent,/正在读取历史记录/);
pending.shift().reject(Error('history unavailable'));await task;
assert.match(node('capture-history-status').textContent,/历史读取失败.*history unavailable/);
assert.match(node('capture-event-total').textContent,/历史记录未载入/);
assert.doesNotMatch(node('capture-event-total').textContent,/会话已存 0/);
assert.equal(node('capture-history-start').disabled,false);
assert.equal(node('capture-history-older').disabled,true);
task=node('capture-history-start').handlers.click();
pending.shift().resolve({sessionId:'aabb',eventCount:800,events:[event(800,'ui','有效历史页面')],nextBefore:800,hasMore:true});
await task;
task=node('capture-history-older').handlers.click();
pending.shift().reject(Error('page unavailable'));await task;
assert.match(node('capture-events').textContent,/有效历史页面/);
assert.match(node('capture-event-total').textContent,/会话已存 800 条/);
assert.equal(node('capture-history-newer').disabled,true);
assert.equal(node('capture-history-older').disabled,false);
task=node('capture-history-older').handlers.click();
assert.equal(requests.at(-1).path,'/api/device/history?sessionId=aabb&before=800&limit=200');
pending.shift().resolve({sessionId:'wrong-session',eventCount:9,events:[event(2,'control','错误会话记录')],nextBefore:null,hasMore:false});
await task;
assert.match(node('capture-history-status').textContent,/当前会话不一致/);
assert.match(node('capture-events').textContent,/有效历史页面/);
assert.doesNotMatch(node('capture-events').textContent,/错误会话记录/);
""")

    def test_history_responses_after_return_live_or_new_session_are_ignored(self):
        self.run_page_script(r"""
const value=bridge();value.monitor.timeline.events=[event(4,'control','原会话实时')];
context.renderCameraTimeline(value);
let task=node('capture-history-start').handlers.click(),old=pending.shift();
node('capture-history-live').handlers.click();
old.resolve({sessionId:'aabb',eventCount:1,events:[event(1,'ui','迟到历史')],nextBefore:null,hasMore:false});
await task;
assert.match(node('capture-events').textContent,/原会话实时/);
assert.doesNotMatch(node('capture-events').textContent,/迟到历史/);
assert.equal(node('capture-window').disabled,false);
task=node('capture-history-start').handlers.click();old=pending.shift();
const fresh=bridge('ccdd');fresh.monitor.timeline.events=[event(1,'storage','新会话实时')];
context.renderCameraTimeline(fresh);
assert.equal(node('capture-window').value,'all');assert.equal(node('capture-window').disabled,false);
assert.equal(node('capture-history-live').disabled,true);
const current=node('capture-history-start').handlers.click(),newPending=pending.shift();
assert.equal(requests.at(-1).path,'/api/device/history?sessionId=ccdd&limit=200');
old.reject(Error('旧会话错误'));await task;
assert.equal(toasts.length,0);
assert.match(node('capture-history-status').textContent,/正在读取已存事件/);
newPending.resolve({sessionId:'ccdd',eventCount:1,events:[event(1,'storage','新会话历史')],nextBefore:null,hasMore:false});
await current;
assert.match(node('capture-events').textContent,/新会话历史/);
assert.doesNotMatch(node('capture-history-status').textContent,/旧会话错误/);
""")

    def test_resynchronizing_and_incomplete_windows_keep_missing_evidence_visible(self):
        self.run_page_script(r"""
const value=bridge(),timeline=value.monitor.timeline;
Object.assign(value.monitor,{backlogBytes:null,readState:'resynchronizing',lastSampleStable:false,lastSuccessfulReadUtc:null});
timeline.lastReadUtc='2026-10-08T04:00:09Z';
timeline.captures=[{id:1,startEventId:2,windowStartRetained:false,label:'旧拍摄窗口'}];
timeline.gaps=[{reason:'log rotated',previousSourceUnread:{bootId:'old-boot',inode:'old-inode',fromOffset:100,
  toObservedSize:300,knownUnreadBytes:200,unfinishedLine:true}}];
const sample=event(10,'storage','跨块事件');sample.evidenceRanges=[
  {evidencePath:'local/first-block',offset:200,bytes:120},{evidencePath:'local/second-block',offset:320,bytes:80}];
timeline.events=[sample];
context.renderCameraTimeline(value);
assert.match(node('capture-budget').textContent,/未读积压 未知/);
assert.doesNotMatch(node('capture-budget').textContent,/未读积压 0 B/);
assert.match(node('capture-health').textContent,/重建读取起点.*最近样本尚未稳定/);
assert.match(node('capture-sample-time').textContent,/尚无本次成功读取/);
assert.doesNotMatch(node('capture-sample-time').textContent,/04:00:09Z/);
assert.match(node('capture-gaps').textContent,/旧日志.*old-boot.*old-inode.*起点 100.*文件大小 300.*已知未读 200 B.*末行未完成/);
assert.match(node('capture-events').textContent,/local\/first-block.*起点 200.*120 B/);
assert.match(node('capture-events').textContent,/local\/second-block.*起点 320.*80 B/);
assert.match(node('capture-window').children[1].textContent,/展示不完整/);
node('capture-window').value='1';node('capture-window').handlers.change();
assert.match(node('capture-event-total').textContent,/窗口起点.*展示不完整/);
assert.match(node('capture-sections').children[0].textContent,/当前窗口 0 条事件.*展示不完整/);
""")

    def test_actual_render_filters_original_evidence_and_monitor_actions(self):
        script = r"""
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const nodes=new Map();
function makeNode(){return {children:[],_text:'',value:'',dataset:{},disabled:false,handlers:{},
  append(...items){this.children.push(...items);},replaceChildren(...items){this._text='';this.children=items;},
  addEventListener(name,callback){this.handlers[name]=callback;},
  set textContent(v){this._text=String(v);this.children=[];},
  get textContent(){return this._text+this.children.map(x=>x.textContent).join('');}};}
function node(id){if(!nodes.has(id))nodes.set(id,makeNode());return nodes.get(id);}
node('capture-window').value='all';node('capture-component').value='all';
let bridge={closed:false,workerActive:false,monitor:{state:'idle',timeline:{events:[],captures:[]}}};
let fail=false,requests=[],release;
const context={document:{getElementById:node,createElement:makeNode},fmtTime:t=>t,toast(){},
  api:async(path,body)=>{requests.push({path,body});await new Promise(r=>release=r);if(fail)throw Error('query refused');return bridge;}};
vm.createContext(context);vm.runInContext(fs.readFileSync(process.argv[1],'utf8'),context);
assert.equal(node('capture-sections').children.length,7);
assert.match(node('capture-sections').textContent,/未观测/);
const event=(id,section,label)=>({id,section,label,phase:'observed',raw:'<script>not executable</script> '+label,
  deviceTime:'10-08 12:00:0'+id,receivedUtc:'received',evidencePath:'local/raw-'+id,
  bootId:'actual-boot',logWindowId:1,correlation:'uncorrelated',frameId:null,requestId:null});
bridge={closed:false,workerActive:true,current:{id:'session',operation:'monitor-start',state:'running'},
  monitor:{active:true,state:'running',sessionId:'session',scope:'bounded real device log',evidencePath:'local/evidence',timeline:{
    bootId:'actual-boot',samples:2,lastReadUtc:'last-sample',gaps:[],recentRaw:['raw-one','raw-two'],capturedCount:2,
    events:[event(1,'imaging','预览对焦日志'),event(2,'control','拍摄请求'),event(3,'storage','写入回执'),event(4,'control','拍摄请求')],
    captures:[{id:1,startEventId:2,label:'拍摄窗口 1',bootId:'actual-boot',logWindowId:1},{id:2,startEventId:4,label:'拍摄窗口 2',bootId:'actual-boot',logWindowId:1}]}}};
Object.assign(bridge.monitor,{maxSeconds:28800,maxEvidenceBytes:2147483648,elapsedSeconds:1800,retainedBytes:18874368});
Object.assign(bridge.monitor,{sourceKind:'manual-live-fixed-byte-range',backlogBytes:206752});
context.renderCameraTimeline(bridge);
assert.match(node('capture-budget').textContent,/30分钟.*8小时/);
assert.match(node('capture-budget').textContent,/18 MiB.*2 GiB/);
assert.match(node('capture-budget').textContent,/未读积压 201.9 KiB/);
bridge.monitor.elapsedSeconds=1801;context.renderCameraTimeline(bridge);
assert.match(node('capture-budget').textContent,/30分钟1秒/); // Updates even when the log snapshot is unchanged.
assert.equal(node('capture-status').textContent,'正在读取机内新增日志');
assert.equal(node('capture-start').disabled,true);assert.equal(node('capture-stop').disabled,false);
assert.equal(node('capture-window').children.length,3);
assert.equal(node('capture-events').children.length,4);
node('capture-events').children[0].captureDetails.open=true;
bridge.monitor.timeline.samples=3;context.renderCameraTimeline(bridge);
assert.equal(node('capture-events').children[0].captureDetails.open,true);
assert.match(node('capture-events').textContent,/<script>not executable<\/script>/);
assert.match(node('capture-events').textContent,/未能逐帧关联/);
assert.equal(node('capture-raw-text').textContent,'raw-one\nraw-two');
node('capture-window').value='1';node('capture-window').handlers.change();
assert.equal(node('capture-events').children.length,2);
assert.doesNotMatch(node('capture-events').textContent,/预览对焦日志/);
assert.match(node('capture-sections').children[2].textContent,/当前窗口 0 条事件/);
node('capture-component').value='storage';node('capture-component').handlers.change();
assert.equal(node('capture-events').children.length,1);
assert.match(node('capture-events').textContent,/写入回执/);
node('capture-window').value='2';node('capture-component').value='all';
bridge.monitor.timeline.events.push({...event(5,'storage','重启后的其他保存'),bootId:'new-boot',logWindowId:2});
bridge.monitor.timeline.samples=4;context.renderCameraTimeline(bridge);
assert.equal(node('capture-events').children.length,1);
assert.doesNotMatch(node('capture-events').textContent,/重启后的其他保存/);
node('capture-window').value='all';context.renderCaptureEvents();
assert.match(node('capture-events').textContent,/启动 new-boot/);
bridge={...bridge,workerActive:false,current:{state:'failed'},monitor:{...bridge.monitor,active:false,state:'failed',error:'camera disconnected'}};
context.renderCameraTimeline(bridge);
assert.equal(node('capture-status').textContent,'读取失败');assert.match(node('capture-reason').textContent,/disconnected/);
assert.equal(node('capture-stop').disabled,true);
assert.match(node('capture-sample-time').textContent,/last-sample/); // Retained, dated evidence, not fresh success.
(async()=>{
  fail=true;const pending=context.captureAction('monitor-start');assert.equal(node('capture-start').disabled,true);
  release();await pending;assert.match(node('capture-reason').textContent,/本次请求失败/);
  assert.equal(node('capture-start').disabled,false);
  fail=false;const success=context.captureAction('monitor-start');release();await success;
  assert.equal(requests.length,2);assert.equal(requests[0].path,'/api/device/action');
  assert.deepEqual(JSON.parse(JSON.stringify(requests[0].body)),{operation:'monitor-start'});
  assert.doesNotMatch(node('capture-reason').textContent,/本次请求失败/);
  context.renderCameraTimeline({...bridge,closed:true});assert.equal(node('capture-start').disabled,true);
})().catch(error=>{console.error(error);process.exitCode=1;});
"""
        result = subprocess.run(["node", "-e", script, str(Path(__file__).parent / "web/timeline.js")],
                                capture_output=True, text=True, encoding="utf-8", timeout=10)
        self.assertEqual(0, result.returncode, result.stderr)


if __name__ == "__main__":
    unittest.main()
