'use strict';
let state=null, token='', activeTab='overview', frameTimer=null, logTimer=null, renderedRevision=-1;
let cameraScanning=false, cameraScanError='';
const labels={todo:'待办',doing:'进行中',blocked:'阻塞',done:'已登记完成'};
const $=id=>document.getElementById(id);
function el(tag,text,cls){const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n;}
function toast(message,error=false){$('notice').textContent=message;$('notice').className='toast'+(error?' error':'');clearTimeout(toast.timer);toast.timer=setTimeout(()=>$('notice').classList.add('hidden'),6000);}
async function api(path,body){
  const endpoint=typeof path==='string'?path.split('?')[0]:'';
  const allowed=/^\/api\/(?:state|source|diff|log|model-task|system\/(?:catalog|file|save|reset)|device\/(?:status|timeline|history|action)|camera\/scan|models\/(?:probe|submit)|jobs\/(?:start|stop)|preview\/(?:start|stop|input)|tasks(?:\/[a-zA-Z0-9_-]+)?|notes)$/;
  if(!allowed.test(endpoint)||/[\\#\u0000-\u0020]/.test(path))throw Error('仅允许工作台固定本地接口');
  const options={method:body===undefined?'GET':'POST',headers:token?{'X-Session-Token':token}:{},mode:'same-origin',credentials:'same-origin',redirect:'error'};
  if(body!==undefined){options.headers['Content-Type']='application/json';options.body=JSON.stringify(body);}
  const r=await fetch(path,options),v=await r.json();if(!r.ok)throw Error(v.error||'请求失败');return v;
}
async function action(path,body){try{const result=await api(path,body);if(path.startsWith('/api/tasks')||path==='/api/notes'){state.board=result;renderedRevision=-1;renderBoard();}return result;}catch(e){toast(e.message,true);if(state){const fresh=await api('/api/state').catch(()=>null);if(fresh)accept(fresh);}return null;}}
function fmtTime(t){return t?new Date(t).toLocaleString('zh-CN',{hour12:false}):'尚无时间记录';}
function switchTab(name){activeTab=name;document.querySelectorAll('.tab').forEach(n=>n.classList.toggle('active',n.id===name));document.querySelectorAll('.nav').forEach(n=>n.classList.toggle('active',n.dataset.tab===name));$('page-title').textContent={overview:'开发工作台',capture:'拍摄时间线',preview:'界面实验室',devices:'相机与模型',tasks:'任务协作',code:'系统代码',logs:'本地日志'}[name];if(name==='code'){loadSource();if(typeof loadSystemCatalog==='function')loadSystemCatalog();}if(name==='logs')loadLog();}
document.querySelectorAll('[data-tab],[data-goto]').forEach(n=>n.addEventListener('click',()=>switchTab(n.dataset.tab||n.dataset.goto)));
function accept(value){state=value;if(value.sessionToken)token=value.sessionToken;$('clock').textContent=new Date().toLocaleTimeString('zh-CN',{hour12:false});renderOverview();renderBoard();renderPreview();renderJobs();renderDevices();if(typeof renderSystemStatus==='function')renderSystemStatus(value.deviceBridge);if(typeof renderCameraTimeline==='function')renderCameraTimeline(value.deviceBridge);}
function renderOverview(){renderCameraOverview();const evidence=state.evidence;const receipt=evidence.receipt;$('receipt-status').textContent=receipt?({PASS:'宿主观察通过',FAIL:'宿主观察失败',UNMATCHED:'旧结果 · 源码未匹配'}[receipt.result]||receipt.result):'尚无结果';const a=evidence.audit;$('audit-status').textContent={running:'正在执行',finished:'已有终态',incomplete:'已停止 · 未完整结束',unknown:'运行状态未确认'}[a.state];$('audit-detail').textContent=`${a.progress===null?'未读取进度':a.progress+'%（测试进度）'} · ${a.failuresObserved} 项已记录失败`;$('remaining').replaceChildren(...evidence.remaining.map(t=>el('li',t)));$('task-summary').replaceChildren(...state.board.tasks.slice(0,5).map(t=>{const row=el('div',undefined,'summary-row');row.append(el('span',t.state==='done'?'●':'○'),el('span',t.title),el('span',labels[t.state]));return row;}));}
function renderBoard(){if(renderedRevision===state.board.revision)return;const editing=document.activeElement;if(editing&&editing.closest('.task-card'))return;renderedRevision=state.board.revision;const cols=Object.keys(labels).map(key=>{const column=el('div',undefined,'kanban-column');const tasks=state.board.tasks.filter(t=>t.state===key);const heading=el('div',labels[key],'kanban-heading');heading.append(el('span',String(tasks.length)));column.append(heading);tasks.forEach(t=>{const card=el('article',undefined,'task-card');const formRevision=state.board.revision;card.append(el('h4',t.title));const owner=el('input');owner.value=t.owner;owner.maxLength=80;owner.setAttribute('aria-label','负责人');const select=el('select');Object.entries(labels).forEach(([v,l])=>{const o=el('option',l);o.value=v;o.selected=v===t.state;select.append(o);});select.setAttribute('aria-label','任务状态');const note=el('textarea');note.value=t.note;note.maxLength=4000;note.placeholder='具体阻塞 / 证据路径 / 下一步';const save=el('button','保存调整');save.addEventListener('click',async()=>{save.disabled=true;await action('/api/tasks/'+t.id,{revision:formRevision,owner:owner.value,state:select.value,note:note.value});save.disabled=false;document.activeElement.blur();renderedRevision=-1;renderBoard();});card.append(owner,select,note,save);if(t.heartbeatUtc)card.append(el('small','最近协作者登记：'+fmtTime(t.heartbeatUtc)));column.append(card);});return column;});$('kanban').replaceChildren(...cols);$('notes').replaceChildren(...state.board.notes.slice().reverse().map(n=>{const row=el('div',undefined,'note-row');row.append(el('small',n.author+' · '+fmtTime(n.utc)),el('div',n.text));return row;}));}
$('task-form').addEventListener('submit',async e=>{e.preventDefault();const result=await action('/api/tasks',{revision:state.board.revision,title:$('task-title').value,owner:$('task-owner').value||'待分配'});if(result){$('task-title').value='';toast('任务已保存，其他窗口会同步。');}});
$('note-form').addEventListener('submit',async e=>{e.preventDefault();const result=await action('/api/notes',{revision:state.board.revision,text:$('note-text').value,author:'用户'});if(result)$('note-text').value='';});
function renderPreview(){const p=state.preview;const running=p.state==='running';$('start-preview').disabled=running;$('stop-preview').disabled=!running;$('back-preview').disabled=!running||!p.ready;$('capture-frame').disabled=!p.ready;$('preview-state').textContent={running:p.ready?'预览运行中':'正在启动',failed:'预览失败',stopped:'已停止',not_started:'未启动'}[p.state]||p.state||'未启动';$('preview-detail').textContent=p.error||p.phase||'1024 × 768 · Qt 软件渲染';const details=[p.mode?'模式：'+(p.mode==='candidate'?'隔离扩展候选':'原厂菜单'):null,p.pid?'进程：'+p.pid:null,p.receipt?'菜单观察：'+JSON.stringify(p.receipt):null,p.error?'问题：'+p.error:null].filter(Boolean);$('preview-observation').textContent=details.join('\n')||'尚无运行中的预览。';if(!running){$('preview-frame').classList.add('hidden');$('preview-placeholder').classList.remove('hidden');}}
$('start-preview').addEventListener('click',async()=>{const mode=$('preview-mode').value;$('start-preview').disabled=true;const result=await action('/api/preview/start',{mode});if(result){toast('预览已启动；等待真实画面。');switchTab('preview');}});
$('stop-preview').addEventListener('click',()=>action('/api/preview/stop',{}));
$('back-preview').addEventListener('click',()=>action('/api/preview/input',{kind:'back'}));
$('preview-frame').addEventListener('click',e=>{if(!state.preview.ready)return;const rect=e.target.getBoundingClientRect();const nw=e.target.naturalWidth,nh=e.target.naturalHeight;const scale=Math.min(rect.width/nw,rect.height/nh);const w=nw*scale,h=nh*scale;const x=(e.clientX-rect.left-(rect.width-w)/2)/scale,y=(e.clientY-rect.top-(rect.height-h)/2)/scale;if(x<0||y<0||x>=nw||y>=nh)return;action('/api/preview/input',{kind:'tap',x:Math.floor(x),y:Math.floor(y)});});
document.addEventListener('keydown',e=>{if(e.key==='Escape'&&activeTab==='preview'&&state?.preview.ready){e.preventDefault();action('/api/preview/input',{kind:'back'});}});
$('capture-frame').addEventListener('click',async()=>{try{const r=await fetch('/api/frame');if(!r.ok)throw Error('暂无预览画面');const blob=await r.blob();const url=URL.createObjectURL(blob);const a=el('a');a.href=url;a.download='x2dii-desktop-preview-'+Date.now()+'.png';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}catch(e){toast(e.message,true);}});
async function loadFrame(){if(activeTab!=='preview'||!state?.preview.ready)return;try{const r=await fetch('/api/frame?t='+Date.now());if(!r.ok)return;const url=URL.createObjectURL(await r.blob());const img=$('preview-frame');const old=img.dataset.objectUrl;img.onload=()=>{img.classList.remove('hidden');$('preview-placeholder').classList.add('hidden');if(old)URL.revokeObjectURL(old);};img.dataset.objectUrl=url;img.src=url;}catch(e){/* Connection state is handled by SSE. */}}
async function loadSource(){try{const key=$('source-select').value;const v=await api(key==='diff'?'/api/diff':'/api/source?id='+encodeURIComponent(key));$('source-text').textContent=v.text||'无差异';$('source-meta').textContent=key==='diff'?'原文件 '+v.oldSha.slice(0,12)+' → 候选 '+v.newSha.slice(0,12):v.name+' · '+v.sha256.slice(0,16);}catch(e){$('source-text').textContent=e.message;}}
$('source-select').addEventListener('change',loadSource);$('refresh-source').addEventListener('click',loadSource);
function renderJobs(){const jobs=state.jobs;if(!$('job-select').options.length)jobs.allowed.forEach(j=>{const o=el('option',j.label);o.value=j.id;$('job-select').append(o);});const job=jobs.current;const running=job?.state==='running';$('start-job').disabled=running;$('stop-job').disabled=!running;$('job-state').textContent=job?`${({running:'正在执行',passed:'本项检查通过',failed:'本项检查失败',stopped:'已停止',timeout:'执行超时'})[job.state]||job.state} · ${job.elapsedSeconds||0}s`:'尚未运行';}
$('start-job').addEventListener('click',async()=>{const result=await action('/api/jobs/start',{id:$('job-select').value});if(result){$('log-select').value='job';loadLog();}});$('stop-job').addEventListener('click',()=>action('/api/jobs/stop',{}));
async function loadLog(){if(activeTab!=='logs')return;try{const v=await api('/api/log?id='+$('log-select').value);const box=$('log-text');if(box.textContent!==v.text){box.textContent=v.text||'当前日志为空。';if($('auto-scroll').checked)box.scrollTop=box.scrollHeight;}}catch(e){$('log-text').textContent=e.message;}}
$('log-select').addEventListener('change',loadLog);
async function connect(){try{accept(await api('/api/state'));$('connection').textContent='工作台状态同步 · 每秒更新';$('live-status').textContent='● 工作台已连接';const events=new EventSource('/api/events');let opened=false;events.onopen=()=>{if(opened)api('/api/state').then(accept).catch(()=>{});opened=true;};events.addEventListener('state',e=>{accept(JSON.parse(e.data));$('connection').textContent='工作台状态同步 · 每秒更新';$('live-status').textContent='● 工作台已连接';});events.onerror=()=>{$('connection').textContent='连接中断，正在重连…';$('live-status').textContent='工作台连接中断';};frameTimer=setInterval(loadFrame,700);logTimer=setInterval(loadLog,1000);}catch(e){$('connection').textContent='工作台无法连接';toast(e.message,true);setTimeout(connect,3000);}}
let modelSignature='';
function cameraOverview(c={},scanning=false,error=''){
  let title='尚未检测相机',tone='unknown',detail='点击重新检测，只读取 Windows 的 USB 设备记录。';
  if(scanning){title='正在检测相机…';detail='只读识别中，不会修改机身或切换连接模式。';}
  else if(error){title='检测请求失败 · 连接状态未知';detail=error;}
  else if(c.status==='usb_identified'&&c.present===true){
    title='相机已连接（USB 已识别）';tone='connected';
    detail='检测到 X2D II；尚未验证机身代码读取、部署或加载。';
    const missing=(c.instances||[]).filter(r=>r.problem===28||r.problem==='28'||r.problem==='CM_PROB_FAILED_INSTALL').length;
    if(missing)detail+=' '+missing+' 个接口缺少驱动。';
    if(c.metadata?.complete===false)detail+=' 接口详情不完整，不影响 USB 识别。';
  }else if(c.status==='not_detected'&&c.present===false){title='未检测到相机';tone='absent';detail='本次完整查询没有发现 X2D II USB 设备。';}
  else if(c.status==='discovery_failed'||c.status==='discovery_incomplete'||c.status==='usb_identified'||c.status==='not_detected'){
    title='相机连接状态未知';detail=c.error||'设备查询未完成或结果不一致，请重新检测。';
  }
  return {title,tone,detail,time:c.finished_utc||c.timestamp_utc||null};
}
function renderCameraOverview(){
  const view=cameraOverview(state?.camera||{},cameraScanning,cameraScanError);
  $('overview-camera-status').textContent=view.title;
  $('overview-camera-detail').textContent=view.detail;
  $('camera-connection').dataset.state=view.tone;
  $('overview-camera-time').textContent=view.time?'最近检测：'+fmtTime(view.time)+' · 手动检测快照':'尚未检测 · 非持续连接监测';
  ['overview-scan-camera','scan-camera'].forEach(id=>{$(id).disabled=cameraScanning||!state;});
}
function cameraDescription(c){
  const labels={'not-scanned':'尚未识别相机',not_detected:'未检测到 X2D II',usb_identified:'已识别 X2D II USB 设备',discovery_failed:'设备查询失败，连接状态未知',discovery_incomplete:'设备查询不完整，连接状态未知'};
  const missingDrivers=(c.instances||[]).filter(r=>r.problem===28||r.problem==='28'||r.problem==='CM_PROB_FAILED_INSTALL').length;
  const time=c.finished_utc||c.timestamp_utc;
  const rows=[labels[c.status]||c.status,time?'最近检测快照：'+fmtTime(time):'',c.instances?.length?'匹配接口：'+c.instances.length:'',
    missingDrivers?'接口驱动：'+missingDrivers+' 个接口缺少驱动；相机 USB 已识别':'',
    c.present&&c.metadata?.complete===false?'接口详情不完整；不影响 USB 识别':'',
    c.debug_connected?'调试通道：已验证':'调试和拍摄通道：尚未接入',c.error?'问题：'+c.error:''];
  return rows.filter(Boolean).join('\n');
}
function renderDevices(){
  if(!state.models)return;
  const camera=state.camera||{},view=cameraOverview(camera,cameraScanning,cameraScanError);
  $('camera-detail').textContent=(cameraScanning||cameraScanError)?view.title+'\n'+view.detail+'\n\n上次检测快照（不代表当前状态）：\n'+cameraDescription(camera):cameraDescription(camera);
  const m=state.models, signature=JSON.stringify(m.models);
  if(signature!==modelSignature){modelSignature=signature;$('model-select').replaceChildren(...(m.models.length?m.models:['']).map(name=>{const o=el('option',name||'尚未检测');o.value=name;return o;}));}
  $('model-detail').textContent=m.error||m.scope;
  const value=JSON.stringify(m.jobs);
  if($('model-jobs').dataset.signature!==value){
    $('model-jobs').dataset.signature=value;
    $('model-jobs').replaceChildren(...m.jobs.slice().reverse().map(j=>{
      const row=el('div',undefined,'summary-row');
      row.append(el('span',j.model),el('span',({queued:'排队中',running:'模型正在执行','awaiting-review':'等待 Codex 审查',failed:'任务失败',interrupted:'已中断'})[j.state]||j.state));
      const b=el('button','查看输出');
      b.addEventListener('click',async()=>{try{const v=await api('/api/model-task?id='+j.id);$('model-output').textContent=v.output||v.error||'尚未完成';}catch(e){toast(e.message,true);}});
      row.append(b);return row;
    }));
  }
}
async function scanCamera(){
  if(cameraScanning||!state)return;
  cameraScanning=true;cameraScanError='';renderCameraOverview();renderDevices();
  try{state.camera=await api('/api/camera/scan',{});}
  catch(e){cameraScanError=e.message;toast(e.message,true);}
  finally{cameraScanning=false;renderCameraOverview();renderDevices();}
}
['overview-scan-camera','scan-camera'].forEach(id=>$(id).addEventListener('click',scanCamera));
$('probe-model').addEventListener('click',async()=>{$('probe-model').disabled=true;const v=await action('/api/models/probe',{endpoint:$('model-endpoint').value});if(v){state.models=v;renderDevices();}$('probe-model').disabled=false;});
$('model-form').addEventListener('submit',async e=>{e.preventDefault();const v=await action('/api/models/submit',{prompt:$('model-prompt').value,source:$('model-source').value,model:$('model-select').value});if(v){$('model-prompt').value='';toast('已加入本地模型队列；结果等待 Codex 审查。');}});
connect();
