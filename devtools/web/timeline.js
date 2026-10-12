'use strict';
let captureBridge=null,captureSignature='',captureActionPending=false,captureLastSession=null,captureRequestError='';
let captureHistoryMode=false,captureHistory=null,captureHistoryPending=false,captureHistoryError='',captureHistoryRequest=0,captureHistoryBefore=null,captureHistoryStack=[];
const captureParts=[['ui','界面与菜单'],['control','拍摄控制'],['hardware','硬件采集与控制'],['imaging','图像与算法'],['storage','保存与持久化'],['platform','基础系统'],['maintenance','通信与维护']];
const captureNode=id=>document.getElementById(id);
function captureElement(tag,text,cls){const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n;}
function captureData(bridge){const monitor=bridge?.monitor||{};return {monitor,timeline:monitor.timeline||monitor};}
function captureDuration(seconds){
  if(!Number.isFinite(seconds)||seconds<0)return '未提供';
  const total=Math.floor(seconds),hours=Math.floor(total/3600),minutes=Math.floor(total%3600/60),rest=total%60;
  return (hours?hours+'小时':'')+(minutes?minutes+'分钟':'')+(rest||!total?rest+'秒':'');
}
function captureBytes(bytes){
  if(!Number.isFinite(bytes)||bytes<0)return '未提供';
  const units=['B','KiB','MiB','GiB'];let value=bytes,index=0;
  while(value>=1024&&index<units.length-1){value/=1024;index++;}
  return Number(value.toFixed(1))+' '+units[index];
}
function captureFreshness(utc){
  const timestamp=Date.parse(utc),age=(Date.now()-timestamp)/1000;
  return Number.isFinite(timestamp)&&age>=0?'距今'+captureDuration(age):'时间无效，无法判断新鲜度';
}
function captureGapText(gap){
  if(typeof gap==='string')return '观测缺口：'+gap;
  const previous=gap.previousSourceUnread;
  return '观测缺口：'+(gap.reason||gap.type||'日志连续性未确定')+(previous?' · 旧日志尾部未恢复：'+(previous.bootId||'启动未知')+' / '+(previous.inode??'文件标识未知')+' · 起点 '+previous.fromOffset+' · 观察文件大小 '+previous.toObservedSize+' · 已知未读 '+captureBytes(previous.knownUnreadBytes)+(previous.unfinishedLine?' · 末行未完成':''):'');
}
function captureWindowEvents(timeline){
  const events=timeline.events||[],captures=timeline.captures||[],selected=captureNode('capture-window').value;
  if(selected==='all')return events;
  const index=captures.findIndex(c=>String(c.id)===selected);if(index<0)return events;
  const capture=captures[index],start=capture.startEventId,next=captures[index+1]?.startEventId;
  return events.filter(e=>e.id>=start&&(next===undefined||e.id<next)&&
    (!capture.bootId||e.bootId===capture.bootId)&&
    (capture.logWindowId===undefined||e.logWindowId===capture.logWindowId));
}
function resetCaptureHistory(){
  ++captureHistoryRequest;captureHistoryMode=false;captureHistory=null;captureHistoryPending=false;captureHistoryError='';captureHistoryBefore=null;captureHistoryStack=[];
}
function renderCaptureHistoryControls(){
  captureNode('capture-window').disabled=captureHistoryMode;
  captureNode('capture-history-start').disabled=!captureLastSession||captureHistoryPending;
  captureNode('capture-history-start').textContent=captureHistoryMode?'重新载入最新记录':'查看已存记录';
  captureNode('capture-history-older').disabled=!captureHistoryMode||captureHistoryPending||!captureHistory?.hasMore||captureHistory.nextBefore===null;
  captureNode('capture-history-newer').disabled=!captureHistoryMode||captureHistoryPending||!captureHistoryStack.length;
  captureNode('capture-history-live').disabled=!captureHistoryMode;
  captureNode('capture-history-status').textContent=captureHistoryError?'历史读取失败：'+captureHistoryError:captureHistoryPending?'正在读取已存事件…':captureHistoryMode?'历史记录 · 已存 '+(captureHistory?.eventCount??0)+' 条 · 本页 '+(captureHistory?.events.length??0)+' 条 · '+(captureHistory?.hasMore?'可查看更早记录':'已到最早记录'):'实时视图 · 最近最多 200 条；已存事件可按页查看。';
  captureNode('capture-filter-note').textContent=captureHistoryMode?'历史页按事件分页；拍摄窗口暂不可选，部分筛选仍可使用。':'拍摄窗口按日志先后划分，不代表逐帧关联证明；较早事件请查看已存记录。';
}
async function loadCaptureHistory(before=null,direction='latest'){
  if(!captureLastSession||captureHistoryPending)return;
  const session=captureLastSession,request=++captureHistoryRequest;
  captureHistoryMode=true;captureHistoryPending=true;captureHistoryError='';renderCaptureEvents();
  try{
    const path='/api/device/history?sessionId='+encodeURIComponent(session)+(before===null?'':'&before='+encodeURIComponent(before))+'&limit=200';
    const page=await api(path);
    if(request!==captureHistoryRequest||session!==captureLastSession)return;
    if(page.sessionId!==session||!Array.isArray(page.events))throw Error('返回的历史记录与当前会话不一致');
    if(direction==='older')captureHistoryStack.push(captureHistoryBefore);
    else if(direction==='newer')captureHistoryStack.pop();
    else captureHistoryStack=[];
    captureHistoryBefore=before;
    captureHistory={...page,events:page.events.slice(-200)};
  }catch(error){
    if(request!==captureHistoryRequest||session!==captureLastSession)return;
    captureHistoryError=error.message;toast('历史读取失败：'+error.message,true);
  }finally{
    if(request===captureHistoryRequest&&session===captureLastSession){captureHistoryPending=false;renderCaptureEvents();}
  }
}
function returnCaptureLive(){resetCaptureHistory();renderCaptureEvents();}
function renderCameraTimeline(bridge){
  if(!bridge)return;captureBridge=bridge;
  const {monitor,timeline}=captureData(bridge),reconnecting=monitor.state==='reconnecting',running=monitor.active===true||monitor.state==='running'||reconnecting||bridge.current?.operation==='monitor-start'&&bridge.current?.state==='running';
  const busy=bridge.workerActive===true||bridge.current?.state==='running'||running;
  captureNode('capture-start').disabled=captureActionPending||busy||bridge.closed===true;
  captureNode('capture-stop').disabled=captureActionPending||!running||monitor.stopRequested===true||monitor.state==='stopping';
  const status=monitor.stopRequested||monitor.state==='stopping'?'正在停止读取':reconnecting?'通道断开，正在重连':running?'正在读取机内新增日志':({failed:'读取失败',blocked:'通道尚未接通',stopped:'已停止读取',completed:'读取已结束','limit-reached':'已到本次读取上限',idle:'尚未开始读取','not-started':'尚未开始读取'})[monitor.state]||'尚未开始读取';
  captureNode('capture-status').textContent=status;
  captureNode('capture-reason').textContent=captureRequestError||monitor.error||(reconnecting?monitor.lastTransportError:null)||monitor.reason||(running?'在相机上拍照即可观察；不触发拍摄、不修改机身。':'先开启实时读取，再在相机上拍照。');
  const lastSuccess=Object.prototype.hasOwnProperty.call(monitor,'lastSuccessfulReadUtc')?monitor.lastSuccessfulReadUtc:timeline.lastReadUtc;
  captureNode('capture-sample-time').textContent=lastSuccess?'最后成功读取：'+fmtTime(lastSuccess)+' · '+captureFreshness(lastSuccess):'尚无本次成功读取；新鲜度尚未建立';
  const events=timeline.events||[],captures=timeline.captures||[],gaps=timeline.gaps||[];
  const stored=monitor.historyEventCount??timeline.historyEventCount;
  captureNode('capture-log-count').textContent=(timeline.samples||0)+' 次采样 / 会话累计 '+(timeline.eventCount??events.length)+' 条事件 / '+(Number.isFinite(stored)?'已存 '+stored+' 条':'已存数量未提供')+' / 最近保留 '+(timeline.retainedEventCount??events.length)+' 条 / '+(timeline.capturedCount??captures.length)+' 个拍摄请求';
  const backlog=Number.isFinite(monitor.backlogBytes)&&monitor.backlogBytes>=0?captureBytes(monitor.backlogBytes):'未知';
  captureNode('capture-budget').textContent='会话时长 '+captureDuration(monitor.elapsedSeconds??0)+' / '+captureDuration(monitor.maxSeconds)+' · 本地记录 '+captureBytes(monitor.retainedBytes??0)+' / '+captureBytes(monitor.maxEvidenceBytes)+' · 先到者停止；磁盘空间不足也会停止'+(monitor.sourceKind==='manual-live-fixed-byte-range'?' · 未读积压 '+backlog:'');
  const trend=({growing:'积压增长',draining:'积压减少',steady:'积压稳定'})[monitor.backlogTrend]||'积压趋势未提供';
  captureNode('capture-health').textContent=(monitor.readState==='resynchronizing'?'日志来源变化，正在重建读取起点 · ':'')+'累计读取 '+captureBytes(monitor.bytesRead)+' · 当前读取速度 '+captureBytes(monitor.readBytesPerSecond)+'/秒 · '+trend+' · 本轮重试 '+(monitor.reconnectAttempts??0)+' 次 · 累计重连 '+(monitor.totalReconnects??0)+' 次'+(monitor.lastSampleStable===false?' · 最近样本尚未稳定':'')+(monitor.lastTransportError?' · 最近通道错误：'+monitor.lastTransportError:'');
  const gapCount=timeline.gapCount??gaps.length;
  captureNode('capture-gap-count').textContent=gapCount?'有 '+gapCount+' 处观测缺口':timeline.samples?'本次尚未检测到日志缺口（不保证全部事件）':'观测连续性尚未建立';
  const session=monitor.sessionId||(bridge.current?.operation==='monitor-start'?bridge.current?.id:null)||null;
  if(session!==captureLastSession){captureLastSession=session;resetCaptureHistory();captureNode('capture-window').value='all';captureSignature='';captureNode('capture-events').replaceChildren();}
  renderCaptureHistoryControls();
  const signature=JSON.stringify({session,timeline,scope:monitor.scope});
  if(signature===captureSignature)return;captureSignature=signature;
  const previous=captureNode('capture-window').value||'all';
  const choices=[captureElement('option','本次监测所有事件')];choices[0].value='all';
  for(const capture of captures){const option=captureElement('option',(capture.label||'拍摄请求 '+capture.id+' · '+(capture.startDeviceTime||''))+(capture.windowStartRetained===false?'（起点已不在最近列表，展示不完整）':''));option.value=String(capture.id);choices.push(option);}
  captureNode('capture-window').replaceChildren(...choices);
  captureNode('capture-window').value=choices.some(o=>o.value===previous)?previous:'all';
  captureNode('capture-gaps').replaceChildren(...gaps.slice(-5).map(g=>captureElement('div',captureGapText(g),'capture-gap')));
  captureNode('capture-evidence-path').textContent=[monitor.evidencePath||'',timeline.bootId?'机身本次启动：'+timeline.bootId:'',monitor.scope||'','原始读取回包保存在本地证据文件；最近 200 条只是页面快速视图。',timeline.truncatedRawLines?'以下 '+timeline.truncatedRawLines+' 行是截断预览，完整采样见本地证据文件。':null,timeline.trailingFragment?'末行尚未写完，暂不计为事件。':null].filter(Boolean).join('\n');
  captureNode('capture-raw-text').textContent=(Array.isArray(timeline.recentRaw)?timeline.recentRaw.join('\n'):timeline.recentRaw)||timeline.rawText||'尚无本次日志原文。';
  renderCaptureEvents();
}
function renderCaptureEvents(){
  const {timeline}=captureData(captureBridge),events=captureHistoryMode?(captureHistory?.events||[]):captureWindowEvents(timeline),component=captureNode('capture-component').value||'all';
  const selectedWindow=!captureHistoryMode&&captureNode('capture-window').value!=='all',cumulative=!captureHistoryMode&&!selectedWindow&&timeline.sectionCountScope==='session';
  const incompleteWindow=selectedWindow&&(timeline.captures||[]).find(c=>String(c.id)===captureNode('capture-window').value)?.windowStartRetained===false;
  renderCaptureHistoryControls();
  const opened=new Set(Array.from(captureNode('capture-events').children).filter(row=>row.captureDetails?.open).map(row=>row.dataset.eventId));
  captureNode('capture-sections').replaceChildren(...captureParts.map(([id,title])=>{
    const list=events.filter(e=>e.section===id),section=cumulative?(timeline.sections||[]).find(s=>s.id===id):null;
    const count=cumulative?(section?.count??0):list.length,last=cumulative?section?.lastEvent:list.at(-1),card=captureElement('button',undefined,'capture-section'+(component===id?' selected':''));
    const summary=(captureHistoryMode?'本页 '+count+' 条事件':selectedWindow?'当前窗口 '+count+' 条事件':cumulative?'会话累计 '+count+' 条事件':count?'最近列表 '+count+' 条事件':'未观测')+(incompleteWindow?'（展示不完整）':'');
    card.dataset.section=id;card.append(captureElement('strong',title),captureElement('span',summary,'capture-part-count'),captureElement('small',last?.label||(captureHistoryMode?'本页没有这一部分的事件':selectedWindow?'当前窗口没有保留这一部分的事件':'日志未提供这一部分的变化')));
    card.addEventListener('click',()=>{captureNode('capture-component').value=id;renderCaptureEvents();});return card;
  }));
  const shown=(component==='all'?events:events.filter(e=>e.section===component)).slice(-200);
  captureNode('capture-event-total').textContent=(captureHistoryMode?(captureHistory?'本页筛选后显示 '+shown.length+' 条 · 会话已存 '+captureHistory.eventCount+' 条':captureHistoryPending?'正在读取历史记录…':'历史记录未载入'):selectedWindow?'当前窗口显示 '+shown.length+' 条':'会话累计 '+(timeline.eventCount??timeline.events?.length??0)+' 条事件 · 当前显示 '+shown.length+' 条')+(incompleteWindow?' · 窗口起点已不在最近列表，展示不完整':'')+' · 发生时刻来自机身日志';
  if(!shown.length){captureNode('capture-events').replaceChildren(captureElement('p',captureHistoryMode?(captureHistoryPending?'正在载入历史记录。':captureHistoryError?'本页未载入记录；可重试或返回实时视图。':'本页当前筛选没有事件；不能据此判定此部分没有运行。'):'当前范围未观测到事件；不能据此判定此部分没有运行。','fine'));return;}
  captureNode('capture-events').replaceChildren(...shown.slice().reverse().map(event=>{
    const row=captureElement('article',undefined,'capture-event'+(event.phase==='error'||event.phase==='warning'?' warning':''));row.dataset.eventId=String(event.id);
    const head=captureElement('div',undefined,'capture-event-heading');head.append(captureElement('time',event.deviceTime||'日志无时刻'),captureElement('span',captureParts.find(p=>p[0]===event.section)?.[1]||event.section,'badge subtle'),captureElement('strong',event.label||'机内日志事件'));
    const refs=[event.bootId?'启动 '+event.bootId:null,event.logWindowId!==undefined?'日志窗口 '+event.logWindowId:null,event.frameId!==null&&event.frameId!==undefined?'帧号 '+event.frameId:null,event.requestId!==null&&event.requestId!==undefined?'请求号 '+event.requestId:null,event.correlation==='explicit-id'?'带显式标识；仍需按命名空间关联':'未能逐帧关联',event.receivedUtc?'接收 '+fmtTime(event.receivedUtc):null].filter(Boolean);
    row.append(head,captureElement('small',refs.join(' · '),'capture-event-meta'));
    const detail=captureElement('details');detail.open=opened.has(String(event.id));row.captureDetails=detail;
    const ranges=(event.evidenceRanges||[]).map(range=>range.evidencePath+' · 起点 '+range.offset+' · '+captureBytes(range.bytes));
    detail.append(captureElement('summary',event.rawTruncated?'日志原文预览（已截断）与完整证据':'原始日志与证据'),captureElement('pre',event.raw||'原文不可用','capture-event-raw'),captureElement('small',[event.evidencePath||'证据位置未返回',...ranges].join('\n'),'source-path'));row.append(detail);return row;
  }));
}
async function captureAction(operation){
  if(captureActionPending)return;captureActionPending=true;if(captureBridge)renderCameraTimeline(captureBridge);
  try{const value=await api('/api/device/action',{operation});captureRequestError='';renderCameraTimeline(value);if(typeof renderSystemStatus==='function')renderSystemStatus(value);}
  catch(error){toast(error.message,true);captureRequestError='本次请求失败：'+error.message;}
  finally{captureActionPending=false;if(captureBridge)renderCameraTimeline(captureBridge);}
}
captureNode('capture-start').addEventListener('click',()=>captureAction('monitor-start'));
captureNode('capture-stop').addEventListener('click',()=>captureAction('monitor-stop'));
captureNode('capture-history-start').addEventListener('click',()=>loadCaptureHistory());
captureNode('capture-history-older').addEventListener('click',()=>captureHistory?.hasMore&&loadCaptureHistory(captureHistory.nextBefore,'older'));
captureNode('capture-history-newer').addEventListener('click',()=>captureHistoryStack.length&&loadCaptureHistory(captureHistoryStack.at(-1),'newer'));
captureNode('capture-history-live').addEventListener('click',returnCaptureLive);
captureNode('capture-window').addEventListener('change',renderCaptureEvents);
captureNode('capture-component').addEventListener('change',renderCaptureEvents);
renderCaptureEvents();
