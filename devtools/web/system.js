'use strict';
let systemCatalog=null,systemSection='ui',systemFile=null,systemEditing=false,systemDirty=false,systemSaving=false,systemRequest=0,systemCatalogLoading=false,systemView='current',deviceOutputSignature='',lastDeviceBridge=null,deviceActionPending=false;
const systemNode=id=>document.getElementById(id);
function systemElement(tag,text,cls){const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n;}
function systemSourceLabel(value){const scope=typeof value==='object'?value?.scope:value;return {'active-extension':'本地扩展代码','historical-analysis':'历史反编译分析','frozen-stock-extraction':'原厂只读提取'}[scope]||scope||'来源未说明';}
function clearSystemSelection(){++systemRequest;systemFile=null;systemView='current';renderSystemFile();if(lastDeviceBridge)renderSystemStatus(lastDeviceBridge);}
function canLeaveSystemFile(){if(systemCatalogLoading){toast('正在刷新文件目录，请等待完成。',true);return false;}if(systemSaving){toast('正在保存，请等待完成。',true);return false;}if(!systemEditing)return true;toast('请先保存或取消当前编辑，避免丢失修改。',true);return false;}
async function loadSystemCatalog(force=false){
  if(systemCatalog&&!force)return;
  if(systemCatalogLoading||!canLeaveSystemFile())return;
  systemCatalogLoading=true;++systemRequest;systemNode('refresh-system').disabled=true;renderSystemFile();
  try{const catalog=await api('/api/system/catalog');systemCatalog=catalog;systemCatalogLoading=false;renderSystemCatalog();const section=systemCatalog.sections.find(s=>s.id===systemSection);const selected=section?.files.find(f=>f.available&&f.id===systemFile?.id)||section?.files.find(f=>f.available);if(selected)await selectSystemFile(selected.id);else clearSystemSelection();}
  catch(e){systemNode('system-code-view').textContent=e.message;toast(e.message,true);}
  finally{systemCatalogLoading=false;systemNode('refresh-system').disabled=false;renderSystemFile();}
}
function renderSystemCatalog(){
  if(!systemCatalog)return;
  systemNode('system-sections').replaceChildren(...systemCatalog.sections.map(s=>{
    const button=systemElement('button',undefined,'system-section'+(s.id===systemSection?' selected':''));
    button.dataset.section=s.id;button.append(systemElement('strong',s.title),systemElement('small',s.files.filter(f=>f.available).length+' 份可读取文件'));
    button.addEventListener('click',()=>{if(!canLeaveSystemFile())return;systemSection=s.id;systemNode('system-file-filter').value='';clearSystemSelection();renderSystemCatalog();const first=s.files.find(f=>f.available);if(first)selectSystemFile(first.id);});return button;
  }));
  const section=systemCatalog.sections.find(s=>s.id===systemSection);
  systemNode('system-section-title').textContent=section?.title||'系统文件';systemNode('system-section-description').textContent=section?.description||'';
  const filter=systemNode('system-file-filter').value.trim().toLowerCase();
  systemNode('system-file-list').replaceChildren(...(section?.files||[]).filter(f=>(f.name+' '+f.id).toLowerCase().includes(filter)).map(f=>{
    const b=systemElement('button',undefined,'system-file'+(systemFile?.id===f.id?' selected':''));b.dataset.file=f.id;b.disabled=!f.available;
    b.append(systemElement('strong',f.name),systemElement('small',f.available?(systemSourceLabel(f.sourceTag)+' · '+(f.editable?'可编辑本地副本':'只读分析 / 文件信息')):(f.reason||'文件不可用')));
    b.addEventListener('click',()=>selectSystemFile(f.id));return b;
  }));
}
async function selectSystemFile(id){
  if(!canLeaveSystemFile())return;
  const request=++systemRequest;systemFile=null;renderSystemFile();systemNode('system-code-view').textContent='正在读取…';
  try{const file=await api('/api/system/file?id='+encodeURIComponent(id));if(request!==systemRequest)return;systemFile=file;systemView='current';systemEditing=false;systemDirty=false;renderSystemFile();renderSystemCatalog();}
  catch(e){if(request===systemRequest){systemFile=null;renderSystemFile();systemNode('system-code-view').textContent=e.message;toast(e.message,true);}}
}
function renderSystemFile(){
  const f=systemFile,editable=!!f?.editable;
  systemNode('system-file-title').textContent=f?.name||'选择一个文件';
  systemNode('system-file-meta').textContent=f?[systemSourceLabel(f.provenance),'SHA '+(f.baseSha256||f.sha256||'').slice(0,16),'副本版本 '+(f.revision||0)].join(' · '):'';
  systemNode('system-source-path').textContent=f?[f.path||f.sourcePath||'',f.devicePath?'机内对应：'+f.devicePath:''].filter(Boolean).join('\n'):'';
  systemNode('system-edit-state').textContent=systemEditing?(systemDirty?'有未保存修改':'编辑本地副本'):(f?.draft?'已保存本地修改':editable?'原始文件 · 可编辑副本':'只读');
  ['system-original','system-current','system-diff'].forEach(id=>systemNode(id).disabled=!f||systemEditing);
  systemNode('system-edit').disabled=systemCatalogLoading||!editable||systemEditing;
  systemNode('system-save').disabled=systemSaving||!systemEditing||!systemDirty;
  systemNode('system-cancel').disabled=systemSaving||!systemEditing;
  systemNode('system-reset').disabled=systemSaving||!f?.draft||systemEditing;
  systemNode('system-code-edit').readOnly=systemSaving;
  systemNode('system-code-view').classList.toggle('hidden',systemEditing);systemNode('system-code-edit').classList.toggle('hidden',!systemEditing);
  systemNode('system-editor-notice').textContent=f?.reason||'保存为本地修改副本，不覆盖原厂输入，不自动部署到机身。恢复本地原文不是机身回退。';
  if(!systemEditing){const text=systemView==='original'?(f?.originalText??f?.text):systemView==='diff'?(f?.diff||'没有已保存的差异。'):f?.text;renderCodeText(text||'暂无文件内容。',systemView==='diff');}
}
function renderCodeText(text,diff=false){
  const lines=text.split('\n');systemNode('system-code-view').replaceChildren(...lines.map((line,index)=>{
    const row=systemElement('span',undefined,'code-line'+(diff&&line.startsWith('+')&&!line.startsWith('+++')?' added':diff&&line.startsWith('-')&&!line.startsWith('---')?' removed':''));
    row.append(systemElement('span',String(index+1),'line-number'),systemElement('span',line||' ','line-content'));return row;
  }));
}
function setSystemView(view){if(!systemFile||systemEditing)return;systemView=view;renderSystemFile();}
async function saveSystemDraft(reset=false){
  if(!systemFile||systemSaving)return;const file=systemFile;systemSaving=true;renderSystemFile();
  try{const value=await api(reset?'/api/system/reset':'/api/system/save',{id:file.id,baseSha256:file.baseSha256,revision:file.revision,text:reset?undefined:systemNode('system-code-edit').value});
    if(systemFile?.id===file.id){systemFile=value;systemEditing=false;systemDirty=false;systemView='current';renderSystemFile();renderSystemCatalog();}
    toast(reset?'已恢复本地原文；机身没有改变。':'修改副本已保存；尚未部署到机身。');
  }catch(e){toast(e.message,true);}
  finally{systemSaving=false;renderSystemFile();}
}
function renderSystemStatus(bridge){
  if(!bridge)return;lastDeviceBridge=bridge;
  const busy=deviceActionPending||bridge.current?.state==='running'||bridge.current?.state==='queued';
  const connected=bridge.connected===true;
  systemNode('device-bridge-state').textContent=busy?(bridge.current?.operation==='monitor-start'?'实时日志读取中':'机内操作进行中'):connected?'机内通道已验证':({'not_connected':'尚未连接','not-connected':'尚未连接',failed:'接入失败',disconnected:'连接已断开',closing:'正在安全关闭',closed:'已关闭'})[bridge.state]||bridge.state||'尚未连接';
  systemNode('device-bridge-reason').textContent=bridge.reason||'';
  systemNode('overview-body-status').textContent=busy?'机内操作进行中':connected?'机内读取已接通':'机内通道尚未连接';
  systemNode('overview-body-detail').textContent=bridge.reason||'只读身份已验证；部署、加载与恢复仍按各自条件显示。';
  systemNode('body-connection').dataset.state=connected&&!busy?'connected':'unknown';
  systemNode('device-connect').disabled=busy;systemNode('device-read').disabled=busy||!connected;systemNode('device-qualification').disabled=busy;
  const labels={read:'机内读取',deploy:'部署已审查候选',load:'激活开机加载配置',restore:'恢复原厂加载'};
  const capabilities=bridge.capabilities||{};
  systemNode('device-capabilities').replaceChildren(...Object.entries(labels).map(([key,label])=>{
    const cap=capabilities[key],enabled=typeof cap==='object'?cap.enabled===true:cap===true;
    if(key!=='read')systemNode('device-'+key).disabled=busy||!enabled;
    const item=systemElement('div',undefined,'device-capability'+(enabled?' enabled':''));item.append(systemElement('strong',label+(enabled?' · 可用':' · 未就绪')),systemElement('small',typeof cap==='object'?(cap.reason||''):''));return item;
  }));
  const selectedRead=bridge.lastRead?.[systemSection];
  const reading=selectedRead||bridge.lastRead?.[bridge.latestReadComponent]||(bridge.lastRead?.text?bridge.lastRead:null);
  const signature=JSON.stringify({section:systemSection,current:bridge.current,reading});
  if(signature!==deviceOutputSignature){deviceOutputSignature=signature;const records=reading?.queries||reading?.results||[];
    const list=Array.isArray(records)?records:Object.values(records);
    const identity=reading?.identity;
    const heading=identity?(selectedRead?'当前部分机内快照':'其他部分上次快照')+' · '+(reading.component||'')+' · '+fmtTime(reading.timestampUtc)+'\n'+[identity.model,identity.firmware,identity.bootId?'boot '+identity.bootId:null,identity.uid!==undefined?'UID '+identity.uid:null,identity.domain].filter(v=>v!==null&&v!==undefined&&v!=='').join(' · ')+'\n'+(reading.scope||'')+'\n\n':'';
    const failure=bridge.current?.state==='failed'?'本次操作失败：'+(bridge.current.error||'未知原因')+'\n\n':'';
    systemNode('device-read-output').textContent=failure+heading+(reading?.text|| (list.length?list.map(r=>(r.name||r.query||'机内读取')+'\n'+(r.text||r.textPreview||r.error||'')).join('\n\n'):(bridge.current?.error||bridge.current?.message||'尚无本次机内读取。')));
  }
}
async function systemDeviceAction(operation){
  if(deviceActionPending)return;deviceActionPending=true;if(lastDeviceBridge)renderSystemStatus(lastDeviceBridge);
  try{const body={operation};if(operation==='read')body.component=systemSection;lastDeviceBridge=await api('/api/device/action',body);}
  catch(e){toast(e.message,true);}
  finally{deviceActionPending=false;if(lastDeviceBridge)renderSystemStatus(lastDeviceBridge);}
}
systemNode('refresh-system').addEventListener('click',()=>loadSystemCatalog(true));
systemNode('system-file-filter').addEventListener('input',renderSystemCatalog);
systemNode('system-original').addEventListener('click',()=>setSystemView('original'));
systemNode('system-current').addEventListener('click',()=>setSystemView('current'));
systemNode('system-diff').addEventListener('click',()=>setSystemView('diff'));
systemNode('system-edit').addEventListener('click',()=>{if(systemCatalogLoading||!systemFile?.editable)return;systemEditing=true;systemDirty=false;systemNode('system-code-edit').value=systemFile.text;renderSystemFile();systemNode('system-code-edit').focus();});
systemNode('system-code-edit').addEventListener('input',()=>{systemDirty=systemNode('system-code-edit').value!==systemFile?.text;renderSystemFile();});
systemNode('system-cancel').addEventListener('click',()=>{systemEditing=false;systemDirty=false;renderSystemFile();});
systemNode('system-save').addEventListener('click',()=>saveSystemDraft());systemNode('system-reset').addEventListener('click',()=>saveSystemDraft(true));
for(const operation of ['connect','read','qualification','deploy','load','restore'])systemNode('device-'+operation).addEventListener('click',()=>systemDeviceAction(operation));
if(typeof window!=='undefined')window.addEventListener('beforeunload',event=>{if(systemDirty||systemSaving){event.preventDefault();event.returnValue='';}});
