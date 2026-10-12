"""Execute the actual workbench system UI; not camera integration evidence."""
from pathlib import Path
import subprocess
import unittest


class SystemWebTests(unittest.TestCase):
    def test_actual_editor_navigation_save_conflict_and_device_status(self):
        script = r"""
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const nodes=new Map();
function makeNode(){return {children:[],_text:'',value:'',dataset:{},disabled:false,readOnly:false,handlers:{},
  classList:{toggle(){}},focus(){},append(...items){this.children.push(...items);},
  replaceChildren(...items){this._text='';this.children=items;},
  addEventListener(event,handler){this.handlers[event]=handler;},
  set textContent(value){this._text=String(value);this.children=[];},
  get textContent(){return this._text+this.children.map(n=>n.textContent).join('');}};}
function node(id){if(!nodes.has(id))nodes.set(id,makeNode());return nodes.get(id);}
const sections=['ui','control','hardware','imaging','storage','platform','maintenance'];
const catalog={sections:sections.map(id=>({id,title:id,description:id+' code',files:[{id:id+'-source',name:id+'.rc',available:true,editable:true,sourceTag:'stock'}]}))};
const base={id:'ui-source',name:'ui.rc',section:'ui',text:'original\n',originalText:'original\n',
  baseSha256:'a'.repeat(64),sha256:'a'.repeat(64),revision:0,editable:true,provenance:{scope:'frozen-stock-extraction'},draft:false};
let current={...base},saveMode='conflict',releaseSave,requests=[],messages=[];
let replyCatalog=catalog,deferCatalog=false,releaseCatalog,deferReadId=null,releaseRead;
const windowHandlers={};
const context={document:{getElementById:node,createElement:makeNode},fmtTime:t=>t,toast:(text)=>messages.push(text),
  window:{addEventListener:(name,handler)=>windowHandlers[name]=handler},
  api:async(path,body)=>{
    body=body===undefined?undefined:JSON.parse(JSON.stringify(body));requests.push({path,body});
    if(path==='/api/system/catalog'){if(deferCatalog)await new Promise(resolve=>releaseCatalog=resolve);return replyCatalog;}
    if(path.startsWith('/api/system/file?id=')){const id=decodeURIComponent(path.split('=')[1]);if(id===deferReadId)await new Promise(resolve=>releaseRead=resolve);return {...current,id};}
    if(path==='/api/system/save'){
      await new Promise(resolve=>releaseSave=resolve);
      if(saveMode==='conflict')throw Error('source revision changed');
      current={...current,text:body.text,revision:1,draft:true,diff:'-original\n+changed\n'};return current;
    }
    if(path==='/api/system/reset'){assert.equal(Object.hasOwn(body,'text'),false);current={...base,revision:2};return current;}
    if(path==='/api/device/action')return {state:'not_connected',connected:false,current:{state:'running'},capabilities:{}};
    throw Error('Unexpected route '+path);
  }};
vm.createContext(context);vm.runInContext(fs.readFileSync(process.argv[1],'utf8'),context);
(async()=>{
  await context.loadSystemCatalog();
  assert.equal(node('system-sections').children.length,7);
  assert.equal(node('system-code-view').textContent,'1original2 ');
  assert.equal(node('system-edit').disabled,false);
  assert.match(node('system-file-meta').textContent,/原厂只读提取/);
  assert.doesNotMatch(node('system-file-meta').textContent,/\[object Object\]/);
  node('system-edit').handlers.click();node('system-code-edit').value='changed\n';node('system-code-edit').handlers.input();
  assert.equal(node('system-save').disabled,false);
  let warned=false;windowHandlers.beforeunload({preventDefault(){warned=true;}});assert.equal(warned,true);
  await context.selectSystemFile('storage-source');
  assert.equal(vm.runInContext('systemFile.id',context),'ui-source');
  assert.match(messages.at(-1),/保存或取消/);
  const failed=context.saveSystemDraft();
  assert.equal(node('system-cancel').disabled,true);assert.equal(node('system-code-edit').readOnly,true);
  await context.selectSystemFile('control-source');assert.match(messages.at(-1),/正在保存/);
  releaseSave();await failed;
  assert.equal(node('system-code-edit').value,'changed\n');assert.equal(node('system-save').disabled,false);
  assert.equal(node('system-code-edit').readOnly,false);assert.equal(vm.runInContext('systemEditing',context),true);
  saveMode='success';const saved=context.saveSystemDraft();releaseSave();await saved;
  assert.equal(vm.runInContext('systemFile.revision',context),1);
  assert.equal(vm.runInContext('systemEditing',context),false);
  node('system-original').handlers.click();assert.match(node('system-code-view').textContent,/original/);
  node('system-diff').handlers.click();assert.match(node('system-code-view').textContent,/\+changed/);
  const post=requests.find(r=>r.path==='/api/system/save');assert.equal(post.body.baseSha256,base.baseSha256);
  assert.equal(post.body.revision,0);assert.equal(post.body.text,'changed\n');
  await context.saveSystemDraft(true);assert.equal(vm.runInContext('systemFile.draft',context),false);
  const bridge={state:'connected',connected:true,reason:'fixed read only',capabilities:{
    read:{enabled:true},deploy:{enabled:false,reason:'current candidate not qualified'},
    load:{enabled:false},restore:{enabled:false}},
    latestReadComponent:'ui',lastRead:{ui:{component:'ui',timestampUtc:'fresh',identity:{model:'HB722',uid:0,bootId:'boot'},text:'ACTUAL_READ_TEXT'}}};
  context.renderSystemStatus(bridge);
  assert.equal(node('device-deploy').disabled,true);assert.equal(node('device-load').disabled,true);
  assert.equal(node('device-restore').disabled,true);assert.equal(node('device-read').disabled,false);
  assert.match(node('device-read-output').textContent,/ACTUAL_READ_TEXT/);
  assert.match(node('device-read-output').textContent,/HB722/);
  assert.match(node('device-read-output').textContent,/UID 0/);
  context.renderSystemStatus({...bridge,connected:false,state:'failed',current:{state:'failed',error:'disconnected'}});
  assert.equal(node('device-read').disabled,true);assert.match(node('device-read-output').textContent,/本次操作失败/);
  context.renderSystemStatus({state:'not-connected',connected:false,capabilities:{}});
  assert.equal(node('device-bridge-state').textContent,'尚未连接');
  catalog.sections.find(s=>s.id==='hardware').files=[];
  deferReadId='control-source';const late=context.selectSystemFile('control-source');
  node('system-sections').children[2].handlers.click();
  assert.equal(vm.runInContext('systemFile',context),null);
  releaseRead();await late;
  assert.equal(vm.runInContext('systemSection',context),'hardware');
  assert.equal(vm.runInContext('systemFile',context),null);
  vm.runInContext("systemSection='ui'",context);
  deferReadId='ui-source';const refreshLate=context.selectSystemFile('ui-source');
  replyCatalog={sections:catalog.sections.map(s=>({...s,files:s.id==='ui'?[]:s.files}))};
  await context.loadSystemCatalog(true);releaseRead();await refreshLate;
  assert.equal(vm.runInContext('systemFile',context),null);
  replyCatalog=catalog;deferReadId=null;await context.loadSystemCatalog(true);
  deferCatalog=true;const catalogPending=context.loadSystemCatalog(true);
  assert.equal(node('system-edit').disabled,true);
  node('system-edit').handlers.click();assert.equal(vm.runInContext('systemEditing',context),false);
  await context.selectSystemFile('control-source');assert.match(messages.at(-1),/刷新文件目录/);
  releaseCatalog();await catalogPending;deferCatalog=false;
  assert.equal(vm.runInContext('systemFile.id',context),'ui-source');
})().catch(error=>{console.error(error);process.exitCode=1;});
"""
        result = subprocess.run(["node", "-e", script, str(Path(__file__).parent / "web/system.js")],
                                capture_output=True, text=True, encoding="utf-8", timeout=10)
        self.assertEqual(0, result.returncode, result.stderr)


if __name__ == "__main__":
    unittest.main()
