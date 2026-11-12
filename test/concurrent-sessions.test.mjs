import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { SnapshotStore } from '../src/snapshot-store.mjs';
import { handleHostHookEvent } from '../src/hook-firewall.mjs';
import { probeOsIsolationBackend } from '../src/runtime-support.mjs';

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(),'bg-session-'));
  const workspace = path.join(root,'workspace');
  fs.mkdirSync(workspace);
  const ws = fs.realpathSync.native(workspace);
  const state = path.join(root,'state');
  for (const file of ['app.js','other.js']) fs.writeFileSync(path.join(ws,file),'export function price() { return 1; }\n');
  return {ws,state,close:()=>fs.rmSync(root,{recursive:true,force:true})};
}
const source = (value) => `export function price() { return ${value}; }\n`;

test('Structured edits reject a stale session on the touched path and accept refreshed turns', async () => {
  const f = fixture();
  const invoke = (session,event,extra={}) => handleHostHookEvent({host:'claude',event,rawStdin:JSON.stringify({cwd:f.ws,session_id:session,prompt:'Fix app.js and other.js',...extra}),storeDir:f.state,_testHostVersionOverride:'2.1.300'});
  const edit = (file,oldValue,newValue,id) => ({tool_name:'Edit',tool_use_id:id,tool_input:{file_path:file,old_string:`return ${oldValue};`,new_string:`return ${newValue};`}});
  const apply = async (session,file,oldValue,newValue,id) => {
    const payload=edit(file,oldValue,newValue,id);
    const pre=await invoke(session,'PreToolUse',payload);
    assert.equal(pre.stdoutObj,null,JSON.stringify(pre));
    fs.writeFileSync(path.join(f.ws,file),source(newValue));
    const post=await invoke(session,'PostToolUse',payload);
    assert.equal(post.stdoutObj,null,JSON.stringify(post));
  };
  try {
    await invoke('s1','UserPromptSubmit');
    await invoke('s2','UserPromptSubmit');
    await apply('s1','app.js',1,2,'s1-first');
    const stale=await invoke('s2','PreToolUse',edit('app.js',2,3,'s2-stale'));
    assert.match(stale.stdoutObj.hookSpecificOutput.permissionDecisionReason,/SESSION_WRITE_CONFLICT/);
    assert.equal(fs.readFileSync(path.join(f.ws,'app.js'),'utf8'),source(2));
    await apply('s2','other.js',1,2,'s2-other');
    const stillStale=await invoke('s2','PreToolUse',edit('app.js',2,3,'s2-still-stale'));
    assert.match(stillStale.stdoutObj.hookSpecificOutput.permissionDecisionReason,/SESSION_WRITE_CONFLICT/);
    await invoke('s2','UserPromptSubmit');
    await apply('s2','app.js',2,3,'s2-refreshed');
    await apply('s2','app.js',3,4,'s2-next');
  } finally { f.close(); }
});

test('Shell stale writes roll back to command entry without losing another session output', async () => {
  const f=fixture();
  let store=new SnapshotStore(f.ws,{storeDir:f.state});
  try {
    await store.open();
    store.startOrUpdateTurn('Fix app.js and other.js',{sessionId:'s1'});
    store.startOrUpdateTurn('Fix app.js and other.js',{sessionId:'s2'});
    const first=store.beginCommandTransaction({sessionId:'s1'});
    fs.writeFileSync(path.join(f.ws,'app.js'),source(2));
    assert.equal(store.reconcileCommandTransaction(first.txId).ok,true);
    store.close();
    store = new SnapshotStore(f.ws,{storeDir:f.state});
    await store.open();
    for (let attempt=0;attempt<2;attempt++) {
      const stale=store.beginCommandTransaction({sessionId:'s2'});
      fs.writeFileSync(path.join(f.ws,'app.js'),source(3));
      const denied=store.reconcileCommandTransaction(stale.txId);
      assert.equal(denied.rolledBack,true);
      assert.ok(denied.violations.some((v)=>v.code==='SESSION_WRITE_CONFLICT'));
      assert.equal(fs.readFileSync(path.join(f.ws,'app.js'),'utf8'),source(2));
    }
    const unrelated=store.beginCommandTransaction({sessionId:'s2'});
    fs.writeFileSync(path.join(f.ws,'other.js'),source(2));
    assert.equal(store.reconcileCommandTransaction(unrelated.txId).ok,true);
    store.startOrUpdateTurn('Fix app.js',{sessionId:'s2',resetTask:true});
    const refreshed=store.beginCommandTransaction({sessionId:'s2'});
    fs.writeFileSync(path.join(f.ws,'app.js'),source(3));
    assert.equal(store.reconcileCommandTransaction(refreshed.txId).ok,true);
  } finally {store.close();f.close();}
});

test('Legacy sessions use their turn checkpoint and require refresh only for drifted paths',async()=>{
  const f=fixture();const store=new SnapshotStore(f.ws,{storeDir:f.state});
  try{
    await store.open();store.startOrUpdateTurn('Fix app.js and other.js',{sessionId:'legacy'});
    fs.writeFileSync(path.join(f.ws,'app.js'),source(9));
    assert.equal(store.findSessionWriteConflicts('legacy',store.scanWorkspaceNamespace({storeBlobs:false}).entries,['other.js']).length,0);
    assert.equal(store.findSessionWriteConflicts('legacy',store.scanWorkspaceNamespace({storeBlobs:false}).entries,['app.js'])[0].code,'SESSION_WRITE_CONFLICT');
    store.startOrUpdateTurn('Fix app.js',{sessionId:'legacy'});
    assert.equal(store.findSessionWriteConflicts('legacy',store.scanWorkspaceNamespace({storeBlobs:false}).entries,['app.js']).length,0);
  }finally{store.close();f.close();}
});

test('Isolated results cannot promote stale-session writes and successful promotion advances only touched files',async(t)=>{
  if(!probeOsIsolationBackend().available){t.skip('OS isolation unavailable');return;}
  const f=fixture();const store=new SnapshotStore(f.ws,{storeDir:f.state});
  try{
    await store.open();store.startOrUpdateTurn('Fix app.js and other.js',{sessionId:'s1'});store.startOrUpdateTurn('Fix app.js and other.js',{sessionId:'s2'});
    const first=store.beginCommandTransaction({sessionId:'s1'});fs.writeFileSync(path.join(f.ws,'app.js'),source(2));assert.equal(store.reconcileCommandTransaction(first.txId).ok,true);
    const stale=await store.runIsolatedCommand([process.execPath,'-e',`require('fs').writeFileSync('app.js',${JSON.stringify(source(3))})`],{sessionId:'s2',promoteMode:'staged'});
    assert.equal(stale.code,'SESSION_WRITE_CONFLICT');assert.equal(fs.readFileSync(path.join(f.ws,'app.js'),'utf8'),source(2));
    const fresh=await store.runIsolatedCommand([process.execPath,'-e',`require('fs').writeFileSync('other.js',${JSON.stringify(source(2))})`],{sessionId:'s2',promoteMode:'staged'});
    assert.equal(fresh.ok,true,JSON.stringify(fresh));
    const promoted=store.promoteStagedBundle(fresh.txId,{assumeSingleWriter:true});
    assert.equal(promoted.ok,true,JSON.stringify(promoted));
    const again=store.beginCommandTransaction({sessionId:'s2',writePaths:['other.js']});fs.writeFileSync(path.join(f.ws,'other.js'),source(3));assert.equal(store.reconcileCommandTransaction(again.txId).ok,true);
    assert.throws(()=>store.beginCommandTransaction({sessionId:'s2',writePaths:['app.js']}),/changed outside session/);
  }finally{store.close();f.close();}
});
