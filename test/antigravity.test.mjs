import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { handleHostHookEvent } from '../src/hook-firewall.mjs';
import { installOrUninstallHooks, validateEffectiveHostConfig, MANAGED_MARKER } from '../src/init-installer.mjs';

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bg-antigravity-'));
  let workspace = path.join(root, "项目 with ' quote");
  fs.mkdirSync(workspace);
  workspace = fs.realpathSync.native(workspace);
  const state = path.join(root, 'state');
  const payload = { conversationId: 'anti-test', workspacePaths: [workspace], lastUserInput: 'Fix app.js' };
  return { root, workspace, state, payload,
    invoke: (event, extra = {}) => handleHostHookEvent({host:'antigravity', event, rawStdin: JSON.stringify({...payload,...extra}), storeDir:state, _testHostVersionOverride:'2.31.2'}),
    close: () => fs.rmSync(root, {recursive:true,force:true}) };
}

test('Antigravity native installer preserves foreign groups and supports uninstall', () => {
  const f = fixture();
  try {
    fs.mkdirSync(path.join(f.workspace,'.agents'));
    const file = path.join(f.workspace,'.agents/hooks.json');
    fs.writeFileSync(file, JSON.stringify({foreign:{enabled:true,Stop:[]}}));
    installOrUninstallHooks(f.workspace,{host:'antigravity',dryRun:true});
    assert.equal(JSON.parse(fs.readFileSync(file)).foreign.enabled,true);
    assert.equal(JSON.parse(fs.readFileSync(file))[MANAGED_MARKER],undefined);
    installOrUninstallHooks(f.workspace,{host:'antigravity'});
    assert.equal(validateEffectiveHostConfig(f.workspace,'antigravity').state,'VALID');
    const installed = JSON.parse(fs.readFileSync(file));
    assert.equal(installed.foreign.enabled,true);
    assert.equal(installed[MANAGED_MARKER].PreToolUse[0].matcher,'*');
    installOrUninstallHooks(f.workspace,{host:'antigravity',uninstall:true});
    assert.deepEqual(JSON.parse(fs.readFileSync(file)),{foreign:{enabled:true,Stop:[]}});
  } finally { f.close(); }
});

test('Antigravity range edits allow a normal body fix and deny sibling export deletion', async () => {
  const f = fixture();
  try {
    const original = 'export function price() { return 1; }\nexport function sibling() { return 1; }\n';
    fs.writeFileSync(path.join(f.workspace,'app.js'),original);
    assert.equal((await f.invoke('PreInvocation')).exitCode,0);
    const call = {name:'replace_file_content',args:{TargetFile:path.join(f.workspace,'app.js'),StartLine:1,EndLine:1,TargetContent:'return 1;',ReplacementContent:'return 2;'}};
    const allowed = await f.invoke('PreToolUse',{stepIdx:1,toolCall:call});
    assert.equal(allowed.stdoutObj.decision,'allow',JSON.stringify(allowed));
    fs.writeFileSync(path.join(f.workspace,'app.js'),original.replace('return 1;','return 2;'));
    assert.deepEqual((await f.invoke('PostToolUse',{stepIdx:1,toolCall:call})).stdoutObj,{});
    const denied = await f.invoke('PreToolUse',{stepIdx:2,toolCall:{name:'write_to_file',args:{TargetFile:'app.js',Overwrite:true,CodeContent:'export function price() { return 2; }\n'}}});
    assert.equal(denied.stdoutObj.decision,'deny');
    assert.match(denied.stdoutObj.reason,/PUBLIC_EXPORT_MUTATED/);
  } finally { f.close(); }
});

test('Antigravity shell overwrite waits for wrapper recovery and preserves quoted Cwd', async () => {
  const f = fixture();
  const previous = process.env.BLAST_GUARD_STATE_DIR;
  process.env.BLAST_GUARD_STATE_DIR = f.state;
  try {
    const original = 'export function price() { return 1; }\nexport function sibling() { return 10; }\n';
    fs.writeFileSync(path.join(f.workspace,'app.js'),original);
    await f.invoke('PreInvocation');
    const toolCall = {name:'run_command',args:{Cwd:f.workspace,CommandLine:'node -e "require(\'fs\').writeFileSync(\'app.js\',\'export function price() { return 2; }\\n\')"',WaitMsBeforeAsync:5000}};
    const pre = await f.invoke('PreToolUse',{stepIdx:1,toolCall});
    assert.equal(pre.stdoutObj.decision,'allow',JSON.stringify(pre));
    assert.ok(pre.stdoutObj.overwrite);
    const result = spawnSync('/bin/sh',['-c',pre.stdoutObj.overwrite.CommandLine],{cwd:pre.stdoutObj.overwrite.Cwd,encoding:'utf8'});
    assert.equal(result.status,126,result.stdout+result.stderr);
    assert.match(result.stderr,/PUBLIC_EXPORT_MUTATED/);
    assert.equal(fs.readFileSync(path.join(f.workspace,'app.js'),'utf8'),original);
    assert.deepEqual((await f.invoke('PostToolUse',{stepIdx:1,toolCall,error:'exit status 126'})).stdoutObj,{});
    const persistent = await f.invoke('PreToolUse',{stepIdx:2,toolCall:{name:'run_command',args:{...toolCall.args,RunPersistent:true}}});
    assert.equal(persistent.stdoutObj.decision,'deny');
  } finally {
    if (previous === undefined) delete process.env.BLAST_GUARD_STATE_DIR;
    else process.env.BLAST_GUARD_STATE_DIR = previous;
    f.close();
  }
});

test('Installed Codex shell wrapping preserves inputs and rolls back nonzero execution', async () => {
  const f = fixture();
  try {
    const file = path.join(f.workspace, 'app.js');
    const original = 'export function price() { return 1; }\n';
    fs.writeFileSync(file, original);
    const invoke = (event, extra = {}) => handleHostHookEvent({ host:'codex',event,rawStdin:JSON.stringify({cwd:f.workspace,session_id:'codex-wrap',prompt:'Fix app.js',...extra}),storeDir:f.state,_testHostVersionOverride:'0.167.0',wrapShell:true });
    await invoke('UserPromptSubmit');
    const edit = 'node -e "const fs=require(\'fs\');fs.writeFileSync(\'app.js\',fs.readFileSync(\'app.js\',\'utf8\').replace(\'return 1\',\'return 2\'))"';
    const failed = await invoke('PreToolUse',{tool_name:'Bash',tool_use_id:'failed',tool_input:{command:edit+'; exit 7',timeout_ms:5000}});
    const rewritten = failed.stdoutObj.hookSpecificOutput.updatedInput;
    assert.equal(rewritten.timeout_ms,5000);
    const runFailed = spawnSync('/bin/bash',['-c',rewritten.command],{cwd:f.workspace,encoding:'utf8'});
    assert.equal(runFailed.status,7,runFailed.stdout+runFailed.stderr);
    assert.equal(fs.readFileSync(file,'utf8'),original);
    await invoke('PostToolUse',{tool_name:'Bash',tool_use_id:'failed',tool_input:rewritten});
    const passed = await invoke('PreToolUse',{tool_name:'Bash',tool_use_id:'passed',tool_input:{command:edit}});
    const runPassed = spawnSync('/bin/bash',['-c',passed.stdoutObj.hookSpecificOutput.updatedInput.command],{cwd:f.workspace,encoding:'utf8'});
    assert.equal(runPassed.status,0,runPassed.stdout+runPassed.stderr);
    assert.equal(fs.readFileSync(file,'utf8'),original.replace('return 1','return 2'));
    await invoke('PostToolUse',{tool_name:'Bash',tool_use_id:'passed',tool_input:passed.stdoutObj.hookSpecificOutput.updatedInput});
  } finally { f.close(); }
});

test('Antigravity repeated PreInvocation remains idempotent while shell wrapper is active', async () => {
  const f = fixture();
  try {
    fs.writeFileSync(path.join(f.workspace,'app.js'),'export function price() { return 1; }\n');
    await f.invoke('PreInvocation');
    const toolCall = {name:'run_command',args:{Cwd:f.workspace,CommandLine:'printf "started\\n"; sleep 0.5; cat app.js'}};
    const pre = await f.invoke('PreToolUse',{stepIdx:1,toolCall});
    const child = spawn('/bin/sh',['-c',pre.stdoutObj.overwrite.CommandLine],{cwd:pre.stdoutObj.overwrite.Cwd});
    const closed = once(child,'close');
    await once(child.stdout,'data');
    const repeated = await f.invoke('PreInvocation',{invocationNum:2,initialNumSteps:3});
    assert.equal(repeated.exitCode,0);
    assert.equal(repeated.stdoutObj.terminationBehavior,undefined);
    const waiting = await f.invoke('Stop',{fullyIdle:false});
    assert.equal(waiting.stdoutObj.decision,'continue');
    const [exitCode] = await closed;
    assert.equal(exitCode,0);
    const updated = await f.invoke('PreInvocation',{lastUserInput:'Fix app.js and update README.md'});
    assert.equal(updated.stdoutObj.terminationBehavior,undefined);
  } finally { f.close(); }
});

test('Antigravity CLI emits recovery diagnostics on stderr with native empty PostToolUse JSON', async () => {
  const f = fixture();
  try {
    const file = path.join(f.workspace,'app.js');
    const original = 'export function price() { return 1; }\nexport function sibling() { return 10; }\n';
    fs.writeFileSync(file,original);
    await f.invoke('PreInvocation');
    const toolCall = {name:'replace_file_content',args:{TargetFile:'app.js',StartLine:1,EndLine:1,TargetContent:'return 1;',ReplacementContent:'return 2;'}};
    await f.invoke('PreToolUse',{stepIdx:1,toolCall});
    fs.writeFileSync(file,'export function price() { return 2; }\n');
    const cli = new URL('../bin/blast-guard.mjs',import.meta.url);
    const result = spawnSync(process.execPath,[fileURLToPath(cli),'hook','--host','antigravity','--event','PostToolUse','--store-dir',f.state],{cwd:f.workspace,input:JSON.stringify({...f.payload,stepIdx:1,toolCall}),encoding:'utf8'});
    assert.equal(result.status,2);
    assert.deepEqual(JSON.parse(result.stdout),{});
    assert.match(result.stderr,/rolled back/);
    assert.equal(fs.readFileSync(file,'utf8'),original);
  } finally { f.close(); }
});

test('Antigravity App 2.31.2 observed edit_file Path Target Replacement payload is supported', async () => {
  const fixtureData = fixture();
  const file = path.join(fixtureData.workspace, 'app.js');
  const original = '/**\n * 核心机制：\n */\nexport function price() { return 1; }\nexport function sibling() { return 10; }\n';
  try {
    fs.writeFileSync(file, original);
    await fixtureData.invoke('PreInvocation');
    const nativeCall = {
      name: 'edit_file',
      args: { Path: file, Target: ' * 核心机制：', Replacement: ' * 核心机制说明：' },
    };
    const pre = await fixtureData.invoke('PreToolUse', { stepIdx: 8, toolCall: nativeCall });
    assert.equal(pre.stdoutObj.decision, 'allow', JSON.stringify(pre));
    fs.writeFileSync(file, original.replace(' * 核心机制：', ' * 核心机制说明：'));
    const post = await fixtureData.invoke('PostToolUse', { stepIdx: 8, toolCall: nativeCall });
    assert.deepEqual(post.stdoutObj, {});
    const forbidden = await fixtureData.invoke('PreToolUse', {
      stepIdx: 9,
      toolCall: { name: 'edit_file', args: { Path: file, Target: 'export function sibling() { return 10; }\n', Replacement: '' } },
    });
    assert.equal(forbidden.stdoutObj.decision, 'deny');
    assert.match(forbidden.stdoutObj.reason, /PUBLIC_EXPORT_MUTATED/);
  } finally {
    fixtureData.close();
  }
});
