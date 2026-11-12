import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { handleHostHookEvent } from '../src/hook-firewall.mjs';
import { SnapshotStore } from '../src/snapshot-store.mjs';

test('unresolved prohibition blocks writes, preserves reads and persists until reset', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bg-unresolved-'));
  const workspace = path.join(root, 'workspace');
  fs.mkdirSync(workspace);
  const cwd = fs.realpathSync.native(workspace);
  const storeDir = path.join(root, 'state');
  const source = 'export function value() { return 1; }\n';
  const file = path.join(cwd, 'app.js');
  fs.writeFileSync(file, source);
  const invoke = (event, extra = {}) => handleHostHookEvent({
    host: 'claude', event, storeDir, _testHostVersionOverride: '2.1.300',
    rawStdin: JSON.stringify({ cwd, session_id: 's', prompt: '不要动其他文件，只修app.js', ...extra }),
  });
  const edit = { tool_name: 'Edit', tool_use_id: 'edit', tool_input: { file_path: 'app.js', old_string: 'return 1;', new_string: 'return 2;' } };
  try {
    await invoke('UserPromptSubmit');
    assert.equal((await invoke('PreToolUse', { tool_name: 'Read', tool_input: { file_path: 'app.js' } })).stdoutObj, null);
    const blocked = await invoke('PreToolUse', edit);
    assert.match(JSON.stringify(blocked.stdoutObj), /UNRESOLVED_PROHIBITION/);
    assert.match(JSON.stringify(blocked.stdoutObj), /start a new conversation/);
    assert.doesNotMatch(JSON.stringify(blocked.stdoutObj), /ONLY if impossible/);

    // Shell writes are checked after execution and must roll back to entry.
    const shell = { tool_name: 'Bash', tool_use_id: 'shell', tool_input: { command: 'true' } };
    assert.equal((await invoke('PreToolUse', shell)).stdoutObj, null);
    fs.writeFileSync(file, source.replace('return 1', 'return 2'));
    const post = await invoke('PostToolUse', shell);
    assert.match(JSON.stringify(post.stdoutObj), /UNRESOLVED_PROHIBITION/);
    assert.equal(fs.readFileSync(file, 'utf8'), source);

    await invoke('UserPromptSubmit', { prompt: '继续' });
    assert.match(JSON.stringify((await invoke('PreToolUse', edit)).stdoutObj), /UNRESOLVED_PROHIBITION/);

    const store = new SnapshotStore(cwd, { storeDir });
    try {
      await store.open();
      store.startOrUpdateTurn('修复app.js', { sessionId: 's', resetTask: true });
    } finally { store.close(); }
    assert.equal((await invoke('PreToolUse', { ...edit, tool_use_id: 'after-reset' })).stdoutObj, null);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
