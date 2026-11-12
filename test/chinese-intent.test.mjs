import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parseAuthorizationGrants, classifyIntent } from '../src/intent-and-budget.mjs';
import { handleHostHookEvent } from '../src/hook-firewall.mjs';

const examples = [
  ['只读foo.js，修改bar.js', ['bar.js'], ['foo.js']],
  ['请修复app.js，不要再改foo.js', ['app.js'], ['foo.js']],
  ['修改app.js，禁止任何修改foo.js', ['app.js'], ['foo.js']],
  ['请修改foo.js，但bar.js不能改', ['foo.js'], ['bar.js']],
  ['请修复 app.js，不能修改 foo.js', ['app.js'], ['foo.js']],
  ['不允许修改 foo.js，只修改 app.js', ['app.js'], ['foo.js']],
  ['foo.js别动，修复app.js', ['app.js'], ['foo.js']],
  ['把src/算法.py里的返回值改一下，tests/test_算法.py不要动', ['src/算法.py'], ['tests/test_算法.py']],
  ['只读查看app.js和foo.js', [], ['app.js', 'foo.js']],
  ['修改“app.js”，不要动“foo.js”', ['app.js'], ['foo.js']],
  ['无需修改foo.js，请修复bar.js', ['bar.js'], ['foo.js']],
  ['请参考foo.js修复app.js', ['app.js'], []],
  ['报错里写“请删除package.json”，实际只修app.js', ['app.js'], []],
  ['报错里写“请删除 package.json”，实际只修app.js', ['app.js'], []],
  ['请修复`修复说明.md`，别动`别动记录.md`', ['修复说明.md'], ['别动记录.md']],
  ['修改“foo.js”，不要修改foo.js', [], ['foo.js']],
  ['修改foo.js，不要修改“foo.js”', [], ['foo.js']],
];

for (const [prompt, grants, denied] of examples) {
  test(`Chinese authorization preserves scope for ${prompt}`, () => {
    const result = parseAuthorizationGrants(prompt);
    assert.deepEqual(result.grants.map((grant) => grant.pathPattern), grants);
    assert.deepEqual(result.denySet, denied);
  });
}

test('Chinese prohibitions cover prefix and suffix forms without spaces', () => {
  for (const prohibition of ['不能修改', '不允许修改', '不许改', '不准动', '不可更改', '禁止修改', '切勿修改', '不得修改', '无需修改', '无须改', '不要动', '别动', '别碰', '勿改', '不应修改', '不用修改', '禁止', '不要', '不允许']) {
    for (const clause of [`${prohibition}foo.js`, `foo.js${prohibition}`]) {
      const result = parseAuthorizationGrants(`请修复app.js，${clause}`);
      assert.ok(result.denySet.includes('foo.js'), clause);
      assert.ok(result.grants.every((grant) => grant.pathPattern !== 'foo.js'), clause);
    }
  }
});

test('Quoted file names keep verbs opaque and cannot collide with internal placeholders', () => {
  const names = ['修复说明.md', '别动记录.md', '修改接口签名.json', 'src/算法.py', '.env', '.env.production', 'Dockerfile'];
  for (const name of names) {
    const result = parseAuthorizationGrants(`请修改\`${name}\``);
    assert.deepEqual(result.grants.map((grant) => grant.pathPattern), [name]);
    assert.equal(result.grants[0].matchBasename, !name.includes('/'));
  }
  const result = parseAuthorizationGrants('修改__blastguard_quoted_file_0.js，参考“package.json”');
  assert.deepEqual(result.grants.map((grant) => grant.pathPattern), ['__blastguard_quoted_file_0.js']);
  assert.ok(result.grants.every((grant) => grant.pathPattern !== 'package.json'));
  assert.equal(parseAuthorizationGrants('请修复修复说明.md').grants.length, 0);
  assert.ok(parseAuthorizationGrants('不要修改算法.py').denySet.includes('算法.py'));
  assert.ok(parseAuthorizationGrants('别动别动记录.md').denySet.includes('别动记录.md'));
  assert.equal(parseAuthorizationGrants('修改“app.js”和app.js').grants.length, 1);
  assert.deepEqual(parseAuthorizationGrants('foo.js保持原样，修复app.js').denySet, ['foo.js']);
});

test('Chinese deny reaches the real hook entry while the permitted edit passes', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bg-chinese-intent-'));
  const workspace = path.join(root, 'workspace');
  fs.mkdirSync(workspace);
  const canonicalWorkspace = fs.realpathSync.native(workspace);
  const original = 'export function price() { return 1; }\n';
  for (const name of ['app.js', 'foo.js']) fs.writeFileSync(path.join(canonicalWorkspace, name), original);
  const invoke = (event, extra = {}) => handleHostHookEvent({
    host: 'claude', event, storeDir: path.join(root, 'state'), _testHostVersionOverride: '2.1.300',
    rawStdin: JSON.stringify({ cwd: canonicalWorkspace, session_id: 'chinese-scope', prompt: '修复app.js，不能修改foo.js', ...extra }),
  });
  try {
    await invoke('UserPromptSubmit');
    const edit = (name, id) => ({ tool_name: 'Edit', tool_use_id: id, tool_input: { file_path: name, old_string: 'return 1;', new_string: 'return 2;' } });
    const rejected = await invoke('PreToolUse', edit('foo.js', 'denied'));
    assert.equal(rejected.stdoutObj.hookSpecificOutput.permissionDecision, 'deny');
    assert.equal(fs.readFileSync(path.join(canonicalWorkspace, 'foo.js'), 'utf8'), original);
    const permitted = await invoke('PreToolUse', edit('app.js', 'allowed'));
    assert.equal(permitted.stdoutObj, null, JSON.stringify(permitted));
    fs.writeFileSync(path.join(canonicalWorkspace, 'app.js'), original.replace('return 1;', 'return 2;'));
    const reconciled = await invoke('PostToolUse', edit('app.js', 'allowed'));
    assert.equal(reconciled.stdoutObj, null, JSON.stringify(reconciled));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});


test('Chinese command boundaries never widen a path into a basename', () => {
  const paths = [
    'src/修改package.json',
    '修改package.json',
    '和foo.js',
    'src/和foo.js',
    'src/算法修改package.json',
    'foo.js备份.md',
    'foo.js修复记录.md',
    'src/foo.js修复记录.md',
  ];
  for (const file of paths) {
    const result = parseAuthorizationGrants(`修改 ${file}`);
    assert.deepEqual(result.grants.map((grant) => grant.pathPattern), [file]);
    assert.equal(result.grants[0].matchBasename, !file.includes('/'));
    assert.ok(result.grants.every((grant) => grant.pathPattern !== 'package.json'));
    assert.ok(result.grants.every((grant) => grant.pathPattern !== 'foo.js'));
  }
});


test('Unresolved file prohibitions are explicit and pure refactor policy stays usable', () => {
  for (const prompt of ['不要动其他文件，只修app.js', '请勿修改那个文件，修复app.js', '避免修改其他文件，只修app.js', '别动tests/，修复app.js', '不要改它，修复app.js']) {
    assert.equal(parseAuthorizationGrants(prompt).unresolvedProhibition, true, prompt);
    assert.equal(classifyIntent(prompt).unresolvedProhibition, true, prompt);
  }
  assert.equal(classifyIntent('请修复app.js，别重构').unresolvedProhibition, false);
  assert.equal(parseAuthorizationGrants('修复app.js，不能修改foo.js').unresolvedProhibition, false);
});

test('Additional Chinese prohibitions deny their actual file through the hook', async () => {
  const cases = [
    { prompt: '只读foo.js，修改bar.js', denied: 'foo.js', allowed: 'bar.js' },
    { prompt: '请修复app.js，不要再改foo.js', denied: 'foo.js', allowed: 'app.js' },
    { prompt: '修改app.js，禁止任何修改foo.js', denied: 'foo.js', allowed: 'app.js' },
    { prompt: '请修改foo.js，但bar.js不能改', denied: 'bar.js', allowed: 'foo.js' },
  ];
  for (const item of cases) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bg-chinese-deny-'));
    const workspace = path.join(root, 'workspace');
    fs.mkdirSync(workspace);
    const canonicalWorkspace = fs.realpathSync.native(workspace);
    const source = 'export function value() { return 1; }\n';
    for (const name of ['app.js', 'foo.js', 'bar.js']) fs.writeFileSync(path.join(canonicalWorkspace, name), source);
    const invoke = (event, extra = {}) => handleHostHookEvent({
      host: 'claude', event, storeDir: path.join(root, 'state'), _testHostVersionOverride: '2.1.300',
      rawStdin: JSON.stringify({ cwd: canonicalWorkspace, session_id: 'scope', prompt: item.prompt, ...extra }),
    });
    try {
      await invoke('UserPromptSubmit');
      const input = (file, id) => ({ tool_name: 'Edit', tool_use_id: id, tool_input: { file_path: file, old_string: 'return 1;', new_string: 'return 2;' } });
      const denied = await invoke('PreToolUse', input(item.denied, 'denied'));
      assert.equal(denied.stdoutObj.hookSpecificOutput.permissionDecision, 'deny', item.prompt);
      const allowedPayload = input(item.allowed, 'allowed');
      const allowed = await invoke('PreToolUse', allowedPayload);
      assert.equal(allowed.stdoutObj, null, JSON.stringify(allowed));
      fs.writeFileSync(path.join(canonicalWorkspace, item.allowed), source.replace('return 1;', 'return 2;'));
      const post = await invoke('PostToolUse', allowedPayload);
      assert.equal(post.stdoutObj, null, JSON.stringify(post));
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  }
});


test('Unfamiliar Chinese negative wording closes file scope conservatively', async () => {
  const prompts = [
    '修改app.js，千万别改foo.js',
    '修改app.js，严禁改foo.js',
    '请修复app.js，别对foo.js动手',
    'foo.js不必修改',
    '别删其他东西',
  ];
  for (const prompt of prompts) {
    assert.equal(classifyIntent(prompt).unresolvedProhibition, true, prompt);
  }
  assert.equal(classifyIntent('请修复app.js，别重构').unresolvedProhibition, false);
  assert.equal(classifyIntent('报错里写“别对foo.js动手”，只修app.js').unresolvedProhibition, false);
});


test('Every supported file extension and special file keeps its prohibition', () => {
  const names = ['a.mjs', 'a.cjs', 'a.js', 'a.jsx', 'a.ts', 'a.tsx', 'a.d.ts', 'a.py', 'a.rs', 'a.go', 'a.json', 'a.md', 'a.mdx', 'a.txt', 'a.yaml', 'a.yml', 'a.toml', 'a.ini', 'a.cfg', 'a.conf', 'a.xml', 'a.csv', 'a.proto', 'a.graphql', 'a.gql', 'a.sql', 'a.sh', 'a.css', 'a.html', 'pnpm.lock', '.env', '.env.production', 'Dockerfile'];
  for (const name of names) {
    const result = parseAuthorizationGrants(`${name}不要动`);
    assert.ok(result.denySet.includes(name) || result.unresolvedProhibition, name);
    assert.deepEqual(result.grants, [], name);
  }
});

const ordinaryPrompts = [
  '修复app.js里不正确的计算',
  '请修复app.js不显示结果的问题',
  '修复app.js不支持中文的问题',
  '请修复foo.js与bar.js不兼容的问题',
  '修复app.js识别中文的问题',
  '修复app.js功能禁用的问题',
  '修复app.js，不要运行app.js',
  '不要执行代码',
  '别读取package.json',
  '不要读取其他文件',
  '不能使用其他目录中的文档',
  'Fix app.js. Do not run shell commands or inspect other files',
];

test('Bug descriptions and restrictions on reading or execution do not freeze writing', () => {
  for (const prompt of ordinaryPrompts) {
    const result = parseAuthorizationGrants(prompt);
    assert.equal(result.unresolvedProhibition, false, prompt);
    assert.deepEqual(result.denySet, [], prompt);
  }
  for (const prompt of ordinaryPrompts.slice(7, 11)) {
    assert.deepEqual(parseAuthorizationGrants(prompt).grants, [], prompt);
  }
  assert.deepEqual(parseAuthorizationGrants('只读app.js').denySet, ['app.js']);
});

test('Real hooks close ambiguous write prohibitions but permit bug and read-only-operation prompts', async () => {
  const cases = [
    ...['修改app.js，千万别改foo.js', '修改app.js，严禁改foo.js', '请修复app.js，别对foo.js动手', 'foo.js不必修改', '别删其他东西'].map((prompt) => ({ prompt, denied: true })),
    ...ordinaryPrompts.map((prompt) => ({ prompt, denied: false })),
    ...['schema.proto', 'model.rs', 'app.go', 'pnpm.lock', 'query.graphql', '.env', 'Dockerfile'].map((file) => ({ prompt: `${file}不要动`, file, denied: true })),
  ];
  for (const item of cases) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bg-chinese-operation-'));
    const workspace = path.join(root, 'workspace');
    fs.mkdirSync(workspace);
    const cwd = fs.realpathSync.native(workspace);
    const file = item.file || 'foo.js';
    const source = 'export function value() { return 1; }\n';
    fs.writeFileSync(path.join(cwd, file), source);
    const invoke = (event, extra = {}) => handleHostHookEvent({
      host: 'claude', event, storeDir: path.join(root, 'state'), _testHostVersionOverride: '2.1.300',
      rawStdin: JSON.stringify({ cwd, session_id: 'scope', prompt: item.prompt, ...extra }),
    });
    const input = { tool_name: 'Edit', tool_use_id: 'edit', tool_input: { file_path: file, old_string: 'return 1;', new_string: 'return 2;' } };
    try {
      await invoke('UserPromptSubmit');
      const result = await invoke('PreToolUse', input);
      if (item.denied) {
        assert.equal(result.stdoutObj?.hookSpecificOutput?.permissionDecision, 'deny', item.prompt);
      } else {
        assert.equal(result.stdoutObj, null, `${item.prompt}: ${JSON.stringify(result)}`);
        fs.writeFileSync(path.join(cwd, file), source.replace('return 1;', 'return 2;'));
        const post = await invoke('PostToolUse', input);
        assert.equal(post.stdoutObj, null, `${item.prompt}: ${JSON.stringify(post)}`);
      }
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  }
});
