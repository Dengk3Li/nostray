import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createBoundedOutputCapture } from "../src/output-capture.mjs";
import { SnapshotStore, executeWrappedCommand } from "../src/snapshot-store.mjs";
import { configureTaskVerification, readTaskVerification, verifyTaskAtStop, recordPromptAcceptanceConditions } from "../src/task-verification.mjs";
import { handleHostHookEvent } from "../src/hook-firewall.mjs";
import { probeOsIsolationBackend } from "../src/runtime-support.mjs";

const cli = fileURLToPath(new URL("../bin/blast-guard.mjs", import.meta.url));

async function fixture(testBody = "assert.equal(amount(1), 3);") {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "bg-stop-verification-")));
  const workspace = path.join(root, "workspace");
  const state = path.join(root, "state");
  fs.mkdirSync(workspace);
  fs.writeFileSync(path.join(workspace, "app.mjs"), "export function amount(n) { return n + 1; }\n");
  if (testBody !== null) fs.writeFileSync(path.join(workspace, "app.test.mjs"),
    `import test from 'node:test';\nimport assert from 'node:assert/strict';\nimport fs from 'node:fs';\nimport {amount} from './app.mjs';\ntest('amount', () => { ${testBody} });\n`);
  const store = new SnapshotStore(workspace, { storeDir: state });
  await store.open();
  store.startOrUpdateTurn("Fix app.mjs", { sessionId: "task" });
  store.writeSessionMarker("task");
  return { root, workspace, state, store, close: () => { store.close(); fs.rmSync(root, { recursive: true, force: true }); } };
}

function fixAmount(f) {
  const tx = f.store.beginCommandTransaction({ sessionId: "task" });
  fs.writeFileSync(path.join(f.workspace, "app.mjs"), "export function amount(n) { return n + 2; }\n");
  assert.equal(f.store.reconcileCommandTransaction(tx.txId).ok, true);
}

test("Output capture preserves short bytes, spills long output privately and reports disk caps", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "bg-output-test-"));
  try {
    const short = createBoundedOutputCapture({ directory: path.join(root, "short") });
    short.append("短输出\n");
    assert.deepEqual(short.finish(), { text: "短输出\n", artifact: null });
    assert.equal(fs.existsSync(path.join(root, "short")), false);
    const capture = createBoundedOutputCapture({ directory: path.join(root, "long"), maxMemoryBytes: 1024, maxFileBytes: 2048 });
    for (let i = 0; i < 20; i++) capture.append(Buffer.alloc(1024, "x"));
    const result = capture.finish();
    assert.ok(Buffer.byteLength(result.text) < 5000);
    assert.equal(result.artifact.totalBytes, 20480);
    assert.equal(result.artifact.savedBytes, 2048);
    assert.equal(result.artifact.truncated, true);
    assert.equal(fs.statSync(result.artifact.path).mode & 0o777, 0o600);
    assert.equal(fs.statSync(path.dirname(result.artifact.path)).mode & 0o777, 0o700);
    assert.match(result.text, /达到文件上限/);
    assert.equal(fs.readFileSync(result.artifact.path).length, 2048);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("Wrapper spills actual stdout and stderr while retaining a failing command exit status", async () => {
  const f = await fixture(null);
  try {
    const result = await executeWrappedCommand(f.workspace, [process.execPath, "-e",
      "process.stdout.write('x'.repeat(2*1024*1024));process.stderr.write('y'.repeat(300000));process.exitCode=7"],
    { sessionId: "task", storeDir: f.state });
    assert.equal(result.exitCode, 7);
    assert.ok(result.stdout.length < 6000);
    assert.ok(result.stderr.length < 6000);
    assert.equal(fs.statSync(result.outputArtifacts.stdout.path).size, 2 * 1024 * 1024);
    assert.equal(fs.statSync(result.outputArtifacts.stderr.path).size, 300000);
    assert.equal(result.outputArtifacts.stdout.truncated, false);
    assert.equal(f.store.getUnreconciledJournals().length, 0);
  } finally { f.close(); }
});

test("Stop checks scope and explicit task conditions then runs related tests in a disposable sandbox", async (t) => {
  if (!probeOsIsolationBackend().available) { t.skip("OS isolation unavailable"); return; }
  const f = await fixture("fs.writeFileSync('test-artifact.txt','temporary'); assert.equal(amount(1), 3);");
  try {
    configureTaskVerification(f.store, "task", { conditions: [{ path: "app.mjs", contains: "n + 2" }] });
    fixAmount(f);
    const result = await verifyTaskAtStop(f.store, "task");
    assert.equal(result.state, "PASSED", JSON.stringify(result));
    assert.equal(result.regression.source, "static-import-reachability");
    assert.equal(result.regression.results[0].testCount, 1);
    assert.equal(fs.existsSync(path.join(f.workspace, "test-artifact.txt")), false);
    assert.equal((await verifyTaskAtStop(f.store, "task")).reused, true);
    assert.equal(readTaskVerification(f.store, "task").report.state, "PASSED");
  } finally { f.close(); }
});

test("Explicit unmet conditions block Stop before executing regressions", async () => {
  const f = await fixture();
  try {
    configureTaskVerification(f.store, "task", { conditions: [{ path: "missing-output.txt", exists: true }],
      tests: [{ command: [process.execPath, "-e", "process.stdout.write('should not run')"], successContains: "should not run" }] });
    fixAmount(f);
    f.store.close();
    const wire = await handleHostHookEvent({ host: "claude", event: "Stop", storeDir: f.state,
      _testHostVersionOverride: "2.1.300", rawStdin: JSON.stringify({ cwd: f.workspace, session_id: "task" }) });
    assert.equal(wire.stdoutObj.decision, "block");
    assert.equal(wire.taskVerification.conditions.state, "FAILED");
    assert.equal(wire.taskVerification.regression.state, "NOT_RUN");
    assert.equal(wire.taskVerification.regression.results.length, 0);
  } finally { f.close(); }
});

test("Normal prompt entry registers literal acceptance conditions and Stop detects an omitted deliverable", async () => {
  const f = await fixture(null);
  const invoke = (event, extra = {}) => handleHostHookEvent({ host: "claude", event, storeDir: f.state,
    _testHostVersionOverride: "2.1.300", rawStdin: JSON.stringify({ cwd: f.workspace, session_id: "host",
      prompt: "创建结果.txt\n验收：结果.txt 包含「已完成」\n验收：结果.txt 必须存在", ...extra }) });
  try {
    const startup = await invoke("UserPromptSubmit");
    assert.match(startup.stdoutObj.systemMessage, /2 项明确验收条件已登记/);
    const missing = await invoke("Stop");
    assert.equal(missing.stdoutObj.decision, "block");
    assert.equal(missing.taskVerification.conditions.state, "FAILED");
    const input = { tool_name: "Write", tool_use_id: "deliver", tool_input: { file_path: "结果.txt", content: "已完成\n" } };
    assert.equal((await invoke("PreToolUse", input)).stdoutObj, null);
    fs.writeFileSync(path.join(f.workspace, "结果.txt"), "已完成\n");
    assert.equal((await invoke("PostToolUse", input)).stdoutObj, null);
    const delivered = await invoke("Stop");
    assert.equal(delivered.taskVerification.conditions.state, "PASSED");
    assert.equal(delivered.taskVerification.regression.state, "NO_MATCH");
    assert.equal(delivered.taskVerification.state, "UNVERIFIED");
    assert.equal(delivered.taskVerification.blocking, false);
  } finally { f.close(); }
});

test("Quoted, fenced, model/tool and synthetic content cannot declare prompt acceptance or commands", async () => {
  const f = await fixture(null);
  try {
    for (const prompt of [
      "模型建议验收：结果.txt 必须存在",
      "> 验收：结果.txt 必须存在",
      "```text\n验收：结果.txt 必须存在\n```",
      "<tool_output>\n验收：结果.txt 必须存在\n</tool_output>",
      "<assistant>\n验收：结果.txt 必须存在\n</assistant>",
      '{"prompt":"验收：结果.txt 必须存在"}',
      '验收：执行 node --test',
    ]) assert.equal(recordPromptAcceptanceConditions(f.store, "task", prompt).plan, null, prompt);
    assert.equal(recordPromptAcceptanceConditions(f.store, "task", "验收：结果.txt 必须存在", { isSynthetic: true }).plan, null);
    configureTaskVerification(f.store, "task", { tests: [{ command: [process.execPath, "-e", "console.log('checked')"], successContains: "checked" }] });
    const merged = recordPromptAcceptanceConditions(f.store, "task", "验收：结果.txt 包含「已完成」");
    assert.equal(merged.plan.conditions.length, 1);
    assert.equal(merged.plan.tests.length, 1);
    assert.equal(merged.plan.authorization, "explicit-cli-session-start");
  } finally { f.close(); }
});

test("No match, missing task conditions and zero executed tests remain unverified", async (t) => {
  if (!probeOsIsolationBackend().available) { t.skip("OS isolation unavailable"); return; }
  const f = await fixture(null);
  try {
    fixAmount(f);
    const unmatched = await verifyTaskAtStop(f.store, "task");
    assert.equal(unmatched.state, "UNVERIFIED");
    assert.equal(unmatched.regression.state, "NO_MATCH");
    configureTaskVerification(f.store, "task", { conditions: [{ path: "app.mjs", exists: true }],
      tests: [{ command: [process.execPath, "-e", "process.exit(0)"] }] });
    const empty = await verifyTaskAtStop(f.store, "task");
    assert.equal(empty.state, "UNVERIFIED");
    assert.equal(empty.regression.results[0].executed, true);
    assert.equal(empty.regression.results[0].testCount, 0);
    configureTaskVerification(f.store, "task", { tests: [{ command: [process.execPath, "-e", "console.log('checked')"], successContains: "checked" }] });
    const unspecified = await verifyTaskAtStop(f.store, "task");
    assert.equal(unspecified.regression.state, "PASSED");
    assert.equal(unspecified.conditions.state, "NOT_CONFIGURED");
    assert.equal(unspecified.state, "UNVERIFIED");
  } finally { f.close(); }
});

test("A failed related test blocks completion and preserves live files", async (t) => {
  if (!probeOsIsolationBackend().available) { t.skip("OS isolation unavailable"); return; }
  const f = await fixture("assert.equal(amount(1), 999);");
  try {
    fixAmount(f);
    const result = await verifyTaskAtStop(f.store, "task");
    assert.equal(result.regression.state, "FAILED", JSON.stringify(result));
    assert.equal(result.blocking, true);
    assert.equal(fs.readFileSync(path.join(f.workspace, "app.mjs"), "utf8"), "export function amount(n) { return n + 2; }\n");
  } finally { f.close(); }
});

test("Task-wide accepted changes survive new turns without attributing another session's prior changes", async (t) => {
  if (!probeOsIsolationBackend().available) { t.skip("OS isolation unavailable"); return; }
  const f = await fixture();
  try {
    configureTaskVerification(f.store, "task", { conditions: [{ path: "app.mjs", contains: "n + 2" }] });
    fixAmount(f);
    // A user reviews a second session's output when starting the next turn.
    fs.writeFileSync(path.join(f.workspace, "other.mjs"), "export const other = 3;\n");
    f.store.startOrUpdateTurn("Continue. Do not modify app.mjs.", { sessionId: "task" });
    f.store.writeSessionMarker("task");
    const result = await verifyTaskAtStop(f.store, "task");
    assert.equal(result.state, "PASSED", JSON.stringify(result));
    assert.deepEqual(result.changedFiles, ["app.mjs"]);
    assert.equal(result.regression.results[0].testCount, 1);
    assert.equal(result.taskAttributionComplete, true);
  } finally { f.close(); }
});

test("Concurrent Stop readers preserve one running verification and block duplicate or recursive completion", async (t) => {
  if (!probeOsIsolationBackend().available) { t.skip("OS isolation unavailable"); return; }
  const f = await fixture("return new Promise(resolve => setTimeout(() => { assert.equal(amount(1), 3); resolve(); }, 450));");
  const reader = new SnapshotStore(f.workspace, { storeDir: f.state });
  let first;
  try {
    configureTaskVerification(f.store, "task", { conditions: [{ path: "app.mjs", contains: "n + 2" }] });
    f.store.startOrUpdateTurn("Read current files", { sessionId: "other" });
    fixAmount(f);
    first = verifyTaskAtStop(f.store, "task");
    await reader.open({ allowInitialize: false });
    const stored = readTaskVerification(reader, "task").report;
    assert.equal(stored.state, "RUNNING");
    for (const [session, options] of [["task", {}], ["task", { force: true }], ["other", {}]]) {
      const pending = await verifyTaskAtStop(reader, session, options);
      assert.equal(pending.state, "RUNNING");
      assert.equal(pending.blocking, true);
      assert.equal(pending.inProgress, true);
      assert.deepEqual(readTaskVerification(reader, "task").report, stored);
    }
    const wire = await handleHostHookEvent({ host: "claude", event: "Stop", storeDir: f.state,
      _testHostVersionOverride: "2.1.300", rawStdin: JSON.stringify({ cwd: f.workspace, session_id: "task", stop_hook_active: true }) });
    assert.equal(wire.stdoutObj.decision, "block");
    assert.equal(wire.taskVerification.state, "RUNNING");
    assert.equal((await first).state, "PASSED");
    assert.equal(readTaskVerification(reader, "task").report.state, "PASSED");
    assert.equal(readTaskVerification(reader, "task").active, null);
    assert.equal(readTaskVerification(reader, "other").report, null);
  } finally { if (first) await first; reader.close(); f.close(); }
});

test("A finishing verification cannot overwrite a newer explicit acceptance plan", async (t) => {
  if (!probeOsIsolationBackend().available) { t.skip("OS isolation unavailable"); return; }
  const f = await fixture("return new Promise(resolve => setTimeout(() => { assert.equal(amount(1), 3); resolve(); }, 150));");
  let first;
  try {
    configureTaskVerification(f.store, "task", { conditions: [{ path: "app.mjs", contains: "n + 2" }] });
    fixAmount(f);
    first = verifyTaskAtStop(f.store, "task");
    const updated = configureTaskVerification(f.store, "task", { conditions: [{ path: "app.mjs", exists: true }], tests: ["app.test.mjs"] });
    assert.equal(updated.report, null);
    assert.equal((await verifyTaskAtStop(f.store, "task")).state, "RUNNING");
    const obsolete = await first;
    assert.equal(obsolete.superseded, true);
    assert.equal(obsolete.state, "UNVERIFIED");
    assert.equal(readTaskVerification(f.store, "task").report, null);
    assert.equal(readTaskVerification(f.store, "task").plan.revision, updated.plan.revision);
    assert.equal((await verifyTaskAtStop(f.store, "task")).state, "PASSED");
  } finally { if (first) await first; f.close(); }
});

test("A task reset at the isolated-command boundary fences the previous verification result", async (t) => {
  if (!probeOsIsolationBackend().available) { t.skip("OS isolation unavailable"); return; }
  const f = await fixture();
  const originalRun = f.store.runIsolatedCommand.bind(f.store);
  try {
    configureTaskVerification(f.store, "task", { conditions: [{ path: "app.mjs", contains: "n + 2" }] });
    fixAmount(f);
    const oldBaseline = f.store.loadSession("task").taskBaselineId;
    f.store.runIsolatedCommand = async (...args) => {
      const result = await originalRun(...args);
      f.store.startOrUpdateTurn("Start a new task", { sessionId: "task", resetTask: true });
      f.store.writeSessionMarker("task");
      configureTaskVerification(f.store, "task", { conditions: [{ path: "app.mjs", exists: true }], tests: ["app.test.mjs"] }, { reset: true });
      return result;
    };
    const obsolete = await verifyTaskAtStop(f.store, "task");
    assert.equal(obsolete.superseded, true);
    assert.notEqual(f.store.loadSession("task").taskBaselineId, oldBaseline);
    assert.equal(readTaskVerification(f.store, "task").report, null);
    f.store.runIsolatedCommand = originalRun;
    assert.equal((await verifyTaskAtStop(f.store, "task")).state, "PASSED");
  } finally { f.close(); }
});

test("An interrupted owner remains unverified until an explicit retry takes the abandoned lease", async (t) => {
  if (!probeOsIsolationBackend().available) { t.skip("OS isolation unavailable"); return; }
  const f = await fixture();
  try {
    configureTaskVerification(f.store, "task", { conditions: [{ path: "app.mjs", contains: "n + 2" }] });
    fixAmount(f);
    assert.equal((await verifyTaskAtStop(f.store, "task")).state, "PASSED");
    const exited = spawnSync(process.execPath, ["-e", ""]);
    const session = f.store.loadSession("task");
    const lease = { token: "abandoned", ownerPid: exited.pid, sessionId: "task", startedAt: new Date().toISOString(),
      taskBaselineId: session.taskBaselineId, turnCheckpointId: session.turnCheckpointId, planHash: "abandoned" };
    f.store.db.prepare("INSERT INTO meta(key,value) VALUES(?,?)").run("task-verification:workspace-active", JSON.stringify(lease));
    const storedBefore = readTaskVerification(f.store, "task").report;
    const interrupted = await verifyTaskAtStop(f.store, "task");
    assert.equal(interrupted.state, "UNVERIFIED");
    assert.equal(interrupted.blocking, true);
    assert.deepEqual(readTaskVerification(f.store, "task").report, storedBefore);
    assert.equal((await verifyTaskAtStop(f.store, "task", { force: true })).state, "PASSED");
    assert.equal(readTaskVerification(f.store, "task").active, null);
  } finally { f.close(); }
});

test("Python standard-library related regression runs and unavailable Python dependencies remain unverified", async (t) => {
  if (!probeOsIsolationBackend().available) { t.skip("OS isolation unavailable"); return; }
  const f = await fixture(null);
  try {
    fs.writeFileSync(path.join(f.workspace, "amount.py"), "def amount(n):\n    return n + 1\n");
    fs.writeFileSync(path.join(f.workspace, "test_amount.py"), "import unittest\nfrom amount import amount\nclass AmountTest(unittest.TestCase):\n    def test_amount(self):\n        self.assertEqual(amount(1), 3)\n");
    f.store.startOrUpdateTurn("Fix amount.py", { sessionId: "task", resetTask: true });
    f.store.writeSessionMarker("task");
    configureTaskVerification(f.store, "task", { conditions: [{ path: "amount.py", contains: "n + 2" }] });
    const tx = f.store.beginCommandTransaction({ sessionId: "task" });
    fs.writeFileSync(path.join(f.workspace, "amount.py"), "def amount(n):\n    return n + 2\n");
    assert.equal(f.store.reconcileCommandTransaction(tx.txId).ok, true);
    const result = await verifyTaskAtStop(f.store, "task");
    assert.deepEqual(result.regression.results[0].command, ["python3", "-m", "unittest", "test_amount.py"]);
    if (spawnSync("python3", ["--version"]).status === 0) {
      assert.equal(result.state, "PASSED", JSON.stringify(result));
      assert.equal(result.regression.results[0].testCount, 1);
    } else assert.equal(result.state, "UNVERIFIED");
    configureTaskVerification(f.store, "task", { conditions: [{ path: "amount.py", exists: true }],
      tests: [{ command: ["python3", "-c", "import blastguard_missing_acceptance_dependency_7f923"] }] });
    const missing = await verifyTaskAtStop(f.store, "task");
    assert.equal(missing.state, "UNVERIFIED");
    assert.equal(missing.regression.results[0].state, "UNVERIFIED");
  } finally { f.close(); }
});

test("An all-skipped Node test never counts as a completed regression", async (t) => {
  if (!probeOsIsolationBackend().available) { t.skip("OS isolation unavailable"); return; }
  const f = await fixture();
  try {
    fs.writeFileSync(path.join(f.workspace, "app.test.mjs"), "import test from 'node:test';import {amount} from './app.mjs';test.skip('amount',()=>amount(1));\n");
    f.store.startOrUpdateTurn("Fix app.mjs", { sessionId: "task", resetTask: true });
    f.store.writeSessionMarker("task");
    fixAmount(f);
    const result = await verifyTaskAtStop(f.store, "task");
    assert.equal(result.regression.state, "UNVERIFIED");
    assert.equal(result.regression.results[0].testCount, 0);
  } finally { f.close(); }
});

test("Python pytest files select pytest and missing runner dependencies remain unverified", async (t) => {
  if (!probeOsIsolationBackend().available) { t.skip("OS isolation unavailable"); return; }
  const f = await fixture(null);
  try {
    fs.writeFileSync(path.join(f.workspace, "amount.py"), "def amount(n):\n    return n + 1\n");
    fs.writeFileSync(path.join(f.workspace, "test_amount.py"), "import pytest\nfrom amount import amount\ndef test_amount():\n    assert amount(1) == 3\n");
    f.store.startOrUpdateTurn("Fix amount.py", { sessionId: "task", resetTask: true });
    f.store.writeSessionMarker("task");
    configureTaskVerification(f.store, "task", { conditions: [{ path: "amount.py", contains: "n + 2" }] });
    const tx = f.store.beginCommandTransaction({ sessionId: "task" });
    fs.writeFileSync(path.join(f.workspace, "amount.py"), "def amount(n):\n    return n + 2\n");
    assert.equal(f.store.reconcileCommandTransaction(tx.txId).ok, true);
    const result = await verifyTaskAtStop(f.store, "task");
    assert.deepEqual(result.regression.results[0].command, ["python3", "-m", "pytest", "-q", "--disable-warnings", "test_amount.py"]);
    const pytestAvailable = spawnSync("python3", ["-m", "pytest", "--version"]).status === 0;
    assert.equal(result.state, pytestAvailable ? "PASSED" : "UNVERIFIED", JSON.stringify(result));
  } finally { f.close(); }
});

test("CLI session plans freeze explicit authorization, expose reports and honor --store-dir", async () => {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "bg-cli-task-plan-")));
  const workspace = path.join(root, "workspace");
  const state = path.join(root, "state");
  fs.mkdirSync(workspace);
  fs.writeFileSync(path.join(workspace, "app.mjs"), "export const amount = 2;\n");
  fs.writeFileSync(path.join(workspace, "app.test.mjs"), "import test from 'node:test';import assert from 'node:assert/strict';test('two',()=>assert.equal(2,2));\n");
  const acceptance = path.join(root, "acceptance.json");
  fs.writeFileSync(acceptance, JSON.stringify({ conditions: [{ path: "app.mjs", contains: "2" }], tests: ["app.test.mjs"] }));
  const run = (args) => spawnSync(process.execPath, [cli, "session", ...args, "--dir", workspace, "--store-dir", state, "--json"], { encoding: "utf8" });
  try {
    const start = run(["start", "--session", "task", "--acceptance", acceptance]);
    assert.equal(start.status, 0, start.stderr);
    assert.equal(JSON.parse(start.stdout).verification.plan.authorization, "explicit-cli-session-start");
    assert.equal(fs.existsSync(path.join(state, "state.sqlite")), true);
    const status = run(["status", "--session", "task"]);
    assert.equal(status.status, 0, status.stderr);
    assert.equal(JSON.parse(status.stdout).report, null);
    const verify = run(["verify", "--session", "task"]);
    const verified = JSON.parse(verify.stdout);
    assert.equal(verified.state, probeOsIsolationBackend().available ? "PASSED" : "UNVERIFIED", verify.stdout + verify.stderr);
    const reset = run(["start", "--session", "task", "--reset-task"]);
    assert.equal(JSON.parse(reset.stdout).verification.plan, null);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
