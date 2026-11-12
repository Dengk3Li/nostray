import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { handleHostHookEvent } from "../src/hook-firewall.mjs";
import { readHostStartupObservations, recordHostStartupObservation } from "../src/hook-observation.mjs";
import { SnapshotStore } from "../src/snapshot-store.mjs";

function fixture() {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "bg-hook-observation-")));
  const workspace = path.join(root, "workspace");
  const state = path.join(root, "state");
  fs.mkdirSync(workspace);
  fs.writeFileSync(path.join(workspace, "app.js"), "export function price() { return 1; }\n");
  return { root, workspace, state, close: () => fs.rmSync(root, { recursive: true, force: true }) };
}

function fileInventory(directory) {
  return fs.readdirSync(directory, { recursive: true }).sort().map((entry) => {
    const stat = fs.lstatSync(path.join(directory, entry));
    return [entry, stat.size, stat.mtimeMs, stat.mode];
  });
}

test("Startup receipts retain separate host/session observations and offline reads leave state unchanged", async () => {
  const f = fixture();
  const oldPath = process.env.PATH;
  try {
    const binaries = path.join(f.root, "bin");
    fs.mkdirSync(binaries);
    // This fixture confirms receipt of a hook invocation only. No real Claude process is launched.
    fs.writeFileSync(path.join(binaries, "claude"), "#!/bin/sh\nprintf '2.1.300\\n'\n", { mode: 0o755 });
    process.env.PATH = binaries + path.delimiter + oldPath;
    for (const sessionId of ["first", "second"]) {
      const result = await handleHostHookEvent({ host: "claude", event: "UserPromptSubmit", storeDir: f.state,
        rawStdin: JSON.stringify({ cwd: f.workspace, session_id: sessionId, prompt: "Fix app.js" }) });
      assert.equal(result.startupCheck.observationRecorded, true);
      assert.match(result.stdoutObj.systemMessage, /快照覆盖完整/);
      assert.match(result.stdoutObj.systemMessage, /写后/);
      assert.equal(result.stdoutObj.hookSpecificOutput.additionalContext, "Make the minimal change needed.");
    }
    const synthetic = await handleHostHookEvent({ host: "claude", event: "UserPromptSubmit", storeDir: f.state,
      rawStdin: JSON.stringify({ cwd: f.workspace, session_id: "synthetic", prompt: "Fix app.js", is_synthetic: true }) });
    assert.equal(synthetic.startupCheck.observationRecorded, false);
    assert.match(synthetic.stdoutObj.systemMessage, /模拟回放/);
    const before = fileInventory(f.state);
    const observations = readHostStartupObservations(f.workspace, { storeDir: f.state, host: "claude" });
    assert.equal(observations.state, "OBSERVED");
    assert.equal(observations.observations.length, 2);
    assert.ok(observations.observations.every((record) => record.identityEvidence === "hook-event-received" && record.preToolUseVerified === false));
    assert.equal(readHostStartupObservations(f.workspace, { storeDir: f.state, sessionId: "first" }).observations.length, 1);
    assert.equal(readHostStartupObservations(f.workspace, { storeDir: f.state, host: "codex" }).state, "NOT_OBSERVED");
    assert.deepEqual(fileInventory(f.state), before);
    const receiptDirectory = path.join(f.state, "hook-observations");
    const receiptPath = path.join(receiptDirectory, fs.readdirSync(receiptDirectory)[0]);
    const corruptedReceipt = JSON.parse(fs.readFileSync(receiptPath, "utf8"));
    delete corruptedReceipt.snapshot;
    fs.writeFileSync(receiptPath, JSON.stringify(corruptedReceipt));
    assert.equal(readHostStartupObservations(f.workspace, { storeDir: f.state }).state, "UNREADABLE");
  } finally {
    if (oldPath === undefined) delete process.env.PATH;
    else process.env.PATH = oldPath;
    f.close();
  }
});

test("Version overrides, synthetic prompts and standalone sessions cannot create host startup receipts", async () => {
  const f = fixture();
  const store = new SnapshotStore(f.workspace, { storeDir: f.state });
  try {
    const unopenedInventory = fileInventory(f.root);
    assert.equal(readHostStartupObservations(f.workspace, { storeDir: f.state }).state, "NOT_OBSERVED");
    assert.deepEqual(fileInventory(f.root), unopenedInventory);
    await store.open();
    store.startOrUpdateTurn("Fix app.js", { sessionId: "cli" });
    assert.equal(readHostStartupObservations(f.workspace, { storeDir: f.state }).state, "NOT_OBSERVED");
    store.close();
    const result = await handleHostHookEvent({ host: "codex", event: "UserPromptSubmit", storeDir: f.state,
      _testHostVersionOverride: "0.167.0", rawStdin: JSON.stringify({ cwd: f.workspace, session_id: "test", prompt: "Fix app.js" }) });
    assert.equal(result.startupCheck.observationRecorded, false);
    assert.match(result.stdoutObj.systemMessage, /codex UserPromptSubmit 模拟回放/);
    assert.equal(result.stdoutObj.hookSpecificOutput.additionalContext, "Make the minimal change needed.");
    const args = { host: "codex", event: "UserPromptSubmit", sessionId: "fake", hostVersion: "0.167.0",
      snapshot: { coverageComplete: true }, shell: { mode: "hook-checkpoint", description: "description" } };
    assert.equal(recordHostStartupObservation(store, args), null);
    assert.equal(recordHostStartupObservation(store, { ...args, host: "claude", isSynthetic: true }), null);
    assert.equal(recordHostStartupObservation(store, { ...args, host: "claude", versionOverrideUsed: true }), null);
    assert.equal(readHostStartupObservations(f.workspace, { storeDir: f.state }).state, "NOT_OBSERVED");
  } finally { store.close(); f.close(); }
});

test("Oversize startup warnings retain blocking file details across Antigravity reentry", async () => {
  const f = fixture();
  try {
    fs.writeFileSync(path.join(f.workspace, "asset.bin"), Buffer.alloc(17 * 1024 * 1024));
    const invoke = () => handleHostHookEvent({ host: "antigravity", event: "PreInvocation", storeDir: f.state,
      _testHostVersionOverride: "2.31.2", rawStdin: JSON.stringify({ conversationId: "repeat", workspacePaths: [f.workspace], lastUserInput: "Fix app.js" }) });
    const first = await invoke();
    assert.equal(first.startupCheck.snapshot.coverageComplete, false);
    assert.deepEqual(first.startupCheck.snapshot.blockingFile, { path: "asset.bin", sizeBytes: 17 * 1024 * 1024, limitBytes: 16 * 1024 * 1024, kind: "file" });
    assert.match(first.stdoutObj.injectSteps[0].ephemeralMessage, /asset.bin.*17 MiB.*16 MiB/);
    assert.equal(first.startupCheck.shell.mode, "wrapped-checkpoint");
    const repeated = await invoke();
    assert.deepEqual(repeated.startupCheck.snapshot, first.startupCheck.snapshot);
    assert.match(repeated.stdoutObj.injectSteps[0].ephemeralMessage, /asset.bin.*17 MiB.*16 MiB/);
  } finally { f.close(); }
});

test("Cursor startup uses its native continue response and reports incomplete snapshots", async () => {
  const f = fixture();
  try {
    fs.writeFileSync(path.join(f.workspace, "asset.bin"), Buffer.alloc(17 * 1024 * 1024));
    const result = await handleHostHookEvent({ host: "cursor", event: "beforeSubmitPrompt", storeDir: f.state,
      _testHostVersionOverride: "0.50.0", rawStdin: JSON.stringify({ cwd: f.workspace, session_id: "cursor", prompt: "Fix app.js" }) });
    assert.equal(result.stdoutObj.continue, true);
    assert.match(result.stdoutObj.user_message, /asset.bin.*17 MiB/);
    assert.equal(result.stdoutObj.hookSpecificOutput, undefined);
  } finally { f.close(); }
});

test("Receipt failures are surfaced without claiming an observation was saved", async () => {
  const f = fixture();
  const oldPath = process.env.PATH;
  try {
    const binaries = path.join(f.root, "bin");
    fs.mkdirSync(binaries);
    fs.writeFileSync(path.join(binaries, "claude"), "#!/bin/sh\nprintf '2.1.300\\n'\n", { mode: 0o755 });
    process.env.PATH = binaries + path.delimiter + oldPath;
    fs.mkdirSync(f.state);
    fs.writeFileSync(path.join(f.state, "hook-observations"), "not a directory");
    const result = await handleHostHookEvent({ host: "claude", event: "UserPromptSubmit", storeDir: f.state,
      rawStdin: JSON.stringify({ cwd: f.workspace, session_id: "failed", prompt: "Fix app.js" }) });
    assert.equal(result.startupCheck.observationRecorded, false);
    assert.match(result.stdoutObj.systemMessage, /回执未保存/);
    assert.equal(readHostStartupObservations(f.workspace, { storeDir: f.state }).state, "UNREADABLE");
  } finally {
    if (oldPath === undefined) delete process.env.PATH;
    else process.env.PATH = oldPath;
    f.close();
  }
});
