import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { SnapshotStore } from "../src/snapshot-store.mjs";
import { handleHostHookEvent } from "../src/hook-firewall.mjs";
import { evaluateCandidateWriteSet } from "../src/conservation-engine.mjs";
import { createVoiEscalationCard } from "../src/scope-policy.mjs";

async function workspace(t, files) {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "bg-scope-policy-"));
  const root = path.join(temp, "workspace");
  fs.mkdirSync(root);
  for (const [file, source] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
    fs.writeFileSync(path.join(root, file), source);
  }
  const store = new SnapshotStore(root, { storeDir: path.join(temp, "state") });
  await store.open();
  t.after(() => { store.close(); fs.rmSync(temp, { recursive: true, force: true }); });
  return { root, store, state: path.join(temp, "state") };
}

function evaluate(store, file, before, after) {
  const session = store.loadSession("s");
  return evaluateCandidateWriteSet([{ relPosix: file, changeType: "modify", isDirectory: false, isBinary: false, commandBeforeText: before, taskBaselineText: before, afterText: after }], {
    budget: session.budget, workingSet: new Set(session.workingSet), grants: session.grants, denySet: session.denySet,
  });
}

test("A normal Read freezes a reference fingerprint and exports while preserving traced leaf localization", async t => {
  const type = "export function shape(value) { return value; }\n";
  const { root, store, state } = await workspace(t, {
    "src/leaf.js": "import { shape } from './type.js';\nimport { helper } from './helper.js';\nexport function leaf(value) { return shape(helper(value)); }\n",
    "src/type.js": type,
    "src/helper.js": "export function helper(value) { return value; }\n",
  });
  store.startOrUpdateTurn("Fix src/leaf.js using src/type.js as reference.", { sessionId: "s" });
  store.writeSessionMarker("s");
  const response = await handleHostHookEvent({ host: "claude", event: "PreToolUse", workspaceRoot: root, storeDir: state, _testHostVersionOverride: "2.1.295", rawStdin: JSON.stringify({ cwd: root, session_id: "s", tool_name: "Read", tool_input: { file_path: path.join(root, "src/type.js") } }) });
  assert.equal(response.exitCode, 0);
  assert.equal(response.readObservation.frozen, true);
  const policy = store.loadSession("s").budget.scopePolicy;
  assert.equal(policy.frozenReferences[0].sha256.length, 64);
  assert.equal(policy.frozenReferences[0].exports[0].name, "shape");
  assert.ok(policy.leaseEvidence.some(entry => entry.path === "src/helper.js" && entry.from === "src/leaf.js" && entry.reason === "one-hop-static-import"));
  assert.equal(evaluate(store, "src/type.js", type, type.replace("return value", "return null")).violations[0].code, "READ_REFERENCE_FROZEN");
  assert.equal(fs.readFileSync(path.join(root, "src/type.js"), "utf8"), type);
});

test("Explicit refactors group cycle members and preserve public boundaries consumed outside the group", async t => {
  const a = "import { b } from './b.js';\nexport function a(value) { return b(value); }\n";
  const b = "import { a } from './a.js';\nexport function b(value) { return value ? a(0) : 0; }\n";
  const c = "import { a } from './a.js';\nexport function c(value) { return a(value); }\n";
  const { store } = await workspace(t, { "src/a.js": a, "src/b.js": b, "src/c.js": c });
  store.startOrUpdateTurn("Refactor src/a.js", { sessionId: "s" });
  assert.equal(evaluate(store, "src/b.js", b, b.replace("function b(value)", "function b(value, extra)")).ok, true);
  assert.ok(evaluate(store, "src/a.js", a, a.replace("function a(value)", "function a(value, extra)")).violations.some(item => item.code === "PUBLIC_EXPORT_MUTATED"));
  assert.equal(evaluate(store, "src/c.js", c, c.replace("return a(value)", "return a(value + 1)")).violations[0].code, "REFACTOR_SCC_BOUNDARY");
  store.startOrUpdateTurn("Change signature src/a.js", { sessionId: "s" });
  assert.equal(evaluate(store, "src/a.js", a, a.replace("function a(value)", "function a(value, extra)")).ok, true);
});

test("Scope upgrades are exact, persisted user choices and preserve contracts for ordinary file approval", async t => {
  const before = "export function shape(value) { return value; }\n";
  const { store } = await workspace(t, { "src/leaf.js": "export function leaf() { return 1; }\n", "src/type.js": before });
  store.startOrUpdateTurn("Fix src/leaf.js using src/type.js as reference.", { sessionId: "s" });
  store.recordReadObservation("s", "src/type.js");
  const rejected = evaluate(store, "src/type.js", before, before.replace("return value", "return null"));
  const diagnostic = store.computeViolationDiagnostic(rejected.violations, "s");
  const card = store.getPendingEscalation("s");
  assert.ok(diagnostic.includes(card.id));
  assert.equal(card.options.length, 3);
  assert.equal(card.risk.product, card.risk.ambiguity * card.risk.irreversibleCost);
  store.startOrUpdateTurn(card.options[1].reply, { sessionId: "s", isSynthetic: true });
  assert.equal(store.getPendingEscalation("s").status, "pending");
  assert.equal(evaluate(store, "src/type.js", before, before.replace("return value", "return null")).ok, false);
  store.startOrUpdateTurn(card.options[1].reply, { sessionId: "s" });
  assert.equal(store.getPendingEscalation("s").status, "resolved");
  assert.equal(evaluate(store, "src/type.js", before, before.replace("return value", "return null")).ok, true);
  assert.equal(evaluate(store, "src/type.js", before, before.replace("function shape(value)", "function shape(value, extra)")).ok, false);
});

test("Named local fixes allow traced neighbors, reject unrelated leaves, and unlocated tasks keep their normal budget", async t => {
  const helper = "export function helper(value) { return value; }\n";
  const other = "export function other(value) { return value; }\n";
  const { store } = await workspace(t, {
    "src/leaf.js": "import { helper } from './helper.js';\nexport function leaf(v) { return helper(v); }\n",
    "src/helper.js": helper, "src/other.js": other,
  });
  store.startOrUpdateTurn("Fix src/leaf.js", { sessionId: "s" });
  assert.equal(evaluate(store, "src/helper.js", helper, helper.replace("return value", "return null")).ok, true);
  const unrelated = evaluate(store, "src/other.js", other, other.replace("return value", "return null"));
  assert.equal(unrelated.violations[0].code, "LOCALIZATION_OUTSIDE_ONE_HOP");
  assert.equal(createVoiEscalationCard(unrelated.violations, { sessionId: "s", turnId: 1, workingSet: ["src/leaf.js"] }), null);
  store.startOrUpdateTurn("Fix the rounding issue", { sessionId: "s", resetTask: true });
  assert.equal(evaluate(store, "src/other.js", other, other.replace("return value", "return null")).ok, true);
});

test("Read discovers unmentioned public types and approvals expire on the next ordinary user turn", async t => {
  const source = "export interface Shape { value: number; }\n";
  const { store } = await workspace(t, { "src/leaf.js": "export const leaf = 1;\n", "src/domain.ts": source });
  store.startOrUpdateTurn("Fix the issue", { sessionId: "s" });
  assert.equal(store.recordReadObservation("s", "src/domain.ts").frozen, true);
  const violation = evaluate(store, "src/domain.ts", source, source.replace("number", "string"));
  store.computeViolationDiagnostic(violation.violations, "s");
  const pending = store.getPendingEscalation("s");
  assert.equal(store.loadSession("s").escalation.id, pending.id);
  store.startOrUpdateTurn("Continue fixing the issue", { sessionId: "s" });
  assert.equal(store.getPendingEscalation("s").status, "expired");
  store.startOrUpdateTurn(pending.options[2].reply, { sessionId: "s" });
  assert.equal(evaluate(store, "src/domain.ts", source, source.replace("number", "string")).ok, false);
  store.startOrUpdateTurn("Fix another issue", { sessionId: "s", resetTask: true });
  assert.equal(store.getPendingEscalation("s"), null);
  assert.equal(store.loadSession("s").budget.scopePolicy.frozenReferences.length, 0);
});

test("Test cards offer additive authorization and preserve the existing assertions", async t => {
  const before = "import assert from 'node:assert/strict';\nimport test from 'node:test';\ntest('base', () => { assert.equal(1, 1); });\n";
  const additional = "test('extra', () => { assert.equal(2, 2); });\n";
  const { store } = await workspace(t, { "test/leaf.test.js": before });
  store.startOrUpdateTurn("Fix the issue", { sessionId: "s" });
  const rejected = evaluate(store, "test/leaf.test.js", before, before + additional);
  const text = store.computeViolationDiagnostic(rejected.violations, "s");
  const card = store.getPendingEscalation("s");
  assert.equal(card.options.length, 2);
  assert.match(text, /添加测试，保留既有断言/);
  assert.doesNotMatch(text, /schemaVersion/);
  store.startOrUpdateTurn(card.options[1].reply, { sessionId: "s" });
  assert.equal(evaluate(store, "test/leaf.test.js", before, before + additional).ok, true);
  assert.equal(evaluate(store, "test/leaf.test.js", before, before.replace("assert.equal(1, 1);", "")).ok, false);
  assert.equal(createVoiEscalationCard([{ code: "EXPLICITLY_NEGATED_PATH", path: "src/a.js" }], { sessionId: "s", turnId: 1 }), null);
});

test("The prompt/read/write hook entry points show a short card and honor its next real user reply", async t => {
  const source = "export interface Shape { value: number; }\n";
  const changed = source.replace("number", "string");
  const { root, store, state } = await workspace(t, { "src/domain.ts": source });
  const call = (event, payload) => handleHostHookEvent({ host: "claude", event, workspaceRoot: root, storeDir: state, _testHostVersionOverride: "2.1.295", rawStdin: JSON.stringify({ cwd: root, session_id: "s", ...payload }) });
  await call("UserPromptSubmit", { prompt: "Fix the issue" });
  await call("PreToolUse", { tool_name: "Read", tool_input: { file_path: path.join(root, "src/domain.ts") } });
  const writeInput = { file_path: path.join(store.canonicalRoot, "src/domain.ts"), content: changed };
  const denied = await call("PreToolUse", { tool_name: "Write", tool_use_id: "w1", tool_input: writeInput });
  assert.equal(denied.stdoutObj.hookSpecificOutput.permissionDecision, "deny");
  const card = store.loadSession("s").escalation;
  assert.ok(JSON.stringify(denied).includes(card.options[2].reply));
  assert.equal(fs.readFileSync(path.join(root, "src/domain.ts"), "utf8"), source);
  await call("UserPromptSubmit", { prompt: card.options[2].reply });
  const accepted = await call("PreToolUse", { tool_name: "Write", tool_use_id: "w2", tool_input: writeInput });
  assert.equal(accepted.exitCode, 0, JSON.stringify(accepted));
  fs.writeFileSync(path.join(root, "src/domain.ts"), changed);
  const post = await call("PostToolUse", { tool_name: "Write", tool_use_id: "w2", tool_input: writeInput });
  assert.equal(post.exitCode, 0, JSON.stringify(post));
  assert.equal(fs.readFileSync(path.join(root, "src/domain.ts"), "utf8"), changed);
});

test("Reference-only mentions survive ordinary follow-ups before the file is read", async t => {
  const helper = "export function helper(value) { return value; }\n";
  const { store } = await workspace(t, { "src/leaf.js": "import { helper } from './helper.js';\nexport const leaf = 1;\n", "src/helper.js": helper });
  store.startOrUpdateTurn("Fix src/leaf.js using src/helper.js as reference.", { sessionId: "s" });
  store.startOrUpdateTurn("Continue fixing the issue", { sessionId: "s" });
  const policy = store.loadSession("s").budget.scopePolicy;
  assert.ok(policy.references.includes("src/helper.js"));
  assert.equal(policy.leaseEvidence.some(entry => entry.path === "src/helper.js"), false);
  assert.equal(store.recordReadObservation("s", "src/helper.js").frozen, true);
  assert.equal(evaluate(store, "src/helper.js", helper, helper.replace("return value", "return null")).violations[0].code, "READ_REFERENCE_FROZEN");
});

test("Local TypeScript aliases participate in leases and unresolved local edges disable completeness", async t => {
  const helper = "export function helper(value: number) { return value; }\n";
  const { root, store } = await workspace(t, {
    "tsconfig.json": '{\n// JSONC is supported\n"compilerOptions": { "baseUrl": ".", "paths": { "@/*": ["src/*"], }, },\n}\n',
    "src/leaf.ts": "import { helper } from '@/helper';\nexport function leaf(value: number) { return helper(value); }\n",
    "src/helper.ts": helper,
  });
  store.startOrUpdateTurn("Fix src/leaf.ts", { sessionId: "s" });
  const policy = store.loadSession("s").budget.scopePolicy;
  assert.equal(policy.complete, true);
  assert.ok(policy.leaseEvidence.some(entry => entry.path === "src/helper.ts"));
  assert.equal(evaluate(store, "src/helper.ts", helper, helper.replace("return value", "return 0")).ok, true);
  fs.writeFileSync(path.join(root, "tsconfig.json"), '{"extends":"./unavailable.json"}\n');
  store.startOrUpdateTurn("Continue fixing the issue", { sessionId: "s" });
  assert.equal(store.loadSession("s").budget.scopePolicy.complete, false);
  assert.equal(evaluate(store, "src/helper.ts", helper, helper.replace("return value", "return 0")).ok, true);
});
