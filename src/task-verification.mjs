import fs from "node:fs";
import path from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { evaluateCandidateWriteSet } from "./conservation-engine.mjs";
import { buildWorkspaceDependencyGraph } from "./dependency-graph.mjs";
import { inspectWorkspacePath } from "./path-security.mjs";
import { sanitizeTerminalText } from "./runtime-support.mjs";
import { sanitizePromptForAuthorization } from "./intent-and-budget.mjs";

const keyFor = (kind, sessionId) => `task-verification:${kind}:${createHash("sha256").update(sessionId).digest("hex")}`;
const hash = (value) => createHash("sha256").update(JSON.stringify(value)).digest("hex");
const VERIFICATION_LEASE_KEY = "task-verification:workspace-active";

function ownerIsAlive(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0) return false;
  try { process.kill(pid, 0); return true; }
  catch (error) { return error.code === "EPERM"; }
}

function readVerificationLease(store) {
  const row = store.db.prepare("SELECT value FROM meta WHERE key = ?").get(VERIFICATION_LEASE_KEY);
  return row ? JSON.parse(row.value) : null;
}

function waitingReport(store, requestedSessionId, lease, reason = null) {
  const previous = readMeta(store, "report", lease.sessionId);
  const running = ownerIsAlive(lease.ownerPid);
  return { ...previous, schemaVersion: "blast-guard.task-verification.v1", sessionId: requestedSessionId,
    verifiedAt: previous?.verifiedAt || lease.startedAt, state: running ? "RUNNING" : "UNVERIFIED", blocking: true,
    inProgress: running, activeSessionId: lease.sessionId,
    scope: previous?.scope || { state: "UNVERIFIED", violations: [] },
    conditions: previous?.conditions || { state: "NOT_CONFIGURED", results: [] },
    regression: { state: running ? "RUNNING" : "UNVERIFIED", results: [], reason: reason || (running
      ? "本工作区已有任务核验正在运行，请等待本次核验完成。"
      : "上次核验进程已中断。先恢复未结事务，再用 session verify --force 重试。") } };
}

function claimVerificationLease(store, session, plan, force) {
  return store.withImmediateTransaction(() => {
    const existing = readVerificationLease(store);
    if (existing && (ownerIsAlive(existing.ownerPid) || !force)) return { waiting: waitingReport(store, session.sessionId, existing) };
    if (existing && store.db.prepare("SELECT singleton FROM active_lock WHERE singleton = 1").get()) {
      return { waiting: waitingReport(store, session.sessionId, existing, "中断核验仍有未结事务。请先运行 rollback --recover，再重试核验。") };
    }
    const lease = { token: randomBytes(16).toString("hex"), ownerPid: process.pid, sessionId: session.sessionId,
      startedAt: new Date().toISOString(), taskBaselineId: session.taskBaselineId,
      turnCheckpointId: session.turnCheckpointId, planHash: hash(plan) };
    store.db.prepare("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
      .run(VERIFICATION_LEASE_KEY, JSON.stringify(lease));
    return { lease };
  });
}

function leaseMatchesCurrentTask(store, lease) {
  const active = readVerificationLease(store);
  const session = store.loadSession(lease.sessionId);
  return active?.token === lease.token && session?.taskBaselineId === lease.taskBaselineId &&
    session?.turnCheckpointId === lease.turnCheckpointId && hash(readMeta(store, "plan", lease.sessionId)) === lease.planHash;
}

function supersededReport(report) {
  return { ...report, state: "UNVERIFIED", blocking: true, superseded: true,
    regression: { ...report.regression, state: "UNVERIFIED", reason: "任务回合或验收计划已更新，本次旧核验结果不再用于完成判断。" } };
}

function persistVerificationReport(store, lease, report) {
  return store.withImmediateTransaction(() => {
    if (!leaseMatchesCurrentTask(store, lease)) return supersededReport(report);
    store.db.prepare("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
      .run(keyFor("report", lease.sessionId), JSON.stringify(report));
    return report;
  });
}

function relativePath(value) {
  if (typeof value !== "string" || !value || value.includes("\0") || path.isAbsolute(value) ||
      value.split(/[\\/]/).some((part) => part === "..")) throw new Error("Acceptance paths must be workspace-relative paths without '..'.");
  return value.replace(/\\/g, "/").replace(/^\.\//, "");
}

export function validateTaskVerificationPlan(plan) {
  if (!plan || typeof plan !== "object" || Array.isArray(plan)) throw new Error("Acceptance plan must be a JSON object.");
  const conditions = plan.conditions || [];
  const tests = plan.tests || [];
  if (!Array.isArray(conditions) || conditions.length > 64 || !Array.isArray(tests) || tests.length > 16) throw new Error("Acceptance plan supports at most 64 conditions and 16 test commands.");
  return {
    conditions: conditions.map((condition) => {
      if (!condition || typeof condition !== "object" || Array.isArray(condition) ||
          (condition.exists !== undefined && typeof condition.exists !== "boolean") ||
          (condition.contains !== undefined && (typeof condition.contains !== "string" || !condition.contains || condition.contains.length > 16384)) ||
          (condition.exists === false && condition.contains !== undefined)) throw new Error("Each condition needs a path and exists:boolean or a nonempty contains:string.");
      if (condition.exists === undefined && condition.contains === undefined) throw new Error("A condition needs exists or contains.");
      return { path: relativePath(condition.path), exists: condition.exists ?? true,
        ...(condition.contains !== undefined ? { contains: condition.contains } : {}) };
    }),
    tests: tests.map((entry) => {
      if (typeof entry === "string") return { testFile: relativePath(entry) };
      if (!entry || typeof entry !== "object" || !Array.isArray(entry.command) || !entry.command.length || entry.command.length > 64 ||
          entry.command.some((argument) => typeof argument !== "string" || !argument || argument.length > 4096 || argument.includes("\0"))) {
        throw new Error("Each test must be a relative Node test file or {command:[executable,...args], paths?:[relative paths], successContains?:string}.");
      }
      if (entry.paths !== undefined && !Array.isArray(entry.paths)) throw new Error("Test paths must be an array.");
      if (entry.successContains !== undefined && (typeof entry.successContains !== "string" || !entry.successContains || entry.successContains.length > 1024)) throw new Error("successContains must be a nonempty string of at most 1024 characters.");
      const timeoutMs = entry.timeoutMs ?? 60000;
      if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 120000) throw new Error("Test timeoutMs must be between 100 and 120000.");
      return { command: entry.command, paths: (entry.paths || []).map(relativePath), timeoutMs,
        ...(entry.successContains ? { successContains: entry.successContains } : {}) };
    }),
  };
}

function readMeta(store, kind, sessionId) {
  const row = store.db.prepare("SELECT value FROM meta WHERE key = ?").get(keyFor(kind, sessionId));
  return row ? JSON.parse(row.value) : null;
}

/** The CLI is the only caller that installs plans. Hook stdin and repository configuration never authorize commands. */
export function configureTaskVerification(store, sessionId, plan, { reset = false } = {}) {
  if (!store.loadSession(sessionId)) throw new Error(`Session '${sessionId}' does not exist.`);
  const normalized = plan === null ? null : validateTaskVerificationPlan(plan);
  store.withImmediateTransaction(() => {
    if (reset) store.db.prepare("DELETE FROM meta WHERE key IN (?,?)").run(keyFor("plan", sessionId), keyFor("report", sessionId));
    if (plan !== null) {
      const saved = { ...normalized, authorization: "explicit-cli-session-start", configuredAt: new Date().toISOString(), revision: randomBytes(12).toString("hex") };
      store.db.prepare("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
        .run(keyFor("plan", sessionId), JSON.stringify(saved));
      store.db.prepare("DELETE FROM meta WHERE key = ?").run(keyFor("report", sessionId));
    }
  });
  return readTaskVerification(store, sessionId);
}

export function readTaskVerification(store, sessionId) {
  const active = readVerificationLease(store);
  return { plan: readMeta(store, "plan", sessionId), report: readMeta(store, "report", sessionId),
    active: active ? { sessionId: active.sessionId, startedAt: active.startedAt, ownerPid: active.ownerPid,
      state: ownerIsAlive(active.ownerPid) ? "RUNNING" : "INTERRUPTED" } : null };
}

/** Only standalone, literal user directives are recognized. No command can be authorized through this grammar. */
export function recordPromptAcceptanceConditions(store, sessionId, rawPrompt, { isSynthetic = false } = {}) {
  const directPrompt = String(rawPrompt || "").replace(/<(assistant|tool_result|tool_response)\b[^>]*>[\s\S]*?<\/\1>/gi, "\n");
  const text = sanitizePromptForAuthorization(directPrompt, { isSynthetic });
  const conditions = [];
  for (const line of text.split("\n")) {
    const exists = line.match(/^\s*验收[：:]\s*([^\s]+)\s+必须存在[。.]?\s*$/);
    const contains = line.match(/^\s*验收[：:]\s*([^\s]+)\s+包含「([^」\r\n]+)」[。.]?\s*$/);
    if (exists) conditions.push({ path: relativePath(exists[1]), exists: true });
    else if (contains) {
      if (contains[2].length > 16384) throw new Error("A literal acceptance condition must be no longer than 16384 characters.");
      conditions.push({ path: relativePath(contains[1]), exists: true, contains: contains[2] });
    }
  }
  if (!conditions.length) return readTaskVerification(store, sessionId);
  const existing = readMeta(store, "plan", sessionId);
  const merged = [...new Map([...(existing?.conditions || []), ...conditions].map((condition) => [hash(condition), condition])).values()];
  if (merged.length > 64) throw new Error("A task supports at most 64 explicit acceptance conditions. Reset the task before adding more.");
  if (!existing || hash(merged) !== hash(existing.conditions)) {
    store.withImmediateTransaction(() => {
      const saved = { ...existing, conditions: merged, tests: existing?.tests || [], revision: randomBytes(12).toString("hex"),
        authorization: existing?.authorization || "explicit-user-prompt-conditions", configuredAt: existing?.configuredAt || new Date().toISOString() };
      store.db.prepare("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
        .run(keyFor("plan", sessionId), JSON.stringify(saved));
      store.db.prepare("DELETE FROM meta WHERE key = ?").run(keyFor("report", sessionId));
    });
  }
  return readTaskVerification(store, sessionId);
}

function checkConditions(store, conditions) {
  const results = conditions.map((condition) => {
    const target = inspectWorkspacePath(store.canonicalRoot, condition.path, { forWrite: false, allowDirectoryLeaf: true, checkPlatformAttrs: false });
    if (!target.ok) return { ...condition, passed: false, reason: target.reason };
    if (!condition.exists) return { ...condition, passed: !target.exists };
    if (!target.exists) return { ...condition, passed: false, reason: "Required path is missing." };
    if (condition.contains === undefined) return { ...condition, passed: true };
    const stat = fs.statSync(target.absPath);
    if (!stat.isFile() || stat.size > 16 * 1024 * 1024) return { ...condition, passed: false, reason: "Text condition requires a regular file no larger than 16 MiB." };
    return { ...condition, passed: fs.readFileSync(target.absPath, "utf8").includes(condition.contains) };
  });
  return { state: results.length ? results.every((result) => result.passed) ? "PASSED" : "FAILED" : "NOT_CONFIGURED", results };
}

function testFileCommand(root, testFile) {
  if (/\.(?:mjs|cjs|js)$/.test(testFile)) return { command: [process.execPath, "--test", "--test-reporter=tap", testFile], timeoutMs: 60000, testFile };
  if (/\.py$/.test(testFile)) {
    const source = fs.readFileSync(path.join(root, testFile), "utf8");
    const standardLibraryTest = /\b(?:unittest\.)?TestCase\b/.test(source) && !/^\s*(?:import pytest|from pytest\b)/m.test(source);
    return { command: ["python3", "-m", ...(standardLibraryTest ? ["unittest", testFile] : ["pytest", "-q", "--disable-warnings", testFile])], timeoutMs: 60000, testFile };
  }
  throw new Error("Automatic test files support Node .js/.mjs/.cjs and Python .py. Configure an explicit command for other runners.");
}

function relatedTests(root, changedFiles, plan) {
  if (plan?.tests.length) {
    const tests = plan.tests.filter((entry) => !entry.paths?.length || entry.paths.some((scope) => changedFiles.some((file) => file === scope || file.startsWith(scope + "/"))));
    return { tests: tests.map((entry) => entry.testFile ? testFileCommand(root, entry.testFile) : entry), discoveryComplete: true, source: "explicit-cli-plan" };
  }
  const graph = buildWorkspaceDependencyGraph(root);
  const candidates = new Set(changedFiles);
  for (const file of changedFiles) for (const caller of graph.computeCallerImpact(file).callerList) candidates.add(caller);
  const tests = [...candidates].filter((file) => /(?:^|\/)(?:test|tests|__tests__)\/|\.(?:test|spec)\.|(?:^|\/)test_[^/]+\.py$/.test(file) && /\.(?:mjs|cjs|js|py)$/.test(file) && fs.existsSync(path.join(root, file))).sort();
  return { tests: tests.slice(0, 16).map((file) => testFileCommand(root, file)), source: "static-import-reachability",
    discoveryComplete: tests.length <= 16 && !graph.truncated && !graph.unparsedFiles && !graph.oversizedFiles &&
      !graph.unreadableFiles && !graph.unreadableDirectories && !graph.unresolvedImports && !graph.unparsedConfigurations };
}

function completedTestCount(output) {
  const tap = output.match(/^# tests\s+(\d+)\s*$/m);
  if (tap) {
    const skipped = Number(output.match(/^# skipped\s+(\d+)\s*$/m)?.[1] || 0);
    const todo = Number(output.match(/^# todo\s+(\d+)\s*$/m)?.[1] || 0);
    return Math.max(0, Number(tap[1]) - skipped - todo);
  }
  const unittest = output.match(/Ran\s+(\d+)\s+tests?\b/);
  if (unittest) return Math.max(0, Number(unittest[1]) - Number(output.match(/OK\s+\(skipped=(\d+)\)/)?.[1] || 0));
  return Number(output.match(/\b(\d+)\s+passed\b/)?.[1] || 0);
}

/** Two-stage verification. Only explicit CLI plans or discovered existing tests run, always in a disposable OS sandbox. */
export async function verifyTaskAtStop(store, sessionId, { force = false } = {}) {
  const session = store.loadSession(sessionId);
  if (!session) throw new Error(`Session '${sessionId}' is missing.`);
  const plan = readMeta(store, "plan", sessionId);
  const admission = claimVerificationLease(store, session, plan, force);
  if (admission.waiting) return admission.waiting;
  const lease = admission.lease;
  const report = { schemaVersion: "blast-guard.task-verification.v1", sessionId, verifiedAt: new Date().toISOString(),
    state: "UNVERIFIED", scope: { state: "UNVERIFIED", violations: [] }, conditions: { state: "NOT_CONFIGURED", results: [] },
    regression: { state: "NOT_RUN", results: [] }, changedFiles: [], blocking: false };
  try {
    store.assertNoUnreconciledTransactions();
    store.assertNoActiveLock();
    const scan = store.scanWorkspaceNamespace({ storeBlobs: false });
    if (!scan.coverageComplete) throw new Error(scan.incompleteReason || "Workspace coverage is incomplete.");
    const turn = store.loadCheckpoint(session.turnCheckpointId);
    const baseline = store.loadCheckpoint(session.taskBaselineId);
    const turnDiffs = store.diffNamespaces(turn, baseline, scan).filter((entry) => entry.relPosix !== ".blast-guard-session");
    const taskAccepted = store.loadTaskAcceptedFileVersions(session);
    const taskDiffs = store.diffNamespaces(baseline, baseline, scan).filter((entry) => taskAccepted.files.has(entry.relPosix));
    const diffs = [...new Map([...taskDiffs, ...turnDiffs].map((entry) => [entry.relPosix, entry])).values()];
    report.changedFiles = diffs.filter((entry) => !entry.isDirectory).map((entry) => entry.relPosix);
    report.taskAttributionComplete = taskAccepted.complete;
    const scope = evaluateCandidateWriteSet(turnDiffs, { budget: session.budget, workingSet: new Set(session.workingSet), grants: session.grants, denySet: session.denySet });
    const conflicts = store.findSessionWriteConflicts(sessionId, scan.entries, report.changedFiles);
    report.scope = { state: scope.ok && !conflicts.length ? "PASSED" : "FAILED", violations: [...scope.violations, ...conflicts] };
    report.conditions = checkConditions(store, plan?.conditions || []);
    if (report.scope.state === "FAILED" || report.conditions.state === "FAILED") {
      report.state = "FAILED";
      report.blocking = true;
      return persistVerificationReport(store, lease, report);
    }
    const fingerprint = hash({ turn: session.turnId, plan, entries: [...scan.entries].map(([name, entry]) => [name, store.fileVersionFingerprint(entry)]), git: scan.gitControl });
    const previous = readMeta(store, "report", sessionId);
    if (!leaseMatchesCurrentTask(store, lease)) return supersededReport(report);
    if (!force && previous?.fingerprint === fingerprint && previous.state !== "RUNNING") return { ...previous, reused: true };
    report.fingerprint = fingerprint;
    if (process.env.BLAST_GUARD_VERIFICATION_ACTIVE === "1") {
      report.regression = { state: "UNVERIFIED", reason: "Nested or interrupted verification requires an explicit session verify --force retry.", results: [] };
      return persistVerificationReport(store, lease, report);
    }
    let selection;
    try { selection = relatedTests(store.canonicalRoot, report.changedFiles, plan); }
    catch (error) {
      report.regression = { state: "UNVERIFIED", reason: error.message, results: [] };
      return persistVerificationReport(store, lease, report);
    }
    report.regression = { state: selection.tests.length ? "RUNNING" : "NO_MATCH", source: selection.source, discoveryComplete: selection.discoveryComplete, results: [] };
    if (!selection.tests.length) return persistVerificationReport(store, lease, report);
    report.state = "RUNNING";
    const running = persistVerificationReport(store, lease, report);
    if (running.superseded) return running;
    const deadline = Date.now() + 120000;
    const regressionEnvironment = { ...process.env, BLAST_GUARD_VERIFICATION_ACTIVE: "1" };
    // Node's private runner marker suppresses a new --test process when inherited from a test tool.
    delete regressionEnvironment.NODE_TEST_CONTEXT;
    for (const test of selection.tests) {
      if (!leaseMatchesCurrentTask(store, lease)) return supersededReport(report);
      if (Date.now() >= deadline) {
        report.regression.results.push({ command: test.command, state: "UNVERIFIED", executed: false,
          exitCode: null, code: "VERIFICATION_TIME_BUDGET", reason: "Verification time budget exhausted.", testCount: 0 });
        break;
      }
      const result = await store.runIsolatedCommand(test.command, { sessionId, discardChanges: true,
        denyNetwork: true, timeoutMs: Math.min(test.timeoutMs, deadline - Date.now()), env: regressionEnvironment });
      if (!leaseMatchesCurrentTask(store, lease)) return supersededReport(report);
      const output = `${result.stdout || ""}\n${result.stderr || ""}`;
      const testCount = completedTestCount(output);
      const executed = result.code === "VERIFICATION_COMMAND_EXECUTED";
      const successEvidence = testCount > 0 || Boolean(test.successContains && output.includes(test.successContains));
      const unavailableDependency = /ModuleNotFoundError|No module named|ERR_MODULE_NOT_FOUND|Cannot find (?:module|package)|command not found|No such file or directory/i.test(output);
      const noCollectedTests = /no tests ran|collected 0 items|0 tests collected/i.test(output);
      const state = !executed || noCollectedTests || (result.exitCode !== 0 && unavailableDependency) ? "UNVERIFIED" : result.exitCode !== 0 ? "FAILED" : successEvidence ? "PASSED" : "UNVERIFIED";
      report.regression.results.push({ command: test.command, state, executed, exitCode: result.exitCode,
        code: result.code, reason: result.reason || (unavailableDependency ? "Test runner or imported dependency is unavailable; regression remains unverified." : noCollectedTests ? "The runner did not collect any tests." : null),
        testCount, stdout: result.stdout || "", stderr: result.stderr || "", outputArtifacts: result.outputArtifacts || null });
      if (state !== "PASSED") break;
    }
    const outcomes = report.regression.results;
    report.regression.state = outcomes.some((result) => result.state === "FAILED") ? "FAILED"
      : outcomes.length === selection.tests.length && outcomes.every((result) => result.state === "PASSED") && selection.discoveryComplete ? "PASSED" : "UNVERIFIED";
    report.blocking = report.regression.state === "FAILED";
    report.state = report.blocking ? "FAILED" : report.regression.state === "PASSED" && report.conditions.state === "PASSED" && taskAccepted.complete ? "PASSED" : "UNVERIFIED";
    // A live file changed during isolated verification invalidates the result.
    const after = store.scanWorkspaceNamespace({ storeBlobs: false });
    if (!after.coverageComplete || store.diffNamespaces({ ...scan, checkpointId: null }, null, after).length) {
      report.state = "UNVERIFIED";
      report.regression.state = "UNVERIFIED";
      report.regression.reason = "Live workspace changed while tests ran. Review current files and verify again.";
    }
    return persistVerificationReport(store, lease, report);
  } catch (error) {
    report.state = "FAILED";
    report.blocking = true;
    report.scope = { state: "FAILED", violations: [{ code: error.code || "VERIFICATION_PREFLIGHT_FAILED", message: error.message }] };
    return persistVerificationReport(store, lease, report);
  } finally {
    store.withImmediateTransaction(() => {
      if (readVerificationLease(store)?.token === lease.token) {
        store.db.prepare("DELETE FROM meta WHERE key = ?").run(VERIFICATION_LEASE_KEY);
      }
    });
  }
}

export function formatTaskVerification(report) {
  const labels = { PASSED: "通过", FAILED: "未通过", UNVERIFIED: "未核实", NO_MATCH: "未找到关联测试", NOT_RUN: "未运行", NOT_CONFIGURED: "未配置明确任务条件", RUNNING: "进行中" };
  const details = report.scope.violations.map((item) => `${item.code} ${item.path || ""} ${item.message}`).join("\n");
  const conditions = report.conditions.results.filter((item) => !item.passed).map((item) => `条件未满足 ${item.path}${item.reason ? ` · ${item.reason}` : ""}`).join("\n");
  const tests = report.regression.results.map((item) => {
    const preview = item.state === "PASSED" ? "" : (item.stderr || item.stdout || "").slice(-1600);
    return `${labels[item.state]} · ${item.command.join(" ")} · exit ${item.exitCode}${item.reason ? ` · ${item.reason}` : ""}${preview ? `\n${preview}` : ""}`;
  }).join("\n");
  return sanitizeTerminalText([`[BlastGuard 任务核验] ${labels[report.state]}`, `第一阶段 · 范围检查${labels[report.scope.state]}；任务条件${labels[report.conditions.state]}`,
    `第二阶段 · 回归${labels[report.regression.state]}${report.regression.reason ? ` · ${report.regression.reason}` : ""}`, details, conditions, tests].filter(Boolean).join("\n"));
}
