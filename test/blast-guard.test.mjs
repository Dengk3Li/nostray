import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

import {
  BLAST_GUARD_BIN_PATH,
  computeWorkspaceId,
  probeOsIsolationBackend,
  parseAuthorizationGrants,
  classifyIntent,
  compareCodeExports,
  verifyAdditiveTestConservation,
  verifyMarkdownSectionConservation,
  verifyEpistemicAndNumericAnchors,
  verifyJsonConservation,
  evaluateCandidateWriteSet,
  inspectWorkspacePath,
  classifyProtectionRing,
  buildWorkspaceDependencyGraph,
  SnapshotStore,
  buildUnifiedFilePatch,
  executeWrappedCommand,
  spawnAndReapProcessGroup,
  handleHostHookEvent,
  simulateCodexApplyPatch,
  validateSuppliedHostVersion,
  runGitPreCommitCheck,
  auditRepository,
  renderAuditTerminalCard,
  renderAuditSvgScorecard,
  installOrUninstallHooks,
  inspectHostInstallations,
  runFaultInjectionSelfTests,
  GIT_ORIG_HOOK_FILENAME,
} from "../src/index.mjs";
import { runBlastBench as runBenchDirect } from "../bench/blast-bench.mjs";

const BOUNDED_CLAUDE_VER = "2.1.300";
const BOUNDED_CODEX_VER = "0.167.0";
const BOUNDED_CURSOR_VER = "0.50.0";

function createTempSandbox(prefix = "bg-test-") {
  fs.mkdirSync(os.tmpdir(), { recursive: true });
  const root = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  const ws = path.join(root, "workspace with spaces");
  const state = path.join(root, "ext-state");
  fs.mkdirSync(ws, { recursive: true });
  return {
    root,
    ws,
    state,
    cleanup() {
      fs.rmSync(root, { recursive: true, force: true });
    },
  };
}

test("Path security (, , ): prefix collision, symlink to guard binary, hardlinks, build/package.json, and non-exempt xattrs", (t) => {
  const sbx = createTempSandbox("bg-path-");
  try {
    fs.mkdirSync(path.join(sbx.ws, "contracts"), { recursive: true });
    fs.writeFileSync(path.join(sbx.ws, "contracts/api.schema.json"), '{"type":"object"}\n');
    fs.writeFileSync(path.join(sbx.ws, "plain.txt"), "hello\n");
    const siblingDir = `${fs.realpathSync.native(sbx.ws)}-other`;
    fs.mkdirSync(siblingDir, { recursive: true });
    fs.writeFileSync(path.join(siblingDir, "evil.js"), "x\n");

    const canonicalWs = fs.realpathSync.native(sbx.ws);

    // 1. Sibling `/workspace with spaces-other/evil.js` must NOT pass prefix check
    const rSibling = inspectWorkspacePath(canonicalWs, path.join(siblingDir, "evil.js"));
    assert.equal(rSibling.ok, false);
    assert.equal(rSibling.code, "OUTSIDE_WORKSPACE_ROOT");

    // 2. Relative traversal `../../etc/passwd`
    const rTrav = inspectWorkspacePath(canonicalWs, "../../etc/passwd");
    assert.equal(rTrav.ok, false);
    assert.equal(rTrav.code, "OUTSIDE_WORKSPACE_ROOT");

    // 3. Symlink leaf aliasing Ring-0 contract
    fs.symlinkSync("contracts/api.schema.json", path.join(canonicalWs, "harmless.txt"));
    const rLink = inspectWorkspacePath(canonicalWs, "harmless.txt", { forWrite: true });
    assert.equal(rLink.ok, false);

    // 4. Leaf symlink inside workspace targeting BLAST_GUARD_BIN_PATH -> IMMUTABLE_GUARD_BINARY (``)!
    fs.symlinkSync(BLAST_GUARD_BIN_PATH, path.join(canonicalWs, "guard-link.mjs"));
    const rGuardLink = inspectWorkspacePath(canonicalWs, "guard-link.mjs", { forWrite: true });
    assert.equal(rGuardLink.ok, false);
    assert.equal(rGuardLink.code, "IMMUTABLE_GUARD_BINARY");

    // 5. Hardlinked leaf file (`nlink === 2`) rejected on write (``)!
    fs.linkSync(path.join(canonicalWs, "plain.txt"), path.join(canonicalWs, "plain-hardlink.txt"));
    const rHardlink = inspectWorkspacePath(canonicalWs, "plain-hardlink.txt", { forWrite: true });
    assert.equal(rHardlink.ok, false);
    assert.equal(rHardlink.code, "UNSAFE_HARDLINK_ALIAS");
    fs.unlinkSync(path.join(canonicalWs, "plain-hardlink.txt"));

    // 6. `build/package.json` & `tests/conftest.py` are classified as RING_0 (``, ``)!
    assert.equal(classifyProtectionRing("build/package.json").ring, "RING_0");
    assert.equal(classifyProtectionRing("tests/conftest.py").ring, "RING_0");
    assert.equal(classifyProtectionRing("tests/conftest.py").category, "TEST_SUITE");

    // 7. Non-exempt extended attribute (`com.blastguard.custom`) fails strict metadata check on Darwin (``)!
    if (process.platform === "darwin" && fs.existsSync("/usr/bin/xattr")) {
      const xattrFile = path.join(canonicalWs, "with-xattr.txt");
      fs.writeFileSync(xattrFile, "attr-test\n");
      const setX = spawnSync("/usr/bin/xattr", ["-w", "com.blastguard.custom", "secret", xattrFile]);
      if (setX.status === 0) {
        const rXattr = inspectWorkspacePath(canonicalWs, "with-xattr.txt", {
          forWrite: true,
          checkPlatformAttrs: true,
        });
        assert.equal(rXattr.ok, false);
        assert.equal(rXattr.code, "UNSUPPORTED_METADATA_REQUIREMENT");
      }
    }

    fs.rmSync(siblingDir, { recursive: true, force: true });
  } finally {
    sbx.cleanup();
  }
});

test("OS Sandbox escape defense (): kernel denies writes to live workspace, state store, AND unrelated host directories", async (t) => {
  const osSbx = probeOsIsolationBackend({ forceRefresh: true });
  if (!osSbx.available) {
    t.skip(`OS isolation backend unavailable: ${osSbx.reason}`);
    return;
  }

  const sbx = createTempSandbox("bg-seatbelt-p01-");
  const unrelatedDir = fs.mkdtempSync(path.join(os.tmpdir(), "bg-unrelated-outside-"));
  try {
    fs.writeFileSync(path.join(sbx.ws, "leaf.js"), "export function calc(x) { return x + 1; }\n");
    const store = new SnapshotStore(sbx.ws, { storeDir: sbx.state });
    await store.open();
    store.startOrUpdateTurn("Update leaf.js", { sessionId: "iso-p01" });
    store.close();

    const outsideProbeFile = path.join(unrelatedDir, "escaped.txt");
    const liveProbeFile = path.join(sbx.ws, "escaped-live.txt");
    const stateProbeFile = path.join(sbx.state, "escaped-state.txt");

    const isoRes = await executeWrappedCommand(
      sbx.ws,
      [
        process.execPath,
        "-e",
        `const fs = require("node:fs");
         let liveBlocked = false, stateBlocked = false, outsideBlocked = false;
         try { fs.writeFileSync(${JSON.stringify(liveProbeFile)}, "x"); } catch { liveBlocked = true; }
         try { fs.writeFileSync(${JSON.stringify(stateProbeFile)}, "x"); } catch { stateBlocked = true; }
         try { fs.writeFileSync(${JSON.stringify(outsideProbeFile)}, "x"); } catch { outsideBlocked = true; }
         if (!liveBlocked || !stateBlocked || !outsideBlocked) process.exit(42);
         fs.writeFileSync("leaf.js", "export function calc(x) { return x + 2; }\\n");`,
      ],
      { mode: "isolated", promoteMode: "staged", sessionId: "iso-p01", storeDir: sbx.state }
    );

    assert.equal(isoRes.exitCode, 0);
    assert.equal(fs.existsSync(outsideProbeFile), false);
    assert.equal(fs.existsSync(liveProbeFile), false);
    assert.equal(fs.existsSync(stateProbeFile), false);
  } finally {
    fs.rmSync(unrelatedDir, { recursive: true, force: true });
    sbx.cleanup();
  }
});

test("Staged promotion security & valid git unified patch (, ): rejects traversal txId, hash tamper, policy revocation & concurrent drift", async (t) => {
  const osSbx = probeOsIsolationBackend();
  if (!osSbx.available) {
    t.skip(`OS isolation backend unavailable: ${osSbx.reason}`);
    return;
  }

  const sbx = createTempSandbox("bg-iso-promote-");
  try {
    fs.writeFileSync(path.join(sbx.ws, "calc.js"), "export function double(x) { return x * 2; }\n");
    fs.writeFileSync(path.join(sbx.ws, "no-nl.txt"), "line1\nline2");
    const store = new SnapshotStore(sbx.ws, { storeDir: sbx.state });
    await store.open();
    store.startOrUpdateTurn("Update calc.js and no-nl.txt and add added.txt", { sessionId: "iso1" });
    store.close();

    // 1. Stage compliant modify + missing-newline edit + file add
    const res1 = await executeWrappedCommand(
      sbx.ws,
      [
        process.execPath,
        "-e",
        `const fs = require("node:fs");
         fs.writeFileSync("calc.js", "export function double(x) { return Number(x) * 2; }\\n");
         fs.writeFileSync("no-nl.txt", "line1\\nline2-updated");
         fs.writeFileSync("added.txt", "brand new\\n");`,
      ],
      { mode: "isolated", promoteMode: "staged", sessionId: "iso1", storeDir: sbx.state }
    );
    assert.equal(res1.ok, true);
    assert.equal(res1.promoted, false);
    assert.equal(res1.code, "EXISTING_FILE_OWNERSHIP_UNPROVEN");

    // Verify `patch.diff` is a genuine unified diff accepted by `git apply --check` (``)!
    const patchFile = path.join(res1.stagedBundleDir, "patch.diff");
    assert.ok(fs.existsSync(patchFile));
    const applyCheck = spawnSync("git", ["apply", "--check", patchFile], {
      cwd: sbx.ws,
      encoding: "utf8",
    });
    assert.equal(applyCheck.status, 0, `git apply --check failed: ${applyCheck.stderr}`);

    // Verify staged artifact file mode is read-only (`0o400`)
    const stagedCalcPath = path.join(res1.stagedBundleDir, "files", "calc.js");
    assert.equal(fs.statSync(stagedCalcPath).mode & 0o777, 0o400);

    // 2. Path traversal `txId` (`../evil`) rejected (``)
    const storeCheck = new SnapshotStore(sbx.ws, { storeDir: sbx.state });
    await storeCheck.open();
    const badTxRes = storeCheck.promoteStagedBundle("../outside", { assumeSingleWriter: true });
    assert.equal(badTxRes.ok, false);

    // 3. Turn-2 policy revocation (`do not modify calc.js` puts `calc.js` in `denySet`) blocks stale Turn-1 bundle (``)!
    storeCheck.startOrUpdateTurn("Keep calc.js unchanged; do not modify calc.js.", { sessionId: "iso1" });
    const policyBlocked = storeCheck.promoteStagedBundle(res1.txId, { assumeSingleWriter: true });
    assert.equal(policyBlocked.ok, false);
    assert.equal(policyBlocked.code, "EXPLICITLY_NEGATED_PATH");

    // Re-grant `calc.js`, then tamper staged file bytes on disk -> must fail hash verification (``)!
    storeCheck.startOrUpdateTurn("Update calc.js and no-nl.txt and add added.txt", {
      sessionId: "iso1",
      resetTask: true,
    });
    storeCheck.close();

    const res2 = await executeWrappedCommand(
      sbx.ws,
      [
        process.execPath,
        "-e",
        `require("node:fs").writeFileSync("calc.js", "export function double(x) { return Number(x) * 2; }\\n");`,
      ],
      { mode: "isolated", promoteMode: "staged", sessionId: "iso1", storeDir: sbx.state }
    );
    assert.equal(res2.ok, true, `Second isolated staging failed: ${JSON.stringify(res2)}`);
    const stagedCalc2 = path.join(res2.stagedBundleDir, "files", "calc.js");
    fs.chmodSync(path.dirname(stagedCalc2), 0o700);
    fs.chmodSync(stagedCalc2, 0o600);
    fs.writeFileSync(stagedCalc2, "export function hacked() {}\n");

    const storeTamper = new SnapshotStore(sbx.ws, { storeDir: sbx.state });
    await storeTamper.open();
    const tamperRes = storeTamper.promoteStagedBundle(res2.txId, { assumeSingleWriter: true });
    assert.equal(tamperRes.ok, false);
    assert.equal(
      fs.readFileSync(path.join(sbx.ws, "calc.js"), "utf8"),
      "export function double(x) { return x * 2; }\n"
    );
    storeTamper.close();

    // 4. Concurrent live edit before promotion -> CONCURRENT_EDIT_CONFLICT + quarantine!
    const res3 = await executeWrappedCommand(
      sbx.ws,
      [
        process.execPath,
        "-e",
        `require("node:fs").writeFileSync("calc.js", "export function double(x) { return Number(x) * 2; }\\n");`,
      ],
      { mode: "isolated", promoteMode: "staged", sessionId: "iso1", storeDir: sbx.state }
    );
    fs.writeFileSync(path.join(sbx.ws, "calc.js"), "export function double(x) { return x + x; /* user edit */ }\n");
    const store3 = new SnapshotStore(sbx.ws, { storeDir: sbx.state });
    await store3.open();
    const conflictProm = store3.promoteStagedBundle(res3.txId, { assumeSingleWriter: true });
    assert.equal(conflictProm.ok, false);
    assert.equal(conflictProm.code, "CONCURRENT_EDIT_CONFLICT");
    assert.ok(fs.existsSync(conflictProm.quarantineDir));
    assert.equal(
      fs.readFileSync(path.join(sbx.ws, "calc.js"), "utf8"),
      "export function double(x) { return x + x; /* user edit */ }\n"
    );
    store3.close();
  } finally {
    sbx.cleanup();
  }
});

test("Prompt authorization sanitizer (, , ): JSON payloads, reference clauses, without-negations, negated refactor, and RFC 6901 pointers", () => {
  // 1. Synthetic continuation flag AND raw JSON object payload grant nothing (``)
  assert.equal(
    parseAuthorizationGrants("Update package.json", { isSynthetic: true }).grants.length,
    0
  );
  assert.equal(
    parseAuthorizationGrants('{"role":"tool","message":"Update package.json and contracts/order.schema.json"}').grants.length,
    0
  );

  // 2. Reference-only mention & `without` negation (``)
  const refAndWithout = parseAuthorizationGrants(
    "Update src/app.js using package.json as reference, without having to update tsconfig.json."
  );
  assert.deepEqual(
    refAndWithout.grants.map((g) => g.pathPattern),
    ["src/app.js"]
  );
  assert.ok(refAndWithout.denySet.includes("tsconfig.json"));

  // 3. Negated `refactor` keyword must NOT inflate budget to EXPLICIT_REFACTOR (``)!
  const noRefactor = classifyIntent("Do not refactor anything. Fix typo in src/app.js.");
  assert.equal(noRefactor.tier, "SURGICAL_FIX");
  assert.equal(noRefactor.budget.maxWritableFiles, 3);

  // 4. Arbitrary RFC 6901 JSON Pointer (`/version` and `/a~1b/0`) + invalid `~2` escape refusal (``)
  const ptrGrant = parseAuthorizationGrants("Update exact pointer /version and /a~1b/0 in package.json");
  assert.equal(ptrGrant.grants.length, 1);
  assert.deepEqual(ptrGrant.grants[0].jsonPointers, ["/version", "/a~1b/0"]);
  assert.equal(ptrGrant.grants[0].exactJsonPointers, true);

  const badEscape = parseAuthorizationGrants("Update /bad~2escape in package.json");
  assert.equal(badEscape.grants.length, 0);

  // 5. Unrepresentable narrow sub-file scope (`only line 3`) refuses broad whole-file grant (``)
  const narrowLine = parseAuthorizationGrants("Modify only line 3 in package.json");
  assert.equal(narrowLine.grants.length, 0);

  // 6. Shallow Markdown section grant carries `shallowSection: true` (``)
  const shallowGrant = parseAuthorizationGrants('Update shallow section "Overview" in README.md');
  assert.equal(shallowGrant.grants.length, 1);
  assert.equal(shallowGrant.grants[0].shallowSection, true);
});

test("Code scanner & additive test guard (, , ): forward exports, multi-declarators, TS object returns, Python class methods, and pytest bypasses", () => {
  // 1. Forward JS/TS `export { f }; function f(...)` signature change (``)
  const fwdBefore = "export { compute };\nfunction compute(a: number, b: number): number { return a + b; }\n";
  const fwdMutated = "export { compute };\nfunction compute(a: string): number { return Number(a); }\n";
  assert.equal(compareCodeExports(fwdBefore, fwdMutated, "fwd.ts").ok, false);

  // 2. Multi-declarator `export const a = 1, b = (x: number) => x` (``)
  const multiBefore = "export const VERSION = 1, calc = (x: number): number => x * 2;\n";
  const multiDroppedB = "export const VERSION = 1;\n";
  assert.equal(compareCodeExports(multiBefore, multiDroppedB, "multi.ts").ok, false);

  // 3. TS object-literal return type `: { id: string; ok: boolean }` (``)
  const objRetBefore = 'export function build(): { id: string; ok: boolean } { return { id: "1", ok: true }; }\n';
  const objRetChanged = 'export function build(): { id: string } { return { id: "1" }; }\n';
  assert.equal(compareCodeExports(objRetBefore, objRetChanged, "ret.ts").ok, false);

  // 4. Invalid JS lexemes & dynamic CJS `exports[k]` return UNKNOWN (`CONSERVATION_UNCERTAIN`, ``)
  assert.equal(compareCodeExports("export const a = 1;\n", "export const a === === 1;\n", "bad.js").code, "CONSERVATION_UNCERTAIN");
  assert.equal(compareCodeExports("exports[dynamicKey] = 1;\n", "exports.fixed = 1;\n", "dyn.cjs").code, "CONSERVATION_UNCERTAIN");

  // 5. Python public class method signature & default string literal conservation (``)
  const pyClsBefore = [
    "class Ledger:",
    '    def book(self, cents: int, currency: str = "USD") -> bool:',
    "        return cents > 0",
    "",
  ].join("\n");
  const pyClsChangedDefault = pyClsBefore.replace('"USD"', '"EUR"');
  assert.equal(compareCodeExports(pyClsBefore, pyClsChangedDefault, "ledger.py").ok, false);

  // 6. Python additive test bypasses (``): semicolon import + pytest.skip, wildcard import, pytest hook, duplicate test shadowing
  const pyTestBase = "import pytest\n\ndef test_one():\n    assert 1 == 1\n";
  assert.equal(
    verifyAdditiveTestConservation(
      pyTestBase,
      'import os; pytest.skip("skip all", allow_module_level=True)\n' + pyTestBase,
      "test_a.py"
    ).ok,
    false
  );
  assert.equal(
    verifyAdditiveTestConservation(pyTestBase, "from evil_override import *\n" + pyTestBase, "test_a.py").ok,
    false
  );
  assert.equal(
    verifyAdditiveTestConservation(
      pyTestBase,
      pyTestBase + "\ndef pytest_collection_modifyitems(items):\n    items.clear()\n",
      "test_a.py"
    ).ok,
    false
  );
  assert.equal(
    verifyAdditiveTestConservation(
      pyTestBase,
      pyTestBase + "\ndef test_one():\n    assert True\n",
      "test_a.py"
    ).ok,
    false
  );

  // 7. Ungranted `tests/conftest.py` creation is blocked in FOCUSED_FEATURE, while explicitly granted `.rs` leaf file is honored (``, ``)!
  const parsedFeature = classifyIntent("Add feature and update src/engine.rs");
  const conftestEval = evaluateCandidateWriteSet(
    [
      {
        relPosix: "tests/conftest.py",
        changeType: "add",
        commandBeforeText: null,
        taskBaselineText: null,
        afterText: "import pytest\n",
      },
    ],
    {
      budget: parsedFeature.budget,
      workingSet: new Set(),
      grants: parsedFeature.grants,
      denySet: parsedFeature.denySet,
    }
  );
  assert.equal(conftestEval.ok, false);

  const rustEval = evaluateCandidateWriteSet(
    [
      {
        relPosix: "src/engine.rs",
        changeType: "modify",
        commandBeforeText: "pub fn add(a: i32, b: i32) -> i32 { a + b }\n",
        taskBaselineText: "pub fn add(a: i32, b: i32) -> i32 { a + b }\n",
        afterText: "pub fn add(a: i32, b: i32) -> i32 { a.saturating_add(b) }\n",
      },
    ],
    {
      budget: parsedFeature.budget,
      workingSet: new Set(),
      grants: parsedFeature.grants,
      denySet: parsedFeature.denySet,
    }
  );
  assert.equal(rustEval.ok, true);
});

test("Markdown, JSON Schema & Dependency Graph (, , ): schema keyword deletions, exact numeric tokens, shallow sections, list headings & self-loops", () => {
  // 1. JSON Schema: deleting `required`, deleting nested `type`, deleting `properties` key, or replacing object schema with `true` -> ALL blocked (``)!
  const baseSchema =
    '{"type":"object","required":["id"],"properties":{"id":{"type":"string"},"memo":{"type":"string"}}}\n';
  assert.equal(
    verifyJsonConservation(baseSchema, '{"type":"object","properties":{"id":{"type":"string"},"memo":{"type":"string"}}}\n', {
      isSchemaLike: true,
      wholeFileGranted: true,
    }).code,
    "JSON_SCHEMA_CONSTRAINT_MUTATED"
  );
  assert.equal(
    verifyJsonConservation(baseSchema, '{"type":"object","required":["id"],"properties":{"id":{},"memo":{"type":"string"}}}\n', {
      isSchemaLike: true,
      jsonPointers: ["/properties/id"],
    }).code,
    "JSON_SCHEMA_CONSTRAINT_MUTATED"
  );
  assert.equal(
    verifyJsonConservation(baseSchema, "true\n", {
      isSchemaLike: true,
      wholeFileGranted: true,
    }).code,
    "JSON_SCHEMA_CONSTRAINT_MUTATED"
  );

  // 2. Exact numeric token equality (`5%` -> `15%` blocked) & numeric-only sentence deletion blocked (``)!
  assert.equal(
    verifyEpistemicAndNumericAnchors("Revenue may grow 5%.\n", "Revenue may grow 15%.\n").ok,
    false
  );
  assert.equal(
    verifyEpistemicAndNumericAnchors(
      "Intro paragraph.\nGross margin was 42% in FY25.\n",
      "Intro paragraph.\n"
    ).ok,
    false
  );

  // 3. Shallow section grant blocks child subsection (`## Child`) & indented `# Heading` inside list item is ignored (``, ``)!
  const mdDoc = [
    "# Overview",
    "Parent intro.",
    "- bullet item",
    "  # Indented Fake Heading In List",
    "Still parent intro.",
    "## Subdetail",
    "Locked child detail.",
    "",
  ].join("\n");
  assert.equal(
    verifyMarkdownSectionConservation(mdDoc, mdDoc.replace("Still parent intro.", "Updated parent intro."), {
      sectionTargets: ["Overview"],
      shallowSection: true,
    }).ok,
    true
  );
  assert.equal(
    verifyMarkdownSectionConservation(mdDoc, mdDoc.replace("Locked child detail.", "Mutated child detail."), {
      sectionTargets: ["Overview"],
      shallowSection: true,
    }).ok,
    false
  );

  // 4. Dependency graph retains self-imports as singleton cyclic SCCs (``)
  const sbx = createTempSandbox("bg-selfloop-");
  try {
    fs.mkdirSync(path.join(sbx.ws, "src"), { recursive: true });
    fs.writeFileSync(path.join(sbx.ws, "src/self.ts"), 'import { x } from "./self.js";\nexport const x = 1;\n');
    const graph = buildWorkspaceDependencyGraph(sbx.ws);
    assert.equal(graph.cyclicSccs.length, 1);
    assert.deepEqual(graph.cyclicSccs[0], ["src/self.ts"]);
  } finally {
    sbx.cleanup();
  }
});

test("SnapshotStore & Recovery (, , , , , , ): external boundary, empty DB tamper, active_lock, dir modes, .git tamper & post-crash drift", async () => {
  const sbx = createTempSandbox("bg-store-hardening-");
  try {
    // 1. `storeDir` inside workspace throws `OUTSIDE_WORKSPACE_REQUIRED` (``)
    assert.throws(
      () => new SnapshotStore(sbx.ws, { storeDir: path.join(sbx.ws, ".inside-state") }),
      (err) => err.code === "OUTSIDE_WORKSPACE_REQUIRED"
    );

    // Initialize repo + directory modes + `.git` control plane
    spawnSync("git", ["init"], { cwd: sbx.ws, stdio: "pipe" });
    fs.mkdirSync(path.join(sbx.ws, "scripts"), { recursive: true, mode: 0o750 });
    fs.chmodSync(path.join(sbx.ws, "scripts"), 0o750);
    fs.mkdirSync(path.join(sbx.ws, "tests"), { recursive: true });
    fs.writeFileSync(path.join(sbx.ws, "tests/core.test.js"), "test('ok', () => {});\n");
    fs.writeFileSync(path.join(sbx.ws, "app.js"), "export const v = 1;\n");

    const store = new SnapshotStore(sbx.ws, { storeDir: sbx.state });
    await store.open();
    const s1 = store.startOrUpdateTurn("Fix app.js", { sessionId: "s-hard" });
    store.writeSessionMarker("s-hard");

    // 2. `resetTask: true` persists new `task_baseline_id` in SQLite (``)
    fs.writeFileSync(path.join(sbx.ws, "app.js"), "export const v = 2;\n");
    const sReset = store.startOrUpdateTurn("Start fresh task on app.js", {
      sessionId: "s-hard",
      resetTask: true,
    });
    assert.notEqual(sReset.taskBaselineId, s1.taskBaselineId);
    assert.equal(store.loadSession("s-hard").taskBaselineId, sReset.taskBaselineId);

    // 3. `active_lock` blocks second transaction while first is active (``)
    const tx1 = store.beginCommandTransaction({ sessionId: "s-hard", toolUseId: "tu-lock-1" });
    assert.throws(
      () => store.beginCommandTransaction({ sessionId: "s-hard", toolUseId: "tu-lock-2" }),
      (err) => err.code === "UNRECONCILED_ACTIVE_COMMAND" || err.code === "CONCURRENT_HOOK_LOCK_HELD"
    );

    // Mutate directory mode (`0o750` -> `0o777`) + violate Ring-0 -> verify directory mode restored (``)!
    fs.chmodSync(path.join(sbx.ws, "scripts"), 0o777);
    fs.unlinkSync(path.join(sbx.ws, "tests/core.test.js"));
    const recDir = store.reconcileCommandTransaction(tx1.txId);
    assert.equal(recDir.rolledBack, true);
    assert.equal(fs.statSync(path.join(sbx.ws, "scripts")).mode & 0o777, 0o750);
    assert.equal(fs.existsSync(path.join(sbx.ws, "tests/core.test.js")), true);

    // 4. `.git/info/exclude` tamper + deleted `tests/core.test.js` -> restores `tests/core.test.js` FIRST then flags GIT_METADATA_TAMPERED (``)!
    const txGit = store.beginCommandTransaction({ sessionId: "s-hard", toolUseId: "tu-git-tamper" });
    fs.unlinkSync(path.join(sbx.ws, "tests/core.test.js"));
    fs.appendFileSync(path.join(sbx.ws, ".git/info/exclude"), "\n*.secret\n");
    const gitTamperRes = store.reconcileCommandTransaction(txGit.txId);
    assert.equal(gitTamperRes.ok, false);
    assert.equal(gitTamperRes.recoveryCode, "GIT_METADATA_TAMPERED");
    // Ordinary workspace file WAS restored despite `.git` tamper!
    assert.equal(fs.existsSync(path.join(sbx.ws, "tests/core.test.js")), true);
    store.close();

    // 5. Empty replacement `state.sqlite` while `.blast-guard-session` marker exists fails closed (``)!
    fs.writeFileSync(path.join(sbx.state, "state.sqlite"), Buffer.alloc(0));
    const storeCorrupt = new SnapshotStore(sbx.ws, { storeDir: sbx.state });
    await assert.rejects(
      () => storeCorrupt.open(),
      (err) => err.code === "STATE_INTEGRITY_FAILURE"
    );

    // 6. Background descendant subshell reaped/quiesced by `spawnAndReapProcessGroup` (``)
    const markerBg = path.join(sbx.root, "late-child.txt");
    const procRes = await spawnAndReapProcessGroup(
      process.execPath,
      [
        "-e",
        `const { spawn } = require("node:child_process");
         const c = spawn(process.execPath, ["-e", "setTimeout(() => require('node:fs').writeFileSync(${JSON.stringify(markerBg)}, 'late'), 400)"], { stdio: "ignore" });
         c.unref();`,
      ],
      { cwd: sbx.ws, env: process.env, timeoutMs: 3000 }
    );
    await new Promise((r) => setTimeout(r, 500));
    assert.equal(procRes.quiescent, true);
    assert.equal(fs.existsSync(markerBg), false);
  } finally {
    sbx.cleanup();
  }
});

test("Multi-host firewall (, , , , ): structured journal, mismatched tool_use_id, sketch deny, Task journal, apply_patch anchors & version bounds", async () => {
  const sbx = createTempSandbox("bg-hosts-");
  try {
    fs.writeFileSync(path.join(sbx.ws, "package.json"), '{"name":"demo"}\n');
    fs.mkdirSync(path.join(sbx.ws, "src"), { recursive: true });
    fs.writeFileSync(path.join(sbx.ws, "src/util.js"), "export function greet(name) {\n  return 'hi ' + name;\n}\n");
    fs.writeFileSync(
      path.join(sbx.ws, "notes.md"),
      "# Allowed\nsame line\n# Protected\nsame line\n"
    );

    // 1. Out-of-range host version (`2.1.281` < `2.1.295`) governs hook execution and denies fail-closed (``)!
    const oldVerDeny = await handleHostHookEvent({
      host: "claude",
      event: "PreToolUse",
      _testHostVersionOverride: "2.1.281",
      rawStdin: JSON.stringify({
        cwd: sbx.ws,
        session_id: "cx",
        tool_use_id: "tu-ver",
        tool_name: "Read",
        tool_input: { file_path: "src/util.js" },
      }),
      storeDir: sbx.state,
    });
    assert.equal(oldVerDeny.stdoutObj?.hookSpecificOutput?.permissionDecision, "deny");
    assert.ok(oldVerDeny.stdoutObj.hookSpecificOutput.permissionDecisionReason.includes("UNTESTED_HOST_VERSION"));

    // Start bounded session granting `src/util.js` and `# Allowed` in `notes.md`
    await handleHostHookEvent({
      host: "codex",
      event: "UserPromptSubmit",
      _testHostVersionOverride: BOUNDED_CODEX_VER,
      rawStdin: JSON.stringify({
        cwd: sbx.ws,
        session_id: "cx",
        prompt: 'Fix greeting in src/util.js and update shallow section "Allowed" in notes.md',
      }),
      storeDir: sbx.state,
    });

    // 2. Codex `apply_patch` with duplicate lines under `# Allowed` vs `# Protected` + `@@ # Protected` anchor is DENIED (``)!
    const anchoredProtectedPatch = [
      "*** Begin Patch",
      "*** Update File: notes.md",
      "@@ # Protected",
      "-same line",
      "+mutated protected section",
      "*** End Patch",
    ].join("\n");
    const cxAnchorDeny = await handleHostHookEvent({
      host: "codex",
      event: "PreToolUse",
      _testHostVersionOverride: BOUNDED_CODEX_VER,
      rawStdin: JSON.stringify({
        cwd: sbx.ws,
        session_id: "cx",
        call_id: "cx-anchor-1",
        tool_name: "apply_patch",
        tool_input: { patch: anchoredProtectedPatch },
      }),
      storeDir: sbx.state,
    });
    assert.equal(cxAnchorDeny.stdoutObj?.hookSpecificOutput?.permissionDecision, "deny");

    // 3. Valid `apply_patch` opens `'ACTIVE'` journal (`call_id: "cx-allow-1"`), rejects stale `call_id` on `PostToolUse` (``), and reconciles on exact `call_id`!
    const goodPatch = [
      "*** Begin Patch",
      "*** Update File: src/util.js",
      "@@",
      " export function greet(name) {",
      "-  return 'hi ' + name;",
      "+  return 'hello, ' + name;",
      " }",
      "*** End Patch",
    ].join("\n");
    const cxAllow = await handleHostHookEvent({
      host: "codex",
      event: "PreToolUse",
      _testHostVersionOverride: BOUNDED_CODEX_VER,
      rawStdin: JSON.stringify({
        cwd: sbx.ws,
        session_id: "cx",
        call_id: "cx-allow-1",
        tool_name: "apply_patch",
        tool_input: { patch: goodPatch },
      }),
      storeDir: sbx.state,
    });
    assert.equal(cxAllow.stdoutObj, null);

    // Mismatched/stale `call_id` on `PostToolUse` MUST block (`MISMATCHED_TOOL_USE_ID`) without closing active journal (``)!
    const mismatchPost = await handleHostHookEvent({
      host: "codex",
      event: "PostToolUse",
      _testHostVersionOverride: BOUNDED_CODEX_VER,
      rawStdin: JSON.stringify({
        cwd: sbx.ws,
        session_id: "cx",
        call_id: "cx-wrong-stale-id",
        tool_name: "apply_patch",
      }),
      storeDir: sbx.state,
    });
    assert.equal(mismatchPost.stdoutObj?.decision, "block");
    assert.ok(mismatchPost.stdoutObj?.reason.includes("MISMATCHED_TOOL_USE_ID"));

    // Apply compliant change and reconcile with exact `cx-allow-1`
    fs.writeFileSync(path.join(sbx.ws, "src/util.js"), "export function greet(name) {\n  return 'hello, ' + name;\n}\n");
    const exactPost = await handleHostHookEvent({
      host: "codex",
      event: "PostToolUse",
      _testHostVersionOverride: BOUNDED_CODEX_VER,
      rawStdin: JSON.stringify({
        cwd: sbx.ws,
        session_id: "cx",
        call_id: "cx-allow-1",
        tool_name: "apply_patch",
      }),
      storeDir: sbx.state,
    });
    assert.equal(exactPost.stdoutObj, null);

    // 4. Cursor `edit_file` sketch payload (`{ target_file, instructions, code_edit }`) denied (`UNSUPPORTED_EDIT_PAYLOAD`, ``)!
    const curSketchDeny = await handleHostHookEvent({
      host: "cursor",
      event: "preToolUse",
      _testHostVersionOverride: BOUNDED_CURSOR_VER,
      rawStdin: JSON.stringify({
        cwd: sbx.ws,
        session_id: "cx",
        invocation_id: "cur-sketch-1",
        tool_name: "edit_file",
        tool_input: {
          target_file: "src/util.js",
          instructions: "rewrite file",
          code_edit: "// ... existing code ...",
        },
      }),
      storeDir: sbx.state,
    });
    assert.equal(curSketchDeny.stdoutObj?.permission, "deny");
    assert.ok(curSketchDeny.stdoutObj?.agent_message.includes("UNSUPPORTED_EDIT_PAYLOAD"));

    // 5. `Task` subagent tool opens `'ACTIVE'` journal and rolls back unauthorized subagent mutations on `PostToolUse` (``)!
    const taskPre = await handleHostHookEvent({
      host: "claude",
      event: "PreToolUse",
      _testHostVersionOverride: BOUNDED_CLAUDE_VER,
      rawStdin: JSON.stringify({
        cwd: sbx.ws,
        session_id: "cx",
        tool_use_id: "tu-task-1",
        tool_name: "Task",
        tool_input: { description: "Run helper subagent" },
      }),
      storeDir: sbx.state,
    });
    assert.equal(taskPre.stdoutObj, null);
    // Simulate subagent tampering with `package.json`!
    fs.writeFileSync(path.join(sbx.ws, "package.json"), '{"name":"tampered-by-subagent"}\n');
    const taskPost = await handleHostHookEvent({
      host: "claude",
      event: "PostToolUse",
      _testHostVersionOverride: BOUNDED_CLAUDE_VER,
      rawStdin: JSON.stringify({
        cwd: sbx.ws,
        session_id: "cx",
        tool_use_id: "tu-task-1",
        tool_name: "Task",
      }),
      storeDir: sbx.state,
    });
    assert.equal(taskPost.stdoutObj?.decision, "block");
    assert.equal(fs.readFileSync(path.join(sbx.ws, "package.json"), "utf8"), '{"name":"demo"}\n');
  } finally {
    sbx.cleanup();
  }
});

test("Git pre-commit & Dispatcher Installer (, , , , ): CJK staged paths, session selection, Python/exit-0 user hook preservation & live E2E", async () => {
  const sbx = createTempSandbox("bg-git-init-");
  try {
    const gitEnv = {
      ...process.env,
      GIT_AUTHOR_NAME: "Test User",
      GIT_AUTHOR_EMAIL: "test@example.com",
      GIT_COMMITTER_NAME: "Test User",
      GIT_COMMITTER_EMAIL: "test@example.com",
      BLAST_GUARD_STATE_DIR: sbx.state,
    };
    spawnSync("git", ["init"], { cwd: sbx.ws, env: gitEnv, stdio: "pipe" });

    // Pre-existing non-shell (`#!node`) Git pre-commit hook that writes a marker AND exits 0 (``)!
    const userHookRanMarker = path.join(sbx.root, "user-orig-hook.ran");
    const origNodeHook = `#!${process.execPath}\nrequire("node:fs").writeFileSync(${JSON.stringify(userHookRanMarker)}, "ran\\n");\nprocess.exit(0);\n`;
    const gitHookFile = path.join(sbx.ws, ".git/hooks/pre-commit");
    fs.writeFileSync(gitHookFile, origNodeHook, { mode: 0o755 });
    fs.chmodSync(gitHookFile, 0o755);

    // Pre-existing user Claude hook
    fs.mkdirSync(path.join(sbx.ws, ".claude"), { recursive: true });
    fs.writeFileSync(
      path.join(sbx.ws, ".claude/settings.json"),
      JSON.stringify(
        {
          hooks: {
            PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "echo user-hook" }] }],
          },
        },
        null,
        2
      )
    );

    // Install across all hosts
    installOrUninstallHooks(sbx.ws, { host: "all" });
    assert.ok(fs.existsSync(path.join(sbx.ws, ".git/hooks", GIT_ORIG_HOOK_FILENAME)));
    assert.equal(fs.readFileSync(path.join(sbx.ws, ".git/hooks", GIT_ORIG_HOOK_FILENAME), "utf8"), origNodeHook);

    // 1. Seed commit on unborn HEAD: clean leaf passes BlastGuard AND executes preserved `#!node` hook!
    fs.mkdirSync(path.join(sbx.ws, "contracts"), { recursive: true });
    fs.writeFileSync(path.join(sbx.ws, "item.js"), "export const x = 1;\n");
    spawnSync("git", ["add", "item.js"], { cwd: sbx.ws, env: gitEnv, stdio: "pipe" });
    const firstCommit = spawnSync("git", ["commit", "-m", "init"], {
      cwd: sbx.ws,
      env: gitEnv,
      encoding: "utf8",
    });
    assert.equal(firstCommit.status, 0, firstCommit.stderr);
    assert.equal(fs.existsSync(userHookRanMarker), true);

    // 2. Staged CJK filename `contracts/资料.json` (which Git quotes without `-z`) MUST be blocked by `git commit` (``)!
    fs.unlinkSync(userHookRanMarker);
    fs.writeFileSync(path.join(sbx.ws, "contracts/资料.json"), '{"secret":1}\n');
    spawnSync("git", ["add", "contracts/资料.json"], { cwd: sbx.ws, env: gitEnv, stdio: "pipe" });
    const cjkDenyCommit = spawnSync("git", ["commit", "-m", "sneak cjk contract"], {
      cwd: sbx.ws,
      env: gitEnv,
      encoding: "utf8",
    });
    assert.notEqual(cjkDenyCommit.status, 0);
    assert.ok((cjkDenyCommit.stderr || "").includes("[BlastGuard"));
    // Preserved user hook did NOT even run because BlastGuard rejected FIRST (``)!
    assert.equal(fs.existsSync(userHookRanMarker), false);

    // 3. Non-`"default"` session (`custom-sess-42`) unlocks `contracts/资料.json` via `.blast-guard-session` marker (``)!
    const canonicalGitWs = fs.realpathSync.native(sbx.ws);
    const resolvedGitWsStoreDir = path.join(sbx.state, computeWorkspaceId(canonicalGitWs));
    await handleHostHookEvent({
      host: "codex",
      event: "UserPromptSubmit",
      _testHostVersionOverride: BOUNDED_CODEX_VER,
      rawStdin: JSON.stringify({
        cwd: sbx.ws,
        session_id: "custom-sess-42",
        prompt: "Create contracts/资料.json",
      }),
      storeDir: resolvedGitWsStoreDir,
    });
    const cjkGrantedCommit = spawnSync("git", ["commit", "-m", "authorized cjk contract"], {
      cwd: sbx.ws,
      env: gitEnv,
      encoding: "utf8",
    });
    assert.equal(cjkGrantedCommit.status, 0, cjkGrantedCommit.stderr);
    assert.equal(fs.existsSync(userHookRanMarker), true);

    // 4. Live `inspectHostInstallations({ runLiveVerify: true })` & `runFaultInjectionSelfTests()` (``, ``)
    const osSbx = probeOsIsolationBackend();
    const faultRes = await runFaultInjectionSelfTests();
    if (osSbx.available) {
      assert.equal(faultRes.ok, true);
      const verified = await inspectHostInstallations(sbx.ws, { runLiveVerify: true, storeDir: sbx.state });
      assert.equal(verified.hosts.git.tier, "HOST_E2E_VERIFIED");
      assert.equal(verified.hosts.git.verificationEvidence.liveHostE2eOk, true);
      if (verified.hosts.claude.versionStatus !== "BOUNDED_SUPPORTED") {
        assert.equal(verified.hosts.claude.tier, "UNTESTED_HOST_VERSION");
      } else {
        assert.equal(verified.hosts.claude.tier, "ADAPTER_SELF_TESTED");
      }
      if (verified.hosts.codex.versionStatus === "BOUNDED_SUPPORTED") {
        assert.equal(verified.hosts.codex.tier, "ADAPTER_SELF_TESTED");
      }
      if (!verified.hosts.cursor.hostBinaryFound) {
        assert.equal(verified.hosts.cursor.tier, "UNTESTED_HOST_VERSION");
      }
    } else {
      // Inside a nested outer sandbox that blocks sandbox-exec, self-test MUST fail closed (``)!
      assert.equal(faultRes.ok, false);
      assert.equal(faultRes.checks.osSandboxProbeOk, false);
    }

    // 5. Corrupting an installed BlastGuard `.cursor/hooks.json` (marker present, missing failClosed & events) is caught as `DEGRADED_SELF_TEST_FAILED` (``)!
    fs.writeFileSync(
      path.join(sbx.ws, ".cursor/hooks.json"),
      '{"version":1,"hooks":{"preToolUse":[{"command":"echo broken","_managedBy":"blast-guard:managed:v1"}]}}\n'
    );
    const degradedCheck = await inspectHostInstallations(sbx.ws, { runLiveVerify: false, storeDir: sbx.state });
    assert.equal(degradedCheck.hosts.cursor.tier, "DEGRADED_SELF_TEST_FAILED");

    // 6. Clean `--uninstall` restores original `#!node` Git pre-commit byte-for-byte & preserves user Claude hook!
    installOrUninstallHooks(sbx.ws, { host: "all", uninstall: true });
    assert.equal(fs.readFileSync(gitHookFile, "utf8"), origNodeHook);
    assert.equal(fs.existsSync(path.join(sbx.ws, ".git/hooks", GIT_ORIG_HOOK_FILENAME)), false);
    const afterUninstallClaude = JSON.parse(fs.readFileSync(path.join(sbx.ws, ".claude/settings.json"), "utf8"));
    assert.equal(afterUninstallClaude.hooks.PreToolUse.length, 1);
    assert.equal(afterUninstallClaude.hooks.PreToolUse[0].hooks[0].command, "echo user-hook");
  } finally {
    sbx.cleanup();
  }
});

test("Audit CLI `--json` purity and non-Git folder handling", () => {
  const sbx = createTempSandbox("bg-audit-nongit-");
  try {
    fs.writeFileSync(path.join(sbx.ws, "AGENTS.md"), "# Rules\n");
    fs.writeFileSync(path.join(sbx.ws, "schema.json"), '{"type":"object"}\n');

    const cliRes = spawnSync(
      process.execPath,
      [BLAST_GUARD_BIN_PATH, "audit", sbx.ws, "--json"],
      {
        env: { ...process.env, BLAST_GUARD_STATE_DIR: sbx.state },
        encoding: "utf8",
      }
    );
    assert.equal(cliRes.status, 0);
    assert.equal(cliRes.stderr, "");
    const parsed = JSON.parse(cliRes.stdout);
    assert.equal(parsed.historicalHygiene.available, false);
    assert.equal(parsed.historicalHygiene.grade, "N/A");
    assert.equal(parsed.workspaceExposure.ring0ContractCount, 2);
    assert.equal(parsed.protectionStatus.overallTier, "UNPROTECTED");
    assert.ok(parsed.badge.statusText.includes("Checked"));
  } finally {
    sbx.cleanup();
  }
});

test("Audit exclusions apply to both scans without matching sibling prefixes", () => {
  const sbx = createTempSandbox("bg-audit-exclusions-");
  try {
    for (const dir of ["archive", "archive-live", "资料 旧", "nested/site-packages", "tests"]) {
      fs.mkdirSync(path.join(sbx.ws, dir), { recursive: true });
    }
    for (const dir of ["archive", "archive-live", "资料 旧", "nested/site-packages"]) {
      fs.writeFileSync(path.join(sbx.ws, dir, "package.json"), '{"name":"fixture"}\n');
      fs.writeFileSync(path.join(sbx.ws, dir, "core.mjs"), "export const x = 1;\n");
      fs.writeFileSync(path.join(sbx.ws, dir, "caller.mjs"), 'import "./core.mjs";\n');
    }
    fs.writeFileSync(path.join(sbx.ws, "tests/keep.test.js"), "test('keep', () => {});\n");
    fs.writeFileSync(path.join(sbx.ws, "bad.mjs"), '"unterminated');

    const args = [
      BLAST_GUARD_BIN_PATH, "audit", sbx.ws,
      "--exclude", "archive", "--exclude=资料 旧", "--exclude-dir", "site-packages", "--json",
    ];
    const cliRes = spawnSync(process.execPath, args, { encoding: "utf8" });
    assert.equal(cliRes.status, 0, cliRes.stderr);
    const report = JSON.parse(cliRes.stdout);
    const exposure = report.workspaceExposure;
    assert.deepEqual(exposure.exclusions, {
      paths: ["archive", "资料 旧"],
      directoryNames: ["site-packages"],
    });
    assert.equal(exposure.ring0ContractCount, 1);
    assert.equal(exposure.ring0TestSuiteCount, 1);
    assert.equal(exposure.dependencyScan.scannedCodeFiles, 4);
    assert.equal(exposure.dependencyScan.unparsedFiles, 1);
    assert.deepEqual(exposure.dependencyScan.problemFileSamples.unparsed, ["bad.mjs"]);
    assert.equal(exposure.topHighFanInModules[0].file, "archive-live/core.mjs");
    assert.match(report.badge.statusText, /Partial Scan/);
    assert.match(renderAuditTerminalCard(report, { useColor: false }), /Dependency Scan.*PARTIAL/);
    assert.match(renderAuditSvgScorecard(report), /Dependency scan: .*PARTIAL/);

    for (const invalid of [["--exclude"], ["--exclude", "../outside"], ["--exclude-dir", "a/b"]]) {
      const invalidRes = spawnSync(process.execPath, [BLAST_GUARD_BIN_PATH, "audit", sbx.ws, ...invalid], {
        encoding: "utf8",
      });
      assert.equal(invalidRes.status, 2);
      assert.match(invalidRes.stderr, /exclu/i);
    }
  } finally {
    sbx.cleanup();
  }
});

test("Audit reports workspace and dependency limits independently", async () => {
  const sbx = createTempSandbox("bg-audit-coverage-");
  try {
    for (const maxFiles of [-1, 1.5, NaN, Infinity]) {
      assert.throws(() => buildWorkspaceDependencyGraph(sbx.ws, { maxFiles }), /non-negative safe integer/);
    }
    fs.mkdirSync(path.join(sbx.ws, "files"));
    for (let i = 0; i < 2001; i++) {
      fs.writeFileSync(path.join(sbx.ws, "files", `code-${i}.js`), "");
    }
    for (let i = 0; i < 7999; i++) {
      fs.writeFileSync(path.join(sbx.ws, "files", `note-${i}.txt`), "");
    }

    const graphLimited = await auditRepository(sbx.ws);
    assert.equal(graphLimited.workspaceExposure.scannedWorkspaceFiles, 10000);
    assert.equal(graphLimited.workspaceExposure.workspaceScan.truncated, false);
    assert.equal(graphLimited.workspaceExposure.dependencyScan.scannedCodeFiles, 2000);
    assert.equal(graphLimited.workspaceExposure.dependencyScan.truncated, true);
    assert.match(graphLimited.badge.statusText, /Partial Scan/);
    assert.match(renderAuditTerminalCard(graphLimited, { useColor: false }), /Dependency Scan.*PARTIAL/);
    assert.match(renderAuditSvgScorecard(graphLimited), /Dependency scan: .*PARTIAL/);

    fs.unlinkSync(path.join(sbx.ws, "files/code-2000.js"));
    const atGraphLimit = await auditRepository(sbx.ws);
    assert.equal(atGraphLimit.workspaceExposure.dependencyScan.scannedCodeFiles, 2000);
    assert.equal(atGraphLimit.workspaceExposure.dependencyScan.truncated, false);

    fs.writeFileSync(path.join(sbx.ws, "files/extra-a.txt"), "");
    fs.writeFileSync(path.join(sbx.ws, "files/extra-b.txt"), "");
    const workspaceLimited = await auditRepository(sbx.ws);
    assert.equal(workspaceLimited.workspaceExposure.workspaceScan.truncated, true);
    assert.equal(workspaceLimited.workspaceExposure.dependencyScan.truncated, false);
    assert.match(renderAuditTerminalCard(workspaceLimited, { useColor: false }), /Workspace Scan.*PARTIAL/);
    assert.match(workspaceLimited.badge.statusText, /Partial Scan/);
  } finally {
    sbx.cleanup();
  }
});

test("Full 24-case BlastBench adversarial & zero-FP suite passes 100%", async (t) => {
  const osSbx = probeOsIsolationBackend();
  if (!osSbx.available) {
    t.skip(`OS isolation backend unavailable: ${osSbx.reason}`);
    return;
  }
  const report = await runBenchDirect();
  assert.equal(report.allPassed, true);
  assert.equal(report.comparison.blastGuard.unrecoveredDamage, 0);
  assert.equal(report.comparison.blastGuard.falsePositivesOnLegitWork, "0/4");
  assert.equal(report.denominators.totalCases, 24);
});

test("Round-2 Regression A (, /02/03, , , , ): EEXIST non-destructive compensation, root/marker/git-dir coverage, no-progress drift quarantine, live lock preservation, detached child reaping & CRLF/binary git patches", async (t) => {
  const osSbx = probeOsIsolationBackend();
  const sbx = createTempSandbox("bg-r2-sys-");
  try {
    spawnSync("git", ["init"], { cwd: sbx.ws, stdio: "pipe" });
    fs.chmodSync(sbx.ws, 0o755);
    fs.writeFileSync(path.join(sbx.ws, "base.js"), "export const x = 1;\n");

    // 1. `` & ``: `chmod 0777 .`, `.blast-guard-session` tamper, and `chmod 0777 .git`
    {
      const store = new SnapshotStore(sbx.ws, { storeDir: sbx.state });
      await store.open();
      store.startOrUpdateTurn("Fix base.js", { sessionId: "r2-root" });
      store.writeSessionMarker("r2-root");
      store.close();

      // 1a. `chmod 0777 .` inside checkpoint wrapper MUST be detected and rolled back to `0o755`!
      const rootChmodRes = await executeWrappedCommand(
        sbx.ws,
        ["chmod", "0777", "."],
        { mode: "checkpoint", sessionId: "r2-root", storeDir: sbx.state }
      );
      assert.equal(rootChmodRes.ok, false);
      assert.equal(rootChmodRes.rolledBack, true);
      assert.equal(fs.statSync(sbx.ws).mode & 0o777, 0o755);

      // 1b. Deleting `.blast-guard-session` inside checkpoint wrapper MUST be detected and restored!
      const origMarker = fs.readFileSync(path.join(sbx.ws, ".blast-guard-session"), "utf8");
      const markerDelRes = await executeWrappedCommand(
        sbx.ws,
        [process.execPath, "-e", 'require("node:fs").unlinkSync(".blast-guard-session")'],
        { mode: "checkpoint", sessionId: "r2-root", storeDir: sbx.state }
      );
      assert.equal(markerDelRes.ok, false);
      assert.equal(markerDelRes.rolledBack, true);
      assert.equal(fs.readFileSync(path.join(sbx.ws, ".blast-guard-session"), "utf8"), origMarker);

      // 1c. `chmod 0777 .git` changes Git root directory mode -> flagged as `GIT_METADATA_TAMPERED`!
      const origGitMode = fs.statSync(path.join(sbx.ws, ".git")).mode & 0o777;
      const targetGitMode = origGitMode === 0o777 ? "0700" : "0777";
      const gitDirChmod = await executeWrappedCommand(
        sbx.ws,
        ["chmod", targetGitMode, ".git"],
        { mode: "checkpoint", sessionId: "r2-root", storeDir: sbx.state }
      );
      assert.equal(gitDirChmod.ok, false);
      assert.equal(gitDirChmod.recoveryCode, "GIT_METADATA_TAMPERED");
      fs.chmodSync(path.join(sbx.ws, ".git"), origGitMode);
    }

    // 2. ``: `ACTIVE` transaction WITHOUT progress rows + later manual user edit -> `recoverUnfinishedTransactions()` quarantines without clobbering user edit!
    {
      const sbx4 = createTempSandbox("bg-r2-p104-");
      try {
        fs.writeFileSync(path.join(sbx4.ws, "user.js"), "export const v = 1;\n");
        const st4 = new SnapshotStore(sbx4.ws, { storeDir: sbx4.state });
        await st4.open();
        st4.startOrUpdateTurn("Fix user.js", { sessionId: "s4" });
        st4.beginCommandTransaction({ sessionId: "s4", toolUseId: "tu-4" });
        st4.close();

        // User manually edits `user.js` after wrapper died before recording any rollback progress
        fs.writeFileSync(path.join(sbx4.ws, "user.js"), "export const v = 999; // manual user edit\n");

        const st4Rec = new SnapshotStore(sbx4.ws, { storeDir: sbx4.state });
        await st4Rec.open({ allowInitialize: false });
        const rec4 = st4Rec.recoverUnfinishedTransactions();
        st4Rec.close();

        assert.equal(rec4.ok, false);
        assert.equal(rec4.recoveredTransactions[0].code, "EXTERNAL_CONCURRENT_WRITE_DETECTED");
        assert.ok(fs.existsSync(rec4.recoveredTransactions[0].quarantineDir));
        assert.equal(
          fs.readFileSync(path.join(sbx4.ws, "user.js"), "utf8"),
          "export const v = 999; // manual user edit\n"
        );
      } finally {
        sbx4.cleanup();
      }
    }

    // 3. ``: Recovery preserves live `isolated_exec` lock (`owner_pid = process.pid`) instead of deleting `active_lock`!
    {
      const sbx5 = createTempSandbox("bg-r2-p105-");
      try {
        const st5 = new SnapshotStore(sbx5.ws, { storeDir: sbx5.state });
        await st5.open();
        st5.db
          .prepare(
            `INSERT INTO active_lock (singleton, tx_id, owner_kind, session_id, tool_use_id, owner_pid, created_at)
             VALUES (1, 'iso-live', 'isolated_exec', 'default', 'iso-live', ?, ?)`
          )
          .run(process.pid, Date.now());
        const rec5 = st5.recoverUnfinishedTransactions();
        assert.equal(rec5.ok, false);
        assert.equal(rec5.code, "CONCURRENT_HOOK_LOCK_HELD");
        const remainingLocks = st5.db.prepare(`SELECT * FROM active_lock`).all();
        assert.equal(remainingLocks.length, 1);
        st5.close();
      } finally {
        sbx5.cleanup();
      }
    }

    // 4. ``: All-add staged bundle `EEXIST` collision compensates own earlier add (`first.js`) and NEVER deletes colliding external `new.txt`!
    if (osSbx.available) {
      const sbx02 = createTempSandbox("bg-r2-p002-");
      try {
        fs.writeFileSync(path.join(sbx02.ws, "keep.js"), "export const k = 1;\n");
        const st02 = new SnapshotStore(sbx02.ws, { storeDir: sbx02.state });
        await st02.open();
        st02.startOrUpdateTurn("Create first.js and new.txt", { sessionId: "s02" });
        const staged = await st02.runIsolatedCommand(
          [
            process.execPath,
            "-e",
            `const fs = require("node:fs");
             fs.writeFileSync("first.js", "export const a = 1;\\n");
             fs.writeFileSync("new.txt", "staged-version\\n");`,
          ],
          { sessionId: "s02", promoteMode: "staged" }
        );
        assert.equal(staged.ok, true);

        const prom = st02.promoteStagedBundle(staged.txId, {
          _beforeApplyEntryHook: (rel) => {
            if (rel === "new.txt") {
              fs.writeFileSync(path.join(sbx02.ws, "new.txt"), "external-precious-file\n");
            }
          },
        });
        st02.close();

        assert.equal(prom.ok, false);
        assert.equal(prom.code, "CONCURRENT_EDIT_CONFLICT");
        assert.equal(fs.existsSync(path.join(sbx02.ws, "first.js")), false);
        assert.equal(fs.existsSync(path.join(sbx02.ws, "new.txt")), true);
        assert.equal(fs.readFileSync(path.join(sbx02.ws, "new.txt"), "utf8"), "external-precious-file\n");
      } finally {
        sbx02.cleanup();
      }
    }

    // 5. ``: Detached grandchild (`{ detached: true, stdio: "ignore" }`) is reaped (`ESRCH`) before returning `quiescent: true`!
    {
      const childProgram = `
        const { spawn } = require("node:child_process");
        const child = spawn(process.execPath, ["-e", "setTimeout(() => {}, 15000)"], {
          detached: true,
          stdio: "ignore"
        });
        process.stdout.write(String(child.pid));
        child.unref();
      `;
      const result = await spawnAndReapProcessGroup(
        process.execPath,
        ["-e", childProgram],
        { cwd: sbx.ws, env: process.env }
      );
      const detachedPid = Number(result.stdout.trim());
      assert.ok(detachedPid > 0);
      let stillAlive = true;
      try {
        process.kill(detachedPid, 0);
      } catch (err) {
        if (err.code === "ESRCH") stillAlive = false;
      } finally {
        try {
          process.kill(detachedPid, "SIGKILL");
        } catch {}
      }
      if (result.enumerationAvailable) {
        assert.equal(result.quiescent, true);
        assert.equal(stillAlive, false);
      } else {
        // When outer container blocks `/bin/ps`, reaper MUST fail closed (`quiescent: false`)!
        assert.equal(result.quiescent, false);
      }
    }

    // 6. ``: CRLF preservation & binary `GIT binary patch` accepted byte-identically by `git apply`!
    {
      const sbxPatch = createTempSandbox("bg-r2-patch-");
      try {
        spawnSync("git", ["init"], { cwd: sbxPatch.ws, stdio: "pipe" });
        const crlfBefore = "old1\r\nold2\r\n";
        const crlfAfter = "old1\r\nnew2\r\n";
        fs.writeFileSync(path.join(sbxPatch.ws, "crlf.txt"), Buffer.from(crlfBefore, "binary"));
        const crlfPatch = buildUnifiedFilePatch("crlf.txt", crlfBefore, crlfAfter, { changeType: "modify" });
        assert.ok(crlfPatch.includes("\r\n"));
        const crlfPatchPath = path.join(sbxPatch.root, "crlf.patch");
        fs.writeFileSync(crlfPatchPath, Buffer.from(crlfPatch, "binary"));
        const applyCrlf = spawnSync("git", ["apply", "--whitespace=nowarn", crlfPatchPath], {
          cwd: sbxPatch.ws,
          encoding: "utf8",
        });
        assert.equal(applyCrlf.status, 0, applyCrlf.stderr);
        assert.deepEqual(fs.readFileSync(path.join(sbxPatch.ws, "crlf.txt")), Buffer.from(crlfAfter, "binary"));

        const binBytes = Buffer.from([0x00, 0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0xff]);
        const binPatch = buildUnifiedFilePatch("icon.bin", null, null, {
          changeType: "add",
          isBinary: true,
          afterBytes: binBytes,
        });
        const binPatchPath = path.join(sbxPatch.root, "bin.patch");
        fs.writeFileSync(binPatchPath, binPatch, "utf8");
        const applyBin = spawnSync("git", ["apply", binPatchPath], {
          cwd: sbxPatch.ws,
          encoding: "utf8",
        });
        assert.equal(applyBin.status, 0, applyBin.stderr);
        assert.deepEqual(fs.readFileSync(path.join(sbxPatch.ws, "icon.bin")), binBytes);
      } finally {
        sbxPatch.cleanup();
      }
    }
  } finally {
    sbx.cleanup();
  }
});

test("Round-2 Regression B (, , .., New , New , , New ): parsers, pointers, replacement templates, standalone git 3-file budget & read-only sandbox audit", async () => {
  // 1. ``: Multiline JSON envelope, `based on` reference target, and meta-mention of `refactor`
  const mlJson = classifyIntent(
    'Fix app.js. JSON payload follows\n{\n"message": "update package.json"\n}\nThanks.'
  );
  assert.deepEqual(mlJson.grants.map((g) => g.pathPattern), ["app.js"]);
  const basedOn = classifyIntent("Fix app.js based on the settings in package.json");
  assert.deepEqual(basedOn.grants.map((g) => g.pathPattern), ["app.js"]);
  const metaRefactor = classifyIntent("The word refactor occurs in the log. Fix app.js.");
  assert.equal(metaRefactor.tier, "SURGICAL_FIX");

  // 2. ``: `/dev`, `/a.b only`, and per-pointer exact merging (`/scripts exact pointer` + `/version`)
  const pDev = classifyIntent("Update package.json /dev");
  assert.deepEqual(pDev.grants[0].jsonPointers, ["/dev"]);
  const pDot = classifyIntent("Update package.json /a.b only");
  assert.deepEqual(pDot.grants[0].jsonPointers, ["/a.b"]);
  assert.equal(
    verifyJsonConservation('{"a":{"a.b":1,"danger":1}}\n', '{"a":{"a.b":1,"danger":2}}\n', {
      isSchemaLike: false,
      pointerSpecs: pDot.grants[0].pointerSpecs,
    }).ok,
    false
  );
  const pMerged = classifyIntent("Update package.json /scripts exact pointer. Update package.json /version");
  assert.equal(
    verifyJsonConservation(
      '{"version":"1.0.0","scripts":{"build":"tsc"}}\n',
      '{"version":"1.0.1","scripts":{"build":"rm -rf /"}}\n',
      {
        isSchemaLike: false,
        pointerSpecs: pMerged.grants[0].pointerSpecs,
      }
    ).ok,
    false
  );

  // 3. ``: Newly added property subtree containing `type` / `required` fails closed!
  assert.equal(
    verifyJsonConservation(
      '{"properties":{}}',
      '{"properties":{"new":{"type":"object","required":["x"]}}}',
      {
        isSchemaLike: true,
        wholeFileGranted: true,
        allowSchemaKeywords: false,
      }
    ).ok,
    false
  );

  // 4. ``: Invalid JS syntax, transitive alias, callable class field, nested CJS, and Python rebinding
  assert.equal(
    compareCodeExports("export function f(a) { return a; }", "export function f(a) { const x = ; return a; }", "a.js").ok,
    false
  );
  assert.equal(
    compareCodeExports("function f(a) {} const g=f; export {g};", "function f() {} const g=f; export {g};", "b.js").ok,
    false
  );
  assert.equal(
    compareCodeExports("export class A { f = (a) => a; }", "export class A { f = () => 1; }", "c.js").ok,
    false
  );
  assert.equal(
    compareCodeExports(
      "exports.f = function(a) {};",
      "exports.f = function(a) {};\nif (true) { exports.f = function() {}; }",
      "d.cjs"
    ).ok,
    false
  );
  assert.equal(
    compareCodeExports("def f(a):\n    return a\n", "def f(a):\n    return a\nf = None\n", "e.py").ok,
    false
  );

  // 5. ``: Python import alias collision, executable default arg, JS computed test title, and non-append prepend
  assert.equal(
    verifyAdditiveTestConservation(
      "def test_good():\n    assert False\n",
      "def test_good():\n    assert False\nfrom builtins import print as test_good\n",
      "test_a.py"
    ).ok,
    false
  );
  assert.equal(
    verifyAdditiveTestConservation(
      "def test_good():\n    assert False\n",
      "def test_good():\n    assert False\ndef test_new(x=globals().update(test_good=lambda: None)):\n    pass\n",
      "test_a.py"
    ).ok,
    false
  );
  assert.equal(
    verifyAdditiveTestConservation(
      'test("existing", () => {});\n',
      'test("existing", () => {});\ntest((process.exit(0), "new"), () => {});\n',
      "a.test.js"
    ).ok,
    false
  );
  assert.equal(
    verifyAdditiveTestConservation(
      'test("existing", () => {});\n',
      'test("prepended", () => {});\ntest("existing", () => {});\n',
      "a.test.js"
    ).ok,
    false
  );

  // 6. ``: Sentence-final numbers, `$5.`, `1e3`, `"5%\n"`, injective alignment & per-section shallow merge
  assert.equal(verifyEpistemicAndNumericAnchors("Revenue was 5.", "Revenue was 15.").ok, false);
  assert.equal(verifyEpistemicAndNumericAnchors("The cost is $5.", "The cost is $50.").ok, false);
  assert.equal(verifyEpistemicAndNumericAnchors("Growth is 1e3 units.", "Growth is 2e3 units.").ok, false);
  assert.equal(verifyEpistemicAndNumericAnchors("5%\n", "").ok, false);
  assert.equal(
    verifyEpistemicAndNumericAnchors("Revenue may grow 5%.\nProfit may grow 5%.", "Revenue may grow 5%.").ok,
    false
  );
  const secMerged = classifyIntent('Update shallow section "A" in notes.md. Update section "B" in notes.md');
  const mdSecDoc = "# A\nintro\n## ChildA\nlocked\n# B\nok\n## ChildB\nok2\n";
  assert.equal(
    verifyMarkdownSectionConservation(mdSecDoc, mdSecDoc.replace("locked", "mutated"), {
      sectionSpecs: secMerged.grants[0].sectionSpecs,
    }).ok,
    false
  );

  // 7. ``: Unknown host version fails closed (`validateSuppliedHostVersion("claude", null)`)
  assert.equal(validateSuppliedHostVersion("claude", null).ok, false);
  assert.equal(validateSuppliedHostVersion("claude", null).code, "UNTESTED_HOST_VERSION");

  // 8. ``, ``, `New `: Identical anchor/removal `apply_patch`, `$&`/`$$` Edit templates, and deleting BOTH state + marker!
  const sbx = createTempSandbox("bg-r2-hooks-");
  try {
    fs.writeFileSync(path.join(sbx.ws, "notes.md"), "# Allowed\nsame line\n# Protected\nRevenue 5%.\nsame line\n");
    await handleHostHookEvent({
      host: "codex",
      event: "UserPromptSubmit",
      _testHostVersionOverride: BOUNDED_CODEX_VER,
      rawStdin: JSON.stringify({
        cwd: sbx.ws,
        session_id: "s-r2",
        prompt: 'Update shallow section "Allowed" in notes.md',
      }),
      storeDir: sbx.state,
    });

    // ``: `@@ same line\n-same line\n+mutated` advances past line 2 to protected occurrence on line 5 -> MUST DENY!
    const sameAnchorPatch = [
      "*** Begin Patch",
      "*** Update File: notes.md",
      "@@ same line",
      "-same line",
      "+mutated",
      "*** End Patch",
    ].join("\n");
    const rSameAnchor = await handleHostHookEvent({
      host: "codex",
      event: "PreToolUse",
      _testHostVersionOverride: BOUNDED_CODEX_VER,
      rawStdin: JSON.stringify({
        cwd: sbx.ws,
        session_id: "s-r2",
        call_id: "c-same-anchor",
        tool_name: "apply_patch",
        tool_input: { patch: sameAnchorPatch },
      }),
      storeDir: sbx.state,
    });
    assert.equal(rSameAnchor.stdoutObj?.hookSpecificOutput?.permissionDecision, "deny");

    // `New `: `$&`, `$'`, `` $` ``, and `$$` replacement strings MUST NOT expand in `Edit` simulation -> MUST DENY!
    for (const [idx, tpl] of ["$&", "$'", "$`", "$$"].entries()) {
      const rTpl = await handleHostHookEvent({
        host: "claude",
        event: "PreToolUse",
        _testHostVersionOverride: BOUNDED_CLAUDE_VER,
        rawStdin: JSON.stringify({
          cwd: sbx.ws,
          session_id: "s-r2",
          tool_use_id: `tu-tpl-${idx}`,
          tool_name: "Edit",
          tool_input: {
            file_path: "notes.md",
            old_string: "Revenue 5%.",
            new_string: tpl,
          },
        }),
        storeDir: sbx.state,
      });
      assert.equal(rTpl.stdoutObj?.hookSpecificOutput?.permissionDecision, "deny");
    }

    // ``: Delete BOTH `.blast-guard-session` AND external `sbx.state` -> next `PreToolUse` MUST fail closed with `STATE_INTEGRITY_FAILURE`!
    fs.rmSync(path.join(sbx.ws, ".blast-guard-session"), { force: true });
    fs.rmSync(sbx.state, { recursive: true, force: true });
    const rWiped = await handleHostHookEvent({
      host: "claude",
      event: "PreToolUse",
      _testHostVersionOverride: BOUNDED_CLAUDE_VER,
      rawStdin: JSON.stringify({
        cwd: sbx.ws,
        session_id: "s-r2",
        tool_use_id: "tu-after-wipe",
        tool_name: "Edit",
        tool_input: {
          file_path: "notes.md",
          old_string: "same line\n# Protected",
          new_string: "updated\n# Protected",
        },
      }),
      storeDir: sbx.state,
    });
    assert.equal(rWiped.stdoutObj?.hookSpecificOutput?.permissionDecision, "deny");
    assert.ok(rWiped.stdoutObj.hookSpecificOutput.permissionDecisionReason.includes("STATE_INTEGRITY_FAILURE"));
  } finally {
    sbx.cleanup();
  }

  // 9. `New `: Standalone Git without prior session enforces 3-file `SURGICAL_FIX` budget (4 or 13 files denied!)
  const sbxGit = createTempSandbox("bg-r2-git21-");
  try {
    spawnSync("git", ["init"], { cwd: sbxGit.ws, stdio: "pipe" });
    for (let i = 1; i <= 4; i++) {
      const f = `leaf_${i}.js`;
      fs.writeFileSync(path.join(sbxGit.ws, f), `export const v${i} = ${i};\n`);
      spawnSync("git", ["add", f], { cwd: sbxGit.ws, stdio: "pipe" });
    }
    const gRes4 = await runGitPreCommitCheck(sbxGit.ws, { storeDir: sbxGit.state });
    assert.equal(gRes4.ok, false);
    assert.equal(gRes4.exitCode, 1);
    assert.ok(gRes4.violations.some((v) => v.code === "SCOPE_BUDGET_EXCEEDED"));
  } finally {
    sbxGit.cleanup();
  }

  // 10. `New `: `blast-guard audit . --json` & `status --json` succeed with exit `0` under kernel `(deny file-write*)`!
  if (process.platform === "darwin" && probeOsIsolationBackend().available) {
    const sbxRo = createTempSandbox("bg-r2-readonly-");
    try {
      fs.writeFileSync(path.join(sbxRo.ws, "AGENTS.md"), "# Policy\n");
      const roAudit = spawnSync(
        "/usr/bin/sandbox-exec",
        [
          "-p",
          "(version 1)(allow default)(deny file-write*)",
          process.execPath,
          BLAST_GUARD_BIN_PATH,
          "audit",
          sbxRo.ws,
          "--json",
        ],
        {
          env: { ...process.env, BLAST_GUARD_STATE_DIR: path.join(sbxRo.root, "nonexistent-ro-state") },
          encoding: "utf8",
        }
      );
      assert.equal(roAudit.status, 0, `Read-only audit failed: ${roAudit.stderr}`);
      assert.equal(roAudit.stderr, "");
      const parsedRo = JSON.parse(roAudit.stdout);
      assert.equal(parsedRo.schemaVersion, "blast-guard.audit.v1");
    } finally {
      sbxRo.cleanup();
    }
  }
});

test("Round-3 Regression ( ACL+@,  unavailable ps fail-closed,  class-field/object aliases, /05 sequential force recovery)", async () => {
  // 1. Darwin ACL on workspace root when `@` (`com.apple.provenance`) masks `+` in `/bin/ls -led` (``)!
  if (process.platform === "darwin") {
    const sbxAcl = createTempSandbox("bg-r3-acl-");
    try {
      fs.writeFileSync(path.join(sbxAcl.ws, "a.js"), "export const x = 1;\n");
      const addAcl = spawnSync("/bin/chmod", ["+a", "group:everyone allow list", sbxAcl.ws], {
        encoding: "utf8",
      });
      if (addAcl.status === 0) {
        const st = new SnapshotStore(sbxAcl.ws, { storeDir: sbxAcl.state });
        await st.open();
        st.startOrUpdateTurn("Fix a.js", { sessionId: "s" });
        st.close();

        const wrapAcl = await executeWrappedCommand(
          sbxAcl.ws,
          [process.execPath, "-e", 'require("node:fs").writeFileSync("ran.txt", "ran")'],
          { mode: "checkpoint", storeDir: sbxAcl.state, sessionId: "s" }
        );
        assert.equal(wrapAcl.ok, false);
        assert.equal(wrapAcl.code, "UNSUPPORTED_METADATA_REQUIREMENT");
        assert.equal(fs.existsSync(path.join(sbxAcl.ws, "ran.txt")), false);
      }
    } finally {
      try {
        spawnSync("/bin/chmod", ["-N", sbxAcl.ws]);
      } catch {}
      sbxAcl.cleanup();
    }
  }

  // 2. Unavailable process enumeration (`_testForceEnumerationUnavailable` + real Seatbelt `(deny process-info*)`) fails closed (`quiescent: false`)!
  {
    const sbxEnum = createTempSandbox("bg-r3-enum-");
    try {
      const forced = await spawnAndReapProcessGroup(
        process.execPath,
        ["-e", "process.stdout.write('ok')"],
        { cwd: sbxEnum.ws, env: process.env, _testForceEnumerationUnavailable: true }
      );
      assert.equal(forced.enumerationAvailable, false);
      assert.equal(forced.quiescent, false);

      if (process.platform === "darwin" && probeOsIsolationBackend().available) {
        const denyProcInfo = spawnSync(
          "/usr/bin/sandbox-exec",
          [
            "-p",
            "(version 1)(allow default)(deny process-info*)",
            process.execPath,
            "--input-type=module",
            "-e",
            `import { spawnAndReapProcessGroup } from ${JSON.stringify(new URL("../src/snapshot-store.mjs", import.meta.url).href)};
             const r = await spawnAndReapProcessGroup(process.execPath, ["-e", "process.stdout.write('hi')"], { cwd: ${JSON.stringify(sbxEnum.ws)} });
             process.stdout.write(JSON.stringify({ quiescent: r.quiescent, enumerationAvailable: r.enumerationAvailable }));`,
          ],
          { encoding: "utf8" }
        );
        assert.equal(denyProcInfo.status, 0, denyProcInfo.stderr);
        const parsed = JSON.parse(denyProcInfo.stdout);
        assert.equal(parsed.enumerationAvailable, false);
        assert.equal(parsed.quiescent, false);
      }
    } finally {
      sbxEnum.cleanup();
    }
  }

  // 3. Callable class-field alias (`export class A { f = f; }`) & exported object shorthand (`export const api = { f }`) catch signature mutations (``)!
  {
    const before = "function f(a){ return a + 1; }\nexport class A { f = f; }\nconst pad1 = 1;\nconst pad2 = 2;\n";
    const safeInternalFix = "function f(a){ return a + 2; }\nexport class A { f = f; }\nconst pad1 = 1;\nconst pad2 = 2;\n";
    const after = "function f(){ return 2; }\nexport class A { f = f; }\nconst pad1 = 1;\nconst pad2 = 2;\n";
    assert.equal(compareCodeExports(before, safeInternalFix, "a.js").ok, true);
    const cmp = compareCodeExports(before, after, "a.js");
    assert.equal(cmp.ok, false);
    assert.equal(cmp.code, "PUBLIC_EXPORT_MUTATED");

    const oneLineBefore = "function f(a){};export class A {f=f;}\n";
    const oneLineAfter = "function f(){};export class A {f=f;}\n";
    assert.equal(compareCodeExports(oneLineBefore, oneLineAfter, "a.js").ok, false);

    const objBefore = "function f(a){}\nexport const api = { f };\n";
    const objAfter = "function f(){}\nexport const api = { f };\n";
    assert.equal(compareCodeExports(objBefore, objAfter, "api.js").ok, false);

    const sbxAlias = createTempSandbox("bg-r3-alias-");
    try {
      fs.writeFileSync(path.join(sbxAlias.ws, "a.js"), before);
      await handleHostHookEvent({
        host: "codex",
        event: "UserPromptSubmit",
        _testHostVersionOverride: BOUNDED_CODEX_VER,
        rawStdin: JSON.stringify({ cwd: sbxAlias.ws, session_id: "s", prompt: "Fix a small bug" }),
        storeDir: sbxAlias.state,
      });
      const editHook = await handleHostHookEvent({
        host: "codex",
        event: "PreToolUse",
        _testHostVersionOverride: BOUNDED_CODEX_VER,
        rawStdin: JSON.stringify({
          cwd: sbxAlias.ws,
          session_id: "s",
          call_id: "c-alias",
          tool_name: "Edit",
          tool_input: { file_path: "a.js", old_string: "f(a)", new_string: "f()" },
        }),
        storeDir: sbxAlias.state,
      });
      assert.equal(editHook.stdoutObj?.hookSpecificOutput?.permissionDecision, "deny");
      assert.ok(editHook.stdoutObj.hookSpecificOutput.permissionDecisionReason.includes("PUBLIC_EXPORT_MUTATED"));
    } finally {
      sbxAlias.cleanup();
    }
  }

  // 4. Sequential `recoverUnfinishedTransactions()` -> `recoverUnfinishedTransactions({ forceRestoreBaseline: true })` (``, ``)!
  {
    const sbxForce = createTempSandbox("bg-r3-force-");
    try {
      fs.writeFileSync(path.join(sbxForce.ws, "a.js"), "export const x = 1;\n");
      let s = new SnapshotStore(sbxForce.ws, { storeDir: sbxForce.state });
      await s.open();
      s.startOrUpdateTurn("Fix a.js", { sessionId: "s" });
      s.beginCommandTransaction({ sessionId: "s", toolUseId: "c1" });
      s.close();

      fs.writeFileSync(path.join(sbxForce.ws, "a.js"), "export const x = 9;\n");
      s = new SnapshotStore(sbxForce.ws, { storeDir: sbxForce.state });
      await s.open();
      const r1 = s.recoverUnfinishedTransactions();
      assert.equal(r1.ok, false);
      assert.equal(r1.code, "EXTERNAL_CONCURRENT_WRITE_DETECTED");
      assert.equal(fs.readFileSync(path.join(sbxForce.ws, "a.js"), "utf8"), "export const x = 9;\n");

      const r2 = s.recoverUnfinishedTransactions({ forceRestoreBaseline: true });
      assert.equal(r2.ok, true);
      assert.equal(r2.code, "RECOVERED_CLEAN");
      assert.equal(fs.readFileSync(path.join(sbxForce.ws, "a.js"), "utf8"), "export const x = 1;\n");
      s.close();
    } finally {
      sbxForce.cleanup();
    }
  }
});

test("Round-4 Regression ( in-place edit compensation,  repeated CLI recovery,  Codex apply_patch parity,  setsid+chdir+execve({}) lease reaping)", async () => {
  // 1. : Separate competing writer modifies `a.txt` IN PLACE and creates `z.txt` (`EEXIST`) during promotion -> BOTH survive untouched!
  if (probeOsIsolationBackend().available) {
    const sbxPromo = createTempSandbox("bg-r4-promo-");
    try {
      const s = new SnapshotStore(sbxPromo.ws, { storeDir: sbxPromo.state });
      await s.open();
      s.startOrUpdateTurn("Create files a.txt and z.txt", { sessionId: "s" });
      const staged = await s.runIsolatedCommand(
        [
          process.execPath,
          "-e",
          `const fs = require("node:fs");
           fs.writeFileSync("a.txt", "staged a\\n");
           fs.writeFileSync("z.txt", "staged z\\n");`,
        ],
        { sessionId: "s", promoteMode: "staged" }
      );
      assert.equal(staged.ok, true);

      let writerStatus = -1;
      const res = s.promoteStagedBundle(staged.txId, {
        _beforeApplyEntryHook: (relPosix) => {
          if (relPosix === "z.txt") {
            const w = spawnSync(
              process.execPath,
              [
                "-e",
                `const fs = require("node:fs");
                 fs.writeFileSync(process.argv[1], "external precious a");
                 fs.writeFileSync(process.argv[2], "external precious z");`,
                path.join(sbxPromo.ws, "a.txt"),
                path.join(sbxPromo.ws, "z.txt"),
              ],
              { encoding: "utf8" }
            );
            writerStatus = w.status;
          }
        },
      });
      assert.equal(writerStatus, 0);
      assert.equal(res.ok, false);
      assert.equal(res.code, "EXTERNAL_CONCURRENT_WRITE_DETECTED");
      assert.equal(res.rolledBack, false);
      assert.equal(fs.existsSync(path.join(sbxPromo.ws, "a.txt")), true);
      assert.equal(fs.readFileSync(path.join(sbxPromo.ws, "a.txt"), "utf8"), "external precious a");
      assert.equal(fs.readFileSync(path.join(sbxPromo.ws, "z.txt"), "utf8"), "external precious z");
      assert.equal(
        fs.readFileSync(path.join(res.quarantineDir, "live", "a.txt"), "utf8"),
        "external precious a"
      );

      // Even ordinary `rollback --recover` afterward must NOT delete `a.txt` or `z.txt` without `--force-baseline`!
      const recNoForce = s.recoverUnfinishedTransactions();
      assert.equal(recNoForce.ok, false);
      assert.equal(recNoForce.code, "EXTERNAL_CONCURRENT_WRITE_DETECTED");
      assert.equal(fs.readFileSync(path.join(sbxPromo.ws, "a.txt"), "utf8"), "external precious a");
      assert.equal(fs.readFileSync(path.join(sbxPromo.ws, "z.txt"), "utf8"), "external precious z");
      s.close();
    } finally {
      sbxPromo.cleanup();
    }
  }

  // 2. : Real `SIGKILL`-terminated child + TWO consecutive CLI `rollback --recover` runs without `--force-baseline` -> BOTH preserve live edit!
  {
    const sbxRec = createTempSandbox("bg-r4-sigkill-");
    try {
      fs.writeFileSync(path.join(sbxRec.ws, "a.js"), "export const a = 1;\n");
      const startCli = spawnSync(
        process.execPath,
        [BLAST_GUARD_BIN_PATH, "session", "start", "--dir", sbxRec.ws, "--prompt", "Fix a.js", "--json"],
        {
          env: { ...process.env, BLAST_GUARD_STATE_DIR: sbxRec.state },
          encoding: "utf8",
        }
      );
      assert.equal(startCli.status, 0, startCli.stderr);

      const killChild = spawnSync(
        process.execPath,
        [
          "--input-type=module",
          "-e",
          `import { SnapshotStore } from ${JSON.stringify(new URL("../src/snapshot-store.mjs", import.meta.url).href)};
           const st = new SnapshotStore(process.argv[1]);
           await st.open({ allowInitialize: false });
           st.beginCommandTransaction({ sessionId: "default", toolUseId: "sigkill-1" });
           process.kill(process.pid, "SIGKILL");`,
          sbxRec.ws,
        ],
        {
          env: { ...process.env, BLAST_GUARD_STATE_DIR: sbxRec.state },
          encoding: "utf8",
        }
      );
      assert.equal(killChild.signal, "SIGKILL");

      fs.writeFileSync(path.join(sbxRec.ws, "a.js"), "export const a = 999; // precious\n");

      const runCliRecover = (extraArgs = []) =>
        spawnSync(
          process.execPath,
          [BLAST_GUARD_BIN_PATH, "rollback", "--recover", "--dir", sbxRec.ws, "--json", ...extraArgs],
          {
            env: { ...process.env, BLAST_GUARD_STATE_DIR: sbxRec.state },
            encoding: "utf8",
          }
        );

      const first = runCliRecover();
      assert.notEqual(first.status, 0);
      assert.equal(JSON.parse(first.stdout).code, "EXTERNAL_CONCURRENT_WRITE_DETECTED");
      assert.equal(
        fs.readFileSync(path.join(sbxRec.ws, "a.js"), "utf8"),
        "export const a = 999; // precious\n"
      );

      const second = runCliRecover();
      assert.notEqual(second.status, 0);
      assert.equal(JSON.parse(second.stdout).code, "EXTERNAL_CONCURRENT_WRITE_DETECTED");
      assert.equal(
        fs.readFileSync(path.join(sbxRec.ws, "a.js"), "utf8"),
        "export const a = 999; // precious\n"
      );

      const forced = runCliRecover(["--force-baseline"]);
      assert.equal(forced.status, 0, forced.stderr);
      assert.equal(JSON.parse(forced.stdout).code, "RECOVERED_CLEAN");
      assert.equal(fs.readFileSync(path.join(sbxRec.ws, "a.js"), "utf8"), "export const a = 1;\n");
    } finally {
      sbxRec.cleanup();
    }
  }

  // 3. : Codex `apply_patch` insertion-only EOF placement blocks protected-section mutation + CRLF/EOF differential parity!
  {
    const sbxPatch = createTempSandbox("bg-r4-patch-");
    try {
      const mdBase = "# Allowed\nhello\n# Protected\nlocked\n";
      fs.writeFileSync(path.join(sbxPatch.ws, "notes.md"), mdBase);

      await handleHostHookEvent({
        host: "codex",
        event: "UserPromptSubmit",
        _testHostVersionOverride: BOUNDED_CODEX_VER,
        rawStdin: JSON.stringify({
          cwd: sbxPatch.ws,
          session_id: "s",
          prompt: 'Update shallow section "Allowed" in notes.md',
        }),
        storeDir: sbxPatch.state,
      });

      const sneakPatch = "*** Begin Patch\n*** Update File: notes.md\n@@ # Allowed\n+inserted\n*** End Patch";
      const preHook = await handleHostHookEvent({
        host: "codex",
        event: "PreToolUse",
        _testHostVersionOverride: BOUNDED_CODEX_VER,
        rawStdin: JSON.stringify({
          cwd: sbxPatch.ws,
          session_id: "s",
          call_id: "call-sneak",
          tool_name: "apply_patch",
          tool_input: { patch: sneakPatch },
        }),
        storeDir: sbxPatch.state,
      });
      assert.equal(preHook.stdoutObj?.hookSpecificOutput?.permissionDecision, "deny");
      assert.ok(
        preHook.stdoutObj.hookSpecificOutput.permissionDecisionReason.includes(
          "NON_TARGET_SECTION_MUTATED"
        )
      );

      // Trailing-empty-context fallback attack (`@@ # Protected\n+inserted\n ` and `*** End of File`)
      // must insert at `cursor` inside `# Protected` (NOT EOF inside `# Allowed`) and be DENIED!
      const sbxTrail = createTempSandbox("bg-r5-trail-");
      try {
        const mdProtectedFirst = "# Protected\nlocked\n# Allowed\nhello\n";
        fs.writeFileSync(path.join(sbxTrail.ws, "notes.md"), mdProtectedFirst);
        fs.writeFileSync(path.join(sbxTrail.ws, "package.json"), '{"name":"demo","version":"1.0.0"}\n');

        await handleHostHookEvent({
          host: "codex",
          event: "UserPromptSubmit",
          _testHostVersionOverride: BOUNDED_CODEX_VER,
          rawStdin: JSON.stringify({
            cwd: sbxTrail.ws,
            session_id: "s-trail",
            prompt: 'Update shallow section "Allowed" in notes.md',
          }),
          storeDir: sbxTrail.state,
        });

        for (const [idx, badPatch] of [
          "*** Begin Patch\n*** Update File: notes.md\n@@ # Protected\n+inserted\n \n*** End Patch",
          "*** Begin Patch\n*** Update File: notes.md\n@@ # Protected\n+inserted\n \n*** End of File\n*** End Patch",
          "*** Begin Patch\n*** Update File: notes.md\n*** Move to: package.json\n@@ # Allowed\n-hello\n+world\n*** End Patch",
          "*** Begin Patch\n*** Update File: ./notes.md\n*** Move to: notes.md\n@@ # Allowed\n-hello\n+world\n*** End Patch",
        ].entries()) {
          const res = await handleHostHookEvent({
            host: "codex",
            event: "PreToolUse",
            _testHostVersionOverride: BOUNDED_CODEX_VER,
            rawStdin: JSON.stringify({
              cwd: sbxTrail.ws,
              session_id: "s-trail",
              call_id: `call-trail-${idx}`,
              tool_name: "apply_patch",
              tool_input: { patch: badPatch },
            }),
            storeDir: sbxTrail.state,
          });
          assert.equal(res.stdoutObj?.hookSpecificOutput?.permissionDecision, "deny");
        }
      } finally {
        sbxTrail.cleanup();
      }

      // Differential test cases against expected Codex `rust-v0.167.0` output (and live installed binary if available)
      const diffCases = [
        {
          init: mdBase,
          patch: "*** Begin Patch\n*** Update File: f.txt\n@@ # Allowed\n+inserted\n*** End Patch",
          expected: "# Allowed\nhello\n# Protected\nlocked\ninserted\n",
        },
        {
          init: "# Protected\nlocked\n# Allowed\nhello\n",
          patch: "*** Begin Patch\n*** Update File: f.txt\n@@ # Protected\n+inserted\n \n*** End Patch",
          expected: "# Protected\ninserted\nlocked\n# Allowed\nhello\n",
        },
        {
          init: "# Protected\nlocked\n# Allowed\nhello\n",
          patch:
            "*** Begin Patch\n*** Update File: f.txt\n@@ # Protected\n+inserted\n \n*** End of File\n*** End Patch",
          expected: "# Protected\ninserted\nlocked\n# Allowed\nhello\n",
        },
        {
          init: "line1\n\nline2\n",
          patch: "*** Begin Patch\n*** Update File: f.txt\n@@\n line1\n\n-line2\n+line2_mod\n*** End Patch",
          expected: "line1\n\nline2_mod\n",
        },
        {
          init: "one\ntwo",
          patch:
            "<<EOF\n*** Begin Patch\n*** Update File: f.txt\n@@\n one\n-two\n+three\n*** End Patch\nEOF",
          expected: "one\nthree\n",
        },
        {
          init: "one\r\ntwo\r\n",
          patch: "*** Begin Patch\n*** Update File: f.txt\n@@\n one\n-two\n+three\n*** End Patch",
          expected: "one\r\nthree\r\n",
        },
        {
          init: "# Allowed\nhello\n# Protected\nlocked\n",
          patch:
            "*** Begin Patch\n*** Update File: f.txt\n@@ # Allowed\n+eof_line\n@@\n-hello\n+world\n*** End Patch",
          expected: "# Allowed\nworld\n# Protected\nlocked\neof_line\n",
        },
        {
          init: "foo \u2014 \u201cbar\u201d\n",
          patch: '*** Begin Patch\n*** Update File: f.txt\n@@\n-foo - "bar"\n+baz\n*** End Patch',
          expected: "baz\n",
        },
      ];

      const codexBin = (process.env.CODEX_BIN || spawnSync("which", ["codex"], { encoding: "utf8" }).stdout?.trim() || path.join(os.homedir(), ".local/bin/codex"));
      const hasLiveCodex = fs.existsSync(codexBin);

      for (const dc of diffCases) {
        const sim = simulateCodexApplyPatch(sbxPatch.ws, dc.patch, () => ({ text: dc.init }));
        assert.equal(sim.ok, true, sim.reason);
        assert.equal(sim.changes[0].afterText, dc.expected);

        if (hasLiveCodex) {
          const liveDir = fs.mkdtempSync(path.join(os.tmpdir(), "bg-codex-live-"));
          try {
            fs.writeFileSync(path.join(liveDir, "f.txt"), dc.init);
            const run = spawnSync(codexBin, ["--codex-run-as-apply-patch", dc.patch], {
              cwd: liveDir,
              encoding: "utf8",
            });
            assert.equal(run.status, 0, run.stderr);
            const liveOut = fs.readFileSync(path.join(liveDir, "f.txt"), "utf8");
            assert.equal(sim.changes[0].afterText, liveOut);
          } finally {
            fs.rmSync(liveDir, { recursive: true, force: true });
          }
        }
      }
    } finally {
      sbxPatch.cleanup();
    }
  }

  // 4. : Double-fork + `setsid()` + `chdir("/")` + `dup2(/dev/null, 0..2)` + `execve(node, ..., {})` reaped (`ESRCH`, zero late writes) + isolated `!quiescent` retention!
  {
    const sbxEsc = createTempSandbox("bg-r4-esc-");
    const pidAlive = (pid) => {
      try {
        process.kill(pid, 0);
        return true;
      } catch {
        return false;
      }
    };
    let escapedPid = 0;
    try {
      const targetFile = path.join(sbxEsc.ws, "a.js");
      fs.writeFileSync(targetFile, "export const safe = 1;\n");

      const st = new SnapshotStore(sbxEsc.ws, { storeDir: sbxEsc.state });
      await st.open();
      st.startOrUpdateTurn("Fix a.js", { sessionId: "s" });

      // Direct verification of isolated `!quiescent` retention branch (`retainOpenLock = true` + `'RECOVERY_FAILED'`)!
      if (probeOsIsolationBackend().available) {
        const isoFail = await st.runIsolatedCommand(
          [process.execPath, "-e", "process.stdout.write('ok')"],
          { sessionId: "s", _testForceEnumerationUnavailable: true }
        );
        assert.equal(isoFail.ok, false);
        assert.equal(isoFail.code, "DESCENDANT_PROCESS_NOT_QUIESCENT");
        const lockRow = st.db.prepare("SELECT * FROM active_lock WHERE singleton = 1").get();
        assert.ok(lockRow, "Expected active_lock to remain retained on non-quiescent isolated run");
        const openJ = st.getUnreconciledJournals("s");
        assert.equal(openJ.length, 1);
        assert.equal(openJ[0].state, "RECOVERY_FAILED");
        // Cleanly recover before running checkpoint test
        const recClean = st.recoverUnfinishedTransactions({ forceRestoreBaseline: true });
        assert.equal(recClean.ok, true);
      }
      st.close();

      const pythonBin = fs.existsSync("/usr/bin/python3") ? "/usr/bin/python3" : "python3";
      const pyCheck = spawnSync(pythonBin, ["--version"], { encoding: "utf8" });
      if (pyCheck.status === 0) {
        const delayedNodeProg = `setTimeout(() => { require("node:fs").writeFileSync(${JSON.stringify(
          targetFile
        )}, "LATE UNAUTHORIZED WRITE\\n"); }, 350); setTimeout(() => {}, 1500);`;
        const pyEscapeProg = [
          "import os, sys",
          "pid = os.fork()",
          "if pid:",
          "    print(pid, flush=True)",
          "    os._exit(0)",
          "os.setsid()",
          'os.chdir("/")',
          'fd = os.open("/dev/null", os.O_RDWR)',
          "for d in (0, 1, 2):",
          "    os.dup2(fd, d)",
          "os.execve(sys.argv[1], [sys.argv[1], '-e', sys.argv[2]], {})",
        ].join("\n");

        const wrapRes = await executeWrappedCommand(
          sbxEsc.ws,
          [pythonBin, "-c", pyEscapeProg, process.execPath, delayedNodeProg],
          { mode: "checkpoint", storeDir: sbxEsc.state, sessionId: "s" }
        );
        escapedPid = Number(String(wrapRes.stdout || "").trim());
        assert.ok(escapedPid > 1, `Expected escaped PID in stdout, got: ${wrapRes.stdout}`);
        assert.equal(pidAlive(escapedPid), false, `Escaped PID ${escapedPid} survived reaping!`);

        await new Promise((r) => setTimeout(r, 850));
        assert.equal(fs.readFileSync(targetFile, "utf8"), "export const safe = 1;\n");
      }
    } finally {
      if (escapedPid > 1) {
        try {
          process.kill(escapedPid, "SIGKILL");
        } catch {}
      }
      sbxEsc.cleanup();
    }
  }
});

test("Round-6 Regression: missing-destination ancestor canonicalization, case-insensitive reserved namespaces, multi-op alias overlay & --format json", async () => {
  const sbxExist = createTempSandbox("bg-r6-exist-");
  const sbxFresh = createTempSandbox("bg-r6-fresh-");
  const codexBin = (process.env.CODEX_BIN || spawnSync("which", ["codex"], { encoding: "utf8" }).stdout?.trim() || path.join(os.homedir(), ".local/bin/codex"));
  const hasLiveCodex = fs.existsSync(codexBin);
  // Synthetic protocol checks invoke the internal adapter, without claiming a running Codex host.
  const invokeSyntheticHook = async (ws, stateDir, host, event, payload) => {
    const result = await handleHostHookEvent({
      host,
      event,
      _testHostVersionOverride: BOUNDED_CODEX_VER,
      rawStdin: JSON.stringify(payload),
      storeDir: stateDir,
    });
    assert.equal(result.exitCode, 0);
    return result.stdoutObj;
  };

  try {
    // 1. Existing `.codex/`, `.git/`, `tests/` with missing destination files & missing intermediate directories
    fs.mkdirSync(path.join(sbxExist.ws, ".codex"), { recursive: true });
    fs.mkdirSync(path.join(sbxExist.ws, ".git", "hooks"), { recursive: true });
    fs.mkdirSync(path.join(sbxExist.ws, "tests"), { recursive: true });
    fs.writeFileSync(path.join(sbxExist.ws, "notes.md"), "# Allowed\nhello\n# Protected\nlocked\n");

    const canonicalExist = fs.realpathSync.native(sbxExist.ws);
    if (process.platform === "darwin") {
      const iCodex = inspectWorkspacePath(canonicalExist, ".CODEX/hooks.json");
      assert.equal(iCodex.ok, true);
      assert.equal(iCodex.exists, false);
      assert.equal(iCodex.relPosix, ".codex/hooks.json");

      const iCodexSub = inspectWorkspacePath(canonicalExist, ".CODEX/missing-mid/evil.txt");
      assert.equal(iCodexSub.ok, true);
      assert.equal(iCodexSub.relPosix, ".codex/missing-mid/evil.txt");

      const iTests = inspectWorkspacePath(canonicalExist, "TESTS/helper.js");
      assert.equal(iTests.ok, true);
      assert.equal(iTests.relPosix, "tests/helper.js");

      const iTestsSub = inspectWorkspacePath(canonicalExist, "TESTS/nested/helper.js");
      assert.equal(iTestsSub.ok, true);
      assert.equal(iTestsSub.relPosix, "tests/nested/helper.js");
    }

    if (hasLiveCodex) {
      await invokeSyntheticHook(sbxExist.ws, sbxExist.state, "codex", "UserPromptSubmit", {
        cwd: sbxExist.ws,
        session_id: "s-exist",
        prompt: 'Update shallow section "Allowed" in notes.md',
      });
    } else {
      await handleHostHookEvent({
        host: "codex",
        event: "UserPromptSubmit",
        _testHostVersionOverride: BOUNDED_CODEX_VER,
        rawStdin: JSON.stringify({
          cwd: sbxExist.ws,
          session_id: "s-exist",
          prompt: 'Update shallow section "Allowed" in notes.md',
        }),
        storeDir: sbxExist.state,
      });
    }

    const existingDirAliasProbes = [
      { target: ".CODEX/hooks.json", body: "+{}", expectedCode: "IMMUTABLE_INFRA_PROTECTED" },
      { target: ".CODEX/evil.txt", body: "+evil", expectedCode: "IMMUTABLE_INFRA_PROTECTED" },
      { target: ".CODEX/sub/nested/evil.txt", body: "+evil", expectedCode: "IMMUTABLE_INFRA_PROTECTED" },
      { target: ".GIT/hooks/pre-commit", body: "+#!/bin/sh\n+exit 0", expectedCode: "IMMUTABLE_INFRA_PROTECTED" },
      { target: "TESTS/helper.js", body: "+process.exit(0);", expectedCode: "TEST_TAMPERING_BLOCKED" },
      { target: "TESTS/nested/helper.js", body: "+process.exit(0);", expectedCode: "TEST_TAMPERING_BLOCKED" },
    ];

    for (const [idx, p] of existingDirAliasProbes.entries()) {
      const patch = `*** Begin Patch\n*** Add File: ${p.target}\n${p.body}\n*** End Patch`;
      let outObj;
      if (hasLiveCodex) {
        outObj = await invokeSyntheticHook(sbxExist.ws, sbxExist.state, "codex", "PreToolUse", {
          cwd: sbxExist.ws,
          session_id: "s-exist",
          call_id: `r6-exist-${idx}`,
          tool_name: "apply_patch",
          tool_input: { patch },
        });
      } else {
        const res = await handleHostHookEvent({
          host: "codex",
          event: "PreToolUse",
          _testHostVersionOverride: BOUNDED_CODEX_VER,
          rawStdin: JSON.stringify({
            cwd: sbxExist.ws,
            session_id: "s-exist",
            call_id: `r6-exist-${idx}`,
            tool_name: "apply_patch",
            tool_input: { patch },
          }),
          storeDir: sbxExist.state,
        });
        outObj = res.stdoutObj;
      }
      assert.equal(outObj?.hookSpecificOutput?.permissionDecision, "deny", `Expected deny for ${p.target}`);
      assert.ok(
        outObj.hookSpecificOutput.permissionDecisionReason.includes(p.expectedCode),
        `Expected ${p.expectedCode} for ${p.target}, got: ${outObj.hookSpecificOutput.permissionDecisionReason}`
      );
    }

    // 2. Newly created reserved namespaces (when `.codex`, `.git`, `.claude`, `.cursor`, `.husky`, `.blast-guard`, `tests` DO NOT exist yet!)
    fs.writeFileSync(path.join(sbxFresh.ws, "notes.md"), "# Allowed\nhello\n# Protected\nlocked\n");

    if (hasLiveCodex) {
      await invokeSyntheticHook(sbxFresh.ws, sbxFresh.state, "codex", "UserPromptSubmit", {
        cwd: sbxFresh.ws,
        session_id: "s-fresh",
        prompt: 'Update shallow section "Allowed" in notes.md without touching secret.txt',
      });
    } else {
      await handleHostHookEvent({
        host: "codex",
        event: "UserPromptSubmit",
        _testHostVersionOverride: BOUNDED_CODEX_VER,
        rawStdin: JSON.stringify({
          cwd: sbxFresh.ws,
          session_id: "s-fresh",
          prompt: 'Update shallow section "Allowed" in notes.md without touching secret.txt',
        }),
        storeDir: sbxFresh.state,
      });
    }

    const brandNewReservedProbes = [
      { target: ".CODEX/hooks.json", body: "+{}", expectedCode: "IMMUTABLE_INFRA_PROTECTED" },
      { target: ".CLAUDE/settings.json", body: "+{}", expectedCode: "IMMUTABLE_INFRA_PROTECTED" },
      { target: ".CURSOR/hooks.json", body: "+{}", expectedCode: "IMMUTABLE_INFRA_PROTECTED" },
      { target: ".GIT/hooks/pre-commit", body: "+#!/bin/sh", expectedCode: "IMMUTABLE_INFRA_PROTECTED" },
      { target: ".HUSKY/pre-commit", body: "+#!/bin/sh", expectedCode: "IMMUTABLE_INFRA_PROTECTED" },
      { target: ".BLAST-GUARD/override.json", body: "+{}", expectedCode: "IMMUTABLE_INFRA_PROTECTED" },
      { target: ".BLAST-GUARD-SESSION", body: "+{}", expectedCode: "IMMUTABLE_INFRA_PROTECTED" },
      { target: "TESTS/helper.js", body: "+process.exit(0);", expectedCode: "TEST_TAMPERING_BLOCKED" },
      { target: "TEST/sub/helper.js", body: "+process.exit(0);", expectedCode: "TEST_TAMPERING_BLOCKED" },
      { target: "__TESTS__/helper.js", body: "+process.exit(0);", expectedCode: "TEST_TAMPERING_BLOCKED" },
      { target: "E2E/helper.js", body: "+process.exit(0);", expectedCode: "TEST_TAMPERING_BLOCKED" },
      { target: "SECRET.TXT", body: "+bypass", expectedCode: "EXPLICITLY_NEGATED_PATH" },
    ];

    for (const [idx, p] of brandNewReservedProbes.entries()) {
      const patch = `*** Begin Patch\n*** Add File: ${p.target}\n${p.body}\n*** End Patch`;
      let outObj;
      if (hasLiveCodex) {
        outObj = await invokeSyntheticHook(sbxFresh.ws, sbxFresh.state, "codex", "PreToolUse", {
          cwd: sbxFresh.ws,
          session_id: "s-fresh",
          call_id: `r6-fresh-${idx}`,
          tool_name: "apply_patch",
          tool_input: { patch },
        });
      } else {
        const res = await handleHostHookEvent({
          host: "codex",
          event: "PreToolUse",
          _testHostVersionOverride: BOUNDED_CODEX_VER,
          rawStdin: JSON.stringify({
            cwd: sbxFresh.ws,
            session_id: "s-fresh",
            call_id: `r6-fresh-${idx}`,
            tool_name: "apply_patch",
            tool_input: { patch },
          }),
          storeDir: sbxFresh.state,
        });
        outObj = res.stdoutObj;
      }
      assert.equal(outObj?.hookSpecificOutput?.permissionDecision, "deny", `Expected deny for ${p.target}`);
      assert.ok(
        outObj.hookSpecificOutput.permissionDecisionReason.includes(p.expectedCode),
        `Expected ${p.expectedCode} for ${p.target}, got: ${outObj.hookSpecificOutput.permissionDecisionReason}`
      );
    }

    // 3. Multi-op `apply_patch` across missing case-aliased directories matches live Codex byte-for-byte
    if (process.platform === "darwin") {
      const multiAliasPatch = [
        "*** Begin Patch",
        "*** Add File: NewSub/Foo.txt",
        "+one",
        "*** Update File: NEWSUB/FOO.TXT",
        "@@",
        "-one",
        "+two",
        "*** End Patch",
      ].join("\n");
      const sim = simulateCodexApplyPatch(canonicalExist, multiAliasPatch, () => ({ text: null }));
      assert.equal(sim.ok, true, sim.reason);
      assert.equal(sim.changes.length, 1);
      assert.equal(sim.changes[0].op, "add");
      assert.equal(sim.changes[0].afterText, "two\n");

      if (hasLiveCodex) {
        const liveDir = fs.mkdtempSync(path.join(os.tmpdir(), "bg-r6-live-"));
        try {
          const run = spawnSync(codexBin, ["--codex-run-as-apply-patch", multiAliasPatch], {
            cwd: liveDir,
            encoding: "utf8",
          });
          assert.equal(run.status, 0, run.stderr);
          assert.equal(fs.readFileSync(path.join(liveDir, "NewSub/Foo.txt"), "utf8"), sim.changes[0].afterText);
        } finally {
          fs.rmSync(liveDir, { recursive: true, force: true });
        }
      }
    }

    // 4. `--format json` CLI flag produces pure valid JSON with empty stderr
    for (const sub of ["audit", "status"]) {
      const r = spawnSync(
        process.execPath,
        [BLAST_GUARD_BIN_PATH, sub, "--dir", sbxFresh.ws, "--format", "json"],
        { encoding: "utf8", env: { ...process.env, BLAST_GUARD_STATE_DIR: sbxFresh.state } }
      );
      assert.equal(r.status, 0, r.stderr);
      assert.equal(r.stderr, "");
      assert.ok(JSON.parse(r.stdout));
    }
  } finally {
    sbxExist.cleanup();
    sbxFresh.cleanup();
  }
});

test("Round-7 Regression: cancelled/transient protected writes, partial-failure prefixes & sequential namespace conflicts", async () => {
  const sbxGit = createTempSandbox("bg-r7-git-");
  const codexBin = (process.env.CODEX_BIN || spawnSync("which", ["codex"], { encoding: "utf8" }).stdout?.trim() || path.join(os.homedir(), ".local/bin/codex"));
  const hasLiveCodex = fs.existsSync(codexBin);
  // Tool payload simulation is distinct from the native apply_patch binary comparisons below.
  const invokeHook = async (ws, stateDir, event, payload) => {
    const result = await handleHostHookEvent({
      host: "codex",
      event,
      _testHostVersionOverride: BOUNDED_CODEX_VER,
      rawStdin: JSON.stringify(payload),
      storeDir: stateDir,
    });
    assert.equal(result.exitCode, 0);
    return result.stdoutObj;
  };

  try {
    spawnSync("git", ["init"], { cwd: sbxGit.ws, encoding: "utf8" });
    const hookFile = path.join(sbxGit.ws, ".git/hooks/pre-commit");
    fs.mkdirSync(path.dirname(hookFile), { recursive: true });
    fs.writeFileSync(hookFile, "#!/bin/sh\nexit 1\n", { mode: 0o755 });
    fs.chmodSync(hookFile, 0o755);
    fs.writeFileSync(path.join(sbxGit.ws, "notes.md"), "# Allowed\nhello\n# Protected\nlocked\n");
    fs.writeFileSync(path.join(sbxGit.ws, "package.json"), '{"name":"demo","version":"1.0.0"}\n');
    fs.mkdirSync(path.join(sbxGit.ws, "sub"), { recursive: true });
    fs.writeFileSync(path.join(sbxGit.ws, "sub/only.txt"), "x\n");

    await invokeHook(sbxGit.ws, sbxGit.state, "UserPromptSubmit", {
      cwd: sbxGit.ws,
      session_id: "s-r7",
      prompt: 'Update shallow section "Allowed" in notes.md',
    });

    // 1. Cancelled / transient protected writes & partial-failure exploit probes
    const cancelledAttacks = [
      {
        name: "Astra git hook overwrite + blocker.txt/child.txt partial-failure cancellation",
        patch: [
          "*** Begin Patch",
          "*** Add File: .GIT/hooks/pre-commit",
          "+#!/bin/sh",
          "+exit 0",
          "*** Add File: blocker.txt",
          "+block",
          "*** Add File: blocker.txt/child.txt",
          "+child",
          "*** Add File: .git/hooks/pre-commit",
          "+#!/bin/sh",
          "+exit 1",
          "*** End Patch",
        ].join("\n"),
        expectedCode: "IMMUTABLE_INFRA_PROTECTED",
      },
      {
        name: "Overwrite-then-restore git hook without namespace conflict",
        patch: [
          "*** Begin Patch",
          "*** Add File: .GIT/hooks/pre-commit",
          "+#!/bin/sh",
          "+exit 0",
          "*** Add File: allowed.js",
          "+export const x = 1;",
          "*** Add File: .git/hooks/pre-commit",
          "+#!/bin/sh",
          "+exit 1",
          "*** End Patch",
        ].join("\n"),
        expectedCode: "IMMUTABLE_INFRA_PROTECTED",
      },
      {
        name: "Add-then-delete .codex/hooks.json transient write",
        patch: [
          "*** Begin Patch",
          "*** Add File: .codex/hooks.json",
          "+{}",
          "*** Delete File: .codex/hooks.json",
          "*** Add File: allowed.js",
          "+export const x = 1;",
          "*** End Patch",
        ].join("\n"),
        expectedCode: "IMMUTABLE_INFRA_PROTECTED",
      },
      {
        name: "Add-then-delete .claude/settings.json transient write",
        patch: [
          "*** Begin Patch",
          "*** Add File: .claude/settings.json",
          "+{}",
          "*** Delete File: .claude/settings.json",
          "*** Add File: allowed.js",
          "+export const x = 1;",
          "*** End Patch",
        ].join("\n"),
        expectedCode: "IMMUTABLE_INFRA_PROTECTED",
      },
      {
        name: "Add-then-delete tests/helper.js transient write",
        patch: [
          "*** Begin Patch",
          "*** Add File: tests/helper.js",
          "+process.exit(0);",
          "*** Delete File: tests/helper.js",
          "*** Add File: allowed.js",
          "+export const x = 1;",
          "*** End Patch",
        ].join("\n"),
        expectedCode: "TEST_TAMPERING_BLOCKED",
      },
      {
        name: "Transient mutation of # Protected section restored later in same patch",
        patch: [
          "*** Begin Patch",
          "*** Update File: notes.md",
          "@@ # Protected",
          "-locked",
          "+TAMPERED",
          "*** Add File: blocker.txt",
          "+block",
          "*** Add File: blocker.txt/child.txt",
          "+child",
          "*** Update File: notes.md",
          "@@ # Protected",
          "-TAMPERED",
          "+locked",
          "*** End Patch",
        ].join("\n"),
        expectedCode: "NON_TARGET_SECTION_MUTATED",
      },
      {
        name: "Sequential file-as-ancestor conflict (blocker.txt -> blocker.txt/child.txt)",
        patch: [
          "*** Begin Patch",
          "*** Add File: blocker.txt",
          "+block",
          "*** Add File: blocker.txt/child.txt",
          "+child",
          "*** End Patch",
        ].join("\n"),
        expectedCode: "NOT_A_DIRECTORY_ANCESTOR",
      },
      {
        name: "Sequential created-dir conflict (dir/child.txt -> add dir)",
        patch: [
          "*** Begin Patch",
          "*** Add File: dir/child.txt",
          "+c",
          "*** Add File: dir",
          "+file",
          "*** End Patch",
        ].join("\n"),
        expectedCode: "DIRECTORY_WRITE_TARGET_UNSUPPORTED",
      },
      {
        name: "Initial directory conflict after deleting child (sub/only.txt -> delete -> add sub)",
        patch: [
          "*** Begin Patch",
          "*** Delete File: sub/only.txt",
          "*** Add File: sub",
          "+file",
          "*** End Patch",
        ].join("\n"),
        expectedCode: "FILE_DELETION_BLOCKED",
      },
    ];

    for (const [idx, atk] of cancelledAttacks.entries()) {
      const outObj = await invokeHook(sbxGit.ws, sbxGit.state, "PreToolUse", {
        cwd: sbxGit.ws,
        session_id: "s-r7",
        call_id: `r7-atk-${idx}`,
        tool_name: "apply_patch",
        tool_input: { patch: atk.patch },
      });
      assert.equal(outObj?.hookSpecificOutput?.permissionDecision, "deny", `Expected deny for: ${atk.name}`);
      assert.ok(
        outObj.hookSpecificOutput.permissionDecisionReason.includes(atk.expectedCode),
        `Expected ${atk.expectedCode} for '${atk.name}', got: ${outObj.hookSpecificOutput.permissionDecisionReason}`
      );
    }

    assert.equal(fs.readFileSync(hookFile, "utf8"), "#!/bin/sh\nexit 1\n");

    // 2. Verify live Codex also fails on sequential namespace conflicts, and succeeds on authorized delete-file-then-create-dir
    const canonicalGitWs = fs.realpathSync.native(sbxGit.ws);
    const conflictSim1 = simulateCodexApplyPatch(
      canonicalGitWs,
      "*** Begin Patch\n*** Add File: blocker.txt\n+b\n*** Add File: BLOCKER.TXT/child.txt\n+c\n*** End Patch",
      () => ({ text: null })
    );
    assert.equal(conflictSim1.ok, false);
    assert.equal(conflictSim1.code, "NOT_A_DIRECTORY_ANCESTOR");

    const conflictSim2 = simulateCodexApplyPatch(
      canonicalGitWs,
      "*** Begin Patch\n*** Add File: dir/child.txt\n+c\n*** Delete File: dir/child.txt\n*** Add File: dir\n+f\n*** End Patch",
      () => ({ text: null })
    );
    assert.equal(conflictSim2.ok, false);
    assert.equal(conflictSim2.code, "DIRECTORY_WRITE_TARGET_UNSUPPORTED");

    if (hasLiveCodex) {
      const sbxWasFile = createTempSandbox("bg-r7-wasfile-");
      try {
        fs.writeFileSync(path.join(sbxWasFile.ws, "wasfile.txt"), "old\n");
        await invokeHook(sbxWasFile.ws, sbxWasFile.state, "UserPromptSubmit", {
          cwd: sbxWasFile.ws,
          session_id: "s-wf",
          prompt: "Delete file wasfile.txt",
        });
        const validReplacePatch =
          "*** Begin Patch\n*** Delete File: wasfile.txt\n*** Add File: wasfile.txt/child.txt\n+newchild\n*** End Patch";
        const preAllow = await invokeHook(sbxWasFile.ws, sbxWasFile.state, "PreToolUse", {
          cwd: sbxWasFile.ws,
          session_id: "s-wf",
          call_id: "wf-1",
          tool_name: "apply_patch",
          tool_input: { patch: validReplacePatch },
        });
        assert.notEqual(preAllow?.hookSpecificOutput?.permissionDecision, "deny");
        const runCodex = spawnSync(codexBin, ["--codex-run-as-apply-patch", validReplacePatch], {
          cwd: sbxWasFile.ws,
          encoding: "utf8",
        });
        assert.equal(runCodex.status, 0, runCodex.stderr);
        assert.equal(fs.readFileSync(path.join(sbxWasFile.ws, "wasfile.txt/child.txt"), "utf8"), "newchild\n");
      } finally {
        sbxWasFile.cleanup();
      }
    }

    // 3. Round-8 Regression: Transient operation-prefix leases persist across PostToolUse reconciliation
    const sbxLease = createTempSandbox("bg-r8-lease-");
    try {
      for (let k = 0; k < 4; k++) {
        fs.writeFileSync(path.join(sbxLease.ws, `${k}.txt`), "old\n");
      }
      await invokeHook(sbxLease.ws, sbxLease.state, "UserPromptSubmit", {
        cwd: sbxLease.ws,
        session_id: "s-lease",
        prompt: "Fix a local bug",
      });

      const patch1 = [
        "*** Begin Patch",
        "*** Add File: 0.txt",
        "+changed",
        "*** Add File: 0.txt",
        "+old",
        "*** Add File: 1.txt",
        "+changed",
        "*** Add File: 1.txt",
        "+old",
        "*** Add File: 2.txt",
        "+changed",
        "*** End Patch",
      ].join("\n");

      const pre1 = await invokeHook(sbxLease.ws, sbxLease.state, "PreToolUse", {
        cwd: sbxLease.ws,
        session_id: "s-lease",
        call_id: "lease-call-1",
        tool_name: "apply_patch",
        tool_input: { patch: patch1 },
      });
      assert.notEqual(pre1?.hookSpecificOutput?.permissionDecision, "deny");

      if (hasLiveCodex) {
        const exec1 = spawnSync(codexBin, ["--codex-run-as-apply-patch", patch1], {
          cwd: sbxLease.ws,
          encoding: "utf8",
        });
        assert.equal(exec1.status, 0, exec1.stderr);
      } else {
        fs.writeFileSync(path.join(sbxLease.ws, "2.txt"), "changed\n");
      }

      const post1 = await invokeHook(sbxLease.ws, sbxLease.state, "PostToolUse", {
        cwd: sbxLease.ws,
        session_id: "s-lease",
        call_id: "lease-call-1",
        tool_name: "apply_patch",
        tool_input: { patch: patch1 },
      });
      assert.notEqual(post1?.decision, "block");

      // Second patch touching 4th file `3.txt` MUST be denied because `0.txt`, `1.txt`, `2.txt` consumed all 3 SURGICAL_FIX leases!
      const patch2 = ["*** Begin Patch", "*** Add File: 3.txt", "+changed", "*** End Patch"].join("\n");
      const pre2 = await invokeHook(sbxLease.ws, sbxLease.state, "PreToolUse", {
        cwd: sbxLease.ws,
        session_id: "s-lease",
        call_id: "lease-call-2",
        tool_name: "apply_patch",
        tool_input: { patch: patch2 },
      });
      assert.equal(pre2?.hookSpecificOutput?.permissionDecision, "deny");
      assert.ok(pre2.hookSpecificOutput.permissionDecisionReason.includes("SCOPE_BUDGET_EXCEEDED"));
    } finally {
      sbxLease.cleanup();
    }

    // 4. Round-9 Regression: Failed tool execution before first write (zero filesystem diffs) must NOT pollute working_set_json
    const sbxFailZero = createTempSandbox("bg-r9-fail-zero-");
    try {
      for (let k = 0; k < 4; k++) {
        fs.writeFileSync(path.join(sbxFailZero.ws, `${k}.txt`), "old\n");
      }
      fs.chmodSync(path.join(sbxFailZero.ws, "0.txt"), 0o444);

      await invokeHook(sbxFailZero.ws, sbxFailZero.state, "UserPromptSubmit", {
        cwd: sbxFailZero.ws,
        session_id: "s-fail-zero",
        prompt: "Fix a local bug",
      });

      const failPatch = [
        "*** Begin Patch",
        "*** Add File: 0.txt",
        "+changed",
        "*** Add File: 0.txt",
        "+old",
        "*** Add File: 1.txt",
        "+changed",
        "*** Add File: 1.txt",
        "+old",
        "*** Add File: 2.txt",
        "+changed",
        "*** End Patch",
      ].join("\n");

      const preFail = await invokeHook(sbxFailZero.ws, sbxFailZero.state, "PreToolUse", {
        cwd: sbxFailZero.ws,
        session_id: "s-fail-zero",
        call_id: "fail-zero-1",
        tool_name: "apply_patch",
        tool_input: { patch: failPatch },
      });
      assert.notEqual(preFail?.hookSpecificOutput?.permissionDecision, "deny");

      if (hasLiveCodex) {
        const execFail = spawnSync(codexBin, ["--codex-run-as-apply-patch", failPatch], {
          cwd: sbxFailZero.ws,
          encoding: "utf8",
        });
        assert.notEqual(execFail.status, 0);
      }

      const postFail = await invokeHook(sbxFailZero.ws, sbxFailZero.state, "PostToolUseFailure", {
        cwd: sbxFailZero.ws,
        session_id: "s-fail-zero",
        call_id: "fail-zero-1",
        tool_name: "apply_patch",
        tool_input: { patch: failPatch },
      });
      assert.notEqual(postFail?.decision, "block");

      // Because the failed command modified zero files, `3.txt` MUST still be allowed!
      const editThreePatch = ["*** Begin Patch", "*** Add File: 3.txt", "+changed", "*** End Patch"].join("\n");
      const preThree = await invokeHook(sbxFailZero.ws, sbxFailZero.state, "PreToolUse", {
        cwd: sbxFailZero.ws,
        session_id: "s-fail-zero",
        call_id: "fail-zero-2",
        tool_name: "apply_patch",
        tool_input: { patch: editThreePatch },
      });
      assert.notEqual(preThree?.hookSpecificOutput?.permissionDecision, "deny");
    } finally {
      try {
        fs.chmodSync(path.join(sbxFailZero.ws, "0.txt"), 0o644);
      } catch {}
      sbxFailZero.cleanup();
    }
  } finally {
    sbxGit.cleanup();
  }
});
