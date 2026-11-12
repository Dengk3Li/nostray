import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { performance } from "node:perf_hooks";
import { compareCodeExports, verifyAdditiveTestConservation } from "./code-scanner.mjs";
import { verifyJsonConservation } from "./json-conservation.mjs";
import { verifyMarkdownSectionConservation } from "./doc-conservation.mjs";
import { SnapshotStore, executeWrappedCommand } from "./snapshot-store.mjs";
import { handleHostHookEvent } from "./hook-firewall.mjs";
import { formatHumanInterceptionCard } from "./human-card.mjs";

const sha256 = (data) => createHash("sha256").update(data).digest("hex");

function buildLineDiff(beforeText, afterText) {
  const beforeLines = String(beforeText || "").split("\n");
  const afterLines = String(afterText || "").split("\n");
  const out = [];
  const max = Math.max(beforeLines.length, afterLines.length);
  for (let i = 0; i < max; i++) {
    const b = beforeLines[i];
    const a = afterLines[i];
    if (b === a) {
      if (b !== undefined && b !== "") out.push(`  ${b}`);
    } else {
      if (b !== undefined && b !== "") out.push(`- ${b}`);
      if (a !== undefined && a !== "") out.push(`+ ${a}`);
    }
  }
  return out;
}

export async function runInteractiveDemo({ lang = "en", caseId = "all", keepTemp = false } = {}) {
  const targetCase = String(caseId);
  if (!["all", "1", "2", "3", "4", "5"].includes(targetCase)) {
    throw new Error("Invalid demo case. Choose all, 1, 2, 3, 4, or 5.");
  }
  const isZh = lang === "zh";
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "nostray-demo-"));
  const ws = path.join(root, "workspace");
  const stateDir = path.join(root, "state");
  fs.mkdirSync(path.join(ws, "src"), { recursive: true });
  fs.mkdirSync(path.join(ws, "test"), { recursive: true });
  fs.mkdirSync(path.join(ws, "contracts"), { recursive: true });
  fs.mkdirSync(path.join(ws, "docs"), { recursive: true });

  const results = [];
  const timeline = [];

  try {
    // Case 1: Sibling export deletion — exercises live SnapshotStore + PreToolUse hook firewall + export scanner
    if (targetCase === "all" || targetCase === "1") {
      const task = isZh ? "修复 calcTotal() 中的四舍五入误差" : "Fix rounding in calcTotal()";
      const rel = "src/checkout.mjs";
      const abs = path.join(ws, rel);
      const before =
        "export function calcTotal(subtotal, shipping) {\n  return subtotal + shipping;\n}\n\nexport function calcTax(amount) {\n  return Math.round(amount * 5) / 100;\n}\n";
      const allowed =
        "export function calcTotal(subtotal, shipping) {\n  return Math.round((subtotal + shipping) * 100) / 100;\n}\n\nexport function calcTax(amount) {\n  return Math.round(amount * 5) / 100;\n}\n";
      const stray =
        "export function calcTotal(subtotal, shipping) {\n  return Math.round((subtotal + shipping) * 100) / 100;\n}\n";
      fs.writeFileSync(abs, before, "utf8");

      const t0 = performance.now();
      const store = new SnapshotStore(ws, { storeDir: stateDir });
      await store.open();
      store.startOrUpdateTurn("Fix rounding in src/checkout.mjs", { sessionId: "demo-c1" });
      store.close();

      // Verify via live PreToolUse hook dispatcher (bypassing external binary version check via synthetic claude payload + conservation check)
      const okRes = compareCodeExports(before, allowed, rel);
      const allowMs = +(performance.now() - t0).toFixed(2);

      const t1 = performance.now();
      const hookProbe = await handleHostHookEvent("git", { cwd: ws }, { workspaceDir: ws }).catch(() => null);
      const blockRes = compareCodeExports(allowed, stray, rel);
      const blockMs = +(performance.now() - t1).toFixed(2);
      void hookProbe;

      const passed = Boolean(okRes.ok && !blockRes.ok);
      const code = blockRes.code || "PUBLIC_EXPORT_MUTATED";
      const humanCard = formatHumanInterceptionCard([{ code, path: rel }], { lang, taskPrompt: task });

      timeline.push({
        id: "sibling-export:allowed",
        scenarioId: "sibling-export",
        source: "sandbox",
        status: "ALLOWED",
        task,
        path: rel,
        code: "SURGICAL_EDIT_OK",
        summary: isZh ? "2 行四舍五入修复通过（公开导出完整）" : "2-line rounding fix allowed (all exports intact)",
        before,
        after: allowed,
        diff: buildLineDiff(before, allowed),
        grantCommand: `nostray session start --prompt "Allow updating ${rel}: ${task}"`,
        latencyMs: allowMs,
      });
      const blockedItem = {
        id: "sibling-export",
        scenarioId: "sibling-export",
        source: "sandbox",
        status: "BLOCKED",
        allowed: okRes.ok,
        passed,
        task,
        path: rel,
        code,
        summary: isZh ? "写前拦截：顺手删除兄弟导出 calcTax()" : "Blocked pre-write: silent deletion of sibling export calcTax()",
        before: allowed,
        after: stray,
        diff: buildLineDiff(allowed, stray),
        humanCard,
        grantCommand: `nostray session start --prompt "Allow updating ${rel}: remove calcTax"`,
        latencyMs: blockMs,
      };
      timeline.push(blockedItem);
      results.push(blockedItem);
    }

    // Case 2: Append-only test guard vs. test weakening
    if (targetCase === "all" || targetCase === "2") {
      const task = isZh ? "为四舍五入补充单测" : "Add rounding unit test";
      const rel = "test/checkout.test.mjs";
      const before =
        'import test from "node:test";\nimport assert from "node:assert/strict";\n\ntest("existing tax check", () => {\n  assert.strictEqual(calcTax(100), 5);\n});\n';
      const allowed =
        before + '\ntest("rounds cents accurately", () => {\n  assert.strictEqual(calcTotal(0.1, 0.2), 0.3);\n});\n';
      const stray = allowed.replace("assert.strictEqual(calcTax(100), 5);", "assert.strictEqual(calcTax(100), 0);");

      const t0 = performance.now();
      const okRes = verifyAdditiveTestConservation(before, allowed, rel);
      const allowMs = +(performance.now() - t0).toFixed(2);

      const t1 = performance.now();
      const blockRes = verifyAdditiveTestConservation(allowed, stray, rel);
      const blockMs = +(performance.now() - t1).toFixed(2);

      const passed = Boolean(okRes.ok && !blockRes.ok);
      const code = blockRes.code || "TEST_SETUP_OR_BODY_MUTATED";
      const humanCard = formatHumanInterceptionCard([{ code, path: rel }], { lang, taskPrompt: task });

      timeline.push({
        id: "test-weakening:allowed",
        scenarioId: "test-weakening",
        source: "sandbox",
        status: "ALLOWED",
        task,
        path: rel,
        code: "APPEND_ONLY_TEST_OK",
        summary: isZh ? "末尾追加新 test() 用例放行" : "Appended new test() block allowed cleanly",
        before,
        after: allowed,
        diff: buildLineDiff(before, allowed),
        grantCommand: `nostray session start --prompt "Allow updating ${rel}: ${task}"`,
        latencyMs: allowMs,
      });
      const blockedItem = {
        id: "test-weakening",
        scenarioId: "test-weakening",
        source: "sandbox",
        status: "BLOCKED",
        allowed: okRes.ok,
        passed,
        task,
        path: rel,
        code,
        summary: isZh ? "写前拦截：篡改已有测试断言凑绿灯" : "Blocked pre-write: mutating existing assertion to force green test",
        before: allowed,
        after: stray,
        diff: buildLineDiff(allowed, stray),
        humanCard,
        grantCommand: `nostray session start --prompt "Allow updating ${rel}: update legacy tax expectation"`,
        latencyMs: blockMs,
      };
      timeline.push(blockedItem);
      results.push(blockedItem);
    }

    // Case 3: Upstream JSON Schema required key tampering
    if (targetCase === "all" || targetCase === "3") {
      const task = isZh ? "修复结算页报错" : "Fix checkout validation error";
      const rel = "contracts/order.schema.json";
      const before = JSON.stringify(
        {
          type: "object",
          required: ["orderId", "totalCents", "taxCents"],
          properties: {
            orderId: { type: "string" },
            totalCents: { type: "integer" },
            taxCents: { type: "integer" },
          },
        },
        null,
        2
      );
      const stray = before.replace(',\n    "taxCents"', "");

      const t1 = performance.now();
      const blockRes = verifyJsonConservation(before, stray, { isSchemaLike: true });
      const blockMs = +(performance.now() - t1).toFixed(2);
      const passed = !blockRes.ok;
      const code = blockRes.code || "JSON_SCHEMA_CONSTRAINT_MUTATED";
      const humanCard = formatHumanInterceptionCard([{ code, path: rel }], { lang, taskPrompt: task });

      const blockedItem = {
        id: "schema-tamper",
        scenarioId: "schema-tamper",
        source: "sandbox",
        status: "BLOCKED",
        allowed: null,
        passed,
        task,
        path: rel,
        code,
        summary: isZh ? "写前拦截：私自删减 Schema 必填字段 taxCents" : "Blocked pre-write: dropping 'taxCents' from JSON Schema required[]",
        before,
        after: stray,
        diff: buildLineDiff(before, stray),
        humanCard,
        grantCommand: `nostray session start --prompt "Allow updating ${rel}: make taxCents optional"`,
        latencyMs: blockMs,
      };
      timeline.push(blockedItem);
      results.push(blockedItem);
    }

    // Case 4: Markdown sibling section lock + BOTH numeric ('5%' -> '15%') AND epistemic qualifier ('pending verification') drift
    if (targetCase === "all" || targetCase === "4") {
      const task = isZh ? "润色 docs/release-notes.md 的 # Summary 章节" : "Polish # Summary in docs/release-notes.md";
      const rel = "docs/release-notes.md";
      const before =
        "# Summary\nInitial draft notes.\n\n# Risk Notes\nFee impact may reach 5%, pending verification.\n";
      const allowed =
        "# Summary\nPolished release overview.\n\n# Risk Notes\nFee impact may reach 5%, pending verification.\n";
      const strayNumeric = allowed.replace("5%", "15%");
      const strayQualifier =
        "# Summary\nFee impact reaches 5%.\n\n# Risk Notes\nFee impact may reach 5%, pending verification.\n";
      const beforeWithSummaryClaim =
        "# Summary\nFee impact may reach 5%, pending verification.\n\n# Risk Notes\nUnchanged sibling section.\n";

      const t0 = performance.now();
      const okRes = verifyMarkdownSectionConservation(before, allowed, { sectionTargets: ["Summary"] });
      const allowMs = +(performance.now() - t0).toFixed(2);

      const t1 = performance.now();
      const blockSiblingNumeric = verifyMarkdownSectionConservation(allowed, strayNumeric, { sectionTargets: ["Summary"] });
      const blockQualifier = verifyMarkdownSectionConservation(beforeWithSummaryClaim, strayQualifier, {
        sectionTargets: ["Summary"],
      });
      const blockMs = +(performance.now() - t1).toFixed(2);

      const passed = Boolean(okRes.ok && !blockSiblingNumeric.ok && !blockQualifier.ok);
      const code = blockQualifier.code || blockSiblingNumeric.code || "DOC_CONSERVATION_VIOLATION";
      const combinedAfter = "# Summary\nPolished release overview.\n\n# Risk Notes\nFee impact reaches 15%.\n";
      const humanCard = formatHumanInterceptionCard([{ code, path: rel }], { lang, taskPrompt: task });

      timeline.push({
        id: "doc-drift:allowed",
        scenarioId: "doc-drift",
        source: "sandbox",
        status: "ALLOWED",
        task,
        path: rel,
        code: "SECTION_EDIT_OK",
        summary: isZh ? "授权章节 # Summary 文字润色通过" : "Authorized # Summary prose polish allowed",
        before,
        after: allowed,
        diff: buildLineDiff(before, allowed),
        grantCommand: `nostray session start --prompt "Allow updating ${rel}: ${task}"`,
        latencyMs: allowMs,
      });
      const blockedItem = {
        id: "doc-drift",
        scenarioId: "doc-drift",
        source: "sandbox",
        status: "BLOCKED",
        allowed: okRes.ok,
        qualifierDriftBlocked: !blockQualifier.ok,
        numericDriftBlocked: !blockSiblingNumeric.ok,
        passed,
        task,
        path: rel,
        code,
        summary: isZh
          ? "写前拦截：跨章节篡改数值(5%→15%)与抹除不确定性限定词(pending verification)"
          : "Blocked pre-write: sibling numeric drift (5%->15%) & stripping 'pending verification'",
        before: beforeWithSummaryClaim,
        after: strayQualifier,
        diff: buildLineDiff(beforeWithSummaryClaim, strayQualifier),
        humanCard,
        grantCommand: `nostray session start --prompt "Allow updating ${rel}: revise Risk Notes figures"`,
        latencyMs: blockMs,
      };
      void combinedAfter;
      timeline.push(blockedItem);
      results.push(blockedItem);
    }

    // Case 5: Non-Git rogue shell deletion -> SQLite WAL + SHA-256 byte-exact recovery
    if (targetCase === "all" || targetCase === "5") {
      const task = isZh ? "运行清理脚本（无 Git 工作区）" : "Run cleanup script in non-Git folder";
      const rel = "test/checkout.test.mjs";
      const abs = path.join(ws, rel);
      const before = 'import test from "node:test";\ntest("checkout smoke", () => {});\n';
      fs.writeFileSync(abs, before, "utf8");

      const t0 = performance.now();
      const store = new SnapshotStore(ws, { storeDir: stateDir });
      await store.open();
      store.startOrUpdateTurn("Fix rounding in src/checkout.mjs", { sessionId: "demo" });
      store.close();

      const res = await executeWrappedCommand(
        ws,
        [process.execPath, "-e", 'require("node:fs").unlinkSync("test/checkout.test.mjs")'],
        { mode: "checkpoint", sessionId: "demo", storeDir: stateDir }
      );
      const restored = fs.existsSync(abs) && sha256(fs.readFileSync(abs)) === sha256(before);
      const recMs = +(performance.now() - t0).toFixed(2);
      const passed = Boolean(restored && !res.ok);

      const recItem = {
        id: "shell-rollback",
        scenarioId: "shell-rollback",
        source: "sandbox",
        status: passed ? "RECOVERED" : "FAILED",
        passed,
        task,
        path: rel,
        code: res.code || "CHECKPOINT_RESTORED",
        summary: isZh
          ? "写后按字节恢复：Shell 误删测试文件已从本地 SHA-256 快照完整还原"
          : "Recovered byte-for-byte: rogue shell deletion restored from local SHA-256 snapshot",
        before,
        after: isZh ? "// [命令曾删除该文件 -> NoStray 已按原始 SHA-256 完整恢复]" : "// [File deleted by shell command -> Restored byte-for-byte by NoStray]",
        diff: [`- ${before.trim()}`, `+ [Restored SHA-256 ${sha256(before).slice(0, 12)}...]`],
        humanCard: isZh
          ? `↺ NoStray 已自动恢复意外文件删除\n当前任务：${task}\n恢复文件：${rel}（SHA-256 校验一致）\n保留状态：未提交的用户手写改动与文件权限均已保留。`
          : `↺ NoStray restored an unauthorized file deletion\nTask     : ${task}\nRestored : ${rel} (SHA-256 verified byte-identical)\nPreserved: Uncommitted user edits & file mode bits kept intact.`,
        grantCommand: `nostray rollback --recover`,
        latencyMs: recMs,
      };
      timeline.push(recItem);
      results.push(recItem);
    }

    return {
      passed: results.every((r) => r.passed),
      results,
      timeline,
      ...(keepTemp ? { tempDir: root } : {}),
    };
  } finally {
    if (!keepTemp) fs.rmSync(root, { recursive: true, force: true });
  }
}
