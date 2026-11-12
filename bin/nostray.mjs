#!/usr/bin/env node
import { startUiServer } from "../src/ui-server.mjs";
import { runInteractiveDemo } from "../src/demo-runner.mjs";
import fs from "node:fs";
import path from "node:path";
import {
  verifyRuntimeSupport,
  shouldUseColor,
} from "../src/runtime-support.mjs";
import {
  auditRepository,
  renderFirstRunSummary,
  renderAuditTerminalCard,
  renderAuditSvgScorecard,
} from "../src/repo-auditor.mjs";
import {
  installOrUninstallHooks,
  inspectHostInstallations,
  inspectStartupReadiness,
} from "../src/init-installer.mjs";
import { formatStartupReport } from "../src/readiness.mjs";
import { configureTaskVerification, readTaskVerification, verifyTaskAtStop,
  formatTaskVerification, validateTaskVerificationPlan, recordPromptAcceptanceConditions } from "../src/task-verification.mjs";
import {
  handleHostHookEvent,
  runGitPreCommitCheck,
} from "../src/hook-firewall.mjs";
import {
  SnapshotStore,
  executeWrappedCommand,
} from "../src/snapshot-store.mjs";
import {
  runBlastBench,
  renderBenchTerminalTable,
} from "../bench/blast-bench.mjs";

const PKG_VERSION = "0.1.0";

function printHelp() {
  process.stdout.write(
    [
      `nostray v${PKG_VERSION} — Deterministic Blast-Radius & Contract Guard for AI Agents`,
      ``,
      `Usage:`,
      `  nostray                          Audit the current workspace (read-only)`,
      `  nostray audit [dir] [--limit 30] [--exclude <path>]... [--exclude-dir <name>]... [--verify] [--svg <out.svg>] [--json]`,
      `  nostray init [--dir <dir>] [--host claude|codex|cursor|git|antigravity|all] [--dry-run] [--uninstall] [--wrap-shell] [--json]`,
      `  nostray status [--dir <dir>] [--host <name>] [--session <id>] [--verify] [--json]`,
      `  nostray bench [--json]`,
      `  nostray demo [--case all|1|2|3|4|5] [--lang zh|en] [--json]`,
      `  nostray ui [--port 4318] [--dir <dir>]`,
      `  nostray session start --prompt "<task>" [--session <id>] [--dir <dir>] [--reset|--reset-task] [--json]`,
      `  nostray session start --acceptance <plan.json> --prompt "<task>" [--session <id>]`,
      `  nostray session verify [--session <id>] [--force] [--json]`,
      `  nostray session status [--session <id>] [--json]`,
      `  nostray session promote <txId> [--dir <dir>] [--assume-single-writer] [--owned-worktree] [--json]`,
      `  nostray wrap [--mode checkpoint|isolated] [--check-only] [--promote staged|live] [--session <id>] [--assume-single-writer] [--owned-worktree] [--deny-network] -- <cmd> [args...]`,
      `  nostray rollback --recover [--force-baseline] [--dir <dir>] [--json]`,
      `  nostray hook --host <claude|codex|cursor|git|antigravity> [--event <EventName>] [--session <id>]`,
      ``,
      `Options:`,
      `  --help, -h       Show this help message`,
      `  --version, -v    Print package version`,
      `  --wrap-shell     Opt in to checkpoint wrapping for installed Codex shell hooks`,
      `  --exclude        Omit a workspace-relative path from audit scans (repeatable)`,
      `  --exclude-dir    Omit directories with this name from audit scans (repeatable)`,
      `  --acceptance     Explicit task conditions and isolated regression commands for this session`,
      `  Acceptance JSON example: {"conditions":[{"path":"src/amount.mjs","contains":"Math.round"}],"tests":["test/amount.test.mjs"]}`,
      `  A command test may use {"command":["python3","-m","unittest","tests.test_amount"],"paths":["src/amount.py"]}.`,
      `  Only an explicitly supplied plan authorizes its commands. Stop uses an OS sandbox and discards test writes.`,
      `  A standalone user-prompt line can declare 验收：结果.txt 包含「已完成」 or 验收：报告.md 必须存在.`,
      ``,
    ].join("\n")
  );
}

function readAllStdin() {
  try {
    return fs.readFileSync(0, "utf8");
  } catch {
    return "";
  }
}

function parseFlags(argv) {
  const positional = [];
  const flags = {};
  let doubleDashArgs = null;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--") {
      doubleDashArgs = argv.slice(i + 1);
      break;
    }
    if (arg.startsWith("--")) {
      const eqIdx = arg.indexOf("=");
      let key;
      let value;
      if (eqIdx !== -1) {
        key = arg.slice(2, eqIdx);
        value = arg.slice(eqIdx + 1);
      } else {
        key = arg.slice(2);
        const next = argv[i + 1];
        if (next !== undefined && !next.startsWith("--")) {
          value = next;
          i++;
        } else {
          value = true;
        }
      }
      if (key === "exclude" || key === "exclude-dir") {
        if (!flags[key]) flags[key] = [];
        flags[key].push(value);
      } else {
        flags[key] = value;
      }
    } else if (arg === "-h") {
      flags.help = true;
    } else if (arg === "-v") {
      flags.version = true;
    } else {
      positional.push(arg);
    }
  }

  return { positional, flags, doubleDashArgs };
}

async function main() {
  const runtime = verifyRuntimeSupport();
  if (!runtime.ok) {
    process.stderr.write(`[blast-guard ${runtime.code}] ${runtime.reason}\n`);
    process.exit(2);
  }

  const rawArgs = process.argv.slice(2);
  const { positional, flags, doubleDashArgs } = parseFlags(rawArgs);
  if (typeof flags.format === "string" && flags.format.toLowerCase() === "json") {
    flags.json = true;
  }
  const subcmd = positional[0] || "audit";

  if (flags.version) {
    process.stdout.write(`${PKG_VERSION}\n`);
    return;
  }

  if (flags.help || subcmd === "help") {
    printHelp();
    return;
  }
  if (!positional.length && (flags.verify || flags.svg)) {
    throw new Error("Use the explicit audit command with --verify or --svg. The default analysis is read-only.");
  }
  const inspectHost = flags.host ?? null;
  const inspectSession = flags.session ?? null;
  if (["audit", "status", "verify", "session"].includes(subcmd)) {
    if (inspectHost !== null && !["codex", "claude", "antigravity", "cursor", "git"].includes(inspectHost)) {
      throw new Error("--host requires codex, claude, antigravity, cursor or git.");
    }
    if (inspectSession !== null && (typeof inspectSession !== "string" || !inspectSession.trim())) throw new Error("--session requires a session ID.");
  }

  if (subcmd === "ui") {
    const ui = await startUiServer({ dir: typeof flags.dir === "string" ? flags.dir : process.cwd(), port: flags.port === undefined ? 4318 : Number(flags.port) });
    if (flags["json-once"]) { process.stdout.write(JSON.stringify(ui.state) + "\n"); await new Promise(resolve => ui.server.close(resolve)); }
    else process.stdout.write(`NoStray Studio: http://127.0.0.1:${ui.port}/\n`);
    return;
  }

  if (subcmd === "demo") {
    const lang = flags.lang === "zh" ? "zh" : "en";
    const result = await runInteractiveDemo({ lang, caseId: String(flags.case || "all"), keepTemp: Boolean(flags["keep-temp"]) });
    if (flags.json) {
      process.stdout.write(JSON.stringify(result, null, 2) + "\n");
    } else {
      const color = shouldUseColor();
      const g = color ? "\x1b[32m" : "", rCol = color ? "\x1b[31m" : "", bCol = color ? "\x1b[36m" : "", dim = color ? "\x1b[2m" : "", rst = color ? "\x1b[0m" : "";
      for (const item of result.timeline || result.results) {
        const icon = item.status === "ALLOWED" ? `${g}✓ ALLOWED${rst}` : item.status === "RECOVERED" ? `${bCol}↺ RECOVERED${rst}` : `${rCol}✗ BLOCKED${rst}`;
        process.stdout.write(`\n${icon} ${item.path} ${dim}(${item.latencyMs} ms)${rst} — ${item.summary || item.id}\n`);
        if (item.humanCard) process.stdout.write(`${item.humanCard}\n`);
      }
      const passedCount = result.results.filter((x) => x.passed).length;
      process.stdout.write(
        lang === "zh"
          ? `\n${g}演示完成：${passedCount}/${result.results.length} 类越界场景全部成功拦截或恢复。${rst}\n下一步：nostray ui  ·  nostray audit .  ·  nostray init --host git\n`
          : `\n${g}Demo complete: ${passedCount}/${result.results.length} stray-edit scenarios contained.${rst}\nNext: nostray ui  ·  nostray audit .  ·  nostray init --host git\n`
      );
    }
    if (!result.passed) process.exitCode = 1;
    return;
  }

  // 1. `hook` — strict single-line JSON stdout wire protocol (zero extra output on stdout!)
  if (subcmd === "hook") {
    const host = String(flags.host || "claude").toLowerCase();
    const event = typeof flags.event === "string" ? flags.event : null;
    if (host === "git" || event === "pre-commit") {
      const explicitSession = typeof flags.session === "string" ? flags.session : null;
      const gitRes = await runGitPreCommitCheck(process.cwd(), { sessionId: explicitSession });
      if (!gitRes.ok) {
        process.stderr.write(`${gitRes.reason}\n`);
      }
      process.exit(gitRes.exitCode);
    }
    const rawStdin = readAllStdin();
    const wire = await handleHostHookEvent({
      host,
      event,
      rawStdin,
      wrapShell: Boolean(flags["wrap-shell"]),
      storeDir: typeof flags["store-dir"] === "string" ? path.resolve(flags["store-dir"]) : null,
      workspaceRoot: process.cwd(),
    });
    if (wire.diagnostic) process.stderr.write(wire.diagnostic + "\n");
    if (wire.stdoutObj !== null && wire.stdoutObj !== undefined) {
      process.stdout.write(JSON.stringify(wire.stdoutObj) + "\n");
    }
    process.exit(wire.exitCode);
  }

  // 2. `audit`
  if (subcmd === "audit") {
    const targetDir = positional[1] ? path.resolve(positional[1]) : path.resolve(String(flags.dir || process.cwd()));
    const limit = flags.limit ? Number(flags.limit) : 30;
    const report = await auditRepository(targetDir, {
      limit,
      verifyHooks: Boolean(flags.verify),
      host: inspectHost,
      sessionId: inspectSession,
      excludePaths: flags.exclude || [],
      excludeDirectoryNames: flags["exclude-dir"] || [],
    });
    if (typeof flags.svg === "string") {
      const svgOut = path.resolve(flags.svg);
      fs.mkdirSync(path.dirname(svgOut), { recursive: true });
      fs.writeFileSync(svgOut, renderAuditSvgScorecard(report, { showFullPath: Boolean(flags["show-path"]) }), "utf8");
    }
    if (flags.json) {
      process.stdout.write(JSON.stringify(report, null, 2) + "\n");
    } else if (!positional.length) {
      process.stdout.write(renderFirstRunSummary(report, { lang: flags.lang, showFullPath: Boolean(flags["show-path"]) }) + "\n");
    } else {
      process.stdout.write(renderAuditTerminalCard(report, { useColor: shouldUseColor(process.stdout), lang: flags.lang, showFullPath: Boolean(flags["show-path"]) }) + "\n");
    }
    return;
  }

  // 3. `init`
  if (subcmd === "init") {
    const targetDir = positional[1] ? path.resolve(positional[1]) : path.resolve(String(flags.dir || process.cwd()));
    const host = typeof flags.host === "string" ? flags.host : "all";
    const res = installOrUninstallHooks(targetDir, {
      host,
      dryRun: Boolean(flags["dry-run"]),
      uninstall: Boolean(flags.uninstall),
      wrapShell: Boolean(flags["wrap-shell"]),
    });
    if (flags.json) {
      process.stdout.write(JSON.stringify(res, null, 2) + "\n");
    } else {
      for (const act of res.actions) {
        process.stdout.write(`  [${act.host.padEnd(6)}] ${act.status}${act.file ? ` -> ${act.file}` : ""}\n`);
      }
    }
    return;
  }

  // 4. `status` / `verify`
  if (subcmd === "status" || subcmd === "verify") {
    const targetDir = positional[1] ? path.resolve(positional[1]) : path.resolve(String(flags.dir || process.cwd()));
    const status = await inspectHostInstallations(targetDir, {
      runLiveVerify: Boolean(flags.verify || subcmd === "verify"),
      host: inspectHost,
      sessionId: inspectSession,
    });
    if (flags.json) {
      process.stdout.write(JSON.stringify(status, null, 2) + "\n");
    } else {
      process.stdout.write(`Workspace      : ${status.workspaceRoot}\n`);
      process.stdout.write(formatStartupReport(status.readiness) + "\n");
      if (!inspectHost) process.stdout.write(`Best Host Tier : ${status.overallTier}\n`);
      const osSandboxSummary =
        status.osIsolation.verified === false
          ? `NOT_PROBED (${status.osIsolation.reason})`
          : status.osIsolation.available
            ? status.osIsolation.backend
            : `UNAVAILABLE (${status.osIsolation.reason})`;
      process.stdout.write(`OS Sandbox     : ${osSandboxSummary}\n`);
      for (const [h, info] of Object.entries(status.hosts)) {
        if (inspectHost && h !== inspectHost) continue;
        process.stdout.write(
          `  - ${h.padEnd(7)} : ${info.tier} (versionStatus=${info.versionStatus}${info.detectedVersion ? `, detected="${info.detectedVersion}"` : ""})\n`
        );
      }
    }
    return;
  }

  // 5. `bench`
  if (subcmd === "bench") {
    const report = await runBlastBench();
    if (flags.json) {
      process.stdout.write(JSON.stringify(report, null, 2) + "\n");
    } else {
      process.stdout.write(renderBenchTerminalTable(report, { useColor: shouldUseColor(process.stdout), lang: flags.lang, showFullPath: Boolean(flags["show-path"]) }) + "\n");
    }
    process.exit(report.allPassed ? 0 : 1);
  }

  // 6. `session` (`start` | `promote` | `reset`)
  if (subcmd === "session") {
    const action = positional[1] || "start";
    if (!["start", "reset", "promote", "verify", "status"].includes(action)) throw new Error("Unknown session action; choose start, reset, promote, verify or status.");
    const targetDir = path.resolve(String(flags.dir || process.cwd()));
    const sessionId = String(flags.session || "default");
    let acceptance = null;
    if (flags.acceptance !== undefined) {
      if (!["start", "reset"].includes(action) || typeof flags.acceptance !== "string") throw new Error("Use --acceptance <plan.json> with session start/reset.");
      const acceptancePath = path.resolve(flags.acceptance);
      if (fs.statSync(acceptancePath).size > 65536) throw new Error("Acceptance JSON must be no larger than 64 KiB.");
      acceptance = JSON.parse(fs.readFileSync(acceptancePath, "utf8"));
      validateTaskVerificationPlan(acceptance);
    }
    const sessionStoreDir = typeof flags["store-dir"] === "string" ? path.resolve(flags["store-dir"]) : null;
    const store = new SnapshotStore(targetDir, sessionStoreDir ? { storeDir: sessionStoreDir } : {});
    await store.open({ allowInitialize: !["verify", "status"].includes(action), readOnly: action === "status" });
    try {
      if (action === "status") {
        const verification = { ...readTaskVerification(store, sessionId), escalation: store.loadSession(sessionId)?.escalation || null };
        if (flags.json) process.stdout.write(JSON.stringify(verification, null, 2) + "\n");
        else {
          process.stdout.write((verification.report ? formatTaskVerification(verification.report) : "任务核验尚未执行，可运行 blast-guard session verify。") + "\n");
          if (verification.active) process.stdout.write(`工作区核验${verification.active.state === "RUNNING" ? "进行中" : "已中断"} · 会话 ${verification.active.sessionId}\n`);
        }
        return;
      }
      if (action === "verify") {
        const report = await verifyTaskAtStop(store, sessionId, { force: Boolean(flags.force) });
        process.stdout.write((flags.json ? JSON.stringify(report, null, 2) : formatTaskVerification(report)) + "\n");
        process.exitCode = report.state === "PASSED" ? 0 : report.state === "FAILED" ? 1 : 2;
        return;
      }
      if (action === "start" || action === "reset") {
        const prompt = typeof flags.prompt === "string" ? flags.prompt : "Fix the issue";
        const state = store.startOrUpdateTurn(prompt, {
          sessionId,
          resetTask: Boolean(flags.reset || flags["reset-task"] || action === "reset"),
        });
        store.writeSessionMarker(state.sessionId);
        configureTaskVerification(store, sessionId, acceptance, {
          reset: Boolean(flags.reset || flags["reset-task"] || action === "reset"),
        });
        const verification = recordPromptAcceptanceConditions(store, sessionId, prompt);
        const readiness = inspectStartupReadiness(targetDir, {
          host: inspectHost, sessionId: state.sessionId, snapshot: state, storeDir: sessionStoreDir,
        });
        if (flags.json) {
          process.stdout.write(JSON.stringify({ ...state, readiness, verification }, null, 2) + "\n");
        } else {
          process.stdout.write(`会话 ${state.sessionId} · 第 ${state.turnId} 回合 · ${state.tier}\n${formatStartupReport(readiness)}\n`);
          process.stdout.write(verification.plan ? `任务条件 ${verification.plan.conditions.length} 项，显式回归 ${verification.plan.tests.length} 项；Stop 将在隔离副本核验。\n` : "明确任务条件尚未配置；Stop 会检查范围并尝试匹配关联测试，任务完成情况将标为未核实。\n");
        }
        if (!state.coverageComplete) process.exitCode = 1;
        return;
      }

      if (action === "promote") {
        const txId = positional[2];
        if (!txId) {
          process.stderr.write("Usage: nostray session promote <txId> [--assume-single-writer]\n");
          process.exit(2);
        }
        const prom = store.promoteStagedBundle(txId, {
          assumeSingleWriter: Boolean(flags["assume-single-writer"]),
          ownedWorktree: Boolean(flags["owned-worktree"]),
        });
        if (flags.json) {
          process.stdout.write(JSON.stringify(prom, null, 2) + "\n");
        } else if (prom.ok) {
          process.stdout.write(`Promoted ${prom.promotedFiles.length} file(s) from ${txId}.\n`);
        } else {
          process.stderr.write(`[${prom.code}] ${prom.reason}\n`);
        }
        process.exit(prom.ok ? 0 : 1);
      }
    } finally {
      store.close();
    }
  }

  // 7. `rollback`
  if (subcmd === "rollback") {
    const targetDir = path.resolve(String(flags.dir || process.cwd()));
    const store = new SnapshotStore(targetDir);
    await store.open({ allowInitialize: false });
    try {
      const rec = store.recoverUnfinishedTransactions({
        forceRestoreBaseline: Boolean(flags["force-baseline"]),
      });
      if (flags.json) {
        process.stdout.write(JSON.stringify(rec, null, 2) + "\n");
      } else {
        process.stdout.write(
          `Recovery ${rec.ok ? "SUCCEEDED" : "FAILED"} (${rec.recoveredTransactions.length} transaction(s) processed).\n`
        );
      }
      process.exit(rec.ok ? 0 : 1);
    } finally {
      store.close();
    }
  }

  // 8. `wrap`
  if (subcmd === "wrap") {
    const cmdArgs = doubleDashArgs && doubleDashArgs.length > 0 ? doubleDashArgs : positional.slice(1);
    if (!cmdArgs || cmdArgs.length === 0) {
      process.stderr.write("Usage: nostray wrap [--mode checkpoint|isolated] -- <command> [args...]\n");
      process.exit(2);
    }
    const mode = typeof flags.mode === "string" ? flags.mode : "checkpoint";
    const promoteMode = typeof flags.promote === "string" ? flags.promote : "staged";
    const res = await executeWrappedCommand(process.cwd(), cmdArgs, {
      mode,
      checkOnly: Boolean(flags["check-only"]),
      storeDir: typeof flags["store-dir"] === "string" ? path.resolve(flags["store-dir"]) : null,
      promoteMode,
      assumeSingleWriter: Boolean(flags["assume-single-writer"]),
      ownedWorktree: Boolean(flags["owned-worktree"]),
      denyNetwork: Boolean(flags["deny-network"]),
      sessionId: typeof flags.session === "string" ? flags.session : "default",
    });

    if (flags.json) {
      process.stdout.write(JSON.stringify(res, null, 2) + "\n");
      process.exit(res.ok ? res.exitCode : res.exitCode || 1);
    }

    if (res.stdout) process.stdout.write(res.stdout);
    if (res.stderr) process.stderr.write(res.stderr);
    if (!res.ok) {
      if (res.discardedChanges) process.exit(res.exitCode || 1);
      process.stderr.write(`\n${res.diagnostic || `[BlastGuard ${res.code}] ${res.reason || "Policy violation"}`}\n`);
      process.exit(res.exitCode || 126);
    }
    if (mode === "isolated" && !res.promoted && res.changedFiles?.length > 0) {
      process.stderr.write(
        `[BlastGuard ${res.code}] Validated ${res.changedFiles.length} file(s) in staged bundle: ${res.stagedBundleDir}\n` +
          `To apply to live workspace under single-writer ownership: nostray session promote ${res.txId} --assume-single-writer\n`
      );
    }
    process.exit(res.exitCode ?? 0);
  }

  process.stderr.write(`Unknown command '${subcmd}'. Run 'nostray --help' for usage.\n`);
  process.exit(2);
}

main().catch((err) => {
  process.stderr.write(`[blast-guard ${err.code || "FATAL_ERROR"}] ${err.message}\n`);
  process.exit(2);
});
