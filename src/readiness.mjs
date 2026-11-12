import { sanitizeTerminalText } from "./runtime-support.mjs";
import { SnapshotStore } from "./snapshot-store.mjs";

function oneLine(value) {
  return sanitizeTerminalText(value).replace(/[\n\r\t\u2028\u2029]/g, " ");
}

export function snapshotSummary(scan) {
  return {
    coverageComplete: scan.coverageComplete,
    incompleteCode: scan.incompleteCode ?? null,
    incompleteReason: scan.incompleteReason ?? null,
    blockingFile: scan.blockingFile ?? null,
  };
}

export function inspectSnapshotCoverage(workspaceRoot, storeDir) {
  // The same strict scan that admits a command. Never open SQLite or persist blobs.
  try {
    const store = new SnapshotStore(workspaceRoot, { storeDir });
    return snapshotSummary(store.scanWorkspaceNamespace({ storeBlobs: false }));
  } catch (err) {
    return snapshotSummary({
      coverageComplete: false,
      incompleteCode: err.code || "SNAPSHOT_INSPECTION_FAILED",
      incompleteReason: err.message,
    });
  }
}

export function formatSnapshotCoverage(scan) {
  if (scan.coverageComplete) return "快照覆盖完整（本次扫描时的工作区）";
  const file = scan.blockingFile;
  if (file) {
    const mib = bytes => Number((bytes / (1024 * 1024)).toFixed(2));
    const detail = file.kind === "file"
      ? `单文件上限 ${mib(file.limitBytes)} MiB`
      : `加入此文件会超过总量上限 ${mib(file.limitBytes)} MiB`;
    return `快照覆盖不完整，${oneLine(file.path)}（${mib(file.sizeBytes)} MiB，${detail}）。需要完整快照的写入将被拒绝。`;
  }
  return `快照覆盖不完整，需要完整快照的写入将被拒绝。原因：${oneLine(scan.incompleteReason || scan.incompleteCode || "扫描未完成")}`;
}

export function describeShellMode(host, { wrapShell = false, configured = true } = {}) {
  if (host === "git") return { mode: "commit-only", description: "Git 只在提交时检查；它不接管 Shell 写入。" };
  if (!configured) return { mode: "unconfirmed", description: "未确认项目 Shell 接入，无法依靠写前拦截或写后恢复。" };
  if (host === "antigravity" || (host === "codex" && wrapShell)) {
    return { mode: "wrapped-checkpoint", description: "先检查已知危险命令；普通 Shell 在工作区执行，包装器在写后检查，违规或失败时尝试恢复。" };
  }
  const limitation = host === "codex" ? "默认 Codex 接入不能保证撤销失败命令的所有写入。" : "";
  return { mode: "hook-checkpoint", description: `先检查已知危险命令；普通 Shell 在工作区执行，由写后钩子检查，违规时尝试恢复。${limitation}` };
}

export function formatStartupReport(report) {
  const lines = [`  ${formatSnapshotCoverage(report.snapshot)}`];
  const configs = { VALID: "项目已配置", ABSENT: "未发现项目配置", INVALID: "项目配置无效" };
  for (const [host, info] of Object.entries(report.hosts)) {
    let activity = "尚未观察到启动钩子";
    if (host === "git") activity = "无会话启动钩子";
    else if (info.observation) {
      const rec = info.observation;
      const origin = rec.identityEvidence === "codex-running-parent-confirmed" ? "已核实 Codex 父进程" : "已收到事件，调用进程身份未核实";
      activity = `最近收到 ${oneLine(rec.event)} · ${oneLine(rec.observedAt)} · 会话 ${oneLine(rec.sessionId)}（${origin}；仅证明启动事件）`;
    } else if (report.observationErrors.length) activity = "启动回执读取不完整，运行情况未知";
    const shellLabel = info.configState === "VALID" ? "Shell（配置生效时）" : "Shell";
    lines.push(`  ${host} · ${configs[info.configState]} · ${activity}`, `    ${shellLabel} · ${info.shell.description}`);
  }
  if (!Object.keys(report.hosts).length) {
    lines.push(report.observationErrors.length
      ? "  启动回执读取不完整，无法确认宿主和 Shell。"
      : "  未发现项目钩子配置或启动回执；尚未确认有宿主接管 Shell。");
  }
  if (!report.selectedHost) lines.push("  查看指定宿主：blast-guard status --host codex（可加 --session 会话ID）");
  return lines.join("\n");
}
