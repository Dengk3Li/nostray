import { detectPreferredLang } from "./human-card.mjs";
import fs from "node:fs";
import path from "node:path";
import { readGitSample, compareCommitStructures, displayHistoryText } from "./git-history.mjs";
import {
  canonicalizeWorkspaceRoot,
  classifyProtectionRing,
  shouldSkipPerformanceIgnoredDir,
  toPosixRel,
} from "./path-security.mjs";
import {
  shouldUseColor,
  sanitizeTerminalText,
} from "./runtime-support.mjs";
import { buildWorkspaceDependencyGraph } from "./dependency-graph.mjs";
import { inspectHostInstallations } from "./init-installer.mjs";
import { formatStartupReport } from "./readiness.mjs";

const SMALL_INTENT_SUBJECT_RE =
  /\b(?:typo|fix|bugfix|hotfix|nit|tweak|bump|lint|round|padding|align|tooltip|rename\s+var|minor|patch)\b|(?:小修|微调|修补|错别字|圆角|对齐|样式微调)/i;
const WORKSPACE_FILE_LIMIT = 10000;
const DEPENDENCY_FILE_LIMIT = 2000;

function normalizeAuditExclusions(excludePaths, excludeDirectoryNames) {
  if (!Array.isArray(excludePaths) || !Array.isArray(excludeDirectoryNames)) {
    throw new Error("Audit exclusions must be arrays of paths or directory names.");
  }

  const paths = excludePaths.map((value) => {
    if (typeof value !== "string" || !value || value.includes("\0")) {
      throw new Error("Each --exclude requires a non-empty workspace-relative path.");
    }
    const portable = value.replace(/\\/g, "/");
    if (path.posix.isAbsolute(portable) || path.win32.isAbsolute(value) || portable.split("/").includes("..")) {
      throw new Error(`Invalid audit exclusion '${value}': use a workspace-relative path without '..'.`);
    }
    const normalized = path.posix.normalize(portable).replace(/\/$/, "");
    if (!normalized || normalized === ".") {
      throw new Error("An audit exclusion cannot be the workspace root.");
    }
    return normalized;
  });

  const directoryNames = excludeDirectoryNames.map((value) => {
    if (typeof value !== "string" || !value || value === "." || value === ".." || /[\\/\0]/.test(value)) {
      throw new Error("Each --exclude-dir requires a single directory name.");
    }
    return value;
  });

  return { paths: [...new Set(paths)], directoryNames: [...new Set(directoryNames)] };
}

function hasIncompleteCoverage(scan) {
  return Boolean(
    scan?.truncated || scan?.unreadableDirectories || scan?.unreadableFiles ||
    scan?.oversizedFiles || scan?.unparsedFiles || scan?.unresolvedImports || scan?.unparsedConfigurations
  );
}

/**
 * Strictly read-only 3-Axis Repository & Workspace Blast-Radius Auditor:
 * - Never executes repository scripts or external Git diff/textconv helpers (`--no-ext-diff --no-textconv`, `GIT_OPTIONAL_LOCKS=0`)
 * - Axis 1 (`historicalHygiene`): Returns `"N/A"` (`insufficientHistory: true`) on non-Git folders or repos with <3 non-merge commits!
 *   Flags *Heuristic High-Blast Review Candidates* with transparent weights & sample denominators.
 * - Axis 2 (`workspaceExposure`): Counts Ring-0 contracts, test files, Tarjan cyclic SCCs, and top high-fan-in hub modules.
 * - Axis 3 (`protectionStatus`): Reports truthful tier (`UNPROTECTED`, `CONFIGURED`, `ADAPTER_SELF_TESTED`, `HOST_E2E_VERIFIED`).
 */
export async function auditRepository(
  workspaceRoot = process.cwd(),
  { limit = 30, verifyHooks = false, storeDir = null, excludePaths = [], excludeDirectoryNames = [], host = null, sessionId = null } = {}
) {
  const canonicalRoot = canonicalizeWorkspaceRoot(workspaceRoot);
  const exclusions = normalizeAuditExclusions(excludePaths, excludeDirectoryNames);
  const gitHistory = scanReadOnlyGitHistory(canonicalRoot, { limit });
  const exposure = scanWorkspaceContractExposure(canonicalRoot, exclusions);
  const hostStatus = await inspectHostInstallations(canonicalRoot, {
    runLiveVerify: verifyHooks,
    storeDir,
    host,
    sessionId,
  });

  return {
    schemaVersion: "blast-guard.audit.v1",
    auditedAt: new Date().toISOString(),
    workspaceRoot: canonicalRoot,
    historicalHygiene: gitHistory,
    workspaceExposure: exposure,
    readiness: hostStatus.readiness,
    protectionStatus: {
      overallTier: hostStatus.overallTier,
      hosts: hostStatus.hosts,
    },
    badge: buildHonestBadgeSpec(gitHistory, exposure, hostStatus.overallTier),
    shareBadge: `![NoStray](https://img.shields.io/badge/NoStray-${hostStatus.overallTier === "HOST_E2E_VERIFIED" ? "guarded-15803d" : "checked-334155"})`,
  };
}

function scanReadOnlyGitHistory(canonicalRoot, { limit = 30 } = {}) {
  const sample = readGitSample(canonicalRoot, limit);
  const commits = sample.commits.filter(c => c.parent);
  const initialImports = sample.commits.filter(c => c.initial).map(c => ({
    sha: c.sha, subject: c.subject, files: c.fileStats.length,
  }));
  const structureCoverage = compareCommitStructures(canonicalRoot, commits);
  const reviewCandidates = [];
  let weightedPenaltySum = 0;

  for (const c of commits) {
    const nonLockFiles = c.fileStats.filter((f) => !f.isGeneratedLock && !f.isBinary);
    const totalFiles = nonLockFiles.length;
    const totalDeleted = nonLockFiles.reduce((acc, f) => acc + f.deleted, 0);
    const totalAdded = nonLockFiles.reduce((acc, f) => acc + f.added, 0);
    const contractFiles = nonLockFiles.filter((f) => f.category === "CONTRACT_OR_CONFIG");
    const testFilesWithHeavyDeletes = nonLockFiles.filter(
      (f) => f.category === "TEST_SUITE" && f.deleted >= 8 && f.deleted > f.added * 1.5
    );
    const smallSubject = SMALL_INTENT_SUBJECT_RE.test(c.subject);

    const signals = [];
    let commitPenalty = 0;

    // Heuristic 1: Small-intent commit message vs wide multi-file sprawl (>=8 non-lock files)
    if (smallSubject && totalFiles >= 8) {
      signals.push(`small-subject-sprawl (${totalFiles} files touched)`);
      commitPenalty += 18;
    } else if (totalFiles >= 18) {
      signals.push(`wide-fanout (${totalFiles} non-lock files)`);
      commitPenalty += 10;
    }

    // Heuristic 2: Leaf edit coupled with net test-line deletion
    if (testFilesWithHeavyDeletes.length > 0 && nonLockFiles.some((f) => f.ring !== "RING_0")) {
      signals.push(`source+test-net-deletion (${testFilesWithHeavyDeletes.length} test file(s))`);
      commitPenalty += 16;
    }

    // Heuristic 3: Small-intent subject coupled with Ring-0 contract mutation
    if (smallSubject && contractFiles.length > 0 && totalFiles >= 3) {
      signals.push(`small-subject+contract-touch (${contractFiles[0].filePath})`);
      commitPenalty += 12;
    }

    // Heuristic 4: Heavy mass line deletion (>250 lines deleted with >70% deletion ratio)
    if (totalDeleted >= 250 && totalDeleted > (totalAdded + totalDeleted) * 0.7) {
      signals.push(`heavy-deletion-burst (-${totalDeleted}/+${totalAdded} lines)`);
      commitPenalty += 10;
    }

    if (signals.length > 0 || c.findingCount > 0) {
      weightedPenaltySum += Math.min(30, commitPenalty);
      reviewCandidates.push({
        sha: c.sha,
        subject: c.subject,
        nonLockFilesTouched: totalFiles,
        addedLines: totalAdded,
        deletedLines: totalDeleted,
        contractPaths: contractFiles.slice(0, 3).map(file => file.filePath),
        heuristicSignals: signals,
        parent: c.parent.slice(0, 10),
        findings: c.findings,
        findingCount: c.findingCount,
        partialFiles: c.partialFiles,
      });
    }
  }

  // Normalize only across commits for which a parent version was available.
  const enoughHistory = commits.length >= 3;
  const normalizedPenalty = enoughHistory ? Math.min(100, Math.round((weightedPenaltySum / commits.length) * 3.2)) : null;
  const score = enoughHistory ? 100 - normalizedPenalty : null;
  const priority = candidate => Math.max(0, ...candidate.findings.map(findingPriority));
  reviewCandidates.sort((a, b) => priority(b) - priority(a));
  const reason = sample.state === "no-git" ? "No Git worktree."
    : sample.state === "unavailable" ? "Git history is empty or unreadable."
    : enoughHistory ? null : "At least three comparable non-merge commits are required for a score.";
  return {
    historyState: sample.state, available: sample.state === "ready", insufficientHistory: !enoughHistory, reason, score,
    grade: scoreToLetterGrade(score), sampledNonMergeCommits: sample.commits.length,
    comparedCommits: commits.length, initialImports, shallowBoundaries: sample.commits.filter(c => c.boundary).length,
    structureCoverage, requestedLimit: limit,
    structuralCommitCount: reviewCandidates.filter(c => c.findingCount > 0).length,
    flaggedCommitCount: reviewCandidates.length, reviewCandidates: reviewCandidates.slice(0, 8),
    note: "Structural evidence describes differences between committed versions. Candidate status does not establish a defect or authorship.",
    formula: "100 - min(100, round((sum(heuristic commit penalties) / comparable non-merge commits) * 3.2))",
  };
}

function scoreToLetterGrade(score) {
  if (score === null || score === undefined) return "N/A";
  if (score >= 95) return "A+";
  if (score >= 88) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

function scanWorkspaceContractExposure(canonicalRoot, exclusions) {
  let totalFiles = 0;
  let contractFiles = 0;
  let testFiles = 0;
  let truncated = false;
  let unreadableDirectories = 0;
  let skippedSymlinks = 0;
  const sampleContracts = [];
  const shouldExclude = (relativePath, isDirectory) =>
    exclusions.paths.some((entry) => relativePath === entry || relativePath.startsWith(`${entry}/`)) ||
    (isDirectory && exclusions.directoryNames.includes(path.posix.basename(relativePath)));

  function walk(absDir, relDirPosix) {
    if (truncated) return;
    if (relDirPosix && shouldSkipPerformanceIgnoredDir(relDirPosix)) return;
    let entries;
    try {
      entries = fs.readdirSync(absDir, { withFileTypes: true });
    } catch {
      unreadableDirectories++;
      return;
    }
    for (const ent of entries) {
      if (truncated) break;
      if (ent.name === ".git" || ent.name === ".blast-guard" || ent.name === ".blast-guard-session") continue;
      const childRel = relDirPosix ? `${relDirPosix}/${ent.name}` : ent.name;
      const relPosix = toPosixRel(childRel);
      const childAbs = path.join(absDir, ent.name);
      if (shouldExclude(relPosix, ent.isDirectory())) continue;
      if (ent.isSymbolicLink()) {
        skippedSymlinks++;
        continue;
      }
      if (ent.isDirectory()) {
        walk(childAbs, relPosix);
      } else if (ent.isFile()) {
        if (totalFiles === WORKSPACE_FILE_LIMIT) {
          truncated = true;
          break;
        }
        totalFiles++;
        const r = classifyProtectionRing(relPosix);
        if (r.ring === "RING_0") {
          if (r.category === "TEST_SUITE") {
            testFiles++;
          } else {
            contractFiles++;
            if (sampleContracts.length < 6) sampleContracts.push(sanitizeTerminalText(relPosix));
          }
        }
      }
    }
  }

  walk(canonicalRoot, "");

  const graph = buildWorkspaceDependencyGraph(canonicalRoot, {
    maxFiles: DEPENDENCY_FILE_LIMIT,
    shouldExclude,
  });
  const hubs = [];
  for (const [file, callers] of graph.reverseCallers.entries()) {
    if (callers.size > 0) {
      hubs.push({ file: sanitizeTerminalText(file), directCallers: callers.size });
    }
  }
  hubs.sort((a, b) => b.directCallers - a.directCallers);

  return {
    scannedWorkspaceFiles: totalFiles,
    truncatedAt10k: truncated,
    workspaceScan: {
      fileLimit: WORKSPACE_FILE_LIMIT,
      truncated,
      unreadableDirectories,
      skippedSymlinks,
    },
    dependencyScan: {
      scannedCodeFiles: graph.fileCount,
      fileLimit: DEPENDENCY_FILE_LIMIT,
      truncated: graph.truncated,
      unreadableDirectories: graph.unreadableDirectories,
      unreadableFiles: graph.unreadableFiles,
      oversizedFiles: graph.oversizedFiles,
      unparsedFiles: graph.unparsedFiles,
      unresolvedImports: graph.unresolvedImports,
      unparsedConfigurations: graph.unparsedConfigurations,
      skippedSymlinks: graph.skippedSymlinks,
      problemFileSamples: graph.problemFileSamples,
    },
    exclusions,
    ring0ContractCount: contractFiles,
    ring0TestSuiteCount: testFiles,
    cyclicSccCount: graph.cyclicSccs.length,
    cyclicSccs: graph.cyclicSccs.slice(0, 5),
    topHighFanInModules: hubs.slice(0, 5),
    sampleContracts,
  };
}

function buildHonestBadgeSpec(hist, exposure, overallTier) {
  //  invariant: NEVER issue "Protected" badge unless active protection is verified!
  let label = "blast-guard";
  let statusText;
  let colorHex;
  const partial = hasIncompleteCoverage(exposure.workspaceScan) || hasIncompleteCoverage(exposure.dependencyScan);
  const scoped = Boolean(exposure.exclusions?.paths?.length || exposure.exclusions?.directoryNames?.length);

  if (overallTier === "HOST_E2E_VERIFIED") {
    statusText = hist.score !== null ? `A Host E2E Verified | Hygiene ${hist.score}/100` : "A Host E2E Verified";
    colorHex = "#15803d";
  } else if (overallTier === "ADAPTER_SELF_TESTED") {
    statusText = "Adapter Tested (Host E2E Pending)";
    colorHex = "#0369a1";
  } else if (overallTier === "CONFIGURED") {
    statusText = "Configured (Unverified)";
    colorHex = "#b45309";
  } else if (overallTier === "UNTESTED_HOST_VERSION") {
    statusText = "Untested Host Version";
    colorHex = "#b45309";
  } else if (overallTier === "DEGRADED_SELF_TEST_FAILED") {
    statusText = "Degraded (Self-Test Failed)";
    colorHex = "#b91c1c";
  } else {
    statusText = "Checked";
    colorHex = "#334155";
  }
  if (partial) statusText += " | Partial Scan";
  else if (scoped) statusText += " | Scoped Scan";

  const encodedStatus = encodeURIComponent(statusText);
  const encodedColor = colorHex.replace("#", "");
  const markdownBadge = `![BlastGuard](https://img.shields.io/badge/BlastGuard-${encodedStatus}-${encodedColor})`;

  return {
    label,
    statusText,
    colorHex,
    markdown: markdownBadge,
  };
}

function changedDeclarationFragment(before, after) {
  const words = value => [...String(value ?? "").matchAll(/[\p{L}\p{N}_$]+|[^\s]/gu)];
  const oldWords = words(before), newWords = words(after);
  let start = 0;
  while (start < Math.min(oldWords.length, newWords.length) && oldWords[start][0] === newWords[start][0]) start++;
  let oldEnd = oldWords.length, newEnd = newWords.length;
  while (oldEnd > start && newEnd > start && oldWords[oldEnd - 1][0] === newWords[newEnd - 1][0]) { oldEnd--; newEnd--; }
  function segment(value, tokens, end) {
    if (end <= start) return "";
    const last = tokens[end - 1];
    return displayHistoryText(value.slice(tokens[start].index, last.index + last[0].length)).replace(/^,\s*|,\s*$/g, "");
  }
  const removed = segment(before, oldWords, oldEnd);
  const added = segment(after, newWords, newEnd);
  if (added.length + removed.length > 110 || /__STR_/.test(added + removed)) return "";
  if (added && removed) return `（${removed} → ${added}）`;
  if (added) return `（新增 ${added}）`;
  if (removed) return `（移除 ${removed}）`;
  return "";
}

function findingPriority(finding) {
  if (finding.kind.endsWith("-removed")) return 3;
  if (finding.kind === "assertion-changed") return 2;
  return 1;
}

function describeFinding(finding) {
  const clip = value => {
    const text = displayHistoryText(value);
    return text.length > 120 ? text.slice(0, 117) + "…" : text;
  };
  switch (finding.kind) {
    case "export-removed": return `移除公开导出 ${clip(finding.name)}`;
    case "export-changed": return `公开接口 ${clip(finding.name)} 的声明发生变化${changedDeclarationFragment(finding.before, finding.after)}`;
    case "assertion-removed": return `原断言不再出现 ${clip(finding.before)}`;
    case "assertion-changed": return `原断言 ${clip(finding.before)} → 同类断言 ${clip(finding.after)}`;
    default: return clip(finding.name);
  }
}

function historyHighlights(history, candidateCount) {
  const lines = [];
  for (const item of history.reviewCandidates.slice(0, candidateCount)) {
    const findings = [...(item.findings || [])].sort((a, b) => findingPriority(b) - findingPriority(a));
    lines.push(`  ${item.sha}「${item.subject}」`);
    if (findings.length) {
      for (const finding of findings.slice(0, 2)) lines.push(`    ${finding.path} · ${describeFinding(finding)}`);
    } else {
      lines.push(`    规模线索 · ${item.nonLockFilesTouched} 个文本文件，+${item.addedLines}/-${item.deletedLines} 行；尚无具体导出或断言证据。`);
    }
  }
  for (const item of (history.initialImports || []).slice(0, 2)) {
    lines.push(`首次导入 ${item.sha}「${item.subject}」，${item.files} 个文件，单列为基线。`);
  }
  if (history.shallowBoundaries) lines.push(`浅克隆有 ${history.shallowBoundaries} 个边界提交，本地没有父版本可比。`);
  const coverage = history.structureCoverage;
  if (coverage?.partialFiles) {
    lines.push(`结构比对范围有限：${coverage.eligibleFiles} 个待比对文件版本中，${coverage.partialFiles} 个未能完整核对。`);
  }
  return lines;
}

export function renderFirstRunSummary(report, options = {}) {
  if (detectPreferredLang(options) !== "zh") {
    const ex = report.workspaceExposure;
    return [`NoStray · ${sanitizeTerminalText(options.showFullPath ? report.workspaceRoot : path.basename(report.workspaceRoot))}`, `Scanned ${ex.scannedWorkspaceFiles} files: ${ex.ring0ContractCount} contracts and ${ex.ring0TestSuiteCount} test files.`, `Contract samples: ${ex.sampleContracts.slice(0, 3).join(", ")}`, `Protection: ${report.protectionStatus.overallTier}`, "Full audit: nostray audit ."].join("\n");
  }
  const { historicalHygiene: history, workspaceExposure: exposure } = report;
  const lines = [`BlastGuard · ${sanitizeTerminalText(options.showFullPath ? report.workspaceRoot : path.basename(report.workspaceRoot))}`];
  if (history.comparedCommits) {
    lines.push(`历史复查 · ${history.comparedCommits} 次有父版本的提交，${history.structuralCommitCount} 次检出导出或断言变动，${history.flaggedCommitCount - history.structuralCommitCount} 次仅有改动规模线索。`);
  }
  lines.push(...historyHighlights(history, 2));
  if (history.score === null) {
    const why = history.historyState === "no-git" ? "当前目录没有 Git 仓库"
      : history.historyState === "unavailable" ? "未读到 Git 历史" : `${history.comparedCommits} 次可比提交`;
    lines.push(`历史改动暂不评分：${why}，评分至少需要 3 次可比提交。`);
  } else {
    lines.push(`改动规模评分 ${history.score}/100（参考提交说明、涉及文件及增删行数）。`);
  }
  const hub = exposure.topHighFanInModules[0];
  if (hub) lines.push(`依赖影响：${hub.directCallers} 个模块直接引用 ${hub.file}。`);
  lines.push(`扫描到 ${exposure.scannedWorkspaceFiles} 个文件，其中有 ${exposure.ring0ContractCount} 个契约或配置文件、${exposure.ring0TestSuiteCount} 个测试文件。`);
  if (exposure.sampleContracts.length) lines.push(`契约文件示例：${exposure.sampleContracts.slice(0, 3).join("、")}`);
  if (hasIncompleteCoverage(exposure.workspaceScan) || hasIncompleteCoverage(exposure.dependencyScan)) lines.push("文件或依赖扫描覆盖不完整，详细原因见 audit。");
  if (exposure.exclusions.paths.length || exposure.exclusions.directoryNames.length) lines.push("文件与依赖统计已应用排除项，快照检查仍覆盖整个工作区。");
  lines.push("", "首次写入前的检查", formatStartupReport(report.readiness), "", "完整体检与徽章：blast-guard audit .");
  return lines.join("\n");
}

export function renderAuditTerminalCard(report, options = {}) {
  const { useColor = shouldUseColor(process.stdout) } = options;
  const zh = detectPreferredLang(options) === "zh";
  const c = useColor
    ? {
        bold: "\x1b[1m",
        dim: "\x1b[2m",
        red: "\x1b[31m",
        green: "\x1b[32m",
        yellow: "\x1b[33m",
        cyan: "\x1b[36m",
        reset: "\x1b[0m",
      }
    : { bold: "", dim: "", red: "", green: "", yellow: "", cyan: "", reset: "" };

  const h = report.historicalHygiene;
  const ex = report.workspaceExposure;
  const pr = report.protectionStatus;
  const workspaceScan = ex.workspaceScan;
  const dependencyScan = ex.dependencyScan;

  const histSummary = h.insufficientHistory
    ? `${c.yellow}N/A (Insufficient Git History: ${h.sampledNonMergeCommits} non-merge commits)${c.reset}`
    : `${c.bold}${h.score}/100 (${h.grade})${c.reset} across ${h.comparedCommits} comparable commits (change-size heuristics)`;

  const tierColor =
    pr.overallTier === "HOST_E2E_VERIFIED"
      ? c.green
      : pr.overallTier === "ADAPTER_SELF_TESTED"
        ? c.cyan
        : pr.overallTier === "CONFIGURED"
          ? c.yellow
          : c.red;

  const lines = [
    `${c.bold}┌──────────────────────────────────────────────────────────────────────────┐${c.reset}`,
    `${c.bold}│  NOSTRAY v0.1 — 3-Axis Blast-Radius & Contract Exposure Scorecard    │${c.reset}`,
    `${c.bold}└──────────────────────────────────────────────────────────────────────────┘${c.reset}`,
    `  Workspace       : ${sanitizeTerminalText(options.showFullPath ? report.workspaceRoot : path.basename(report.workspaceRoot))}`,
    `  1. Git Hygiene  : ${histSummary}`,
    `  2. Observed     : ${c.bold}${ex.ring0ContractCount}${c.reset} Ring-0 contract(s), ${c.bold}${ex.ring0TestSuiteCount}${c.reset} test file(s), ${c.bold}${ex.cyclicSccCount}${c.reset} dependency cycle(s)`,
    `  3. Best Host    : ${tierColor}${c.bold}${pr.overallTier}${c.reset}`,
  ];

  if (ex.sampleContracts?.length) lines.push(`  ${zh ? "契约文件示例" : "Contract samples"} : ${ex.sampleContracts.slice(0, 3).join(", ")}`);
  if (report.readiness && zh) lines.push("", "  首次写入前的检查", formatStartupReport(report.readiness), "");
  if (workspaceScan && dependencyScan) {
    const workspaceStatus = hasIncompleteCoverage(workspaceScan) ? "PARTIAL" : "traversal finished";
    const dependencyStatus = hasIncompleteCoverage(dependencyScan) ? "PARTIAL" : "traversal finished";
    lines.push(
      `  Workspace Scan  : ${ex.scannedWorkspaceFiles}/${workspaceScan.fileLimit} files, ${workspaceStatus}`,
      `  Dependency Scan : ${dependencyScan.scannedCodeFiles}/${dependencyScan.fileLimit} code files, ${dependencyStatus}`,
      `  Scan Issues     : workspace limit=${workspaceScan.truncated}, unreadable directories=${workspaceScan.unreadableDirectories}; ` +
        `dependency limit=${dependencyScan.truncated}, unreadable directories=${dependencyScan.unreadableDirectories}, ` +
        `unreadable files=${dependencyScan.unreadableFiles}, oversized=${dependencyScan.oversizedFiles}, unparsed=${dependencyScan.unparsedFiles}, unresolved imports=${dependencyScan.unresolvedImports ?? 0}, unknown configs=${dependencyScan.unparsedConfigurations ?? 0}`,
      `  Scope           : built-in ignored directories and symlinks omitted; dependency graph uses supported static JS/TS/Python imports.`,
    );
    const excluded = [
      ...(ex.exclusions?.paths || []).map((entry) => `path=${sanitizeTerminalText(entry)}`),
      ...(ex.exclusions?.directoryNames || []).map((entry) => `dir=${sanitizeTerminalText(entry)}`),
    ];
    if (excluded.length) {
      lines.push(`  Excluded        : ${excluded.join(", ")} (workspace scans only; Git history unchanged)`);
    }
    for (const [reason, samples] of Object.entries(dependencyScan.problemFileSamples || {})) {
      if (samples.length) {
        lines.push(`  ${reason.padEnd(15)} : ${samples.map(sanitizeTerminalText).join(", ")}`);
      }
    }
  } else {
    lines.push(`  Coverage        : unknown (report does not include scan coverage)`);
  }
  if (pr.hosts) {
    lines.push(
      `  Host Tiers      : ${Object.entries(pr.hosts).map(([host, info]) => `${host}=${info.tier}`).join(", ")}`
    );
  }

  if (ex.topHighFanInModules.length > 0) {
    lines.push(
      `  Top Blast Hubs  : ${ex.topHighFanInModules
        .slice(0, 3)
        .map((m) => `${m.file} (${m.directCallers} callers)`)
        .join(", ")}`
    );
  }

  if (zh) lines.push("", "  历史复查（提交与父版本）", ...historyHighlights(h, 4));
  if (h.insufficientHistory) lines.push(`  ${c.dim}${h.reason}${c.reset}`);
  if (h.comparedCommits && zh) lines.push(`  ${h.comparedCommits} 次有父版本的提交，${h.structuralCommitCount} 次检出导出或断言变动。`);

  lines.push("");
  lines.push(`  README Badge    : ${report.shareBadge || report.badge.markdown}`);
  if (pr.overallTier === "UNPROTECTED") {
    lines.push(`  Quick Enable    : ${c.cyan}Preview init --dry-run for your host, then check status --verify (see README).${c.reset}`);
  }
  return lines.join("\n");
}

export function renderAuditSvgScorecard(report) {
  const esc = (s) =>
    String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");

  const h = report.historicalHygiene;
  const ex = report.workspaceExposure;
  const tier = report.protectionStatus.overallTier;
  const scoreLabel = h.insufficientHistory ? "N/A" : `${h.score}/100 (${h.grade})`;
  const ws = ex.workspaceScan;
  const graph = ex.dependencyScan;
  const workspaceCoverage = ws
    ? `${ex.scannedWorkspaceFiles}/${ws.fileLimit} files, ${hasIncompleteCoverage(ws) ? "PARTIAL" : "traversal finished"}`
    : "coverage unknown";
  const dependencyCoverage = graph
    ? `${graph.scannedCodeFiles}/${graph.fileLimit} code files, ${hasIncompleteCoverage(graph) ? "PARTIAL" : "traversal finished"}`
    : "coverage unknown";
  const exclusionsCount = (ex.exclusions?.paths?.length || 0) + (ex.exclusions?.directoryNames?.length || 0);
  const tierTextColor = {
    "#15803d": "#4ade80",
    "#0369a1": "#7dd3fc",
    "#b45309": "#fbbf24",
    "#b91c1c": "#f87171",
  }[report.badge.colorHex] || "#e2e8f0";

  return `<svg xmlns="http://www.w3.org/2000/svg" width="760" height="314" viewBox="0 0 760 314">
  <rect width="760" height="314" rx="12" fill="#0f172a"/>
  <rect x="16" y="16" width="728" height="282" rx="8" fill="#1e293b" stroke="#334155"/>
  <text x="36" y="52" fill="#f8fafc" font-family="ui-monospace, SFMono-Regular, Menlo, monospace" font-size="18" font-weight="700">NoStray v0.1 — Blast-Radius &amp; Contract Scorecard</text>
  <text x="36" y="88" fill="#94a3b8" font-family="ui-monospace, SFMono-Regular, Menlo, monospace" font-size="14">1. Historical Change-Size Score : <tspan fill="#e2e8f0" font-weight="600">${esc(scoreLabel)}</tspan></text>
  <text x="36" y="118" fill="#94a3b8" font-family="ui-monospace, SFMono-Regular, Menlo, monospace" font-size="14">2. Observed Surface          : <tspan fill="#e2e8f0" font-weight="600">${ex.ring0ContractCount} contracts / ${ex.ring0TestSuiteCount} test files / ${ex.cyclicSccCount} cycles</tspan></text>
  <text x="36" y="148" fill="#94a3b8" font-family="ui-monospace, SFMono-Regular, Menlo, monospace" font-size="14">3. Best Host Tier            : <tspan fill="${tierTextColor}" font-weight="700">${esc(tier)}</tspan></text>
  <text x="36" y="178" fill="#e2e8f0" font-family="ui-monospace, SFMono-Regular, Menlo, monospace" font-size="13">Workspace scan: ${esc(workspaceCoverage)}</text>
  <text x="36" y="200" fill="#e2e8f0" font-family="ui-monospace, SFMono-Regular, Menlo, monospace" font-size="13">Dependency scan: ${esc(dependencyCoverage)}</text>
  <text x="36" y="226" fill="#94a3b8" font-family="ui-monospace, SFMono-Regular, Menlo, monospace" font-size="12">Static JS/TS/Python imports; default ignores and symlinks omitted.</text>
  <text x="36" y="248" fill="#94a3b8" font-family="ui-monospace, SFMono-Regular, Menlo, monospace" font-size="12">Requested exclusions: ${exclusionsCount}; Git history unaffected.</text>
</svg>
`;
}
