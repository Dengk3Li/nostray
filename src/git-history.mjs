import { spawnSync } from "node:child_process";
import path from "node:path";
import { classifyProtectionRing } from "./path-security.mjs";
import { SUPPORTED_JS_TS_EXTS, SUPPORTED_PYTHON_EXTS } from "./code-scanner.mjs";
import { compareHistoricalFile } from "./history-structure.mjs";
import { sanitizeTerminalText } from "./runtime-support.mjs";

const MAX_PAIRS = 64;
const MAX_BLOB = 256 * 1024;
const MAX_BYTES = 6 * 1024 * 1024;
const MAX_FINDINGS_PER_COMMIT = 24;
const OBJECT_ID = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/;
const isSupported = name => {
  const ext = path.posix.extname(name).toLowerCase();
  return SUPPORTED_JS_TS_EXTS.has(ext) || SUPPORTED_PYTHON_EXTS.has(ext);
};

export const displayHistoryText = value => sanitizeTerminalText(value).replace(/[\r\n\t]/g, " ");

function git(cwd, args, options = {}) {
  return spawnSync("git", ["-c", "core.hooksPath=/dev/null", ...args], {
    cwd, env: { ...process.env, LC_ALL: "C", GIT_OPTIONAL_LOCKS: "0", GIT_NO_LAZY_FETCH: "1", GIT_NO_REPLACE_OBJECTS: "1" },
    encoding: "utf8", timeout: 8000, maxBuffer: 16 * 1024 * 1024, ...options,
  });
}

// Both paths in a rename and all Git header fields are separate NUL-delimited records.
function parseGitLog(output) {
  const records = output.split("\0");
  const commits = [];
  let current;
  let entries;
  for (let i = 0; i < records.length; i++) {
    const token = records[i].replace(/^\n(?=[:0-9-])/, "");
    if (!token) continue;
    if (token.startsWith("H") && OBJECT_ID.test(token.slice(1))) {
      current = { oid: token.slice(1), parent: records[++i], timestamp: Number(records[++i]), subject: displayHistoryText(records[++i]), fileStats: [] };
      current.sha = current.oid.slice(0, 10);
      commits.push(current);
      entries = new Map();
      continue;
    }
    if (!current) throw new Error("Missing Git commit header");
    if (token.startsWith(":")) {
      const [oldMode, newMode, oldId, newId, status] = token.slice(1).split(" ");
      const oldPath = records[++i];
      const newPath = /^[RC]/.test(status) ? records[++i] : oldPath;
      entries.set(newPath, { oldMode, newMode, oldId, newId, oldPath, newPath, status });
      continue;
    }
    const stats = /^(\d+|-)\t(\d+|-)\t([\s\S]*)$/.exec(token);
    if (!stats) throw new Error("Invalid Git numstat record");
    let name = stats[3];
    if (!name) { i++; name = records[++i]; }
    const entry = entries.get(name);
    if (!entry) throw new Error("Missing Git tree record");
    const { ring, category } = classifyProtectionRing(name);
    current.fileStats.push({
      ...entry, ring, category, filePath: displayHistoryText(name),
      added: Number(stats[1]) || 0, deleted: Number(stats[2]) || 0, isBinary: stats[1] === "-",
      isGeneratedLock: /(?:^|\/)(?:package-lock\.json|pnpm-lock\.yaml|yarn\.lock|Cargo\.lock|poetry\.lock|uv\.lock)$/.test(name),
    });
  }
  return commits;
}

export function readGitSample(cwd, limit) {
  const inside = git(cwd, ["rev-parse", "--is-inside-work-tree"]);
  if (inside.status !== 0 || inside.stdout.trim() !== "true") return { commits: [], state: "no-git" };
  const result = git(cwd, ["log", "--no-merges", "--root", "--no-color", "--no-decorate", "--no-show-signature",
    "--no-ext-diff", "--no-textconv", "--find-renames", "--no-abbrev", "-n", String(Math.max(1, Math.min(200, limit))),
    "--format=format:%x00H%H%x00%P%x00%ct%x00%s%x00", "--raw", "--numstat", "-z", "--"]);
  if (result.status !== 0) return { commits: [], state: "unavailable" };
  let commits;
  try { commits = parseGitLog(result.stdout); } catch { return { commits: [], state: "unavailable" }; }
  // In a shallow clone %P is empty at the boundary, even if the actual commit names a parent.
  for (const c of commits.filter(c => !c.parent)) {
    const object = git(cwd, ["cat-file", "commit", c.oid], { maxBuffer: 1024 * 1024 });
    c.initial = object.status === 0 && !/^parent /m.test(object.stdout.split("\n\n", 1)[0]);
    c.boundary = !c.initial;
  }
  return { commits, state: "ready" };
}

// Only the two committed versions are read. No checkout, worktree files, or repository code are used.
function readBlobs(cwd, ids) {
  const blobs = new Map();
  if (!ids.length) return blobs;
  const sizes = git(cwd, ["cat-file", "--batch-check"], { input: ids.join("\n") + "\n" });
  if (sizes.status !== 0) return blobs;
  const selected = [];
  let total = 0;
  for (const row of sizes.stdout.trimEnd().split("\n")) {
    const [oid, type, sizeText] = row.split(" ");
    const size = Number(sizeText);
    if (type === "blob" && size <= MAX_BLOB && total + size <= MAX_BYTES) {
      selected.push(oid);
      total += size;
    }
  }
  if (!selected.length) return blobs;
  const result = git(cwd, ["cat-file", "--batch"], { input: selected.join("\n") + "\n", encoding: null });
  if (result.status !== 0) return blobs;
  const data = result.stdout;
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let cursor = 0;
  for (const oid of selected) {
    const newline = data.indexOf(10, cursor);
    if (newline < cursor) break;
    const [name, type, length] = data.toString("ascii", cursor, newline).split(" ");
    const end = newline + 1 + Number(length);
    if (name !== oid || type !== "blob" || !Number.isSafeInteger(end) || data[end] !== 10) break;
    const content = data.subarray(newline + 1, end);
    try { if (!content.includes(0)) blobs.set(oid, decoder.decode(content)); } catch { /* Non-UTF-8 source. */ }
    cursor = end + 1;
  }
  return blobs;
}

export function compareCommitStructures(cwd, commits) {
  const pairs = [];
  for (const c of commits) {
    c.findings = [];
    c.findingCount = 0;
    c.partialFiles = 0;
    for (const f of c.fileStats) {
      if (f.isBinary || !isSupported(f.oldPath) || !/^100/.test(f.oldMode) || f.oldId === f.newId || f.status.startsWith("C")) continue;
      pairs.push({ c, f });
    }
  }
  const ids = new Set();
  for (const { f } of pairs.slice(0, MAX_PAIRS)) {
    ids.add(f.oldId);
    if (f.status !== "D") ids.add(f.newId);
  }
  const blobs = readBlobs(cwd, [...ids]);
  const coverage = { eligibleFiles: pairs.length, comparedFiles: 0, partialFiles: 0, maxFilePairs: MAX_PAIRS, maxBlobBytes: MAX_BLOB, maxTotalBlobBytes: MAX_BYTES };
  for (const [i, { c, f }] of pairs.entries()) {
    const before = blobs.get(f.oldId);
    const after = f.status === "D" ? "" : blobs.get(f.newId);
    if (i >= MAX_PAIRS || before === undefined || after === undefined ||
        (f.status !== "D" && (!/^100/.test(f.newMode) || path.posix.extname(f.oldPath) !== path.posix.extname(f.newPath)))) {
      c.partialFiles++; coverage.partialFiles++; continue;
    }
    const diff = compareHistoricalFile({ path: f.oldPath, before, after, isTest: classifyProtectionRing(f.oldPath).category === "TEST_SUITE" });
    coverage.comparedFiles++;
    if (diff.partial) { c.partialFiles++; coverage.partialFiles++; }
    c.findingCount += diff.findings.length;
    for (const item of diff.findings.slice(0, MAX_FINDINGS_PER_COMMIT - c.findings.length)) {
      c.findings.push({ ...item, path: f.filePath, ...(f.oldPath !== f.newPath ? { previousPath: displayHistoryText(f.oldPath) } : {}) });
    }
  }
  return coverage;
}
