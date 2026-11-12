import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import zlib from "node:zlib";
import { persistSnapshotBlob } from "./snapshot-blob.mjs";
import { spawn, spawnSync } from "node:child_process";
import {
  BLAST_GUARD_PACKAGE_ROOT,
  loadSqliteDatabaseSync,
  resolveWorkspaceStoreDir,
  writeDurableFileAtomic,
  fsyncDirectoryBestEffort,
  probeOsIsolationBackend,
  buildSeatbeltProfile,
  streamSha256File,
} from "./runtime-support.mjs";
import {
  DEFAULT_EXEMPT_XATTRS,
  canonicalizeWorkspaceRoot,
  isContainedRelativePath,
  classifyProtectionRing,
  inspectWorkspacePath,
  checkUnsupportedFileMetadata,
  inspectTreePlatformMetadata,
  toPosixRel,
} from "./path-security.mjs";
import {
  TIER_BUDGETS,
  classifyIntent,
  mergeTurnGrants,
  formatVoiEscalationGuidance,
} from "./intent-and-budget.mjs";
import { evaluateCandidateWriteSet } from "./conservation-engine.mjs";
import { buildWorkspaceDependencyGraph } from "./dependency-graph.mjs";
import { buildScopePolicy, observeScopeRead, refactorBoundary, createVoiEscalationCard, resolveVoiApproval, formatEscalationCard } from "./scope-policy.mjs";
import { createBoundedOutputCapture } from "./output-capture.mjs";

export const DEFAULT_RESOURCE_LIMITS = Object.freeze({
  maxTrackedFiles: 25000,
  maxSingleBlobBytes: 16 * 1024 * 1024, // 16 MiB
  maxTotalSnapshotBytes: 256 * 1024 * 1024, // 256 MiB
  maxScanMs: 2500,
});

function sha256Buffer(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function isProbablyBinaryBuffer(buf) {
  const sampleLen = Math.min(buf.length, 4096);
  for (let i = 0; i < sampleLen; i++) {
    if (buf[i] === 0) return true;
  }
  return false;
}

function canonicalizeMaybeMissingPath(rawPath) {
  const abs = path.resolve(rawPath);
  const tail = [];
  let cur = abs;
  while (true) {
    try {
      const real = fs.realpathSync.native(cur);
      return tail.length > 0 ? path.join(real, ...tail.reverse()) : real;
    } catch (err) {
      if (err && err.code === "ENOENT") {
        const parent = path.dirname(cur);
        if (parent === cur) return abs;
        tail.push(path.basename(cur));
        cur = parent;
        continue;
      }
      return abs;
    }
  }
}

/**
 * Snapshot the COMPLETE `.git` control-plane & worktree metadata surface (``):
 * - Walks every directory, symlink, and file inside `.git` (including `.git/info/exclude`, `logs/`, `refs/`, `hooks/`, `config`, `index`, `HEAD`, loose objects)
 * - For large packfiles (`objects/pack/*.{pack,idx,rev,bitmap,mtimes}` or files > 8 MiB), records `(mode, size, mtimeNs, ctimeNs, ino)` so multi-GB packs aren't read while still catching mutations
 * - For Git worktrees / submodules where `.git` is a pointer file (`gitdir: ...`), hashes `.git`, resolves `gitdir` AND `commondir`, and snapshots both!
 */
export function hashGitControlPlane(canonicalRoot) {
  const gitEntry = path.join(canonicalRoot, ".git");
  let st = null;
  try {
    st = fs.lstatSync(gitEntry, { bigint: true });
  } catch {
    return null;
  }

  const records = [];

  if (st.isDirectory()) {
    records.push(`.git:rootdir:${Number(st.mode) & 0o7777}`);
    walkGitMetadataTree(gitEntry, ".git", records);
    records.sort();
    return {
      kind: "gitdir",
      entryCount: records.length,
      digest: sha256Buffer(Buffer.from(records.join("\n"), "utf8")),
      records,
    };
  }

  if (st.isFile()) {
    const rawBytes = fs.readFileSync(gitEntry);
    records.push(`.git:file:${Number(st.mode) & 0o7777}:${sha256Buffer(rawBytes)}`);
    const txt = rawBytes.toString("utf8");
    const m = txt.match(/^gitdir:\s*(.+)$/m);
    if (m) {
      const rawGitDir = m[1].trim();
      const resolvedGitDir = path.resolve(canonicalRoot, rawGitDir);
      try {
        const gdSt = fs.lstatSync(resolvedGitDir, { bigint: true });
        records.push(`worktree_gitdir:rootdir:${Number(gdSt.mode) & 0o7777}`);
      } catch {
        records.push("worktree_gitdir:root_unreadable");
      }
      walkGitMetadataTree(resolvedGitDir, "worktree_gitdir", records);
      const commonDirFile = path.join(resolvedGitDir, "commondir");
      try {
        if (fs.existsSync(commonDirFile) && fs.lstatSync(commonDirFile).isFile()) {
          const relCommon = fs.readFileSync(commonDirFile, "utf8").trim();
          const resolvedCommon = path.resolve(resolvedGitDir, relCommon);
          try {
            const cmSt = fs.lstatSync(resolvedCommon, { bigint: true });
            records.push(`worktree_commondir:rootdir:${Number(cmSt.mode) & 0o7777}`);
          } catch {
            records.push("worktree_commondir:root_unreadable");
          }
          walkGitMetadataTree(resolvedCommon, "worktree_commondir", records, {
            skipTopWorktreesExcept: path.basename(resolvedGitDir),
          });
        }
      } catch {
        records.push("worktree_commondir:unreadable");
      }
    }
    records.sort();
    return {
      kind: "gitfile-worktree",
      entryCount: records.length,
      digest: sha256Buffer(Buffer.from(records.join("\n"), "utf8")),
      records,
    };
  }

  const fallback = `unsupported:${Number(st.mode)}:${st.mtimeNs.toString()}`;
  return {
    kind: "symlink-or-special",
    entryCount: 1,
    digest: sha256Buffer(Buffer.from(fallback, "utf8")),
    records: [fallback],
  };
}

function walkGitMetadataTree(absDir, relPrefix, out, options = {}) {
  let entries;
  try {
    entries = fs.readdirSync(absDir, { withFileTypes: true });
  } catch (err) {
    out.push(`${relPrefix}:unreadable:${err.code || "ERR"}`);
    return;
  }
  entries.sort((a, b) => a.name.localeCompare(b.name));
  for (const ent of entries) {
    const rel = `${relPrefix}/${ent.name}`;
    if (
      options.skipTopWorktreesExcept &&
      relPrefix === "worktree_commondir/worktrees" &&
      ent.name !== options.skipTopWorktreesExcept
    ) {
      continue;
    }
    const full = path.join(absDir, ent.name);
    try {
      const st = fs.lstatSync(full, { bigint: true });
      const mode = Number(st.mode) & 0o7777;
      if (st.isSymbolicLink()) {
        out.push(`${rel}:link:${fs.readlinkSync(full)}`);
      } else if (st.isDirectory()) {
        out.push(`${rel}:dir:${mode}`);
        walkGitMetadataTree(full, rel, out, options);
      } else if (st.isFile()) {
        const sizeNum = Number(st.size);
        const isPackArtifact =
          rel.includes("/objects/pack/") && /\.(?:pack|idx|rev|bitmap|mtimes)$/i.test(ent.name);
        if (isPackArtifact || sizeNum > 8 * 1024 * 1024) {
          out.push(
            `${rel}:packstat:${mode}:${sizeNum}:${st.mtimeNs.toString()}:${st.ctimeNs.toString()}:${st.ino.toString()}`
          );
        } else {
          const h = streamSha256File(full, 8 * 1024 * 1024);
          out.push(`${rel}:file:${mode}:${h.sha256}`);
        }
      } else {
        out.push(`${rel}:special:${mode}`);
      }
    } catch (err) {
      out.push(`${rel}:stat_err:${err.code || "ERR"}`);
    }
  }
}

function pickIdentityTuple(entry) {
  if (!entry) return null;
  return {
    entryType: entry.entryType,
    mode: entry.mode,
    size: entry.size,
    mtimeNs: entry.mtimeNs,
    ctimeNs: entry.ctimeNs,
    dev: entry.dev,
    ino: entry.ino,
    sha256: entry.sha256 || null,
    linkTarget: entry.linkTarget || null,
  };
}

function identityTupleMatches(liveEntry, expectedTuple) {
  if (!liveEntry || !expectedTuple) return false;
  return (
    liveEntry.entryType === expectedTuple.entryType &&
    liveEntry.mode === expectedTuple.mode &&
    liveEntry.size === expectedTuple.size &&
    liveEntry.mtimeNs === expectedTuple.mtimeNs &&
    liveEntry.ctimeNs === expectedTuple.ctimeNs &&
    liveEntry.dev === expectedTuple.dev &&
    liveEntry.ino === expectedTuple.ino &&
    (liveEntry.sha256 || null) === (expectedTuple.sha256 || null) &&
    (liveEntry.linkTarget || null) === (expectedTuple.linkTarget || null)
  );
}

function entryMatchesRecordedState(liveEntry, recType, recSha256, recMode, recLink) {
  if (!recType || recType === "missing") {
    return !liveEntry;
  }
  if (!liveEntry) return false;
  if (liveEntry.entryType !== recType) return false;
  if (recMode !== null && recMode !== undefined && liveEntry.mode !== recMode) return false;
  if (recType === "file") {
    return (liveEntry.sha256 || null) === (recSha256 || null);
  }
  if (recType === "symlink") {
    return (liveEntry.linkTarget || null) === (recLink || null);
  }
  return true;
}

/**
 * Quote a POSIX relative path for `diff --git` / `---` / `+++` headers if needed (``).
 */
function formatGitPatchPath(prefix, relPosix) {
  const full = `${prefix}${relPosix}`;
  if (!/[\s"\\\u0000-\u001F\u007F]/.test(full)) {
    return full;
  }
  let escaped = '"';
  for (const ch of full) {
    if (ch === "\\") escaped += "\\\\";
    else if (ch === '"') escaped += '\\"';
    else if (ch === "\t") escaped += "\\t";
    else if (ch === "\n") escaped += "\\n";
    else if (ch === "\r") escaped += "\\r";
    else escaped += ch;
  }
  escaped += '"';
  return escaped;
}

const GIT_BASE85_ALPHABET =
  "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";

function encodeGitBase85Line(chunk) {
  const len = chunk.length;
  const lenChar =
    len <= 26 ? String.fromCharCode(64 + len) : String.fromCharCode(97 + len - 27);
  let out = lenChar;
  for (let i = 0; i < len; i += 4) {
    let acc = 0;
    for (let b = 0; b < 4; b++) {
      acc = acc * 256 + (i + b < len ? chunk[i + b] : 0);
    }
    const chars = new Array(5);
    for (let c = 4; c >= 0; c--) {
      chars[c] = GIT_BASE85_ALPHABET[acc % 85];
      acc = Math.floor(acc / 85);
    }
    out += chars.join("");
  }
  return out;
}

function encodeGitBinaryLiteralSection(buf) {
  const safeBuf = Buffer.isBuffer(buf) ? buf : Buffer.from(buf || "");
  const lines = [`literal ${safeBuf.length}`];
  const deflated = zlib.deflateSync(safeBuf);
  for (let i = 0; i < deflated.length; i += 52) {
    lines.push(encodeGitBase85Line(deflated.subarray(i, Math.min(deflated.length, i + 52))));
  }
  lines.push("");
  return lines.join("\n");
}

function computeGitBlobSha1(buf) {
  const safeBuf = Buffer.isBuffer(buf) ? buf : Buffer.from(buf || "");
  return crypto
    .createHash("sha1")
    .update(`blob ${safeBuf.length}\0`)
    .update(safeBuf)
    .digest("hex");
}

function splitPatchLines(text) {
  if (typeof text !== "string" || text.length === 0) {
    return { lines: [], hasTrailingNewline: true };
  }
  // Preserve exact `\r` bytes inside lines so CRLF files round-trip byte-identically under `git apply` (``)!
  const hasTrailingNewline = text.endsWith("\n");
  const lines = hasTrailingNewline ? text.slice(0, -1).split("\n") : text.split("\n");
  return { lines, hasTrailingNewline };
}

/**
 * Generate a standard `git apply`-compatible unified or `GIT binary patch` (``).
 */
export function buildUnifiedFilePatch(
  relPosix,
  beforeText,
  afterText,
  {
    changeType = "modify",
    isBinary = false,
    beforeMode = 0o644,
    afterMode = 0o644,
    beforeBytes = null,
    afterBytes = null,
  } = {}
) {
  const aHeaderPath = formatGitPatchPath("a/", relPosix);
  const bHeaderPath = formatGitPatchPath("b/", relPosix);
  const fmtMode = (m) => `100${((m ?? 0o644) & 0o777).toString(8).padStart(3, "0")}`;

  const out = [`diff --git ${aHeaderPath} ${bHeaderPath}`];
  const modeChanged = changeType !== "add" && changeType !== "delete" && (beforeMode & 0o777) !== (afterMode & 0o777);
  if (changeType === "add") {
    out.push(`new file mode ${fmtMode(afterMode)}`);
  } else if (changeType === "delete") {
    out.push(`deleted file mode ${fmtMode(beforeMode)}`);
  } else if (modeChanged) {
    out.push(`old mode ${fmtMode(beforeMode)}`);
    out.push(`new mode ${fmtMode(afterMode)}`);
  }

  if (isBinary) {
    const zeroSha1 = "0000000000000000000000000000000000000000";
    const bBuf =
      changeType === "add"
        ? Buffer.alloc(0)
        : Buffer.isBuffer(beforeBytes)
          ? beforeBytes
          : Buffer.from(beforeText ?? "", "utf8");
    const aBuf =
      changeType === "delete"
        ? Buffer.alloc(0)
        : Buffer.isBuffer(afterBytes)
          ? afterBytes
          : Buffer.from(afterText ?? "", "utf8");
    const oldSha = changeType === "add" ? zeroSha1 : computeGitBlobSha1(bBuf);
    const newSha = changeType === "delete" ? zeroSha1 : computeGitBlobSha1(aBuf);
    const indexSuffix =
      changeType === "add" || changeType === "delete" || modeChanged ? "" : ` ${fmtMode(afterMode)}`;
    out.push(`index ${oldSha}..${newSha}${indexSuffix}`);
    out.push("GIT binary patch");
    out.push(encodeGitBinaryLiteralSection(aBuf));
    out.push(encodeGitBinaryLiteralSection(bBuf));
    return out.join("\n") + "\n";
  }

  const bParsed = changeType === "add" ? { lines: [], hasTrailingNewline: true } : splitPatchLines(beforeText ?? "");
  const aParsed = changeType === "delete" ? { lines: [], hasTrailingNewline: true } : splitPatchLines(afterText ?? "");

  if (
    changeType === "mode-change" &&
    bParsed.lines.length === aParsed.lines.length &&
    bParsed.hasTrailingNewline === aParsed.hasTrailingNewline &&
    bParsed.lines.every((l, idx) => l === aParsed.lines[idx])
  ) {
    return out.join("\n") + "\n";
  }

  out.push(`--- ${changeType === "add" ? "/dev/null" : aHeaderPath}`);
  out.push(`+++ ${changeType === "delete" ? "/dev/null" : bHeaderPath}`);

  const edits = computeLineEdits(bParsed.lines, aParsed.lines);
  const hunks = groupEditsIntoUnifiedHunks(edits, 3);

  for (const hunk of hunks) {
    const oldStart = hunk.oldCount === 0 ? 0 : hunk.oldStart1Based;
    const newStart = hunk.newCount === 0 ? 0 : hunk.newStart1Based;
    out.push(`@@ -${oldStart},${hunk.oldCount} +${newStart},${hunk.newCount} @@`);

    for (const op of hunk.ops) {
      if (op.type === "equal") {
        out.push(` ${op.line}`);
        if (
          op.oldIdx === bParsed.lines.length - 1 &&
          op.newIdx === aParsed.lines.length - 1 &&
          !bParsed.hasTrailingNewline &&
          !aParsed.hasTrailingNewline
        ) {
          out.push("\\ No newline at end of file");
        }
      } else if (op.type === "delete") {
        out.push(`-${op.line}`);
        if (op.oldIdx === bParsed.lines.length - 1 && !bParsed.hasTrailingNewline) {
          out.push("\\ No newline at end of file");
        }
      } else if (op.type === "insert") {
        out.push(`+${op.line}`);
        if (op.newIdx === aParsed.lines.length - 1 && !aParsed.hasTrailingNewline) {
          out.push("\\ No newline at end of file");
        }
      }
    }
  }

  return out.join("\n") + "\n";
}

function computeLineEdits(oldLines, newLines) {
  const m = oldLines.length;
  const n = newLines.length;
  let prefix = 0;
  while (prefix < m && prefix < n && oldLines[prefix] === newLines[prefix]) {
    prefix++;
  }
  let suffix = 0;
  while (
    suffix < m - prefix &&
    suffix < n - prefix &&
    oldLines[m - 1 - suffix] === newLines[n - 1 - suffix]
  ) {
    suffix++;
  }

  const ops = [];
  for (let i = 0; i < prefix; i++) {
    ops.push({ type: "equal", line: oldLines[i], oldIdx: i, newIdx: i });
  }

  const midOld = oldLines.slice(prefix, m - suffix);
  const midNew = newLines.slice(prefix, n - suffix);
  const mm = midOld.length;
  const nn = midNew.length;

  if (mm === 0 && nn === 0) {
    // nothing in middle
  } else if (mm * nn <= 250000) {
    const dp = Array.from({ length: mm + 1 }, () => new Int32Array(nn + 1));
    for (let i = mm - 1; i >= 0; i--) {
      for (let j = nn - 1; j >= 0; j--) {
        if (midOld[i] === midNew[j]) {
          dp[i][j] = dp[i + 1][j + 1] + 1;
        } else {
          dp[i][j] = Math.max(dp[i + 1][j], dp[i][j + 1]);
        }
      }
    }
    let i = 0;
    let j = 0;
    while (i < mm || j < nn) {
      if (i < mm && j < nn && midOld[i] === midNew[j]) {
        ops.push({ type: "equal", line: midOld[i], oldIdx: prefix + i, newIdx: prefix + j });
        i++;
        j++;
      } else if (i < mm && (j === nn || dp[i + 1][j] >= dp[i][j + 1])) {
        ops.push({ type: "delete", line: midOld[i], oldIdx: prefix + i, newIdx: -1 });
        i++;
      } else {
        ops.push({ type: "insert", line: midNew[j], oldIdx: -1, newIdx: prefix + j });
        j++;
      }
    }
  } else {
    for (let i = 0; i < mm; i++) {
      ops.push({ type: "delete", line: midOld[i], oldIdx: prefix + i, newIdx: -1 });
    }
    for (let j = 0; j < nn; j++) {
      ops.push({ type: "insert", line: midNew[j], oldIdx: -1, newIdx: prefix + j });
    }
  }

  for (let s = 0; s < suffix; s++) {
    const oi = m - suffix + s;
    const ni = n - suffix + s;
    ops.push({ type: "equal", line: oldLines[oi], oldIdx: oi, newIdx: ni });
  }

  // Handle trailing-newline-only change when all lines are textually equal!
  if (ops.every((o) => o.type === "equal") && m > 0) {
    const lastIdx = ops.length - 1;
    ops.splice(
      lastIdx,
      1,
      { type: "delete", line: oldLines[m - 1], oldIdx: m - 1, newIdx: -1 },
      { type: "insert", line: newLines[n - 1], oldIdx: -1, newIdx: n - 1 }
    );
  }

  return ops;
}

function groupEditsIntoUnifiedHunks(ops, contextLines = 3) {
  const changeIndices = [];
  for (let i = 0; i < ops.length; i++) {
    if (ops[i].type !== "equal") changeIndices.push(i);
  }
  if (changeIndices.length === 0) return [];

  const ranges = [];
  let curStart = Math.max(0, changeIndices[0] - contextLines);
  let curEnd = Math.min(ops.length - 1, changeIndices[0] + contextLines);

  for (let k = 1; k < changeIndices.length; k++) {
    const nextStart = Math.max(0, changeIndices[k] - contextLines);
    const nextEnd = Math.min(ops.length - 1, changeIndices[k] + contextLines);
    if (nextStart <= curEnd + 1) {
      curEnd = Math.max(curEnd, nextEnd);
    } else {
      ranges.push([curStart, curEnd]);
      curStart = nextStart;
      curEnd = nextEnd;
    }
  }
  ranges.push([curStart, curEnd]);

  const hunks = [];
  for (const [start, end] of ranges) {
    const slice = ops.slice(start, end + 1);
    let oldCount = 0;
    let newCount = 0;
    let firstOldIdx = null;
    let firstNewIdx = null;

    // Count preceding old/new lines before `start` to establish exact 1-based line numbers
    let oldBefore = 0;
    let newBefore = 0;
    for (let p = 0; p < start; p++) {
      if (ops[p].type === "equal" || ops[p].type === "delete") oldBefore++;
      if (ops[p].type === "equal" || ops[p].type === "insert") newBefore++;
    }

    for (const op of slice) {
      if (op.type === "equal" || op.type === "delete") {
        if (firstOldIdx === null) firstOldIdx = op.oldIdx;
        oldCount++;
      }
      if (op.type === "equal" || op.type === "insert") {
        if (firstNewIdx === null) firstNewIdx = op.newIdx;
        newCount++;
      }
    }

    hunks.push({
      oldStart1Based: firstOldIdx !== null ? firstOldIdx + 1 : oldBefore + 1,
      oldCount,
      newStart1Based: firstNewIdx !== null ? firstNewIdx + 1 : newBefore + 1,
      newCount,
      ops: slice,
    });
  }
  return hunks;
}

export class SnapshotStore {
  constructor(workspaceRoot, options = {}) {
    this.canonicalRoot = canonicalizeWorkspaceRoot(workspaceRoot);
    const resolved = resolveWorkspaceStoreDir(this.canonicalRoot);
    this.workspaceId = resolved.workspaceId;

    const rawStoreDir = path.resolve(options.storeDir || resolved.storeDir);
    const canonicalStoreDir = canonicalizeMaybeMissingPath(rawStoreDir);

    // External Store Boundary (``): state store MUST reside strictly outside canonical workspace root & guard install!
    if (isContainedRelativePath(path.relative(this.canonicalRoot, canonicalStoreDir))) {
      const err = new Error(
        `Authoritative state directory '${canonicalStoreDir}' must reside strictly outside canonical workspace root '${this.canonicalRoot}'.`
      );
      err.code = "OUTSIDE_WORKSPACE_REQUIRED";
      throw err;
    }
    if (isContainedRelativePath(path.relative(BLAST_GUARD_PACKAGE_ROOT, canonicalStoreDir))) {
      const err = new Error(
        `Authoritative state directory '${canonicalStoreDir}' cannot reside inside blast-guard installation '${BLAST_GUARD_PACKAGE_ROOT}'.`
      );
      err.code = "IMMUTABLE_GUARD_BINARY";
      throw err;
    }

    this.storeDir = canonicalStoreDir;
    this.blobsDir = path.join(this.storeDir, "blobs");
    this.quarantineDir = path.join(this.storeDir, "quarantine");
    this.stagedDir = path.join(this.storeDir, "staged");
    this.dbPath = path.join(this.storeDir, "state.sqlite");
    this.markerPath = path.join(this.canonicalRoot, ".blast-guard-session");
    this.limits = { ...DEFAULT_RESOURCE_LIMITS, ...(options.limits || {}) };
    this.exemptXattrs = Array.isArray(options.exemptXattrs)
      ? options.exemptXattrs
      : DEFAULT_EXEMPT_XATTRS;
    this.db = null;
  }

  readSessionMarker() {
    if (!fs.existsSync(this.markerPath)) return null;
    try {
      const raw = fs.readFileSync(this.markerPath, "utf8");
      const parsed = JSON.parse(raw);
      if (!parsed || typeof parsed !== "object" || typeof parsed.sessionId !== "string") {
        const err = new Error(`Malformed workspace session marker at ${this.markerPath}.`);
        err.code = "STATE_INTEGRITY_FAILURE";
        throw err;
      }
      if (parsed.workspaceId !== this.workspaceId) {
        const err = new Error(
          `Workspace session marker workspaceId mismatch (expected ${this.workspaceId}, got ${parsed.workspaceId}).`
        );
        err.code = "STATE_INTEGRITY_FAILURE";
        throw err;
      }
      return parsed;
    } catch (err) {
      if (err.code === "STATE_INTEGRITY_FAILURE") throw err;
      const wrapped = new Error(`Corrupt workspace session marker (${this.markerPath}): ${err.message}`);
      wrapped.code = "STATE_INTEGRITY_FAILURE";
      throw wrapped;
    }
  }

  writeSessionMarker(sessionId) {
    const sid = String(sessionId || "default");
    const tokenRow = this.db
      ?.prepare(`SELECT value FROM meta WHERE key = 'marker_token'`)
      .get();
    const payload = {
      workspaceId: this.workspaceId,
      workspaceRoot: this.canonicalRoot,
      sessionId: sid,
      markerToken: tokenRow?.value || null,
      updatedAt: Date.now(),
    };
    const rawBuf = Buffer.from(JSON.stringify(payload) + "\n", "utf8");
    writeDurableFileAtomic(this.markerPath, rawBuf, 0o600);

    // Keep active session baseline/turn checkpoints synchronized with BlastGuard's own marker write (``)
    if (this.db) {
      try {
        const st = fs.lstatSync(this.markerPath, { bigint: true });
        const markerSha = sha256Buffer(rawBuf);
        const blobDest = this.blobPathForHash(markerSha);
        if (!fs.existsSync(blobDest)) {
          writeDurableFileAtomic(blobDest, rawBuf, 0o400);
        }
        const sess = this.db.prepare(`SELECT * FROM sessions WHERE session_id = ?`).get(sid);
        if (sess) {
          const cpIds = Array.from(new Set([sess.turn_checkpoint_id, sess.task_baseline_id].filter(Boolean)));
          const upsert = this.db.prepare(`
            INSERT INTO checkpoint_entries (
              checkpoint_id, rel_posix, entry_type, mode, size, mtime_ns, ctime_ns,
              dev, ino, nlink, sha256, link_target, is_binary, oversize
            ) VALUES (?, '.blast-guard-session', 'file', ?, ?, ?, ?, ?, ?, ?, ?, NULL, 0, 0)
            ON CONFLICT(checkpoint_id, rel_posix) DO UPDATE SET
              entry_type = 'file',
              mode = excluded.mode,
              size = excluded.size,
              mtime_ns = excluded.mtime_ns,
              ctime_ns = excluded.ctime_ns,
              dev = excluded.dev,
              ino = excluded.ino,
              nlink = excluded.nlink,
              sha256 = excluded.sha256,
              link_target = NULL,
              is_binary = 0,
              oversize = 0
          `);
          this.withImmediateTransaction(() => {
            for (const cpId of cpIds) {
              upsert.run(
                cpId,
                Number(st.mode) & 0o7777,
                Number(st.size),
                st.mtimeNs.toString(),
                st.ctimeNs.toString(),
                Number(st.dev),
                st.ino.toString(),
                Number(st.nlink),
                markerSha
              );
            }
          });
        }
      } catch {
        // best-effort checkpoint marker sync
      }
    }
    return payload;
  }

  async open({ allowInitialize = true, expectExistingActiveSession = false, readOnly = false } = {}) {
    if (this.db) {
      if (!allowInitialize || expectExistingActiveSession) {
        this._verifyExistingStateIntegrity({ expectExistingActiveSession, marker: this.readSessionMarker() });
      }
      return this;
    }
    const DatabaseSync = await loadSqliteDatabaseSync();

    const marker = this.readSessionMarker();
    const mustAlreadyBeInitialized = Boolean(!allowInitialize || expectExistingActiveSession || marker || readOnly);

    if (mustAlreadyBeInitialized) {
      let dbStat = null;
      try {
        dbStat = fs.statSync(this.dbPath);
      } catch {
        dbStat = null;
      }
      if (!dbStat || !dbStat.isFile() || dbStat.size === 0) {
        const err = new Error(
          `Active session expected or initialization disallowed, but authoritative SQLite database (${this.dbPath}) is missing or empty.`
        );
        err.code = "STATE_INTEGRITY_FAILURE";
        throw err;
      }
    }

    if (!readOnly) {
      fs.mkdirSync(this.blobsDir, { recursive: true, mode: 0o700 });
      fs.mkdirSync(this.quarantineDir, { recursive: true, mode: 0o700 });
      fs.mkdirSync(this.stagedDir, { recursive: true, mode: 0o700 });
    }

    try {
      this.db = readOnly
        ? new DatabaseSync(this.dbPath, { readOnly: true })
        : new DatabaseSync(this.dbPath);

      if (readOnly) {
        this._verifyExistingStateIntegrity({ expectExistingActiveSession, marker });
        return this;
      }

      this.db.exec(`
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = FULL;
        PRAGMA busy_timeout = 5000;
        PRAGMA foreign_keys = ON;
      `);

      // If existing state is expected, verify schema + identity + session/checkpoint linkage BEFORE running DDL (``)!
      if (mustAlreadyBeInitialized) {
        this._verifyExistingStateIntegrity({ expectExistingActiveSession, marker });
      }

      this.db.exec(`
        CREATE TABLE IF NOT EXISTS meta (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS active_lock (
          singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
          tx_id TEXT NOT NULL,
          owner_kind TEXT NOT NULL,
          session_id TEXT NOT NULL,
          tool_use_id TEXT,
          owner_pid INTEGER,
          created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sessions (
          session_id TEXT PRIMARY KEY,
          turn_id INTEGER NOT NULL DEFAULT 1,
          tier TEXT NOT NULL,
          budget_json TEXT NOT NULL,
          working_set_json TEXT NOT NULL,
          grants_json TEXT NOT NULL,
          deny_set_json TEXT NOT NULL,
          task_baseline_id TEXT NOT NULL,
          turn_checkpoint_id TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS checkpoints (
          checkpoint_id TEXT PRIMARY KEY,
          session_id TEXT NOT NULL,
          kind TEXT NOT NULL,
          git_control_json TEXT,
          coverage_complete INTEGER NOT NULL,
          incomplete_reason TEXT,
          total_files INTEGER NOT NULL,
          total_bytes INTEGER NOT NULL,
          created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS checkpoint_entries (
          checkpoint_id TEXT NOT NULL,
          rel_posix TEXT NOT NULL,
          entry_type TEXT NOT NULL,
          mode INTEGER NOT NULL,
          size INTEGER NOT NULL,
          mtime_ns TEXT NOT NULL,
          ctime_ns TEXT NOT NULL,
          dev INTEGER NOT NULL,
          ino TEXT NOT NULL,
          nlink INTEGER NOT NULL,
          sha256 TEXT,
          link_target TEXT,
          is_binary INTEGER NOT NULL DEFAULT 0,
          oversize INTEGER NOT NULL DEFAULT 0,
          PRIMARY KEY (checkpoint_id, rel_posix)
        );

        CREATE TABLE IF NOT EXISTS journals (
          tx_id TEXT PRIMARY KEY,
          session_id TEXT NOT NULL,
          tool_use_id TEXT,
          command_checkpoint_id TEXT NOT NULL,
          accepted_working_set_json TEXT,
          state TEXT NOT NULL,
          error_code TEXT,
          error_detail TEXT,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS journal_entry_progress (
          tx_id TEXT NOT NULL,
          rel_posix TEXT NOT NULL,
          action TEXT NOT NULL,
          status TEXT NOT NULL,
          observed_type TEXT,
          observed_sha256 TEXT,
          observed_mode INTEGER,
          observed_link TEXT,
          restored_type TEXT,
          restored_sha256 TEXT,
          restored_mode INTEGER,
          restored_link TEXT,
          detail TEXT,
          PRIMARY KEY (tx_id, rel_posix)
        );

        CREATE TABLE IF NOT EXISTS staged_bundles (
          tx_id TEXT PRIMARY KEY,
          session_id TEXT NOT NULL,
          baseline_checkpoint_id TEXT NOT NULL,
          manifest_json TEXT NOT NULL,
          manifest_sha256 TEXT NOT NULL,
          promoted_at INTEGER,
          created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS promotion_applied_entries (
          seq INTEGER PRIMARY KEY AUTOINCREMENT,
          promo_tx_id TEXT NOT NULL,
          rel_posix TEXT NOT NULL,
          action TEXT NOT NULL,
          prev_entry_type TEXT NOT NULL,
          prev_blob_sha256 TEXT,
          prev_mode INTEGER,
          applied_dev INTEGER,
          applied_ino TEXT,
          applied_mode INTEGER,
          applied_ctime_ns TEXT,
          applied_sha256 TEXT,
          UNIQUE (promo_tx_id, rel_posix)
        );
      `);

      try {
        this.db.exec(`ALTER TABLE active_lock ADD COLUMN owner_pid INTEGER`);
      } catch {
        // column already exists
      }
      try {
        this.db.exec(`ALTER TABLE promotion_applied_entries ADD COLUMN applied_mode INTEGER`);
      } catch {
        // column already exists
      }
      try {
        this.db.exec(`ALTER TABLE promotion_applied_entries ADD COLUMN applied_ctime_ns TEXT`);
      } catch {
        // column already exists
      }
      try {
        this.db.exec(`ALTER TABLE journals ADD COLUMN accepted_working_set_json TEXT`);
      } catch {
        // column already exists
      }

      // Initialize `meta` identity bindings on brand-new stores
      this.withImmediateTransaction(() => {
        const initRow = this.db.prepare(`SELECT value FROM meta WHERE key = 'initialized'`).get();
        if (!initRow) {
          const ins = this.db.prepare(`INSERT INTO meta (key, value) VALUES (?, ?)`);
          ins.run("initialized", "1");
          ins.run("workspace_id", this.workspaceId);
          ins.run("workspace_root", this.canonicalRoot);
          ins.run("marker_token", crypto.randomBytes(16).toString("hex"));
        } else {
          const wsIdRow = this.db.prepare(`SELECT value FROM meta WHERE key = 'workspace_id'`).get();
          const wsRootRow = this.db.prepare(`SELECT value FROM meta WHERE key = 'workspace_root'`).get();
          if (wsIdRow?.value !== this.workspaceId || wsRootRow?.value !== this.canonicalRoot) {
            const err = new Error(
              `SQLite state store workspace identity mismatch (expected ${this.canonicalRoot}).`
            );
            err.code = "STATE_INTEGRITY_FAILURE";
            throw err;
          }
        }
      });
    } catch (err) {
      this.close();
      if (err.code === "STATE_INTEGRITY_FAILURE") throw err;
      const wrapped = new Error(`Authoritative SQLite store corrupted or unreadable: ${err.message}`);
      wrapped.code = "STATE_INTEGRITY_FAILURE";
      throw wrapped;
    }

    return this;
  }

  _verifyExistingStateIntegrity({ expectExistingActiveSession, marker }) {
    const requiredTables = ["meta", "sessions", "checkpoints", "journals"];
    for (const tbl of requiredTables) {
      const row = this.db
        .prepare(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`)
        .get(tbl);
      if (!row) {
        const err = new Error(
          `Replacement or uninitialized SQLite database detected (missing required table '${tbl}').`
        );
        err.code = "STATE_INTEGRITY_FAILURE";
        throw err;
      }
    }

    const getMeta = (k) => this.db.prepare(`SELECT value FROM meta WHERE key = ?`).get(k)?.value;
    if (
      getMeta("initialized") !== "1" ||
      getMeta("workspace_id") !== this.workspaceId ||
      getMeta("workspace_root") !== this.canonicalRoot
    ) {
      const err = new Error(
        `SQLite state store failed workspace identity/initialization check for '${this.canonicalRoot}'.`
      );
      err.code = "STATE_INTEGRITY_FAILURE";
      throw err;
    }

    const verifySessionLinkage = (sid) => {
      const sess = this.db.prepare(`SELECT * FROM sessions WHERE session_id = ?`).get(sid);
      if (!sess) {
        const err = new Error(`Expected active session '${sid}' is missing from authoritative SQLite store.`);
        err.code = "STATE_INTEGRITY_FAILURE";
        throw err;
      }
      const taskCp = this.db
        .prepare(`SELECT checkpoint_id FROM checkpoints WHERE checkpoint_id = ?`)
        .get(sess.task_baseline_id);
      const turnCp = this.db
        .prepare(`SELECT checkpoint_id FROM checkpoints WHERE checkpoint_id = ?`)
        .get(sess.turn_checkpoint_id);
      if (!taskCp || !turnCp) {
        const err = new Error(
          `Session '${sid}' references missing baseline/turn checkpoint(s) in authoritative SQLite store.`
        );
        err.code = "STATE_INTEGRITY_FAILURE";
        throw err;
      }
    };

    if (marker) {
      const expectedToken = getMeta("marker_token");
      if (!marker.markerToken || (expectedToken && marker.markerToken !== expectedToken)) {
        const err = new Error("Workspace session marker token does not match SQLite store token (replacement DB or forged marker detected).");
        err.code = "STATE_INTEGRITY_FAILURE";
        throw err;
      }
      verifySessionLinkage(marker.sessionId);
    }

    const checkMissingMarkerForSession = (sid) => {
      if (marker) return;
      // Only enforce pre-command marker presence when no open journal is awaiting rollback/reconciliation
      const openJournal = this.db
        .prepare(`SELECT tx_id FROM journals WHERE state IN ('ACTIVE', 'ROLLING_BACK', 'RECOVERY_FAILED') LIMIT 1`)
        .get();
      if (openJournal) return;
      const sess = this.db.prepare(`SELECT turn_checkpoint_id FROM sessions WHERE session_id = ?`).get(sid);
      if (!sess) return;
      const recordedMarker = this.db
        .prepare(`SELECT sha256 FROM checkpoint_entries WHERE checkpoint_id = ? AND rel_posix = '.blast-guard-session'`)
        .get(sess.turn_checkpoint_id);
      if (recordedMarker) {
        const err = new Error(
          `Expected workspace session marker '.blast-guard-session' for session '${sid}' was deleted outside an authorized transaction.`
        );
        err.code = "STATE_INTEGRITY_FAILURE";
        throw err;
      }
    };

    if (typeof expectExistingActiveSession === "string") {
      verifySessionLinkage(expectExistingActiveSession);
      checkMissingMarkerForSession(expectExistingActiveSession);
    } else if (expectExistingActiveSession === true) {
      const allSess = this.db.prepare(`SELECT session_id FROM sessions`).all();
      if (allSess.length === 0) {
        const err = new Error("Expected at least one active session in SQLite store, but sessions table is empty.");
        err.code = "STATE_INTEGRITY_FAILURE";
        throw err;
      }
      for (const s of allSess) {
        verifySessionLinkage(s.session_id);
        checkMissingMarkerForSession(s.session_id);
      }
    }
  }

  close() {
    if (this.db) {
      try {
        this.db.close();
      } catch {
        // ignore
      }
      this.db = null;
    }
  }

  withImmediateTransaction(fn) {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const res = fn();
      this.db.exec("COMMIT");
      return res;
    } catch (err) {
      try {
        this.db.exec("ROLLBACK");
      } catch {
        // ignore rollback error
      }
      throw err;
    }
  }

  /**
   * Atomically check unreconciled journals + `active_lock` singleton inside `BEGIN IMMEDIATE` (``).
   */
  acquireAdmissionLock({ txId, ownerKind, sessionId = "default", toolUseId = null, allowMatchingToolUseId = null }) {
    this.withImmediateTransaction(() => {
      this.assertNoUnreconciledTransactions({ allowMatchingToolUseId });
      const existingLock = this.db.prepare(`SELECT * FROM active_lock WHERE singleton = 1`).get();
      if (existingLock) {
        if (!(allowMatchingToolUseId && existingLock.tool_use_id === allowMatchingToolUseId)) {
          const err = new Error(
            `Workspace mutation admission serialized: active lock held by '${existingLock.tx_id}' (${existingLock.owner_kind}).`
          );
          err.code = "UNRECONCILED_ACTIVE_COMMAND";
          throw err;
        }
        return;
      }
      this.db
        .prepare(
          `INSERT INTO active_lock (singleton, tx_id, owner_kind, session_id, tool_use_id, owner_pid, created_at) VALUES (1, ?, ?, ?, ?, ?, ?)`
        )
        .run(txId, ownerKind, sessionId, toolUseId, process.pid, Date.now());
    });
  }

  releaseAdmissionLock(txId) {
    if (!this.db) return;
    this.withImmediateTransaction(() => {
      this.db.prepare(`DELETE FROM active_lock WHERE singleton = 1 AND tx_id = ?`).run(txId);
    });
  }

  assertNoActiveLock() {
    const existingLock = this.db.prepare(`SELECT * FROM active_lock WHERE singleton = 1`).get();
    if (existingLock) {
      const err = new Error(
        `Active transaction lock '${existingLock.tx_id}' (${existingLock.owner_kind}) is currently open.`
      );
      err.code = "UNRECONCILED_ACTIVE_COMMAND";
      throw err;
    }
  }

  blobPathForHash(sha256) {
    return path.join(this.blobsDir, sha256.slice(0, 2), sha256);
  }

  /**
   * Always reads and verifies `absFilePath` content against `expectedSha256` FIRST,
   * even when `dest` already exists in the content-addressed blob store (``)!
   */
  writeVerifiedBlobFromFile(absFilePath, expectedSha256) {
    const bytes = fs.readFileSync(absFilePath);
    const actual = sha256Buffer(bytes);
    if (actual !== expectedSha256) {
      const err = new Error(
        `Live file '${absFilePath}' failed SHA-256 verification (expected ${expectedSha256}, got ${actual}).`
      );
      err.code = "CONCURRENT_SNAPSHOT_RACE";
      throw err;
    }

    const dest = this.blobPathForHash(expectedSha256);
    if (fs.existsSync(dest)) {
      const check = streamSha256File(dest);
      if (check.sha256 === expectedSha256) {
        return dest;
      }
      const err = new Error(`Stored blob ${expectedSha256} failed SHA-256 integrity verification!`);
      err.code = "BLOB_INTEGRITY_ERROR";
      throw err;
    }

    persistSnapshotBlob(absFilePath, dest, bytes, expectedSha256);
    return dest;
  }

  readVerifiedBlob(expectedSha256) {
    const src = this.blobPathForHash(expectedSha256);
    if (!fs.existsSync(src)) {
      const err = new Error(`Missing required recovery blob ${expectedSha256} in ${this.blobsDir}.`);
      err.code = "BLOB_INTEGRITY_ERROR";
      throw err;
    }
    const bytes = fs.readFileSync(src);
    const actual = sha256Buffer(bytes);
    if (actual !== expectedSha256) {
      const err = new Error(
        `Blob ${expectedSha256} failed SHA-256 verification (got ${actual}). Refusing corrupt restoration.`
      );
      err.code = "BLOB_INTEGRITY_ERROR";
      throw err;
    }
    return bytes;
  }

  getUnreconciledJournals(sessionId = null) {
    const sql = sessionId
      ? `SELECT * FROM journals WHERE session_id = ? AND state IN ('ACTIVE', 'ROLLING_BACK', 'RECOVERY_FAILED') ORDER BY created_at ASC`
      : `SELECT * FROM journals WHERE state IN ('ACTIVE', 'ROLLING_BACK', 'RECOVERY_FAILED') ORDER BY created_at ASC`;
    const stmt = this.db.prepare(sql);
    return sessionId ? stmt.all(sessionId) : stmt.all();
  }

  assertNoUnreconciledTransactions({ allowMatchingToolUseId = null } = {}) {
    const openRows = this.getUnreconciledJournals();
    const blocking = openRows.filter(
      (r) => !(allowMatchingToolUseId && r.state === "ACTIVE" && r.tool_use_id === allowMatchingToolUseId)
    );
    if (blocking.length > 0) {
      const first = blocking[0];
      const err = new Error(
        `Unreconciled transaction '${first.tx_id}' in state '${first.state}' blocks further workspace mutations. Run 'blast-guard rollback --recover' first.`
      );
      err.code =
        first.state === "ACTIVE" ? "UNRECONCILED_ACTIVE_COMMAND" : "UNRECOVERED_TRANSACTION";
      err.journal = first;
      throw err;
    }
  }

  /**
   * Scan the COMPLETE writable workspace namespace (`dir`, `file`, and `symlink` entries) (``, ``):
   * - NEVER skips writable directories via `AUDIT_PERFORMANCE_IGNORED_DIRS` (`build/`, `dist/`, etc. are 100% inventoried!)
   * - Tracks directory modes so `chmod` or empty-dir additions/deletions are losslessly detected & recovered
   * - Preflights whole-tree extended attributes and ACLs (`inspectTreePlatformMetadata`) when `strictCheckpointCoverage === true`
   * - Rejects ANY regular file with `nlink > 1` (`UNSAFE_HARDLINK_ALIAS`)
   */
  scanWorkspaceNamespace({
    previousEntriesMap = null,
    storeBlobs = true,
    strictCheckpointCoverage = true,
    checkTreeMetadata = strictCheckpointCoverage,
  } = {}) {
    const startedAt = performance.now();
    const entries = new Map();
    let totalBytes = 0;
    let coverageComplete = true;
    let incompleteCode = null;
    let incompleteReason = null;
    let blockingFile = null;

    if (checkTreeMetadata) {
      const treeMeta = inspectTreePlatformMetadata(this.canonicalRoot, {
        exemptXattrs: this.exemptXattrs,
        timeoutMs: this.limits.maxScanMs,
      });
      if (!treeMeta.ok && strictCheckpointCoverage) {
        return {
          coverageComplete: false,
          incompleteCode: treeMeta.code,
          incompleteReason: treeMeta.reason,
          totalFiles: 0,
          totalBytes: 0,
          scanMs: Number((performance.now() - startedAt).toFixed(2)),
          gitControl: hashGitControlPlane(this.canonicalRoot),
          entries,
        };
      }
      if (!treeMeta.ok) {
        coverageComplete = false;
        incompleteCode = treeMeta.code;
        incompleteReason = treeMeta.reason;
      }
    }

    // Inventory workspace root `"."` itself so `chmod 0777 .` or root special bits are tracked & restored (``)!
    try {
      const rootSt = fs.lstatSync(this.canonicalRoot, { bigint: true });
      const rootModeCheck = checkUnsupportedFileMetadata(this.canonicalRoot, rootSt, { checkXattr: false });
      if (!rootModeCheck.ok) {
        coverageComplete = false;
        incompleteCode = rootModeCheck.code;
        incompleteReason = rootModeCheck.reason;
        if (strictCheckpointCoverage) {
          return {
            coverageComplete: false,
            incompleteCode,
            incompleteReason,
            totalFiles: 0,
            totalBytes: 0,
            scanMs: Number((performance.now() - startedAt).toFixed(2)),
            gitControl: hashGitControlPlane(this.canonicalRoot),
            entries,
          };
        }
      }
      entries.set(".", {
        relPosix: ".",
        entryType: "dir",
        mode: Number(rootSt.mode) & 0o7777,
        size: 0,
        mtimeNs: rootSt.mtimeNs.toString(),
        ctimeNs: rootSt.ctimeNs.toString(),
        dev: Number(rootSt.dev),
        ino: rootSt.ino.toString(),
        nlink: Number(rootSt.nlink),
        sha256: null,
        linkTarget: null,
        isBinary: 0,
        oversize: 0,
      });
    } catch (err) {
      coverageComplete = false;
      incompleteCode = "CHECKPOINT_COVERAGE_INCOMPLETE";
      incompleteReason = `Failed statting workspace root '${this.canonicalRoot}': ${err.message}`;
      if (strictCheckpointCoverage) {
        return {
          coverageComplete: false,
          incompleteCode,
          incompleteReason,
          totalFiles: 0,
          totalBytes: 0,
          scanMs: Number((performance.now() - startedAt).toFixed(2)),
          gitControl: hashGitControlPlane(this.canonicalRoot),
          entries,
        };
      }
    }

    const walk = (absDir, relDirPosix) => {
      const elapsed = performance.now() - startedAt;
      if (elapsed > this.limits.maxScanMs) {
        coverageComplete = false;
        incompleteCode = "CHECKPOINT_COVERAGE_INCOMPLETE";
        incompleteReason = `Workspace scan exceeded maxScanMs (${this.limits.maxScanMs} ms).`;
        return;
      }

      let dirEntries;
      try {
        dirEntries = fs.readdirSync(absDir, { withFileTypes: true });
      } catch (err) {
        coverageComplete = false;
        incompleteCode = "CHECKPOINT_COVERAGE_INCOMPLETE";
        incompleteReason = `Failed reading directory '${relDirPosix || "."}': ${err.message}`;
        return;
      }

      dirEntries.sort((a, b) => a.name.localeCompare(b.name));

      for (const ent of dirEntries) {
        if (!coverageComplete && strictCheckpointCoverage) return;
        const childRel = relDirPosix ? `${relDirPosix}/${ent.name}` : ent.name;
        const relPosix = toPosixRel(childRel);

        // `.git` internals are tracked via `hashGitControlPlane`
        if (relPosix === ".git" || relPosix.startsWith(".git/")) {
          continue;
        }
        // Note: `.blast-guard-session` is intentionally inventoried as a Ring-00 file (``)
        // so any command deleting, tampering, or chmodding `.blast-guard-session` triggers Ring-00 rollback!

        if (entries.size >= this.limits.maxTrackedFiles) {
          coverageComplete = false;
          incompleteCode = "CHECKPOINT_COVERAGE_INCOMPLETE";
          incompleteReason = `Workspace exceeds maxTrackedFiles (${this.limits.maxTrackedFiles}).`;
          return;
        }

        const childAbs = path.join(absDir, ent.name);
        const st = fs.lstatSync(childAbs, { bigint: true });

        const metaModeCheck = checkUnsupportedFileMetadata(childAbs, st, { checkXattr: false });
        if (!metaModeCheck.ok) {
          coverageComplete = false;
          incompleteCode = metaModeCheck.code;
          incompleteReason = metaModeCheck.reason;
          if (strictCheckpointCoverage) return;
        }

        if (st.isSymbolicLink()) {
          const linkTarget = fs.readlinkSync(childAbs);
          const resolvedTarget = path.resolve(absDir, linkTarget);
          let realTarget = resolvedTarget;
          try {
            realTarget = fs.realpathSync.native(childAbs);
          } catch {
            // keep lexical target if dangling
          }
          if (
            isContainedRelativePath(path.relative(BLAST_GUARD_PACKAGE_ROOT, realTarget)) ||
            isContainedRelativePath(path.relative(BLAST_GUARD_PACKAGE_ROOT, resolvedTarget))
          ) {
            coverageComplete = false;
            incompleteCode = "IMMUTABLE_GUARD_BINARY";
            incompleteReason = `Workspace symlink '${relPosix}' points inside blast-guard installation.`;
            if (strictCheckpointCoverage) return;
          } else {
            const relTarget = path.relative(this.canonicalRoot, realTarget);
            if (!isContainedRelativePath(relTarget)) {
              coverageComplete = false;
              incompleteCode = "UNSAFE_LINK_ALIAS";
              incompleteReason = `Workspace symlink '${relPosix}' points outside workspace root (${linkTarget}).`;
              if (strictCheckpointCoverage) return;
            } else {
              const targetRing = classifyProtectionRing(toPosixRel(relTarget));
              const srcRing = classifyProtectionRing(relPosix);
              if (
                (targetRing.ring === "RING_00" || targetRing.ring === "RING_0") &&
                srcRing.ring !== targetRing.ring
              ) {
                coverageComplete = false;
                incompleteCode = "UNSAFE_LINK_ALIAS";
                incompleteReason = `Symlink '${relPosix}' aliases protected target '${toPosixRel(relTarget)}'.`;
                if (strictCheckpointCoverage) return;
              }
            }
          }

          entries.set(relPosix, {
            relPosix,
            entryType: "symlink",
            mode: Number(st.mode) & 0o7777,
            size: Number(st.size),
            mtimeNs: st.mtimeNs.toString(),
            ctimeNs: st.ctimeNs.toString(),
            dev: Number(st.dev),
            ino: st.ino.toString(),
            nlink: Number(st.nlink),
            sha256: null,
            linkTarget,
            isBinary: 0,
            oversize: 0,
          });
          continue;
        }

        if (st.isDirectory()) {
          entries.set(relPosix, {
            relPosix,
            entryType: "dir",
            mode: Number(st.mode) & 0o7777,
            size: 0,
            mtimeNs: st.mtimeNs.toString(),
            ctimeNs: st.ctimeNs.toString(),
            dev: Number(st.dev),
            ino: st.ino.toString(),
            nlink: Number(st.nlink),
            sha256: null,
            linkTarget: null,
            isBinary: 0,
            oversize: 0,
          });
          walk(childAbs, relPosix);
          continue;
        }

        if (!st.isFile()) {
          coverageComplete = false;
          incompleteCode = "UNSUPPORTED_SPECIAL_FILE";
          incompleteReason = `Unsupported special file (FIFO/socket/device) at '${relPosix}'.`;
          if (strictCheckpointCoverage) return;
          continue;
        }

        // Reject ALL multi-link regular files (`nlink > 1`) (``, ``)
        if (Number(st.nlink) > 1) {
          coverageComplete = false;
          incompleteCode = "UNSAFE_HARDLINK_ALIAS";
          incompleteReason = `Hardlink '${relPosix}' (nlink=${st.nlink}) creates an inode alias that breaks single-path isolation.`;
          if (strictCheckpointCoverage) return;
        }

        const ringInfo = classifyProtectionRing(relPosix);
        const isProtectedRing = ringInfo.ring === "RING_00" || ringInfo.ring === "RING_0";
        const sizeNum = Number(st.size);

        if (
          sizeNum > this.limits.maxSingleBlobBytes ||
          totalBytes + sizeNum > this.limits.maxTotalSnapshotBytes
        ) {
          coverageComplete = false;
          incompleteCode = "CHECKPOINT_COVERAGE_INCOMPLETE";
          const singleFileLimit = sizeNum > this.limits.maxSingleBlobBytes;
          blockingFile = {
            kind: singleFileLimit ? "file" : "total",
            path: relPosix,
            sizeBytes: sizeNum,
            limitBytes: singleFileLimit ? this.limits.maxSingleBlobBytes : this.limits.maxTotalSnapshotBytes,
          };
          incompleteReason =
            singleFileLimit
              ? `File '${relPosix}' (${sizeNum} bytes) exceeds maxSingleBlobBytes (${this.limits.maxSingleBlobBytes}).`
              : `Workspace snapshot exceeds maxTotalSnapshotBytes (${this.limits.maxTotalSnapshotBytes}).`;
          entries.set(relPosix, {
            relPosix,
            entryType: "file",
            mode: Number(st.mode) & 0o7777,
            size: sizeNum,
            mtimeNs: st.mtimeNs.toString(),
            ctimeNs: st.ctimeNs.toString(),
            dev: Number(st.dev),
            ino: st.ino.toString(),
            nlink: Number(st.nlink),
            sha256: null,
            linkTarget: null,
            isBinary: 1,
            oversize: 1,
          });
          if (strictCheckpointCoverage) return;
          continue;
        }

        totalBytes += sizeNum;

        let sha256 = null;
        let isBinary = 0;
        const prev = !isProtectedRing && previousEntriesMap ? previousEntriesMap.get(relPosix) : null;
        if (
          prev &&
          prev.entryType === "file" &&
          !prev.oversize &&
          prev.size === sizeNum &&
          prev.mtimeNs === st.mtimeNs.toString() &&
          prev.ctimeNs === st.ctimeNs.toString() &&
          prev.ino === st.ino.toString() &&
          prev.sha256 &&
          (!storeBlobs || fs.existsSync(this.blobPathForHash(prev.sha256)))
        ) {
          sha256 = prev.sha256;
          isBinary = prev.isBinary;
        } else {
          const bytes = fs.readFileSync(childAbs);
          sha256 = sha256Buffer(bytes);
          isBinary = isProbablyBinaryBuffer(bytes) ? 1 : 0;
          if (storeBlobs) {
            const dest = this.blobPathForHash(sha256);
            if (!fs.existsSync(dest)) {
              persistSnapshotBlob(childAbs, dest, bytes, sha256);
            }
          }
        }

        entries.set(relPosix, {
          relPosix,
          entryType: "file",
          mode: Number(st.mode) & 0o7777,
          size: sizeNum,
          mtimeNs: st.mtimeNs.toString(),
          ctimeNs: st.ctimeNs.toString(),
          dev: Number(st.dev),
          ino: st.ino.toString(),
          nlink: Number(st.nlink),
          sha256,
          linkTarget: null,
          isBinary,
          oversize: 0,
        });
      }
    };

    walk(this.canonicalRoot, "");

    const gitControl = hashGitControlPlane(this.canonicalRoot);
    return {
      coverageComplete,
      incompleteCode,
      incompleteReason,
      blockingFile,
      totalFiles: entries.size,
      totalBytes,
      scanMs: Number((performance.now() - startedAt).toFixed(2)),
      gitControl,
      entries,
    };
  }

  persistCheckpoint(sessionId, kind, scanResult) {
    const checkpointId = `cp-${kind}-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`;
    const now = Date.now();
    const insertCp = this.db.prepare(`
      INSERT INTO checkpoints (
        checkpoint_id, session_id, kind, git_control_json, coverage_complete,
        incomplete_reason, total_files, total_bytes, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const insertEntry = this.db.prepare(`
      INSERT INTO checkpoint_entries (
        checkpoint_id, rel_posix, entry_type, mode, size, mtime_ns, ctime_ns,
        dev, ino, nlink, sha256, link_target, is_binary, oversize
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertCp.run(
      checkpointId,
      sessionId,
      kind,
      scanResult.gitControl ? JSON.stringify(scanResult.gitControl) : null,
      scanResult.coverageComplete ? 1 : 0,
      scanResult.incompleteReason || null,
      scanResult.totalFiles,
      scanResult.totalBytes,
      now
    );

    for (const ent of scanResult.entries.values()) {
      insertEntry.run(
        checkpointId,
        ent.relPosix,
        ent.entryType,
        ent.mode,
        ent.size,
        ent.mtimeNs,
        ent.ctimeNs,
        ent.dev,
        ent.ino,
        ent.nlink,
        ent.sha256,
        ent.linkTarget,
        ent.isBinary,
        ent.oversize
      );
    }
    return checkpointId;
  }

  loadCheckpoint(checkpointId) {
    const cp = this.db
      .prepare(`SELECT * FROM checkpoints WHERE checkpoint_id = ?`)
      .get(checkpointId);
    if (!cp) {
      const err = new Error(`Checkpoint '${checkpointId}' missing from SQLite store.`);
      err.code = "STATE_INTEGRITY_FAILURE";
      throw err;
    }
    const rows = this.db
      .prepare(`SELECT * FROM checkpoint_entries WHERE checkpoint_id = ?`)
      .all(checkpointId);
    const entries = new Map();
    for (const r of rows) {
      entries.set(r.rel_posix, {
        relPosix: r.rel_posix,
        entryType: r.entry_type,
        mode: r.mode,
        size: r.size,
        mtimeNs: r.mtime_ns,
        ctimeNs: r.ctime_ns,
        dev: r.dev,
        ino: r.ino,
        nlink: r.nlink,
        sha256: r.sha256,
        linkTarget: r.link_target,
        isBinary: r.is_binary,
        oversize: r.oversize,
      });
    }
    return {
      checkpointId: cp.checkpoint_id,
      sessionId: cp.session_id,
      kind: cp.kind,
      gitControl: cp.git_control_json ? JSON.parse(cp.git_control_json) : null,
      coverageComplete: Boolean(cp.coverage_complete),
      incompleteReason: cp.incomplete_reason,
      totalFiles: cp.total_files,
      totalBytes: cp.total_bytes,
      entries,
    };
  }

  loadSession(sessionId = "default") {
    const row = this.db.prepare(`SELECT * FROM sessions WHERE session_id = ?`).get(sessionId);
    if (!row) return null;
    return {
      sessionId: row.session_id,
      turnId: row.turn_id,
      tier: row.tier,
      budget: JSON.parse(row.budget_json),
      workingSet: JSON.parse(row.working_set_json),
      grants: JSON.parse(row.grants_json),
      denySet: JSON.parse(row.deny_set_json),
      taskBaselineId: row.task_baseline_id,
      turnCheckpointId: row.turn_checkpoint_id,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      escalation: this.getPendingEscalation(sessionId),
    };
  }

  listSessions() {
    const rows = this.db
      .prepare(`SELECT session_id FROM sessions ORDER BY updated_at DESC`)
      .all();
    return rows.map((r) => this.loadSession(r.session_id)).filter(Boolean);
  }

  /**
   * Initialize Turn 1 or update Turn K policy atomically (``, ``):
   * - Serializes via `active_lock` inside `BEGIN IMMEDIATE`
   * - Updates `task_baseline_id` when `resetTask === true`, while keeping `task_baseline_id` immutable across ordinary Turn 2+ updates!
   */
  startOrUpdateTurn(rawPrompt, { sessionId = "default", isSynthetic = false, resetTask = false } = {}) {
    const lockId = `turn-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`;
    this.acquireAdmissionLock({ txId: lockId, ownerKind: "turn_policy", sessionId });

    try {
      const existing = resetTask ? null : this.loadSession(sessionId);
      const nextTurnId = existing ? existing.turnId + 1 : 1;
      const intent = classifyIntent(rawPrompt, { turnId: nextTurnId, isSynthetic });
      const pendingCard = this.db.prepare("SELECT value FROM meta WHERE key = ?").get(`escalation:${sessionId}`);
      const approval = resetTask ? null : resolveVoiApproval(pendingCard ? JSON.parse(pendingCard.value) : null, rawPrompt, { isSynthetic, turnId: nextTurnId });
      if (approval?.grant) intent.grants.push(approval.grant);

      const prevCp = existing ? this.loadCheckpoint(existing.turnCheckpointId) : null;
      const scan = this.scanWorkspaceNamespace({
        previousEntriesMap: prevCp ? prevCp.entries : null,
        storeBlobs: true,
        strictCheckpointCoverage: false,
        checkTreeMetadata: true,
      });

      const now = Date.now();
      const sessionState = this.withImmediateTransaction(() => {
        const turnCheckpointId = this.persistCheckpoint(sessionId, `turn-${nextTurnId}`, scan);
        const taskBaselineId =
          resetTask || !existing?.taskBaselineId ? turnCheckpointId : existing.taskBaselineId;

        const tierOrder = { SURGICAL_FIX: 1, FOCUSED_FEATURE: 2, EXPLICIT_REFACTOR: 3 };
        const chosenTier =
          existing && tierOrder[existing.tier] > tierOrder[intent.tier]
            ? existing.tier
            : intent.tier;
        // An unresolved prohibition must survive a follow-up such as "continue".
        // Only an explicit new-task reset discards the previous session policy.
        const unresolvedProhibition = Boolean(
          intent.unresolvedProhibition || existing?.budget?.unresolvedProhibition
        );
        let chosenBudget = unresolvedProhibition
          ? { ...TIER_BUDGETS[chosenTier], unresolvedProhibition: true }
          : TIER_BUDGETS[chosenTier];

        const mergedGrants = mergeTurnGrants(existing?.grants || [], intent.grants).filter(
          (g) => !intent.denySet.includes(g.pathPattern)
        );
        const mergedDenySet = Array.from(
          new Set([
            ...(existing?.denySet || []).filter(
              (d) => !intent.grants.some((g) => g.pathPattern === d)
            ),
            ...intent.denySet,
          ])
        );

        const wsSet = new Set(existing?.workingSet || []);
        for (const g of mergedGrants) {
          if (!g.matchBasename && !g.invalidNarrowScope) {
            const r = classifyProtectionRing(g.pathPattern);
            if (r.ring !== "RING_00" && r.ring !== "RING_0" && wsSet.size < chosenBudget.maxWritableFiles) {
              wsSet.add(g.pathPattern);
            }
          }
        }

        const workingSetArr = Array.from(wsSet);
        const graph = buildWorkspaceDependencyGraph(this.canonicalRoot, { maxFiles: 2000 });
        chosenBudget = { ...chosenBudget, scopePolicy: buildScopePolicy(graph, {
          grants: mergedGrants, referenceMentions: intent.referenceMentions,
          existing: existing?.budget?.scopePolicy, turnId: nextTurnId, workspaceFiles: [...scan.entries.keys()],
        }) };
        if (chosenTier === "EXPLICIT_REFACTOR" && chosenBudget.scopePolicy.complete) {
          const group = refactorBoundary(chosenBudget.scopePolicy, wsSet);
          chosenBudget.maxWritableFiles = Math.max(chosenBudget.maxWritableFiles, group.allowed.size);
        }
        this.db
          .prepare(`
            INSERT INTO sessions (
              session_id, turn_id, tier, budget_json, working_set_json, grants_json,
              deny_set_json, task_baseline_id, turn_checkpoint_id, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(session_id) DO UPDATE SET
              turn_id = excluded.turn_id,
              tier = excluded.tier,
              budget_json = excluded.budget_json,
              working_set_json = excluded.working_set_json,
              grants_json = excluded.grants_json,
              deny_set_json = excluded.deny_set_json,
              task_baseline_id = excluded.task_baseline_id,
              turn_checkpoint_id = excluded.turn_checkpoint_id,
              updated_at = excluded.updated_at
          `)
          .run(
            sessionId,
            nextTurnId,
            chosenTier,
            JSON.stringify(chosenBudget),
            JSON.stringify(workingSetArr),
            JSON.stringify(mergedGrants),
            JSON.stringify(mergedDenySet),
            taskBaselineId,
            turnCheckpointId,
            existing?.createdAt || now,
            now
          );

        this.db.prepare("DELETE FROM meta WHERE key = ?").run(this.sessionAcceptedVersionKey(sessionId));
        if (!existing?.taskBaselineId || resetTask) {
          this.db.prepare("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
            .run(this.sessionTaskAcceptedVersionKey(sessionId), JSON.stringify({ taskBaselineId, files: [], complete: true }));
        }
        if (approval) this.db.prepare("UPDATE meta SET value = ? WHERE key = ?").run(JSON.stringify(approval.card), `escalation:${sessionId}`);
        else if (resetTask) this.db.prepare("DELETE FROM meta WHERE key = ?").run(`escalation:${sessionId}`);
        else if (pendingCard && !isSynthetic) {
          const stale = JSON.parse(pendingCard.value);
          if (stale.status === "pending") this.db.prepare("UPDATE meta SET value = ? WHERE key = ?").run(JSON.stringify({ ...stale, status: "expired", expiredAtTurn: nextTurnId }), `escalation:${sessionId}`);
        }
        this.db.prepare(`DELETE FROM active_lock WHERE singleton = 1 AND tx_id = ?`).run(lockId);

        return {
          sessionId,
          turnId: nextTurnId,
          tier: chosenTier,
          budget: chosenBudget,
          workingSet: workingSetArr,
          grants: mergedGrants,
          denySet: mergedDenySet,
          taskBaselineId,
          turnCheckpointId,
          scanMs: scan.scanMs,
          coverageComplete: scan.coverageComplete,
          incompleteCode: scan.incompleteCode,
          incompleteReason: scan.incompleteReason,
          blockingFile: scan.blockingFile ?? null,
        };
      });

      return sessionState;
    } catch (err) {
      this.releaseAdmissionLock(lockId);
      throw err;
    }
  }

  ensureActiveSession(sessionId = "default", fallbackPrompt = "Fix the issue") {
    const existing = this.loadSession(sessionId);
    if (existing) return existing;
    return this.startOrUpdateTurn(fallbackPrompt, { sessionId });
  }

  sessionAcceptedVersionKey(sessionId) {
    return `session-accepted-files:${sha256Buffer(Buffer.from(sessionId, "utf8"))}`;
  }

  sessionTaskAcceptedVersionKey(sessionId) {
    return `task-accepted-files:${sha256Buffer(Buffer.from(sessionId, "utf8"))}`;
  }

  loadTaskAcceptedFileVersions(session) {
    const row = this.db.prepare("SELECT value FROM meta WHERE key = ?").get(this.sessionTaskAcceptedVersionKey(session.sessionId));
    if (!row) return { files: this.loadAcceptedFileVersions(session), complete: session.turnId === 1 };
    try {
      const saved = JSON.parse(row.value);
      if (saved.taskBaselineId !== session.taskBaselineId || !Array.isArray(saved.files)) throw new Error("Invalid task accepted-file state.");
      return { files: new Map(saved.files), complete: saved.complete !== false };
    } catch (cause) {
      const error = new Error(`Session '${session.sessionId}' task accepted-file state is invalid: ${cause.message}`);
      error.code = "STATE_INTEGRITY_FAILURE";
      throw error;
    }
  }

  fileVersionFingerprint(entry) {
    if (!entry) return null;
    return [entry.entryType, entry.sha256 || null, entry.mode & 0o7777, entry.linkTarget || null, Boolean(entry.oversize)];
  }

  loadAcceptedFileVersions(session) {
    const row = this.db.prepare("SELECT value FROM meta WHERE key = ?").get(this.sessionAcceptedVersionKey(session.sessionId));
    if (!row) return new Map();
    try {
      const saved = JSON.parse(row.value);
      if (saved.turnCheckpointId !== session.turnCheckpointId || !Array.isArray(saved.files)) throw new Error("Invalid accepted-file version state.");
      return new Map(saved.files);
    } catch (cause) {
      const error = new Error(`Session '${session.sessionId}' accepted-file version state is invalid: ${cause.message}`);
      error.code = "STATE_INTEGRITY_FAILURE";
      throw error;
    }
  }

  findSessionWriteConflicts(sessionId, beforeEntries, paths) {
    const session = this.loadSession(sessionId);
    if (!session) throw new Error(`Session '${sessionId}' is missing.`);
    const accepted = this.loadAcceptedFileVersions(session);
    const turn = this.loadCheckpoint(session.turnCheckpointId);
    const conflicts = [];
    for (const relPosix of new Set(paths)) {
      const expected = accepted.has(relPosix) ? accepted.get(relPosix) : this.fileVersionFingerprint(turn.entries.get(relPosix));
      const current = this.fileVersionFingerprint(beforeEntries.get(relPosix));
      if (JSON.stringify(expected) !== JSON.stringify(current)) {
        conflicts.push({ code: "SESSION_WRITE_CONFLICT", path: relPosix, message: `File '${relPosix}' changed outside session '${sessionId}' since its last accepted version. Start a new user turn to review the current file before editing it.` });
      }
    }
    return conflicts;
  }

  // Call inside the same SQLite transaction that marks the command/promotion CLEAN.
  recordSessionAcceptedFiles(sessionId, paths, afterEntries) {
    const session = this.loadSession(sessionId);
    const accepted = this.loadAcceptedFileVersions(session);
    const taskAccepted = this.loadTaskAcceptedFileVersions(session);
    for (const relPosix of new Set(paths)) {
      accepted.set(relPosix, this.fileVersionFingerprint(afterEntries.get(relPosix)));
      taskAccepted.files.set(relPosix, this.fileVersionFingerprint(afterEntries.get(relPosix)));
    }
    const saved = { turnCheckpointId: session.turnCheckpointId, files: [...accepted] };
    this.db.prepare("INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
      .run(this.sessionAcceptedVersionKey(sessionId), JSON.stringify(saved));
    this.db.prepare("INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
      .run(this.sessionTaskAcceptedVersionKey(sessionId), JSON.stringify({ taskBaselineId: session.taskBaselineId,
        files: [...taskAccepted.files], complete: taskAccepted.complete }));
  }

  updateSessionWorkingSet(sessionId, nextWorkingSet) {
    this.withImmediateTransaction(() => {
      this.assertNoUnreconciledTransactions();
      this.assertNoActiveLock();
      this.db
        .prepare(`UPDATE sessions SET working_set_json = ?, updated_at = ? WHERE session_id = ?`)
        .run(JSON.stringify(nextWorkingSet), Date.now(), sessionId);
    });
  }

  recordReadObservation(sessionId, rawFilePath) {
    const session = this.loadSession(sessionId);
    if (!session || typeof rawFilePath !== "string") return null;
    let realReadPath;
    try { realReadPath = fs.realpathSync.native(path.resolve(this.canonicalRoot, rawFilePath)); }
    catch { return null; }
    const inspected = inspectWorkspacePath(this.canonicalRoot, realReadPath, { forWrite: false, allowDirectoryLeaf: false });
    if (!inspected.ok || !inspected.lstat?.isFile()) return null;
    const fd = fs.openSync(inspected.absPath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    const policy = session.budget.scopePolicy;
    const needsContent = classifyProtectionRing(inspected.relPosix).ring === "RING_0" || policy?.references.includes(inspected.relPosix) || /\.(?:ts|tsx)$/.test(inspected.relPosix) || /(?:^|\/)(?:types?|typings|interfaces?)\.(?:js|mjs|py)$/i.test(inspected.relPosix);
    let text = null;
    try {
      const stat = fs.fstatSync(fd);
      if (!stat.isFile() || stat.size > this.limits.maxSingleBlobBytes) return null;
      if (needsContent) text = fs.readFileSync(fd, "utf8");
    } finally {
      fs.closeSync(fd);
    }
    return this.withImmediateTransaction(() => {
      const current = this.loadSession(sessionId);
      if (!current.budget.scopePolicy) return null;
      const policy = observeScopeRead(current.budget.scopePolicy, { file: inspected.relPosix, text, turnId: current.turnId, grants: current.grants });
      const budget = { ...current.budget, scopePolicy: policy };
      this.db.prepare("UPDATE sessions SET budget_json = ?, updated_at = ? WHERE session_id = ?").run(JSON.stringify(budget), Date.now(), sessionId);
      return { file: inspected.relPosix, frozen: policy.frozenReferences.some(entry => entry.path === inspected.relPosix), leaseEvidence: policy.leaseEvidence.filter(entry => entry.path === inspected.relPosix) };
    });
  }

  getPendingEscalation(sessionId = "default") {
    const row = this.db.prepare("SELECT value FROM meta WHERE key = ?").get(`escalation:${sessionId}`);
    return row ? JSON.parse(row.value) : null;
  }

  /**
   * Open a durable `'ACTIVE'` command checkpoint & journal before a mutating tool/command runs (``):
   * - Reserves `active_lock` singleton inside `BEGIN IMMEDIATE` BEFORE scanning so concurrent calls cannot interleave!
   * - Releases `active_lock` on preflight scan failure; retains `active_lock` while `'ACTIVE'` until reconciled!
   */
  beginCommandTransaction({ sessionId = "default", toolUseId = null, acceptedWorkingSet = null, writePaths = null } = {}) {
    // Ensure session exists before acquiring the command lock (startOrUpdateTurn acquires & releases its own lock)
    const session = this.ensureActiveSession(sessionId);

    const txId = `tx-${Date.now()}-${crypto.randomBytes(5).toString("hex")}`;
    this.acquireAdmissionLock({
      txId,
      ownerKind: "command_journal",
      sessionId,
      toolUseId,
    });

    try {
      const turnCp = this.loadCheckpoint(session.turnCheckpointId);
      const scan = this.scanWorkspaceNamespace({
        previousEntriesMap: turnCp.entries,
        storeBlobs: true,
        strictCheckpointCoverage: true,
      });

      if (!scan.coverageComplete) {
        const err = new Error(
          scan.incompleteReason || "Workspace cannot be losslessly snapshotted for checkpoint mode."
        );
        err.code = scan.incompleteCode || "CHECKPOINT_COVERAGE_INCOMPLETE";
        throw err;
      }

      if (writePaths) {
        const conflicts = this.findSessionWriteConflicts(sessionId, scan.entries, writePaths);
        if (conflicts.length) {
          const error = new Error(conflicts.map((conflict) => conflict.message).join("\n"));
          error.code = "SESSION_WRITE_CONFLICT";
          throw error;
        }
      }

      const acceptedWsJson =
        acceptedWorkingSet !== null && acceptedWorkingSet !== undefined
          ? JSON.stringify(Array.from(acceptedWorkingSet))
          : null;

      const now = Date.now();
      const commandCheckpointId = this.withImmediateTransaction(() => {
        const cpId = this.persistCheckpoint(sessionId, "command", scan);
        this.db
          .prepare(`
            INSERT INTO journals (
              tx_id, session_id, tool_use_id, command_checkpoint_id, accepted_working_set_json, state, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?, ?)
          `)
          .run(txId, sessionId, toolUseId, cpId, acceptedWsJson, now, now);
        return cpId;
      });

      return {
        txId,
        sessionId,
        toolUseId,
        commandCheckpointId,
        scanMs: scan.scanMs,
      };
    } catch (err) {
      this.releaseAdmissionLock(txId);
      throw err;
    }
  }

  abortCommandTransaction(txId) {
    this.withImmediateTransaction(() => {
      this.db
        .prepare(`UPDATE journals SET state = 'ABORTED', updated_at = ? WHERE tx_id = ? AND state = 'ACTIVE'`)
        .run(Date.now(), txId);
      this.db.prepare(`DELETE FROM active_lock WHERE singleton = 1 AND tx_id = ?`).run(txId);
    });
  }

  readBaselineTextFromEntry(entry) {
    if (!entry || entry.entryType !== "file" || entry.oversize || entry.isBinary || !entry.sha256) {
      return null;
    }
    const bytes = this.readVerifiedBlob(entry.sha256);
    return bytes.toString("utf8");
  }

  /**
   * Compute full namespace diff (`beforeKeys ∪ afterKeys`) across files, symlinks, directories, and `.git` control plane.
   */
  diffNamespaces(commandCp, taskBaselineCp, afterScan, { readFromRoot = this.canonicalRoot } = {}) {
    const allPaths = new Set([
      ...commandCp.entries.keys(),
      ...afterScan.entries.keys(),
    ]);
    const diffs = [];

    const hasDescendantInMap = (map, dirPosix) => {
      const prefix = `${dirPosix}/`;
      for (const key of map.keys()) {
        if (key.startsWith(prefix)) return true;
      }
      return false;
    };

    const beforeGitDigest = commandCp.gitControl?.digest || commandCp.gitControl?.sha256 || null;
    const afterGitDigest = afterScan.gitControl?.digest || afterScan.gitControl?.sha256 || null;
    if (beforeGitDigest !== afterGitDigest) {
      diffs.push({
        relPosix: ".git/HEAD",
        changeType: "modify",
        gitControlTampered: true,
        commandBeforeText: beforeGitDigest || "",
        taskBaselineText: beforeGitDigest || "",
        afterText: afterGitDigest || "",
        isBinary: false,
      });
    }

    for (const relPosix of Array.from(allPaths).sort()) {
      const b = commandCp.entries.get(relPosix);
      const a = afterScan.entries.get(relPosix);
      const t = taskBaselineCp ? taskBaselineCp.entries.get(relPosix) : b;

      if (!b && a) {
        if (a.entryType === "dir") {
          // Only report standalone empty directory additions (parent dirs of added files are covered by those files, unless Ring-00)
          const rInfo = classifyProtectionRing(relPosix);
          if (rInfo.ring === "RING_00" || !hasDescendantInMap(afterScan.entries, relPosix)) {
            diffs.push({
              relPosix,
              changeType: "add",
              isDirectory: true,
              beforeEntry: null,
              afterEntry: a,
              commandBeforeText: null,
              taskBaselineText: null,
              afterText: null,
              isBinary: false,
            });
          }
          continue;
        }
        let afterText = null;
        if (a.entryType === "file" && !a.isBinary && !a.oversize) {
          afterText = fs.readFileSync(path.join(readFromRoot, relPosix), "utf8");
        }
        diffs.push({
          relPosix,
          changeType: a.entryType === "symlink" ? "type-change" : "add",
          isDirectory: false,
          beforeEntry: null,
          afterEntry: a,
          commandBeforeText: null,
          taskBaselineText: t ? this.readBaselineTextFromEntry(t) : null,
          afterText,
          isBinary: Boolean(a.isBinary || a.oversize),
        });
        continue;
      }

      if (b && !a) {
        if (b.entryType === "dir") {
          const rInfo = classifyProtectionRing(relPosix);
          if (rInfo.ring === "RING_00" || !hasDescendantInMap(commandCp.entries, relPosix)) {
            diffs.push({
              relPosix,
              changeType: "delete",
              isDirectory: true,
              beforeEntry: b,
              afterEntry: null,
              commandBeforeText: null,
              taskBaselineText: null,
              afterText: null,
              isBinary: false,
            });
          }
          continue;
        }
        diffs.push({
          relPosix,
          changeType: "delete",
          isDirectory: false,
          beforeEntry: b,
          afterEntry: null,
          commandBeforeText: this.readBaselineTextFromEntry(b),
          taskBaselineText: t ? this.readBaselineTextFromEntry(t) : null,
          afterText: null,
          isBinary: Boolean(b.isBinary || b.oversize),
        });
        continue;
      }

      if (b.entryType !== a.entryType) {
        diffs.push({
          relPosix,
          changeType: "type-change",
          isDirectory: a.entryType === "dir",
          beforeEntry: b,
          afterEntry: a,
          commandBeforeText: this.readBaselineTextFromEntry(b),
          taskBaselineText: t ? this.readBaselineTextFromEntry(t) : null,
          afterText: null,
          isBinary: true,
        });
        continue;
      }

      if (b.entryType === "dir") {
        if (b.mode !== a.mode) {
          diffs.push({
            relPosix,
            changeType: "mode-change",
            isDirectory: true,
            beforeEntry: b,
            afterEntry: a,
            commandBeforeText: null,
            taskBaselineText: null,
            afterText: null,
            isBinary: false,
          });
        }
        continue;
      }

      if (b.entryType === "symlink") {
        if (b.linkTarget !== a.linkTarget) {
          diffs.push({
            relPosix,
            changeType: "type-change",
            isDirectory: false,
            beforeEntry: b,
            afterEntry: a,
            isBinary: true,
          });
        }
        continue;
      }

      // Both are regular files
      const contentChanged = b.sha256 !== a.sha256 || b.oversize !== a.oversize;
      const modeChanged = b.mode !== a.mode;
      if (!contentChanged && !modeChanged) continue;

      let afterText = null;
      if (!a.isBinary && !a.oversize) {
        afterText = fs.readFileSync(path.join(readFromRoot, relPosix), "utf8");
      }

      diffs.push({
        relPosix,
        changeType: contentChanged ? "modify" : "mode-change",
        isDirectory: false,
        beforeEntry: b,
        afterEntry: a,
        commandBeforeText: this.readBaselineTextFromEntry(b),
        taskBaselineText: t ? this.readBaselineTextFromEntry(t) : this.readBaselineTextFromEntry(b),
        afterText,
        isBinary: Boolean(b.isBinary || a.isBinary || b.oversize || a.oversize),
      });
    }

    return diffs;
  }

  /**
   * Reconcile an active command transaction after tool/command execution:
   * - Re-scans with `strictCheckpointCoverage: true` so any injected xattr/ACL/hardlink/special-file/oversize hazard is caught!
   * - Supports `forceRollbackOnAnyMutation` (e.g. for `PostToolUseFailure` when a failed command partially tore files).
   */
  reconcileCommandTransaction(
    txId,
    { simulateCrashAfterFirstRestore = false, forceRollbackOnAnyMutation = false } = {}
  ) {
    const journal = this.db.prepare(`SELECT * FROM journals WHERE tx_id = ?`).get(txId);
    if (!journal) {
      const err = new Error(`Transaction journal '${txId}' not found.`);
      err.code = "STATE_INTEGRITY_FAILURE";
      throw err;
    }

    const session = this.loadSession(journal.session_id);
    if (!session) {
      const err = new Error(`Session '${journal.session_id}' missing during reconciliation.`);
      err.code = "STATE_INTEGRITY_FAILURE";
      throw err;
    }

    const commandCp = this.loadCheckpoint(journal.command_checkpoint_id);
    const taskBaselineCp = this.loadCheckpoint(session.taskBaselineId);
    const afterScan = this.scanWorkspaceNamespace({
      previousEntriesMap: null,
      storeBlobs: false,
      strictCheckpointCoverage: true,
    });

    const diffs = this.diffNamespaces(commandCp, taskBaselineCp, afterScan);

    const structuralHazards = this.findSessionWriteConflicts(session.sessionId, commandCp.entries, diffs.map((diff) => diff.relPosix));
    if (!afterScan.coverageComplete && afterScan.incompleteCode) {
      structuralHazards.push({
        code: afterScan.incompleteCode,
        path: "<workspace>",
        message: afterScan.incompleteReason,
      });
    }

    let preAcceptedLeases = [];
    if (!forceRollbackOnAnyMutation && journal.accepted_working_set_json) {
      try {
        const parsed = JSON.parse(journal.accepted_working_set_json);
        if (Array.isArray(parsed)) preAcceptedLeases = parsed;
      } catch {
        preAcceptedLeases = [];
      }
    }
    const baseWorkingSet = new Set([...session.workingSet, ...preAcceptedLeases]);

    if (diffs.length === 0 && structuralHazards.length === 0) {
      this.withImmediateTransaction(() => {
        this.db
          .prepare(`UPDATE journals SET state = 'CLEAN', updated_at = ? WHERE tx_id = ?`)
          .run(Date.now(), txId);
        this.db.prepare(`DELETE FROM active_lock WHERE singleton = 1 AND tx_id = ?`).run(txId);
      });
      return {
        ok: true,
        rolledBack: false,
        changedFiles: [],
        violations: [],
      };
    }

    if (forceRollbackOnAnyMutation && diffs.length > 0) {
      structuralHazards.push({
        code: "TOOL_EXECUTION_FAILED_ROLLBACK",
        path: diffs[0].relPosix,
        message: `Tool execution failed after mutating ${diffs.length} entry(ies); rolling back partial mutations to commandCheckpoint.`,
      });
    }

    const evalRes = evaluateCandidateWriteSet(diffs, {
      budget: session.budget,
      workingSet: baseWorkingSet,
      grants: session.grants,
      denySet: session.denySet,
    });

    const allViolations = [...structuralHazards, ...evalRes.violations];

    if (allViolations.length === 0) {
      for (const d of diffs) {
        if (d.afterEntry && d.afterEntry.entryType === "file" && d.afterEntry.sha256 && !d.afterEntry.oversize) {
          this.writeVerifiedBlobFromFile(
            path.join(this.canonicalRoot, d.relPosix),
            d.afterEntry.sha256
          );
        }
      }
      this.withImmediateTransaction(() => {
        this.recordSessionAcceptedFiles(session.sessionId, diffs.map((diff) => diff.relPosix), afterScan.entries);
        this.db
          .prepare(`UPDATE sessions SET working_set_json = ?, updated_at = ? WHERE session_id = ?`)
          .run(JSON.stringify(evalRes.nextWorkingSet), Date.now(), session.sessionId);
        this.db
          .prepare(`UPDATE journals SET state = 'CLEAN', updated_at = ? WHERE tx_id = ?`)
          .run(Date.now(), txId);
        this.db.prepare(`DELETE FROM active_lock WHERE singleton = 1 AND tx_id = ?`).run(txId);
      });
      return {
        ok: true,
        rolledBack: false,
        changedFiles: diffs.map((d) => d.relPosix),
        nextWorkingSet: evalRes.nextWorkingSet,
        violations: [],
      };
    }

    const rollbackRes = this.executeCrashSafeRollback(txId, commandCp, afterScan, {
      simulateCrashAfterFirstRestore,
    });

    return {
      ok: false,
      rolledBack: rollbackRes.ok,
      workspaceRestored: Boolean(rollbackRes.workspaceRestored),
      recoveryFailed: !rollbackRes.ok,
      recoveryCode: rollbackRes.code || null,
      recoveryError: rollbackRes.error || null,
      restoredCount: rollbackRes.restoredCount,
      removedCount: rollbackRes.removedCount,
      changedFiles: diffs.map((d) => d.relPosix),
      violations: allViolations,
    };
  }

  /**
   * Execute durable, crash-drift-aware workspace restoration back to `commandCp` (``, ``):
   * 1. When replaying an interrupted `'ROLLING_BACK'` / `'RECOVERY_FAILED'` journal (`existingProgress.length > 0`),
   *    verifies that no external concurrent edits occurred on `RESTORED`, `PENDING`, or untouched paths since the crash!
   *    If post-crash edits exist, quarantines both live & baseline bytes into `quarantine/<txId>/` and fails closed with
   *    `EXTERNAL_CONCURRENT_WRITE_DETECTED` without overwriting the user's newer edits!
   * 2. Restores all ordinary workspace entries (`files`, `symlinks`, `dirs`) FIRST even if `.git` metadata also changed (``),
   *    and if `.git` metadata changed, quarantines `.git` tamper records into `quarantine/<txId>/git-tamper.json` and transitions
   *    to `'RECOVERY_FAILED'` (`GIT_METADATA_TAMPERED`)!
   */
  executeCrashSafeRollback(
    txId,
    commandCp,
    currentScan = null,
    {
      simulateCrashAfterFirstRestore = false,
      callerContext = "immediate_reconcile",
      forceRestoreBaseline = false,
    } = {}
  ) {
    const scanNow =
      currentScan ||
      this.scanWorkspaceNamespace({
        previousEntriesMap: null,
        storeBlobs: false,
        strictCheckpointCoverage: false,
      });

    const journalRow = this.db.prepare(`SELECT * FROM journals WHERE tx_id = ?`).get(txId);
    const existingProgressRows = this.db
      .prepare(`SELECT * FROM journal_entry_progress WHERE tx_id = ? ORDER BY rel_posix ASC`)
      .all(txId);

    const progressMap = new Map();
    for (const r of existingProgressRows) {
      progressMap.set(r.rel_posix, r);
    }

    // ── : Safe No-Progress Crash Recovery (Persistent Across Retries) ───────
    // When `recoverUnfinishedTransactions()` encounters ANY unreconciled journal (`ACTIVE`, `ROLLING_BACK`,
    // or `RECOVERY_FAILED`) with `progressMap.size === 0`, BlastGuard never recorded observed post-command states
    // before crashing or failing, so external user edits may exist on disk. Repeated ordinary `rollback --recover`
    // calls MUST continue refusing destructive overwrite until `--force-baseline` (`forceRestoreBaseline`) is explicitly supplied!
    if (callerContext === "crash_recovery" && progressMap.size === 0) {
      const pendingDiffs = this.diffNamespaces(commandCp, commandCp, scanNow);
      if (pendingDiffs.length === 0) {
        this.withImmediateTransaction(() => {
          this.db
            .prepare(`UPDATE journals SET state = 'CLEAN', error_code = NULL, error_detail = NULL, updated_at = ? WHERE tx_id = ?`)
            .run(Date.now(), txId);
          this.db.prepare(`DELETE FROM active_lock WHERE singleton = 1 AND tx_id = ?`).run(txId);
        });
        return { ok: true, workspaceRestored: true, restoredCount: 0, removedCount: 0 };
      }

      const qDir = path.join(this.quarantineDir, txId);
      fs.mkdirSync(qDir, { recursive: true, mode: 0o700 });
      const unattestedPaths = [];
      for (const d of pendingDiffs) {
        if (d.gitControlTampered) {
          unattestedPaths.push({ relPosix: ".git", changeType: "git-control-tampered" });
          continue;
        }
        unattestedPaths.push({ relPosix: d.relPosix, changeType: d.changeType });
        if (d.relPosix !== ".") {
          const liveAbs = path.join(this.canonicalRoot, d.relPosix);
          try {
            if (fs.existsSync(liveAbs) && fs.lstatSync(liveAbs).isFile()) {
              writeDurableFileAtomic(
                path.join(qDir, "live", d.relPosix),
                fs.readFileSync(liveAbs),
                0o400
              );
            }
          } catch {
            // ignore unreadable live file
          }
          const baseEnt = commandCp.entries.get(d.relPosix);
          if (baseEnt && baseEnt.entryType === "file" && baseEnt.sha256 && !baseEnt.oversize) {
            try {
              writeDurableFileAtomic(
                path.join(qDir, "baseline", d.relPosix),
                this.readVerifiedBlob(baseEnt.sha256),
                0o400
              );
            } catch {
              // ignore
            }
          }
        }
      }
      writeDurableFileAtomic(
        path.join(qDir, "active-unattested-drift.json"),
        Buffer.from(JSON.stringify({ txId, unattestedPaths }, null, 2) + "\n", "utf8"),
        0o400
      );

      if (!forceRestoreBaseline) {
        const msg =
          `Unreconciled transaction '${txId}' (${journalRow?.state || "ACTIVE"}) has ${unattestedPaths.length} unattested workspace diff(s) (${unattestedPaths
            .map((p) => p.relPosix)
            .join(", ")}) with no recorded rollback progress; live workspace preserved and copies quarantined in ${qDir}. ` +
          `Inspect ${qDir} or re-run 'blast-guard rollback --recover --force-baseline' to restore pre-crash baseline.`;
        this.withImmediateTransaction(() => {
          this.db
            .prepare(
              `UPDATE journals SET state = 'RECOVERY_FAILED', error_code = ?, error_detail = ?, updated_at = ? WHERE tx_id = ?`
            )
            .run("EXTERNAL_CONCURRENT_WRITE_DETECTED", msg, Date.now(), txId);
        });
        return {
          ok: false,
          code: "EXTERNAL_CONCURRENT_WRITE_DETECTED",
          quarantineDir: qDir,
          driftedPaths: unattestedPaths,
          restoredCount: 0,
          removedCount: 0,
          error: msg,
        };
      }
    }

    // ── : Crash-Replay Post-Crash Concurrent Drift Detection ──────────────
    if (progressMap.size > 0) {
      const checkPaths = new Set([
        ...commandCp.entries.keys(),
        ...scanNow.entries.keys(),
        ...progressMap.keys(),
      ]);
      const driftedPaths = [];

      for (const relPosix of Array.from(checkPaths).sort()) {
        const cur = scanNow.entries.get(relPosix) || null;
        const base = commandCp.entries.get(relPosix) || null;
        const prog = progressMap.get(relPosix);

        if (prog) {
          // Note: parent directory timestamps/existence may naturally shift as child entries are removed/restored;
          // enforce strict post-crash drift check on all regular files & symlinks (and explicit mode-changed dirs).
          if (prog.observed_type === "dir" && prog.restored_type === "missing") {
            continue;
          }
          if (prog.status === "RESTORED") {
            const matchesRestored = entryMatchesRecordedState(
              cur,
              prog.restored_type,
              prog.restored_sha256,
              prog.restored_mode,
              prog.restored_link
            );
            if (!matchesRestored) {
              driftedPaths.push({
                relPosix,
                reason: "Path was already restored before crash, then modified externally afterward.",
              });
            }
          } else {
            // `PENDING`: valid states are `observed_*` (not yet touched) OR `restored_*` (crash occurred right after atomic rename before DB status update)
            const matchesObserved = entryMatchesRecordedState(
              cur,
              prog.observed_type,
              prog.observed_sha256,
              prog.observed_mode,
              prog.observed_link
            );
            const matchesRestored = entryMatchesRecordedState(
              cur,
              prog.restored_type,
              prog.restored_sha256,
              prog.restored_mode,
              prog.restored_link
            );
            if (!matchesObserved && !matchesRestored) {
              driftedPaths.push({
                relPosix,
                reason: "Pending recovery path was modified externally after crash.",
              });
            }
          }
        } else {
          // Path was untouched by the original crashed command -> must still match `commandCp`!
          if (base?.entryType === "dir" && cur?.entryType === "dir" && base.mode === cur.mode) {
            continue;
          }
          const matchesBase = entryMatchesRecordedState(
            cur,
            base ? base.entryType : "missing",
            base?.sha256 || null,
            base?.mode ?? null,
            base?.linkTarget || null
          );
          if (!matchesBase) {
            driftedPaths.push({
              relPosix,
              reason: "Previously untouched workspace path was modified externally after crash.",
            });
          }
        }
      }

      if (driftedPaths.length > 0) {
        const qDir = path.join(this.quarantineDir, txId);
        fs.mkdirSync(qDir, { recursive: true, mode: 0o700 });
        for (const dp of driftedPaths) {
          const liveAbs = path.join(this.canonicalRoot, dp.relPosix);
          try {
            if (fs.existsSync(liveAbs) && fs.lstatSync(liveAbs).isFile()) {
              const qLive = path.join(qDir, "live", dp.relPosix);
              writeDurableFileAtomic(qLive, fs.readFileSync(liveAbs), 0o400);
            }
          } catch {
            // ignore unreadable live file
          }
          const baseEnt = commandCp.entries.get(dp.relPosix);
          if (baseEnt && baseEnt.entryType === "file" && baseEnt.sha256 && !baseEnt.oversize) {
            try {
              const qBase = path.join(qDir, "baseline", dp.relPosix);
              writeDurableFileAtomic(qBase, this.readVerifiedBlob(baseEnt.sha256), 0o400);
            } catch {
              // ignore
            }
          }
        }
        writeDurableFileAtomic(
          path.join(qDir, "drift-report.json"),
          Buffer.from(JSON.stringify({ txId, driftedPaths }, null, 2) + "\n", "utf8"),
          0o400
        );

        if (!forceRestoreBaseline) {
          const detailMsg = `Post-crash external concurrent edit detected on ${driftedPaths
            .map((d) => d.relPosix)
            .join(", ")}; conflicting bytes quarantined at ${qDir} without overwriting live workspace.`;
          this.withImmediateTransaction(() => {
            this.db
              .prepare(
                `UPDATE journals SET state = 'RECOVERY_FAILED', error_code = ?, error_detail = ?, updated_at = ? WHERE tx_id = ?`
              )
              .run("EXTERNAL_CONCURRENT_WRITE_DETECTED", detailMsg, Date.now(), txId);
          });
          return {
            ok: false,
            code: "EXTERNAL_CONCURRENT_WRITE_DETECTED",
            quarantineDir: qDir,
            driftedPaths,
            restoredCount: 0,
            removedCount: 0,
            error: detailMsg,
          };
        }
      }
    }

    // Build ordered work plan:
    // 1. Remove created files/symlinks first (deepest path first so empty created dirs unwind cleanly)
    // 2. Remove created directories (deepest path first)
    // 3. Restore baseline directories (shallowest first)
    // 4. Restore baseline files & symlinks
    const unionPaths = Array.from(
      new Set([...commandCp.entries.keys(), ...scanNow.entries.keys()])
    ).sort();

    const removeFileItems = [];
    const removeDirItems = [];
    const restoreDirItems = [];
    const restoreFileItems = [];

    for (const relPosix of unionPaths) {
      const b = commandCp.entries.get(relPosix) || null;
      const a = scanNow.entries.get(relPosix) || null;
      if (!b && a) {
        const item = { relPosix, action: "REMOVE_CREATED", beforeEntry: null, observedEntry: a };
        if (a.entryType === "dir") removeDirItems.push(item);
        else removeFileItems.push(item);
      } else if (b && !a) {
        const item = { relPosix, action: "RESTORE_ENTRY", beforeEntry: b, observedEntry: null };
        if (b.entryType === "dir") restoreDirItems.push(item);
        else restoreFileItems.push(item);
      } else if (
        b &&
        a &&
        (b.entryType !== a.entryType ||
          b.mode !== a.mode ||
          b.sha256 !== a.sha256 ||
          b.linkTarget !== a.linkTarget)
      ) {
        const item = { relPosix, action: "RESTORE_ENTRY", beforeEntry: b, observedEntry: a };
        if (b.entryType === "dir") restoreDirItems.push(item);
        else restoreFileItems.push(item);
      }
    }

    removeFileItems.sort((x, y) => y.relPosix.length - x.relPosix.length || x.relPosix.localeCompare(y.relPosix));
    removeDirItems.sort((x, y) => y.relPosix.length - x.relPosix.length || x.relPosix.localeCompare(y.relPosix));
    restoreDirItems.sort((x, y) => x.relPosix.length - y.relPosix.length || x.relPosix.localeCompare(y.relPosix));

    // Put file restorations & file removals ahead of pure directory cleanup so `simulateCrashAfterFirstRestore`
    // deterministically crashes after the first real entry restore while remaining entries stay `PENDING`!
    const workItems = [
      ...restoreFileItems,
      ...removeFileItems,
      ...removeDirItems,
      ...restoreDirItems,
    ];

    if (progressMap.size === 0) {
      this.withImmediateTransaction(() => {
        this.db
          .prepare(`UPDATE journals SET state = 'ROLLING_BACK', updated_at = ? WHERE tx_id = ?`)
          .run(Date.now(), txId);
        const insProg = this.db.prepare(`
          INSERT INTO journal_entry_progress (
            tx_id, rel_posix, action, status,
            observed_type, observed_sha256, observed_mode, observed_link,
            restored_type, restored_sha256, restored_mode, restored_link, detail
          ) VALUES (?, ?, ?, 'PENDING', ?, ?, ?, ?, ?, ?, ?, ?, NULL)
          ON CONFLICT(tx_id, rel_posix) DO UPDATE SET status = 'PENDING', detail = NULL
        `);
        for (const item of workItems) {
          const obs = item.observedEntry;
          const res = item.beforeEntry;
          insProg.run(
            txId,
            item.relPosix,
            item.action,
            obs ? obs.entryType : "missing",
            obs?.sha256 || null,
            obs?.mode ?? null,
            obs?.linkTarget || null,
            res ? res.entryType : "missing",
            res?.sha256 || null,
            res?.mode ?? null,
            res?.linkTarget || null
          );
        }
      });
    } else {
      this.withImmediateTransaction(() => {
        this.db
          .prepare(`UPDATE journals SET state = 'ROLLING_BACK', updated_at = ? WHERE tx_id = ?`)
          .run(Date.now(), txId);
      });
    }

    let restoredCount = 0;
    let removedCount = 0;
    let processed = 0;

    try {
      for (const item of workItems) {
        if (simulateCrashAfterFirstRestore && processed === 1) {
          const crashErr = new Error("Simulated mid-rollback crash (fault injection)");
          crashErr.code = "SIMULATED_ROLLBACK_CRASH";
          throw crashErr;
        }
        if (item.action === "REMOVE_CREATED") {
          this.safeRemoveWorkspaceEntry(item.relPosix, commandCp.entries);
          removedCount++;
        } else {
          this.safeRestoreBaselineEntry(item.beforeEntry);
          restoredCount++;
        }
        processed++;
        this.db
          .prepare(`UPDATE journal_entry_progress SET status = 'RESTORED' WHERE tx_id = ? AND rel_posix = ?`)
          .run(txId, item.relPosix);
      }

      // Verify ordinary workspace entries converged 100% to `commandCp.entries`!
      const verifyScan = this.scanWorkspaceNamespace({
        previousEntriesMap: null,
        storeBlobs: false,
        strictCheckpointCoverage: true,
      });
      const allPostDiffs = this.diffNamespaces(commandCp, commandCp, verifyScan);
      const workspaceDiffs = allPostDiffs.filter((d) => !d.gitControlTampered);

      if (!verifyScan.coverageComplete || workspaceDiffs.length > 0) {
        const err = new Error(
          `Post-rollback verification detected ${workspaceDiffs.length} residual workspace discrepancy(ies).`
        );
        err.code = "POST_ROLLBACK_VERIFICATION_FAILED";
        throw err;
      }

      // Now check `.git` control-plane immutability AFTER ordinary workspace files are 100% restored (``)!
      const beforeGitDigest = commandCp.gitControl?.digest || commandCp.gitControl?.sha256 || null;
      const afterGitDigest = verifyScan.gitControl?.digest || verifyScan.gitControl?.sha256 || null;
      if (beforeGitDigest !== afterGitDigest) {
        const qDir = path.join(this.quarantineDir, txId);
        fs.mkdirSync(qDir, { recursive: true, mode: 0o700 });
        writeDurableFileAtomic(
          path.join(qDir, "git-tamper.json"),
          Buffer.from(
            JSON.stringify(
              {
                txId,
                workspaceEntriesRestored: true,
                beforeGitControl: commandCp.gitControl,
                afterGitControl: verifyScan.gitControl,
              },
              null,
              2
            ) + "\n",
            "utf8"
          ),
          0o400
        );
        const gitMsg =
          "Ordinary workspace files were restored to commandCheckpoint, but .git control-plane metadata was altered and quarantined for manual inspection.";
        this.withImmediateTransaction(() => {
          this.db
            .prepare(
              `UPDATE journals SET state = 'RECOVERY_FAILED', error_code = ?, error_detail = ?, updated_at = ? WHERE tx_id = ?`
            )
            .run("GIT_METADATA_TAMPERED", gitMsg, Date.now(), txId);
        });
        return {
          ok: false,
          code: "GIT_METADATA_TAMPERED",
          workspaceRestored: true,
          quarantineDir: qDir,
          restoredCount,
          removedCount,
          error: `GIT_METADATA_TAMPERED: ${gitMsg}`,
        };
      }

      this.withImmediateTransaction(() => {
        this.db
          .prepare(
            `UPDATE journals SET state = 'CLEAN', error_code = NULL, error_detail = NULL, updated_at = ? WHERE tx_id = ?`
          )
          .run(Date.now(), txId);
        this.db.prepare(`DELETE FROM active_lock WHERE singleton = 1 AND tx_id = ?`).run(txId);
      });

      return { ok: true, workspaceRestored: true, restoredCount, removedCount };
    } catch (err) {
      if (err.code === "SIMULATED_ROLLBACK_CRASH") {
        throw err;
      }
      this.withImmediateTransaction(() => {
        this.db
          .prepare(
            `UPDATE journals SET state = 'RECOVERY_FAILED', error_code = ?, error_detail = ?, updated_at = ? WHERE tx_id = ?`
          )
          .run(err.code || "RECOVERY_ERROR", err.message, Date.now(), txId);
      });
      return {
        ok: false,
        code: err.code || "RECOVERY_ERROR",
        workspaceRestored: false,
        restoredCount,
        removedCount,
        error: `${err.code || "RECOVERY_ERROR"}: ${err.message}`,
      };
    }
  }

  safeRemoveWorkspaceEntry(relPosix, baselineEntriesMap = null) {
    const segments = relPosix.split("/");
    let cursor = this.canonicalRoot;
    for (let i = 0; i < segments.length - 1; i++) {
      cursor = path.join(cursor, segments[i]);
      try {
        const st = fs.lstatSync(cursor);
        if (st.isSymbolicLink()) {
          fs.unlinkSync(cursor);
          return;
        }
      } catch (err) {
        if (err.code === "ENOENT") return;
        throw err;
      }
    }

    const targetAbs = path.join(this.canonicalRoot, relPosix);
    try {
      const st = fs.lstatSync(targetAbs);
      if (st.isDirectory() && !st.isSymbolicLink()) {
        fs.rmSync(targetAbs, { recursive: true, force: false });
      } else {
        fs.unlinkSync(targetAbs);
      }
      fsyncDirectoryBestEffort(path.dirname(targetAbs));
    } catch (err) {
      if (err.code !== "ENOENT") throw err;
    }

    // Prune empty parent directories ONLY if they were NOT present in `baselineEntriesMap`!
    let dir = path.dirname(targetAbs);
    while (dir !== this.canonicalRoot && dir.startsWith(this.canonicalRoot + path.sep)) {
      const dirRelPosix = toPosixRel(path.relative(this.canonicalRoot, dir));
      if (baselineEntriesMap && baselineEntriesMap.has(dirRelPosix)) {
        break;
      }
      try {
        const items = fs.readdirSync(dir);
        if (items.length === 0) {
          fs.rmdirSync(dir);
          dir = path.dirname(dir);
        } else {
          break;
        }
      } catch {
        break;
      }
    }
  }

  safeRestoreBaselineEntry(entry) {
    if (entry.relPosix === ".") {
      fs.chmodSync(this.canonicalRoot, entry.mode & 0o7777);
      fsyncDirectoryBestEffort(this.canonicalRoot);
      return;
    }

    const segments = entry.relPosix.split("/");
    let cursor = this.canonicalRoot;
    for (let i = 0; i < segments.length - 1; i++) {
      cursor = path.join(cursor, segments[i]);
      try {
        const st = fs.lstatSync(cursor);
        if (!st.isDirectory() || st.isSymbolicLink()) {
          fs.unlinkSync(cursor);
          fs.mkdirSync(cursor, { mode: 0o755 });
        }
      } catch (err) {
        if (err.code === "ENOENT") {
          fs.mkdirSync(cursor, { mode: 0o755 });
        } else {
          throw err;
        }
      }
    }

    const targetAbs = path.join(this.canonicalRoot, entry.relPosix);

    if (entry.entryType === "dir") {
      try {
        const existingSt = fs.lstatSync(targetAbs);
        if (existingSt.isSymbolicLink() || !existingSt.isDirectory()) {
          fs.unlinkSync(targetAbs);
          fs.mkdirSync(targetAbs, { mode: entry.mode & 0o7777 });
        } else {
          fs.chmodSync(targetAbs, entry.mode & 0o7777);
        }
      } catch (err) {
        if (err.code === "ENOENT") {
          fs.mkdirSync(targetAbs, { mode: entry.mode & 0o7777 });
        } else {
          throw err;
        }
      }
      fsyncDirectoryBestEffort(path.dirname(targetAbs));
      return;
    }

    try {
      const existingSt = fs.lstatSync(targetAbs);
      if (existingSt.isSymbolicLink()) {
        fs.unlinkSync(targetAbs);
      } else if (existingSt.isDirectory()) {
        fs.rmSync(targetAbs, { recursive: true, force: false });
      }
    } catch (err) {
      if (err.code !== "ENOENT") throw err;
    }

    if (entry.entryType === "symlink") {
      try {
        fs.unlinkSync(targetAbs);
      } catch (err) {
        if (err.code !== "ENOENT") throw err;
      }
      fs.symlinkSync(entry.linkTarget, targetAbs);
      fsyncDirectoryBestEffort(path.dirname(targetAbs));
      return;
    }

    const verifiedBytes = this.readVerifiedBlob(entry.sha256);
    writeDurableFileAtomic(targetAbs, verifiedBytes, entry.mode & 0o7777);
  }

  /**
   * Replay and recover any unfinished `'ACTIVE'`, `'ROLLING_BACK'`, or `'RECOVERY_FAILED'` journals (``, ``).
   * - Respects live `active_lock` ownership (`owner_kind` / `owner_pid`): NEVER deletes an `active_lock` held by a live
   *   `isolated_exec`, `bundle_promote`, `turn_policy`, or external running hook process!
   */
  recoverUnfinishedTransactions({ forceRestoreBaseline = false } = {}) {
    const recoveryLockId = `rec-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`;
    let openRows = [];
    let blockedByLiveLock = null;
    let acquiredRecoveryLock = false;

    this.withImmediateTransaction(() => {
      openRows = this.getUnreconciledJournals();
      const existingLock = this.db.prepare(`SELECT * FROM active_lock WHERE singleton = 1`).get();
      if (existingLock) {
        const ownedByOpenJournal = openRows.some((r) => r.tx_id === existingLock.tx_id);
        const lockPid = existingLock.owner_pid !== null && existingLock.owner_pid !== undefined ? Number(existingLock.owner_pid) : null;
        const externalLivePid = Boolean(lockPid && lockPid !== process.pid && isPidAlive(lockPid));
        const nonJournalActiveLock = Boolean(
          !ownedByOpenJournal && existingLock.owner_kind !== "recovery" && (lockPid === null || isPidAlive(lockPid))
        );
        if (externalLivePid || nonJournalActiveLock) {
          blockedByLiveLock = existingLock;
          return;
        }
        // Dead or journal-owned lock -> transition ownership to `recovery` for serialized recovery
        try {
          this.db
            .prepare(
              `UPDATE active_lock SET tx_id = ?, owner_kind = 'recovery', owner_pid = ?, created_at = ? WHERE singleton = 1`
            )
            .run(recoveryLockId, process.pid, Date.now());
        } catch {
          this.db
            .prepare(
              `UPDATE active_lock SET tx_id = ?, owner_kind = 'recovery', created_at = ? WHERE singleton = 1`
            )
            .run(recoveryLockId, Date.now());
        }
        acquiredRecoveryLock = true;
      } else if (openRows.length > 0) {
        try {
          this.db
            .prepare(
              `INSERT INTO active_lock (singleton, tx_id, owner_kind, session_id, tool_use_id, owner_pid, created_at) VALUES (1, ?, 'recovery', ?, NULL, ?, ?)`
            )
            .run(recoveryLockId, openRows[0].session_id || "default", process.pid, Date.now());
        } catch {
          this.db
            .prepare(
              `INSERT INTO active_lock (singleton, tx_id, owner_kind, session_id, tool_use_id, created_at) VALUES (1, ?, 'recovery', ?, NULL, ?)`
            )
            .run(recoveryLockId, openRows[0].session_id || "default", Date.now());
        }
        acquiredRecoveryLock = true;
      }
    });

    if (blockedByLiveLock) {
      return {
        ok: false,
        code: "CONCURRENT_HOOK_LOCK_HELD",
        reason: `Cannot run recovery while active lock '${blockedByLiveLock.tx_id}' (${blockedByLiveLock.owner_kind}) is held by a live operation.`,
        recoveredTransactions: [],
      };
    }

    try {
      const results = [];
      for (const row of openRows) {
        const commandCp = this.loadCheckpoint(row.command_checkpoint_id);
        const res = this.executeCrashSafeRollback(row.tx_id, commandCp, null, {
          callerContext: "crash_recovery",
          forceRestoreBaseline,
        });
        results.push({ txId: row.tx_id, previousState: row.state, ...res });
      }
      const allOk = results.every((r) => r.ok);
      return {
        ok: allOk,
        code: allOk ? "RECOVERED_CLEAN" : results.find((r) => !r.ok)?.code || "RECOVERY_FAILED",
        recoveredTransactions: results,
      };
    } finally {
      if (acquiredRecoveryLock) {
        try {
          this.withImmediateTransaction(() => {
            this.db
              .prepare(`DELETE FROM active_lock WHERE singleton = 1 AND tx_id = ?`)
              .run(recoveryLockId);
          });
        } catch {
          // ignore
        }
      }
    }
  }

  /**
   * Execute `<command>` inside an OS-sandboxed isolated staging workspace (``, ``, ``, ``, ``, ``).
   */
  async runIsolatedCommand(
    cmdArgs,
    {
      sessionId = "default",
      promoteMode = "staged",
      assumeSingleWriter = false,
      ownedWorktree = false,
      denyNetwork = false,
      timeoutMs = 120000,
      env = process.env,
      discardChanges = false,
      _testForceEnumerationUnavailable = false,
    } = {}
  ) {
    const sbx = probeOsIsolationBackend();
    if (!sbx.available) {
      return {
        ok: false,
        code: "ISOLATION_BACKEND_UNAVAILABLE",
        reason: sbx.reason,
        exitCode: 125,
        promoted: false,
        violations: [
          {
            code: "ISOLATION_BACKEND_UNAVAILABLE",
            path: "<sandbox>",
            message: sbx.reason,
          },
        ],
      };
    }

    const session = this.ensureActiveSession(sessionId);
    const txId = `iso-${Date.now()}-${crypto.randomBytes(5).toString("hex")}`;
    this.acquireAdmissionLock({
      txId,
      ownerKind: "isolated_exec",
      sessionId,
      toolUseId: txId,
    });

    fs.mkdirSync(os.tmpdir(), { recursive: true });
    const rawTmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bg-iso-"));
    const realIsoRoot = fs.realpathSync.native(rawTmpRoot);
    const stagingWorkdir = path.join(realIsoRoot, "work");
    const privateTmp = path.join(realIsoRoot, "tmp");
    fs.mkdirSync(stagingWorkdir, { recursive: true, mode: 0o700 });
    fs.mkdirSync(privateTmp, { recursive: true, mode: 0o700 });

    let retainOpenLock = false;
    try {
      const turnCp = this.loadCheckpoint(session.turnCheckpointId);
      const taskBaselineCp = this.loadCheckpoint(session.taskBaselineId);
      const baselineScan = this.scanWorkspaceNamespace({
        previousEntriesMap: turnCp.entries,
        storeBlobs: true,
        strictCheckpointCoverage: false,
      });

      if (
        !baselineScan.coverageComplete &&
        baselineScan.incompleteCode !== "CHECKPOINT_COVERAGE_INCOMPLETE"
      ) {
        return {
          ok: false,
          code: baselineScan.incompleteCode,
          reason: baselineScan.incompleteReason,
          exitCode: 125,
          promoted: false,
          violations: [
            {
              code: baselineScan.incompleteCode,
              path: "<workspace>",
              message: baselineScan.incompleteReason,
            },
          ],
        };
      }

      // Materialize workspace entries into `stagingWorkdir` (dirs, internal symlinks, non-oversize files)
      const dirModesToApply = [];
      for (const ent of baselineScan.entries.values()) {
        if (ent.relPosix === ".") {
          dirModesToApply.push({ destAbs: stagingWorkdir, mode: ent.mode });
          continue;
        }
        const destAbs = path.join(stagingWorkdir, ent.relPosix);
        if (ent.entryType === "dir") {
          fs.mkdirSync(destAbs, { recursive: true, mode: 0o755 });
          dirModesToApply.push({ destAbs, mode: ent.mode });
        } else if (ent.entryType === "symlink") {
          fs.mkdirSync(path.dirname(destAbs), { recursive: true, mode: 0o755 });
          fs.symlinkSync(ent.linkTarget, destAbs);
        } else if (!ent.oversize) {
          fs.mkdirSync(path.dirname(destAbs), { recursive: true, mode: 0o755 });
          const srcAbs = path.join(this.canonicalRoot, ent.relPosix);
          fs.copyFileSync(srcAbs, destAbs);
          fs.chmodSync(destAbs, ent.mode);
        }
      }
      for (const dm of dirModesToApply.reverse()) {
        try {
          fs.chmodSync(dm.destAbs, dm.mode);
        } catch {
          // ignore
        }
      }

      const home = os.homedir();
      const protectedPaths = [
        this.canonicalRoot,
        path.dirname(this.storeDir),
        this.storeDir,
        BLAST_GUARD_PACKAGE_ROOT,
        path.join(home, ".blast-guard"),
        path.join(home, ".claude"),
        path.join(home, ".codex"),
        path.join(home, ".cursor"),
        path.join(home, ".gitconfig"),
        path.join(home, ".config", "git"),
      ];

      let spawnBin;
      let spawnArgs;
      if (sbx.backend === "darwin-seatbelt") {
        const profile = buildSeatbeltProfile({
          protectedPaths,
          allowedWritePaths: [stagingWorkdir, privateTmp],
          denyNetwork,
        });
        spawnBin = sbx.binary;
        spawnArgs = ["-p", profile, ...cmdArgs];
      } else {
        spawnBin = sbx.binary;
        spawnArgs = [
          "--ro-bind", "/", "/",
          "--bind", stagingWorkdir, stagingWorkdir,
          "--bind", privateTmp, privateTmp,
          "--dev", "/dev",
          "--proc", "/proc",
          ...(sbx.bwrapPidArgs || []),
          ...(denyNetwork ? ["--unshare-net"] : []),
          ...cmdArgs,
        ];
      }

      const execRes = await spawnAndReapProcessGroup(spawnBin, spawnArgs, {
        cwd: stagingWorkdir,
        extraPaths: [privateTmp],
        env: {
          ...env,
          TMPDIR: privateTmp,
          TMP: privateTmp,
          TEMP: privateTmp,
        },
        timeoutMs,
        outputDir: path.join(this.storeDir, "outputs"),
        _testForceEnumerationUnavailable,
      });

      // : Require full descendant quiescence BEFORE scanning or publishing any bundle,
      // and retain lock + fail-closed journal if any descendant escaped termination!
      if (!execRes.quiescent) {
        retainOpenLock = true;
        const nowFail = Date.now();
        this.withImmediateTransaction(() => {
          this.db
            .prepare(`
              INSERT INTO journals (
                tx_id, session_id, tool_use_id, command_checkpoint_id, state, error_code, error_detail, created_at, updated_at
              ) VALUES (?, ?, ?, ?, 'RECOVERY_FAILED', ?, ?, ?, ?)
            `)
            .run(
              txId,
              session.sessionId,
              txId,
              session.turnCheckpointId,
              "DESCENDANT_PROCESS_NOT_QUIESCENT",
              "Sandboxed command left unkillable surviving descendants; workspace reservation retained fail-closed.",
              nowFail,
              nowFail
            );
        });
        return {
          ok: false,
          code: "DESCENDANT_PROCESS_NOT_QUIESCENT",
          reason: "Sandboxed command left surviving background descendants or open stdio pipes; refusing bundle publication and retaining fail-closed reservation.",
          exitCode: 126,
          stdout: execRes.stdout,
          stderr: execRes.stderr,
          outputArtifacts: execRes.outputArtifacts,
          promoted: false,
          stagedBundleDir: null,
          violations: [
            {
              code: "DESCENDANT_PROCESS_NOT_QUIESCENT",
              path: "<process-group>",
              message: "Command process group or detached descendants did not reach quiescence after termination.",
            },
          ],
        };
      }

      // Verification commands execute only in the disposable copy and never produce a promotable bundle.
      if (discardChanges) {
        return { ok: execRes.exitCode === 0, code: "VERIFICATION_COMMAND_EXECUTED", txId,
          exitCode: execRes.exitCode, stdout: execRes.stdout, stderr: execRes.stderr,
          outputArtifacts: execRes.outputArtifacts, promoted: false, discardedChanges: true, violations: [] };
      }

      // Atomically move `stagingWorkdir` (`work`) to `sealedWorkdir` (`sealed`) outside the sandbox's allowed write path
      // before scanning and hashing candidate files (``, ``)!
      const sealedWorkdir = path.join(realIsoRoot, "sealed");
      fs.renameSync(stagingWorkdir, sealedWorkdir);

      // : Strict structural & metadata scan on `sealedWorkdir`!
      const stagedScanner = new SnapshotStore(sealedWorkdir, {
        storeDir: path.join(realIsoRoot, "scanner-dummy-store"),
        limits: this.limits,
        exemptXattrs: this.exemptXattrs,
      });
      const afterStagedScan = stagedScanner.scanWorkspaceNamespace({
        previousEntriesMap: null,
        storeBlobs: false,
        strictCheckpointCoverage: true,
      });

      if (!afterStagedScan.coverageComplete) {
        const failCode = afterStagedScan.incompleteCode || "CHECKPOINT_COVERAGE_INCOMPLETE";
        return {
          ok: false,
          code: failCode,
          reason: afterStagedScan.incompleteReason,
          exitCode: execRes.exitCode || 126,
          stdout: execRes.stdout,
          stderr: execRes.stderr,
          outputArtifacts: execRes.outputArtifacts,
          promoted: false,
          stagedBundleDir: null,
          violations: [
            {
              code: failCode,
              path: "<staging>",
              message: afterStagedScan.incompleteReason || "Staging scan detected unsupported/unsafe entries.",
            },
          ],
        };
      }

      // Check that no omitted oversize baseline asset path was created/overwritten inside stagingWorkdir (``)!
      for (const [relPosix, bEnt] of baselineScan.entries.entries()) {
        if (bEnt.oversize && afterStagedScan.entries.has(relPosix)) {
          return {
            ok: false,
            code: "CHECKPOINT_COVERAGE_INCOMPLETE",
            reason: `Command wrote to omitted oversize baseline path '${relPosix}'; refusing validation.`,
            exitCode: 126,
            stdout: execRes.stdout,
            stderr: execRes.stderr,
            outputArtifacts: execRes.outputArtifacts,
            promoted: false,
            stagedBundleDir: null,
            violations: [
              {
                code: "CHECKPOINT_COVERAGE_INCOMPLETE",
                path: relPosix,
                message: `Oversize baseline path '${relPosix}' cannot be mutated.`,
              },
            ],
          };
        }
      }

      // Build baseline map excluding intentionally unmaterialized oversize entries
      const effectiveBaselineEntries = new Map();
      for (const [k, v] of baselineScan.entries.entries()) {
        if (!v.oversize) effectiveBaselineEntries.set(k, v);
      }

      const diffs = this.diffNamespaces(
        { entries: effectiveBaselineEntries, gitControl: null },
        taskBaselineCp,
        { entries: afterStagedScan.entries, gitControl: null },
        { readFromRoot: sealedWorkdir }
      );

      const sessionConflicts = this.findSessionWriteConflicts(session.sessionId, baselineScan.entries, diffs.map((diff) => diff.relPosix));
      if (sessionConflicts.length) {
        return { ok: false, code: "SESSION_WRITE_CONFLICT", exitCode: 126, promoted: false, stdout: execRes.stdout,
          stderr: execRes.stderr, outputArtifacts: execRes.outputArtifacts, violations: sessionConflicts };
      }

      // Check Ring-00 protection BEFORE rejecting directory/symlink mutations so root/marker tampering reports IMMUTABLE_INFRA_PROTECTED
      const evalRes = evaluateCandidateWriteSet(diffs, {
        budget: session.budget,
        workingSet: new Set(session.workingSet),
        grants: session.grants,
        denySet: session.denySet,
      });

      if (!evalRes.ok) {
        return {
          ok: false,
          code: evalRes.violations[0].code,
          exitCode: execRes.exitCode || 1,
          stdout: execRes.stdout,
          stderr: execRes.stderr,
          outputArtifacts: execRes.outputArtifacts,
          promoted: false,
          stagedBundleDir: null,
          violations: evalRes.violations,
        };
      }

      // Disallow standalone directory/symlink type mutations in staged bundles unless empty clean
      for (const d of diffs) {
        if (d.isDirectory || d.changeType === "type-change") {
          return {
            ok: false,
            code: "UNSUPPORTED_STAGED_ENTRY_TYPE",
            reason: `Staged bundle does not support standalone directory/symlink mutation on '${d.relPosix}'.`,
            exitCode: 126,
            stdout: execRes.stdout,
            stderr: execRes.stderr,
            outputArtifacts: execRes.outputArtifacts,
            promoted: false,
            stagedBundleDir: null,
            violations: [
              {
                code: "UNSUPPORTED_STAGED_ENTRY_TYPE",
                path: d.relPosix,
                message: `Unsupported directory or symlink mutation '${d.changeType}' on '${d.relPosix}'.`,
              },
            ],
          };
        }
      }

      // ──  & : Publish Verified Immutable Staged Bundle + Authoritative SQLite Record ──
      const outBundleDir = path.join(this.stagedDir, txId);
      const outFilesRoot = path.join(outBundleDir, "files");
      fs.mkdirSync(outFilesRoot, { recursive: true, mode: 0o700 });

      const manifestItems = [];
      const patchChunks = [];
      const createdDirsInBundle = new Set([outBundleDir, outFilesRoot]);

      for (const d of diffs) {
        const inspRel = inspectWorkspacePath(sealedWorkdir, d.relPosix, {
          forWrite: false,
          allowDirectoryLeaf: false,
        });
        if (!inspRel.ok) {
          throw new Error(`Invalid candidate path '${d.relPosix}' during bundle publication.`);
        }

        manifestItems.push({
          relPosix: d.relPosix,
          changeType: d.changeType,
          beforeIdentity: d.beforeEntry ? pickIdentityTuple(d.beforeEntry) : null,
          afterSha256: d.afterEntry?.sha256 || null,
          afterMode: d.afterEntry ? d.afterEntry.mode & 0o7777 : null,
          afterEntryType: d.afterEntry?.entryType || null,
          isBinary: Boolean(d.isBinary),
        });

        let candidateBytes = null;
        if (d.afterEntry && d.afterEntry.entryType === "file") {
          const srcStaged = path.join(sealedWorkdir, d.relPosix);
          candidateBytes = fs.readFileSync(srcStaged);
          const actualHash = sha256Buffer(candidateBytes);
          if (actualHash !== d.afterEntry.sha256) {
            const err = new Error(`Candidate file '${d.relPosix}' changed during staging read.`);
            err.code = "BUNDLE_INTEGRITY_ERROR";
            throw err;
          }
          const outFile = path.join(outFilesRoot, d.relPosix);
          let pDir = path.dirname(outFile);
          fs.mkdirSync(pDir, { recursive: true, mode: 0o700 });
          while (pDir.startsWith(outFilesRoot) && pDir !== outFilesRoot) {
            createdDirsInBundle.add(pDir);
            pDir = path.dirname(pDir);
          }
          writeDurableFileAtomic(outFile, candidateBytes, 0o400);
        }

        const beforeBytes = d.beforeEntry?.sha256 ? this.readVerifiedBlob(d.beforeEntry.sha256) : null;
        patchChunks.push(
          buildUnifiedFilePatch(d.relPosix, d.commandBeforeText, d.afterText, {
            changeType: d.changeType,
            isBinary: Boolean(d.isBinary),
            beforeMode: d.beforeEntry?.mode ?? 0o644,
            afterMode: d.afterEntry?.mode ?? 0o644,
            beforeBytes,
            afterBytes: candidateBytes,
          })
        );
      }

      const manifestObj = {
        schemaVersion: "blast-guard.bundle.v1",
        txId,
        sessionId: session.sessionId,
        workspaceId: this.workspaceId,
        diffs: manifestItems,
      };
      const manifestJson = JSON.stringify(manifestObj, null, 2) + "\n";
      const manifestSha256 = sha256Buffer(Buffer.from(manifestJson, "utf8"));

      writeDurableFileAtomic(
        path.join(outBundleDir, "manifest.json"),
        Buffer.from(manifestJson, "utf8"),
        0o400
      );
      writeDurableFileAtomic(
        path.join(outBundleDir, "patch.diff"),
        Buffer.from(patchChunks.join(""), "utf8"),
        0o400
      );

      // Seal bundle directories to owner-private (`0o700`) while staged files & manifest are read-only (`0o400`) (``)!
      const sortedDirs = Array.from(createdDirsInBundle).sort((a, b) => b.length - a.length);
      for (const dirPath of sortedDirs) {
        try {
          fs.chmodSync(dirPath, 0o700);
        } catch {
          // ignore
        }
      }

      this.withImmediateTransaction(() => {
        const baseCpId = this.persistCheckpoint(session.sessionId, "isolated-base", baselineScan);
        this.db
          .prepare(`
            INSERT INTO staged_bundles (
              tx_id, session_id, baseline_checkpoint_id, manifest_json, manifest_sha256, promoted_at, created_at
            ) VALUES (?, ?, ?, ?, ?, NULL, ?)
          `)
          .run(txId, session.sessionId, baseCpId, manifestJson, manifestSha256, Date.now());
      });

      const overwritesExisting = diffs.some((d) => d.changeType !== "add");

      if (promoteMode === "staged" && !assumeSingleWriter && !ownedWorktree) {
        if (overwritesExisting) {
          return {
            ok: true,
            txId,
            code: "EXISTING_FILE_OWNERSHIP_UNPROVEN",
            exitCode: execRes.exitCode,
            stdout: execRes.stdout,
            stderr: execRes.stderr,
            outputArtifacts: execRes.outputArtifacts,
            promoted: false,
            stagedBundleDir: outBundleDir,
            changedFiles: diffs.map((d) => d.relPosix),
            violations: [],
          };
        }
        if (diffs.length === 0) {
          return {
            ok: true,
            txId,
            code: "CLEAN_NO_MUTATIONS",
            exitCode: execRes.exitCode,
            stdout: execRes.stdout,
            stderr: execRes.stderr,
            outputArtifacts: execRes.outputArtifacts,
            promoted: false,
            stagedBundleDir: outBundleDir,
            changedFiles: [],
            violations: [],
          };
        }
      }

      if (promoteMode === "live" && overwritesExisting && !assumeSingleWriter && !ownedWorktree) {
        return {
          ok: false,
          txId,
          code: "EXISTING_FILE_OWNERSHIP_UNPROVEN",
          reason:
            "Refusing automatic live overwrite of existing files without --assume-single-writer or --owned-worktree attestation.",
          exitCode: 126,
          stdout: execRes.stdout,
          stderr: execRes.stderr,
          outputArtifacts: execRes.outputArtifacts,
          promoted: false,
          stagedBundleDir: outBundleDir,
          changedFiles: diffs.map((d) => d.relPosix),
          violations: [
            {
              code: "EXISTING_FILE_OWNERSHIP_UNPROVEN",
              path: diffs.find((d) => d.changeType !== "add")?.relPosix || "<workspace>",
              message:
                "Existing-file live promotion requires explicit single-writer ownership (--assume-single-writer or --owned-worktree); changes safely saved in staged bundle.",
            },
          ],
        };
      }

      if (promoteMode === "live" || assumeSingleWriter || ownedWorktree) {
        // Release `isolated_exec` lock right before delegating to hardened `promoteStagedBundle` (which acquires its own promotion lock & journal!)
        this.releaseAdmissionLock(txId);
        const prom = this.promoteStagedBundle(txId, { assumeSingleWriter, ownedWorktree });
        if (!prom.ok) {
          return {
            ok: false,
            txId,
            code: prom.code,
            reason: prom.reason,
            exitCode: 126,
            stdout: execRes.stdout,
            stderr: execRes.stderr,
            outputArtifacts: execRes.outputArtifacts,
            promoted: false,
            stagedBundleDir: outBundleDir,
            quarantineDir: prom.quarantineDir || null,
            violations: prom.violations || [
              { code: prom.code, path: "<promote>", message: prom.reason },
            ],
          };
        }
        return {
          ok: true,
          txId,
          code: "PROMOTED_CLEAN",
          exitCode: execRes.exitCode,
          stdout: execRes.stdout,
          stderr: execRes.stderr,
          outputArtifacts: execRes.outputArtifacts,
          promoted: true,
          stagedBundleDir: outBundleDir,
          changedFiles: prom.promotedFiles,
          nextWorkingSet: prom.nextWorkingSet,
          violations: [],
        };
      }

      return {
        ok: true,
        txId,
        code: "STAGED_CLEAN",
        exitCode: execRes.exitCode,
        stdout: execRes.stdout,
        stderr: execRes.stderr,
        outputArtifacts: execRes.outputArtifacts,
        promoted: false,
        stagedBundleDir: outBundleDir,
        changedFiles: diffs.map((d) => d.relPosix),
        violations: [],
      };
    } finally {
      if (!retainOpenLock) {
        this.releaseAdmissionLock(txId);
      }
      try {
        makeTreeOwnerWritableBestEffort(realIsoRoot);
        fs.rmSync(realIsoRoot, { recursive: true, force: true });
      } catch {
        // ignore
      }
    }
  }

  /**
   * Hardened Staged Bundle Promotion (``, ``):
   * - Validates `txId` format & directory containment
   * - Verifies authoritative `staged_bundles` SQLite record & `manifest_sha256` against disk `manifest.json`
   * - Validates every path via `inspectWorkspacePath(..., { forWrite: true })` (blocking `../`, symlinks, hardlinks, Ring-00)
   * - Verifies SHA-256 of EVERY staged candidate file in memory BEFORE the first live write
   * - Verifies full baseline identity tuple `(entryType, mode, size, mtimeNs, ctimeNs, dev, ino, sha256)` on live files
   * - Re-evaluates write-set against CURRENT session policy/grants/denySet/workingSet
   * - Persists every applied promotion entry in `promotion_applied_entries` and compensates ONLY entries demonstrably applied by this promotion (``)!
   */
  promoteStagedBundle(
    txId,
    { assumeSingleWriter = false, ownedWorktree = false, _beforeApplyEntryHook = null } = {}
  ) {
    const rawId = String(txId ?? "");
    if (!/^iso-\d+-[0-9a-f]{8,}$/.test(rawId)) {
      return {
        ok: false,
        code: "INVALID_BUNDLE_TX_ID",
        reason: `Invalid staged bundle identifier '${rawId}'.`,
      };
    }

    const bundleDir = path.join(this.stagedDir, rawId);
    if (!isContainedRelativePath(path.relative(this.stagedDir, bundleDir))) {
      return {
        ok: false,
        code: "INVALID_BUNDLE_TX_ID",
        reason: `Bundle path escapes staged directory.`,
      };
    }

    const promoLockId = `promo-${Date.now()}-${crypto.randomBytes(5).toString("hex")}`;
    this.acquireAdmissionLock({
      txId: promoLockId,
      ownerKind: "bundle_promote",
      sessionId: "default",
      toolUseId: rawId,
    });

    let promoJournalCommitted = false;
    try {
      const bundleRow = this.db
        .prepare(`SELECT * FROM staged_bundles WHERE tx_id = ?`)
        .get(rawId);
      if (!bundleRow) {
        return {
          ok: false,
          code: "STAGED_BUNDLE_NOT_FOUND",
          reason: `Authoritative staged bundle '${rawId}' not found in SQLite store.`,
        };
      }
      if (bundleRow.promoted_at !== null) {
        return {
          ok: false,
          code: "STAGED_BUNDLE_ALREADY_PROMOTED",
          reason: `Staged bundle '${rawId}' has already been promoted.`,
        };
      }

      let bundleDirStat = null;
      try {
        bundleDirStat = fs.lstatSync(bundleDir);
      } catch {
        bundleDirStat = null;
      }
      if (!bundleDirStat || !bundleDirStat.isDirectory() || bundleDirStat.isSymbolicLink()) {
        return {
          ok: false,
          code: "STAGED_BUNDLE_NOT_FOUND",
          reason: `Staged bundle directory '${bundleDir}' is missing or invalid.`,
        };
      }

      const manifestPath = path.join(bundleDir, "manifest.json");
      let diskManifestBytes;
      try {
        const mst = fs.lstatSync(manifestPath);
        if (!mst.isFile() || mst.isSymbolicLink()) throw new Error("Not a regular file");
        diskManifestBytes = fs.readFileSync(manifestPath);
      } catch (err) {
        return {
          ok: false,
          code: "BUNDLE_INTEGRITY_ERROR",
          reason: `Failed reading staged manifest.json: ${err.message}`,
        };
      }

      if (sha256Buffer(diskManifestBytes) !== bundleRow.manifest_sha256) {
        return {
          ok: false,
          code: "BUNDLE_INTEGRITY_ERROR",
          reason: `Staged manifest.json failed SHA-256 verification against authoritative SQLite digest (tampering detected).`,
        };
      }

      const manifest = JSON.parse(bundleRow.manifest_json);
      const manifestDiffs = Array.isArray(manifest.diffs) ? manifest.diffs : [];

      const overwritesExisting = manifestDiffs.some((d) => d.changeType !== "add");
      if (overwritesExisting && !assumeSingleWriter && !ownedWorktree) {
        return {
          ok: false,
          code: "EXISTING_FILE_OWNERSHIP_UNPROVEN",
          reason:
            "Promoting existing-file overwrites requires --assume-single-writer or --owned-worktree attestation.",
        };
      }

      const session = this.loadSession(bundleRow.session_id);
      if (!session) {
        return {
          ok: false,
          code: "STATE_INTEGRITY_FAILURE",
          reason: `Session '${bundleRow.session_id}' referenced by bundle '${rawId}' no longer exists.`,
        };
      }
      const taskBaselineCp = this.loadCheckpoint(session.taskBaselineId);

      // Step 1: Validate every manifest path, Ring-00 protection, and candidate staged file SHA-256 BEFORE touching disk!
      const filesRoot = path.join(bundleDir, "files");
      const verifiedCandidateBuffers = new Map();

      for (const d of manifestDiffs) {
        if (
          !d ||
          typeof d.relPosix !== "string" ||
          !["add", "modify", "mode-change", "delete"].includes(d.changeType)
        ) {
          return {
            ok: false,
            code: "BUNDLE_INTEGRITY_ERROR",
            reason: "Malformed diff item in staged bundle manifest.",
          };
        }

        const insp = inspectWorkspacePath(this.canonicalRoot, d.relPosix, {
          forWrite: true,
          allowDirectoryLeaf: false,
          checkPlatformAttrs: true,
          exemptXattrs: this.exemptXattrs,
        });
        if (!insp.ok) {
          return {
            ok: false,
            code: insp.code,
            reason: insp.reason,
            violations: [{ code: insp.code, path: d.relPosix, message: insp.reason }],
          };
        }
        if (insp.relPosix !== d.relPosix) {
          return {
            ok: false,
            code: "INVALID_PATH_COMPONENT",
            reason: `Unnormalized path '${d.relPosix}' in bundle manifest.`,
          };
        }

        const ring = classifyProtectionRing(d.relPosix);
        if (ring.ring === "RING_00") {
          return {
            ok: false,
            code: "IMMUTABLE_INFRA_PROTECTED",
            reason: `Bundle cannot target Ring-00 protected path '${d.relPosix}'.`,
          };
        }

        if (d.changeType !== "delete") {
          if (d.afterEntryType !== "file" || typeof d.afterSha256 !== "string") {
            return {
              ok: false,
              code: "BUNDLE_INTEGRITY_ERROR",
              reason: `Bundle entry '${d.relPosix}' is missing valid file hash metadata.`,
            };
          }
          const stagedFileAbs = path.join(filesRoot, d.relPosix);
          if (!isContainedRelativePath(path.relative(filesRoot, stagedFileAbs))) {
            return {
              ok: false,
              code: "OUTSIDE_WORKSPACE_ROOT",
              reason: `Staged file path '${d.relPosix}' escapes bundle files root.`,
            };
          }
          let fst = null;
          try {
            fst = fs.lstatSync(stagedFileAbs);
          } catch {
            fst = null;
          }
          if (!fst || !fst.isFile() || fst.isSymbolicLink() || Number(fst.nlink) > 1) {
            return {
              ok: false,
              code: "BUNDLE_INTEGRITY_ERROR",
              reason: `Staged artifact for '${d.relPosix}' is missing, symlinked, or hardlinked.`,
            };
          }
          const bytes = fs.readFileSync(stagedFileAbs);
          const actualHash = sha256Buffer(bytes);
          if (actualHash !== d.afterSha256) {
            return {
              ok: false,
              code: "BUNDLE_INTEGRITY_ERROR",
              reason: `Staged artifact '${d.relPosix}' failed SHA-256 verification (expected ${d.afterSha256}, got ${actualHash}).`,
            };
          }
          verifiedCandidateBuffers.set(d.relPosix, bytes);
        }
      }

      // Step 2: Scan live workspace & verify full baseline identity tuples (``)!
      const liveScan = this.scanWorkspaceNamespace({
        previousEntriesMap: null,
        storeBlobs: true,
        strictCheckpointCoverage: true,
      });
      if (!liveScan.coverageComplete) {
        return {
          ok: false,
          code: liveScan.incompleteCode || "CHECKPOINT_COVERAGE_INCOMPLETE",
          reason: liveScan.incompleteReason,
        };
      }

      const reEvalCandidates = [];
      for (const d of manifestDiffs) {
        const cur = liveScan.entries.get(d.relPosix) || null;
        if (d.changeType === "add") {
          if (cur) {
            const qDir = this._writePromotionConflictQuarantine(rawId, d.relPosix, bundleDir);
            return {
              ok: false,
              code: "CONCURRENT_EDIT_CONFLICT",
              reason: `Target '${d.relPosix}' already exists on live workspace.`,
              quarantineDir: qDir,
            };
          }
        } else {
          if (!d.beforeIdentity || !identityTupleMatches(cur, d.beforeIdentity)) {
            const qDir = this._writePromotionConflictQuarantine(rawId, d.relPosix, bundleDir);
            return {
              ok: false,
              code: "CONCURRENT_EDIT_CONFLICT",
              reason: `Live file '${d.relPosix}' drifted from staged baseline identity tuple; candidate preserved in ${bundleDir}.`,
              quarantineDir: qDir,
            };
          }
        }

        const cmdBeforeText = cur ? this.readBaselineTextFromEntry(cur) : null;
        const taskEnt = taskBaselineCp.entries.get(d.relPosix);
        const taskBeforeText = taskEnt ? this.readBaselineTextFromEntry(taskEnt) : cmdBeforeText;
        const candBytes = verifiedCandidateBuffers.get(d.relPosix) || null;
        const isBin = Boolean(d.isBinary || (candBytes && isProbablyBinaryBuffer(candBytes)));

        reEvalCandidates.push({
          relPosix: d.relPosix,
          changeType: d.changeType,
          isDirectory: false,
          commandBeforeText: cmdBeforeText,
          taskBaselineText: taskBeforeText,
          afterText: candBytes && !isBin ? candBytes.toString("utf8") : null,
          isBinary: isBin,
        });
      }

      const sessionConflicts = this.findSessionWriteConflicts(session.sessionId, liveScan.entries, manifestDiffs.map((diff) => diff.relPosix));
      if (sessionConflicts.length) return { ok: false, code: "SESSION_WRITE_CONFLICT", violations: sessionConflicts, reason: sessionConflicts[0].message };

      // Step 3: Re-evaluate candidate write-set against CURRENT session policy (``)!
      const policyCheck = evaluateCandidateWriteSet(reEvalCandidates, {
        budget: session.budget,
        workingSet: new Set(session.workingSet),
        grants: session.grants,
        denySet: session.denySet,
      });
      if (!policyCheck.ok) {
        return {
          ok: false,
          code: policyCheck.violations[0].code,
          reason: this.computeViolationDiagnostic(policyCheck.violations, session.sessionId),
          violations: policyCheck.violations,
        };
      }

      // Step 4: Reserve durable `'ACTIVE'` promotion journal BEFORE first live write (``)!
      const now = Date.now();
      this.withImmediateTransaction(() => {
        const cpId = this.persistCheckpoint(session.sessionId, "promote", liveScan);
        this.db
          .prepare(`DELETE FROM promotion_applied_entries WHERE promo_tx_id = ?`)
          .run(promoLockId);
        this.db
          .prepare(`
            INSERT INTO journals (
              tx_id, session_id, tool_use_id, command_checkpoint_id, state, created_at, updated_at
            ) VALUES (?, ?, ?, ?, 'ACTIVE', ?, ?)
          `)
          .run(promoLockId, session.sessionId, `promote:${rawId}`, cpId, now, now);
      });
      promoJournalCommitted = true;

      let currentConflictRelPosix = "<promote>";
      try {
        for (const d of manifestDiffs) {
          currentConflictRelPosix = d.relPosix;
          if (typeof _beforeApplyEntryHook === "function") {
            _beforeApplyEntryHook(d.relPosix, d.changeType);
          }

          // Re-verify path has not been swapped with a symlink right before write
          const liveCheck = inspectWorkspacePath(this.canonicalRoot, d.relPosix, {
            forWrite: true,
            allowDirectoryLeaf: false,
          });
          if (!liveCheck.ok) {
            const err = new Error(liveCheck.reason);
            err.code = liveCheck.code;
            throw err;
          }

          const prevEnt = liveScan.entries.get(d.relPosix) || null;
          const liveAbs = liveCheck.absPath;

          if (d.changeType === "add") {
            fs.mkdirSync(path.dirname(liveAbs), { recursive: true, mode: 0o755 });
            const verifiedBytes = verifiedCandidateBuffers.get(d.relPosix);
            const rand = crypto.randomBytes(5).toString("hex");
            const sameFsTmp = path.join(path.dirname(liveAbs), `.bg-add.${process.pid}.${rand}`);
            writeDurableFileAtomic(sameFsTmp, verifiedBytes, d.afterMode || 0o644);
            try {
              fs.linkSync(sameFsTmp, liveAbs);
            } finally {
              try {
                fs.unlinkSync(sameFsTmp);
              } catch {
                // ignore
              }
            }
            fsyncDirectoryBestEffort(path.dirname(liveAbs));
            const appliedSt = fs.lstatSync(liveAbs, { bigint: true });
            this.db
              .prepare(`
                INSERT INTO promotion_applied_entries (
                  promo_tx_id, rel_posix, action, prev_entry_type, prev_blob_sha256, prev_mode,
                  applied_dev, applied_ino, applied_mode, applied_ctime_ns, applied_sha256
                ) VALUES (?, ?, 'add', 'absent', NULL, NULL, ?, ?, ?, ?, ?)
              `)
              .run(
                promoLockId,
                d.relPosix,
                Number(appliedSt.dev),
                appliedSt.ino.toString(),
                Number(appliedSt.mode) & 0o7777,
                appliedSt.ctimeNs.toString(),
                d.afterSha256
              );
            this.writeVerifiedBlobFromFile(liveAbs, d.afterSha256);
          } else if (d.changeType === "delete") {
            this.safeRemoveWorkspaceEntry(d.relPosix, liveScan.entries);
            this.db
              .prepare(`
                INSERT INTO promotion_applied_entries (
                  promo_tx_id, rel_posix, action, prev_entry_type, prev_blob_sha256, prev_mode,
                  applied_dev, applied_ino, applied_mode, applied_ctime_ns, applied_sha256
                ) VALUES (?, ?, 'delete', 'file', ?, ?, NULL, NULL, NULL, NULL, NULL)
              `)
              .run(
                promoLockId,
                d.relPosix,
                prevEnt?.sha256 || null,
                prevEnt ? prevEnt.mode & 0o7777 : 0o644
              );
          } else {
            let preWriteSt = null;
            try {
              preWriteSt = fs.lstatSync(liveAbs, { bigint: true });
            } catch {
              preWriteSt = null;
            }
            if (
              !preWriteSt ||
              !prevEnt ||
              Number(preWriteSt.dev) !== Number(prevEnt.dev) ||
              preWriteSt.ino.toString() !== String(prevEnt.ino) ||
              preWriteSt.mtimeNs.toString() !== String(prevEnt.mtimeNs) ||
              preWriteSt.ctimeNs.toString() !== String(prevEnt.ctimeNs)
            ) {
              const raceErr = new Error(
                `Live file '${d.relPosix}' changed concurrently right before promotion overwrite.`
              );
              raceErr.code = "CONCURRENT_EDIT_CONFLICT";
              throw raceErr;
            }
            const verifiedBytes = verifiedCandidateBuffers.get(d.relPosix);
            writeDurableFileAtomic(liveAbs, verifiedBytes, d.afterMode || 0o644);
            const appliedSt = fs.lstatSync(liveAbs, { bigint: true });
            this.db
              .prepare(`
                INSERT INTO promotion_applied_entries (
                  promo_tx_id, rel_posix, action, prev_entry_type, prev_blob_sha256, prev_mode,
                  applied_dev, applied_ino, applied_mode, applied_ctime_ns, applied_sha256
                ) VALUES (?, ?, ?, 'file', ?, ?, ?, ?, ?, ?, ?)
              `)
              .run(
                promoLockId,
                d.relPosix,
                d.changeType,
                prevEnt.sha256,
                prevEnt.mode & 0o7777,
                Number(appliedSt.dev),
                appliedSt.ino.toString(),
                Number(appliedSt.mode) & 0o7777,
                appliedSt.ctimeNs.toString(),
                d.afterSha256
              );
            this.writeVerifiedBlobFromFile(liveAbs, d.afterSha256);
          }
        }

        this.withImmediateTransaction(() => {
          const acceptedEntries = new Map(liveScan.entries);
          for (const diff of manifestDiffs) {
            if (diff.changeType === "delete") acceptedEntries.delete(diff.relPosix);
            else acceptedEntries.set(diff.relPosix, { entryType: "file", sha256: diff.afterSha256, mode: diff.afterMode ?? 0o644 });
          }
          this.recordSessionAcceptedFiles(session.sessionId, manifestDiffs.map((diff) => diff.relPosix), acceptedEntries);
          this.db
            .prepare(`UPDATE sessions SET working_set_json = ?, updated_at = ? WHERE session_id = ?`)
            .run(JSON.stringify(policyCheck.nextWorkingSet), Date.now(), session.sessionId);
          this.db
            .prepare(`UPDATE staged_bundles SET promoted_at = ? WHERE tx_id = ?`)
            .run(Date.now(), rawId);
          this.db
            .prepare(`DELETE FROM promotion_applied_entries WHERE promo_tx_id = ?`)
            .run(promoLockId);
          this.db
            .prepare(`UPDATE journals SET state = 'CLEAN', updated_at = ? WHERE tx_id = ?`)
            .run(Date.now(), promoLockId);
          this.db
            .prepare(`DELETE FROM active_lock WHERE singleton = 1 AND tx_id = ?`)
            .run(promoLockId);
        });

        return {
          ok: true,
          code: "PROMOTED_CLEAN",
          txId: rawId,
          promotedFiles: manifestDiffs.map((d) => d.relPosix),
          nextWorkingSet: policyCheck.nextWorkingSet,
        };
      } catch (applyErr) {
        // : Compensate ONLY entries demonstrably still equal to what THIS promotion wrote (`promotion_applied_entries`),
        // NEVER deleting or overwriting external colliding files or in-place external edits!
        return this._compensatePartialPromotion(
          promoLockId,
          rawId,
          bundleDir,
          currentConflictRelPosix,
          applyErr,
          liveScan.entries
        );
      }
    } finally {
      if (!promoJournalCommitted) {
        this.releaseAdmissionLock(promoLockId);
      }
    }
  }

  _compensatePartialPromotion(
    promoLockId,
    bundleTxId,
    bundleDir,
    conflictRelPosix,
    applyErr,
    baselineEntriesMap = null
  ) {
    const appliedRows = this.db
      .prepare(`SELECT * FROM promotion_applied_entries WHERE promo_tx_id = ? ORDER BY seq DESC`)
      .all(promoLockId);

    const appliedEntryRemainsUnchanged = (targetAbs, st, row) => {
      if (!st || st.isSymbolicLink() || !st.isFile() || Number(st.nlink) !== 1) return false;
      if (
        Number(st.dev) !== Number(row.applied_dev) ||
        st.ino.toString() !== String(row.applied_ino)
      ) {
        return false;
      }
      if (
        row.applied_mode !== null &&
        row.applied_mode !== undefined &&
        (Number(st.mode) & 0o7777) !== Number(row.applied_mode)
      ) {
        return false;
      }
      if (
        row.applied_ctime_ns !== null &&
        row.applied_ctime_ns !== undefined &&
        st.ctimeNs.toString() !== String(row.applied_ctime_ns)
      ) {
        return false;
      }
      if (row.applied_sha256) {
        try {
          const curHash = streamSha256File(targetAbs);
          if (curHash.sha256 !== String(row.applied_sha256)) return false;
        } catch {
          return false;
        }
      }
      return true;
    };

    const qDir = path.join(this.quarantineDir, bundleTxId);
    fs.mkdirSync(qDir, { recursive: true, mode: 0o700 });
    const quarantineLiveCopyBestEffort = (relPosix) => {
      if (!relPosix || relPosix.startsWith("<")) return;
      try {
        const liveAbs = path.join(this.canonicalRoot, relPosix);
        if (fs.existsSync(liveAbs) && fs.lstatSync(liveAbs).isFile()) {
          writeDurableFileAtomic(path.join(qDir, "live", relPosix), fs.readFileSync(liveAbs), 0o400);
        }
      } catch {
        // ignore unreadable live file
      }
    };

    let compensationConflict = false;
    const driftedAppliedPaths = [];
    for (const row of appliedRows) {
      try {
        const check = inspectWorkspacePath(this.canonicalRoot, row.rel_posix, {
          forWrite: true,
          allowDirectoryLeaf: false,
        });
        if (!check.ok) {
          compensationConflict = true;
          driftedAppliedPaths.push(row.rel_posix);
          quarantineLiveCopyBestEffort(row.rel_posix);
          continue;
        }
        const targetAbs = check.absPath;
        if (row.action === "add") {
          let st = null;
          try {
            st = fs.lstatSync(targetAbs, { bigint: true });
          } catch {
            st = null;
          }
          if (!st) continue;
          if (!appliedEntryRemainsUnchanged(targetAbs, st, row)) {
            // External writer modified or replaced our added file in-place or by rename; NEVER delete external bytes!
            compensationConflict = true;
            driftedAppliedPaths.push(row.rel_posix);
            quarantineLiveCopyBestEffort(row.rel_posix);
            continue;
          }
          fs.unlinkSync(targetAbs);
          fsyncDirectoryBestEffort(path.dirname(targetAbs));
          let dir = path.dirname(targetAbs);
          while (dir !== this.canonicalRoot && dir.startsWith(this.canonicalRoot + path.sep)) {
            const dirRelPosix = toPosixRel(path.relative(this.canonicalRoot, dir));
            if (baselineEntriesMap && baselineEntriesMap.has(dirRelPosix)) break;
            try {
              const items = fs.readdirSync(dir);
              if (items.length === 0) {
                fs.rmdirSync(dir);
                dir = path.dirname(dir);
              } else {
                break;
              }
            } catch {
              break;
            }
          }
        } else if (row.action === "delete") {
          let existsNow = false;
          try {
            fs.lstatSync(targetAbs);
            existsNow = true;
          } catch {
            existsNow = false;
          }
          if (existsNow) {
            // External writer recreated path after deletion; preserve external file untouched!
            compensationConflict = true;
            driftedAppliedPaths.push(row.rel_posix);
            quarantineLiveCopyBestEffort(row.rel_posix);
            continue;
          }
          if (row.prev_blob_sha256) {
            const prevBytes = this.readVerifiedBlob(row.prev_blob_sha256);
            fs.mkdirSync(path.dirname(targetAbs), { recursive: true, mode: 0o755 });
            const rand = crypto.randomBytes(5).toString("hex");
            const sameFsTmp = path.join(path.dirname(targetAbs), `.bg-comp.${process.pid}.${rand}`);
            writeDurableFileAtomic(sameFsTmp, prevBytes, row.prev_mode ?? 0o644);
            try {
              fs.linkSync(sameFsTmp, targetAbs);
            } finally {
              try {
                fs.unlinkSync(sameFsTmp);
              } catch {
                // ignore
              }
            }
            fsyncDirectoryBestEffort(path.dirname(targetAbs));
          }
        } else {
          let st = null;
          try {
            st = fs.lstatSync(targetAbs, { bigint: true });
          } catch {
            st = null;
          }
          if (!appliedEntryRemainsUnchanged(targetAbs, st, row)) {
            compensationConflict = true;
            driftedAppliedPaths.push(row.rel_posix);
            quarantineLiveCopyBestEffort(row.rel_posix);
            continue;
          }
          if (row.prev_blob_sha256) {
            const prevBytes = this.readVerifiedBlob(row.prev_blob_sha256);
            writeDurableFileAtomic(targetAbs, prevBytes, row.prev_mode ?? 0o644);
          }
        }
      } catch {
        compensationConflict = true;
        driftedAppliedPaths.push(row.rel_posix);
        quarantineLiveCopyBestEffort(row.rel_posix);
      }
    }

    quarantineLiveCopyBestEffort(conflictRelPosix);
    this._writePromotionConflictQuarantine(
      bundleTxId,
      conflictRelPosix,
      bundleDir,
      driftedAppliedPaths
    );
    const isCollision =
      applyErr?.code === "EEXIST" ||
      applyErr?.code === "CONCURRENT_EDIT_CONFLICT" ||
      applyErr?.code === "CONCURRENT_SNAPSHOT_RACE";
    const outCode = isCollision
      ? "CONCURRENT_EDIT_CONFLICT"
      : applyErr?.code || "PROMOTION_WRITE_FAILED";

    this.withImmediateTransaction(() => {
      this.db
        .prepare(`DELETE FROM promotion_applied_entries WHERE promo_tx_id = ?`)
        .run(promoLockId);
      this.db
        .prepare(`DELETE FROM active_lock WHERE singleton = 1 AND tx_id = ?`)
        .run(promoLockId);
      if (!compensationConflict) {
        this.db
          .prepare(
            `UPDATE journals SET state = 'ABORTED', error_code = ?, error_detail = ?, updated_at = ? WHERE tx_id = ?`
          )
          .run(outCode, String(applyErr?.message || outCode), Date.now(), promoLockId);
      } else {
        this.db
          .prepare(
            `UPDATE journals SET state = 'RECOVERY_FAILED', error_code = ?, error_detail = ?, updated_at = ? WHERE tx_id = ?`
          )
          .run(
            "EXTERNAL_CONCURRENT_WRITE_DETECTED",
            `Promotion failed on '${conflictRelPosix}' (${applyErr?.message}) and applied entry drift was detected on [${driftedAppliedPaths.join(", ")}]; external bytes preserved untouched.`,
            Date.now(),
            promoLockId
          );
      }
    });

    return {
      ok: false,
      code: compensationConflict ? "EXTERNAL_CONCURRENT_WRITE_DETECTED" : outCode,
      reason: compensationConflict
        ? `Promotion aborted on '${conflictRelPosix}' (${applyErr?.message || outCode}); concurrent external edits on [${driftedAppliedPaths.join(", ")}] were preserved untouched and quarantined in ${qDir} (journal marked RECOVERY_FAILED).`
        : `Promotion aborted on '${conflictRelPosix}' (${applyErr?.message || outCode}); external files preserved untouched and partial promotion entries compensated.`,
      driftedPaths: driftedAppliedPaths,
      rolledBack: !compensationConflict,
      quarantineDir: qDir,
    };
  }

  _writePromotionConflictQuarantine(txId, conflictPath, bundleDir, driftedAppliedPaths = []) {
    const qDir = path.join(this.quarantineDir, txId);
    fs.mkdirSync(qDir, { recursive: true, mode: 0o700 });
    writeDurableFileAtomic(
      path.join(qDir, "conflict.json"),
      Buffer.from(
        JSON.stringify(
          { txId, conflictPath, driftedAppliedPaths, stagedBundleDir: bundleDir },
          null,
          2
        ) + "\n",
        "utf8"
      ),
      0o400
    );
    return qDir;
  }

  computeViolationDiagnostic(violations, sessionId = "default") {
    if (violations.some((violation) => violation.code === "UNRESOLVED_PROHIBITION")) {
      return "[BlastGuard UNRESOLVED_PROHIBITION] A prohibited file or directory could not be identified reliably. " +
        "Do not retry writes in this session. Clarify the exact prohibited paths and start a new conversation, " +
        "or explicitly reset this task with `blast-guard session start --reset-task --session <session-id> --prompt <task>`.";
    }
    let impact = null;
    try {
      if (violations[0]?.path && !violations[0].path.startsWith("<")) {
        const graph = buildWorkspaceDependencyGraph(this.canonicalRoot, { maxFiles: 1500 });
        impact = graph.computeCallerImpact(violations[0].path);
      }
    } catch {
      // ignore impact lookup failure
    }
    const session = this.loadSession(sessionId) || this.loadSession("default");
    const escalation = session ? createVoiEscalationCard(violations, {
      sessionId: session.sessionId, turnId: session.turnId, workingSet: session.workingSet, callerImpact: impact,
    }) : null;
    if (escalation) this.db.prepare("INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
      .run(`escalation:${session.sessionId}`, JSON.stringify(escalation));
    const guidance = formatVoiEscalationGuidance(violations, {
      workingSet: session?.workingSet || [],
      callerImpact: impact,
    });
    if (!escalation) return guidance;
    const primary = violations[0];
    const impactText = impact ? `\n静态引用影响 ${impact.directCallers} 个直接调用文件、${impact.transitiveCallers} 个传递调用文件。` : "";
    return `[BlastGuard ${primary.code}] ${primary.path}${impactText}\n${formatEscalationCard(escalation)}`;
  }
}

function makeTreeOwnerWritableBestEffort(rootDir) {
  try {
    const st = fs.lstatSync(rootDir);
    if (st.isSymbolicLink() || !st.isDirectory()) return;
    fs.chmodSync(rootDir, (st.mode & 0o7777) | 0o700);
    for (const ent of fs.readdirSync(rootDir, { withFileTypes: true })) {
      if (ent.isDirectory() && !ent.isSymbolicLink()) {
        makeTreeOwnerWritableBestEffort(path.join(rootDir, ent.name));
      }
    }
  } catch {
    // ignore
  }
}

function isPidAlive(pid) {
  const num = Number(pid);
  if (!Number.isInteger(num) || num <= 0) return false;
  try {
    process.kill(num, 0);
    return true;
  } catch (err) {
    return err?.code === "EPERM";
  }
}

function isProcessGroupAlive(pgid) {
  if (!pgid || pgid <= 0) return false;
  try {
    process.kill(-pgid, 0);
    return true;
  } catch (err) {
    return err?.code === "EPERM";
  }
}

function listSameUidProcessRecords({ _forceFail = false } = {}) {
  if (_forceFail) return { ok: false, records: [] };
  const out = [];
  if (process.platform === "linux" && fs.existsSync("/proc")) {
    const myUid = typeof process.getuid === "function" ? process.getuid() : null;
    try {
      for (const name of fs.readdirSync("/proc")) {
        if (!/^\d+$/.test(name)) continue;
        const pid = Number(name);
        try {
          if (myUid !== null) {
            const st = fs.lstatSync(`/proc/${pid}`);
            if (st.uid !== myUid) continue;
          }
          const statRaw = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
          const closeParen = statRaw.lastIndexOf(")");
          if (closeParen === -1) continue;
          const rest = statRaw.slice(closeParen + 2).trim().split(/\s+/);
          const state = rest[0] || "";
          if (state === "Z") continue;
          const ppid = Number(rest[1]);
          const pgid = Number(rest[2]);
          if (pid > 0) out.push({ pid, ppid, pgid });
        } catch {
          // exited concurrently
        }
      }
      if (out.some((rec) => rec.pid === process.pid)) {
        return { ok: true, records: out };
      }
    } catch {
      // fall back to ps
    }
  }

  const psBin = fs.existsSync("/bin/ps") ? "/bin/ps" : "ps";
  const uidArg = typeof process.getuid === "function" ? ["-u", String(process.getuid())] : [];
  const r = spawnSync(psBin, [...uidArg, "-o", "pid=,ppid=,pgid=,state="], {
    encoding: "utf8",
    timeout: 1500,
  });
  if (r.error || r.status !== 0 || !r.stdout) {
    return { ok: false, records: [] };
  }
  for (const rawLine of r.stdout.split("\n")) {
    const m = rawLine.trim().match(/^(\d+)\s+(\d+)\s+(\d+)\s+(\S+)/);
    if (!m) continue;
    const state = m[4];
    if (state.startsWith("Z")) continue;
    out.push({ pid: Number(m[1]), ppid: Number(m[2]), pgid: Number(m[3]) });
  }
  return {
    ok: out.some((rec) => rec.pid === process.pid),
    records: out,
  };
}

function findTokenOrCwdMatchedPids(
  candidateRecords,
  execToken,
  watchedRoots,
  { leaseInfo = null, _forceFail = false } = {}
) {
  const matched = new Set();
  if (_forceFail) return { ok: false, matched };
  const tokenNeedle = `BLAST_GUARD_EXEC_TOKEN=${execToken}`;

  if (process.platform === "linux" && fs.existsSync("/proc")) {
    let selfReadable = false;
    try {
      selfReadable = fs.readFileSync(`/proc/${process.pid}/environ`, "utf8").length >= 0;
    } catch {
      selfReadable = false;
    }
    if (!selfReadable) {
      return { ok: false, matched };
    }
    for (const rec of candidateRecords) {
      try {
        const envRaw = fs.readFileSync(`/proc/${rec.pid}/environ`, "utf8");
        if (envRaw.includes(tokenNeedle)) {
          matched.add(rec.pid);
          continue;
        }
      } catch {
        if (isPidAlive(rec.pid)) {
          return { ok: false, matched };
        }
      }
      if (leaseInfo && leaseInfo.ino) {
        try {
          const fdEntries = fs.readdirSync(`/proc/${rec.pid}/fd`);
          let hitLease = false;
          for (const fn of fdEntries) {
            try {
              const st = fs.statSync(`/proc/${rec.pid}/fd/${fn}`, { bigint: true });
              if (
                Number(st.dev) === Number(leaseInfo.dev) &&
                st.ino.toString() === String(leaseInfo.ino)
              ) {
                matched.add(rec.pid);
                hitLease = true;
                break;
              }
            } catch {
              // fd closed concurrently
            }
          }
          if (hitLease) continue;
        } catch {
          if (isPidAlive(rec.pid)) {
            return { ok: false, matched };
          }
        }
      }
      if (watchedRoots.length > 0) {
        try {
          const pidCwd = fs.realpathSync.native(`/proc/${rec.pid}/cwd`);
          if (watchedRoots.some((r) => pidCwd === r || pidCwd.startsWith(r + path.sep))) {
            matched.add(rec.pid);
          }
        } catch {
          if (isPidAlive(rec.pid)) {
            return { ok: false, matched };
          }
        }
      }
    }
    return { ok: true, matched };
  }

  // Always include `process.pid` so `ps eww` is guaranteed at least one live PID and must exit 0 when permitted!
  const pidList = [process.pid, ...candidateRecords.map((r) => r.pid)];
  const psBin = fs.existsSync("/bin/ps") ? "/bin/ps" : "ps";
  const psEnv = spawnSync(psBin, ["eww", "-o", "pid=,command=", "-p", pidList.join(",")], {
    encoding: "utf8",
    timeout: 1500,
    maxBuffer: 8 * 1024 * 1024,
  });
  if (psEnv.error || psEnv.status !== 0 || !psEnv.stdout) {
    return { ok: false, matched };
  }
  let sawSelf = false;
  for (const line of psEnv.stdout.split("\n")) {
    const m = line.trim().match(/^(\d+)\s+/);
    if (!m) continue;
    const pid = Number(m[1]);
    if (pid === process.pid) sawSelf = true;
    if (pid !== process.pid && line.includes(tokenNeedle)) {
      matched.add(pid);
    }
  }
  if (!sawSelf) {
    return { ok: false, matched };
  }

  // Inspect inherited lease FD (`fd 3` inode) AND workspace `cwd` across any post-baseline unmatched live PIDs (``)!
  // Note: `/usr/sbin/lsof -p pid1,pid2` exits 1 if ANY PID in `-p` exited concurrently between `ps` and `lsof`,
  // even while emitting complete descriptor records for `process.pid` and every still-alive PID! Therefore we
  // verify `seenInLsof.has(process.pid)` AND require that every `stillUnmatched` PID absent from `seenInLsof`
  // has genuinely exited (`!isPidAlive(r.pid)`), failing closed if `lsof` omitted any live PID!
  const stillUnmatched = candidateRecords.filter((r) => !matched.has(r.pid) && isPidAlive(r.pid));
  if (stillUnmatched.length > 0 && ((leaseInfo && leaseInfo.ino) || watchedRoots.length > 0)) {
    if (!fs.existsSync("/usr/sbin/lsof")) {
      return { ok: false, matched };
    }
    const lsofRes = spawnSync(
      "/usr/sbin/lsof",
      [
        "-w",
        "-a",
        "-p",
        [process.pid, ...stillUnmatched.map((r) => r.pid)].join(","),
        "-d",
        "cwd,0-255",
        "-Fpfin",
      ],
      { encoding: "utf8", timeout: 1500, maxBuffer: 8 * 1024 * 1024 }
    );
    if (lsofRes.error || !lsofRes.stdout) {
      return { ok: false, matched };
    }
    const seenInLsof = new Set();
    let curPid = null;
    let curFd = null;
    for (const line of lsofRes.stdout.split("\n")) {
      if (!line) continue;
      const tag = line[0];
      const val = line.slice(1);
      if (tag === "p") {
        curPid = Number(val);
        curFd = null;
        if (curPid > 0) seenInLsof.add(curPid);
      } else if (tag === "f") {
        curFd = val;
      } else if (
        tag === "i" &&
        curPid &&
        curPid !== process.pid &&
        leaseInfo &&
        leaseInfo.ino &&
        val === String(leaseInfo.ino)
      ) {
        matched.add(curPid);
      } else if (
        tag === "n" &&
        curPid &&
        curPid !== process.pid &&
        curFd === "cwd" &&
        watchedRoots.length > 0
      ) {
        let cwdReal = val;
        try {
          cwdReal = fs.realpathSync.native(cwdReal);
        } catch {
          // keep raw
        }
        if (watchedRoots.some((r) => cwdReal === r || cwdReal.startsWith(r + path.sep))) {
          matched.add(curPid);
        }
      }
    }
    if (!seenInLsof.has(process.pid)) {
      return { ok: false, matched };
    }
    for (const r of stillUnmatched) {
      if (!seenInLsof.has(r.pid) && isPidAlive(r.pid)) {
        return { ok: false, matched };
      }
    }
  }

  return { ok: true, matched };
}

/**
 * Spawn command in its own POSIX process group (`detached: true`), track both process-group AND newly detached
 * session/process-group descendants (`setsid` / `detached: true` / `chdir("/")` / `execve(..., {})` grandchildren
 * via PPID/PGID lineage, injected `BLAST_GUARD_EXEC_TOKEN`, workspace CWD sweeps, inherited unlinked lease inode on
 * `fd 3`, and kernel EOF pipe on `fd 4`), forward parent interruption signals, reap all descendants (`SIGKILL`),
 * wait for `ESRCH` across all tracked PIDs/PGIDs AND closure of both stdio and lease pipes, and report verified
 * `quiescent` boolean (``)!
 * If OS process enumeration (`ps` / `/proc` / `lsof`) is unavailable or blocked by an outer sandbox, fails closed
 * (`quiescent: false, enumerationAvailable: false`) instead of assuming an empty process table!
 */
export function spawnAndReapProcessGroup(
  bin,
  args,
  {
    cwd,
    env,
    timeoutMs = 120000,
    extraPaths = [],
    outputDir = null,
    _testForceEnumerationUnavailable = false,
  } = {}
) {
  return new Promise((resolve, reject) => {
    const baselineSnap = listSameUidProcessRecords({
      _forceFail: _testForceEnumerationUnavailable,
    });
    let enumerationComplete = baselineSnap.ok;
    const baselinePids = new Set(baselineSnap.records.map((r) => r.pid));
    baselinePids.add(process.pid);

    const execToken = crypto.randomBytes(16).toString("hex");
    const childEnv = {
      ...(env || process.env),
      BLAST_GUARD_EXEC_TOKEN: execToken,
    };

    const watchedRoots = [];
    for (const p of [cwd, ...(extraPaths || [])]) {
      if (!p) continue;
      try {
        const rp = fs.realpathSync.native(p);
        if (rp !== "/" && rp !== os.homedir() && rp !== os.tmpdir()) {
          watchedRoots.push(rp);
        }
      } catch {
        // ignore
      }
    }

    // Create an unlinked read-only lease file (`fd 3`) + EOF pipe (`fd 4`) inherited across `fork`/`setsid`/`chdir`/`execve` (``)!
    let leaseFd = null;
    let leaseInfo = null;
    const leaseTmpPath = path.join(os.tmpdir(), `.bg-lease-${process.pid}-${execToken}`);
    try {
      fs.mkdirSync(os.tmpdir(), { recursive: true });
      const createFd = fs.openSync(leaseTmpPath, "wx", 0o600);
      fs.closeSync(createFd);
      leaseFd = fs.openSync(leaseTmpPath, "r");
      const leaseSt = fs.fstatSync(leaseFd, { bigint: true });
      leaseInfo = {
        dev: Number(leaseSt.dev),
        ino: leaseSt.ino.toString(),
      };
      fs.unlinkSync(leaseTmpPath);
    } catch {
      enumerationComplete = false;
      try {
        fs.unlinkSync(leaseTmpPath);
      } catch {
        // ignore
      }
      if (leaseFd !== null) {
        try {
          fs.closeSync(leaseFd);
        } catch {
          // ignore
        }
        leaseFd = null;
      }
    }

    let child;
    try {
      child = spawn(bin, args, {
        cwd,
        env: childEnv,
        detached: true,
        stdio: ["ignore", "pipe", "pipe", leaseFd !== null ? leaseFd : "ignore", "pipe"],
      });
    } finally {
      if (leaseFd !== null) {
        try {
          fs.closeSync(leaseFd);
        } catch {
          // ignore
        }
        leaseFd = null;
      }
    }

    const trackedPids = new Set();
    const trackedPgids = new Set();
    if (child.pid) {
      trackedPids.add(child.pid);
      trackedPgids.add(child.pid);
    }

    const stdoutCapture = createBoundedOutputCapture({ directory: outputDir, streamName: "stdout" });
    const stderrCapture = createBoundedOutputCapture({ directory: outputDir, streamName: "stderr" });
    const capturedOutput = () => {
      const stdout = stdoutCapture.finish();
      const stderr = stderrCapture.finish();
      return { stdout: stdout.text, stderr: stderr.text,
        outputArtifacts: { stdout: stdout.artifact, stderr: stderr.artifact } };
    };
    let timedOut = false;
    let settled = false;
    let leasePipeClosed = !child.stdio?.[4];

    if (child.stdio?.[4]) {
      child.stdio[4].on("error", () => {});
      child.stdio[4].on("close", () => {
        leasePipeClosed = true;
      });
      child.stdio[4].resume();
    }

    const sweepProcessTree = ({ inspectEnvAndCwd = false } = {}) => {
      const snap = listSameUidProcessRecords({
        _forceFail: _testForceEnumerationUnavailable,
      });
      if (!snap.ok) {
        enumerationComplete = false;
        return;
      }
      const records = snap.records;
      let changed = true;
      while (changed) {
        changed = false;
        for (const rec of records) {
          if (rec.pid === process.pid || baselinePids.has(rec.pid)) continue;
          if (trackedPids.has(rec.ppid) || trackedPgids.has(rec.pgid)) {
            if (!trackedPids.has(rec.pid)) {
              trackedPids.add(rec.pid);
              changed = true;
            }
            if (rec.pgid > 1 && !trackedPgids.has(rec.pgid)) {
              trackedPgids.add(rec.pgid);
              changed = true;
            }
          }
        }
      }

      if (inspectEnvAndCwd) {
        const unlinkedCandidates = records.filter(
          (rec) =>
            rec.pid !== process.pid &&
            !baselinePids.has(rec.pid) &&
            !trackedPids.has(rec.pid)
        );
        const tokenSweep = findTokenOrCwdMatchedPids(
          unlinkedCandidates,
          execToken,
          watchedRoots,
          { leaseInfo, _forceFail: _testForceEnumerationUnavailable }
        );
        if (!tokenSweep.ok) {
          enumerationComplete = false;
          return;
        }
        if (tokenSweep.matched.size > 0) {
          for (const pid of tokenSweep.matched) {
            trackedPids.add(pid);
            const rec = records.find((r) => r.pid === pid);
            if (rec && rec.pgid > 1) trackedPgids.add(rec.pgid);
          }
          // Expand any children of newly matched detached leaders
          let subChanged = true;
          while (subChanged) {
            subChanged = false;
            for (const rec of records) {
              if (rec.pid === process.pid || baselinePids.has(rec.pid)) continue;
              if (trackedPids.has(rec.ppid) || trackedPgids.has(rec.pgid)) {
                if (!trackedPids.has(rec.pid)) {
                  trackedPids.add(rec.pid);
                  subChanged = true;
                }
                if (rec.pgid > 1 && !trackedPgids.has(rec.pgid)) {
                  trackedPgids.add(rec.pgid);
                  subChanged = true;
                }
              }
            }
          }
        }
      }
    };

    const killAllTracked = (sig = "SIGKILL", { inspectEnvAndCwd = true } = {}) => {
      sweepProcessTree({ inspectEnvAndCwd });
      for (const pgid of trackedPgids) {
        if (pgid > 1 && pgid !== process.pid) {
          try {
            process.kill(-pgid, sig);
          } catch {
            // ignore ESRCH
          }
        }
      }
      for (const pid of trackedPids) {
        if (pid > 1 && pid !== process.pid) {
          try {
            process.kill(pid, sig);
          } catch {
            // ignore ESRCH
          }
        }
      }
    };

    const anyTrackedAlive = () => {
      for (const pgid of trackedPgids) {
        if (pgid > 1 && pgid !== process.pid && isProcessGroupAlive(pgid)) return true;
      }
      for (const pid of trackedPids) {
        if (pid > 1 && pid !== process.pid && isPidAlive(pid)) return true;
      }
      return false;
    };

    const liveTrackerTimer = setInterval(() => {
      try {
        sweepProcessTree({ inspectEnvAndCwd: false });
      } catch {
        // ignore
      }
    }, 15);
    if (typeof liveTrackerTimer.unref === "function") liveTrackerTimer.unref();

    const onParentSignal = (sig) => {
      clearInterval(liveTrackerTimer);
      killAllTracked("SIGKILL", { inspectEnvAndCwd: true });
      if (process.listenerCount(sig) <= 1) {
        process.exit(128 + (sig === "SIGINT" ? 2 : 15));
      }
    };

    process.on("SIGINT", onParentSignal);
    process.on("SIGTERM", onParentSignal);
    process.on("SIGHUP", onParentSignal);

    const cleanupListenersAndTimers = () => {
      clearInterval(liveTrackerTimer);
      process.off("SIGINT", onParentSignal);
      process.off("SIGTERM", onParentSignal);
      process.off("SIGHUP", onParentSignal);
    };

    const timer = setTimeout(() => {
      timedOut = true;
      killAllTracked("SIGKILL", { inspectEnvAndCwd: true });
    }, timeoutMs);

    child.stdout.on("data", (d) => stdoutCapture.append(d));
    child.stderr.on("data", (d) => stderrCapture.append(d));

    let exitInfo = null;
    let stdioClosed = false;

    child.on("close", () => {
      stdioClosed = true;
    });

    child.on("error", (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      cleanupListenersAndTimers();
      try {
        child.stdio?.[4]?.destroy();
      } catch {
        // ignore
      }
      killAllTracked("SIGKILL", { inspectEnvAndCwd: true });
      capturedOutput();
      reject(err);
    });

    child.on("exit", (code, signal) => {
      exitInfo = { code, signal };
      clearTimeout(timer);
      clearInterval(liveTrackerTimer);

      // Immediately discover & reap any lingering background subshells AND detached (`setsid`/`execve`) descendants!
      killAllTracked("SIGKILL", { inspectEnvAndCwd: true });

      // Poll up to 800 ms for ALL tracked PIDs/PGIDs to reach ESRCH AND both stdio & lease pipes (`fd 4`) to close!
      const deadline = Date.now() + 800;
      let didSecondEnvSweep = false;
      const pollQuiescence = () => {
        if (settled) return;
        if (!leasePipeClosed || (!didSecondEnvSweep && Date.now() + 740 < deadline)) {
          didSecondEnvSweep = true;
          killAllTracked("SIGKILL", { inspectEnvAndCwd: true });
        }
        const alive = anyTrackedAlive();
        if (!alive && stdioClosed && leasePipeClosed) {
          settled = true;
          cleanupListenersAndTimers();
          resolve({
            exitCode: timedOut ? 124 : exitInfo.code ?? (exitInfo.signal ? 128 + (os.constants.signals[exitInfo.signal] || 0) : 0),
            timedOut,
            quiescent: Boolean(enumerationComplete),
            enumerationAvailable: Boolean(enumerationComplete),
            ...capturedOutput(),
          });
          return;
        }
        if (Date.now() >= deadline) {
          killAllTracked("SIGKILL", { inspectEnvAndCwd: true });
          const stillAlive = anyTrackedAlive();
          const pipesClosedCleanly = Boolean(stdioClosed && leasePipeClosed);
          try {
            child.stdout.destroy();
            child.stderr.destroy();
            child.stdio?.[4]?.destroy();
          } catch {
            // ignore
          }
          settled = true;
          cleanupListenersAndTimers();
          resolve({
            exitCode: timedOut ? 124 : exitInfo.code ?? (exitInfo.signal ? 128 + (os.constants.signals[exitInfo.signal] || 0) : 0),
            timedOut,
            quiescent: Boolean(enumerationComplete && !stillAlive && pipesClosedCleanly),
            enumerationAvailable: Boolean(enumerationComplete),
            ...capturedOutput(),
          });
          return;
        }
        setTimeout(pollQuiescence, 15);
      };

      pollQuiescence();
    });
  });
}

/**
 * High-level `blast-guard wrap --mode <isolated|checkpoint> -- <cmd...>` entrypoint.
 */
export async function executeWrappedCommand(
  workspaceRoot,
  cmdArgs,
  {
    mode = "checkpoint",
    checkOnly = false,
    sessionId = "default",
    promoteMode = "staged",
    assumeSingleWriter = false,
    ownedWorktree = false,
    denyNetwork = false,
    timeoutMs = 120000,
    storeDir = null,
  } = {}
) {
  if (checkOnly && (mode !== "isolated" || promoteMode !== "staged")) throw new Error("--check-only requires isolated mode and cannot promote generated files.");
  const store = new SnapshotStore(workspaceRoot, storeDir ? { storeDir } : {});
  await store.open();
  try {
    if (mode === "isolated") {
      return await store.runIsolatedCommand(cmdArgs, {
        sessionId,
        promoteMode,
        discardChanges: checkOnly,
        assumeSingleWriter,
        ownedWorktree,
        denyNetwork,
        timeoutMs,
      });
    }

    // Mode B: checkpoint-recovery (under Assumed Single-Writer Precondition)
    const tx = store.beginCommandTransaction({ sessionId, toolUseId: `wrap-${Date.now()}` });
    const execRes = await spawnAndReapProcessGroup(cmdArgs[0], cmdArgs.slice(1), {
      cwd: store.canonicalRoot,
      env: process.env,
      timeoutMs,
      outputDir: path.join(store.storeDir, "outputs"),
    });

    // : If background writer escaped process group and held pipes open (`!execRes.quiescent`),
    // roll back workspace to `commandCheckpoint` AND transition journal to `'RECOVERY_FAILED'` so future mutations remain blocked!
    if (!execRes.quiescent) {
      const commandCp = store.loadCheckpoint(tx.commandCheckpointId);
      store.executeCrashSafeRollback(tx.txId, commandCp);
      store.withImmediateTransaction(() => {
        store.db
          .prepare(
            `UPDATE journals SET state = 'RECOVERY_FAILED', error_code = ?, error_detail = ?, updated_at = ? WHERE tx_id = ?`
          )
          .run(
            "DESCENDANT_PROCESS_NOT_QUIESCENT",
            "Command spawned a detached writer that did not reach quiescence; workspace locked fail-closed.",
            Date.now(),
            tx.txId
          );
      });
      return {
        ok: false,
        mode: "checkpoint",
        code: "DESCENDANT_PROCESS_NOT_QUIESCENT",
        exitCode: 126,
        stdout: execRes.stdout,
        stderr: execRes.stderr,
        outputArtifacts: execRes.outputArtifacts,
        rolledBack: false,
        recoveryFailed: true,
        violations: [
          {
            code: "DESCENDANT_PROCESS_NOT_QUIESCENT",
            path: "<process-group>",
            message: "Detached descendant writer remained active after command exit; journal retained fail-closed.",
          },
        ],
        diagnostic:
          "[BlastGuard DESCENDANT_PROCESS_NOT_QUIESCENT] Detached child writer did not terminate cleanly; run `blast-guard rollback --recover` after ensuring background processes have exited.",
      };
    }

    const commandFailed = execRes.exitCode !== 0 || execRes.timedOut;
    const rec = store.reconcileCommandTransaction(tx.txId, {
      forceRollbackOnAnyMutation: commandFailed,
    });
    return {
      ok: rec.ok,
      mode: "checkpoint",
      code: rec.ok ? "CLEAN" : rec.violations?.[0]?.code || rec.recoveryCode || "POLICY_VIOLATION",
      exitCode: rec.ok || (commandFailed && !rec.recoveryFailed) ? execRes.exitCode : 126,
      stdout: execRes.stdout,
      stderr: execRes.stderr,
      outputArtifacts: execRes.outputArtifacts,
      rolledBack: rec.rolledBack,
      workspaceRestored: Boolean(rec.workspaceRestored),
      recoveryFailed: Boolean(rec.recoveryFailed),
      recoveryCode: rec.recoveryCode || null,
      restoredCount: rec.restoredCount || 0,
      removedCount: rec.removedCount || 0,
      changedFiles: rec.changedFiles || [],
      violations: rec.violations || [],
      diagnostic: rec.ok ? null : store.computeViolationDiagnostic(rec.violations, sessionId),
    };
  } catch (err) {
    const code = err?.code || "PREFLIGHT_FAILED";
    return {
      ok: false,
      mode,
      code,
      reason: err?.message || String(err),
      exitCode: 125,
      stdout: "",
      stderr: "",
      rolledBack: false,
      workspaceRestored: false,
      recoveryFailed: false,
      recoveryCode: null,
      restoredCount: 0,
      removedCount: 0,
      changedFiles: [],
      violations: [{ code, path: "<workspace>", message: err?.message || String(err) }],
      diagnostic: `[BlastGuard ${code}] ${err?.message || String(err)}`,
    };
  } finally {
    store.close();
  }
}
