import fs from "node:fs";
import { createHash } from "node:crypto";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import {
  BLAST_GUARD_BIN_PATH,
  parseSemverTuple,
  isVersionInBoundedRange,
  compareSemver,
  streamSha256File,
  resolveStateBaseDir,
} from "./runtime-support.mjs";
import {
  canonicalizeWorkspaceRoot,
  inspectWorkspacePath,
  isWorkspaceCaseInsensitive,
  toPosixRel,
} from "./path-security.mjs";
import {
  MINIMAL_CHANGE_ANCHOR,
  TIER_BUDGETS,
  formatVoiEscalationGuidance,
} from "./intent-and-budget.mjs";
import { evaluateCandidateWriteSet } from "./conservation-engine.mjs";
import { SnapshotStore } from "./snapshot-store.mjs";
import { recordHostStartupObservation } from "./hook-observation.mjs";
import { verifyTaskAtStop, readTaskVerification, formatTaskVerification, recordPromptAcceptanceConditions } from "./task-verification.mjs";
import { describeShellMode, formatSnapshotCoverage, snapshotSummary } from "./readiness.mjs";

export const BOUNDED_HOST_RANGES = Object.freeze({
  claude: { min: [2, 1, 295], maxExclusive: [2, 3, 0], label: "2.1.295 .. 2.2.x" },
  codex: { min: [0, 160, 0], maxExclusive: [0, 168, 0], label: "0.160.0 .. 0.167.x" },
  cursor: { min: [0, 48, 0], maxExclusive: [0, 52, 0], label: "0.48.0 .. 0.51.x" },
  antigravity: { min: [2, 31, 2], maxExclusive: [2, 32, 0], label: "2.31.2 .. 2.31.x (protocol-tested; host E2E pending)" },
  git: { min: [2, 30, 0], maxExclusive: [2, 51, 0], label: "2.30.0 .. 2.50.x" },
});

const CATASTROPHIC_SHELL_PATTERNS = [
  {
    re: /(?:^|[;&|()\s])rm\s+-[A-Za-z]*r[A-Za-z]*f[A-Za-z]*\s+(?:\/|~|\$HOME|\.\.?)(?:\s|$|;)/i,
    code: "CATASTROPHIC_SHELL_BLOCKED",
    reason: "Recursive rm targeting root, home, or workspace root is blocked.",
  },
  {
    re: /\bgit\s+(?:reset\s+--hard|clean\s+-[A-Za-z]*f|checkout\s+--\s+\.|restore\s+(?:--staged\s+--worktree\s+|\s*)\.)\b/i,
    code: "DESTRUCTIVE_GIT_WIPE_BLOCKED",
    reason: "Destructive Git working-tree wipe command is blocked to protect user uncommitted changes.",
  },
  {
    re: /\.blast-guard\b|BLAST_GUARD_STATE_DIR\b/i,
    code: "GUARD_STATE_TAMPER_BLOCKED",
    reason: "Shell commands targeting BlastGuard state directories or session markers are blocked.",
  },
];

function checkCatastrophicShellCommand(cmdString) {
  const s = String(cmdString || "");
  for (const pat of CATASTROPHIC_SHELL_PATTERNS) {
    if (pat.re.test(s)) {
      return { ok: false, code: pat.code, reason: pat.reason };
    }
  }
  return { ok: true };
}

const HOST_VERSION_MEMORY_CACHE = new Map();

function resolveBinaryOnPath(binName) {
  if (path.isAbsolute(binName) || binName.includes(path.sep)) {
    try {
      const st = fs.statSync(binName);
      if (st.isFile() && (st.mode & 0o111) !== 0) return binName;
    } catch {
      return null;
    }
    return null;
  }
  const pathEnv = process.env.PATH || "";
  for (const dir of pathEnv.split(path.delimiter)) {
    if (!dir) continue;
    const candidate = path.join(dir, binName);
    try {
      const st = fs.statSync(candidate);
      if (st.isFile() && (st.mode & 0o111) !== 0) return candidate;
    } catch {
      // continue scanning PATH
    }
  }
  return null;
}

/**
 * Detect installed host binary, realpath, SHA-256, and version tuple (``).
 * Uses stat-keyed (`realpath`, `dev`, `ino`, `mtimeMs`, `size`) caching so repeated
 * hook calls never pay repeated CLI startup cost while invalidating immediately on binary upgrades.
 */
export function detectInstalledHostBinaryVersion(
  host,
  { cacheDir = null, persistCache = true, binaryPath = null, useCache = true } = {}
) {
  const normHost = String(host || "").toLowerCase();
  const detectionSource = binaryPath ? "explicit-binary" : "path-candidate";
  if (normHost === "antigravity" && process.platform === "darwin") {
    const binary = "/Applications/Antigravity.app/Contents/MacOS/Antigravity";
    const plist = "/Applications/Antigravity.app/Contents/Info.plist";
    if (fs.existsSync(binary) && fs.existsSync(plist)) {
      const version = spawnSync("/usr/libexec/PlistBuddy", ["-c", "Print CFBundleShortVersionString", plist], { encoding: "utf8", timeout: 2500 });
      const rawVersion = version.status === 0 ? version.stdout.trim() : null;
      return { found: true, binary, binaryRealpath: fs.realpathSync.native(binary), binarySha256: streamSha256File(binary).sha256, rawVersion, tuple: parseSemverTuple(rawVersion || "") };
    }
  }
  const homeCodex = path.join(os.homedir(), ".local", "bin", "codex");
  const binCandidates = binaryPath
    ? [binaryPath]
    : normHost === "claude"
      ? ["claude"]
      : normHost === "codex"
        ? ["codex", homeCodex]
        : normHost === "cursor"
          ? ["cursor"]
          : normHost === "git"
            ? ["git"]
            : [];

  for (const cand of binCandidates) {
    const resolvedBin = resolveBinaryOnPath(cand);
    if (!resolvedBin) continue;

    let realBin = resolvedBin;
    let st = null;
    try {
      realBin = fs.realpathSync.native(resolvedBin);
      st = fs.statSync(realBin);
    } catch {
      continue;
    }

    const statKey = `${normHost}|${realBin}|${st.dev}:${st.ino}:${st.mtimeMs}:${st.size}`;
    if (useCache && HOST_VERSION_MEMORY_CACHE.has(statKey)) {
      return { ...HOST_VERSION_MEMORY_CACHE.get(statKey), detectionSource };
    }

    const effectiveCacheDir = cacheDir || resolveStateBaseDir();
    const diskCachePath = useCache && effectiveCacheDir ? path.join(effectiveCacheDir, "host-version-cache.json") : null;
    if (diskCachePath) {
      try {
        if (fs.existsSync(diskCachePath)) {
          const parsedCache = JSON.parse(fs.readFileSync(diskCachePath, "utf8"));
          const hit = parsedCache?.[statKey];
          if (hit && typeof hit.rawVersion === "string") {
            const info = {
              found: true,
              binary: resolvedBin,
              binaryRealpath: realBin,
              binarySha256: hit.binarySha256 || null,
              rawVersion: hit.rawVersion,
              tuple: parseSemverTuple(hit.rawVersion),
              detectionSource,
            };
            HOST_VERSION_MEMORY_CACHE.set(statKey, info);
            return info;
          }
        }
      } catch {
        // ignore corrupted cache and probe freshly
      }
    }

    const res = spawnSync(resolvedBin, ["--version"], { encoding: "utf8", timeout: 2500 });
    if (!res.error && res.status === 0 && (res.stdout || res.stderr)) {
      const raw = `${res.stdout || ""} ${res.stderr || ""}`.trim();
      const tuple = parseSemverTuple(raw);
      let binarySha256 = null;
      try {
        const hashed = streamSha256File(realBin, 64 * 1024 * 1024);
        if (!hashed.oversize) {
          binarySha256 = hashed.sha256;
        }
      } catch {
        binarySha256 = null;
      }
      const info = {
        found: true,
        binary: resolvedBin,
        binaryRealpath: realBin,
        binarySha256,
        rawVersion: raw,
        tuple,
        detectionSource,
      };
      HOST_VERSION_MEMORY_CACHE.set(statKey, info);
      if (diskCachePath && persistCache) {
        try {
          fs.mkdirSync(path.dirname(diskCachePath), { recursive: true });
          let prev = {};
          if (fs.existsSync(diskCachePath)) {
            try {
              prev = JSON.parse(fs.readFileSync(diskCachePath, "utf8")) || {};
            } catch {
              prev = {};
            }
          }
          prev[statKey] = { rawVersion: raw, binarySha256 };
          fs.writeFileSync(diskCachePath, JSON.stringify(prev, null, 2) + "\n", "utf8");
        } catch {
          // best-effort cache persistence
        }
      }
      return info;
    }
  }

  return {
    found: false,
    binary: null,
    binaryRealpath: null,
    binarySha256: null,
    rawVersion: null,
    tuple: null,
    detectionSource,
  };
}

const MAC_PROCESS_IDENTITY_SCRIPT = String.raw`
import ctypes
import json
import struct
import sys

pid = int(sys.argv[1])
if pid <= 1:
    raise ValueError("invalid ancestor pid")
lib = ctypes.CDLL("/usr/lib/libproc.dylib")
lib.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
lib.proc_pidpath.restype = ctypes.c_int
image = ctypes.create_string_buffer(4096)
if lib.proc_pidpath(pid, image, len(image)) <= 0:
    raise RuntimeError("kernel executable identity unavailable")
# sys/proc_info.h: PROC_PIDT_SHORTBSDINFO starts with uint32_t pbsi_pid, pbsi_ppid.
# Use libproc for both queries so startup does not need to execute the setuid ps helper.
lib.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
lib.proc_pidinfo.restype = ctypes.c_int
info = ctypes.create_string_buffer(256)
if lib.proc_pidinfo(pid, 13, 0, info, len(info)) < 8:
    raise RuntimeError("kernel parent identity unavailable")
observed_pid, parent_pid = struct.unpack_from("=II", info)
if observed_pid != pid:
    raise RuntimeError("kernel process identity changed")
print(json.dumps({"ppid": parent_pid, "executable": image.value.decode("utf-8")}))
`;

function inspectAncestorProcess(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 1) throw new Error("Invalid ancestor PID.");
  if (process.platform === "linux") {
    const stat = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
    const endName = stat.lastIndexOf(")");
    if (endName < 0) throw new Error("Malformed process stat.");
    const fields = stat.slice(endName + 2).trim().split(/\s+/);
    return { ppid: Number(fields[1]), executable: fs.readlinkSync(`/proc/${pid}/exe`) };
  }
  if (process.platform === "darwin") {
    const result = spawnSync("/usr/bin/python3", ["-I", "-S", "-c", MAC_PROCESS_IDENTITY_SCRIPT, String(pid)], {
      encoding: "utf8", timeout: 2000, maxBuffer: 32 * 1024,
    });
    if (result.error || result.status !== 0) throw new Error("Kernel process identity lookup failed.");
    return JSON.parse(result.stdout);
  }
  throw new Error("Running Codex identity detection requires macOS or Linux.");
}

/** Support the verified native Codex -> hook launch path; ambiguous intermediary processes fail closed. */
export function detectRunningCodexHostVersion({ cacheDir = null, _testProcessInspector = null } = {}) {
  const inspect = _testProcessInspector || inspectAncestorProcess;
  const pid = process.ppid;
  try {
    if (!Number.isSafeInteger(pid) || pid <= 1) throw new Error("Invalid process parent.");
    const record = inspect(pid);
    if (!record || !Number.isSafeInteger(record.ppid) || record.ppid < 1 || record.ppid === pid ||
        typeof record.executable !== "string" || !path.isAbsolute(record.executable)) {
      throw new Error("Incomplete process identity.");
    }
    // A known interpreter can itself host an older/scripted agent. No intermediary is assumed transparent.
    // Only the immediate kernel image is considered; ps comm/argv and outer Codex processes cannot authorize it.
    if (!/^codex(?:\.exe)?$/i.test(path.basename(record.executable))) {
      throw new Error("The direct hook parent is not a verifiable native Codex image.");
    }
    const image = fs.realpathSync.native(record.executable);
    const info = detectInstalledHostBinaryVersion("codex", {
      cacheDir, binaryPath: image, useCache: false, persistCache: false,
    });
    return { ...info, detectionSource: "running-parent", ancestorPid: pid };
  } catch {
    // Missing helpers, inaccessible/exited ancestors, and malformed records cannot justify PATH fallback.
  }
  return {
    found: false, binary: null, binaryRealpath: null, binarySha256: null,
    rawVersion: null, tuple: null, detectionSource: "running-ancestor",
  };
}

export function validateSuppliedHostVersion(normHost, rawVersionString) {
  const range = BOUNDED_HOST_RANGES[normHost];
  if (!range) {
    return {
      ok: false,
      code: "UNSUPPORTED_HOST",
      reason: `Unsupported host adapter '${normHost}'.`,
    };
  }
  if (!rawVersionString || typeof rawVersionString !== "string" || !rawVersionString.trim()) {
    return {
      ok: false,
      code: "UNTESTED_HOST_VERSION",
      reason: `Host '${normHost}' binary version could not be detected; failing closed outside bounded verified range (${range.label}).`,
    };
  }
  const tuple = parseSemverTuple(rawVersionString);
  if (tuple && compareSemver(tuple, range.maxExclusive) >= 0 && (process.env.NOSTRAY_ALLOW_NEWER_HOST === "1" || process.env.BLAST_GUARD_ALLOW_NEWER_HOST === "1")) return { ok: true, tuple, warning: "UNVERIFIED_NEWER_HOST_VERSION" };
  if (!tuple || !isVersionInBoundedRange(tuple, range.min, range.maxExclusive)) {
    return {
      ok: false,
      code: "UNTESTED_HOST_VERSION",
      reason: `Host '${normHost}' version '${rawVersionString}' is outside bounded verified range (${range.label}); failing closed. For newer versions, set NOSTRAY_ALLOW_NEWER_HOST=1 to proceed without verification.`,
    };
  }
  return { ok: true, tuple };
}

function extractHostCorrelationId(normHost, payload) {
  const candidates =
    normHost === "codex"
      ? [payload?.tool_use_id, payload?.call_id]
      : normHost === "cursor"
        ? [payload?.tool_use_id, payload?.call_id, payload?.invocation_id]
        : [payload?.tool_use_id];
  for (const c of candidates) {
    if (typeof c === "string" && c.trim().length > 0) {
      return c.trim();
    }
  }
  return null;
}

/**
 * Parse and simulate OpenAI Codex `apply_patch` envelope (`*** Begin Patch` ... `*** End Patch`) (``):
 * - Enforces exact `*** Begin Patch` / `*** End Patch` markers and rejects unknown directives/lines
 * - Maintains sequential in-memory overlay across repeated-path operations
 * - Enforces file-existence preconditions on `Add File`, `Delete File`, `Update File`, and `Move to`
 * - Honors `@@ <anchorHeader>` forward skip-ahead from `cursor` (NEVER wrapping back to line 0!)
 * - Honors `*** End of File` EOF hunk anchoring!
 */
export function simulateCodexApplyPatch(canonicalRoot, patchText, readCurrentFileFn) {
  const norm = String(patchText || "").replace(/\r\n/g, "\n");
  const rawLines = norm.split("\n");

  // Trim leading/trailing blank lines around envelope
  let startLine = 0;
  while (startLine < rawLines.length && rawLines[startLine].trim() === "") startLine++;
  let endLine = rawLines.length - 1;
  while (endLine >= startLine && rawLines[endLine].trim() === "") endLine--;

  // Match Codex `parse.rs` lenient heredoc stripping (`<<EOF ... EOF`, `<<'EOF' ... EOF`, `<<"EOF" ... EOF`)
  if (startLine < endLine) {
    const firstTrim = rawLines[startLine].trim();
    const heredocMatch = firstTrim.match(/^<<\s*(['"]?)([A-Za-z0-9_]+)\1$/);
    if (heredocMatch && rawLines[endLine].trim() === heredocMatch[2]) {
      startLine++;
      endLine--;
      while (startLine < rawLines.length && rawLines[startLine].trim() === "") startLine++;
      while (endLine >= startLine && rawLines[endLine].trim() === "") endLine--;
    }
  }

  if (
    startLine >= endLine ||
    rawLines[startLine].trim() !== "*** Begin Patch" ||
    rawLines[endLine].trim() !== "*** End Patch"
  ) {
    return {
      ok: false,
      code: "PATCH_UNPARSEABLE",
      path: "<apply_patch>",
      reason: "apply_patch payload must start with '*** Begin Patch' and end with '*** End Patch' (failing closed).",
    };
  }

  const lines = rawLines.slice(startLine + 1, endLine);
  // Map of canonical relPosix -> { rawPath, normKey, initialExists, initialText, currentExists, currentText }
  const overlay = new Map();
  const lookupKeyMap = new Map();
  const orderedKeys = [];
  const activeDirs = new Set();
  const unlinkedInitialNormPaths = new Set();
  const steps = [];
  const caseInsensitive = canonicalRoot ? isWorkspaceCaseInsensitive(canonicalRoot) : false;
  let opCount = 0;

  const markAncestorsAsActiveDirs = (normKey) => {
    const segs = normKey.split("/");
    for (let p = 1; p < segs.length; p++) {
      activeDirs.add(segs.slice(0, p).join("/"));
    }
  };

  const checkNamespaceForTarget = (normKey, rawPath) => {
    if (activeDirs.has(normKey)) {
      return {
        error: {
          code: "DIRECTORY_WRITE_TARGET_UNSUPPORTED",
          reason: `Target '${rawPath}' conflicts with an existing or created directory in patch namespace.`,
        },
      };
    }
    const segs = normKey.split("/");
    for (let p = 1; p < segs.length; p++) {
      const ancNorm = segs.slice(0, p).join("/");
      if (lookupKeyMap.has(ancNorm)) {
        const ancRec = overlay.get(lookupKeyMap.get(ancNorm));
        if (ancRec && ancRec.currentExists) {
          return {
            error: {
              code: "NOT_A_DIRECTORY_ANCESTOR",
              reason: `Intermediate path component '${ancRec.rawPath}' in '${rawPath}' is a regular file in patch namespace.`,
            },
          };
        }
      }
    }
    return { ok: true };
  };

  const validateRawPatchHeaderPath = (rawPath) => {
    const cleanRaw = rawPath.trim();
    if (!cleanRaw || cleanRaw.includes("\0")) {
      return {
        error: {
          code: "INVALID_PATH_COMPONENT",
          reason: "Empty or NUL-containing patch target path.",
        },
      };
    }
    if (cleanRaw.endsWith("/") || cleanRaw.endsWith("\\")) {
      return {
        error: {
          code: "DIRECTORY_WRITE_TARGET_UNSUPPORTED",
          reason: `Patch target '${cleanRaw}' ends with a directory separator.`,
        },
      };
    }
    const stripped = cleanRaw.startsWith("./") ? cleanRaw.slice(2) : cleanRaw;
    const rawSegs = stripped.split("/");
    for (const seg of rawSegs) {
      if (!seg || seg === "." || seg === "..") {
        return {
          error: {
            code: "INVALID_PATH_COMPONENT",
            reason: `Invalid or unnormalized path segment in '${cleanRaw}'.`,
          },
        };
      }
      if (Buffer.byteLength(seg, "utf8") > 255) {
        return {
          error: {
            code: "INVALID_PATH_COMPONENT",
            reason: `Path component in '${cleanRaw}' exceeds 255-byte filesystem limit.`,
          },
        };
      }
    }
    return { cleanRaw };
  };

  const ensureEntryState = (rawPath) => {
    const hdr = validateRawPatchHeaderPath(rawPath);
    if (hdr.error) return { error: hdr.error };
    const cleanRaw = hdr.cleanRaw;

    // Probe whether we already have an overlay record via fast lexical normalization ONLY if no new live check needed,
    // otherwise call `readCurrentFileFn` with `unlinkedRegularFileSet` so symlinks/hardlinks/ancestor files on live disk are verified!
    const live = readCurrentFileFn(cleanRaw, { unlinkedRegularFileSet: unlinkedInitialNormPaths });
    if (live && live.error) {
      return { error: live.error };
    }
    let canonicalKey =
      live && typeof live === "object" && typeof live.relPosix === "string" && live.relPosix
        ? live.relPosix
        : null;
    if (!canonicalKey && canonicalRoot) {
      const abs = path.resolve(canonicalRoot, cleanRaw);
      const rel = path.relative(canonicalRoot, abs);
      if (rel && rel !== ".." && !rel.startsWith(".." + path.sep) && !path.isAbsolute(rel)) {
        canonicalKey = rel.split(path.sep).join("/");
      }
    }
    if (!canonicalKey) canonicalKey = cleanRaw;

    const normKey = caseInsensitive ? canonicalKey.toLowerCase() : canonicalKey;
    const nsCheck = checkNamespaceForTarget(normKey, cleanRaw);
    if (nsCheck.error) {
      return { error: nsCheck.error };
    }

    if (lookupKeyMap.has(normKey)) {
      return overlay.get(lookupKeyMap.get(normKey));
    }
    const initialText = typeof live === "string" ? live : live?.text ?? null;
    const initialExists = initialText !== null;
    if (initialExists) {
      markAncestorsAsActiveDirs(normKey);
    }
    const rec = {
      rawPath: canonicalKey,
      normKey,
      initialExists,
      initialText,
      currentExists: initialExists,
      currentText: initialText,
    };
    lookupKeyMap.set(normKey, canonicalKey);
    overlay.set(canonicalKey, rec);
    orderedKeys.push(canonicalKey);
    return rec;
  };

  let i = 0;
  while (i < lines.length) {
    const line = lines[i];

    if (line.startsWith("*** Add File: ")) {
      const rawPath = line.slice("*** Add File: ".length).trim();
      const st = ensureEntryState(rawPath);
      if (!st || st.error) {
        return {
          ok: false,
          code: st?.error?.code || "INVALID_PATH_COMPONENT",
          path: rawPath || "<apply_patch>",
          reason: st?.error?.reason || "Invalid Add File target path.",
          steps,
          overlay,
        };
      }
      i++;
      const addedLines = [];
      while (i < lines.length && !lines[i].startsWith("*** ")) {
        if (!lines[i].startsWith("+")) {
          return {
            ok: false,
            code: "PATCH_UNPARSEABLE",
            path: rawPath,
            reason: `Invalid non-'+' line inside Add File hunk for '${rawPath}'.`,
            steps,
            overlay,
          };
        }
        addedLines.push(lines[i].slice(1));
        i++;
      }
      if (addedLines.length === 0) {
        return {
          ok: false,
          code: "PATCH_UNPARSEABLE",
          path: rawPath,
          reason: `Add File hunk for '${rawPath}' is empty.`,
          steps,
          overlay,
        };
      }
      const newText = addedLines.join("\n") + "\n";
      st.currentExists = true;
      st.currentText = newText;
      unlinkedInitialNormPaths.delete(st.normKey);
      markAncestorsAsActiveDirs(st.normKey);
      steps.push([
        {
          op: st.initialExists ? "modify" : "add",
          rawPath: st.rawPath,
          afterText: newText,
        },
      ]);
      opCount++;
      continue;
    }

    if (line.startsWith("*** Delete File: ")) {
      const rawPath = line.slice("*** Delete File: ".length).trim();
      const st = ensureEntryState(rawPath);
      if (!st || st.error) {
        return {
          ok: false,
          code: st?.error?.code || "INVALID_PATH_COMPONENT",
          path: rawPath || "<apply_patch>",
          reason: st?.error?.reason || "Invalid Delete File target path.",
          steps,
          overlay,
        };
      }
      if (!st.currentExists) {
        return {
          ok: false,
          code: "PATCH_TARGET_MISSING",
          path: rawPath,
          reason: `apply_patch Delete File target '${rawPath}' does not exist.`,
          steps,
          overlay,
        };
      }
      i++;
      if (i < lines.length && !lines[i].startsWith("*** ")) {
        return {
          ok: false,
          code: "PATCH_UNPARSEABLE",
          path: rawPath,
          reason: `Unexpected body lines after '*** Delete File: ${rawPath}'.`,
          steps,
          overlay,
        };
      }
      st.currentExists = false;
      st.currentText = null;
      if (st.initialExists) {
        unlinkedInitialNormPaths.add(st.normKey);
      }
      steps.push([
        {
          op: "delete",
          rawPath: st.rawPath,
          afterText: null,
        },
      ]);
      opCount++;
      continue;
    }

    if (line.startsWith("*** Update File: ")) {
      const rawPath = line.slice("*** Update File: ".length).trim();
      const st = ensureEntryState(rawPath);
      if (!st || st.error) {
        return {
          ok: false,
          code: st?.error?.code || "INVALID_PATH_COMPONENT",
          path: rawPath || "<apply_patch>",
          reason: st?.error?.reason || "Invalid Update File target path.",
          steps,
          overlay,
        };
      }
      if (!st.currentExists || st.currentText === null) {
        return {
          ok: false,
          code: "PATCH_TARGET_MISSING",
          path: rawPath,
          reason: `apply_patch Update File target '${rawPath}' does not exist.`,
          steps,
          overlay,
        };
      }

      i++;
      let moveToPath = null;
      if (i < lines.length && lines[i].startsWith("*** Move to: ")) {
        moveToPath = lines[i].slice("*** Move to: ".length).trim();
        i++;
      }

      const hunks = [];
      let curHunk = null;
      while (i < lines.length) {
        const hl = lines[i];
        if (hl === "*** End of File") {
          if (!curHunk || curHunk.lines.length === 0) {
            return {
              ok: false,
              code: "PATCH_UNPARSEABLE",
              path: rawPath,
              reason: "Unexpected '*** End of File' without non-empty active hunk.",
              steps,
              overlay,
            };
          }
          curHunk.eofAnchored = true;
          hunks.push(curHunk);
          curHunk = null;
          i++;
          continue;
        }
        if (hl.startsWith("*** ")) {
          break;
        }
        if (hl.startsWith("@@")) {
          if (curHunk) {
            if (curHunk.lines.length === 0) {
              return {
                ok: false,
                code: "PATCH_UNPARSEABLE",
                path: rawPath,
                reason: `Empty update hunk inside '${rawPath}'.`,
                steps,
                overlay,
              };
            }
            hunks.push(curHunk);
          }
          curHunk = {
            anchorHeader: hl.slice(2).trim(),
            lines: [],
            eofAnchored: false,
          };
          i++;
          continue;
        }
        if (hl === "") {
          if (!curHunk) {
            curHunk = { anchorHeader: "", lines: [], eofAnchored: false };
          }
          curHunk.lines.push(" ");
          i++;
          continue;
        }
        if (hl.startsWith(" ") || hl.startsWith("+") || hl.startsWith("-")) {
          if (!curHunk) {
            curHunk = { anchorHeader: "", lines: [], eofAnchored: false };
          }
          curHunk.lines.push(hl);
          i++;
          continue;
        }
        return {
          ok: false,
          code: "PATCH_UNPARSEABLE",
          path: rawPath,
          reason: `Unrecognized line inside Update File hunk for '${rawPath}': '${hl.slice(0, 60)}'`,
          steps,
          overlay,
        };
      }
      if (curHunk) {
        if (curHunk.lines.length === 0) {
          return {
            ok: false,
            code: "PATCH_UNPARSEABLE",
            path: rawPath,
            reason: `Empty update hunk inside '${rawPath}'.`,
            steps,
            overlay,
          };
        }
        hunks.push(curHunk);
      }

      if (hunks.length === 0) {
        return {
          ok: false,
          code: "PATCH_UNPARSEABLE",
          path: rawPath,
          reason: `Update File hunk for '${rawPath}' is empty.`,
          steps,
          overlay,
        };
      }

      const applied = applyContextHunksToText(st.currentText, hunks);
      if (!applied.ok) {
        return {
          ok: false,
          code: "PATCH_SIMULATION_FAILED",
          path: rawPath,
          reason: applied.reason,
          steps,
          overlay,
        };
      }

      if (moveToPath !== null) {
        const destSt = ensureEntryState(moveToPath);
        if (!destSt || destSt.error) {
          return {
            ok: false,
            code: destSt?.error?.code || "INVALID_PATH_COMPONENT",
            path: moveToPath || "<apply_patch>",
            reason: destSt?.error?.reason || "Invalid Move to destination path.",
            steps,
            overlay,
          };
        }
        // Matches Codex `lib.rs` exact order:
        // 1) `fs::create_dir_all` + `fs::write(dest, new_contents)`
        destSt.currentExists = true;
        destSt.currentText = applied.afterText;
        unlinkedInitialNormPaths.delete(destSt.normKey);
        markAncestorsAsActiveDirs(destSt.normKey);
        steps.push([
          {
            op: destSt.initialExists ? "modify" : "add",
            rawPath: destSt.rawPath,
            afterText: applied.afterText,
          },
        ]);

        // 2) `fs::remove_file(src)`
        st.currentExists = false;
        st.currentText = null;
        if (st.initialExists) {
          unlinkedInitialNormPaths.add(st.normKey);
        }
        steps.push([
          {
            op: "delete",
            rawPath: st.rawPath,
            afterText: null,
          },
        ]);
      } else {
        st.currentText = applied.afterText;
        steps.push([
          {
            op: st.initialExists ? "modify" : "add",
            rawPath: st.rawPath,
            afterText: applied.afterText,
          },
        ]);
      }
      opCount++;
      continue;
    }

    return {
      ok: false,
      code: "PATCH_UNPARSEABLE",
      path: "<apply_patch>",
      reason: `Unsupported apply_patch directive: '${line.slice(0, 60)}'`,
      steps,
      overlay,
    };
  }

  if (opCount === 0) {
    return {
      ok: false,
      code: "PATCH_UNPARSEABLE",
      path: "<apply_patch>",
      reason: "apply_patch envelope contained zero file operations.",
      steps,
      overlay,
    };
  }

  const changes = [];
  for (const key of orderedKeys) {
    const rec = overlay.get(key);
    if (!rec.initialExists && rec.currentExists) {
      changes.push({ op: "add", rawPath: rec.rawPath, afterText: rec.currentText });
    } else if (rec.initialExists && !rec.currentExists) {
      changes.push({ op: "delete", rawPath: rec.rawPath, afterText: null });
    } else if (rec.initialExists && rec.currentExists && rec.initialText !== rec.currentText) {
      changes.push({ op: "modify", rawPath: rec.rawPath, afterText: rec.currentText });
    }
  }

  if (changes.length === 0) {
    return {
      ok: false,
      code: "PATCH_NOOP_OR_EMPTY",
      path: "<apply_patch>",
      reason: "apply_patch resulted in zero net file changes.",
      steps,
      overlay,
    };
  }

  return { ok: true, changes, steps, overlay };
}

function normalizeCodexUnicodeLine(str) {
  return str
    .trim()
    .replace(/[\u2010-\u2015\u2212]/g, "-")
    .replace(/[\u2018-\u201B]/g, "'")
    .replace(/[\u201C-\u201F]/g, '"')
    .replace(/[\u00A0\u2002-\u200A\u202F\u205F\u3000]/g, " ");
}

function seekCodexLineSequence(srcLines, pattern, start, eofAnchored) {
  // Exact match to Codex `seek_sequence.rs`: `if pattern.is_empty() { return Some(start); }`!
  if (pattern.length === 0) {
    return start;
  }
  if (pattern.length > srcLines.length) return -1;

  const normalizers = [
    (s) => s,
    (s) => s.trimEnd(),
    (s) => s.trim(),
    normalizeCodexUnicodeLine,
  ];

  for (const normFn of normalizers) {
    if (eofAnchored) {
      const eofPos = srcLines.length - pattern.length;
      if (eofPos >= start) {
        let match = true;
        for (let k = 0; k < pattern.length; k++) {
          if (normFn(srcLines[eofPos + k]) !== normFn(pattern[k])) {
            match = false;
            break;
          }
        }
        if (match) return eofPos;
      }
    } else {
      for (let s = start; s <= srcLines.length - pattern.length; s++) {
        let match = true;
        for (let k = 0; k < pattern.length; k++) {
          if (normFn(srcLines[s + k]) !== normFn(pattern[k])) {
            match = false;
            break;
          }
        }
        if (match) return s;
      }
    }
  }
  return -1;
}

function applyContextHunksToText(originalText, hunks) {
  const firstNl = originalText.indexOf("\n");
  const eol = firstNl > 0 && originalText[firstNl - 1] === "\r" ? "\r\n" : "\n";

  const norm = originalText.replace(/\r\n/g, "\n");
  const srcLines = norm.length === 0 ? [] : norm.split("\n");
  if (srcLines.length > 0 && srcLines[srcLines.length - 1] === "") {
    srcLines.pop();
  }

  let cursor = 0;
  const replacements = [];

  for (const hunk of hunks) {
    // `@@ <anchorHeader>` forward skip-ahead (``): matches Codex `rust-v0.167.0` `line_index = idx + 1`!
    if (hunk.anchorHeader) {
      const anchorIdx = seekCodexLineSequence(srcLines, [hunk.anchorHeader], cursor, false);
      if (anchorIdx === -1) {
        return {
          ok: false,
          reason: `apply_patch hunk anchor '@@ ${hunk.anchorHeader}' not found at or after line ${cursor + 1}.`,
        };
      }
      cursor = anchorIdx + 1;
    }

    let oldChunk = [];
    let newChunk = [];
    for (const hl of hunk.lines) {
      const prefix = hl[0];
      const body = hl.slice(1);
      if (prefix === " ") {
        oldChunk.push(body);
        newChunk.push(body);
      } else if (prefix === "-") {
        oldChunk.push(body);
      } else if (prefix === "+") {
        newChunk.push(body);
      }
    }

    // Matches Codex `rust-v0.167.0` `file_update.rs`: chunks with initially empty `old_lines` insert at EOF (`original_lines.len()`)!
    if (oldChunk.length === 0) {
      replacements.push({
        startIdx: srcLines.length,
        oldLen: 0,
        newLines: newChunk,
      });
      continue;
    }

    let foundIdx = seekCodexLineSequence(srcLines, oldChunk, cursor, hunk.eofAnchored);

    // Trailing empty context fallback (`file_update.rs`): delegates to `seekCodexLineSequence`, which returns `cursor` (`start`) when `trimmedOld.length === 0`!
    if (foundIdx === -1 && oldChunk[oldChunk.length - 1] === "") {
      const trimmedOld = oldChunk.slice(0, -1);
      const trimmedNew =
        newChunk.length > 0 && newChunk[newChunk.length - 1] === ""
          ? newChunk.slice(0, -1)
          : newChunk;
      foundIdx = seekCodexLineSequence(srcLines, trimmedOld, cursor, hunk.eofAnchored);
      if (foundIdx !== -1) {
        oldChunk = trimmedOld;
        newChunk = trimmedNew;
      }
    }

    if (foundIdx === -1) {
      return {
        ok: false,
        reason: hunk.eofAnchored
          ? "apply_patch EOF-anchored hunk did not match end of file."
          : "apply_patch context hunk did not match file lines at or after current cursor.",
      };
    }

    replacements.push({
      startIdx: foundIdx,
      oldLen: oldChunk.length,
      newLines: newChunk,
    });
    cursor = foundIdx + oldChunk.length;
  }

  replacements.sort((a, b) => a.startIdx - b.startIdx);
  for (let r = replacements.length - 1; r >= 0; r--) {
    const rep = replacements[r];
    srcLines.splice(rep.startIdx, rep.oldLen, ...rep.newLines);
  }

  if (srcLines.length === 0) {
    return { ok: true, afterText: "" };
  }
  return {
    ok: true,
    afterText: srcLines.join(eol) + eol,
  };
}

/**
 * Simulate structured file tool (`Write`, `Edit`, `MultiEdit`, `NotebookEdit`, `apply_patch`, `write_file`, `edit_file`)
 * in memory BEFORE disk write (``, ``, ``):
 * - Uses `inspectWorkspacePath(..., { forWrite: true, checkPlatformAttrs: true })` so symlinks, hardlinks (`nlink > 1`),
 *   guard binary links, directories, xattrs, and ACLs are rejected!
 * - Rejects unsupported/semantic-sketch payloads (`{ target_file, instructions, code_edit }`) fail-closed (`UNSUPPORTED_EDIT_PAYLOAD`)!
 */
function buildStructuredToolCandidates(store, session, toolName, toolInput) {
  const taskCp = store.loadCheckpoint(session.taskBaselineId);

  const readLiveText = (absPath) => {
    try {
      const buf = fs.readFileSync(absPath);
      for (let i = 0; i < Math.min(buf.length, 4096); i++) {
        if (buf[i] === 0) return { isBinary: true, text: null };
      }
      return { isBinary: false, text: buf.toString("utf8") };
    } catch {
      return null;
    }
  };

  // 1. Codex `apply_patch`
  if (
    toolName === "apply_patch" ||
    typeof toolInput?.patch === "string" ||
    (typeof toolInput === "string" && toolInput.includes("*** Begin Patch"))
  ) {
    const rawPatch =
      typeof toolInput === "string"
        ? toolInput
        : typeof toolInput?.command === "string"
          ? toolInput.command
          : typeof toolInput?.patch === "string"
          ? toolInput.patch
          : typeof toolInput?.input === "string"
            ? toolInput.input
            : typeof toolInput?.cmd === "string"
              ? toolInput.cmd
              : "";

    const sim = simulateCodexApplyPatch(store.canonicalRoot, rawPatch, (rawP, ctx) => {
      const insp = inspectWorkspacePath(store.canonicalRoot, rawP, {
        forWrite: true,
        allowDirectoryLeaf: false,
        checkPlatformAttrs: true,
        exemptXattrs: store.exemptXattrs,
        unlinkedRegularFileSet: ctx?.unlinkedRegularFileSet || null,
      });
      if (!insp.ok) {
        return { error: { code: insp.code, reason: insp.reason } };
      }
      if (!insp.exists) {
        return { text: null, relPosix: insp.relPosix };
      }
      const live = readLiveText(insp.absPath);
      if (!live || live.isBinary) {
        return {
          error: {
            code: "BINARY_PATCH_UNSUPPORTED",
            reason: `Binary or unreadable target '${insp.relPosix}' cannot be patched via apply_patch.`,
          },
        };
      }
      return { text: live.text, relPosix: insp.relPosix };
    });

    const toCandidateFromOverlayItem = (item) => {
      const rec = sim.overlay ? sim.overlay.get(item.rawPath) : null;
      const relPosix = rec ? rec.rawPath : item.rawPath;
      const cmdBefore = rec && rec.initialExists ? rec.initialText : null;
      const taskEnt = taskCp.entries.get(relPosix);
      const taskBefore = taskEnt ? store.readBaselineTextFromEntry(taskEnt) : cmdBefore;
      return {
        relPosix,
        changeType: item.op,
        isDirectory: false,
        commandBeforeText: cmdBefore,
        taskBaselineText: taskBefore,
        afterText: item.afterText,
        isBinary: false,
      };
    };

    const stepCandidateGroups = Array.isArray(sim.steps)
      ? sim.steps.map((grp) => grp.map(toCandidateFromOverlayItem))
      : [];

    if (!sim.ok) {
      return {
        ok: false,
        stepCandidateGroups,
        violations: [{ code: sim.code, path: sim.path, message: sim.reason }],
      };
    }

    const candidates = sim.changes.map(toCandidateFromOverlayItem);
    return { ok: true, candidates, stepCandidateGroups };
  }

  if (!toolInput || typeof toolInput !== "object" || Array.isArray(toolInput)) {
    return {
      ok: false,
      violations: [
        {
          code: "UNSUPPORTED_EDIT_PAYLOAD",
          path: `<${toolName}>`,
          message: `Structured edit tool '${toolName}' payload must be a JSON object (failing closed).`,
        },
      ],
    };
  }

  const rawFilePath =
    toolInput.file_path ??
    toolInput.path ??
    toolInput.notebook_path ??
    toolInput.target_file ??
    null;

  if (typeof rawFilePath !== "string" || !rawFilePath.trim()) {
    return {
      ok: false,
      violations: [
        {
          code: "MISSING_TOOL_TARGET_PATH",
          path: `<${toolName}>`,
          message: `Structured edit tool '${toolName}' did not specify a valid target file path (failing closed).`,
        },
      ],
    };
  }

  const insp = inspectWorkspacePath(store.canonicalRoot, rawFilePath, {
    forWrite: true,
    allowDirectoryLeaf: false,
    checkPlatformAttrs: true,
    exemptXattrs: store.exemptXattrs,
  });
  if (!insp.ok) {
    return {
      ok: false,
      violations: [{ code: insp.code, path: rawFilePath, message: insp.reason }],
    };
  }

  // `NotebookEdit` -> explicitly unsupported in v0.1
  if (toolName === "NotebookEdit") {
    return {
      ok: false,
      violations: [
        {
          code: "UNSUPPORTED_NOTEBOOK_MUTATION",
          path: insp.relPosix,
          message: `NotebookEdit structural cell conservation is unsupported in v0.1; explicit file rewrite grant required.`,
        },
      ],
    };
  }

  // Reject semantic sketch / LLM-apply edit payloads (`{ target_file, instructions, code_edit }`) (``)!
  if (
    typeof toolInput.code_edit === "string" ||
    typeof toolInput.instructions === "string"
  ) {
    return {
      ok: false,
      violations: [
        {
          code: "UNSUPPORTED_EDIT_PAYLOAD",
          path: insp.relPosix,
          message: `Non-deterministic sketch edit payload ('code_edit'/'instructions') on '${insp.relPosix}' cannot be verified pre-write; use exact Edit/Write/apply_patch.`,
        },
      ],
    };
  }

  const liveObj = insp.exists && insp.entryType === "file" ? readLiveText(insp.absPath) : null;
  const cmdBefore = liveObj && !liveObj.isBinary ? liveObj.text : null;
  const taskEnt = taskCp.entries.get(insp.relPosix);
  const taskBefore = taskEnt ? store.readBaselineTextFromEntry(taskEnt) : cmdBefore;

  if (Array.isArray(toolInput.antigravityChunks)) {
    if (cmdBefore === null || toolInput.antigravityChunks.length === 0) {
      return { ok: false, violations: [{ code: "UNSUPPORTED_EDIT_PAYLOAD", path: insp.relPosix, message: "Antigravity replacement requires an existing text file and non-empty chunks." }] };
    }
    const lines = cmdBefore.match(/[^\n]*\n|[^\n]+$/g) || [];
    const replacements = [];
    for (const chunk of toolInput.antigravityChunks) {
      const start = chunk.StartLine;
      const end = chunk.EndLine;
      if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 1 || end < start || end > lines.length || typeof chunk.TargetContent !== "string" || !chunk.TargetContent || typeof chunk.ReplacementContent !== "string") {
        return { ok: false, violations: [{ code: "UNSUPPORTED_EDIT_PAYLOAD", path: insp.relPosix, message: "Invalid Antigravity replacement range or literal content." }] };
      }
      const segment = lines.slice(start - 1, end).join("");
      const normalizedSegment = segment.replace(/\r\n/g, "\n");
      const target = chunk.TargetContent.replace(/\r\n/g, "\n");
      const count = normalizedSegment.split(target).length - 1;
      if (count === 0 || (count > 1 && !chunk.AllowMultiple)) {
        return { ok: false, violations: [{ code: "AMBIGUOUS_EDIT_TARGET", path: insp.relPosix, message: "Antigravity replacement target absent or ambiguous within requested line range." }] };
      }
      const newline = cmdBefore.includes("\r\n") ? "\r\n" : "\n";
      const replacement = chunk.ReplacementContent.replace(/\r\n/g, "\n");
      const afterSegment = chunk.AllowMultiple ? normalizedSegment.split(target).join(replacement) : normalizedSegment.replace(target, () => replacement);
      replacements.push({ start, end, text: afterSegment.replace(/\n/g, newline) });
    }
    replacements.sort((a, b) => a.start - b.start);
    if (replacements.some((r, i) => i > 0 && replacements[i - 1].end >= r.start)) {
      return { ok: false, violations: [{ code: "UNSUPPORTED_EDIT_PAYLOAD", path: insp.relPosix, message: "Overlapping Antigravity replacement ranges are unsupported." }] };
    }
    let afterText = cmdBefore;
    for (const replacement of replacements.reverse()) {
      const startOffset = lines.slice(0, replacement.start - 1).join("").length;
      const endOffset = lines.slice(0, replacement.end).join("").length;
      afterText = afterText.slice(0, startOffset) + replacement.text + afterText.slice(endOffset);
    }
    return { ok: true, candidates: [{ relPosix: insp.relPosix, changeType: "modify", isDirectory: false, commandBeforeText: cmdBefore, taskBaselineText: taskBefore, afterText, isBinary: false }] };
  }

  // `Write` / `write_file` (exact full-file content required)
  if ((toolName === "Write" || toolName === "write_file") && typeof toolInput.content === "string") {
    return {
      ok: true,
      candidates: [
        {
          relPosix: insp.relPosix,
          changeType: insp.exists ? "modify" : "add",
          isDirectory: false,
          commandBeforeText: cmdBefore,
          taskBaselineText: taskBefore,
          afterText: toolInput.content,
          isBinary: Boolean(liveObj?.isBinary),
        },
      ],
    };
  }

  // `Edit` / exact `old_string` -> `new_string` replacement
  if (
    (toolName === "Edit" || toolName === "edit_file") &&
    typeof toolInput.old_string === "string" &&
    typeof toolInput.new_string === "string"
  ) {
    if (toolInput.old_string.length === 0) {
      return {
        ok: false,
        violations: [
          {
            code: "UNSUPPORTED_EDIT_PAYLOAD",
            path: insp.relPosix,
            message: `Edit 'old_string' cannot be empty on '${insp.relPosix}'.`,
          },
        ],
      };
    }
    if (!insp.exists || cmdBefore === null || liveObj?.isBinary) {
      return {
        ok: false,
        violations: [
          {
            code: "EDIT_TARGET_MISSING",
            path: insp.relPosix,
            message: `Edit target '${insp.relPosix}' does not exist or is binary.`,
          },
        ],
      };
    }
    const replaceAll = Boolean(toolInput.replace_all);
    const occurrences = cmdBefore.split(toolInput.old_string).length - 1;
    if (occurrences === 0) {
      return {
        ok: false,
        violations: [
          {
            code: "EDIT_STRING_NOT_FOUND",
            path: insp.relPosix,
            message: `Edit old_string was not found in '${insp.relPosix}'.`,
          },
        ],
      };
    }
    if (!replaceAll && occurrences > 1) {
      return {
        ok: false,
        violations: [
          {
            code: "AMBIGUOUS_EDIT_MATCH",
            path: insp.relPosix,
            message: `Edit old_string matched ${occurrences} locations in '${insp.relPosix}' without replace_all=true; failing closed.`,
          },
        ],
      };
    }
    const afterText = replaceAll
      ? cmdBefore.split(toolInput.old_string).join(toolInput.new_string)
      : cmdBefore.replace(toolInput.old_string, () => toolInput.new_string);

    return {
      ok: true,
      candidates: [
        {
          relPosix: insp.relPosix,
          changeType: "modify",
          isDirectory: false,
          commandBeforeText: cmdBefore,
          taskBaselineText: taskBefore,
          afterText,
          isBinary: false,
        },
      ],
    };
  }

  // `MultiEdit`
  if (toolName === "MultiEdit" && Array.isArray(toolInput.edits) && toolInput.edits.length > 0) {
    if (!insp.exists || cmdBefore === null || liveObj?.isBinary) {
      return {
        ok: false,
        violations: [
          {
            code: "EDIT_TARGET_MISSING",
            path: insp.relPosix,
            message: `MultiEdit target '${insp.relPosix}' does not exist or is binary.`,
          },
        ],
      };
    }
    let working = cmdBefore;
    for (const ed of toolInput.edits) {
      if (
        typeof ed?.old_string !== "string" ||
        ed.old_string.length === 0 ||
        typeof ed?.new_string !== "string"
      ) {
        return {
          ok: false,
          violations: [
            {
              code: "MULTIEDIT_HUNK_INVALID",
              path: insp.relPosix,
              message: `MultiEdit hunk has missing or empty old_string/new_string on '${insp.relPosix}'.`,
            },
          ],
        };
      }
      const occ = working.split(ed.old_string).length - 1;
      if (occ === 0 || (!ed.replace_all && occ > 1)) {
        return {
          ok: false,
          violations: [
            {
              code: "MULTIEDIT_HUNK_INVALID",
              path: insp.relPosix,
              message: `MultiEdit hunk failed exact simulation on '${insp.relPosix}' (occurrences=${occ}).`,
            },
          ],
        };
      }
      working = ed.replace_all
        ? working.split(ed.old_string).join(ed.new_string)
        : working.replace(ed.old_string, () => ed.new_string);
    }
    return {
      ok: true,
      candidates: [
        {
          relPosix: insp.relPosix,
          changeType: "modify",
          isDirectory: false,
          commandBeforeText: cmdBefore,
          taskBaselineText: taskBefore,
          afterText: working,
          isBinary: false,
        },
      ],
    };
  }

  // Fail closed on ANY unrecognized structured edit schema (``) — NEVER return `candidates: []`!
  return {
    ok: false,
    violations: [
      {
        code: "UNSUPPORTED_EDIT_PAYLOAD",
        path: insp.relPosix,
        message: `Structured edit tool '${toolName}' payload format is unsupported in v0.1; failing closed.`,
      },
    ],
  };
}

function formatHostWireResponse(host, eventName, decisionPayload) {
  const normHost = String(host || "claude").toLowerCase();

  if (normHost === "antigravity") {
    const blocked = decisionPayload.action === "deny" || decisionPayload.action === "block";
    if (eventName === "UserPromptSubmit") {
      return { exitCode: 0, stdoutObj: blocked
        ? { terminationBehavior: "terminate", injectSteps: [{ errorMessage: { userMessage: decisionPayload.reason } }] }
        : { injectSteps: [{ ephemeralMessage: decisionPayload.additionalContext || MINIMAL_CHANGE_ANCHOR }] } };
    }
    if (eventName === "PreToolUse") {
      return { exitCode: 0, stdoutObj: { decision: blocked ? "deny" : "allow", ...(blocked ? { reason: decisionPayload.reason } : {}) } };
    }
    if (eventName === "Stop") {
      return { exitCode: 0, stdoutObj: { decision: blocked ? "continue" : "allow", ...(blocked ? { reason: decisionPayload.reason } : {}) } };
    }
    // PostToolUse has no blocking response schema. Recovery completes before this response.
    return { exitCode: blocked ? 2 : 0, stdoutObj: {}, ...(blocked ? { diagnostic: decisionPayload.reason } : {}) };
  }
  if (normHost === "cursor") {
    if (eventName === "beforeSubmitPrompt") {
      const blocked = decisionPayload.action === "block" || decisionPayload.action === "deny";
      return {
        exitCode: 0,
        stdoutObj: {
          continue: !blocked,
          ...(decisionPayload.systemMessage || blocked
            ? { user_message: decisionPayload.systemMessage || decisionPayload.reason }
            : {}),
        },
      };
    }
    if (eventName === "preToolUse" || eventName === "PreToolUse") {
      if (decisionPayload.action === "deny") {
        return {
          exitCode: 0,
          stdoutObj: {
            permission: "deny",
            agent_message: decisionPayload.reason,
            user_message: decisionPayload.reason,
          },
        };
      }
      return {
        exitCode: 0,
        stdoutObj: { permission: "allow" },
      };
    }
    if (decisionPayload.action === "block") {
      return {
        exitCode: 0,
        stdoutObj: {
          decision: "block",
          reason: decisionPayload.reason,
        },
      };
    }
    return { exitCode: 0, stdoutObj: {} };
  }

  if (eventName === "UserPromptSubmit" || eventName === "beforeSubmitPrompt") {
    if (decisionPayload.action === "block") {
      return {
        exitCode: 0,
        stdoutObj: {
          decision: "block",
          reason: decisionPayload.reason,
        },
      };
    }
    return {
      exitCode: 0,
      stdoutObj: {
        ...(decisionPayload.systemMessage ? { systemMessage: decisionPayload.systemMessage } : {}),
        hookSpecificOutput: {
          hookEventName: "UserPromptSubmit",
          additionalContext: decisionPayload.additionalContext || MINIMAL_CHANGE_ANCHOR,
        },
      },
    };
  }

  if (eventName === "PreToolUse" || eventName === "preToolUse") {
    if (decisionPayload.action === "deny") {
      return {
        exitCode: 0,
        stdoutObj: {
          hookSpecificOutput: {
            hookEventName: "PreToolUse",
            permissionDecision: "deny",
            permissionDecisionReason: decisionPayload.reason,
          },
        },
      };
    }
    return { exitCode: 0, stdoutObj: null };
  }

  if (
    eventName === "PostToolUse" ||
    eventName === "PostToolUseFailure" ||
    eventName === "postToolUse" ||
    eventName === "postToolUseFailure" ||
    eventName === "Stop" ||
    eventName === "stop"
  ) {
    if (decisionPayload.action === "block") {
      return {
        exitCode: 0,
        stdoutObj: {
          decision: "block",
          reason: decisionPayload.reason,
        },
      };
    }
    return { exitCode: 0, stdoutObj: null };
  }

  return { exitCode: 0, stdoutObj: null };
}

// Strictly non-mutating read tools ONLY (`Task` & `TodoWrite` excluded per ``!)
const READ_ONLY_TOOLS = new Set([
  "Read",
  "Glob",
  "Grep",
  "LS",
  "WebFetch",
  "WebSearch",
  "TodoRead",
  "read_file",
  "grep_search",
  "find_by_name",
]);

const SHELL_TOOLS = new Set([
  "Bash",
  "bash",
  "shell",
  "exec_command",
  "run_terminal_cmd",
  "Shell",
]);

const STRUCTURED_WRITE_TOOLS = new Set([
  "Write",
  "Edit",
  "MultiEdit",
  "NotebookEdit",
  "apply_patch",
  "write_file",
  "edit_file",
]);

/**
 * Process a single host hook event deterministically (``, ``, ``, ``, ``).
 */
export async function handleHostHookEvent({
  host = "claude",
  event = null,
  rawStdin = "",
  workspaceRoot = process.cwd(),
  storeDir = null,
  _testHostVersionOverride = null,
  wrapShell = false,
}) {
  const normHost = String(host || "claude").toLowerCase();
  let payload;
  try {
    payload = rawStdin && rawStdin.trim() ? JSON.parse(rawStdin) : null;
  } catch {
    payload = null;
  }

  let effectiveEvent = event || payload?.hook_event_name || payload?.event || "PreToolUse";
  if (normHost === "antigravity" && payload && typeof payload === "object") {
    if (effectiveEvent === "PreInvocation") effectiveEvent = "UserPromptSubmit";
    if (effectiveEvent === "PostToolUse" && payload.error) effectiveEvent = "PostToolUseFailure";
    if (typeof payload.conversationId !== "string" || !payload.conversationId || !Array.isArray(payload.workspacePaths) || payload.workspacePaths.length !== 1 || typeof payload.workspacePaths[0] !== "string") {
      return formatHostWireResponse(normHost, effectiveEvent, { action: "deny", reason: "[BlastGuard INVALID_HOOK_PAYLOAD] Antigravity requires a conversationId and exactly one guarded workspace." });
    }
    const args = payload.toolCall?.args || {};
    const nativeTool = payload.toolCall?.name || "";
    const tools = { edit_file: "Edit", read_file: "Read", write_to_file: "Write", replace_file_content: "Edit", multi_replace_file_content: "MultiEdit", run_command: "Bash", view_file: "Read", list_dir: "LS", search_web: "WebSearch", read_url_content: "WebFetch" };
    payload = {
      ...payload,
      cwd: Array.isArray(payload.workspacePaths) ? payload.workspacePaths[0] : undefined,
      session_id: payload.conversationId,
      tool_use_id: Number.isSafeInteger(payload.stepIdx) && payload.stepIdx >= 0 ? `antigravity:${payload.conversationId}:${payload.stepIdx}` : null,
      prompt: payload.lastUserInput,
      tool_name: tools[nativeTool] || nativeTool,
      tool_input: nativeTool === "edit_file" ? { file_path: args.Path, old_string: args.Target, new_string: args.Replacement, replace_all: Boolean(args.AllowMultiple) }
        : nativeTool === "write_to_file" ? { file_path: args.TargetFile, content: args.CodeContent }
        : nativeTool === "replace_file_content" || nativeTool === "multi_replace_file_content" ? { file_path: args.TargetFile, antigravityChunks: args.ReplacementChunks || [args] }
        : nativeTool === "run_command" ? { command: args.CommandLine, nativeAntigravityShell: true, cwd: args.Cwd, persistent: args.RunPersistent }
        : args,
    };
  }
  const failAction = effectiveEvent === "PreToolUse" || effectiveEvent === "preToolUse" ? "deny" : "block";

  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return formatHostWireResponse(normHost, effectiveEvent, {
      action: failAction,
      reason: "[BlastGuard INVALID_HOOK_PAYLOAD] Malformed or empty JSON hook stdin; failing closed.",
    });
  }

  // Enforce bounded host version check strictly against installed host binary (``).
  // Payload/env version strings are NEVER trusted; `_testHostVersionOverride` is internal JS test-harness only.
  const hostIdentity = _testHostVersionOverride === null
    ? (normHost === "codex"
      ? detectRunningCodexHostVersion({ cacheDir: storeDir })
      : detectInstalledHostBinaryVersion(normHost, { cacheDir: storeDir }))
    : null;
  const effectiveHostVersion = _testHostVersionOverride ?? hostIdentity?.rawVersion;

  const verCheck = validateSuppliedHostVersion(normHost, effectiveHostVersion);
  if (!verCheck.ok) {
    return formatHostWireResponse(normHost, effectiveEvent, {
      action: failAction,
      reason: `[BlastGuard ${verCheck.code}] ${verCheck.reason}`,
    });
  }

  const cwd = payload.cwd ? path.resolve(payload.cwd) : workspaceRoot;
  const sessionId = String(payload.session_id || payload.conversation_id || "default");
  const toolName = String(payload.tool_name || payload.tool || "");
  const toolInput = payload.tool_input ?? payload.input ?? {};
  const correlationId = extractHostCorrelationId(normHost, payload);

  let store;
  try {
    store = new SnapshotStore(cwd, storeDir ? { storeDir } : {});
  } catch (err) {
    return formatHostWireResponse(normHost, effectiveEvent, {
      action: failAction,
      reason: `[BlastGuard ${err.code || "STATE_INIT_ERROR"}] ${err.message}`,
    });
  }

  try {
    // 1. UserPromptSubmit / beforeSubmitPrompt — ONLY explicit prompt-initialization entry may initialize state (``)
    if (effectiveEvent === "UserPromptSubmit" || effectiveEvent === "beforeSubmitPrompt") {
      await store.open({ allowInitialize: true });
      const rawPrompt = String(payload.prompt ?? payload.user_prompt ?? "");
      const isSynthetic = Boolean(payload.is_synthetic || payload.isSynthetic);
      const promptKey = `antigravity-prompt:${createHash("sha256").update(sessionId).digest("hex")}`;
      const snapshotKey = `${promptKey}:snapshot`;
      const promptHash = createHash("sha256").update(rawPrompt).digest("hex");
      const existingSession = store.loadSession(sessionId);
      const repeatedAntigravityPrompt = normHost === "antigravity" && existingSession &&
        store.db.prepare("SELECT value FROM meta WHERE key = ?").get(promptKey)?.value === promptHash;
      let startupSnapshot;
      if (repeatedAntigravityPrompt) {
        const savedSummary = store.db.prepare("SELECT value FROM meta WHERE key = ?").get(snapshotKey)?.value;
        startupSnapshot = savedSummary
          ? JSON.parse(savedSummary)
          : store.loadCheckpoint(existingSession.turnCheckpointId);
      } else {
        startupSnapshot = store.startOrUpdateTurn(rawPrompt, { sessionId, isSynthetic });
        store.writeSessionMarker(sessionId);
        recordPromptAcceptanceConditions(store, sessionId, rawPrompt, { isSynthetic });
        if (normHost === "antigravity") {
          store.withImmediateTransaction(() => {
            const upsert = store.db.prepare("INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value");
            upsert.run(promptKey, promptHash);
            upsert.run(snapshotKey, JSON.stringify(snapshotSummary(startupSnapshot)));
          });
        }
      }
      const shell = describeShellMode(normHost, { wrapShell, configured: true });
      const startupEvent = event || payload.hook_event_name || payload.event || effectiveEvent;
      let observation = null;
      let observationError = null;
      try {
        observation = recordHostStartupObservation(store, {
          host: normHost, event: startupEvent,
          sessionId, hostVersion: effectiveHostVersion, hostIdentity, snapshot: startupSnapshot, shell,
          isSynthetic, versionOverrideUsed: _testHostVersionOverride !== null,
        });
      } catch (error) {
        observationError = `启动事件回执未保存（${error.code || "OBSERVATION_WRITE_FAILED"}）。`;
      }
      const startupOrigin = isSynthetic || _testHostVersionOverride !== null
        ? `${normHost} ${startupEvent} 模拟回放，真实宿主启动状态待确认。`
        : normHost === "codex"
          ? `codex 已收到 ${startupEvent}，原生直接父进程已核实。`
          : `${normHost} 已收到 ${startupEvent}，调用进程身份未核实。`;
      const acceptanceConditionCount = readTaskVerification(store, sessionId).plan?.conditions.length || 0;
      const acceptanceNotice = acceptanceConditionCount ? `${acceptanceConditionCount} 项明确验收条件已登记。` : "";
      const startupMessage = `[BlastGuard 启动检查] ${startupOrigin}${formatSnapshotCoverage(startupSnapshot)} ${shell.description} ${acceptanceNotice}后续工具钩子的实际覆盖仍需验证。${observationError || ""}`;
      const response = formatHostWireResponse(normHost, effectiveEvent, {
        action: "allow",
        reason: startupMessage,
        additionalContext: normHost === "antigravity"
          ? `${MINIMAL_CHANGE_ANCHOR}\n${startupMessage}`
          : MINIMAL_CHANGE_ANCHOR,
        systemMessage: startupMessage,
      });
      return { ...response, startupCheck: { snapshot: snapshotSummary(startupSnapshot), shell, observationRecorded: Boolean(observation), observationError } };
    }

    // A file read records its reference fingerprint in an existing session; other read tools stay read-only.
    if (
      (effectiveEvent === "PreToolUse" || effectiveEvent === "preToolUse") &&
      READ_ONLY_TOOLS.has(toolName)
    ) {
      let readObservation = null;
      if (fs.existsSync(store.dbPath) || fs.existsSync(store.markerPath)) {
        const rawReadPath = toolInput?.file_path ?? toolInput?.path ?? toolInput?.absolute_path ?? toolInput?.AbsolutePath ?? toolInput?.TargetFile ?? toolInput?.target_file;
        const observeFile = (toolName === "Read" || toolName === "read_file") && typeof rawReadPath === "string";
        await store.open({ allowInitialize: false, readOnly: !observeFile });
        if (observeFile) readObservation = store.recordReadObservation(sessionId, rawReadPath);
      }
      return { ...formatHostWireResponse(normHost, effectiveEvent, { action: "allow" }), readObservation };
    }

    if (((normHost === "antigravity" && toolInput.nativeAntigravityShell) || (normHost === "codex" && wrapShell && SHELL_TOOLS.has(toolName))) && (effectiveEvent === "PostToolUse" || effectiveEvent === "PostToolUseFailure")) {
      return formatHostWireResponse(normHost, effectiveEvent, { action: "allow" });
    }

    // All mutating lifecycle hooks (`PreToolUse`, `PostToolUse`, `PostToolUseFailure`, `Stop`)
    // MUST require pre-existing initialized state + attested session linkage (``)!
    // Deleting `.blast-guard-session`, external DB, or BOTH fails closed with `STATE_INTEGRITY_FAILURE`.
    await store.open({
      allowInitialize: false,
      expectExistingActiveSession: sessionId,
    });

    // 2. PreToolUse / preToolUse (mutating / potentially mutating tools)
    if (effectiveEvent === "PreToolUse" || effectiveEvent === "preToolUse") {
      // Fail closed if any prior transaction or active lock is unreconciled!
      store.assertNoUnreconciledTransactions();
      store.assertNoActiveLock();

      const session = store.loadSession(sessionId);
      if (!session) {
        return formatHostWireResponse(normHost, effectiveEvent, {
          action: "deny",
          reason: `[BlastGuard STATE_INTEGRITY_FAILURE] Active session '${sessionId}' is missing; submit a user prompt or run 'blast-guard session start' before mutating files.`,
        });
      }

      // Shell command (`Bash` / `exec_command` / `run_terminal_cmd`)
      if (SHELL_TOOLS.has(toolName)) {
        const cmdStr =
          typeof toolInput === "string"
            ? toolInput
            : toolInput?.command || toolInput?.cmd || "";
        const haz = checkCatastrophicShellCommand(cmdStr);
        if (!haz.ok) {
          return formatHostWireResponse(normHost, effectiveEvent, {
            action: "deny",
            reason: `[BlastGuard ${haz.code}] ${haz.reason}`,
          });
        }
        if ((normHost === "antigravity" && toolInput.nativeAntigravityShell) || (normHost === "codex" && wrapShell)) {
          if (toolInput.persistent || !cmdStr.trim()) {
            return formatHostWireResponse(normHost, effectiveEvent, { action: "deny", reason: "[BlastGuard UNSUPPORTED_ASYNC_COMMAND] Persistent or empty commands cannot be recovered safely." });
          }
          if (cmdStr.includes(BLAST_GUARD_BIN_PATH) && /(?:^|\s)wrap(?:\s|$)/.test(cmdStr)) {
            return formatHostWireResponse(normHost, effectiveEvent, { action: "deny", reason: "[BlastGuard RECURSIVE_WRAPPER] Submit the original command; nested guard wrappers are refused." });
          }
          const commandCwd = fs.realpathSync.native(path.resolve(cwd, toolInput.cwd || "."));
          const relativeCwd = path.relative(store.canonicalRoot, commandCwd);
          if (relativeCwd === ".." || relativeCwd.startsWith(`..${path.sep}`) || path.isAbsolute(relativeCwd)) {
            return formatHostWireResponse(normHost, effectiveEvent, { action: "deny", reason: "[BlastGuard OUTSIDE_WORKSPACE_ROOT] Command Cwd must be inside the guarded workspace." });
          }
          const quote = (value) => "'" + String(value).replace(/'/g, "'\\''") + "'";
          const shell = normHost === "codex" ? (process.env.SHELL || "/bin/sh") : "/bin/bash";
          const shellFlag = normHost === "codex" ? "-lc" : "-c";
          const command = [process.execPath, BLAST_GUARD_BIN_PATH, "wrap", "--mode", "checkpoint", "--assume-single-writer", "--session", sessionId, "--store-dir", store.storeDir, "--", shell, shellFlag, `cd ${quote(commandCwd)} && ${cmdStr}`].map(quote).join(" ");
          if (normHost === "codex") {
            return { exitCode: 0, stdoutObj: { hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "allow", updatedInput: { ...toolInput, command: `cd ${quote(store.canonicalRoot)} && ${command}` } } } };
          }
          return { exitCode: 0, stdoutObj: { decision: "allow", overwrite: { CommandLine: command, Cwd: store.canonicalRoot } } };
        }
        if (!correlationId) {
          return formatHostWireResponse(normHost, effectiveEvent, {
            action: "deny",
            reason:
              "[BlastGuard MISSING_TOOL_USE_ID] Shell PreToolUse requires a non-empty tool_use_id / call_id for exact PostToolUse transaction correlation.",
          });
        }
        store.beginCommandTransaction({
          sessionId,
          toolUseId: correlationId,
        });
        return formatHostWireResponse(normHost, effectiveEvent, { action: "allow" });
      }

      // Structured edit tools (`Edit`, `MultiEdit`, `Write`, `NotebookEdit`, `apply_patch`, `write_file`, `edit_file`)
      if (STRUCTURED_WRITE_TOOLS.has(toolName)) {
        const built = buildStructuredToolCandidates(store, session, toolName, toolInput);
        // Evaluate every sequential operation step (`built.stepCandidateGroups`) BEFORE final/net check
        // so transient/cancelled protected writes or partial-failure prefixes can never bypass PreToolUse!
        let runningWorkingSet = new Set(session.workingSet);
        if (Array.isArray(built.stepCandidateGroups) && built.stepCandidateGroups.length > 0) {
          for (const stepGroup of built.stepCandidateGroups) {
            const stepEval = evaluateCandidateWriteSet(stepGroup, {
              budget: session.budget,
              workingSet: runningWorkingSet,
              grants: session.grants,
              denySet: session.denySet,
            });
            if (!stepEval.ok) {
              return formatHostWireResponse(normHost, effectiveEvent, {
                action: "deny",
                reason: store.computeViolationDiagnostic(stepEval.violations, sessionId),
              });
            }
            runningWorkingSet = new Set(stepEval.nextWorkingSet);
          }
        }
        if (!built.ok) {
          return formatHostWireResponse(normHost, effectiveEvent, {
            action: "deny",
            reason: store.computeViolationDiagnostic(built.violations, sessionId),
          });
        }
        const evalRes = evaluateCandidateWriteSet(built.candidates, {
          budget: session.budget,
          workingSet: runningWorkingSet,
          grants: session.grants,
          denySet: session.denySet,
        });
        if (!evalRes.ok) {
          return formatHostWireResponse(normHost, effectiveEvent, {
            action: "deny",
            reason: store.computeViolationDiagnostic(evalRes.violations, sessionId),
          });
        }

        // Require exact correlation ID and open durable `'ACTIVE'` checkpoint journal BEFORE allowing structured write (``, ``, ``)!
        if (!correlationId) {
          return formatHostWireResponse(normHost, effectiveEvent, {
            action: "deny",
            reason: `[BlastGuard MISSING_TOOL_USE_ID] Mutating tool '${toolName}' requires a non-empty tool_use_id / call_id so PostToolUse can reconcile its durable transaction.`,
          });
        }
        store.beginCommandTransaction({
          sessionId,
          toolUseId: correlationId,
          acceptedWorkingSet: evalRes.nextWorkingSet,
          writePaths: [...built.candidates, ...(built.stepCandidateGroups || []).flat()].map((candidate) => candidate.relPosix),
        });
        return formatHostWireResponse(normHost, effectiveEvent, { action: "allow" });
      }

      // Delegated (`Task`) or unknown potentially mutating MCP/custom tool -> require correlation ID & open durable checkpoint journal!
      if (!correlationId) {
        return formatHostWireResponse(normHost, effectiveEvent, {
          action: "deny",
          reason: `[BlastGuard MISSING_TOOL_USE_ID] Potentially mutating tool '${toolName || "(unknown)"}' requires a non-empty tool_use_id / call_id.`,
        });
      }
      store.beginCommandTransaction({
        sessionId,
        toolUseId: correlationId,
      });
      return formatHostWireResponse(normHost, effectiveEvent, { action: "allow" });
    }

    // 3. PostToolUse / PostToolUseFailure / postToolUse (`` exact `(session_id, tool_use_id, ACTIVE)` correlation!)
    if (
      effectiveEvent === "PostToolUse" ||
      effectiveEvent === "PostToolUseFailure" ||
      effectiveEvent === "postToolUse" ||
      effectiveEvent === "postToolUseFailure"
    ) {
      const allOpenRows = store.getUnreconciledJournals();
      // Immediately fail closed if any journal is in `'ROLLING_BACK'` or `'RECOVERY_FAILED'`
      const crashRow = allOpenRows.find((r) => r.state !== "ACTIVE");
      if (crashRow) {
        store.assertNoUnreconciledTransactions();
      }

      const exactMatch = correlationId
        ? allOpenRows.find(
            (r) =>
              r.session_id === sessionId &&
              r.tool_use_id === correlationId &&
              r.state === "ACTIVE"
          )
        : null;

      if (!exactMatch) {
        if (allOpenRows.length > 0) {
          const active = allOpenRows[0];
          return formatHostWireResponse(normHost, effectiveEvent, {
            action: "block",
            reason: `[BlastGuard MISMATCHED_TOOL_USE_ID] Post-hook correlation '${correlationId || "(missing)"}' (session '${sessionId}') does not match active transaction '${active.tx_id}' (session '${active.session_id}', tool_use_id '${active.tool_use_id}'). Leaving active journal open fail-closed.`,
          });
        }
        store.assertNoActiveLock();
        return formatHostWireResponse(normHost, effectiveEvent, { action: "allow" });
      }

      const rec = store.reconcileCommandTransaction(exactMatch.tx_id, {
        forceRollbackOnAnyMutation:
          effectiveEvent === "PostToolUseFailure" || effectiveEvent === "postToolUseFailure",
      });
      if (!rec.ok) {
        const statusPrefix = rec.rolledBack
          ? "Unauthorized or failed-tool mutations were automatically rolled back to commandCheckpoint."
          : `CRITICAL: Rollback incomplete (${rec.recoveryError || "manual recovery required"}).`;
        return formatHostWireResponse(normHost, effectiveEvent, {
          action: "block",
          reason: `${statusPrefix}\n${store.computeViolationDiagnostic(rec.violations, sessionId)}`,
        });
      }

      return formatHostWireResponse(normHost, effectiveEvent, { action: "allow" });
    }

    if (normHost === "antigravity" && effectiveEvent === "Stop" && payload.fullyIdle === false) {
      return { exitCode: 0, stdoutObj: { decision: "continue", reason: "BlastGuard is waiting for background commands to finish before final verification." } };
    }
    // 4. Stop / stop
    if (effectiveEvent === "Stop" || effectiveEvent === "stop") {
      if (payload.stop_hook_active === true) {
        const current = readTaskVerification(store, sessionId);
        if (current.active) {
          const pending = await verifyTaskAtStop(store, sessionId);
          const summary = formatTaskVerification(pending);
          return { ...formatHostWireResponse(normHost, effectiveEvent, { action: "block", reason: summary }),
            diagnostic: summary, taskVerification: pending };
        }
        const previous = current.report;
        return { ...formatHostWireResponse(normHost, effectiveEvent, { action: "allow" }),
          diagnostic: previous ? formatTaskVerification(previous) : "[BlastGuard 任务核验] Stop 重入，回归未核实；可运行 session verify。",
          taskVerification: previous };
      }
      const openRows = store.getUnreconciledJournals();
      if (openRows.length > 0) {
        const rec = store.recoverUnfinishedTransactions();
        return formatHostWireResponse(normHost, effectiveEvent, {
          action: "block",
          reason: rec.ok
            ? "[BlastGuard UNRECONCILED_COMMAND_RECOVERED] An interrupted tool left an open transaction; BlastGuard rolled it back to commandCheckpoint. Verify workspace status before finishing."
            : "[BlastGuard RECOVERY_FAILED] Unfinished transaction could not be automatically recovered; inspect `blast-guard status`.",
        });
      }
      const verification = await verifyTaskAtStop(store, sessionId);
      const summary = formatTaskVerification(verification);
      const response = formatHostWireResponse(normHost, effectiveEvent, {
        action: verification.blocking ? "block" : "allow", reason: summary,
      });
      if (!verification.blocking && (normHost === "codex" || normHost === "claude")) response.stdoutObj = { systemMessage: summary };
      return { ...response, diagnostic: summary, taskVerification: verification };
    }

    return formatHostWireResponse(normHost, effectiveEvent, { action: "allow" });
  } catch (err) {
    const reason = `[BlastGuard ${err.code || "INTERNAL_GUARD_ERROR"}] ${err.message}`;
    return formatHostWireResponse(normHost, effectiveEvent, {
      action: failAction,
      reason,
    });
  } finally {
    store.close();
  }
}

/**
 * Parse NUL-delimited staged index records (``):
 * - When `hasHead`: `git diff-index -z --cached --no-renames --no-ext-diff HEAD`
 *   Record format: `:<oldMode> <newMode> <oldOid> <newOid> <status>\0<rawPathBytes>\0`
 * - When `!hasHead` (unborn initial commit): `git ls-files -z --stage`
 *   Record format: `<newMode> <newOid> <stage>\t<rawPathBytes>\0`
 */
function parseStagedGitIndexRecords(canonicalRoot, gitEnv, hasHead, gitBinary = "git") {
  if (hasHead) {
    const res = spawnSync(
      gitBinary,
      ["-c", "core.hooksPath=/dev/null", "diff-index", "-z", "--cached", "--no-renames", "--no-ext-diff", "HEAD"],
      {
        cwd: canonicalRoot,
        env: gitEnv,
        maxBuffer: 32 * 1024 * 1024,
      }
    );
    if (res.error || res.status !== 0) {
      return {
        ok: false,
        code: "GIT_INDEX_READ_ERROR",
        reason: `Failed reading staged Git index: ${res.error?.message || res.stderr?.toString("utf8") || `exit ${res.status}`}`,
      };
    }
    const buf = res.stdout || Buffer.alloc(0);
    const records = [];
    let offset = 0;
    while (offset < buf.length) {
      const nul1 = buf.indexOf(0, offset);
      if (nul1 === -1) break;
      const metaStr = buf.subarray(offset, nul1).toString("utf8");
      const nul2 = buf.indexOf(0, nul1 + 1);
      if (nul2 === -1) {
        return {
          ok: false,
          code: "GIT_INDEX_READ_ERROR",
          reason: "Truncated NUL-delimited git diff-index record.",
        };
      }
      const rawPath = buf.subarray(nul1 + 1, nul2).toString("utf8");
      offset = nul2 + 1;

      const m = metaStr.match(/^:(\d+)\s+(\d+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([A-Z])/i);
      if (!m) {
        return {
          ok: false,
          code: "GIT_INDEX_READ_ERROR",
          reason: `Unrecognized git diff-index metadata header: '${metaStr}'`,
        };
      }
      const [, oldMode, newMode, oldOid, newOid, statusChar] = m;
      if (statusChar === "U") {
        return {
          ok: false,
          code: "GIT_UNMERGED_INDEX",
          reason: `Unmerged conflict entry '${rawPath}' in Git index.`,
        };
      }
      records.push({
        status: statusChar.toUpperCase(),
        oldMode,
        newMode,
        oldOid,
        newOid,
        rawPath,
      });
    }
    return { ok: true, records };
  }

  // Unborn initial commit: `git ls-files -z --stage`
  const res = spawnSync(
    gitBinary,
    ["-c", "core.hooksPath=/dev/null", "ls-files", "-z", "--stage"],
    {
      cwd: canonicalRoot,
      env: gitEnv,
      maxBuffer: 32 * 1024 * 1024,
    }
  );
  if (res.error || res.status !== 0) {
    return {
      ok: false,
      code: "GIT_INDEX_READ_ERROR",
      reason: `Failed reading unborn staged Git index: ${res.error?.message || res.stderr?.toString("utf8") || `exit ${res.status}`}`,
    };
  }
  const buf = res.stdout || Buffer.alloc(0);
  const records = [];
  let offset = 0;
  while (offset < buf.length) {
    const nulIdx = buf.indexOf(0, offset);
    if (nulIdx === -1) break;
    const entryBuf = buf.subarray(offset, nulIdx);
    offset = nulIdx + 1;
    const tabIdx = entryBuf.indexOf(0x09);
    if (tabIdx === -1) {
      return {
        ok: false,
        code: "GIT_INDEX_READ_ERROR",
        reason: "Malformed git ls-files --stage entry.",
      };
    }
    const metaStr = entryBuf.subarray(0, tabIdx).toString("utf8");
    const rawPath = entryBuf.subarray(tabIdx + 1).toString("utf8");
    const parts = metaStr.trim().split(/\s+/);
    if (parts.length < 3) {
      return {
        ok: false,
        code: "GIT_INDEX_READ_ERROR",
        reason: `Invalid git ls-files stage header '${metaStr}'.`,
      };
    }
    const [newMode, newOid, stage] = parts;
    if (stage !== "0") {
      return {
        ok: false,
        code: "GIT_UNMERGED_INDEX",
        reason: `Unmerged index stage ${stage} on '${rawPath}'.`,
      };
    }
    records.push({
      status: "A",
      oldMode: "000000",
      newMode,
      oldOid: null,
      newOid,
      rawPath,
    });
  }
  return { ok: true, records };
}

/**
 * Git `pre-commit` staged-index gate (``, ``, ``):
 * - Verifies `git --version` is inside bounded range `2.30.0 .. 2.50.x`
 * - Uses `-z` NUL-delimited raw index records + `git cat-file blob <oid>` (defeating C-quoted CJK/special-path bypasses and failing closed on blob read errors!)
 * - Resolves active session deterministically (`--session` / `BLAST_GUARD_SESSION_ID` -> `.blast-guard-session` marker -> single unambiguous SQLite session)
 * - Strictly read-only: NEVER rolls back or mutates the user's working tree!
 */
export async function runGitPreCommitCheck(
  workspaceRoot = process.cwd(),
  { storeDir = null, sessionId = null, gitBinary = "git", _testGitVersionOverride = null } = {}
) {
  const canonicalRoot = canonicalizeWorkspaceRoot(workspaceRoot);
  const gitEnv = {
    ...process.env,
    GIT_OPTIONAL_LOCKS: "0",
  };

  // Bounded Git version check (``): strictly bound to `gitBinary --version` except in explicit JS unit tests.
  let detectedGitVer = _testGitVersionOverride;
  if (!detectedGitVer) {
    const verRes = spawnSync(gitBinary, ["--version"], {
      cwd: canonicalRoot,
      env: gitEnv,
      encoding: "utf8",
      timeout: 2500,
    });
    if (verRes.error || verRes.status !== 0) {
      return {
        ok: false,
        exitCode: 1,
        reason: `[BlastGuard GIT_BINARY_ERROR] Failed invoking '${gitBinary} --version'.`,
        violations: [],
      };
    }
    detectedGitVer = (verRes.stdout || verRes.stderr || "").trim();
  }

  const verValid = validateSuppliedHostVersion("git", detectedGitVer);
  if (!verValid.ok) {
    return {
      ok: false,
      exitCode: 1,
      reason: `[BlastGuard ${verValid.code}] ${verValid.reason}`,
      violations: [{ code: verValid.code, path: "<git>", message: verValid.reason }],
    };
  }

  const headRes = spawnSync(gitBinary, ["rev-parse", "--verify", "HEAD"], {
    cwd: canonicalRoot,
    env: gitEnv,
    encoding: "utf8",
  });
  const hasHead = headRes.status === 0;

  const indexParsed = parseStagedGitIndexRecords(canonicalRoot, gitEnv, hasHead, gitBinary);
  if (!indexParsed.ok) {
    return {
      ok: false,
      exitCode: 1,
      reason: `[BlastGuard ${indexParsed.code}] ${indexParsed.reason}`,
      violations: [{ code: indexParsed.code, path: "<git-index>", message: indexParsed.reason }],
    };
  }

  if (indexParsed.records.length === 0) {
    return { ok: true, exitCode: 0, violations: [] };
  }

  const isZeroOid = (oid) => !oid || /^0+$/.test(oid);
  const isRegularGitMode = (m) => m === "100644" || m === "100755";

  const readGitBlobByOid = (oid, contextPath) => {
    if (isZeroOid(oid)) {
      return { ok: false, reason: `Unexpected zero OID on '${contextPath}'.` };
    }
    const res = spawnSync(gitBinary, ["cat-file", "blob", oid], {
      cwd: canonicalRoot,
      env: gitEnv,
      maxBuffer: 16 * 1024 * 1024,
    });
    if (res.error || res.status !== 0 || !Buffer.isBuffer(res.stdout)) {
      return {
        ok: false,
        reason: `Failed reading Git blob '${oid}' for '${contextPath}': ${res.error?.message || res.stderr?.toString("utf8") || `exit ${res.status}`}`,
      };
    }
    const buf = res.stdout;
    for (let i = 0; i < Math.min(buf.length, 4096); i++) {
      if (buf[i] === 0) return { ok: true, isBinary: true, text: null };
    }
    return { ok: true, isBinary: false, text: buf.toString("utf8") };
  };

  // Default standalone Git budget uses exact specified default tier (`SURGICAL_FIX`, maxWritableFiles = 3) (`New `, ``)
  let budget = { ...TIER_BUDGETS.SURGICAL_FIX };
  let workingSet = new Set();
  let grants = [];
  let denySet = [];
  let activeTaskCp = null;

  let store;
  try {
    store = new SnapshotStore(canonicalRoot, storeDir ? { storeDir } : {});
  } catch (err) {
    return {
      ok: false,
      exitCode: 1,
      reason: `[BlastGuard ${err.code || "STATE_INIT_ERROR"}] ${err.message}`,
      violations: [{ code: err.code || "STATE_INIT_ERROR", path: "<git-index>", message: err.message }],
    };
  }

  try {
    const requestedSessionId =
      sessionId ||
      (process.env.BLAST_GUARD_SESSION_ID && process.env.BLAST_GUARD_SESSION_ID.trim()) ||
      null;

    if (requestedSessionId || fs.existsSync(store.dbPath) || fs.existsSync(store.markerPath)) {
      await store.open({
        allowInitialize: false,
        readOnly: true,
        ...(requestedSessionId ? { expectExistingActiveSession: requestedSessionId } : {}),
      });
      store.assertNoUnreconciledTransactions();
      store.assertNoActiveLock();

      let selectedSession = null;
      if (requestedSessionId) {
        selectedSession = store.loadSession(requestedSessionId);
        if (!selectedSession) {
          return {
            ok: false,
            exitCode: 1,
            reason: `[BlastGuard SESSION_NOT_FOUND] Explicit session '${requestedSessionId}' was not found in authoritative state store.`,
            violations: [{ code: "SESSION_NOT_FOUND", path: "<git-index>", message: `Session '${requestedSessionId}' missing.` }],
          };
        }
      } else {
        const marker = store.readSessionMarker();
        if (marker?.sessionId) {
          selectedSession = store.loadSession(marker.sessionId);
          if (!selectedSession) {
            return {
              ok: false,
              exitCode: 1,
              reason: `[BlastGuard STATE_INTEGRITY_FAILURE] Marker session '${marker.sessionId}' is missing from state store.`,
              violations: [{ code: "STATE_INTEGRITY_FAILURE", path: "<git-index>", message: "Marker session missing." }],
            };
          }
        } else {
          const allSessions = store.listSessions();
          if (allSessions.length === 1) {
            selectedSession = allSessions[0];
          } else if (allSessions.length > 1) {
            return {
              ok: false,
              exitCode: 1,
              reason: `[BlastGuard AMBIGUOUS_ACTIVE_SESSION] Multiple sessions (${allSessions.map((s) => s.sessionId).join(", ")}) exist without an active .blast-guard-session marker; pass --session <id> or run 'blast-guard session start'.`,
              violations: [
                {
                  code: "AMBIGUOUS_ACTIVE_SESSION",
                  path: "<git-index>",
                  message: "Ambiguous active session selection.",
                },
              ],
            };
          }
        }
      }

      if (selectedSession) {
        budget = selectedSession.budget;
        workingSet = new Set(selectedSession.workingSet);
        grants = selectedSession.grants;
        denySet = selectedSession.denySet;
        activeTaskCp = store.loadCheckpoint(selectedSession.taskBaselineId);
      }
    }

    const candidates = [];
    for (const rec of indexParsed.records) {
      const relPosix = toPosixRel(rec.rawPath).replace(/^\/+/, "");
      if (!relPosix || relPosix.includes("\0") || relPosix.split("/").some((s) => s === "." || s === "..")) {
        return {
          ok: false,
          exitCode: 1,
          reason: `[BlastGuard INVALID_PATH_COMPONENT] Invalid staged path '${rec.rawPath}'.`,
          violations: [{ code: "INVALID_PATH_COMPONENT", path: rec.rawPath, message: "Invalid staged path." }],
        };
      }

      // Symlink (`120000`) or submodule gitlink (`160000`) in staged index -> `type-change`
      const oldRegular = rec.oldMode === "000000" || isRegularGitMode(rec.oldMode);
      const newRegular = rec.newMode === "000000" || isRegularGitMode(rec.newMode);
      if (!oldRegular || !newRegular || rec.status === "T") {
        candidates.push({
          relPosix,
          changeType: "type-change",
          isDirectory: false,
          commandBeforeText: null,
          taskBaselineText: null,
          afterText: null,
          isBinary: true,
        });
        continue;
      }

      const taskEnt = activeTaskCp?.entries.get(relPosix) || null;
      const taskTextFromStore = taskEnt ? store.readBaselineTextFromEntry(taskEnt) : undefined;

      if (rec.status === "A") {
        const stagedBlob = readGitBlobByOid(rec.newOid, relPosix);
        if (!stagedBlob.ok) {
          return {
            ok: false,
            exitCode: 1,
            reason: `[BlastGuard GIT_BLOB_READ_ERROR] ${stagedBlob.reason}`,
            violations: [{ code: "GIT_BLOB_READ_ERROR", path: relPosix, message: stagedBlob.reason }],
          };
        }
        candidates.push({
          relPosix,
          changeType: "add",
          isDirectory: false,
          commandBeforeText: null,
          taskBaselineText: taskTextFromStore !== undefined ? taskTextFromStore : null,
          afterText: stagedBlob.text,
          isBinary: stagedBlob.isBinary,
        });
      } else if (rec.status === "D") {
        const headBlob = readGitBlobByOid(rec.oldOid, relPosix);
        if (!headBlob.ok) {
          return {
            ok: false,
            exitCode: 1,
            reason: `[BlastGuard GIT_BLOB_READ_ERROR] ${headBlob.reason}`,
            violations: [{ code: "GIT_BLOB_READ_ERROR", path: relPosix, message: headBlob.reason }],
          };
        }
        candidates.push({
          relPosix,
          changeType: "delete",
          isDirectory: false,
          commandBeforeText: headBlob.text,
          taskBaselineText: taskTextFromStore !== undefined ? taskTextFromStore : headBlob.text,
          afterText: null,
          isBinary: headBlob.isBinary,
        });
      } else {
        const headBlob = readGitBlobByOid(rec.oldOid, relPosix);
        const stagedBlob = readGitBlobByOid(rec.newOid, relPosix);
        if (!headBlob.ok || !stagedBlob.ok) {
          const msg = !headBlob.ok ? headBlob.reason : stagedBlob.reason;
          return {
            ok: false,
            exitCode: 1,
            reason: `[BlastGuard GIT_BLOB_READ_ERROR] ${msg}`,
            violations: [{ code: "GIT_BLOB_READ_ERROR", path: relPosix, message: msg }],
          };
        }
        const changeType = rec.oldOid === rec.newOid && rec.oldMode !== rec.newMode ? "mode-change" : "modify";
        candidates.push({
          relPosix,
          changeType,
          isDirectory: false,
          commandBeforeText: headBlob.text,
          taskBaselineText: taskTextFromStore !== undefined ? taskTextFromStore : headBlob.text,
          afterText: stagedBlob.text,
          isBinary: Boolean(headBlob.isBinary || stagedBlob.isBinary),
        });
      }
    }

    const evalRes = evaluateCandidateWriteSet(candidates, {
      budget,
      workingSet,
      grants,
      denySet,
    });

    if (!evalRes.ok) {
      return {
        ok: false,
        exitCode: 1,
        reason: formatVoiEscalationGuidance(evalRes.violations, {
          workingSet: Array.from(workingSet),
        }),
        violations: evalRes.violations,
      };
    }

    return { ok: true, exitCode: 0, violations: [] };
  } catch (err) {
    return {
      ok: false,
      exitCode: 1,
      reason: `[BlastGuard ${err.code || "STATE_ERROR"}] ${err.message}`,
      violations: [{ code: err.code || "STATE_ERROR", path: "<git-index>", message: err.message }],
    };
  } finally {
    store.close();
  }
}
