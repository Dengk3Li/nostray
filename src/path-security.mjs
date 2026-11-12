import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { BLAST_GUARD_PACKAGE_ROOT } from "./runtime-support.mjs";

/**
 * Directories skipped ONLY during read-only static audit / dependency-graph heuristics (`repo-auditor.mjs`, `dependency-graph.mjs`).
 * NEVER used to omit writable directories from strict `SnapshotStore` checkpoint recovery coverage (``)!
 */
export const AUDIT_PERFORMANCE_IGNORED_DIRS = new Set([
  "node_modules",
  ".venv",
  "venv",
  "__pycache__",
  ".pytest_cache",
  ".mypy_cache",
  ".ruff_cache",
  ".next",
  ".nuxt",
  ".turbo",
  "dist",
  "build",
  "coverage",
  "target",
]);

// Retained alias for read-only callers
export const PERFORMANCE_IGNORED_DIRS = AUDIT_PERFORMANCE_IGNORED_DIRS;

const RING_00_PREFIXES = [
  ".git",
  ".blast-guard",
  ".claude",
  ".codex",
  ".agents",
  ".cursor",
  ".husky",
];

const RING_0_CONTRACT_BASENAMES = new Set([
  "agents.md",
  "claude.md",
  "package.json",
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "bun.lockb",
  "pyproject.toml",
  "poetry.lock",
  "uv.lock",
  "cargo.toml",
  "cargo.lock",
  "go.mod",
  "go.sum",
  "tsconfig.json",
  "dockerfile",
  "docker-compose.yml",
  "docker-compose.yaml",
]);

/**
 * On macOS Darwin >=23, the kernel automatically synthesizes `com.apple.provenance` on created files
 * (cannot be deleted or authored by user-space, and is re-synthesized on atomic temp replacement).
 * All user/application extended attributes and all ACLs are rejected unless explicitly configured.
 */
export const DEFAULT_EXEMPT_XATTRS = Object.freeze(
  process.platform === "darwin" ? ["com.apple.provenance"] : []
);

export function toPosixRel(relPath) {
  return relPath.split(path.sep).join("/");
}

export function canonicalizeWorkspaceRoot(workspaceRoot) {
  return fs.realpathSync.native(path.resolve(workspaceRoot));
}

export function isContainedRelativePath(rel) {
  if (rel === "") return true;
  if (rel === ".." || rel.startsWith(`..${path.sep}`) || rel.startsWith("../")) {
    return false;
  }
  return !path.isAbsolute(rel);
}

function isInsideBlastGuardInstallation(absOrRealPath) {
  const relToPkg = path.relative(BLAST_GUARD_PACKAGE_ROOT, absOrRealPath);
  return isContainedRelativePath(relToPkg);
}

const caseInsensitiveRootCache = new Map();

function toggleFirstAsciiLetter(str) {
  for (let i = str.length - 1; i >= 0; i--) {
    const code = str.charCodeAt(i);
    if (code >= 65 && code <= 90) {
      return str.slice(0, i) + String.fromCharCode(code + 32) + str.slice(i + 1);
    }
    if (code >= 97 && code <= 122) {
      return str.slice(0, i) + String.fromCharCode(code - 32) + str.slice(i + 1);
    }
  }
  return null;
}

/**
 * Side-effect-free (read-only `lstatSync` inode check) detection of whether `canonicalRoot`
 * resides on a case-insensitive filesystem (such as default macOS APFS).
 */
export function isWorkspaceCaseInsensitive(canonicalRoot) {
  if (!canonicalRoot) return process.platform === "darwin" || process.platform === "win32";
  if (caseInsensitiveRootCache.has(canonicalRoot)) {
    return caseInsensitiveRootCache.get(canonicalRoot);
  }
  let detected = null;
  try {
    const rootSt = fs.lstatSync(canonicalRoot, { bigint: true });
    // 1. Try toggling case on canonicalRoot basename (or same-device ancestor)
    let probePath = canonicalRoot;
    while (probePath && probePath !== path.dirname(probePath)) {
      const stCur = fs.lstatSync(probePath, { bigint: true });
      if (stCur.dev !== rootSt.dev) break;
      const base = path.basename(probePath);
      const toggledBase = toggleFirstAsciiLetter(base);
      if (toggledBase && toggledBase !== base) {
        const altPath = path.join(path.dirname(probePath), toggledBase);
        try {
          const stAlt = fs.lstatSync(altPath, { bigint: true });
          detected = stAlt.dev === stCur.dev && stAlt.ino === stCur.ino;
        } catch {
          detected = false;
        }
        break;
      }
      probePath = path.dirname(probePath);
    }
    // 2. Fallback: check any existing entry inside canonicalRoot with an ASCII letter
    if (detected === null) {
      const entries = fs.readdirSync(canonicalRoot);
      for (const name of entries) {
        const toggled = toggleFirstAsciiLetter(name);
        if (toggled && toggled !== name) {
          const p1 = path.join(canonicalRoot, name);
          const p2 = path.join(canonicalRoot, toggled);
          const st1 = fs.lstatSync(p1, { bigint: true });
          try {
            const st2 = fs.lstatSync(p2, { bigint: true });
            detected = st1.dev === st2.dev && st1.ino === st2.ino;
          } catch {
            detected = false;
          }
          break;
        }
      }
    }
  } catch {
    // ignore
  }
  const result = detected !== null ? detected : process.platform === "darwin" || process.platform === "win32";
  caseInsensitiveRootCache.set(canonicalRoot, result);
  return result;
}

/**
 * Classify a POSIX-normalized workspace-relative path into Ring-00, Ring-0, or candidate leaf.
 */
export function classifyProtectionRing(relPosix, { workingSet = new Set(), maxWritableFiles = 3, grants = [] } = {}) {
  const clean = relPosix.replace(/^\/+/, "");
  if (!clean || clean === ".") {
    return { ring: "RING_00", category: "IMMUTABLE_INFRA", subkind: "workspace-root" };
  }
  const parts = clean.split("/");
  const first = parts[0];
  const lowerFirst = first.toLowerCase();
  const base = parts[parts.length - 1];
  const lowerBase = base.toLowerCase();
  const lowerClean = clean.toLowerCase();

  // Ring-00: Immutable guard & VCS / host hook infrastructure (case-insensitive across all reserved namespaces!)
  if (
    RING_00_PREFIXES.includes(lowerFirst) ||
    lowerClean === ".blast-guard-session"
  ) {
    return { ring: "RING_00", category: "IMMUTABLE_INFRA", subkind: lowerFirst };
  }

  // Ring-0: Test & Verification files (case-insensitive directory & filename matching!)
  const isTestFile =
    parts.some((seg) => {
      const ls = seg.toLowerCase();
      return ls === "test" || ls === "tests" || ls === "__tests__" || ls === "e2e";
    }) ||
    lowerBase === "conftest.py" ||
    /\.(?:test|spec)\.[a-z0-9]+$/i.test(base) ||
    /^test_.*\.py$/i.test(base) ||
    /^.*_test\.(?:py|go|rs)$/i.test(base);

  if (isTestFile) {
    const matchingGrant = findMatchingGrant(clean, grants);
    return {
      ring: "RING_0",
      category: "TEST_SUITE",
      subkind: "verification",
      granted: Boolean(matchingGrant),
      grant: matchingGrant || null,
    };
  }

  // Ring-0: Contracts, Schemas, Types, Env, CI, Unsupported structured configs (.yaml/.yml/.mdx)
  const isContractFile =
    RING_0_CONTRACT_BASENAMES.has(lowerBase) ||
    lowerBase.startsWith(".env") ||
    lowerClean.startsWith(".github/workflows/") ||
    lowerClean.startsWith("contracts/") ||
    lowerClean.startsWith("schemas/") ||
    lowerClean.startsWith("types/") ||
    (/schema/i.test(base) && /\.(?:json|ts|js|py|graphql|proto)$/i.test(base)) ||
    /\.(?:proto|graphql|gql)$/i.test(base) ||
    /^(?:openapi|swagger)\.[a-z0-9]+$/i.test(base) ||
    /\.d\.ts$/i.test(base) ||
    /\.(?:yaml|yml|mdx)$/i.test(base);

  if (isContractFile) {
    const matchingGrant = findMatchingGrant(clean, grants);
    return {
      ring: "RING_0",
      category: "CONTRACT_OR_CONFIG",
      subkind: lowerBase.endsWith(".json") ? "json-contract" : "contract",
      granted: Boolean(matchingGrant),
      grant: matchingGrant || null,
    };
  }

  // Leaf / implementation / documentation files -> Ring-1 if in workingSet or granted, else candidate/Ring-2
  const matchingGrant = findMatchingGrant(clean, grants);
  if (workingSet.has(clean) || matchingGrant) {
    return {
      ring: "RING_1",
      category: "WORKING_LEASE",
      subkind: "leased",
      granted: Boolean(matchingGrant),
      grant: matchingGrant || null,
    };
  }

  if (workingSet.size < maxWritableFiles) {
    return {
      ring: "RING_1_CANDIDATE",
      category: "LOCALIZATION_CANDIDATE",
      subkind: "available-slot",
      granted: false,
      grant: null,
    };
  }

  return {
    ring: "RING_2",
    category: "OUT_OF_BUDGET",
    subkind: "budget-exhausted",
    granted: false,
    grant: null,
  };
}

export function findMatchingGrant(relPosix, grants = []) {
  for (let i = grants.length - 1; i >= 0; i--) {
    const g = grants[i];
    if (!g || !g.pathPattern) continue;
    if (g.pathPattern === relPosix) return g;
    if (g.matchBasename && path.posix.basename(relPosix) === g.pathPattern) {
      return g;
    }
    if (g.pathPattern.endsWith("/**")) {
      const prefix = g.pathPattern.slice(0, -3);
      if (relPosix === prefix || relPosix.startsWith(`${prefix}/`)) return g;
    }
  }
  return null;
}

/**
 * Used ONLY by read-only static auditor / dependency graph (`repo-auditor.mjs`, `dependency-graph.mjs`).
 */
export function shouldSkipPerformanceIgnoredDir(relPosixDir) {
  const clean = relPosixDir.replace(/^\/+/, "");
  if (!clean) return false;
  const lowerClean = clean.toLowerCase();
  const parts = clean.split("/");
  const lowerFirst = parts[0].toLowerCase();
  if (
    RING_00_PREFIXES.includes(lowerFirst) ||
    lowerClean === ".github" ||
    lowerClean.startsWith(".github/workflows")
  ) {
    return false;
  }
  for (const seg of parts) {
    if (AUDIT_PERFORMANCE_IGNORED_DIRS.has(seg.toLowerCase())) return true;
  }
  return false;
}

/**
 * Resolve and validate a candidate path against canonicalRoot (``):
 * - Checks BOTH lexical AND resolved (`realpathSync.native`) targets against `BLAST_GUARD_PACKAGE_ROOT`
 * - Rejects `..` / unnormalized segments before normalization tricks
 * - Walks every existing component with `lstatSync`
 * - Rejects ALL symlinks (intermediate or leaf) when `forWrite === true` (and cross-ring/escaping symlinks always)
 * - Rejects hardlinked regular files (`st.nlink > 1`) with `UNSAFE_HARDLINK_ALIAS`
 * - Rejects special files (FIFO/socket/device) and unsupported metadata/xattrs/ACLs on write targets
 */
export function inspectWorkspacePath(
  canonicalRoot,
  rawCandidatePath,
  {
    forWrite = true,
    allowDirectoryLeaf = false,
    checkPlatformAttrs = false,
    exemptXattrs = DEFAULT_EXEMPT_XATTRS,
    unlinkedRegularFileSet = null,
  } = {}
) {
  const rawStr = String(rawCandidatePath ?? "");
  if (!rawStr || rawStr.includes("\0")) {
    return {
      ok: false,
      code: "INVALID_PATH_COMPONENT",
      reason: "Empty or NUL-containing path is invalid.",
      canonicalRoot,
      absCandidate: null,
      relPosix: null,
    };
  }

  // Reject explicit `..` traversal segments in relative inputs before `path.resolve` collapses them
  if (!path.isAbsolute(rawStr)) {
    const rawSegs = rawStr.split(/[\\/]+/);
    if (rawSegs.includes("..")) {
      return {
        ok: false,
        code: "OUTSIDE_WORKSPACE_ROOT",
        reason: `Path '${rawStr}' contains parent traversal segment '..'.`,
        canonicalRoot,
        absCandidate: path.resolve(canonicalRoot, rawStr),
        relPosix: null,
      };
    }
  }

  const absCandidate = path.isAbsolute(rawStr)
    ? path.normalize(rawStr)
    : path.resolve(canonicalRoot, rawStr);

  // Lexical installation-root protection
  if (isInsideBlastGuardInstallation(absCandidate)) {
    return {
      ok: false,
      code: "IMMUTABLE_GUARD_BINARY",
      reason: `Path '${rawCandidatePath}' points inside the blast-guard runtime installation (${BLAST_GUARD_PACKAGE_ROOT}).`,
      canonicalRoot,
      absCandidate,
      relPosix: null,
    };
  }

  const relNative = path.relative(canonicalRoot, absCandidate);
  if (!isContainedRelativePath(relNative)) {
    return {
      ok: false,
      code: "OUTSIDE_WORKSPACE_ROOT",
      reason: `Path '${rawCandidatePath}' resolves outside canonical workspace root (${canonicalRoot}).`,
      canonicalRoot,
      absCandidate,
      relPosix: null,
    };
  }

  const relPosix = toPosixRel(relNative);
  const segments = relPosix ? relPosix.split("/") : [];

  if (segments.length === 0) {
    if (forWrite && !allowDirectoryLeaf) {
      return {
        ok: false,
        code: "IMMUTABLE_INFRA_PROTECTED",
        reason: "Cannot overwrite workspace root directory.",
        canonicalRoot,
        absCandidate: canonicalRoot,
        relPosix: "",
      };
    }
    return {
      ok: true,
      exists: true,
      entryType: "directory",
      canonicalRoot,
      absPath: canonicalRoot,
      relPosix: "",
      lstat: fs.lstatSync(canonicalRoot),
    };
  }

  let cursor = canonicalRoot;
  let lastExistingDir = canonicalRoot;
  for (let i = 0; i < segments.length; i++) {
    const seg = segments[i];
    if (!seg || seg === "." || seg === "..") {
      return {
        ok: false,
        code: "INVALID_PATH_COMPONENT",
        reason: `Unnormalized traversal segment in '${rawCandidatePath}'.`,
        canonicalRoot,
        absCandidate,
        relPosix,
      };
    }
    cursor = path.join(cursor, seg);
    let st = null;
    try {
      st = fs.lstatSync(cursor);
    } catch (err) {
      if (err && err.code === "ENOENT") {
        // Canonicalize the deepest existing ancestor via `realpathSync.native` so case-insensitive
        // directory aliases (e.g. `.CODEX/hooks.json`, `.CODEX/sub/evil.txt`, `TESTS/helper.js`)
        // resolve to their true on-disk namespace (`.codex/...`, `tests/...`)!
        let realAncestor = canonicalRoot;
        if (i > 0) {
          try {
            realAncestor = fs.realpathSync.native(lastExistingDir);
          } catch {
            realAncestor = lastExistingDir;
          }
          if (isInsideBlastGuardInstallation(realAncestor)) {
            return {
              ok: false,
              code: "IMMUTABLE_GUARD_BINARY",
              reason: `Resolved ancestor '${realAncestor}' points inside the blast-guard runtime installation.`,
              canonicalRoot,
              absCandidate,
              relPosix,
            };
          }
          const relAnc = path.relative(canonicalRoot, realAncestor);
          if (!isContainedRelativePath(relAnc)) {
            return {
              ok: false,
              code: "OUTSIDE_WORKSPACE_ROOT",
              reason: `Resolved ancestor '${realAncestor}' escapes workspace root (${canonicalRoot}).`,
              canonicalRoot,
              absCandidate,
              relPosix,
            };
          }
        }
        const effectiveAbs = path.join(realAncestor, ...segments.slice(i));
        if (isInsideBlastGuardInstallation(effectiveAbs)) {
          return {
            ok: false,
            code: "IMMUTABLE_GUARD_BINARY",
            reason: `Resolved destination '${effectiveAbs}' points inside the blast-guard runtime installation.`,
            canonicalRoot,
            absCandidate: effectiveAbs,
            relPosix,
          };
        }
        const effectiveRelPosix = toPosixRel(path.relative(canonicalRoot, effectiveAbs));
        return {
          ok: true,
          exists: false,
          entryType: "missing",
          canonicalRoot,
          absPath: effectiveAbs,
          relPosix: effectiveRelPosix,
          lstat: null,
        };
      }
      throw err;
    }

    const isLeaf = i === segments.length - 1;
    if (st.isSymbolicLink()) {
      const linkTargetRaw = fs.readlinkSync(cursor);
      const resolvedLinkTarget = path.resolve(path.dirname(cursor), linkTargetRaw);
      let realTarget = resolvedLinkTarget;
      try {
        realTarget = fs.realpathSync.native(cursor);
      } catch {
        // Broken symlink: check lexical resolvedLinkTarget too
      }

      // Resolved installation-root check BEFORE ring classification (``)!
      if (
        isInsideBlastGuardInstallation(realTarget) ||
        isInsideBlastGuardInstallation(resolvedLinkTarget)
      ) {
        return {
          ok: false,
          code: "IMMUTABLE_GUARD_BINARY",
          reason: `Symlink '${toPosixRel(path.relative(canonicalRoot, cursor))}' resolves inside the blast-guard runtime installation.`,
          canonicalRoot,
          absCandidate,
          relPosix,
          linkTarget: linkTargetRaw,
        };
      }

      const targetRel = path.relative(canonicalRoot, realTarget);
      if (!isContainedRelativePath(targetRel)) {
        return {
          ok: false,
          code: "UNSAFE_LINK_ALIAS",
          reason: `Symlink '${toPosixRel(path.relative(canonicalRoot, cursor))}' points outside workspace (${linkTargetRaw}).`,
          canonicalRoot,
          absCandidate,
          relPosix,
          linkTarget: linkTargetRaw,
        };
      }

      const targetRelPosix = toPosixRel(targetRel);
      const targetRing = classifyProtectionRing(targetRelPosix);
      const sourceRing = classifyProtectionRing(relPosix);

      if (
        forWrite ||
        !isLeaf ||
        ((targetRing.ring === "RING_00" || targetRing.ring === "RING_0") &&
          sourceRing.ring !== targetRing.ring)
      ) {
        return {
          ok: false,
          code: "UNSAFE_LINK_ALIAS",
          reason: forWrite
            ? `Symbolic link '${relPosix}' -> '${targetRelPosix}' cannot be targeted for write operations.`
            : `Symlink '${relPosix}' aliases protected or directory target '${targetRelPosix}' (${targetRing.ring}).`,
          canonicalRoot,
          absCandidate,
          relPosix,
          linkTarget: linkTargetRaw,
          aliasedTarget: targetRelPosix,
        };
      }

      return {
        ok: true,
        exists: true,
        entryType: "symlink",
        canonicalRoot,
        absPath: absCandidate,
        relPosix,
        linkTarget: linkTargetRaw,
        aliasedTarget: targetRelPosix,
        lstat: st,
      };
    }

    // Even for non-symlink entries (e.g. bind-mount or firmlink), verify resolved path is not the guard installation
    let realCursorResolved = cursor;
    try {
      const realCursor = fs.realpathSync.native(cursor);
      realCursorResolved = realCursor;
      if (isInsideBlastGuardInstallation(realCursor)) {
        return {
          ok: false,
          code: "IMMUTABLE_GUARD_BINARY",
          reason: `Resolved path '${realCursor}' points inside the blast-guard runtime installation.`,
          canonicalRoot,
          absCandidate,
          relPosix,
        };
      }
    } catch {
      // ignore transient
    }

    // If an earlier operation in a sequential multi-op patch unlinked this exact single-link regular file,
    // treat it as missing so subsequent path components underneath it resolve identically to host execution.
    if (
      unlinkedRegularFileSet &&
      unlinkedRegularFileSet.size > 0 &&
      st.isFile() &&
      Number(st.nlink) === 1
    ) {
      const relCur = path.relative(canonicalRoot, realCursorResolved);
      if (isContainedRelativePath(relCur)) {
        const curRelPosix = toPosixRel(relCur);
        const curNorm = isWorkspaceCaseInsensitive(canonicalRoot)
          ? curRelPosix.toLowerCase()
          : curRelPosix;
        if (unlinkedRegularFileSet.has(curNorm)) {
          let realAncestor = canonicalRoot;
          if (i > 0) {
            try {
              realAncestor = fs.realpathSync.native(lastExistingDir);
            } catch {
              realAncestor = lastExistingDir;
            }
          }
          const effectiveAbs = path.join(realAncestor, ...segments.slice(i));
          const effectiveRelPosix = toPosixRel(path.relative(canonicalRoot, effectiveAbs));
          return {
            ok: true,
            exists: false,
            entryType: "missing",
            canonicalRoot,
            absPath: effectiveAbs,
            relPosix: effectiveRelPosix,
            lstat: null,
          };
        }
      }
    }

    if (!isLeaf && !st.isDirectory()) {
      return {
        ok: false,
        code: "NOT_A_DIRECTORY_ANCESTOR",
        reason: `Intermediate path component '${toPosixRel(path.relative(canonicalRoot, cursor))}' is not a directory.`,
        canonicalRoot,
        absCandidate,
        relPosix,
      };
    }
    if (!isLeaf) {
      lastExistingDir = cursor;
    }

    if (isLeaf) {
      let effectiveAbs = absCandidate;
      let effectiveRelPosix = relPosix;
      try {
        const realLeaf = fs.realpathSync.native(absCandidate);
        const relReal = path.relative(canonicalRoot, realLeaf);
        if (isContainedRelativePath(relReal)) {
          effectiveAbs = realLeaf;
          effectiveRelPosix = toPosixRel(relReal);
        }
      } catch {
        // keep lexical path
      }

      if (st.isDirectory()) {
        if (forWrite && !allowDirectoryLeaf) {
          return {
            ok: false,
            code: "DIRECTORY_WRITE_TARGET_UNSUPPORTED",
            reason: `Target '${effectiveRelPosix}' is an existing directory, not a regular file.`,
            canonicalRoot,
            absCandidate: effectiveAbs,
            relPosix: effectiveRelPosix,
            lstat: st,
          };
        }
        return {
          ok: true,
          exists: true,
          entryType: "directory",
          canonicalRoot,
          absPath: effectiveAbs,
          relPosix: effectiveRelPosix,
          lstat: st,
        };
      }

      if (!st.isFile()) {
        return {
          ok: false,
          code: "UNSUPPORTED_SPECIAL_FILE",
          reason: `Special filesystem entry '${effectiveRelPosix}' (FIFO/socket/device) is unsupported.`,
          canonicalRoot,
          absCandidate: effectiveAbs,
          relPosix: effectiveRelPosix,
          lstat: st,
        };
      }

      // Hardlink alias defense at EVERY write entry point (``)!
      if (Number(st.nlink) > 1) {
        return {
          ok: false,
          code: "UNSAFE_HARDLINK_ALIAS",
          reason: `File '${effectiveRelPosix}' has multiple hardlinks (nlink=${st.nlink}); refusing mutation to prevent alias tampering.`,
          canonicalRoot,
          absCandidate: effectiveAbs,
          relPosix: effectiveRelPosix,
          lstat: st,
        };
      }

      const metaCheck = checkUnsupportedFileMetadata(effectiveAbs, st, {
        checkXattr: checkPlatformAttrs,
        exemptXattrs,
      });
      if (!metaCheck.ok) {
        return {
          ok: false,
          code: metaCheck.code,
          reason: metaCheck.reason,
          canonicalRoot,
          absCandidate: effectiveAbs,
          relPosix: effectiveRelPosix,
          lstat: st,
        };
      }

      return {
        ok: true,
        exists: true,
        entryType: "file",
        canonicalRoot,
        absPath: effectiveAbs,
        relPosix: effectiveRelPosix,
        lstat: st,
      };
    }
  }

  return {
    ok: false,
    code: "INVALID_PATH_COMPONENT",
    reason: `Failed inspecting '${rawCandidatePath}'.`,
    canonicalRoot,
    absCandidate,
    relPosix,
  };
}

function findDarwinAclLine(lsStdout) {
  for (const ln of String(lsStdout || "").split(/\r?\n/)) {
    // `+` in mode column when no xattr masks it, OR indented numbered ACE line (` 0: ... allow|deny ...`) when `@` masks `+`!
    if (/^[dlcbps-][rwxstST-]{9}\+/.test(ln)) return ln.trim();
    if (/^\s+\d+:\s+\S+.*\b(?:allow|deny)\b/.test(ln)) return ln.trim();
  }
  return null;
}

/**
 * Single-entry metadata & ACL/xattr check (``):
 * Fails closed on privileged mode bits (`0o7000`), non-exempt extended attributes, ACLs, or inspector command failures.
 */
export function checkUnsupportedFileMetadata(
  absPath,
  lstat,
  { checkXattr = false, exemptXattrs = DEFAULT_EXEMPT_XATTRS } = {}
) {
  const modeNum = Number(lstat.mode);
  const specialBits = modeNum & 0o7000;
  if (specialBits !== 0) {
    return {
      ok: false,
      code: "UNSUPPORTED_METADATA_REQUIREMENT",
      reason: `Entry '${absPath}' carries privileged mode bits (0o${specialBits.toString(8)}) that cannot be losslessly restored in user-space.`,
    };
  }

  if (!checkXattr) {
    return { ok: true };
  }

  const exemptSet = new Set(exemptXattrs || []);

  if (process.platform === "darwin") {
    const xRes = spawnSync("/usr/bin/xattr", ["-s", absPath], { encoding: "utf8", timeout: 1500 });
    if (xRes.error || xRes.status !== 0) {
      return {
        ok: false,
        code: "UNSUPPORTED_METADATA_REQUIREMENT",
        reason: `Extended-attribute inspection failed on '${absPath}' (${xRes.error?.message || xRes.stderr || `exit ${xRes.status}`}); failing closed.`,
      };
    }
    const attrs = (xRes.stdout || "")
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean)
      .filter((name) => !exemptSet.has(name));
    if (attrs.length > 0) {
      return {
        ok: false,
        code: "UNSUPPORTED_METADATA_REQUIREMENT",
        reason: `Entry '${absPath}' carries extended attributes (${attrs.join(", ")}) that user-space replacement cannot losslessly preserve.`,
      };
    }

    const aclRes = spawnSync("/bin/ls", ["-led", absPath], { encoding: "utf8", timeout: 1500 });
    if (aclRes.error || aclRes.status !== 0) {
      return {
        ok: false,
        code: "UNSUPPORTED_METADATA_REQUIREMENT",
        reason: `ACL inspection failed on '${absPath}'; failing closed.`,
      };
    }
    const aclLine = findDarwinAclLine(aclRes.stdout);
    if (aclLine) {
      return {
        ok: false,
        code: "UNSUPPORTED_METADATA_REQUIREMENT",
        reason: `Entry '${absPath}' carries macOS ACL entries (${aclLine}) that user-space replacement cannot losslessly preserve.`,
      };
    }
    return { ok: true };
  }

  if (process.platform === "linux") {
    const xRes = spawnSync("getfattr", ["-h", "-d", "-m", "-", absPath], { encoding: "utf8", timeout: 1500 });
    if (xRes.error || xRes.status !== 0) {
      return {
        ok: false,
        code: "UNSUPPORTED_METADATA_REQUIREMENT",
        reason: `Linux extended-attribute inspection (getfattr) unavailable or failed on '${absPath}'; failing closed.`,
      };
    }
    const attrLines = (xRes.stdout || "")
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter((s) => s && !s.startsWith("# file:"))
      .map((s) => s.split("=")[0])
      .filter((name) => !exemptSet.has(name));
    if (attrLines.length > 0) {
      return {
        ok: false,
        code: "UNSUPPORTED_METADATA_REQUIREMENT",
        reason: `Entry '${absPath}' carries Linux extended attributes (${attrLines.join(", ")}) that user-space replacement cannot losslessly preserve.`,
      };
    }

    const aclRes = spawnSync("getfacl", ["-p", "-c", absPath], { encoding: "utf8", timeout: 1500 });
    if (aclRes.error || aclRes.status !== 0) {
      return {
        ok: false,
        code: "UNSUPPORTED_METADATA_REQUIREMENT",
        reason: `Linux POSIX ACL inspection (getfacl) unavailable or failed on '${absPath}'; failing closed.`,
      };
    }
    const nonBaseAcl = (aclRes.stdout || "")
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter((s) => s && !/^(?:user|group|other)::/.test(s));
    if (nonBaseAcl.length > 0) {
      return {
        ok: false,
        code: "UNSUPPORTED_METADATA_REQUIREMENT",
        reason: `Entry '${absPath}' carries non-default POSIX ACL entries (${nonBaseAcl[0]}).`,
      };
    }
    return { ok: true };
  }

  return {
    ok: false,
    code: "UNSUPPORTED_METADATA_REQUIREMENT",
    reason: `Lossless extended-attribute/ACL preflight is unsupported on platform '${process.platform}'.`,
  };
}

/**
 * Fast whole-tree extended-attribute and ACL preflight (``) for strict checkpoint scans:
 * Inspects ALL recoverable files, directories, and symlinks inside `canonicalRoot` (excluding `.git/` internals)
 * in 2 single batch syscalls/processes, failing closed on any inspector failure, ACL, or non-exempt xattr!
 */
export function inspectTreePlatformMetadata(
  canonicalRoot,
  { exemptXattrs = DEFAULT_EXEMPT_XATTRS, timeoutMs = 2500 } = {}
) {
  const exemptSet = new Set(exemptXattrs || []);
  const gitPrefix = `${canonicalRoot}${path.sep}.git`;

  // Check workspace root privileged mode bits (`0o7000`) (``, ``)
  try {
    const rootSt = fs.lstatSync(canonicalRoot);
    if ((rootSt.mode & 0o7000) !== 0) {
      return {
        ok: false,
        code: "UNSUPPORTED_METADATA_REQUIREMENT",
        reason: `Workspace root '${canonicalRoot}' carries privileged mode bits (0o${(rootSt.mode & 0o7777).toString(8)}) that cannot be losslessly restored.`,
      };
    }
  } catch (err) {
    return {
      ok: false,
      code: "UNSUPPORTED_METADATA_REQUIREMENT",
      reason: `Failed stating workspace root '${canonicalRoot}': ${err.message}`,
    };
  }

  // Only `.git/` internals are excluded from workspace rollback xattr/ACL preflight (since `.git` is hash-verified separately and never rolled back);
  // BOTH `canonicalRoot` (`.`) and `.blast-guard-session` ARE strictly inspected (``, ``)!
  const isIgnoredInternal = (absEntry) =>
    absEntry === gitPrefix || absEntry.startsWith(`${gitPrefix}${path.sep}`);

  if (process.platform === "darwin") {
    const xRes = spawnSync("/usr/bin/xattr", ["-sr", canonicalRoot], {
      encoding: "utf8",
      timeout: timeoutMs,
      maxBuffer: 8 * 1024 * 1024,
    });
    if (xRes.error || xRes.status !== 0) {
      return {
        ok: false,
        code: "UNSUPPORTED_METADATA_REQUIREMENT",
        reason: `Workspace extended-attribute preflight failed (${xRes.error?.message || xRes.stderr || `exit ${xRes.status}`}); failing closed.`,
      };
    }
    for (const rawLine of (xRes.stdout || "").split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line) continue;
      const sepIdx = line.lastIndexOf(": ");
      if (sepIdx === -1) continue;
      const entryPath = line.slice(0, sepIdx);
      const attrName = line.slice(sepIdx + 2).trim();
      if (isIgnoredInternal(entryPath)) continue;
      if (!exemptSet.has(attrName)) {
        const relLabel = entryPath === canonicalRoot ? "." : toPosixRel(path.relative(canonicalRoot, entryPath));
        return {
          ok: false,
          code: "UNSUPPORTED_METADATA_REQUIREMENT",
          reason: `Workspace entry '${relLabel}' carries unsupported extended attribute '${attrName}'.`,
        };
      }
    }

    // Check workspace root directory ACL itself via `/bin/ls -led` (``)
    const rootAclRes = spawnSync("/bin/ls", ["-led", canonicalRoot], {
      encoding: "utf8",
      timeout: timeoutMs,
    });
    if (rootAclRes.error || rootAclRes.status !== 0) {
      return {
        ok: false,
        code: "UNSUPPORTED_METADATA_REQUIREMENT",
        reason: `Workspace root ACL preflight failed (${rootAclRes.error?.message || rootAclRes.stderr || `exit ${rootAclRes.status}`}); failing closed.`,
      };
    }
    const rootAclLine = findDarwinAclLine(rootAclRes.stdout);
    if (rootAclLine) {
      return {
        ok: false,
        code: "UNSUPPORTED_METADATA_REQUIREMENT",
        reason: `Workspace root carries macOS ACL rules (${rootAclLine}) that user-space rollback cannot losslessly preserve.`,
      };
    }

    // Check all top-level non-.git entries (including `.blast-guard-session`) with `/bin/ls -leR`
    let topEntries = [];
    try {
      topEntries = fs
        .readdirSync(canonicalRoot)
        .filter((name) => name !== ".git")
        .map((name) => path.join(canonicalRoot, name));
    } catch (err) {
      return {
        ok: false,
        code: "UNSUPPORTED_METADATA_REQUIREMENT",
        reason: `Failed enumerating workspace root for ACL preflight: ${err.message}`,
      };
    }
    if (topEntries.length > 0) {
      const aclRes = spawnSync("/bin/ls", ["-leR", ...topEntries], {
        encoding: "utf8",
        timeout: timeoutMs,
        maxBuffer: 16 * 1024 * 1024,
      });
      if (aclRes.error || aclRes.status !== 0) {
        return {
          ok: false,
          code: "UNSUPPORTED_METADATA_REQUIREMENT",
          reason: `Workspace ACL preflight failed (${aclRes.error?.message || aclRes.stderr || `exit ${aclRes.status}`}); failing closed.`,
        };
      }
      const childAclLine = findDarwinAclLine(aclRes.stdout);
      if (childAclLine) {
        return {
          ok: false,
          code: "UNSUPPORTED_METADATA_REQUIREMENT",
          reason: `Workspace entry carries macOS ACL rules (${childAclLine}) that user-space rollback cannot losslessly preserve.`,
        };
      }
    }
    return { ok: true };
  }

  if (process.platform === "linux") {
    const xRes = spawnSync("getfattr", ["-R", "-h", "-d", "-m", "-", canonicalRoot], {
      encoding: "utf8",
      timeout: timeoutMs,
      maxBuffer: 8 * 1024 * 1024,
    });
    if (xRes.error || xRes.status !== 0) {
      return {
        ok: false,
        code: "UNSUPPORTED_METADATA_REQUIREMENT",
        reason: `Linux workspace extended-attribute preflight (getfattr) unavailable or failed; failing closed.`,
      };
    }
    let currentFile = "";
    for (const rawLine of (xRes.stdout || "").split(/\r?\n/)) {
      const ln = rawLine.trim();
      if (!ln) continue;
      if (ln.startsWith("# file:")) {
        currentFile = path.resolve("/", ln.slice("# file:".length).trim());
        continue;
      }
      if (isIgnoredInternal(currentFile)) continue;
      const attrName = ln.split("=")[0];
      if (attrName && !exemptSet.has(attrName)) {
        return {
          ok: false,
          code: "UNSUPPORTED_METADATA_REQUIREMENT",
          reason: `Workspace entry '${currentFile}' carries unsupported extended attribute '${attrName}'.`,
        };
      }
    }

    const aclRes = spawnSync("getfacl", ["-R", "-s", "-p", canonicalRoot], {
      encoding: "utf8",
      timeout: timeoutMs,
      maxBuffer: 8 * 1024 * 1024,
    });
    if (aclRes.error || aclRes.status !== 0) {
      return {
        ok: false,
        code: "UNSUPPORTED_METADATA_REQUIREMENT",
        reason: `Linux POSIX ACL preflight (getfacl) unavailable or failed; failing closed.`,
      };
    }
    if ((aclRes.stdout || "").trim().length > 0) {
      return {
        ok: false,
        code: "UNSUPPORTED_METADATA_REQUIREMENT",
        reason: "Workspace contains entries with non-trivial POSIX ACLs that user-space rollback cannot losslessly preserve.",
      };
    }
    return { ok: true };
  }

  return {
    ok: false,
    code: "UNSUPPORTED_METADATA_REQUIREMENT",
    reason: `Lossless metadata preflight is unsupported on platform '${process.platform}'.`,
  };
}
