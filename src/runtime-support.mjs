import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

export const MIN_NODE_VERSION = [22, 13, 0];

const THIS_FILE = fileURLToPath(import.meta.url);
export const BLAST_GUARD_PACKAGE_ROOT = fs.realpathSync.native(
  path.resolve(path.dirname(THIS_FILE), "..")
);
export const BLAST_GUARD_BIN_PATH = path.join(
  BLAST_GUARD_PACKAGE_ROOT,
  "bin",
  "blast-guard.mjs"
);

export function parseSemverTuple(raw) {
  const cleaned = String(raw || "").trim().replace(/^v/i, "");
  const m = cleaned.match(/(\d+)\.(\d+)\.(\d+)/);
  if (!m) return null;
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}

export function compareSemver(a, b) {
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  }
  return 0;
}

export function isVersionInBoundedRange(tuple, minTuple, maxExclusiveTuple) {
  if (!tuple) return false;
  return (
    compareSemver(tuple, minTuple) >= 0 &&
    compareSemver(tuple, maxExclusiveTuple) < 0
  );
}

let cachedDatabaseSync = null;

export async function loadSqliteDatabaseSync() {
  if (cachedDatabaseSync) return cachedDatabaseSync;
  const runtimeCheck = verifyRuntimeSupport();
  if (!runtimeCheck.ok) {
    const err = new Error(runtimeCheck.reason);
    err.code = runtimeCheck.code;
    throw err;
  }
  const sqliteMod = await import("node:sqlite");
  if (typeof sqliteMod.DatabaseSync !== "function") {
    const err = new Error("node:sqlite DatabaseSync API is unavailable in this Node runtime.");
    err.code = "UNSUPPORTED_NODE_SQLITE";
    throw err;
  }
  cachedDatabaseSync = sqliteMod.DatabaseSync;
  return cachedDatabaseSync;
}

export function verifyRuntimeSupport(versionString = process.versions.node) {
  const tuple = parseSemverTuple(versionString);
  if (!tuple || compareSemver(tuple, MIN_NODE_VERSION) < 0) {
    return {
      ok: false,
      code: "UNSUPPORTED_NODE_RUNTIME",
      reason: `blast-guard requires Node.js >= ${MIN_NODE_VERSION.join(".")} (for unflagged node:sqlite). Detected: ${versionString}`,
    };
  }
  return { ok: true, nodeVersion: versionString, tuple };
}

export function resolveStateBaseDir() {
  const envDir = process.env.BLAST_GUARD_STATE_DIR;
  if (envDir && envDir.trim()) {
    return path.resolve(envDir.trim());
  }
  return path.join(os.homedir(), ".blast-guard", "stores");
}

export function computeWorkspaceId(canonicalRoot) {
  return crypto
    .createHash("sha256")
    .update(`blast-guard:ws:v1:${canonicalRoot}`)
    .digest("hex")
    .slice(0, 24);
}

export function resolveWorkspaceStoreDir(canonicalRoot) {
  const baseDir = resolveStateBaseDir();
  const wsId = computeWorkspaceId(canonicalRoot);
  return {
    workspaceId: wsId,
    storeDir: path.join(baseDir, wsId),
    baseDir,
  };
}

export function fsyncDirectoryBestEffort(dirPath) {
  let fd = null;
  try {
    fd = fs.openSync(dirPath, fs.constants.O_RDONLY);
    fs.fsyncSync(fd);
  } catch (err) {
    // Some filesystems return EINVAL/EBADF on directory fsync; propagate ENOSPC/EIO.
    if (err && (err.code === "ENOSPC" || err.code === "EIO" || err.code === "EROFS")) {
      throw err;
    }
  } finally {
    if (fd !== null) {
      try {
        fs.closeSync(fd);
      } catch {
        // ignore close error
      }
    }
  }
}

export function writeDurableFileAtomic(targetPath, buffer, mode = 0o600) {
  const dir = path.dirname(targetPath);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const rand = crypto.randomBytes(6).toString("hex");
  const tmpPath = path.join(dir, `.bg-tmp.${process.pid}.${rand}`);
  let fd = null;
  try {
    fd = fs.openSync(
      tmpPath,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL,
      mode
    );
    let offset = 0;
    while (offset < buffer.length) {
      offset += fs.writeSync(fd, buffer, offset, buffer.length - offset);
    }
    fs.fchmodSync(fd, mode);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = null;
    fs.renameSync(tmpPath, targetPath);
    fsyncDirectoryBestEffort(dir);
  } catch (err) {
    if (fd !== null) {
      try {
        fs.closeSync(fd);
      } catch {
        // ignore
      }
    }
    try {
      fs.unlinkSync(tmpPath);
    } catch {
      // ignore
    }
    throw err;
  }
}

export function escapeSeatbeltLiteral(p) {
  return String(p).replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

const SEATBELT_SAFE_WRITE_DEVICES = [
  "/dev/null",
  "/dev/zero",
  "/dev/tty",
  "/dev/dtracehelper",
];

function expandCanonicalPathVariants(paths) {
  const out = new Set();
  for (const raw of paths) {
    if (!raw) continue;
    const norm = path.resolve(String(raw));
    out.add(norm);
    try {
      out.add(fs.realpathSync.native(norm));
    } catch {
      // Non-existent path: keep lexical normalized form
    }
  }
  return Array.from(out);
}

/**
 * Build a global write-deny Seatbelt SBPL profile (``):
 * Denies ALL filesystem writes globally (`(deny file-write*)`), permits writes ONLY inside
 * `allowedWritePaths` (staging + private TMPDIR) and safe character devices, and re-asserts
 * `(deny file-write*)` on `protectedPaths` afterward as defense-in-depth override.
 */
export function buildSeatbeltProfile({
  protectedPaths = [],
  allowedWritePaths = [],
  denyNetwork = false,
}) {
  const lines = [
    "(version 1)",
    "(allow default)",
    "(deny file-write*)",
  ];
  if (denyNetwork) {
    lines.push("(deny network*)");
  }
  for (const dev of SEATBELT_SAFE_WRITE_DEVICES) {
    const lit = escapeSeatbeltLiteral(dev);
    lines.push(`(allow file-write* (literal "${lit}"))`);
  }
  const dedupAllowed = expandCanonicalPathVariants(
    allowedWritePaths.filter((p) => !SEATBELT_SAFE_WRITE_DEVICES.includes(p))
  );
  for (const p of dedupAllowed) {
    const lit = escapeSeatbeltLiteral(p);
    lines.push(`(allow file-write* (subpath "${lit}") (literal "${lit}"))`);
  }
  const dedupProtected = expandCanonicalPathVariants(protectedPaths);
  for (const p of dedupProtected) {
    const lit = escapeSeatbeltLiteral(p);
    lines.push(`(deny file-write* (subpath "${lit}") (literal "${lit}"))`);
  }
  return lines.join("\n") + "\n";
}

let cachedSandboxProbe = null;

export function probeOsIsolationBackend({ forceRefresh = false } = {}) {
  if (process.env.BLAST_GUARD_FORCE_NO_SANDBOX === "1") {
    return {
      available: false,
      backend: null,
      code: "ISOLATION_BACKEND_UNAVAILABLE",
      reason: "OS sandbox disabled via BLAST_GUARD_FORCE_NO_SANDBOX=1.",
    };
  }
  if (cachedSandboxProbe && !forceRefresh) {
    return cachedSandboxProbe;
  }

  let probeRoot;
  let unrelatedRoot;
  try {
    fs.mkdirSync(os.tmpdir(), { recursive: true });
    probeRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bg-sbx-probe-"));
    unrelatedRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bg-sbx-unrel-"));
  } catch (err) {
    return {
      available: false,
      backend: null,
      code: "ISOLATION_BACKEND_UNAVAILABLE",
      reason: `Unable to allocate temporary probe directory in os.tmpdir(): ${err.message}`,
    };
  }
  try {
    const realProbeRoot = fs.realpathSync.native(probeRoot);
    const realUnrelatedRoot = fs.realpathSync.native(unrelatedRoot);
    const forbiddenWorkspaceDir = path.join(realProbeRoot, "live-workspace");
    const forbiddenStateDir = path.join(realProbeRoot, "state-store");
    const forbiddenHostCfgDir = path.join(realProbeRoot, "host-config");
    const allowedDir = path.join(realProbeRoot, "allowed-staging");
    fs.mkdirSync(forbiddenWorkspaceDir, { recursive: true });
    fs.mkdirSync(forbiddenStateDir, { recursive: true });
    fs.mkdirSync(forbiddenHostCfgDir, { recursive: true });
    fs.mkdirSync(allowedDir, { recursive: true });

    const sentinelFile = path.join(forbiddenWorkspaceDir, "sentinel.txt");
    const stateSentinel = path.join(forbiddenStateDir, "state.txt");
    const cfgSentinel = path.join(forbiddenHostCfgDir, "hooks.json");
    const unrelatedFile = path.join(realUnrelatedRoot, "outside-everything.txt");
    const okFile = path.join(allowedDir, "ok.txt");
    fs.writeFileSync(sentinelFile, "immutable\n", "utf8");
    fs.writeFileSync(stateSentinel, "state-ok\n", "utf8");
    fs.writeFileSync(cfgSentinel, "{}\n", "utf8");

    if (process.platform === "darwin" && fs.existsSync("/usr/bin/sandbox-exec")) {
      const profile = buildSeatbeltProfile({
        protectedPaths: [
          forbiddenWorkspaceDir,
          forbiddenStateDir,
          forbiddenHostCfgDir,
          BLAST_GUARD_PACKAGE_ROOT,
        ],
        allowedWritePaths: [allowedDir],
      });
      // Probe 1: protected workspace/state/config paths MUST deny writes
      const denyProtected = spawnSync(
        "/usr/bin/sandbox-exec",
        [
          "-p",
          profile,
          process.execPath,
          "-e",
          `const fs = require("node:fs");
           let anyWrote = false;
           for (const p of ${JSON.stringify([sentinelFile, stateSentinel, cfgSentinel])}) {
             try { fs.writeFileSync(p, "tampered"); anyWrote = true; } catch {}
           }
           process.exit(anyWrote ? 0 : 42);`,
        ],
        { stdio: "pipe", timeout: 4000 }
      );
      // Probe 2: arbitrary unrelated filesystem location outside protectedPaths MUST ALSO deny writes!
      const denyUnrelated = spawnSync(
        "/usr/bin/sandbox-exec",
        [
          "-p",
          profile,
          process.execPath,
          "-e",
          `require("node:fs").writeFileSync(${JSON.stringify(unrelatedFile)}, "escaped")`,
        ],
        { stdio: "pipe", timeout: 4000 }
      );
      // Probe 3: allowed staging write MUST succeed
      const allowRes = spawnSync(
        "/usr/bin/sandbox-exec",
        [
          "-p",
          profile,
          process.execPath,
          "-e",
          `require("node:fs").writeFileSync(${JSON.stringify(okFile)}, "ok")`,
        ],
        { stdio: "pipe", timeout: 4000 }
      );
      if (
        denyProtected.status === 42 &&
        fs.readFileSync(sentinelFile, "utf8") === "immutable\n" &&
        fs.readFileSync(stateSentinel, "utf8") === "state-ok\n" &&
        fs.readFileSync(cfgSentinel, "utf8") === "{}\n" &&
        denyUnrelated.status !== 0 &&
        !fs.existsSync(unrelatedFile) &&
        allowRes.status === 0 &&
        fs.existsSync(okFile)
      ) {
        cachedSandboxProbe = {
          available: true,
          backend: "darwin-seatbelt",
          binary: "/usr/bin/sandbox-exec",
        };
        return cachedSandboxProbe;
      }
      cachedSandboxProbe = {
        available: false,
        backend: null,
        code: "ISOLATION_BACKEND_UNAVAILABLE",
        reason: "macOS sandbox-exec failed global write-deny verification probe.",
      };
      return cachedSandboxProbe;
    }

    if (process.platform === "linux") {
      const bwrapCheck = spawnSync("which", ["bwrap"], { encoding: "utf8", timeout: 2000 });
      const bwrapBin = bwrapCheck.status === 0 ? bwrapCheck.stdout.trim() : "";
      if (bwrapBin) {
        const pidCheck = spawnSync(
          bwrapBin,
          [
            "--ro-bind", "/", "/",
            "--dev", "/dev",
            "--proc", "/proc",
            "--unshare-pid",
            "--die-with-parent",
            process.execPath,
            "-e",
            "process.exit(0)",
          ],
          { stdio: "pipe", timeout: 3000 }
        );
        const bwrapPidArgs = pidCheck.status === 0 ? ["--unshare-pid", "--die-with-parent"] : [];
        const baseBwrapArgs = [
          "--ro-bind", "/", "/",
          "--bind", allowedDir, allowedDir,
          "--dev", "/dev",
          "--proc", "/proc",
          ...bwrapPidArgs,
        ];
        const denyProtected = spawnSync(
          bwrapBin,
          [
            ...baseBwrapArgs,
            process.execPath,
            "-e",
            `require("node:fs").writeFileSync(${JSON.stringify(sentinelFile)}, "tampered")`,
          ],
          { stdio: "pipe", timeout: 4000 }
        );
        const denyUnrelated = spawnSync(
          bwrapBin,
          [
            ...baseBwrapArgs,
            process.execPath,
            "-e",
            `require("node:fs").writeFileSync(${JSON.stringify(unrelatedFile)}, "escaped")`,
          ],
          { stdio: "pipe", timeout: 4000 }
        );
        const allowRes = spawnSync(
          bwrapBin,
          [
            ...baseBwrapArgs,
            process.execPath,
            "-e",
            `require("node:fs").writeFileSync(${JSON.stringify(okFile)}, "ok")`,
          ],
          { stdio: "pipe", timeout: 4000 }
        );
        if (
          denyProtected.status !== 0 &&
          fs.readFileSync(sentinelFile, "utf8") === "immutable\n" &&
          denyUnrelated.status !== 0 &&
          !fs.existsSync(unrelatedFile) &&
          allowRes.status === 0 &&
          fs.existsSync(okFile)
        ) {
          cachedSandboxProbe = {
            available: true,
            backend: "linux-bwrap",
            binary: bwrapBin,
            bwrapPidArgs,
          };
          return cachedSandboxProbe;
        }
      }
    }

    cachedSandboxProbe = {
      available: false,
      backend: null,
      code: "ISOLATION_BACKEND_UNAVAILABLE",
      reason: `No verified kernel isolation backend available on ${process.platform}.`,
    };
    return cachedSandboxProbe;
  } finally {
    try {
      fs.rmSync(probeRoot, { recursive: true, force: true });
    } catch {
      // ignore cleanup
    }
    try {
      fs.rmSync(unrelatedRoot, { recursive: true, force: true });
    } catch {
      // ignore cleanup
    }
  }
}

export function shouldUseColor(stream = process.stdout) {
  if (process.env.NO_COLOR !== undefined) return false;
  if (process.env.FORCE_COLOR === "0") return false;
  if (process.env.FORCE_COLOR && process.env.FORCE_COLOR !== "0") return true;
  return Boolean(stream && stream.isTTY);
}

export function sanitizeTerminalText(str) {
  // Strip raw ESC/OSC/CSI terminal injection sequences from untrusted repo commit titles or filenames
  return String(str ?? "").replace(/[\u0000-\u0008\u000B-\u001F\u007F-\u009F]/g, "");
}

export function streamSha256File(filePath, maxBytes = Infinity) {
  const hash = crypto.createHash("sha256");
  const fd = fs.openSync(filePath, fs.constants.O_RDONLY);
  const buf = Buffer.allocUnsafe(65536);
  let totalBytes = 0;
  try {
    while (true) {
      const bytesRead = fs.readSync(fd, buf, 0, buf.length, null);
      if (bytesRead === 0) break;
      totalBytes += bytesRead;
      if (totalBytes > maxBytes) {
        return { oversize: true, size: totalBytes, sha256: null };
      }
      hash.update(buf.subarray(0, bytesRead));
    }
    return { oversize: false, size: totalBytes, sha256: hash.digest("hex") };
  } finally {
    fs.closeSync(fd);
  }
}
