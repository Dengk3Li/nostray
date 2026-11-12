import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import {
  BLAST_GUARD_BIN_PATH,
  isVersionInBoundedRange,
  probeOsIsolationBackend,
  writeDurableFileAtomic,
} from "./runtime-support.mjs";
import { canonicalizeWorkspaceRoot } from "./path-security.mjs";
import {
  BOUNDED_HOST_RANGES,
  detectInstalledHostBinaryVersion,
  handleHostHookEvent,
} from "./hook-firewall.mjs";
import { SnapshotStore } from "./snapshot-store.mjs";
import { inspectSnapshotCoverage, snapshotSummary, describeShellMode } from "./readiness.mjs";
import { readHostStartupObservations } from "./hook-observation.mjs";

export const MANAGED_MARKER = "blast-guard:managed:v1";
export const GIT_DISPATCHER_HEADER = "# blast-guard:managed-git-dispatcher:v1";
export const GIT_ORIG_HOOK_FILENAME = "pre-commit.blast-guard-user-orig";
export const GIT_ORIG_META_FILENAME = "pre-commit.blast-guard-user-orig.meta.json";

// Legacy v0.1-draft inline markers kept solely for clean migration/uninstall if encountered
const LEGACY_GIT_BLOCK_START = `# >>> ${MANAGED_MARKER} start >>>`;
const LEGACY_GIT_BLOCK_END = `# <<< ${MANAGED_MARKER} end <<<`;

/**
 * Quote a POSIX shell argument safely (handling spaces, quotes, `$`, backticks, CJK paths).
 */
export function shellQuoteSingleArg(arg) {
  return `'${String(arg).replace(/'/g, `'\\''`)}'`;
}

export function buildPinnedLauncherCommand(subArgs = []) {
  const parts = [
    shellQuoteSingleArg(process.execPath),
    shellQuoteSingleArg(BLAST_GUARD_BIN_PATH),
    ...subArgs.map(shellQuoteSingleArg),
  ];
  return parts.join(" ");
}

const CLAUDE_EVENTS = Object.freeze([
  "UserPromptSubmit",
  "PreToolUse",
  "PostToolUse",
  "PostToolUseFailure",
  "Stop",
]);

const CODEX_EVENTS = Object.freeze([
  "UserPromptSubmit",
  "PreToolUse",
  "PostToolUse",
  "Stop",
]);

const CURSOR_EVENTS = Object.freeze([
  "beforeSubmitPrompt",
  "preToolUse",
  "postToolUse",
  "stop",
]);

function buildClaudeHookEntries() {
  const hooksObj = {};
  for (const ev of CLAUDE_EVENTS) {
    hooksObj[ev] = [
      {
        matcher: "*",
        _managedBy: MANAGED_MARKER,
        hooks: [
          {
            type: "command",
            command: buildPinnedLauncherCommand(["hook", "--host", "claude", "--event", ev]),
            onFailure: "block",
            _managedBy: MANAGED_MARKER,
          },
        ],
      },
    ];
  }
  return hooksObj;
}

function buildCodexHookEntries({ wrapShell = false } = {}) {
  const hooksObj = {};
  for (const ev of CODEX_EVENTS) {
    hooksObj[ev] = [
      {
        matcher: "*",
        _managedBy: MANAGED_MARKER,
        hooks: [
          {
            type: "command",
            command: buildPinnedLauncherCommand(["hook", "--host", "codex", "--event", ev, ...(wrapShell ? ["--wrap-shell"] : [])]),
            _managedBy: MANAGED_MARKER,
          },
        ],
      },
    ];
  }
  return hooksObj;
}

const ANTIGRAVITY_EVENTS = Object.freeze(["PreInvocation", "PreToolUse", "PostToolUse", "Stop"]);

function buildAntigravityGroup() {
  const group = { enabled: true, _managedBy: MANAGED_MARKER };
  for (const event of ANTIGRAVITY_EVENTS) {
    const handler = { type: "command", command: buildPinnedLauncherCommand(["hook", "--host", "antigravity", "--event", event]), timeout: 30 };
    group[event] = event === "PreToolUse" || event === "PostToolUse"
      ? [{ matcher: "*", hooks: [handler] }]
      : [handler];
  }
  return group;
}

function buildCursorHookEntries() {
  const hooksObj = {};
  for (const ev of CURSOR_EVENTS) {
    hooksObj[ev] = [
      {
        command: buildPinnedLauncherCommand(["hook", "--host", "cursor", "--event", ev]),
        failClosed: true,
        _managedBy: MANAGED_MARKER,
      },
    ];
  }
  return hooksObj;
}

function mergeJsonHookConfig(existingJsonText, desiredHooksByEvent, { isCursor = false } = {}) {
  let root = {};
  if (existingJsonText && existingJsonText.trim()) {
    root = JSON.parse(existingJsonText);
  }
  if (isCursor && root.version === undefined) {
    root.version = 1;
  }
  if (!root.hooks || typeof root.hooks !== "object" || Array.isArray(root.hooks)) {
    root.hooks = {};
  }

  for (const [ev, desiredArr] of Object.entries(desiredHooksByEvent)) {
    const existingArr = Array.isArray(root.hooks[ev]) ? root.hooks[ev] : [];
    const preservedUserEntries = existingArr.filter((item) => !isBlastGuardOwnedEntry(item));
    // Place BlastGuard entries FIRST so user hooks cannot short-circuit BlastGuard, while preserving user hook order!
    root.hooks[ev] = [...desiredArr, ...preservedUserEntries];
  }

  return JSON.stringify(root, null, 2) + "\n";
}

function removeManagedJsonHooks(existingJsonText) {
  if (!existingJsonText || !existingJsonText.trim()) return null;
  const root = JSON.parse(existingJsonText);
  if (!root.hooks || typeof root.hooks !== "object") {
    return JSON.stringify(root, null, 2) + "\n";
  }
  for (const ev of Object.keys(root.hooks)) {
    if (!Array.isArray(root.hooks[ev])) continue;
    root.hooks[ev] = root.hooks[ev].filter((item) => !isBlastGuardOwnedEntry(item));
    if (root.hooks[ev].length === 0) {
      delete root.hooks[ev];
    }
  }
  return JSON.stringify(root, null, 2) + "\n";
}

function isBlastGuardOwnedEntry(item) {
  if (!item || typeof item !== "object") return false;
  if (item._managedBy === MANAGED_MARKER) return true;
  if (
    Array.isArray(item.hooks) &&
    item.hooks.length > 0 &&
    item.hooks.every((h) => h?._managedBy === MANAGED_MARKER)
  ) {
    return true;
  }
  return false;
}

function resolveGitHooksDir(canonicalRoot) {
  const check = spawnSync("git", ["rev-parse", "--git-path", "hooks"], {
    cwd: canonicalRoot,
    encoding: "utf8",
    timeout: 2000,
  });
  if (check.error || check.status !== 0) return null;
  const raw = (check.stdout || "").trim();
  if (!raw) return null;
  return path.isAbsolute(raw) ? raw : path.resolve(canonicalRoot, raw);
}

/**
 * Ownership-tracked `/bin/sh` dispatcher for Git `pre-commit` (``):
 * - Always executes BlastGuard FIRST (`|| exit $?`) so an `exit 0` in the user's hook can never bypass BlastGuard.
 * - Preserves the user's original `pre-commit` file untouched in `pre-commit.blast-guard-user-orig`
 *   and executes it directly (`"$ORIG_HOOK" "$@"`) so Python (`#!/usr/bin/env python3`), Node (`#!/usr/bin/env node`),
 *   Bash, or compiled hooks execute under their exact native interpreter!
 */
export function buildGitPreCommitDispatcherScript() {
  const guardCmd = buildPinnedLauncherCommand(["hook", "--host", "git", "--event", "pre-commit"]);
  return [
    "#!/bin/sh",
    GIT_DISPATCHER_HEADER,
    "# Managed by BlastGuard: executes BlastGuard pre-commit gate first, then delegates to preserved user hook.",
    `${guardCmd} || exit $?`,
    "",
    'HOOK_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)',
    `ORIG_HOOK="$HOOK_DIR/${GIT_ORIG_HOOK_FILENAME}"`,
    'if [ -f "$ORIG_HOOK" ] && [ -x "$ORIG_HOOK" ]; then',
    '  "$ORIG_HOOK" "$@"',
    "  exit $?",
    "fi",
    "exit 0",
    "",
  ].join("\n");
}

function stripLegacyGitBlock(content) {
  if (!content) return "";
  const startIdx = content.indexOf(LEGACY_GIT_BLOCK_START);
  const endIdx = content.indexOf(LEGACY_GIT_BLOCK_END);
  if (startIdx === -1 || endIdx === -1 || endIdx < startIdx) return content;
  const before = content.slice(0, startIdx).replace(/\n+$/, "");
  const after = content.slice(endIdx + LEGACY_GIT_BLOCK_END.length).replace(/^\n+/, "");
  return [before, after].filter(Boolean).join("\n\n") + "\n";
}

/**
 * Validate that the installed hook configuration on disk is structurally complete and effective (``, ``).
 * Returns `{ state: "ABSENT" | "VALID" | "INVALID", reason?: string }`.
 */
export function validateEffectiveHostConfig(canonicalRoot, host) {
  if (!fs.existsSync(BLAST_GUARD_BIN_PATH)) {
    return {
      state: "INVALID",
      reason: `Pinned BlastGuard entrypoint '${BLAST_GUARD_BIN_PATH}' does not exist on disk.`,
    };
  }

  if (host === "antigravity") {
    const file = path.join(canonicalRoot, ".agents/hooks.json");
    if (!fs.existsSync(file)) return { state: "ABSENT" };
    try {
      const config = JSON.parse(fs.readFileSync(file, "utf8"));
      const group = config[MANAGED_MARKER];
      if (!group) return { state: "ABSENT" };
      if (group._managedBy !== MANAGED_MARKER) return { state: "INVALID", reason: "Antigravity hook name conflicts with an unmanaged group." };
      if (group.enabled === false) return { state: "INVALID", reason: "Antigravity BlastGuard hook group is disabled." };
      for (const event of ANTIGRAVITY_EVENTS) {
        const handlers = event === "PreToolUse" || event === "PostToolUse"
          ? group[event]?.find((entry) => entry.matcher === "*")?.hooks : group[event];
        const expected = buildPinnedLauncherCommand(["hook", "--host", "antigravity", "--event", event]);
        if (!Array.isArray(handlers) || !handlers.some((entry) => entry.command === expected)) {
          return { state: "INVALID", reason: `Antigravity missing managed ${event} handler.` };
        }
      }
      return { state: "VALID" };
    } catch (error) {
      return { state: "INVALID", reason: error.message };
    }
  }
  if (host === "claude" || host === "codex" || host === "cursor") {
    const relFile =
      host === "claude"
        ? ".claude/settings.json"
        : host === "codex"
          ? ".codex/hooks.json"
          : ".cursor/hooks.json";
    const absFile = path.join(canonicalRoot, relFile);
    if (!fs.existsSync(absFile)) {
      return { state: "ABSENT" };
    }

    let rawText = "";
    try {
      const lst = fs.lstatSync(absFile);
      if (!lst.isFile()) {
        return { state: "INVALID", reason: `'${relFile}' is not a regular file.` };
      }
      rawText = fs.readFileSync(absFile, "utf8");
    } catch (err) {
      return { state: "INVALID", reason: `Cannot read '${relFile}': ${err.message}` };
    }

    let parsed;
    try {
      parsed = JSON.parse(rawText);
    } catch (err) {
      return { state: "INVALID", reason: `'${relFile}' contains invalid JSON: ${err.message}` };
    }

    const hasAnyMarker = rawText.includes(MANAGED_MARKER);
    const hooksObj = parsed?.hooks;
    if (!hooksObj || typeof hooksObj !== "object" || Array.isArray(hooksObj)) {
      return hasAnyMarker
        ? { state: "INVALID", reason: `'${relFile}' has BlastGuard marker without valid 'hooks' object.` }
        : { state: "ABSENT" };
    }

    if (host === "cursor") {
      const anyManaged = CURSOR_EVENTS.some(
        (ev) => Array.isArray(hooksObj[ev]) && hooksObj[ev].some((it) => isBlastGuardOwnedEntry(it))
      );
      if (!anyManaged && !hasAnyMarker) return { state: "ABSENT" };
      if (parsed.version !== 1) {
        return { state: "INVALID", reason: `.cursor/hooks.json requires version === 1.` };
      }
      for (const ev of CURSOR_EVENTS) {
        const arr = hooksObj[ev];
        if (!Array.isArray(arr) || arr.length === 0) {
          return { state: "INVALID", reason: `.cursor/hooks.json missing required event '${ev}'.` };
        }
        const expectedCmd = buildPinnedLauncherCommand(["hook", "--host", "cursor", "--event", ev]);
        const match = arr.find(
          (it) =>
            isBlastGuardOwnedEntry(it) &&
            it.command === expectedCmd &&
            it.failClosed === true
        );
        if (!match) {
          return {
            state: "INVALID",
            reason: `.cursor/hooks.json event '${ev}' lacks effective failClosed BlastGuard command.`,
          };
        }
      }
      return { state: "VALID" };
    }

    const requiredEvents = host === "claude" ? CLAUDE_EVENTS : CODEX_EVENTS;
    const anyManaged = requiredEvents.some(
      (ev) => Array.isArray(hooksObj[ev]) && hooksObj[ev].some((it) => isBlastGuardOwnedEntry(it))
    );
    if (!anyManaged && !hasAnyMarker) return { state: "ABSENT" };

    const shellModes = new Set();
    for (const ev of requiredEvents) {
      const arr = hooksObj[ev];
      if (!Array.isArray(arr) || arr.length === 0) {
        return { state: "INVALID", reason: `'${relFile}' is missing required event '${ev}'.` };
      }
      const expectedCmd = buildPinnedLauncherCommand(["hook", "--host", host, "--event", ev]);
      const wrappedCmd = host === "codex" ? buildPinnedLauncherCommand(["hook", "--host", host, "--event", ev, "--wrap-shell"]) : expectedCmd;
      const handlers = arr.filter(entry => isBlastGuardOwnedEntry(entry) && entry.matcher === "*")
        .flatMap(entry => Array.isArray(entry.hooks) ? entry.hooks : [])
        .filter(hk => hk?.type === "command" && (hk.command === expectedCmd || hk.command === wrappedCmd) &&
          (host !== "claude" || hk.onFailure === "block"));
      if (!handlers.length) {
        return {
          state: "INVALID",
          reason: `'${relFile}' event '${ev}' lacks valid BlastGuard matcher='*' command entry.`,
        };
      }
      if (host === "codex") {
        for (const hk of handlers) shellModes.add(hk.command === wrappedCmd);
      }
    }
    if (shellModes.size > 1) return { state: "INVALID", reason: "Managed Codex hooks disagree about --wrap-shell." };
    return host === "codex" ? { state: "VALID", wrapShell: shellModes.has(true) } : { state: "VALID" };
  }

  if (host === "git") {
    const hooksDir = resolveGitHooksDir(canonicalRoot);
    if (!hooksDir) return { state: "ABSENT" };
    const hookPath = path.join(hooksDir, "pre-commit");
    if (!fs.existsSync(hookPath)) return { state: "ABSENT" };

    let lst;
    let content = "";
    try {
      lst = fs.lstatSync(hookPath);
      if (!lst.isFile()) {
        return { state: "INVALID", reason: `Git pre-commit hook '${hookPath}' is not a regular file.` };
      }
      content = fs.readFileSync(hookPath, "utf8");
    } catch (err) {
      return { state: "INVALID", reason: `Cannot read Git pre-commit hook: ${err.message}` };
    }

    const hasManagedMarker =
      content.includes(GIT_DISPATCHER_HEADER) || content.includes(LEGACY_GIT_BLOCK_START);
    if (!hasManagedMarker) {
      return { state: "ABSENT" };
    }

    if ((lst.mode & 0o111) === 0) {
      return { state: "INVALID", reason: "Git pre-commit hook lacks executable permission bits." };
    }

    const expectedGuardLine = `${buildPinnedLauncherCommand(["hook", "--host", "git", "--event", "pre-commit"])} || exit $?`;
    const nonCommentLines = content
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l.length > 0 && !l.startsWith("#"));

    if (!content.startsWith("#!/bin/sh\n" + GIT_DISPATCHER_HEADER) || nonCommentLines[0] !== expectedGuardLine) {
      return {
        state: "INVALID",
        reason: "Git pre-commit hook is not an effective top-of-file BlastGuard dispatcher.",
      };
    }

    const origPath = path.join(hooksDir, GIT_ORIG_HOOK_FILENAME);
    if (fs.existsSync(origPath)) {
      try {
        const origLst = fs.lstatSync(origPath);
        if (!origLst.isFile()) {
          return { state: "INVALID", reason: `Preserved hook '${GIT_ORIG_HOOK_FILENAME}' is not a regular file.` };
        }
      } catch (err) {
        return { state: "INVALID", reason: `Cannot stat '${GIT_ORIG_HOOK_FILENAME}': ${err.message}` };
      }
    }

    return { state: "VALID" };
  }

  return { state: "ABSENT" };
}

/**
 * Install or uninstall BlastGuard hooks across `claude`, `codex`, `cursor`, `git`, or `all`.
 * - `--dry-run` performs zero filesystem mutations.
 * - `--uninstall` removes only BlastGuard-managed entries and restores original Git `pre-commit` byte-for-byte.
 */
export function installOrUninstallHooks(
  workspaceRoot = process.cwd(),
  {
    host = "all",
    dryRun = false,
    uninstall = false,
    wrapShell = false,
  } = {}
) {
  const canonicalRoot = canonicalizeWorkspaceRoot(workspaceRoot);
  const targets =
    host === "all"
      ? ["claude", "codex", "cursor", "git", "antigravity"]
      : [String(host).toLowerCase()];

  const actions = [];

  for (const h of targets) {
    if (h === "antigravity") {
      const relFile = ".agents/hooks.json";
      const absFile = path.join(canonicalRoot, relFile);
      const exists = fs.existsSync(absFile);
      const before = exists ? fs.readFileSync(absFile, "utf8") : "";
      const config = before.trim() ? JSON.parse(before) : {};
      if (!config || typeof config !== "object" || Array.isArray(config)) throw new Error("Antigravity hooks must be a JSON object.");
      if (config[MANAGED_MARKER] && config[MANAGED_MARKER]._managedBy !== MANAGED_MARKER) throw new Error("Antigravity hook name conflicts with an unmanaged group; existing configuration preserved.");
      if (uninstall) delete config[MANAGED_MARKER];
      else config[MANAGED_MARKER] = buildAntigravityGroup();
      const after = JSON.stringify(config, null, 2) + "\n";
      if (!dryRun && (!uninstall || exists) && after !== before) writeDurableFileAtomic(absFile, Buffer.from(after), 0o644);
      actions.push({ host: h, file: relFile, status: dryRun ? (uninstall ? "dry-run-uninstall" : "dry-run-install") : uninstall ? (exists ? "uninstalled" : "noop-not-installed") : "installed" });
      continue;
    }
    if (h === "claude" || h === "codex" || h === "cursor") {
      const relFile =
        h === "claude"
          ? ".claude/settings.json"
          : h === "codex"
            ? ".codex/hooks.json"
            : ".cursor/hooks.json";
      const absFile = path.join(canonicalRoot, relFile);
      const exists = fs.existsSync(absFile);
      const beforeText = exists ? fs.readFileSync(absFile, "utf8") : "";

      if (uninstall) {
        if (!exists) {
          actions.push({ host: h, file: relFile, status: "noop-not-installed" });
          continue;
        }
        const nextText = removeManagedJsonHooks(beforeText);
        if (!dryRun && nextText !== beforeText) {
          writeDurableFileAtomic(absFile, Buffer.from(nextText, "utf8"), 0o644);
        }
        actions.push({
          host: h,
          file: relFile,
          status: dryRun ? "dry-run-uninstall" : nextText !== beforeText ? "uninstalled" : "noop",
        });
        continue;
      }

      const desired =
        h === "claude"
          ? buildClaudeHookEntries()
          : h === "codex"
            ? buildCodexHookEntries({ wrapShell })
            : buildCursorHookEntries();
      const nextText = mergeJsonHookConfig(beforeText, desired, { isCursor: h === "cursor" });
      if (!dryRun && nextText !== beforeText) {
        writeDurableFileAtomic(absFile, Buffer.from(nextText, "utf8"), 0o644);
      }
      actions.push({
        host: h,
        file: relFile,
        status: dryRun ? "dry-run-install" : nextText !== beforeText ? "installed" : "up-to-date",
      });
      continue;
    }

    if (h === "git") {
      const hooksDir = resolveGitHooksDir(canonicalRoot);
      if (!hooksDir) {
        actions.push({
          host: "git",
          file: null,
          status: "skipped-not-a-git-repo",
        });
        continue;
      }
      const hookPath = path.join(hooksDir, "pre-commit");
      const origPath = path.join(hooksDir, GIT_ORIG_HOOK_FILENAME);
      const metaPath = path.join(hooksDir, GIT_ORIG_META_FILENAME);

      let hookLst = null;
      try {
        hookLst = fs.lstatSync(hookPath);
      } catch (err) {
        if (err.code !== "ENOENT") throw err;
      }
      if (hookLst && hookLst.isSymbolicLink()) {
        const err = new Error(`Refusing to modify symlinked Git hook '${hookPath}'.`);
        err.code = "UNSAFE_LINK_ALIAS";
        throw err;
      }

      const exists = Boolean(hookLst);
      const beforeBuf = exists ? fs.readFileSync(hookPath) : null;
      const beforeText = beforeBuf ? beforeBuf.toString("utf8") : "";

      if (uninstall) {
        const isDispatcher = exists && beforeText.includes(GIT_DISPATCHER_HEADER);
        const isLegacy = exists && !isDispatcher && beforeText.includes(LEGACY_GIT_BLOCK_START);

        if (!isDispatcher && !isLegacy) {
          actions.push({ host: "git", file: hookPath, status: "noop-not-installed" });
          continue;
        }

        if (!dryRun) {
          if (isDispatcher) {
            let origExists = false;
            try {
              origExists = fs.lstatSync(origPath).isFile();
            } catch {
              origExists = false;
            }
            if (origExists) {
              let restoredMode = 0o755;
              try {
                if (fs.existsSync(metaPath)) {
                  const meta = JSON.parse(fs.readFileSync(metaPath, "utf8"));
                  if (typeof meta?.origMode === "number") {
                    restoredMode = meta.origMode & 0o7777;
                  }
                } else {
                  restoredMode = fs.statSync(origPath).mode & 0o7777;
                }
              } catch {
                restoredMode = 0o755;
              }
              const origBytes = fs.readFileSync(origPath);
              writeDurableFileAtomic(hookPath, origBytes, restoredMode);
              fs.unlinkSync(origPath);
            } else {
              fs.unlinkSync(hookPath);
            }
            if (fs.existsSync(metaPath)) {
              fs.unlinkSync(metaPath);
            }
          } else if (isLegacy) {
            const stripped = stripLegacyGitBlock(beforeText);
            const remainingNonComment = stripped
              .split(/\r?\n/)
              .map((l) => l.trim())
              .filter((l) => l && !l.startsWith("#!") && l !== "set -e");
            if (remainingNonComment.length === 0) {
              fs.unlinkSync(hookPath);
            } else {
              const origMode = hookLst.mode & 0o7777;
              writeDurableFileAtomic(hookPath, Buffer.from(stripped, "utf8"), origMode || 0o755);
            }
          }
        }

        actions.push({
          host: "git",
          file: hookPath,
          status: dryRun ? "dry-run-uninstall" : "uninstalled",
        });
        continue;
      }

      // Install Git dispatcher while preserving pre-existing user `pre-commit` hook byte-for-byte
      const dispatcherText = buildGitPreCommitDispatcherScript();
      const alreadyDispatcher = exists && beforeText.includes(GIT_DISPATCHER_HEADER);

      if (!dryRun) {
        fs.mkdirSync(hooksDir, { recursive: true });
        if (exists && !alreadyDispatcher) {
          // If migrating from legacy inline block, strip legacy block first before saving user hook
          const userHookBytes = beforeText.includes(LEGACY_GIT_BLOCK_START)
            ? Buffer.from(stripLegacyGitBlock(beforeText), "utf8")
            : beforeBuf;
          const origMode = hookLst.mode & 0o7777;
          const hasUserBody = userHookBytes.toString("utf8").trim().length > 0;
          if (hasUserBody) {
            writeDurableFileAtomic(origPath, userHookBytes, origMode);
            writeDurableFileAtomic(
              metaPath,
              Buffer.from(
                JSON.stringify({ origMode, savedAt: new Date().toISOString() }, null, 2) + "\n",
                "utf8"
              ),
              0o644
            );
          }
        }
        const needsWrite = !exists || beforeText !== dispatcherText || (hookLst.mode & 0o111) === 0;
        if (needsWrite) {
          writeDurableFileAtomic(hookPath, Buffer.from(dispatcherText, "utf8"), 0o755);
        }
      }

      actions.push({
        host: "git",
        file: hookPath,
        status: dryRun
          ? "dry-run-install"
          : !exists || beforeText !== dispatcherText || (hookLst.mode & 0o111) === 0
            ? "installed"
            : "up-to-date",
      });
    }
  }

  return {
    ok: true,
    workspaceRoot: canonicalRoot,
    dryRun,
    uninstall,
    actions,
  };
}

/**
 * Run self-contained crash-journal, post-crash concurrent drift, OS sandbox write-deny,
 * and concurrent live-file promotion fault-injection self-tests (``).
 * Every required probe MUST pass independently (never returning `ok: true` if OS sandbox is unavailable).
 */
export async function runFaultInjectionSelfTests() {
  const sbx = probeOsIsolationBackend();
  const probes = {
    osSandboxProbe: Boolean(sbx.available),
    crashMidRollbackProbe: false,
    postCrashConcurrentDriftProbe: false,
    unattestedLiveOverwriteProbe: false,
    concurrentPromotionRaceProbe: false,
  };

  if (!sbx.available) {
    return {
      ok: false,
      osSandboxAvailable: false,
      probes,
      reason: `OS isolation backend unavailable (${sbx.reason || "unverified"}); required fault-injection probes cannot pass.`,
    };
  }

  fs.mkdirSync(os.tmpdir(), { recursive: true });
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bg-fault-selftest-"));
  try {
    // ── Probe 1: Real SIGKILL-terminated child process mid-rollback -> reopened store fail-closed block -> clean `--recover`
    {
      const state1 = path.join(tmpRoot, "state-1");
      const ws1 = path.join(tmpRoot, "ws-1");
      fs.mkdirSync(ws1, { recursive: true });
      fs.writeFileSync(path.join(ws1, "contracts.schema.json"), '{"type":"object","required":["id"]}\n');
      fs.writeFileSync(path.join(ws1, "leaf.js"), "export function calc(x) { return x + 1; }\n");

      const storeModuleUrl = new URL("./snapshot-store.mjs", import.meta.url).href;
      const crashChildScript = `
        import fs from "node:fs";
        import path from "node:path";
        import { SnapshotStore } from ${JSON.stringify(storeModuleUrl)};
        const ws = process.argv[1];
        const state = process.argv[2];
        const store = new SnapshotStore(ws, { storeDir: state });
        await store.open();
        store.startOrUpdateTurn("Fix bug in leaf.js", { sessionId: "selftest-1" });
        store.writeSessionMarker("selftest-1");
        const tx = store.beginCommandTransaction({ sessionId: "selftest-1", toolUseId: "fault-1" });
        fs.writeFileSync(path.join(ws, "contracts.schema.json"), '{"type":"object"}\\n');
        fs.writeFileSync(path.join(ws, "rogue.txt"), "rogue\\n");
        try {
          store.reconcileCommandTransaction(tx.txId, { simulateCrashAfterFirstRestore: true });
        } catch (err) {
          if (err && err.code === "SIMULATED_ROLLBACK_CRASH") {
            process.kill(process.pid, "SIGKILL");
          }
        }
        process.exit(1);
      `;
      const crashChild = spawnSync(
        process.execPath,
        ["--input-type=module", "-e", crashChildScript, ws1, state1],
        { encoding: "utf8", timeout: 8000 }
      );
      const crashedAsExpected = crashChild.signal === "SIGKILL";

      // Reopen authoritative SQLite WAL from a fresh process handle (``)
      const reopenedStore = new SnapshotStore(ws1, { storeDir: state1 });
      await reopenedStore.open({ allowInitialize: false, expectExistingActiveSession: "selftest-1" });

      let blockedAsExpected = false;
      try {
        reopenedStore.beginCommandTransaction({ sessionId: "selftest-1", toolUseId: "fault-2" });
      } catch (err) {
        if (err.code === "UNRECOVERED_TRANSACTION") blockedAsExpected = true;
      }

      const rec = reopenedStore.recoverUnfinishedTransactions();
      reopenedStore.close();

      const restoredSchema = fs.readFileSync(path.join(ws1, "contracts.schema.json"), "utf8");
      const rogueGone = !fs.existsSync(path.join(ws1, "rogue.txt"));
      probes.crashMidRollbackProbe = Boolean(
        crashedAsExpected &&
          blockedAsExpected &&
          rec.ok &&
          restoredSchema === '{"type":"object","required":["id"]}\n' &&
          rogueGone
      );
      if (!probes.crashMidRollbackProbe) {
        return {
          ok: false,
          osSandboxAvailable: true,
          probes,
          reason: "Terminated-process mid-rollback crash & reopened recovery convergence probe failed.",
        };
      }
    }

    // ── Probe 2: Post-crash external concurrent edit -> quarantine without clobbering user edit
    {
      const state2 = path.join(tmpRoot, "state-2");
      const ws2 = path.join(tmpRoot, "ws-2");
      fs.mkdirSync(ws2, { recursive: true });
      fs.writeFileSync(path.join(ws2, "a.schema.json"), '{"type":"object","required":["id"]}\n');
      fs.writeFileSync(path.join(ws2, "z-notes.md"), "# Notes\nOriginal user note.\n");

      const store = new SnapshotStore(ws2, { storeDir: state2 });
      await store.open();
      store.startOrUpdateTurn("Fix leaf", { sessionId: "selftest-2" });
      const tx = store.beginCommandTransaction({ sessionId: "selftest-2", toolUseId: "fault-drift" });

      fs.writeFileSync(path.join(ws2, "a.schema.json"), '{"type":"object"}\n');
      fs.writeFileSync(path.join(ws2, "z-rogue.txt"), "bad\n");
      try {
        store.reconcileCommandTransaction(tx.txId, { simulateCrashAfterFirstRestore: true });
      } catch {
        // expected mid-rollback crash
      }

      // Concurrent external writer modifies untouched `z-notes.md` while journal is ROLLING_BACK
      fs.writeFileSync(path.join(ws2, "z-notes.md"), "# Notes\nConcurrent user edit after crash.\n");
      const recDrift = store.recoverUnfinishedTransactions();
      store.close();

      const noteSurvived =
        fs.readFileSync(path.join(ws2, "z-notes.md"), "utf8") ===
        "# Notes\nConcurrent user edit after crash.\n";
      probes.postCrashConcurrentDriftProbe = Boolean(
        !recDrift.ok &&
          Array.isArray(recDrift.recoveredTransactions) &&
          recDrift.recoveredTransactions.some(
            (r) =>
              r.code === "EXTERNAL_CONCURRENT_WRITE_DETECTED" &&
              r.quarantineDir &&
              fs.existsSync(r.quarantineDir)
          ) &&
          noteSurvived
      );
      if (!probes.postCrashConcurrentDriftProbe) {
        return {
          ok: false,
          osSandboxAvailable: true,
          probes,
          reason: "Post-crash external concurrent drift quarantine probe failed.",
        };
      }
    }

    // ── Probe 3 & 4: Unattested live overwrite refusal + real concurrent writer race before `promoteStagedBundle`
    {
      const state3 = path.join(tmpRoot, "state-3");
      const ws3 = path.join(tmpRoot, "ws-3");
      fs.mkdirSync(ws3, { recursive: true });
      fs.writeFileSync(path.join(ws3, "leaf.js"), "export function calc(x) { return x + 1; }\n");

      const store = new SnapshotStore(ws3, { storeDir: state3 });
      await store.open();
      store.startOrUpdateTurn("Fix bug in leaf.js", { sessionId: "selftest-3" });

      const unattestedRes = await store.runIsolatedCommand(
        [
          process.execPath,
          "-e",
          'require("node:fs").writeFileSync("leaf.js", "export function calc(x) { return x + 2; }\\n")',
        ],
        { sessionId: "selftest-3", promoteMode: "live", assumeSingleWriter: false }
      );
      probes.unattestedLiveOverwriteProbe = Boolean(
        unattestedRes.code === "EXISTING_FILE_OWNERSHIP_UNPROVEN" &&
          unattestedRes.promoted === false &&
          fs.readFileSync(path.join(ws3, "leaf.js"), "utf8") === "export function calc(x) { return x + 1; }\n"
      );
      if (!probes.unattestedLiveOverwriteProbe) {
        store.close();
        return {
          ok: false,
          osSandboxAvailable: true,
          probes,
          reason: "Unattested live overwrite refusal probe failed.",
        };
      }

      // Probe 4: Synchronized competing-writer process racing AT the promotion apply boundary (``, ``)
      store.startOrUpdateTurn("Add feature files a-added.js and z-collide.txt", { sessionId: "selftest-3" });
      const stagedAddRes = await store.runIsolatedCommand(
        [
          process.execPath,
          "-e",
          `const fs = require("node:fs");
           fs.writeFileSync("a-added.js", "export const ok = 1;\\n");
           fs.writeFileSync("z-collide.txt", "staged candidate\\n");`,
        ],
        { sessionId: "selftest-3", promoteMode: "staged" }
      );
      const conflictRes = store.promoteStagedBundle(stagedAddRes.txId, {
        _beforeApplyEntryHook: (relPosix) => {
          if (relPosix === "z-collide.txt") {
            // Separate competing OS writer creates `z-collide.txt` after `a-added.js` was already linked!
            spawnSync(
              process.execPath,
              [
                "-e",
                'require("node:fs").writeFileSync(process.argv[1], "external competing writer\\n")',
                path.join(ws3, "z-collide.txt"),
              ],
              { stdio: "ignore", timeout: 4000 }
            );
          }
        },
      });

      // Also verify competing in-place overwrite on an already-linked promotion entry is preserved (``)!
      const stagedInPlaceRes = await store.runIsolatedCommand(
        [
          process.execPath,
          "-e",
          `const fs = require("node:fs");
           fs.writeFileSync("b-inplace.txt", "staged b\\n");
           fs.writeFileSync("z-collide2.txt", "staged z2\\n");`,
        ],
        { sessionId: "selftest-3", promoteMode: "staged" }
      );
      const inPlaceConflictRes = store.promoteStagedBundle(stagedInPlaceRes.txId, {
        _beforeApplyEntryHook: (relPosix) => {
          if (relPosix === "z-collide2.txt") {
            spawnSync(
              process.execPath,
              [
                "-e",
                `const fs = require("node:fs");
                 fs.writeFileSync(process.argv[1], "external precious b\\n");
                 fs.writeFileSync(process.argv[2], "external precious z2\\n");`,
                path.join(ws3, "b-inplace.txt"),
                path.join(ws3, "z-collide2.txt"),
              ],
              { stdio: "ignore", timeout: 4000 }
            );
          }
        },
      });
      store.close();

      probes.concurrentPromotionRaceProbe = Boolean(
        !conflictRes.ok &&
          conflictRes.code === "CONCURRENT_EDIT_CONFLICT" &&
          conflictRes.rolledBack === true &&
          conflictRes.quarantineDir &&
          fs.existsSync(conflictRes.quarantineDir) &&
          !fs.existsSync(path.join(ws3, "a-added.js")) &&
          fs.existsSync(path.join(ws3, "z-collide.txt")) &&
          fs.readFileSync(path.join(ws3, "z-collide.txt"), "utf8") === "external competing writer\n" &&
          !inPlaceConflictRes.ok &&
          inPlaceConflictRes.code === "EXTERNAL_CONCURRENT_WRITE_DETECTED" &&
          inPlaceConflictRes.rolledBack === false &&
          fs.existsSync(path.join(ws3, "b-inplace.txt")) &&
          fs.readFileSync(path.join(ws3, "b-inplace.txt"), "utf8") === "external precious b\n" &&
          fs.readFileSync(path.join(ws3, "z-collide2.txt"), "utf8") === "external precious z2\n"
      );
      if (!probes.concurrentPromotionRaceProbe) {
        return {
          ok: false,
          osSandboxAvailable: true,
          probes,
          reason: "Concurrent live-file promotion race quarantine probe failed.",
        };
      }
    }

    return {
      ok: true,
      osSandboxAvailable: true,
      probes,
    };
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
}

/**
 * Live Git E2E pre-commit harness (``, ``):
 * Copies the ACTUAL installed `pre-commit` dispatcher from `canonicalRoot` into an ephemeral Git repo
 * (with external `BLAST_GUARD_STATE_DIR` strictly outside the workspace), verifies:
 * 1. Positive control: compliant leaf commit exits `0`, advances `HEAD`, AND executes a preserved `#!/usr/bin/env node` original hook.
 * 2. Adversarial denial + unreachable-guard proof: even with an `exit 0` original hook present, a staged Ring-0 schema `required` removal
 *    exits non-zero without spawn/timeout error, emits `[BlastGuard` on stderr, leaves `HEAD` unchanged, and preserves unstaged user files!
 */
function runLiveGitE2eHarness(canonicalRoot, gitBinary) {
  const installedHooksDir = resolveGitHooksDir(canonicalRoot);
  const installedHookPath = installedHooksDir ? path.join(installedHooksDir, "pre-commit") : null;
  if (!installedHookPath || !fs.existsSync(installedHookPath)) {
    return { ok: false, detail: "Installed Git pre-commit hook not found in target repository." };
  }

  fs.mkdirSync(os.tmpdir(), { recursive: true });
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bg-git-e2e-"));
  const wsDir = path.join(tmpRoot, "ws");
  const extStateDir = path.join(tmpRoot, "ext-state");
  fs.mkdirSync(wsDir, { recursive: true });

  try {
    const gitEnv = {
      ...process.env,
      GIT_AUTHOR_NAME: "BlastGuard Test",
      GIT_AUTHOR_EMAIL: "test@example.com",
      GIT_COMMITTER_NAME: "BlastGuard Test",
      GIT_COMMITTER_EMAIL: "test@example.com",
      BLAST_GUARD_STATE_DIR: extStateDir,
    };

    const initRes = spawnSync(gitBinary, ["init"], { cwd: wsDir, env: gitEnv, stdio: "pipe", timeout: 4000 });
    if (initRes.error || initRes.status !== 0) {
      return { ok: false, detail: "Failed initializing temporary Git repository for E2E verification." };
    }

    const schemaPath = path.join(wsDir, "order.schema.json");
    const leafPath = path.join(wsDir, "leaf.js");
    fs.writeFileSync(schemaPath, '{"type":"object","required":["orderId"]}\n', "utf8");
    fs.writeFileSync(leafPath, "export function total(x) { return x; }\n", "utf8");
    spawnSync(gitBinary, ["add", "order.schema.json", "leaf.js"], { cwd: wsDir, env: gitEnv, stdio: "pipe" });
    const seedCommit = spawnSync(gitBinary, ["commit", "-m", "initial"], {
      cwd: wsDir,
      env: gitEnv,
      encoding: "utf8",
      timeout: 4000,
    });
    if (seedCommit.error || seedCommit.status !== 0) {
      return { ok: false, detail: "Failed creating seed commit in temporary Git repository." };
    }
    const head0 = spawnSync(gitBinary, ["rev-parse", "HEAD"], {
      cwd: wsDir,
      env: gitEnv,
      encoding: "utf8",
    }).stdout.trim();

    // Copy the ACTUAL installed `pre-commit` bytes and mode from `canonicalRoot`!
    const tmpHooksDir = path.join(wsDir, ".git", "hooks");
    fs.mkdirSync(tmpHooksDir, { recursive: true });
    const installedBytes = fs.readFileSync(installedHookPath);
    const installedMode = fs.statSync(installedHookPath).mode & 0o7777;
    const targetHookPath = path.join(tmpHooksDir, "pre-commit");
    fs.writeFileSync(targetHookPath, installedBytes, { mode: installedMode });
    fs.chmodSync(targetHookPath, installedMode);

    // Step 1: Positive control with a non-shell (`#!/usr/bin/env node` / node shebang) preserved hook!
    const canaryMarker = path.join(tmpHooksDir, "orig-canary.ran");
    const nodeOrigScript = `#!${process.execPath}\nrequire("node:fs").writeFileSync(${JSON.stringify(canaryMarker)}, "ok\\n");\nprocess.exit(0);\n`;
    const tmpOrigPath = path.join(tmpHooksDir, GIT_ORIG_HOOK_FILENAME);
    fs.writeFileSync(tmpOrigPath, nodeOrigScript, { mode: 0o755 });
    fs.chmodSync(tmpOrigPath, 0o755);

    fs.writeFileSync(leafPath, "export function total(x) { return Number(x); }\n", "utf8");
    spawnSync(gitBinary, ["add", "leaf.js"], { cwd: wsDir, env: gitEnv, stdio: "pipe" });
    const posCommit = spawnSync(gitBinary, ["commit", "-m", "valid leaf update"], {
      cwd: wsDir,
      env: gitEnv,
      encoding: "utf8",
      timeout: 5000,
    });
    const head1 = spawnSync(gitBinary, ["rev-parse", "HEAD"], {
      cwd: wsDir,
      env: gitEnv,
      encoding: "utf8",
    }).stdout.trim();

    if (posCommit.error || posCommit.status !== 0 || !head1 || head1 === head0 || !fs.existsSync(canaryMarker)) {
      return {
        ok: false,
        detail: `Positive-control Git commit failed (status=${posCommit.status}, canary=${fs.existsSync(canaryMarker)}, stderr=${(posCommit.stderr || "").trim()}).`,
      };
    }

    // Step 2: Adversarial Ring-0 schema `required` removal with an `exit 0` preserved hook!
    fs.writeFileSync(tmpOrigPath, "#!/bin/sh\nexit 0\n", { mode: 0o755 });
    fs.chmodSync(tmpOrigPath, 0o755);
    fs.writeFileSync(schemaPath, '{"type":"object","required":[]}\n', "utf8");
    spawnSync(gitBinary, ["add", "order.schema.json"], { cwd: wsDir, env: gitEnv, stdio: "pipe" });
    const unstagedNote = path.join(wsDir, "notes.txt");
    fs.writeFileSync(unstagedNote, "my precious unstaged note\n", "utf8");

    const negCommit = spawnSync(gitBinary, ["commit", "-m", "tamper schema"], {
      cwd: wsDir,
      env: gitEnv,
      encoding: "utf8",
      timeout: 5000,
    });
    const headAfterNeg = spawnSync(gitBinary, ["rev-parse", "HEAD"], {
      cwd: wsDir,
      env: gitEnv,
      encoding: "utf8",
    }).stdout.trim();
    const noteSurvived = fs.readFileSync(unstagedNote, "utf8") === "my precious unstaged note\n";
    const combinedOutput = `${negCommit.stderr || ""}\n${negCommit.stdout || ""}`;
    const recognizableDenial =
      combinedOutput.includes("[BlastGuard") &&
      combinedOutput.includes("FROZEN_CONTRACT_READONLY");

    const ok = Boolean(
      !negCommit.error &&
        negCommit.signal === null &&
        negCommit.status !== 0 &&
        recognizableDenial &&
        headAfterNeg === head1 &&
        noteSurvived
    );

    return {
      ok,
      positiveControlPassed: true,
      adversarialDenialVerified: ok,
      detail: ok
        ? "Installed Git `pre-commit` dispatcher passed positive commit + non-shell hook chaining AND aborted violating staged schema edit with recognizable BlastGuard denial while leaving HEAD and unstaged files intact."
        : `Adversarial Git commit probe did not produce verified BlastGuard denial (status=${negCommit.status}, recognizable=${recognizableDenial}, headUnchanged=${headAfterNeg === head1}).`,
    };
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
}

/**
 * Inspect installed host configurations and optionally execute adapter + fault-injection + live host E2E probes (``, ``, ``).
 */
const STARTUP_HOSTS = ["claude", "codex", "cursor", "git", "antigravity"];

export function inspectStartupReadiness(workspaceRoot, { host = null, sessionId = null, storeDir = null, snapshot = null, configs = {} } = {}) {
  if (host !== null && !STARTUP_HOSTS.includes(host)) throw new Error("Unknown --host; choose claude, codex, cursor, git or antigravity.");
  const root = canonicalizeWorkspaceRoot(workspaceRoot);
  const receipts = readHostStartupObservations(root, { host, sessionId, storeDir });
  const hosts = {};
  for (const name of host ? [host] : STARTUP_HOSTS) {
    const cfg = configs[name] || validateEffectiveHostConfig(root, name);
    const observation = receipts.observations.find(item => item.host === name) ?? null;
    if (!host && cfg.state === "ABSENT" && !observation) continue;
    hosts[name] = {
      configState: cfg.state,
      observation,
      shell: describeShellMode(name, { configured: cfg.state === "VALID", wrapShell: cfg.wrapShell }),
    };
  }
  return {
    selectedHost: host, sessionId, hosts,
    snapshot: snapshot ? snapshotSummary(snapshot) : inspectSnapshotCoverage(root, storeDir),
    observationErrors: receipts.errors,
  };
}

export async function inspectHostInstallations(
  workspaceRoot = process.cwd(),
  { runLiveVerify = false, storeDir = null, host = null, sessionId = null } = {}
) {
  const canonicalRoot = canonicalizeWorkspaceRoot(workspaceRoot);
  const hosts = {};
  const configs = {};

  let faultTestResult = null;
  if (runLiveVerify) {
    faultTestResult = await runFaultInjectionSelfTests();
  }

  for (const h of STARTUP_HOSTS) {
    const cfg = validateEffectiveHostConfig(canonicalRoot, h);
    configs[h] = cfg;
    // Keep ordinary `status` and `audit` 100% read-only (`persistCache: runLiveVerify`) (`New `)
    const verInfo = detectInstalledHostBinaryVersion(h, {
      cacheDir: storeDir,
      persistCache: Boolean(runLiveVerify),
    });
    const range = BOUNDED_HOST_RANGES[h];
    const inBoundedRange = verInfo.found
      ? isVersionInBoundedRange(verInfo.tuple, range.min, range.maxExclusive)
      : false;
    const versionStatus = !verInfo.found
      ? "HOST_BINARY_NOT_FOUND"
      : inBoundedRange
        ? "BOUNDED_SUPPORTED"
        : "UNTESTED_HOST_VERSION";

    const baseEvidence = {
      binary: verInfo.binary,
      binaryRealpath: verInfo.binaryRealpath,
      binarySha256: verInfo.binarySha256,
      detectedVersion: verInfo.rawVersion,
      versionSource: h === "codex" ? "PATH_CANDIDATE" : "INSTALLED_BINARY",
      testedVersionRange: range.label,
      configValid: cfg.state === "VALID",
      adapterWireProbeOk: null,
      adapterWireProbeKind: "synthetic",
      faultInjectionOk: faultTestResult ? Boolean(faultTestResult.ok) : null,
      liveHostE2eOk: null,
    };

    if (cfg.state === "ABSENT") {
      hosts[h] = {
        configured: false,
        tier: "UNPROTECTED",
        hostBinaryFound: verInfo.found,
        detectedVersion: verInfo.rawVersion,
        testedVersionRange: range.label,
        versionStatus,
        verificationEvidence: baseEvidence,
      };
      continue;
    }

    if (cfg.state === "INVALID") {
      hosts[h] = {
        configured: true,
        tier: "DEGRADED_SELF_TEST_FAILED",
        hostBinaryFound: verInfo.found,
        detectedVersion: verInfo.rawVersion,
        testedVersionRange: range.label,
        versionStatus,
        verificationEvidence: baseEvidence,
        note: `Invalid or ineffective hook configuration: ${cfg.reason}`,
      };
      continue;
    }

    // Offline status reports the PATH candidate. Codex hook events separately
    // identify the actual running ancestor and fail closed if it is unverified.
    if (!verInfo.found || !inBoundedRange) {
      hosts[h] = {
        configured: true,
        tier: "UNTESTED_HOST_VERSION",
        hostBinaryFound: verInfo.found,
        detectedVersion: verInfo.rawVersion,
        testedVersionRange: range.label,
        versionStatus,
        verificationEvidence: baseEvidence,
        note: h === "codex"
          ? `The Codex PATH candidate ${verInfo.found ? `(${verInfo.rawVersion}) is outside` : "was not found in"} the tested range (${range.label}). Hook events independently check their actual running Codex ancestor.`
          : !verInfo.found
            ? `Host '${h}' binary was not found on PATH; hook execution fails closed with UNTESTED_HOST_VERSION until a binary in (${range.label}) is installed.`
            : `Installed '${h}' binary (${verInfo.rawVersion}) is outside bounded verified range (${range.label}); hook execution fails closed with UNTESTED_HOST_VERSION.`,
      };
      continue;
    }

    if (!runLiveVerify) {
      hosts[h] = {
        configured: true,
        tier: "CONFIGURED",
        hostBinaryFound: verInfo.found,
        detectedVersion: verInfo.rawVersion,
        testedVersionRange: range.label,
        versionStatus,
        verificationEvidence: baseEvidence,
      };
      continue;
    }

    const wireProbe = await runSyntheticAdapterWireProbe(h);
    baseEvidence.adapterWireProbeOk = wireProbe.ok;
    const adapterAndFaultOk = Boolean(wireProbe.ok && faultTestResult?.ok);

    let tier = adapterAndFaultOk ? "ADAPTER_SELF_TESTED" : "DEGRADED_SELF_TEST_FAILED";
    let e2eNote = adapterAndFaultOk
      ? `Adapter positive+negative wire controls, OS sandbox, SIGKILL crash & competing-writer promotion probes passed; bound to ${verInfo.binaryRealpath} (${verInfo.rawVersion}). Synthetic adapter input does not prove host binary honoring or running-host identity.`
      : `Self-test failed: ${wireProbe.reason || faultTestResult?.reason || "probe failure"}`;

    if (adapterAndFaultOk && h === "git") {
      const gitE2e = runLiveGitE2eHarness(canonicalRoot, verInfo.binary);
      baseEvidence.liveHostE2eOk = gitE2e.ok;
      if (gitE2e.ok) {
        tier = "HOST_E2E_VERIFIED";
        e2eNote = gitE2e.detail;
      } else {
        tier = "DEGRADED_SELF_TEST_FAILED";
        e2eNote = gitE2e.detail;
      }
    }

    hosts[h] = {
      configured: true,
      tier,
      hostBinaryFound: verInfo.found,
      detectedVersion: verInfo.rawVersion,
      testedVersionRange: range.label,
      versionStatus,
      adapterProbeOk: wireProbe.ok,
      faultInjectionOk: Boolean(faultTestResult?.ok),
      verificationEvidence: baseEvidence,
      note: e2eNote,
    };
  }

  const tierRank = {
    UNPROTECTED: 0,
    DEGRADED_SELF_TEST_FAILED: 1,
    UNTESTED_HOST_VERSION: 2,
    CONFIGURED: 3,
    ADAPTER_SELF_TESTED: 4,
    HOST_E2E_VERIFIED: 5,
  };

  let bestTier = "UNPROTECTED";
  for (const info of Object.values(hosts)) {
    const rank = tierRank[info.tier] ?? 0;
    if (rank > tierRank[bestTier]) {
      bestTier = info.tier;
    }
  }

  return {
    workspaceRoot: canonicalRoot,
    overallTier: bestTier,
    readiness: inspectStartupReadiness(canonicalRoot, { host, sessionId, storeDir, configs }),
    osIsolation: runLiveVerify
      ? { verified: true, ...probeOsIsolationBackend() }
      : {
          verified: false,
          available: null,
          backend: null,
          reason: "Read-only inspection; pass --verify to execute live OS sandbox probe.",
        },
    faultInjection: faultTestResult,
    hosts,
  };
}

export async function runSyntheticAdapterWireProbe(host) {
  const result = await runSyntheticAdapterWireProbeImpl(host);
  return { ...result, synthetic: true, validationScope: "adapter-protocol-only", realHostVerified: false };
}

async function runSyntheticAdapterWireProbeImpl(host) {
  if (host === "git") {
    return { ok: true };
  }
  fs.mkdirSync(os.tmpdir(), { recursive: true });
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), `bg-wire-${host}-`));
  const tmpWs = path.join(tmpRoot, "ws");
  const extState = path.join(tmpRoot, "ext-state");
  fs.mkdirSync(tmpWs, { recursive: true });

  const invokeHookCli = async (eventName, payloadObj) => {
    if (host === "codex") {
      // This checks the adapter in isolation, not an actual Codex process. The
      // internal-only JS override must never become a CLI flag or env escape hatch.
      const wire = await handleHostHookEvent({
        host, event: eventName, rawStdin: JSON.stringify(payloadObj),
        workspaceRoot: tmpWs, storeDir: extState,
        _testHostVersionOverride: BOUNDED_HOST_RANGES.codex.min.join("."),
      });
      return {
        status: wire.exitCode,
        stdout: wire.stdoutObj == null ? "" : JSON.stringify(wire.stdoutObj) + "\n",
        stderr: wire.diagnostic ? wire.diagnostic + "\n" : "",
      };
    }
    if (host === "antigravity") {
      eventName = eventName === "UserPromptSubmit" ? "PreInvocation" : eventName;
      const input = payloadObj.tool_input || {};
      payloadObj = {
        conversationId: payloadObj.session_id, workspacePaths: [tmpWs], lastUserInput: payloadObj.prompt,
        stepIdx: payloadObj.tool_use_id === "wire-allow-1" ? 1 : 2,
        toolCall: payloadObj.tool_name === "Edit"
          ? { name: "replace_file_content", args: { TargetFile: input.file_path, TargetContent: input.old_string, ReplacementContent: input.new_string, StartLine: 1, EndLine: 1 } }
          : { name: "write_to_file", args: { TargetFile: input.file_path, CodeContent: input.content } },
      };
    }
    return spawnSync(
      process.execPath,
      [BLAST_GUARD_BIN_PATH, "hook", "--host", host, "--event", eventName],
      {
        cwd: tmpWs,
        input: JSON.stringify(payloadObj),
        env: {
          ...process.env,
          BLAST_GUARD_STATE_DIR: extState,
        },
        encoding: "utf8",
        timeout: 5000,
      }
    );
  };

  try {
    fs.writeFileSync(path.join(tmpWs, "order.schema.json"), '{"type":"object","required":["id"]}\n');
    fs.writeFileSync(path.join(tmpWs, "leaf.js"), "export function calc(x) { return x + 1; }\n");

    const promptEvent = host === "cursor" ? "beforeSubmitPrompt" : "UserPromptSubmit";
    const preEvent = host === "cursor" ? "preToolUse" : "PreToolUse";
    const postEvent = host === "cursor" ? "postToolUse" : "PostToolUse";

    // 1. Initialize attested session via UserPromptSubmit / beforeSubmitPrompt
    const rPrompt = await invokeHookCli(promptEvent, {
      cwd: tmpWs,
      session_id: "wire-probe",
      hook_event_name: promptEvent,
      prompt: "Fix bug in leaf.js",
    });
    if (rPrompt.error || rPrompt.status !== 0 || (rPrompt.stderr && rPrompt.stderr.trim() !== "")) {
      return { ok: false, reason: `Prompt hook failed: ${rPrompt.stderr || rPrompt.error?.message}` };
    }
    const promptOut = rPrompt.stdout.trim() ? JSON.parse(rPrompt.stdout) : null;
    if (promptOut?.decision === "block") {
      return { ok: false, reason: `Prompt hook unexpectedly blocked: ${promptOut.reason}` };
    }

    // 2. Positive control: compliant Edit on `leaf.js` MUST be allowed (``)
    const rAllow = await invokeHookCli(preEvent, {
      cwd: tmpWs,
      session_id: "wire-probe",
      hook_event_name: preEvent,
      tool_name: "Edit",
      tool_use_id: "wire-allow-1",
      tool_input: {
        file_path: "leaf.js",
        old_string: "return x + 1;",
        new_string: "return x + 2;",
      },
    });
    if (rAllow.error || rAllow.status !== 0 || (rAllow.stderr && rAllow.stderr.trim() !== "")) {
      return { ok: false, reason: `Positive-control PreToolUse failed: ${rAllow.stderr || rAllow.error?.message}` };
    }
    if (host === "cursor") {
      const allowOut = JSON.parse(rAllow.stdout);
      if (allowOut?.permission !== "allow") {
        return { ok: false, reason: `Positive-control Cursor preToolUse did not allow: ${rAllow.stdout}` };
      }
    } else if (host === "antigravity") {
      if (JSON.parse(rAllow.stdout).decision !== "allow") return { ok: false, reason: `Antigravity positive control denied: ${rAllow.stdout}` };
    } else if (rAllow.stdout.trim() !== "") {
      return { ok: false, reason: `Positive-control ${host} PreToolUse unexpectedly emitted denial: ${rAllow.stdout}` };
    }

    // 3. Reconcile positive-control transaction via PostToolUse
    fs.writeFileSync(path.join(tmpWs, "leaf.js"), "export function calc(x) { return x + 2; }\n");
    const rPost = await invokeHookCli(postEvent, {
      cwd: tmpWs,
      session_id: "wire-probe",
      hook_event_name: postEvent,
      tool_name: "Edit",
      tool_use_id: "wire-allow-1",
    });
    if (rPost.error || rPost.status !== 0 || (rPost.stderr && rPost.stderr.trim() !== "")) {
      return { ok: false, reason: `Positive-control PostToolUse failed: ${rPost.stderr || rPost.error?.message}` };
    }
    if (rPost.stdout.trim() !== "") {
      const postOut = JSON.parse(rPost.stdout);
      if (postOut?.decision === "block") {
        return { ok: false, reason: `Positive-control PostToolUse unexpectedly blocked: ${postOut.reason}` };
      }
    }

    // 4. Negative control: ungranted Ring-0 contract write MUST be denied with exact `FROZEN_CONTRACT_READONLY` (``)
    const rDeny = await invokeHookCli(preEvent, {
      cwd: tmpWs,
      session_id: "wire-probe",
      hook_event_name: preEvent,
      tool_name: "Write",
      tool_use_id: "wire-deny-1",
      tool_input: {
        file_path: "order.schema.json",
        content: '{"type":"object"}\n',
      },
    });
    if (rDeny.error || rDeny.status !== 0 || (rDeny.stderr && rDeny.stderr.trim() !== "")) {
      return { ok: false, reason: `Negative-control PreToolUse failed: ${rDeny.stderr || rDeny.error?.message}` };
    }
    const parsed = JSON.parse(rDeny.stdout);
    if (host === "cursor") {
      const ok =
        parsed.permission === "deny" &&
        typeof parsed.agent_message === "string" &&
        parsed.agent_message.includes("FROZEN_CONTRACT_READONLY");
      return ok
        ? { ok: true }
        : { ok: false, reason: `Unexpected Cursor denial payload: ${rDeny.stdout}` };
    }
    if (host === "antigravity") {
      return { ok: parsed.decision === "deny" && parsed.reason?.includes("FROZEN_CONTRACT_READONLY"), reason: parsed.reason };
    }
    const ok =
      parsed?.hookSpecificOutput?.permissionDecision === "deny" &&
      typeof parsed?.hookSpecificOutput?.permissionDecisionReason === "string" &&
      parsed.hookSpecificOutput.permissionDecisionReason.includes("FROZEN_CONTRACT_READONLY");
    return ok
      ? { ok: true }
      : { ok: false, reason: `Unexpected ${host} denial payload: ${rDeny.stdout}` };
  } catch (err) {
    return { ok: false, reason: err.message };
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
}
