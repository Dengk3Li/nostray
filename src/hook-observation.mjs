import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { SnapshotStore } from "./snapshot-store.mjs";
import { writeDurableFileAtomic } from "./runtime-support.mjs";

const SCHEMA = "blast-guard.host-startup.v1";
const STARTUP_EVENTS = new Set(["UserPromptSubmit", "beforeSubmitPrompt", "PreInvocation"]);
const HOSTS = new Set(["claude", "codex", "cursor", "antigravity"]);

function observationFilename(host, sessionId) {
  return `${createHash("sha256").update(JSON.stringify([host, sessionId])).digest("hex")}.json`;
}

/** Diagnostic receipt only. It does not attest later tool calls or provide a security boundary. */
export function recordHostStartupObservation(store, {
  host, event, sessionId, hostVersion, hostIdentity = null, snapshot, shell,
  isSynthetic = false, versionOverrideUsed = false,
}) {
  if (isSynthetic || versionOverrideUsed || !HOSTS.has(host) || !STARTUP_EVENTS.has(event)) return null;
  if (host === "codex" && (!hostIdentity?.found || hostIdentity.detectionSource !== "running-parent")) return null;
  const observation = {
    schemaVersion: SCHEMA,
    workspaceRoot: store.canonicalRoot,
    workspaceId: store.workspaceId,
    host,
    sessionId,
    event,
    observedAt: new Date().toISOString(),
    hostVersion,
    identityEvidence: host === "codex" ? "codex-running-parent-confirmed" : "hook-event-received",
    diagnosticOnly: true,
    startupEventOnly: true,
    preToolUseVerified: false,
    snapshot: {
      coverageComplete: snapshot.coverageComplete === true,
      incompleteCode: snapshot.incompleteCode || null,
      incompleteReason: snapshot.incompleteReason || null,
      blockingFile: snapshot.blockingFile || null,
    },
    shell: { mode: shell.mode, description: shell.description },
  };
  const receiptPath = path.join(store.storeDir, "hook-observations", observationFilename(host, sessionId));
  writeDurableFileAtomic(receiptPath, Buffer.from(JSON.stringify(observation) + "\n"));
  return observation;
}

/** Reads JSON receipts without opening SQLite, creating directories, or touching WAL/SHM files. */
export function readHostStartupObservations(workspaceRoot, { host = null, sessionId = null, storeDir = null } = {}) {
  let store;
  try {
    store = new SnapshotStore(workspaceRoot, storeDir ? { storeDir } : {});
  } catch (error) {
    return { workspaceRoot, state: "UNREADABLE", observations: [], errors: [{ code: error.code || "OBSERVATION_READ_FAILED", message: error.message }] };
  }
  const result = { workspaceRoot: store.canonicalRoot, state: "NOT_OBSERVED", observations: [], errors: [] };
  const directory = path.join(store.storeDir, "hook-observations");
  let filenames;
  try {
    if (!fs.lstatSync(directory).isDirectory()) throw new Error("Startup receipt path is not a directory.");
    filenames = fs.readdirSync(directory).filter((name) => /^[a-f0-9]{64}\.json$/.test(name));
  } catch (error) {
    if (error.code === "ENOENT") return result;
    return { ...result, state: "UNREADABLE", errors: [{ code: error.code || "OBSERVATION_READ_FAILED", message: error.message }] };
  }
  for (const filename of filenames) {
    const receiptPath = path.join(directory, filename);
    try {
      const stat = fs.lstatSync(receiptPath);
      if (!stat.isFile() || stat.size > 64 * 1024) throw new Error("Invalid or oversized startup receipt.");
      const observation = JSON.parse(fs.readFileSync(receiptPath, "utf8"));
      if (observation.schemaVersion !== SCHEMA || observation.workspaceId !== store.workspaceId ||
          observation.workspaceRoot !== store.canonicalRoot || !HOSTS.has(observation.host) ||
          typeof observation.sessionId !== "string" || !STARTUP_EVENTS.has(observation.event) ||
          typeof observation.hostVersion !== "string" || !observation.hostVersion ||
          typeof observation.snapshot?.coverageComplete !== "boolean" ||
          typeof observation.shell?.mode !== "string" || typeof observation.shell?.description !== "string" ||
          !Number.isFinite(Date.parse(observation.observedAt)) || observation.diagnosticOnly !== true ||
          observation.startupEventOnly !== true || observation.preToolUseVerified !== false ||
          filename !== observationFilename(observation.host, observation.sessionId) ||
          observation.identityEvidence !== (observation.host === "codex" ? "codex-running-parent-confirmed" : "hook-event-received")) {
        throw new Error("Startup receipt identity or scope is invalid.");
      }
      if ((!host || observation.host === host) && (!sessionId || observation.sessionId === sessionId)) {
        result.observations.push(observation);
      }
    } catch (error) {
      result.errors.push({ path: receiptPath, code: error.code || "OBSERVATION_READ_FAILED", message: error.message });
    }
  }
  result.observations.sort((a, b) => b.observedAt.localeCompare(a.observedAt));
  result.state = result.errors.length ? "UNREADABLE" : result.observations.length ? "OBSERVED" : "NOT_OBSERVED";
  return result;
}
