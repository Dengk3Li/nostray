import path from "node:path";
import crypto from "node:crypto";
import { classifyProtectionRing, findMatchingGrant } from "./path-security.mjs";
import { extractPublicContracts } from "./code-scanner.mjs";

function resolveMention(mention, files) {
  if (files.includes(mention)) return [mention];
  if (mention.includes("/")) return [];
  const matches = files.filter(file => path.posix.basename(file) === mention);
  return matches.length === 1 ? matches : [];
}

export function buildScopePolicy(graph, { grants = [], referenceMentions = [], existing = null, turnId = 1, workspaceFiles = null } = {}) {
  const files = [...graph.forwardDeps.keys()];
  const anchors = [...new Set(grants.flatMap(grant => resolveMention(grant.pathPattern, files)))];
  const references = [...new Set([
    ...(existing?.references || []),
    ...referenceMentions.flatMap(mention => resolveMention(mention, workspaceFiles || files)),
  ])].filter(file => !findMatchingGrant(file, grants));
  const complete = !graph.truncated && !graph.unreadableDirectories && !graph.unreadableFiles && !graph.oversizedFiles && !graph.unparsedFiles && !graph.unresolvedImports && !graph.unparsedConfigurations;
  const leaseEvidence = anchors.map(file => ({ path: file, from: file, reason: "explicit-user-target", turnId }));
  if (complete) {
    for (const anchor of anchors) {
      for (const file of graph.forwardDeps.get(anchor) || []) {
        if (classifyProtectionRing(file).ring === "RING_1_CANDIDATE" && !references.includes(file)) {
          leaseEvidence.push({ path: file, from: anchor, reason: "one-hop-static-import", turnId });
        }
      }
    }
  }
  return {
    version: 1, turnId, complete, anchors, references, leaseEvidence,
    groups: graph.sccs.map(group => [...group].sort()),
    externalConsumers: [...graph.reverseCallers.entries()].map(([file, callers]) => [file, [...callers]]),
    frozenReferences: existing?.frozenReferences || [],
    observedReads: existing?.observedReads || [],
  };
}

export function observeScopeRead(policy, { file, text = null, turnId, grants = [] }) {
  const observedReads = [...new Set([...(policy.observedReads || []), file])].slice(-2000);
  const protectedPath = classifyProtectionRing(file).ring === "RING_0";
  const namedTypeFile = /(?:^|\/)(?:types?|typings|interfaces?)\.(?:ts|tsx|js|mjs|py)$/i.test(file);
  const scan = text === null ? { verdict: "UNKNOWN", exports: new Map() } : extractPublicContracts(text, file);
  const exportsTypes = scan.verdict !== "UNKNOWN" && [...scan.exports.values()].some(entry => ["interface", "type", "enum"].includes(entry.kind));
  const isReference = protectedPath || namedTypeFile || exportsTypes || policy.references.includes(file);
  if (!isReference || text === null || findMatchingGrant(file, grants)) return { ...policy, observedReads };
  if (policy.frozenReferences.some(entry => entry.path === file)) return { ...policy, observedReads };
  return {
    ...policy, observedReads,
    frozenReferences: [...policy.frozenReferences, {
      path: file, sha256: crypto.createHash("sha256").update(text).digest("hex"),
      exports: scan.verdict === "UNKNOWN" ? null : [...scan.exports].map(([name, entry]) => ({ name, signature: entry.signature })),
      parserVerdict: scan.verdict, readAtTurn: turnId, frozenAt: new Date().toISOString(),
    }],
  };
}

export function refactorBoundary(policy, workingSet, candidatePaths = []) {
  const seeds = policy.anchors.length ? policy.anchors : [...workingSet].slice(0, 1);
  if (!seeds.length && candidatePaths.length) seeds.push(candidatePaths[0]);
  const allowed = new Set(seeds);
  if (policy.complete) {
    for (const group of policy.groups) {
      if (group.some(file => seeds.includes(file))) for (const file of group) allowed.add(file);
    }
  }
  const external = new Map(policy.externalConsumers);
  const frozenExports = new Set([...allowed].filter(file => {
    const group = policy.groups.find(members => members.includes(file)) || [file];
    return !policy.complete || (external.get(file) || []).some(caller => !group.includes(caller));
  }));
  return { allowed, frozenExports };
}

export function createVoiEscalationCard(violations, { sessionId, turnId, workingSet = [], callerImpact = null } = {}) {
  const primary = violations[0];
  if (!primary || !primary.path || primary.path.startsWith("<")) return null;
  if (/IMMUTABLE|STATE_INTEGRITY|UNRESOLVED_PROHIBITION|EXPLICITLY_NEGATED_PATH/.test(primary.code)) return null;
  const protectedKind = /CONTRACT|EXPORT|TEST|FROZEN|REFACTOR|SCC/.test(primary.code);
  const ambiguity = protectedKind ? 2 : workingSet.includes(primary.path) ? 1 : 2;
  const irreversibleCost = /DELETION|WIPE|TEST/.test(primary.code) ? 3 : protectedKind || callerImpact?.transitiveCallers > 0 ? 2 : 1;
  const id = crypto.createHash("sha256").update(JSON.stringify([sessionId, turnId, primary.code, primary.path])).digest("hex").slice(0, 12);
  if (ambiguity * irreversibleCost < 4) return null;
  const pathText = primary.path;
  const isTest = classifyProtectionRing(pathText).category === "TEST_SUITE";
  const options = [{ id: "1", label: "继续在当前授权范围内修复", action: "keep-scope", grants: [] }];
  options.push({ id: "2", label: isTest ? `授权为 ${pathText} 添加测试，保留既有断言` : `授权修改 ${pathText}，保留既有接口`, action: "grant-file", path: pathText, allowExportChange: false });
  if (!isTest && /DELETION|WIPE/.test(primary.code)) options.push({ id: "3", label: `授权删除或整体重写 ${pathText}`, action: "grant-rewrite", path: pathText, allowFullRewrite: true });
  else if (!isTest && pathText.endsWith(".json") && /CONTRACT|SCHEMA|FROZEN/.test(primary.code)) options.push({ id: "3", label: `授权变更 ${pathText} 的 JSON 契约约束`, action: "grant-schema", path: pathText, allowSchemaKeywords: true });
  else if (!isTest && /EXPORT|CONTRACT|FROZEN/.test(primary.code)) options.push({ id: "3", label: `授权变更 ${pathText} 的公共接口`, action: "grant-export", path: pathText, allowExportChange: true });
  for (const option of options) option.reply = `BlastGuard approve ${id} ${option.id}`;
  return {
    schemaVersion: "blast-guard.escalation.v1", id, sessionId, turnId, status: "pending", path: pathText,
    reasonCode: primary.code, risk: { ambiguity, irreversibleCost, product: ambiguity * irreversibleCost,
      method: "ordinal heuristic; not a calibrated probability", evidence: { protectedKind, leased: workingSet.includes(pathText), directCallers: callerImpact?.directCallers ?? null, transitiveCallers: callerImpact?.transitiveCallers ?? null } },
    options,
  };
}

export function formatEscalationCard(card) {
  return [
    `需要确认对 ${card.path} 的授权。影响风险 ${card.risk.product}（歧义 ${card.risk.ambiguity} × 变更代价 ${card.risk.irreversibleCost}，规则估计）。`,
    ...card.options.map(option => `${option.id}. ${option.label}\n   回复 ${option.reply}`),
  ].join("\n");
}

export function resolveVoiApproval(card, rawPrompt, { isSynthetic = false, turnId = 1 } = {}) {
  if (!card || card.status !== "pending" || isSynthetic) return null;
  const option = card.options.find(item => item.reply === String(rawPrompt).trim());
  if (!option) return null;
  const grant = option.action === "keep-scope" ? null : {
    grantId: `card-${card.id}-${option.id}`, turnId, pathPattern: option.path, matchBasename: false,
    operations: option.allowFullRewrite ? ["read", "write", "rewrite", "delete"] : ["read", "write"], allowExportChange: Boolean(option.allowExportChange),
    allowFullRewrite: Boolean(option.allowFullRewrite), allowSchemaKeywords: Boolean(option.allowSchemaKeywords), allowTestWeakening: false, preserveExistingContracts: true,
    approvalCardId: card.id,
  };
  return { card: { ...card, status: "resolved", chosenOption: option.id, resolvedAtTurn: turnId }, grant };
}
