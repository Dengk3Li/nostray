import path from "node:path";
import crypto from "node:crypto";
import { classifyProtectionRing, findMatchingGrant } from "./path-security.mjs";
import {
  SUPPORTED_JS_TS_EXTS,
  SUPPORTED_PYTHON_EXTS,
  compareCodeExports,
  verifyAdditiveTestConservation,
} from "./code-scanner.mjs";
import {
  verifyMarkdownSectionConservation,
  verifyEpistemicAndNumericAnchors,
} from "./doc-conservation.mjs";
import { verifyJsonConservation } from "./json-conservation.mjs";
import { refactorBoundary } from "./scope-policy.mjs";

function getNonEmptyLines(text) {
  if (!text) return [];
  return String(text)
    .replace(/\r\n/g, "\n")
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
}

export function computeLineDeletionMetrics(baselineText, candidateText) {
  const bLines = getNonEmptyLines(baselineText);
  const cLines = getNonEmptyLines(candidateText);
  if (bLines.length === 0) {
    return { baselineCount: 0, candidateCount: cLines.length, deletedCount: 0, deletedRatio: 0 };
  }
  const freq = new Map();
  for (const line of cLines) {
    freq.set(line, (freq.get(line) || 1 - 1) + 1);
  }
  let survived = 0;
  for (const line of bLines) {
    const rem = freq.get(line) || 0;
    if (rem > 0) {
      survived++;
      freq.set(line, rem - 1);
    }
  }
  const deletedCount = bLines.length - survived;
  return {
    baselineCount: bLines.length,
    candidateCount: cLines.length,
    deletedCount,
    deletedRatio: deletedCount / bLines.length,
  };
}

function isSupportedParserCodeFile(relPosix) {
  const ext = path.posix.extname(relPosix).toLowerCase();
  return SUPPORTED_JS_TS_EXTS.has(ext) || SUPPORTED_PYTHON_EXTS.has(ext);
}

function isUnsupportedCodeExtension(relPosix) {
  return /\.(?:rs|go|java|c|cc|cpp|h|hpp|cs|rb|php|swift|kt|scala)$/i.test(relPosix);
}

function isTestConfigOrHookFilename(relPosix) {
  const lowerBase = path.posix.basename(relPosix).toLowerCase();
  if (lowerBase === "conftest.py" || lowerBase === "pytest.ini") return true;
  const isActualTestFile =
    /\.(?:test|spec)\.[a-z0-9]+$/i.test(lowerBase) ||
    /^test_.*\.py$/i.test(lowerBase) ||
    /^.*_test\.(?:py|go|rs)$/i.test(lowerBase);
  return !isActualTestFile;
}

/**
 * Evaluate a complete candidate write-set atomically against Four-Ring path rules,
 * whole-transaction lease budgets, dual baselines (`commandCheckpoint` & `taskBaseline`),
 * and parser-backed code/test/Markdown/JSON conservation.
 */
export function evaluateCandidateWriteSet(
  candidateChanges,
  {
    budget,
    workingSet = new Set(),
    grants = [],
    denySet = [],
  }
) {
  const violations = [];
  const currentWorkingSet = new Set(workingSet);
  const denyLookup = new Set(denySet);
  const denyLowerLookup = new Set(Array.from(denySet, (s) => String(s).toLowerCase()));
  const pendingNewLeaseFiles = new Set();
  const scopePolicy = budget.scopePolicy;
  const boundary = scopePolicy && budget.tier === "EXPLICIT_REFACTOR"
    ? refactorBoundary(scopePolicy, currentWorkingSet, candidateChanges.filter(change => !change.isDirectory).map(change => change.relPosix))
    : null;

  // Do not silently drop a prohibition whose target could not be determined.
  // Empty write sets remain valid, so read-only tools can continue.
  if (budget.unresolvedProhibition && candidateChanges.length > 0) {
    return {
      ok: false,
      violations: [{
        code: "UNRESOLVED_PROHIBITION",
        path: candidateChanges[0].relPosix || ".",
        message: "A prohibited file or directory could not be identified reliably. Specify exact paths and start a new task before writing.",
      }],
      nextWorkingSet: Array.from(currentWorkingSet),
    };
  }

  // Pass 1: Ring-00, denySet, Ring-0 ungranted, and whole-transaction dynamic lease slots
  for (const ch of candidateChanges) {
    const rel = ch.relPosix;
    const base = path.posix.basename(rel);
    const lowerRel = rel.toLowerCase();
    const lowerBase = base.toLowerCase();
    const directGrant = findMatchingGrant(rel, grants);
    const frozen = scopePolicy?.frozenReferences?.find(reference => reference.path === rel);

    if (
      denyLookup.has(rel) ||
      denyLookup.has(base) ||
      denyLowerLookup.has(lowerRel) ||
      denyLowerLookup.has(lowerBase)
    ) {
      violations.push({
        code: "EXPLICITLY_NEGATED_PATH",
        path: rel,
        message: `User explicitly forbade modifying '${rel}' in prompt instructions.`,
      });
      continue;
    }

    const ringInfo = classifyProtectionRing(rel, {
      workingSet: currentWorkingSet,
      maxWritableFiles: budget.maxWritableFiles,
      grants,
    });

    if (ringInfo.ring === "RING_00") {
      violations.push({
        code: "IMMUTABLE_INFRA_PROTECTED",
        path: rel,
        message: `Infrastructure/VCS/hook path '${rel}' is Ring-00 immutable and can never be modified by agent tools.`,
      });
      continue;
    }

    if (frozen && !directGrant && (ch.changeType !== "modify" || typeof ch.afterText !== "string" || crypto.createHash("sha256").update(ch.afterText).digest("hex") !== frozen.sha256)) {
      violations.push({ code: "READ_REFERENCE_FROZEN", path: rel, message: `Reference '${rel}' was frozen when read in turn ${frozen.readAtTurn}; a new explicit user authorization is required.` });
      continue;
    }
    if (scopePolicy?.complete && scopePolicy.anchors.length && budget.tier === "SURGICAL_FIX" && !directGrant && !ch.isDirectory && ringInfo.ring !== "RING_0" && !scopePolicy.leaseEvidence.some(entry => entry.path === rel)) {
      violations.push({ code: "LOCALIZATION_OUTSIDE_ONE_HOP", path: rel, message: `File '${rel}' is outside the named target and its one-hop implementation imports. Keep the local fix inside the traced lease or ask the user to name this additional target.` });
      continue;
    }
    if (boundary && !boundary.allowed.has(rel) && !directGrant && !ch.isDirectory) {
      violations.push({ code: "REFACTOR_SCC_BOUNDARY", path: rel, message: `File '${rel}' is outside the explicitly selected dependency group; authorize that file before extending this refactor.` });
      continue;
    }

    // Directory creation inside allowed working tree does not consume file lease slots unless mode-mutating existing dir
    if (ch.isDirectory) {
      if (ch.changeType !== "add" && !ringInfo.granted) {
        violations.push({
          code: ch.changeType === "delete" ? "FILE_DELETION_BLOCKED" : "PERMISSION_MODE_MUTATED",
          path: rel,
          message: `Mutating or deleting existing directory '${rel}' requires explicit authorization.`,
        });
      }
      continue;
    }

    if (ringInfo.ring === "RING_0") {
      if (ringInfo.category === "TEST_SUITE") {
        if (ringInfo.granted) {
          // Explicitly granted by user
        } else if (
          budget.allowTestMutation === "additive" &&
          (ch.changeType === "modify" || ch.changeType === "add") &&
          !isTestConfigOrHookFilename(rel)
        ) {
          // Validated by whole-file additive test conservation in Pass 2 (``)
        } else {
          violations.push({
            code: "TEST_TAMPERING_BLOCKED",
            path: rel,
            message: isTestConfigOrHookFilename(rel)
              ? `Test configuration/hook file '${rel}' cannot be added or modified without explicit authorization.`
              : `Verification file '${rel}' is protected in ${budget.tier} mode (cannot modify/delete tests to silence failures).`,
          });
          continue;
        }
      } else {
        if (!ringInfo.granted && !budget.allowContractMutation) {
          violations.push({
            code: "FROZEN_CONTRACT_READONLY",
            path: rel,
            message: `Contract/config '${rel}' is locked as Ring-0 read-only unless explicitly authorized by user.`,
          });
          continue;
        }
      }
      continue;
    }

    if (!currentWorkingSet.has(rel) && !ringInfo.granted) {
      pendingNewLeaseFiles.add(rel);
    }
  }

  const projectedTotalLeases = currentWorkingSet.size + pendingNewLeaseFiles.size;
  if (projectedTotalLeases > budget.maxWritableFiles) {
    for (const rel of pendingNewLeaseFiles) {
      violations.push({
        code: "SCOPE_BUDGET_EXCEEDED",
        path: rel,
        message: `Candidate write-set touches ${projectedTotalLeases} leaf files, exceeding ${budget.tier} maxWritableFiles=${budget.maxWritableFiles} (whole command rejected).`,
      });
    }
  }

  if (violations.length > 0) {
    return {
      ok: false,
      violations,
      nextWorkingSet: Array.from(currentWorkingSet),
    };
  }

  // Pass 2: Deep content & structural conservation on every file in the candidate write-set
  for (const ch of candidateChanges) {
    if (ch.isDirectory) continue;

    const rel = ch.relPosix;
    const grant = findMatchingGrant(rel, grants);
    const ringInfo = classifyProtectionRing(rel, {
      workingSet: new Set([...currentWorkingSet, ...pendingNewLeaseFiles]),
      maxWritableFiles: budget.maxWritableFiles,
      grants,
    });

    if (ch.changeType === "type-change") {
      violations.push({
        code: "ENTRY_TYPE_MUTATION_BLOCKED",
        path: rel,
        message: `Changing filesystem entry type (regular file <-> symlink/dir) on '${rel}' is forbidden.`,
      });
      continue;
    }

    if (ch.changeType === "delete") {
      if (!grant || !grant.allowFullRewrite) {
        violations.push({
          code: "FILE_DELETION_BLOCKED",
          path: rel,
          message: `Deleting existing file '${rel}' requires explicit file-deletion authorization.`,
        });
      }
      continue;
    }

    if (ch.changeType === "add") {
      // ``: Newly added test files in additive mode MUST still pass `verifyAdditiveTestConservation("", after, rel)`
      // so module-level `pytest.skip(..., allow_module_level=True)`, `.only`, or collection hooks are blocked!
      if (ringInfo.category === "TEST_SUITE" && !grant) {
        if (ch.isBinary || typeof ch.afterText !== "string") {
          violations.push({
            code: "TEST_TAMPERING_BLOCKED",
            path: rel,
            message: `Binary or unreadable test file '${rel}' cannot be added without explicit authorization.`,
          });
          continue;
        }
        const addTestCheck = verifyAdditiveTestConservation("", ch.afterText, rel);
        if (!addTestCheck.ok) {
          violations.push({
            code: addTestCheck.code,
            path: rel,
            message: addTestCheck.reason,
          });
        }
        continue;
      }

      if (rel.toLowerCase().endsWith(".json") && typeof ch.afterText === "string") {
        const jsonAddCheck = verifyJsonConservation("{}", ch.afterText, {
          isSchemaLike: false,
          allowFullFileGrant: true,
          allowSchemaKeywords: true,
        });
        if (!jsonAddCheck.ok) {
          violations.push({
            code: jsonAddCheck.code,
            path: rel,
            message: jsonAddCheck.reason,
          });
        }
      }
      continue;
    }

    if (ch.changeType === "mode-change" && ch.commandBeforeText === ch.afterText) {
      if (!grant) {
        violations.push({
          code: "PERMISSION_MODE_MUTATED",
          path: rel,
          message: `Changing file permission mode on '${rel}' without authorization is blocked.`,
        });
      }
      continue;
    }

    if (ch.isBinary) {
      if (!grant || !grant.allowFullRewrite) {
        violations.push({
          code: "BINARY_ASSET_MUTATION_BLOCKED",
          path: rel,
          message: `Mutating binary file '${rel}' requires explicit rewrite authorization.`,
        });
      }
      continue;
    }

    const cmdBefore = typeof ch.commandBeforeText === "string" ? ch.commandBeforeText : "";
    const taskBefore =
      typeof ch.taskBaselineText === "string" ? ch.taskBaselineText : cmdBefore;
    const after = typeof ch.afterText === "string" ? ch.afterText : "";

    // 1. Check both per-command AND cumulative taskBaseline deletion budgets
    if (!grant?.allowFullRewrite) {
      for (const [label, refText] of [
        ["command", cmdBefore],
        ["cumulative-task", taskBefore],
      ]) {
        const del = computeLineDeletionMetrics(refText, after);
        if (del.baselineCount >= 20 && del.deletedRatio > budget.maxDeletedLineRatio) {
          violations.push({
            code: "DIFF_DELETION_BUDGET_EXCEEDED",
            path: rel,
            message: `${label} deletion ratio ${(del.deletedRatio * 100).toFixed(1)}% (${del.deletedCount}/${del.baselineCount} lines) exceeds ${budget.tier} cap ${(budget.maxDeletedLineRatio * 100).toFixed(0)}%.`,
          });
          break;
        }
        if (del.baselineCount > 0 && del.baselineCount < 20) {
          const netLineShrinkRatio =
            Math.max(0, del.baselineCount - del.candidateCount) / del.baselineCount;
          if (
            del.candidateCount === 0 ||
            netLineShrinkRatio > budget.maxSmallFileDeletedRatio
          ) {
            violations.push({
              code: "SMALL_FILE_WIPE_BLOCKED",
              path: rel,
              message: `Small file '${rel}' (${del.baselineCount} -> ${del.candidateCount} lines) shrank by ${(netLineShrinkRatio * 100).toFixed(0)}% (${label}).`,
            });
            break;
          }
        }
      }
    }

    // 2. Test suite additive conservation
    if (ringInfo.category === "TEST_SUITE") {
      if (!grant || grant.preserveExistingContracts) {
        const testResCmd = verifyAdditiveTestConservation(cmdBefore, after, rel);
        if (!testResCmd.ok) {
          violations.push({
            code: testResCmd.code,
            path: rel,
            message: testResCmd.reason,
          });
          continue;
        }
        const testResTask = verifyAdditiveTestConservation(taskBefore, after, rel);
        if (!testResTask.ok) {
          violations.push({
            code: testResTask.code,
            path: rel,
            message: testResTask.reason,
          });
          continue;
        }
      }
      continue;
    }

    // 3. JSON & JSON Schema conservation
    const lowerRel = rel.toLowerCase();
    if (lowerRel.endsWith(".json")) {
      const isSchemaLike =
        /schema/i.test(path.posix.basename(rel)) ||
        lowerRel.startsWith("contracts/") ||
        lowerRel.startsWith("schemas/");
      const hasSpecificPointers =
        (Array.isArray(grant?.pointerSpecs) && grant.pointerSpecs.length > 0) ||
        (grant?.jsonPointers || []).length > 0;
      const jsonCheck = verifyJsonConservation(taskBefore, after, {
        isSchemaLike,
        pointerSpecs: grant?.pointerSpecs || null,
        jsonPointers: grant?.jsonPointers || [],
        exactJsonPointers: Boolean(grant?.exactJsonPointers),
        allowFullFileGrant:
          Boolean(grant && !hasSpecificPointers) ||
          ringInfo.ring !== "RING_0",
        allowSchemaKeywords: Boolean(grant?.allowSchemaKeywords || grant?.allowFullRewrite),
      });
      if (!jsonCheck.ok) {
        violations.push({
          code: jsonCheck.code,
          path: rel,
          message: jsonCheck.reason,
        });
      }
      continue;
    }

    // 4. Unsupported opaque structured formats (.mdx, .yaml, .yml)
    if (/\.(?:mdx|yaml|yml)$/i.test(lowerRel)) {
      if (!grant?.allowFullRewrite && !grant) {
        violations.push({
          code: "UNSUPPORTED_STRUCTURAL_FORMAT",
          path: rel,
          message: `Partial structural conservation is not supported for '${path.posix.extname(rel)}' in v0.1; explicit file authorization required.`,
        });
      }
      continue;
    }

    // 5. Markdown section complement & aligned epistemic/numeric conservation (``)
    if (lowerRel.endsWith(".md")) {
      const mdCheck = verifyMarkdownSectionConservation(taskBefore, after, {
        sectionSpecs: grant?.sectionSpecs || null,
        sectionTargets: grant?.sectionTargets || [],
        shallowSection: Boolean(grant?.shallowSection),
        allowFullRewrite: Boolean(grant?.allowFullRewrite),
      });
      if (!mdCheck.ok) {
        violations.push({
          code: mdCheck.code,
          path: rel,
          message: mdCheck.reason,
        });
        continue;
      }
      if (budget.enforceEpistemicConservation && !grant?.allowFullRewrite) {
        const epCheck = verifyEpistemicAndNumericAnchors(taskBefore, after);
        if (!epCheck.ok) {
          violations.push({
            code: epCheck.code,
            path: rel,
            message: epCheck.reason,
          });
          continue;
        }
      }
      continue;
    }

    // 6. Code public export & signature conservation (``: honor explicit file grants on unsupported code extensions like `.rs` / `.go`)
    if (
      (!budget.allowExportMutation || boundary?.frozenExports.has(rel) || grant?.preserveExistingContracts) &&
      !grant?.allowExportChange &&
      !grant?.allowFullRewrite
    ) {
      if (isUnsupportedCodeExtension(rel)) {
        if (!grant) {
          violations.push({
            code: "CONSERVATION_UNCERTAIN",
            path: rel,
            message: `Extension '${path.posix.extname(rel)}' is outside v0.1 parser-backed code languages; explicit file grant required when export conservation is active.`,
          });
        }
        continue;
      }

      if (isSupportedParserCodeFile(rel)) {
        const expCheckTask = compareCodeExports(taskBefore, after, rel);
        if (!expCheckTask.ok) {
          violations.push({
            code: expCheckTask.code,
            path: rel,
            message: expCheckTask.reason,
          });
          continue;
        }
        if (cmdBefore !== taskBefore) {
          const expCheckCmd = compareCodeExports(cmdBefore, after, rel);
          if (!expCheckCmd.ok) {
            violations.push({
              code: expCheckCmd.code,
              path: rel,
              message: expCheckCmd.reason,
            });
            continue;
          }
        }
      }
    }
  }

  if (violations.length > 0) {
    return {
      ok: false,
      violations,
      nextWorkingSet: Array.from(currentWorkingSet),
    };
  }

  for (const rel of pendingNewLeaseFiles) {
    currentWorkingSet.add(rel);
  }

  return {
    ok: true,
    violations: [],
    nextWorkingSet: Array.from(currentWorkingSet),
  };
}
