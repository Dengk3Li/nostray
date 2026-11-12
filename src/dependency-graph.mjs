import fs from "node:fs";
import path from "node:path";
import {
  canonicalizeWorkspaceRoot,
  shouldSkipPerformanceIgnoredDir,
  toPosixRel,
} from "./path-security.mjs";
import { tokenizeJsTs, SUPPORTED_JS_TS_EXTS, SUPPORTED_PYTHON_EXTS } from "./code-scanner.mjs";

const RESOLVE_CANDIDATE_SUFFIXES = [
  "",
  ".ts",
  ".tsx",
  ".mts",
  ".js",
  ".mjs",
  ".cjs",
  ".jsx",
  ".d.ts",
  "/index.ts",
  "/index.tsx",
  "/index.js",
  "/index.mjs",
  ".py",
  "/__init__.py",
];

function extractJsTsSpecifiers(source) {
  const tokRes = tokenizeJsTs(source);
  if (!tokRes.ok) return null;
  const { tokens } = tokRes;
  const specs = [];
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    // import ... from "spec" / export ... from "spec"
    if (t.value === "from" && tokens[i + 1]?.type === "string") {
      specs.push(tokens[i + 1].value.slice(1, -1));
      continue;
    }
    // side-effect import "spec"
    if (t.value === "import" && tokens[i + 1]?.type === "string") {
      specs.push(tokens[i + 1].value.slice(1, -1));
      continue;
    }
    // dynamic import("spec") or require("spec")
    if (
      (t.value === "import" || t.value === "require") &&
      tokens[i + 1]?.value === "(" &&
      tokens[i + 2]?.type === "string"
    ) {
      specs.push(tokens[i + 2].value.slice(1, -1));
    }
  }
  return specs;
}

function extractPythonRelativeSpecifiers(source, importerRelPosix) {
  const norm = source.replace(/\r\n/g, "\n");
  const lines = norm.split("\n");
  const importerDir = path.posix.dirname(importerRelPosix);
  const candidates = [];

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    // from .foo import bar  OR  from ..pkg import baz
    const relFrom = trimmed.match(/^from\s+(\.+)([A-Za-z0-9_.]*)\s+import\s+([A-Za-z0-9_*, ()]+)/);
    if (relFrom) {
      const dots = relFrom[1].length;
      const modPart = relFrom[2] ? relFrom[2].split(".").join("/") : "";
      let baseDir = importerDir;
      for (let d = 1; d < dots; d++) {
        baseDir = path.posix.dirname(baseDir);
      }
      if (modPart) {
        candidates.push(path.posix.join(baseDir, modPart));
      } else {
        const names = relFrom[3]
          .replace(/[()]/g, "")
          .split(",")
          .map((s) => s.trim().split(/\s+as\s+/)[0])
          .filter((s) => s && s !== "*");
        for (const nm of names) {
          candidates.push(path.posix.join(baseDir, nm));
        }
      }
      continue;
    }
    // Absolute intra-workspace module import e.g. `from app.billing import calc`
    const absFrom = trimmed.match(/^from\s+([A-Za-z_][A-Za-z0-9_.]*)\s+import\s+/);
    if (absFrom) {
      candidates.push(absFrom[1].split(".").join("/"));
    }
  }
  return candidates;
}

function resolveImportTarget(importerRelPosix, rawSpec, knownFilesSet) {
  let baseCandidate = null;
  if (rawSpec.startsWith("./") || rawSpec.startsWith("../")) {
    const dir = path.posix.dirname(importerRelPosix);
    baseCandidate = path.posix.normalize(path.posix.join(dir, rawSpec));
    // TypeScript ESM imports often write `./foo.js` or `./foo.mjs` referring to `./foo.ts`
    const strippedJs = baseCandidate.replace(/\.(?:m?js|cjs)$/i, "");
    for (const rootCand of [baseCandidate, strippedJs]) {
      for (const suf of RESOLVE_CANDIDATE_SUFFIXES) {
        const probe = `${rootCand}${suf}`;
        if (knownFilesSet.has(probe)) return probe;
      }
    }
    return null;
  }

  // Python module path candidate
  if (!rawSpec.startsWith("@") && !rawSpec.includes(":")) {
    for (const suf of ["", ".py", "/__init__.py", ".ts", ".js", ".mjs"]) {
      const probe = `${rawSpec}${suf}`;
      if (knownFilesSet.has(probe)) return probe;
    }
  }
  return null;
}

function readLocalImportAliases(canonicalRoot) {
  const aliases = [];
  let unparsedConfigurations = 0;
  for (const name of ["tsconfig.json", "jsconfig.json"]) {
    const file = path.join(canonicalRoot, name);
    if (!fs.existsSync(file)) continue;
    try {
      const stat = fs.lstatSync(file);
      if (!stat.isFile() || stat.size > 1024 * 1024) throw new Error("Unsupported configuration file");
      const lexical = tokenizeJsTs(fs.readFileSync(file, "utf8"));
      if (!lexical.ok) throw new Error("Unparsed configuration");
      // JSONC comments are already removed by the tokenizer; omit only actual trailing comma tokens.
      const tokens = lexical.tokens.filter((token, index, all) => token.value !== "," || !["}", "]"].includes(all[index + 1]?.value));
      const config = JSON.parse(tokens.map(token => token.value).join(""));
      if (config.extends) unparsedConfigurations++;
      const options = config.compilerOptions || {};
      const base = options.baseUrl || ".";
      if (typeof base !== "string" || path.isAbsolute(base)) throw new Error("Unsupported baseUrl");
      for (const [pattern, targets] of Object.entries(options.paths || {})) {
        if (!Array.isArray(targets) || pattern.split("*").length > 2 || targets.some(target => typeof target !== "string" || target.split("*").length > 2 || path.isAbsolute(target))) {
          unparsedConfigurations++;
          continue;
        }
        aliases.push({ pattern, targets: targets.map(target => path.posix.normalize(path.posix.join(base, target))) });
      }
      if (options.baseUrl) aliases.push({ pattern: "*", targets: [path.posix.join(base, "*")], fallback: true });
    } catch { unparsedConfigurations++; }
  }
  aliases.sort((left, right) => {
    const fallbackOrder = Number(Boolean(left.fallback)) - Number(Boolean(right.fallback));
    if (fallbackOrder) return fallbackOrder;
    const exactOrder = Number(!right.pattern.includes("*")) - Number(!left.pattern.includes("*"));
    if (exactOrder) return exactOrder;
    return right.pattern.split("*")[0].length - left.pattern.split("*")[0].length;
  });
  return { aliases, unparsedConfigurations };
}

function resolveAlias(rawSpec, aliases, knownSet) {
  let matched = false;
  for (const { pattern, targets, fallback } of aliases) {
    const [prefix, suffix] = pattern.split("*");
    const wildcard = suffix !== undefined;
    if (wildcard ? !rawSpec.startsWith(prefix) || !rawSpec.endsWith(suffix) || rawSpec.length < prefix.length + suffix.length : rawSpec !== pattern) continue;
    matched ||= !fallback;
    const middle = wildcard ? rawSpec.slice(prefix.length, rawSpec.length - suffix.length) : "";
    for (const target of targets) {
      const candidate = target.replace("*", middle);
      for (const extension of RESOLVE_CANDIDATE_SUFFIXES) {
        if (knownSet.has(candidate + extension)) return { target: candidate + extension, matched };
      }
    }
  }
  return { target: null, matched };
}

/**
 * Build workspace static dependency graph + Tarjan Strongly Connected Components (cycles)
 * + Reverse-Dependency caller map.
 * The scope policy can use complete static edges for bounded one-hop and SCC leases.
 */
export function buildWorkspaceDependencyGraph(
  workspaceRoot,
  { maxFiles = 5000, shouldExclude = () => false } = {}
) {
  if (!Number.isSafeInteger(maxFiles) || maxFiles < 0) {
    throw new RangeError("maxFiles must be a non-negative safe integer.");
  }
  const canonicalRoot = canonicalizeWorkspaceRoot(workspaceRoot);
  const codeFiles = [];
  let truncated = false;
  let unreadableDirectories = 0;
  let unreadableFiles = 0;
  let oversizedFiles = 0;
  let unparsedFiles = 0;
  let skippedSymlinks = 0;
  const problemFileSamples = { unreadable: [], oversized: [], unparsed: [] };
  const aliasConfig = readLocalImportAliases(canonicalRoot);
  let unresolvedImports = 0;

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
      if (ent.name === ".git" || ent.name === ".blast-guard") continue;
      const childRel = toPosixRel(relDirPosix ? `${relDirPosix}/${ent.name}` : ent.name);
      const childAbs = path.join(absDir, ent.name);
      if (shouldExclude(childRel, ent.isDirectory())) continue;
      if (ent.isSymbolicLink()) {
        skippedSymlinks++;
        continue;
      }
      if (ent.isDirectory()) {
        walk(childAbs, childRel);
      } else if (ent.isFile()) {
        const ext = path.extname(ent.name).toLowerCase();
        if (SUPPORTED_JS_TS_EXTS.has(ext) || SUPPORTED_PYTHON_EXTS.has(ext)) {
          if (codeFiles.length >= maxFiles) {
            truncated = true;
            break;
          }
          codeFiles.push({ relPosix: childRel, absPath: childAbs, ext });
        }
      }
    }
  }

  walk(canonicalRoot, "");

  const knownSet = new Set(codeFiles.map((f) => f.relPosix));
  const forwardDeps = new Map(); // file -> Set<importedFile>
  const reverseCallers = new Map(); // file -> Set<callerFile>

  for (const f of codeFiles) {
    forwardDeps.set(f.relPosix, new Set());
    reverseCallers.set(f.relPosix, new Set());
  }

  for (const f of codeFiles) {
    let content = "";
    try {
      const st = fs.statSync(f.absPath);
      if (st.size > 1024 * 1024) {
        oversizedFiles++;
        if (problemFileSamples.oversized.length < 5) problemFileSamples.oversized.push(f.relPosix);
        continue;
      }
      content = fs.readFileSync(f.absPath, "utf8");
    } catch {
      unreadableFiles++;
      if (problemFileSamples.unreadable.length < 5) problemFileSamples.unreadable.push(f.relPosix);
      continue;
    }

    const rawSpecs = SUPPORTED_PYTHON_EXTS.has(f.ext)
      ? extractPythonRelativeSpecifiers(content, f.relPosix)
      : extractJsTsSpecifiers(content);

    if (rawSpecs === null) {
      unparsedFiles++;
      if (problemFileSamples.unparsed.length < 5) problemFileSamples.unparsed.push(f.relPosix);
      continue;
    }

    for (const sp of rawSpecs) {
      const alias = resolveAlias(sp, aliasConfig.aliases, knownSet);
      const target = alias.target || resolveImportTarget(f.relPosix, sp, knownSet);
      if (target) {
        forwardDeps.get(f.relPosix).add(target);
        reverseCallers.get(target).add(f.relPosix);
      } else if (!SUPPORTED_PYTHON_EXTS.has(f.ext) && (alias.matched || sp.startsWith("@/") || sp.startsWith("#") || (/^\.\.?\//.test(sp) && (!path.posix.extname(sp) || SUPPORTED_JS_TS_EXTS.has(path.posix.extname(sp)))))) {
        unresolvedImports++;
      }
    }
  }

  // Tarjan's Strongly Connected Components (O(V + E))
  let index = 0;
  const indices = new Map();
  const lowlink = new Map();
  const onStack = new Set();
  const stack = [];
  const sccs = [];
  const nodeToScc = new Map();

  function strongConnect(v) {
    indices.set(v, index);
    lowlink.set(v, index);
    index++;
    stack.push(v);
    onStack.add(v);

    for (const w of forwardDeps.get(v) || []) {
      if (!indices.has(w)) {
        strongConnect(w);
        lowlink.set(v, Math.min(lowlink.get(v), lowlink.get(w)));
      } else if (onStack.has(w)) {
        lowlink.set(v, Math.min(lowlink.get(v), indices.get(w)));
      }
    }

    if (lowlink.get(v) === indices.get(v)) {
      const comp = [];
      while (true) {
        const w = stack.pop();
        onStack.delete(w);
        comp.push(w);
        if (w === v) break;
      }
      comp.sort();
      const sccId = sccs.length;
      sccs.push(comp);
      for (const member of comp) {
        nodeToScc.set(member, sccId);
      }
    }
  }

  for (const node of knownSet) {
    if (!indices.has(node)) {
      strongConnect(node);
    }
  }

  const cyclicSccs = sccs.filter(
    (comp) =>
      comp.length > 1 ||
      (comp.length === 1 && Boolean(forwardDeps.get(comp[0])?.has(comp[0])))
  );

  function computeCallerImpact(targetRelPosix) {
    if (!reverseCallers.has(targetRelPosix)) {
      return {
        target: targetRelPosix,
        directCallers: 0,
        transitiveCallers: 0,
        callerList: [],
        sccCycleMembers: [],
      };
    }
    const direct = Array.from(reverseCallers.get(targetRelPosix));
    const visited = new Set();
    const queue = [...direct];
    while (queue.length > 0) {
      const cur = queue.shift();
      if (visited.has(cur)) continue;
      visited.add(cur);
      for (const parent of reverseCallers.get(cur) || []) {
        if (!visited.has(parent)) queue.push(parent);
      }
    }
    visited.delete(targetRelPosix);
    const directNonSelf = direct.filter((d) => d !== targetRelPosix);
    const sccIdx = nodeToScc.get(targetRelPosix);
    const hasSelfLoop = Boolean(forwardDeps.get(targetRelPosix)?.has(targetRelPosix));
    const sccMembers =
      sccIdx !== undefined && (sccs[sccIdx].length > 1 || hasSelfLoop)
        ? sccs[sccIdx]
        : [];
    return {
      target: targetRelPosix,
      directCallers: directNonSelf.length + (hasSelfLoop ? 1 : 0),
      transitiveCallers: visited.size + (hasSelfLoop ? 1 : 0),
      callerList: Array.from(new Set([...visited, ...(hasSelfLoop ? [targetRelPosix] : [])])).sort(),
      sccCycleMembers: sccMembers,
    };
  }

  return {
    truncated,
    fileCount: codeFiles.length,
    unreadableDirectories,
    unreadableFiles,
    oversizedFiles,
    unparsedFiles,
    unresolvedImports,
    unparsedConfigurations: aliasConfig.unparsedConfigurations,
    skippedSymlinks,
    problemFileSamples,
    forwardDeps,
    reverseCallers,
    sccs,
    cyclicSccs,
    computeCallerImpact,
  };
}
