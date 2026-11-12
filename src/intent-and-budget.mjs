import { formatHumanInterceptionCard } from "./human-card.mjs";
import path from "node:path";
import crypto from "node:crypto";
import { toPosixRel } from "./path-security.mjs";

export const MINIMAL_CHANGE_ANCHOR = "Make the minimal change needed.";

export const TIER_BUDGETS = Object.freeze({
  SURGICAL_FIX: Object.freeze({
    tier: "SURGICAL_FIX",
    maxWritableFiles: 3,
    maxDeletedLineRatio: 0.35,
    maxSmallFileDeletedRatio: 0.5,
    allowExportMutation: false,
    allowTestMutation: "none",
    allowContractMutation: false,
    enforceEpistemicConservation: true,
  }),
  FOCUSED_FEATURE: Object.freeze({
    tier: "FOCUSED_FEATURE",
    maxWritableFiles: 6,
    maxDeletedLineRatio: 0.45,
    maxSmallFileDeletedRatio: 0.5,
    allowExportMutation: false,
    allowTestMutation: "additive",
    allowContractMutation: false,
    enforceEpistemicConservation: false,
  }),
  EXPLICIT_REFACTOR: Object.freeze({
    tier: "EXPLICIT_REFACTOR",
    maxWritableFiles: 12,
    maxDeletedLineRatio: 0.65,
    maxSmallFileDeletedRatio: 0.75,
    allowExportMutation: true,
    allowTestMutation: "additive",
    allowContractMutation: false,
    enforceEpistemicConservation: false,
  }),
});

const SYNTHETIC_WRAPPER_RE =
  /<(?:system-reminder|SYSTEM_MESSAGE|environment_context|tool_output|context_summary|context)[\s>][\s\S]*?<\/(?:system-reminder|SYSTEM_MESSAGE|environment_context|tool_output|context_summary|context)>/gi;

const NEGATION_CLAUSE_RE =
  /\b(?:do\s+not|don't|dont|never|without|avoid|except|unless|forbid|prohibit|refrain\s+from|leave\s+[\w./-]+\s+alone|keep\s+[\w./-]+\s+unchanged|read[-\s]?only|untouched|unmodified|not\s+(?:modify|update|edit|change|touch|refactor|delete|remove))\b|(?:请勿|避免|不能|不允许|不许|不准|不可|不应|不建议|不用|不需要|无须|不要|别改|别动|别碰|勿动|勿改|勿碰|禁止|切勿|不得|无需|不要动|不动|不改|不重构|(?:保持|保留)[^，。；\n]{0,24}不变|只读|保持原样|原样保留|原封不动)/i;

const AFFIRMATIVE_EDIT_VERB_RE =
  /\b(?:create|update|edit|modify|change|add|remove|delete|rename|bump|migrate|refactor|rewrite|patch|fix|implement|polish|extend|upgrade|adjust|allow\s+editing|unlock|tweak)\b|(?:创建|新建|修改|更新|调整|新增|删除|移除|重命名|升级|重构|重写|修复|润色|扩写|改一下|同步改|放开|允许修改|微调|只修|仅修|修一下)/i;

// Imperative/affirmative refactor intent only (``: never triggered by meta-mentions like "The word refactor occurs in the log")
const REFACTOR_INTENT_RE =
  /(?:^|(?:please|let's|lets|can\s+you|could\s+you|we\s+need\s+to|i\s+want\s+to|need\s+to|want\s+to|go\s+ahead\s+and|help\s+me|should)\s+)(?:refactor|rename\s+across|migrate\s+all|restructure|extract\s+module|split\s+into\s+modules)\b|(?:^\s*(?:请|帮我|需要|进行|开始|麻烦)?\s*(?:重构|跨模块重命名|整体迁移|拆分模块))/im;

const REFACTOR_META_MENTION_RE =
  /\b(?:word|term|token|string|log|logs|message|output|trace|occurrence|occurs|occurred|appears|appeared|mentions|mentioned)\b[^.\n]{0,40}\brefactor\b|\brefactor\b[^.\n]{0,40}\b(?:occurs|occurred|appears|appeared|in\s+the\s+(?:log|logs|output|error|message))\b/i;

const FEATURE_INTENT_RE =
  /\b(?:add\s+(?:a\s+|new\s+)?(?:feature|endpoint|command|module|handler|route|component|support|test)|implement\s+(?:a\s+|new\s+)?)\b|(?:新增功能|实现新|添加接口|新增模块|新增命令|添加测试)/i;

const REFERENCE_PREFIX_RE =
  /\b(?:using|from|per|via|like|against|matching|following|referencing|referring\s+to|according\s+to|based\s+on|in\s+accordance\s+with|compared\s+to|compared\s+with|derived\s+from|copied\s+from|taken\s+from|read\s+from|loaded\s+from|defined\s+in|configured\s+in|specified\s+in|described\s+in|shown\s+in|logged\s+in|read|inspect|check|consult)\s+(?:(?:the|existing|current|settings|config|configuration|values|fields|schema|rules|data|format|example|log|logs|output|entries|in|of|from)\s+){0,6}[`'"]*$/i;

const REFERENCE_BOUNDARY_RE =
  /\b(?:based\s+on|according\s+to|in\s+accordance\s+with|compared\s+to|compared\s+with|matching|following|referencing|referring\s+to|derived\s+from|copied\s+from|taken\s+from|read\s+from|loaded\s+from|defined\s+in|configured\s+in|specified\s+in|described\s+in|shown\s+in|logged\s+in|reported\s+in|seen\s+in|using|from|per|via|like|against|read|inspect|check|consult)\b|(?:参考|参照|依据|按照|根据|对照|基于|读取|查看)/i;

const REFERENCE_PREFIX_CN_RE =
  /(?:参考|参照|依据|按照|根据|对照|基于|读取|查看)(?:[^，。；\n]{0,12}?(?:里|中|的))?\s*[`'"]*$/;

const REFERENCE_SUFFIX_RE =
  /^[`'"]*\s*(?:as\s+(?:a\s+)?reference|for\s+reference|only\s+for\s+reference|as\s+(?:an?\s+)?example|as\s+template|作为参考|仅供参考)/i;

const SHALLOW_SECTION_RE =
  /\b(?:shallow(?:\s+section)?|without\s+subsections|excluding\s+subsections|exclude\s+child\s+sections|direct\s+body\s+only)\b|(?:不含子章节|不含子节|仅本节正文|浅层章节)/i;

const EXACT_POINTER_RE =
  /\b(?:exact\s+pointer|exact\s+value|scalar\s+only|without\s+children|leaf\s+only)\b|(?:仅精确指针|不含子键)/i;

const NARROW_SCOPE_WORD_RE =
  /\b(?:only|solely|exclusively|just\s+the)\b|(?:仅限?|只改|只更新)/i;

// Matches realistic workspace paths/filenames including Unicode/CJK segments (e.g. contracts/资料.json, src/foo.ts)
const FILE_EXTENSION_SOURCE = /(?:mjs|cjs|js|jsx|ts|tsx|d\.ts|py|rs|go|json|md|mdx|txt|yaml|yml|toml|ini|cfg|conf|xml|csv|proto|graphql|gql|sql|sh|css|html|lock)/.source;
const FILE_TOKEN_RE = new RegExp(
  /(?:^|[\s"'`([<,:;，。：（《])((?:\.\/)?(?:[\p{L}\p{N}_@-]+\/)*[\p{L}\p{N}_@.-]+\.__FILE_EXTENSIONS__|(?:\.env(?:\.[\p{L}\p{N}_.-]+)?)|(?:Dockerfile))(?=$|[\s"'`)\]>.,:;!?，。！？；）》#])/.source.replace("__FILE_EXTENSIONS__", FILE_EXTENSION_SOURCE),
  "giu"
);
const FILE_LIKE_RE = new RegExp(`\\.${FILE_EXTENSION_SOURCE}|\\.env(?:\\.[\\p{L}\\p{N}_.-]+)?|Dockerfile`, "iu");

// Matches candidate RFC 6901 JSON Pointer tokens starting with `/`, preserving internal dots like `/a.b` (``)
const QUOTED_SLASH_POINTER_RE =
  /[`'"]((?<!:)\/[^`'"\s\n]*)[`'"]/g;

const RAW_SLASH_TOKEN_RE =
  /(?:^|[\s(])(\/(?:[^\s"'`),;!?]*[^\s"'`),.;!?])?)(?=$|[\s"'`),.;!?])/g;

const SYSTEM_ABS_PATH_PREFIXES = new Set([
  "dev",
  "usr",
  "bin",
  "sbin",
  "etc",
  "tmp",
  "var",
  "opt",
  "Users",
  "home",
  "Library",
  "System",
  "Volumes",
  "private",
  "proc",
  "sys",
]);

const HEADING_TARGET_PATTERNS = [
  /(?:section|heading|chapter|章节|小节|标题)?\s*[`'"]+(#{1,6}\s+[^`'"\n]{1,80})[`'"]+/gi,
  /(?:section|heading|chapter)\s+[`'"“]([^`'"”\n]{1,80})[`'"”]/gi,
  /[`'"“]([^`'"”\n]{1,80})[`'"”]\s*(?:章节|小节|部分|一节)/g,
  /(第[一二三四五六七八九十\d]+[章节部分])/g,
];

/**
 * Strip balanced single-line or multi-line JSON objects `{ ... }` and JSON-object arrays `[ ... ]`
 * embedded inside user prompts (``, e.g. pasted webhook/log/API JSON payloads across multiple lines).
 */
function stripEmbeddedJsonPayloads(text) {
  let out = "";
  let i = 0;
  const n = text.length;
  let inInlineCode = false;

  while (i < n) {
    const ch = text[i];
    if (ch === "`") {
      inInlineCode = !inInlineCode;
      out += ch;
      i++;
      continue;
    }
    if (!inInlineCode && (ch === "{" || ch === "[")) {
      const openChar = ch;
      const closeChar = ch === "{" ? "}" : "]";
      let depth = 0;
      let j = i;
      let inStr = false;
      let matchedEnd = -1;

      while (j < n) {
        const c = text[j];
        if (inStr) {
          if (c === "\\") {
            j += 2;
            continue;
          }
          if (c === '"') inStr = false;
          j++;
          continue;
        }
        if (c === '"') {
          inStr = true;
          j++;
          continue;
        }
        if (c === openChar) depth++;
        else if (c === closeChar) {
          depth--;
          if (depth === 0) {
            matchedEnd = j + 1;
            break;
          }
        }
        j++;
      }

      if (matchedEnd !== -1) {
        const slice = text.slice(i, matchedEnd);
        const hasJsonKeyColon = /"[^"\n]{1,120}"\s*:/.test(slice);
        if (hasJsonKeyColon) {
          out += "\n";
          i = matchedEnd;
          continue;
        }
      }
    }

    out += ch;
    i++;
  }
  return out;
}

/**
 * Strip untrusted/quoted/synthetic wrappers, single-line & multi-line JSON object/array payloads (``),
 * fenced code blocks, blockquotes, and stack traces so machine envelopes never mint write grants.
 */
export function sanitizePromptForAuthorization(rawPrompt, { isSynthetic = false } = {}) {
  if (isSynthetic || !rawPrompt || typeof rawPrompt !== "string") {
    return "";
  }
  const outerTrim = rawPrompt.trim();
  if (
    (outerTrim.startsWith("{") && outerTrim.endsWith("}")) ||
    (outerTrim.startsWith("[") && outerTrim.endsWith("]"))
  ) {
    return "";
  }

  let text = rawPrompt.replace(/\r\n/g, "\n");
  text = text.replace(SYNTHETIC_WRAPPER_RE, "\n");

  const lines = text.split("\n");
  const keptLines = [];
  let inFence = null;

  for (const line of lines) {
    const trimmed = line.trimStart();
    const trimmedBoth = line.trim();
    const fenceMatch = trimmed.match(/^(`{3,}|~{3,})/);
    if (fenceMatch) {
      const marker = fenceMatch[1];
      if (!inFence) {
        inFence = { char: marker[0], len: marker.length };
        continue;
      } else if (
        marker[0] === inFence.char &&
        marker.length >= inFence.len &&
        trimmed.slice(marker.length).trim() === ""
      ) {
        inFence = null;
        continue;
      }
    }
    if (inFence) continue;

    // Skip Markdown blockquotes
    if (trimmed.startsWith(">")) continue;

    // Skip raw single-line JSON lines
    if (
      (trimmedBoth.startsWith("{") && trimmedBoth.endsWith("}") && /"\s*:/.test(trimmedBoth)) ||
      (trimmedBoth.startsWith("[") && trimmedBoth.endsWith("]") && /"\s*:/.test(trimmedBoth))
    ) {
      continue;
    }

    // Skip Node/Python/Rust stack trace lines & synthetic continuation banners
    if (
      /^\s*at\s+[^\n]+\([^)]+:\d+:\d+\)/.test(line) ||
      /^\s*at\s+[\w./-]+:\d+:\d+/.test(line) ||
      /^\s*File\s+"[^"]+",\s+line\s+\d+/.test(line) ||
      /^Traceback\s+\(most recent call last\):/i.test(trimmed) ||
      /^\s*\[\s*Screenshot\b/i.test(trimmed)
    ) {
      continue;
    }

    keptLines.push(line);
  }

  return stripEmbeddedJsonPayloads(keptLines.join("\n")).trim();
}

/** Keep quoted file names opaque while recognizing Chinese command boundaries. */
function prepareChineseAuthorizationText(text) {
  const quotedFiles = new Map();
  const quotePattern = /`([^`\n]+)`|"([^"\n]+)"|'([^'\n]+)'|“([^”\n]+)”|‘([^’\n]+)’/g;
  let prepared = text.replace(quotePattern, (whole, ...groups) => {
    const content = groups.slice(0, 5).find((value) => typeof value === "string");
    const exactFile = new RegExp(FILE_TOKEN_RE.source, "iu").exec(content);
    if (!exactFile || exactFile[1] !== content || exactFile[0] !== content || content.includes("..")) {
      return AFFIRMATIVE_EDIT_VERB_RE.test(content) || /[不别勿禁]/u.test(content) ? " " : whole;
    }
    const extension = content.startsWith(".env") || content === "Dockerfile" ? ".js" : path.posix.extname(content);
    let alias = `__blastguard_quoted_file_${quotedFiles.size}${extension}`;
    while (text.includes(alias) || quotedFiles.has(alias)) alias = `_${alias}`;
    quotedFiles.set(alias, content.replace(/^\.\//, ""));
    return `\`${alias}\``;
  });
  // Negative commands can include ordinary adverbs. Resolving these boundaries only
  // creates prohibitions, and cannot widen positive write authorization.
  prepared = prepared.replace(/(?<![\p{L}\p{N}_./@-])((?:请)?(?:(?:不能|不允许|不许|不准|不可|不应|不建议|不用|不需要|无须|不要|无需|禁止|切勿|不得|别|勿)(?:\s*(?:再|继续|任何|擅自|随意))*\s*(?:修改|更改|改动|触碰|重构|覆盖|删除|改|动|碰)?|只读(?:查看|读取)?))(?=[A-Za-z_.])/gu, "$1 ");

  // Whitespace-delimited Chinese filenames are already complete tokens. Keep verbs
  // inside them opaque rather than interpreting a second command at their start.
  prepared = prepared.replace(new RegExp(FILE_TOKEN_RE.source, "giu"), (whole, token, offset) => {
    const tokenStart = offset + whole.lastIndexOf(token);
    if (tokenStart === 0 || !/\s/.test(prepared[tokenStart - 1]) || !/[\p{Script=Han}]/u.test(token)) return whole;
    if (!token.includes("/") && /(?:参考|参照|只读查看|只读读取)\s*$/.test(prepared.slice(0, tokenStart))) return whole;
    let alias = `__blastguard_literal_file_${quotedFiles.size}${path.posix.extname(token)}`;
    while (text.includes(alias) || quotedFiles.has(alias)) alias = `_${alias}`;
    quotedFiles.set(alias, token.replace(/^\.\//, ""));
    return whole.replace(token, alias);
  });

  // Split commands only at a prose boundary, never inside a filename or path segment.
  const commandBoundary = /(?<![\p{L}\p{N}_./@-])((?:请|帮我|麻烦|实际)?(?:(?:不能|不允许|不许|不准|不可|不应|不建议|不用|不需要|无须|不要|无需|禁止|切勿|不得|别|勿)(?:修改|更改|改动|触碰|重构|改|动|碰)?|只读查看|只读读取|只修改|只修复|修复|修改|更新|调整|创建|新建|删除|移除|重构|重写|润色|扩写|微调|只修|仅修|查看|读取|参考|参照|依据|根据|基于|不要动|不要改|不要修改|不能修改|不允许修改|不许修改|不准修改|无需修改|更改|改动|触碰|禁止|不要|无需|无须|不能|不允许|不许|不准|不可|保持|保留|把|将|对|在|和|与))(?=[A-Za-z_.])/gu;
  prepared = prepared.replace(commandBoundary, "$1 ");

  // A complete compound name such as foo.js备份.md is one path. Preserve it before
  // considering Chinese suffixes. Reference/read-only prose gets only narrow handling.
  prepared = prepared.replace(new RegExp(FILE_TOKEN_RE.source, "giu"), (whole, token, offset) => {
    const extensions = token.match(new RegExp(`\\.${FILE_EXTENSION_SOURCE}`, "gi")) || [];
    if (extensions.length < 2) return whole;
    const prefix = prepared.slice(0, offset + whole.lastIndexOf(token));
    if (!token.includes("/") && /(?:参考|参照|只读查看|只读读取)\s*$/.test(prefix)) return whole;
    let alias = `__blastguard_compound_file_${quotedFiles.size}${path.posix.extname(token)}`;
    while (text.includes(alias) || quotedFiles.has(alias)) alias = `_${alias}`;
    quotedFiles.set(alias, token.replace(/^\.\//, ""));
    return whole.replace(token, alias);
  });
  const fileSuffix = new RegExp(`(\\.${FILE_EXTENSION_SOURCE}|\\.env(?:\\.[\\p{L}\\p{N}_.-]+)?|Dockerfile)(?=(?:里|中|的|和|与|不能|不允许|不许|不准|不可|不应|不用|不需要|无须|不要|别|勿|禁止|切勿|不得|无需|保持|保留|原样|原封|修复|修改))`, "gu");
  prepared = prepared.replace(fileSuffix, "$1 ");
  prepared = prepared.replace(commandBoundary, "$1 ");
  return { text: prepared, restore: (file) => quotedFiles.get(file) || file };
}

function findLastAffirmativeVerbEnd(textBeforeToken) {
  const globalVerbRe = new RegExp(AFFIRMATIVE_EDIT_VERB_RE.source, "gi");
  let lastEnd = -1;
  let m;
  while ((m = globalVerbRe.exec(textBeforeToken)) !== null) {
    lastEnd = m.index + m[0].length;
  }
  return lastEnd;
}

function analyzeFileMentionsInClause(clause) {
  const allFiles = [];
  const targetFiles = [];
  const referenceOnlyFiles = [];

  FILE_TOKEN_RE.lastIndex = 0;
  let m;
  while ((m = FILE_TOKEN_RE.exec(clause)) !== null) {
    const fullMatch = m[0];
    const tokenRaw = m[1];
    const cleaned = tokenRaw.replace(/^\.\//, "");
    if (!cleaned || cleaned.startsWith("http") || cleaned.includes("..")) continue;
    const rel = toPosixRel(path.posix.normalize(cleaned));
    allFiles.push(rel);

    const tokenOffsetInMatch = fullMatch.lastIndexOf(tokenRaw);
    const tokenStart = m.index + tokenOffsetInMatch;
    const tokenEnd = tokenStart + tokenRaw.length;
    const beforeAll = clause.slice(0, tokenStart);
    const afterAll = clause.slice(tokenEnd);
    const prefix = clause.slice(Math.max(0, tokenStart - 96), tokenStart);
    const suffix = clause.slice(tokenEnd, Math.min(clause.length, tokenEnd + 48));

    const lastVerbEnd = findLastAffirmativeVerbEnd(beforeAll);
    let governedByEditVerb = false;
    if (lastVerbEnd !== -1) {
      const spanSinceVerb = beforeAll.slice(lastVerbEnd);
      governedByEditVerb = !REFERENCE_BOUNDARY_RE.test(spanSinceVerb);
    } else {
      // Topicalized target before verb (e.g. "In notes.md, update...", "把 app.js 修一下")
      const isTopicalizedTarget =
        /^\s*(?:in|for|on|within|在|对|把|将|针对)?\s*[`'"]*$/i.test(beforeAll) &&
        AFFIRMATIVE_EDIT_VERB_RE.test(afterAll);
      governedByEditVerb = isTopicalizedTarget;
    }

    const isRef =
      !governedByEditVerb ||
      REFERENCE_PREFIX_RE.test(prefix) ||
      REFERENCE_PREFIX_CN_RE.test(prefix) ||
      REFERENCE_SUFFIX_RE.test(suffix);

    if (isRef) {
      referenceOnlyFiles.push(rel);
    } else {
      targetFiles.push(rel);
    }
  }

  return {
    allFiles: Array.from(new Set(allFiles)),
    targetFiles: Array.from(new Set(targetFiles)),
    referenceOnlyFiles: Array.from(new Set(referenceOnlyFiles)),
  };
}

function isLikelySystemFilePathToken(candidate, hasJsonTarget) {
  const segs = candidate.slice(1).split("/");
  const firstSeg = segs[0] || "";
  if (!SYSTEM_ABS_PATH_PREFIXES.has(firstSeg)) return false;
  // In a `.json` clause, single-segment `/dev`, `/bin`, `/usr`, `/var`, `/opt`, `/tmp`, `/etc`, `/home`
  // are valid top-level RFC 6901 JSON Pointers (``), NEVER skipped!
  if (hasJsonTarget && segs.length === 1) return false;
  // Multi-segment well-known OS paths (`/dev/null`, `/usr/local/bin`, `/home/...`, `/tmp/...`)
  if (segs.length >= 2) return true;
  return !hasJsonTarget;
}

/**
 * Validate and extract arbitrary RFC 6901 JSON Pointers (``), including internal dots (`/a.b`),
 * single-segment system-like keys (`/dev`, `/bin`), quoted pointers, and `~0` / `~1` escape validation.
 */
function extractJsonPointersFromClause(clause, mentionedFilesSet, hasJsonTarget = false) {
  const validPointers = [];
  let hasInvalidPointer = false;
  const consumedRanges = [];

  const acceptCandidate = (candidate, offset, endOffset, isQuoted) => {
    if (!isQuoted) {
      if (offset >= 2 && clause.slice(offset - 2, offset) === ":/") return;
      if (offset >= 1 && clause[offset - 1] === ":") return;
    }

    const precededByPointerWord = /\bpointer\s+[`'"]*$/i.test(
      clause.slice(Math.max(0, offset - 24), offset)
    );
    if (!precededByPointerWord && !isQuoted && isLikelySystemFilePathToken(candidate, hasJsonTarget)) {
      return;
    }

    const withoutLeadingSlash = candidate.slice(1);
    if (!precededByPointerWord && withoutLeadingSlash && mentionedFilesSet.has(withoutLeadingSlash)) {
      return;
    }

    // Bare "/" without `pointer` keyword in prose (e.g. "read / write") is punctuation, not root pointer
    if (candidate === "/" && !precededByPointerWord && !isQuoted) {
      return;
    }

    // Validate RFC 6901 syntax: every `~` MUST be `~0` or `~1`!
    if (/~(?![01])/.test(candidate)) {
      hasInvalidPointer = true;
      return;
    }

    consumedRanges.push([offset, endOffset]);
    validPointers.push(candidate);
  };

  QUOTED_SLASH_POINTER_RE.lastIndex = 0;
  let qm;
  while ((qm = QUOTED_SLASH_POINTER_RE.exec(clause)) !== null) {
    const candidate = qm[1];
    const start = qm.index + 1;
    acceptCandidate(candidate, start, start + candidate.length, true);
  }

  RAW_SLASH_TOKEN_RE.lastIndex = 0;
  let m;
  while ((m = RAW_SLASH_TOKEN_RE.exec(clause)) !== null) {
    const fullMatch = m[0];
    const candidate = m[1];
    const offset = m.index + fullMatch.lastIndexOf(candidate);
    const endOffset = offset + candidate.length;
    if (consumedRanges.some(([s, e]) => offset >= s && endOffset <= e)) continue;
    acceptCandidate(candidate, offset, endOffset, false);
  }

  return {
    pointers: Array.from(new Set(validPointers)),
    hasInvalidPointer,
  };
}

function mergePointerSpecs(prevSpecs = [], nextSpecs = []) {
  const map = new Map();
  for (const sp of prevSpecs) {
    if (sp && typeof sp.pointer === "string") {
      map.set(sp.pointer, { pointer: sp.pointer, exact: Boolean(sp.exact) });
    }
  }
  for (const sp of nextSpecs) {
    if (!sp || typeof sp.pointer !== "string") continue;
    const prev = map.get(sp.pointer);
    if (!prev) {
      map.set(sp.pointer, { pointer: sp.pointer, exact: Boolean(sp.exact) });
    } else {
      map.set(sp.pointer, {
        pointer: sp.pointer,
        exact: Boolean(prev.exact && sp.exact),
      });
    }
  }
  return Array.from(map.values());
}

function mergeSectionSpecs(prevSpecs = [], nextSpecs = []) {
  const map = new Map();
  for (const sp of prevSpecs) {
    if (sp && typeof sp.target === "string") {
      const key = sp.target.trim().toLowerCase();
      map.set(key, { target: sp.target, shallow: Boolean(sp.shallow) });
    }
  }
  for (const sp of nextSpecs) {
    if (!sp || typeof sp.target !== "string") continue;
    const key = sp.target.trim().toLowerCase();
    const prev = map.get(key);
    if (!prev) {
      map.set(key, { target: sp.target, shallow: Boolean(sp.shallow) });
    } else {
      map.set(key, {
        target: prev.target,
        shallow: Boolean(prev.shallow && sp.shallow),
      });
    }
  }
  return Array.from(map.values());
}

function normalizeGrantPointerSpecs(grant) {
  if (!grant) return [];
  if (Array.isArray(grant.pointerSpecs) && grant.pointerSpecs.length > 0) {
    return grant.pointerSpecs;
  }
  return (grant.jsonPointers || []).map((p) => ({
    pointer: p,
    exact: Boolean(grant.exactJsonPointers),
  }));
}

function normalizeGrantSectionSpecs(grant) {
  if (!grant) return [];
  if (Array.isArray(grant.sectionSpecs) && grant.sectionSpecs.length > 0) {
    return grant.sectionSpecs;
  }
  return (grant.sectionTargets || []).map((t) => ({
    target: t,
    shallow: Boolean(grant.shallowSection),
  }));
}

function hasUnrepresentableSubfileScope(clause, fileToken, { jsonPointers, sectionTargets, hasInvalidPointer }) {
  if (hasInvalidPointer) return true;
  if (!NARROW_SCOPE_WORD_RE.test(clause)) return false;

  const lowerFile = fileToken.toLowerCase();
  if (lowerFile.endsWith(".json")) {
    if (jsonPointers.length > 0) return false;
    const stripped = clause
      .replace(fileToken, " ")
      .replace(AFFIRMATIVE_EDIT_VERB_RE, " ")
      .replace(/\b(?:only|solely|exclusively|just|the|file|please|go\s+ahead\s+and)\b/gi, " ")
      .replace(/(?:仅限?|只改|只更新|文件|请)/g, " ")
      .replace(/[`'".,:;!?()\s]+/g, "")
      .trim();
    return stripped.length > 0;
  }

  if (lowerFile.endsWith(".md")) {
    if (sectionTargets.length > 0) return false;
    const stripped = clause
      .replace(fileToken, " ")
      .replace(AFFIRMATIVE_EDIT_VERB_RE, " ")
      .replace(/\b(?:only|solely|exclusively|just|the|file|document|please|go\s+ahead\s+and)\b/gi, " ")
      .replace(/(?:仅限?|只改|只更新|文件|文档|请)/g, " ")
      .replace(/[`'".,:;!?()\s]+/g, "")
      .trim();
    return stripped.length > 0;
  }

  return false;
}

function extractHeadingTargetsFromClause(clause) {
  const targets = [];
  for (const re of HEADING_TARGET_PATTERNS) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(clause)) !== null) {
      const val = m[1].trim();
      if (val) targets.push(val);
    }
  }
  return Array.from(new Set(targets));
}

/**
 * Split sanitized text into sentences and contrastive sub-clauses using POSITIVE LOOKAHEAD
 * so negation operators (`without`, `except`, `but do not`, `无需`, `不要`) stay attached to the negated clause (``)!
 */
function splitIntoContrastiveClauses(sanitizedText) {
  const sentences = sanitizedText
    .split(/(?:\n+|[!?;。！？；，]+|\.(?=\s|$))\s*/)
    .map((s) => s.trim())
    .filter(Boolean);

  const clauses = [];
  const lookaheadSplitRe =
    /(?=\b(?:but|except|without|while|whereas|however|although|though|unless)\b|(?:但是|但|除了|同时|而(?=(?:不要|别|禁止|不|保持))))/i;

  for (const sentence of sentences) {
    const subClauses = sentence
      .split(lookaheadSplitRe)
      .map((c) => c.trim())
      .filter(Boolean);
    for (const sub of subClauses) {
      const clause = sub.replace(/^(但是|但)(?=[A-Za-z_.])/, "$1 ");
      clauses.push({ clause, parentSentence: sentence });
    }
  }
  return clauses;
}

/**
 * Parse explicit affirmative modification grants while strictly filtering out
 * synthetic JSON, reference-only mentions, stack traces, quoted text, unrepresentable scopes, and negated targets (`denySet`).
 */
export function parseAuthorizationGrants(rawPrompt, { turnId = 1, isSynthetic = false } = {}) {
  const sanitized = sanitizePromptForAuthorization(rawPrompt, { isSynthetic });
  if (!sanitized) {
    return { grants: [], denySet: [], referenceMentions: [], unresolvedProhibition: false };
  }

  const prepared = prepareChineseAuthorizationText(sanitized);
  const clauses = splitIntoContrastiveClauses(prepared.text);
  const denySet = new Set();
  let unresolvedProhibition = false;
  const referenceMentions = new Set();
  const candidateGrants = new Map();

  for (const { clause } of clauses) {
    const fileAnalysis = analyzeFileMentionsInClause(clause);
    for (const f of fileAnalysis.allFiles) referenceMentions.add(f);

    const knownProhibition = NEGATION_CLAUSE_RE.test(clause);
    const scopeContext = fileAnalysis.allFiles.length > 0 || /(?:文件|目录|路径|代码|它|这里|那里|这个|那个|这些|上述|其他|其余|别的|东西|内容|file|path|directory|[\p{L}\p{N}_-]+[\/\\])/iu.test(clause) || FILE_LIKE_RE.test(clause);
    // A negative instruction needs an operation, rather than a character which
    // also occurs in bug descriptions such as 不显示, 不兼容 or 识别中文.
    const uncertainWriteInstruction = /(?:别(?:对|给|把|将|再|随意|擅自|删|改|动|碰|移除|修改|删除)|勿(?:再|随意|擅自|删|改|动|碰|移除|修改|删除)|(?:严禁|禁止|不必|不要|不能|不许|不准|不允许|不得|不可|不应|不建议|不用|不需要|无需|无须)[^，。；\n]{0,80}(?:修改|更改|改动|触碰|重构|覆盖|删除|移除|写入|移动|重命名|动手|改|动|碰|删))/u.test(clause);
    const nonWritingRestriction = /\b(?:inspect|read|browse|view|run|execute|shell\s+commands?)\b|(?:查看|读取|浏览|检查|搜索|检索|查找|使用|参考|运行|执行)/iu.test(clause)
      && !AFFIRMATIVE_EDIT_VERB_RE.test(clause)
      && !/(?:修改|更改|改动|触碰|重构|覆盖|删除|移除|写入|移动|重命名|动手|改|动|碰|删|只读)|\bread[-\s]?only\b/iu.test(clause);
    if (nonWritingRestriction) continue;
    const ambiguousProhibition = uncertainWriteInstruction && scopeContext && !knownProhibition;
    if (knownProhibition || ambiguousProhibition) {
      // A negative cue and a file-like target must never silently fall through to a
      // positive grant. Unknown wording closes this turn through the caller's budget.
      if (ambiguousProhibition || (fileAnalysis.allFiles.length === 0 && scopeContext)) {
        unresolvedProhibition = true;
      }
      for (const f of fileAnalysis.allFiles) {
        denySet.add(f);
        if (/[不别勿禁]/u.test(f)) unresolvedProhibition = true;
        const restored = prepared.restore(f);
        if (f !== restored && !f.includes("quoted_file") && (restored.match(new RegExp(`\\.${FILE_EXTENSION_SOURCE}`, "gi")) || []).length > 1) {
          unresolvedProhibition = true;
        }
        // Unquoted Chinese names can touch the prohibition without a delimiter.
        // Keep both candidates; uncertain ownership remains closed for the turn.
        const possibleTarget = f.replace(/^(?:请)?(?:不要|不能|不允许|不许|不准|不可|不应|不用|无需|无须|禁止|切勿|不得|别|不动|不改|不重构)(?:修改|更改|改动|触碰|重构|改|动|碰)?(?=[\p{Script=Han}])/u, "");
        if (possibleTarget !== f) {
          denySet.add(possibleTarget);
          unresolvedProhibition = true;
        }
      }
      continue;
    }

    if (!AFFIRMATIVE_EDIT_VERB_RE.test(clause)) {
      continue;
    }

    const mentionedSet = new Set(fileAnalysis.allFiles);
    const hasJsonTarget = fileAnalysis.targetFiles.some((f) => f.toLowerCase().endsWith(".json"));
    const ptrExtract = extractJsonPointersFromClause(clause, mentionedSet, hasJsonTarget);
    const jsonPointers = ptrExtract.pointers;
    const exactJsonPointers = EXACT_POINTER_RE.test(clause);
    const clausePointerSpecs = jsonPointers.map((p) => ({ pointer: p, exact: exactJsonPointers }));
    const headingTargets = extractHeadingTargetsFromClause(clause);
    const shallowSection = SHALLOW_SECTION_RE.test(clause);
    const clauseSectionSpecs = headingTargets.map((t) => ({ target: t, shallow: shallowSection }));

    const allowFullRewrite =
      /\b(?:rewrite\s+(?:the\s+)?(?:entire|whole)|delete\s+file|remove\s+file|replace\s+entire)\b|(?:重写整个|整篇重写|删除文件|移除该文件)/i.test(
        clause
      );
    const allowSchemaKeywords =
      /\b(?:required|enum|type\s+constraint|additionalProperties|\$ref|schema\s+constraint)\b|(?:必填项|枚举约束|类型约束)/i.test(
        clause
      );
    const allowExportChange =
      /\b(?:rename\s+export|remove\s+export|change\s+signature|update\s+interface|update\s+type|breaking\s+change)\b|(?:修改导出签名|删除导出|修改接口签名|变更函数签名)/i.test(
        clause
      );

    for (const fileToken of fileAnalysis.targetFiles) {
      if (
        hasUnrepresentableSubfileScope(clause, fileToken, {
          jsonPointers,
          sectionTargets: headingTargets,
          hasInvalidPointer: ptrExtract.hasInvalidPointer,
        })
      ) {
        // Refuse widening an unparseable narrow scope selector into a whole-file grant (``)!
        continue;
      }

      const existing = candidateGrants.get(fileToken);
      const mergedPtrSpecs = mergePointerSpecs(
        normalizeGrantPointerSpecs(existing),
        clausePointerSpecs
      );
      const mergedSecSpecs = mergeSectionSpecs(
        normalizeGrantSectionSpecs(existing),
        clauseSectionSpecs
      );
      candidateGrants.set(fileToken, {
        grantId: `grant-t${turnId}-${crypto.createHash("sha1").update(fileToken).digest("hex").slice(0, 8)}`,
        turnId,
        pathPattern: fileToken,
        matchBasename: !fileToken.includes("/"),
        operations: allowFullRewrite ? ["read", "write", "rewrite", "delete"] : ["read", "write"],
        pointerSpecs: mergedPtrSpecs,
        jsonPointers: mergedPtrSpecs.map((s) => s.pointer),
        exactJsonPointers: mergedPtrSpecs.length > 0 && mergedPtrSpecs.every((s) => s.exact),
        sectionSpecs: mergedSecSpecs,
        sectionTargets: mergedSecSpecs.map((s) => s.target),
        shallowSection: mergedSecSpecs.length > 0 && mergedSecSpecs.every((s) => s.shallow),
        allowFullRewrite: Boolean(existing?.allowFullRewrite || allowFullRewrite),
        allowSchemaKeywords: Boolean(existing?.allowSchemaKeywords || allowSchemaKeywords),
        allowExportChange: Boolean(existing?.allowExportChange || allowExportChange),
      });
    }

    // Handle Markdown section grants when a single .md target was affirmatively mentioned earlier without negation
    if (fileAnalysis.targetFiles.length === 0 && headingTargets.length > 0) {
      const allDocMentions = Array.from(referenceMentions).filter(
        (f) => f.endsWith(".md") && !denySet.has(f) && candidateGrants.has(f)
      );
      if (allDocMentions.length === 1) {
        const docFile = allDocMentions[0];
        const existing = candidateGrants.get(docFile);
        const mergedSecSpecs = mergeSectionSpecs(
          normalizeGrantSectionSpecs(existing),
          clauseSectionSpecs
        );
        candidateGrants.set(docFile, {
          grantId: `grant-t${turnId}-${crypto.createHash("sha1").update(docFile).digest("hex").slice(0, 8)}`,
          turnId,
          pathPattern: docFile,
          matchBasename: !docFile.includes("/"),
          operations: existing?.operations || ["read", "write"],
          pointerSpecs: normalizeGrantPointerSpecs(existing),
          jsonPointers: existing?.jsonPointers || [],
          exactJsonPointers: Boolean(existing?.exactJsonPointers),
          sectionSpecs: mergedSecSpecs,
          sectionTargets: mergedSecSpecs.map((s) => s.target),
          shallowSection: mergedSecSpecs.length > 0 && mergedSecSpecs.every((s) => s.shallow),
          allowFullRewrite: Boolean(existing?.allowFullRewrite),
          allowSchemaKeywords: Boolean(existing?.allowSchemaKeywords),
          allowExportChange: Boolean(existing?.allowExportChange),
        });
      }
    }
  }

  // Enforce denySet precedence over any accidental adjacent match
  for (const denied of denySet) {
    candidateGrants.delete(denied);
    const base = path.posix.basename(denied);
    if (candidateGrants.has(base)) {
      candidateGrants.delete(base);
    }
  }

  const restoredDenySet = new Set(Array.from(denySet, prepared.restore));
  const deniedBasenames = new Set(Array.from(restoredDenySet, (file) => path.posix.basename(file)));
  const restoredGrants = new Map();
  for (const grant of candidateGrants.values()) {
    const file = prepared.restore(grant.pathPattern);
    const matchBasename = !file.includes("/");
    if (restoredDenySet.has(file) || (matchBasename && deniedBasenames.has(file))) continue;
    const previous = restoredGrants.get(file);
    const pointerSpecs = mergePointerSpecs(normalizeGrantPointerSpecs(previous), grant.pointerSpecs);
    const sectionSpecs = mergeSectionSpecs(normalizeGrantSectionSpecs(previous), grant.sectionSpecs);
    restoredGrants.set(file, {
      ...grant,
      pathPattern: file,
      matchBasename,
      grantId: `grant-t${turnId}-${crypto.createHash("sha1").update(file).digest("hex").slice(0, 8)}`,
      pointerSpecs,
      jsonPointers: pointerSpecs.map((spec) => spec.pointer),
      exactJsonPointers: pointerSpecs.length > 0 && pointerSpecs.every((spec) => spec.exact),
      sectionSpecs,
      sectionTargets: sectionSpecs.map((spec) => spec.target),
      shallowSection: sectionSpecs.length > 0 && sectionSpecs.every((spec) => spec.shallow),
      allowFullRewrite: Boolean(previous?.allowFullRewrite || grant.allowFullRewrite),
      allowSchemaKeywords: Boolean(previous?.allowSchemaKeywords || grant.allowSchemaKeywords),
      allowExportChange: Boolean(previous?.allowExportChange || grant.allowExportChange),
      operations: Array.from(new Set([...(previous?.operations || []), ...grant.operations])),
    });
  }
  return {
    grants: Array.from(restoredGrants.values()),
    denySet: Array.from(restoredDenySet),
    referenceMentions: Array.from(new Set(Array.from(referenceMentions, prepared.restore))),
    unresolvedProhibition,
  };
}

function stripInlineQuotesForIntent(clause) {
  return clause
    .replace(/`[^`\n]*`/g, " ")
    .replace(/"[^"\n]*"/g, " ")
    .replace(/(?<=\s|^)'[^'\n]*'(?=\s|[.,;!?]|$)/g, " ");
}

export function classifyIntent(rawPrompt, { turnId = 1, isSynthetic = false } = {}) {
  const sanitized = sanitizePromptForAuthorization(rawPrompt, { isSynthetic });
  const auth = parseAuthorizationGrants(rawPrompt, { turnId, isSynthetic });

  // Derive tier escalation ONLY from non-negated, non-meta-mention affirmative clauses (``)!
  const affirmativeClauses = splitIntoContrastiveClauses(sanitized)
    .filter((c) => !NEGATION_CLAUSE_RE.test(c.clause))
    .map((c) => stripInlineQuotesForIntent(c.clause).trim())
    .filter(Boolean);

  const hasRefactorIntent = affirmativeClauses.some(
    (c) => !REFACTOR_META_MENTION_RE.test(c) && REFACTOR_INTENT_RE.test(c)
  );
  const affirmativeText = affirmativeClauses.join("\n");

  let tierName = "SURGICAL_FIX";
  if (hasRefactorIntent) {
    tierName = "EXPLICIT_REFACTOR";
  } else if (FEATURE_INTENT_RE.test(affirmativeText)) {
    tierName = "FOCUSED_FEATURE";
  }

  const baseBudget = TIER_BUDGETS[tierName];
  return {
    tier: tierName,
    budget: { ...baseBudget },
    minimalAnchor: MINIMAL_CHANGE_ANCHOR,
    grants: auth.grants,
    denySet: auth.denySet,
    referenceMentions: auth.referenceMentions,
    unresolvedProhibition: Boolean(auth.unresolvedProhibition),
  };
}

export function mergeTurnGrants(existingGrants = [], newGrants = []) {
  const byKey = new Map();
  for (const g of existingGrants) {
    byKey.set(`${g.pathPattern}::${Boolean(g.matchBasename)}`, g);
  }
  for (const g of newGrants) {
    const key = `${g.pathPattern}::${Boolean(g.matchBasename)}`;
    const prev = byKey.get(key);
    if (!prev) {
      byKey.set(key, g);
    } else {
      const mergedPtrSpecs = mergePointerSpecs(
        normalizeGrantPointerSpecs(prev),
        normalizeGrantPointerSpecs(g)
      );
      const mergedSecSpecs = mergeSectionSpecs(
        normalizeGrantSectionSpecs(prev),
        normalizeGrantSectionSpecs(g)
      );
      byKey.set(key, {
        ...prev,
        ...g,
        operations: Array.from(new Set([...(prev.operations || []), ...(g.operations || [])])),
        pointerSpecs: mergedPtrSpecs,
        jsonPointers: mergedPtrSpecs.map((s) => s.pointer),
        exactJsonPointers: mergedPtrSpecs.length > 0 && mergedPtrSpecs.every((s) => s.exact),
        sectionSpecs: mergedSecSpecs,
        sectionTargets: mergedSecSpecs.map((s) => s.target),
        shallowSection: mergedSecSpecs.length > 0 && mergedSecSpecs.every((s) => s.shallow),
        allowFullRewrite: Boolean(prev.allowFullRewrite || g.allowFullRewrite),
        allowSchemaKeywords: Boolean(prev.allowSchemaKeywords || g.allowSchemaKeywords),
        allowExportChange: Boolean(prev.allowExportChange || g.allowExportChange),
      });
    }
  }
  return Array.from(byKey.values());
}

export function formatVoiEscalationGuidance(violations = [], { workingSet = [], callerImpact = null } = {}) {
  const primary = violations[0] || {
    code: "SCOPE_VIOLATION",
    path: "<unknown>",
    message: "Unauthorized mutation outside permitted scope.",
  };
  const extraCount = Math.max(0, violations.length - 1);
  const impactNote =
    callerImpact && callerImpact.transitiveCallers > 0
      ? ` Downstream impact: ${callerImpact.directCallers} direct / ${callerImpact.transitiveCallers} transitive caller(s).`
      : "";
  const leaseList = workingSet.length > 0 ? workingSet.join(", ") : "(dynamic leaf slots available)";

  return [
    `[NoStray ${primary.code}] [BlastGuard ${primary.code}] ${primary.path}: ${primary.message}${extraCount > 0 ? ` (+${extraCount} more)` : ""}.${impactNote}`,
    `Active editable lease: ${leaseList}.`,
    `Next step: (1) Solve the task inside leased leaf files without altering frozen contracts/tests. (2) ONLY if impossible without changing '${primary.path}', stop and ask the user with <=3 concise options (showing exact contract change & blast radius) so they can explicitly authorize updating '${primary.path}'.`,
    "", formatHumanInterceptionCard(violations, { callerImpact }),
  ].join("\n");
}
