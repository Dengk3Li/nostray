import path from "node:path";
import crypto from "node:crypto";
import vm from "node:vm";

export const SUPPORTED_JS_TS_EXTS = new Set([".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"]);
export const SUPPORTED_PYTHON_EXTS = new Set([".py"]);

function sha256Short(str) {
  return crypto.createHash("sha256").update(str).digest("hex").slice(0, 16);
}

const BINARY_ONLY_OPERATORS = new Set([
  "===",
  "!==",
  "==",
  "!=",
  "<=",
  ">=",
  "&&",
  "||",
  "??",
  "+=",
  "-=",
  "*=",
  "/=",
  "**=",
  "%=",
  "&=",
  "|=",
  "^=",
  "<<=",
  ">>=",
  ">>>=",
  "&&=",
  "||=",
  "??=",
  "<<",
  ">>",
  ">>>",
  "=>",
]);

const TYPE_PREFIX_KEYWORDS_OR_OPS = new Set([
  ":",
  "|",
  "&",
  "?",
  "=",
  "=>",
  ",",
  "<",
  "extends",
  "is",
  "asserts",
  "keyof",
  "typeof",
  "readonly",
  "infer",
]);

/**
 * Stateful lexical tokenizer for JS/TS that strips single-line comments & block comments,
 * preserves exact string/template/regex token values, validates bracket balance, and rejects
 * invalid stray lexemes (``).
 */
export function tokenizeJsTs(source) {
  const tokens = [];
  const n = source.length;
  let i = 0;
  let line = 1;
  const stack = [];
  const templateBraceDepths = [];

  const isIdentStart = (ch) => /^[$_\p{ID_Start}]$/u.test(ch);
  const isIdentPart = (ch) => /^[$_\u200c\u200d\p{ID_Continue}]$/u.test(ch);
  const codePointAt = (offset) =>
    offset < n ? String.fromCodePoint(source.codePointAt(offset)) : "";

  // Allow `#!` shebang on line 1
  if (source.startsWith("#!")) {
    while (i < n && source[i] !== "\n") i++;
  }

  while (i < n) {
    const ch = source[i];
    const next = i + 1 < n ? source[i + 1] : "";

    if (ch === "\n") {
      line++;
      i++;
      continue;
    }
    if (/\s/.test(ch)) {
      i++;
      continue;
    }

    // Reject stray backslash outside string/regex/comment
    if (ch === "\\") {
      return { ok: false, reason: `Unexpected '\\' token at line ${line}`, tokens };
    }

    // Line comment
    if (ch === "/" && next === "/") {
      i += 2;
      while (i < n && source[i] !== "\n") i++;
      continue;
    }

    // Block comment
    if (ch === "/" && next === "*") {
      i += 2;
      let closed = false;
      while (i < n) {
        if (source[i] === "\n") line++;
        if (source[i] === "*" && source[i + 1] === "/") {
          i += 2;
          closed = true;
          break;
        }
        i++;
      }
      if (!closed) return { ok: false, reason: "Unclosed block comment", tokens };
      continue;
    }

    // Private identifier `#name`
    if (ch === "#") {
      const first = codePointAt(i + 1);
      if (!isIdentStart(first)) {
        return { ok: false, reason: `Invalid '#' token at line ${line}`, tokens };
      }
      let start = i;
      i += 1 + first.length;
      while (i < n && isIdentPart(codePointAt(i))) i += codePointAt(i).length;
      tokens.push({
        type: "ident",
        value: source.slice(start, i),
        line,
        depth: stack.length,
      });
      continue;
    }

    // Single or double quoted string
    if (ch === "'" || ch === '"') {
      const quote = ch;
      const startLine = line;
      let raw = quote;
      i++;
      let closed = false;
      while (i < n) {
        const c = source[i];
        if (c === "\\") {
          raw += c + (source[i + 1] || "");
          if (source[i + 1] === "\n") line++;
          i += 2;
          continue;
        }
        if (c === "\n") {
          return { ok: false, reason: "Unterminated string literal", tokens };
        }
        raw += c;
        i++;
        if (c === quote) {
          closed = true;
          break;
        }
      }
      if (!closed) return { ok: false, reason: "Unterminated string literal", tokens };
      tokens.push({ type: "string", value: raw, line: startLine, endLine: line, depth: stack.length });
      continue;
    }

    // Template literal start
    if (ch === "`") {
      const startLine = line;
      const res = readTemplateSegment(source, i + 1, line);
      if (!res.ok) return { ok: false, reason: res.reason, tokens };
      line = res.line;
      i = res.nextIndex;
      tokens.push({ type: "template", value: res.placeholder, line: startLine, endLine: line, depth: stack.length });
      if (res.enteredExpr) {
        templateBraceDepths.push(stack.length);
        stack.push("{");
        tokens.push({ type: "punct", value: "${", line, depth: stack.length - 1, templateMarker: true });
      }
      continue;
    }

    // Closing brace of `${ ... }` inside template literal
    if (
      ch === "}" &&
      templateBraceDepths.length > 0 &&
      stack.length - 1 === templateBraceDepths[templateBraceDepths.length - 1]
    ) {
      stack.pop();
      templateBraceDepths.pop();
      tokens.push({ type: "punct", value: "}", line, depth: stack.length });
      const startLine = line;
      const res = readTemplateSegment(source, i + 1, line);
      if (!res.ok) return { ok: false, reason: res.reason, tokens };
      line = res.line;
      i = res.nextIndex;
      tokens.push({ type: "template", value: res.placeholder, line: startLine, endLine: line, depth: stack.length, continuation: true });
      if (res.enteredExpr) {
        templateBraceDepths.push(stack.length);
        stack.push("{");
        tokens.push({ type: "punct", value: "${", line, depth: stack.length - 1, templateMarker: true });
      }
      continue;
    }

    // Regex literal heuristic
    if (ch === "/" && next !== "/" && next !== "*") {
      const prev = tokens[tokens.length - 1];
      const canStartRegex =
        !prev ||
        (prev.type === "punct" &&
          [
            "(",
            "${",
            "[",
            "{",
            ",",
            ";",
            ":",
            "=",
            "==",
            "===",
            "!=",
            "!==",
            "!",
            "&&",
            "||",
            "??",
            "?",
            "=>",
            "+",
            "-",
            "+=",
            "-=",
            "*=",
            "/=",
            "**=",
            "%=",
            "&=",
            "|=",
            "^=",
            "<<=",
            ">>=",
            ">>>=",
            "&&=",
            "||=",
            "??=",
            "<<",
            ">>",
            ">>>",
          ].includes(prev.value)) ||
        (prev.type === "ident" &&
          ["return", "throw", "case", "typeof", "void", "delete", "in", "of", "yield", "await"].includes(
            prev.value
          ));
      if (canStartRegex) {
        let raw = "/";
        i++;
        let inCharClass = false;
        let closed = false;
        while (i < n) {
          const c = source[i];
          if (c === "\n") break;
          if (c === "\\") {
            raw += c + (source[i + 1] || "");
            i += 2;
            continue;
          }
          if (c === "[") inCharClass = true;
          else if (c === "]") inCharClass = false;
          else if (c === "/" && !inCharClass) {
            raw += "/";
            i++;
            while (i < n && /[a-z]/i.test(source[i])) {
              raw += source[i];
              i++;
            }
            closed = true;
            break;
          }
          raw += c;
          i++;
        }
        if (closed) {
          tokens.push({ type: "regex", value: raw, line, depth: stack.length });
          continue;
        }
        return { ok: false, reason: "Ambiguous or unterminated regex/JSX slash", tokens };
      }
    }

    // Identifiers & keywords
    const firstIdentifierPoint = codePointAt(i);
    if (isIdentStart(firstIdentifierPoint)) {
      let start = i;
      i += firstIdentifierPoint.length;
      while (i < n && isIdentPart(codePointAt(i))) i += codePointAt(i).length;
      tokens.push({
        type: "ident",
        value: source.slice(start, i),
        line,
        depth: stack.length,
      });
      continue;
    }

    // Numbers
    if (/[0-9]/.test(ch) || (ch === "." && /[0-9]/.test(next))) {
      const match = source.slice(i).match(
        /^(?:0[xX][0-9a-fA-F](?:_?[0-9a-fA-F])*n?|0[bB][01](?:_?[01])*n?|0[oO][0-7](?:_?[0-7])*n?|(?:\d(?:_?\d)*(?:\.(?:\d(?:_?\d)*)?)?|\.\d(?:_?\d)*)(?:[eE][+-]?\d(?:_?\d)*)?n?)/
      );
      const start = i;
      i += match[0].length;
      tokens.push({
        type: "number",
        value: source.slice(start, i),
        line,
        depth: stack.length,
      });
      continue;
    }

    // Multi-char operators
    const four = source.slice(i, i + 4);
    if (four === ">>>=") {
      tokens.push({ type: "punct", value: four, line, depth: stack.length });
      i += 4;
      continue;
    }
    const three = source.slice(i, i + 3);
    if (["...", "===", "!==", ">>>", "**=", "<<=", ">>=", "&&=", "||=", "??="].includes(three)) {
      tokens.push({ type: "punct", value: three, line, depth: stack.length });
      i += 3;
      continue;
    }
    const two = source.slice(i, i + 2);
    if (
      ["=>", "==", "!=", "<=", ">=", "&&", "||", "??", "?.", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<", ">>", "++", "--", "**"].includes(two)
    ) {
      tokens.push({ type: "punct", value: two, line, depth: stack.length });
      i += 2;
      continue;
    }

    // Brackets / Braces / Parens
    if (ch === "{" || ch === "(" || ch === "[") {
      tokens.push({ type: "punct", value: ch, line, depth: stack.length });
      stack.push(ch);
      i++;
      continue;
    }
    if (ch === "}" || ch === ")" || ch === "]") {
      const expected = ch === "}" ? "{" : ch === ")" ? "(" : "[";
      if (stack.length === 0 || stack[stack.length - 1] !== expected) {
        return { ok: false, reason: `Unbalanced '${ch}' at line ${line}`, tokens };
      }
      stack.pop();
      tokens.push({ type: "punct", value: ch, line, depth: stack.length });
      i++;
      continue;
    }

    if (!"+-*/%&|^!~<>?:;=.,@".includes(ch)) {
      return { ok: false, reason: `Unsupported character '${ch}' at line ${line}`, tokens };
    }
    tokens.push({ type: "punct", value: ch, line, depth: stack.length });
    i++;
  }

  if (stack.length !== 0) {
    return { ok: false, reason: `Unclosed '${stack[stack.length - 1]}' at EOF`, tokens };
  }

  const syntaxSanity = validateJsTsTokenSanity(tokens);
  if (!syntaxSanity.ok) {
    return { ok: false, reason: syntaxSanity.reason, tokens };
  }

  return { ok: true, tokens };
}

const INCOMPLETE_EXPR_BEFORE_CLOSERS = new Set([
  "=",
  "+=",
  "-=",
  "*=",
  "/=",
  "**=",
  "%=",
  "&=",
  "|=",
  "^=",
  "<<=",
  ">>=",
  ">>>=",
  "&&=",
  "||=",
  "??=",
  "**",
  "===",
  "!==",
  "==",
  "!=",
  "<=",
  ">=",
  "&&",
  "||",
  "??",
  "=>",
  "+",
  "-",
  "*",
  "/",
  "%",
  "&",
  "|",
  "^",
  "!",
  "~",
  "?",
]);

function validateJsTsTokenSanity(tokens) {
  for (let i = 0; i < tokens.length; i++) {
    const cur = tokens[i];
    const prev = tokens[i - 1];
    const next = tokens[i + 1];

    if (cur.type === "punct") {
      // Catch incomplete expressions like `const x = ;`, `return + ;`, `foo(a, = 1)`, `const x = }` (``)
      if (
        INCOMPLETE_EXPR_BEFORE_CLOSERS.has(cur.value) &&
        (!next || (next.type === "punct" && [";", ")", "]", "}"].includes(next.value)))
      ) {
        return {
          ok: false,
          reason: `Incomplete expression after '${cur.value}' at line ${cur.line}`,
        };
      }
      if (
        (cur.value === "=" || BINARY_ONLY_OPERATORS.has(cur.value)) &&
        (!prev || (prev.type === "punct" && ["{", "(", "[", ";", ","].includes(prev.value)))
      ) {
        return {
          ok: false,
          reason: `Unexpected operator '${cur.value}' at start of expression at line ${cur.line}`,
        };
      }
    }

    if (cur.type === "punct" && next?.type === "punct") {
      if (BINARY_ONLY_OPERATORS.has(cur.value) && BINARY_ONLY_OPERATORS.has(next.value)) {
        return {
          ok: false,
          reason: `Invalid consecutive operators '${cur.value} ${next.value}' at line ${cur.line}`,
        };
      }
      if (cur.value === "=" && next.value === "=") {
        return { ok: false, reason: `Malformed operator at line ${cur.line}` };
      }
    }

    // Every `function` keyword outside property access `.function` must have a parameter list `(`
    if (cur.type === "ident" && cur.value === "function" && tokens[i - 1]?.value !== ".") {
      let p = i + 1;
      if (tokens[p]?.value === "*") p++;
      if (tokens[p]?.type === "ident") p++;
      if (tokens[p]?.value === "<") {
        const endGen = advanceAngleBracketGroup(tokens, p, cur.depth);
        if (endGen < 0) return { ok: false, reason: `Malformed generic parameters at line ${cur.line}` };
        p = endGen;
      }
      if (tokens[p]?.value !== "(") {
        return { ok: false, reason: `Malformed function syntax missing '(' at line ${cur.line}` };
      }
    }
  }
  return { ok: true };
}

/**
 * Full V8 ECMAScript syntax validation for `.js`, `.mjs`, and `.cjs` (``):
 * Rewrites top-level ESM `import`/`export` clauses into valid JS script statements while preserving all
 * declaration/function/expression syntax verbatim, then compiles via `new vm.Script(...)` (zero execution!).
 */
function validatePureJsSyntaxViaV8(source, tokens, ext) {
  if (ext !== ".js" && ext !== ".mjs" && ext !== ".cjs") {
    return { ok: true };
  }
  if (ext === ".cjs" && !tokens.some((t) => t.depth === 0 && (t.value === "import" || t.value === "export"))) {
    try {
      const strippedShebang = source.startsWith("#!") ? source.replace(/^#![^\n]*/, "") : source;
      new vm.Script(`(function (exports, require, module, __filename, __dirname) {\n${strippedShebang}\n})`);
      return { ok: true };
    } catch (err) {
      return { ok: false, reason: `JavaScript syntax error: ${err.message}` };
    }
  }

  // Reconstruct token stream with ESM import/export wrappers lowered to valid V8 Script syntax
  const out = [];
  let anonDefaultCounter = 0;
  let hasTopLevelAwait = false;
  const pushValidationToken = (index) => {
    const token = tokens[index];
    if (token.templateMarker) return;
    const value = token.type === "template" && token.continuation
      ? token.value.slice(1)
      : token.value;
    out.push(value);
    if (tokens[index + 1] && tokens[index + 1].line > (token.endLine ?? token.line)) out.push("\n");
  };

  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t.depth === 0 && t.value === "await") {
      hasTopLevelAwait = true;
    }
    // `import.meta` -> `({})`
    if (t.value === "import" && tokens[i + 1]?.value === "." && tokens[i + 2]?.value === "meta") {
      out.push("(", "{", "}", ")");
      i += 2;
      continue;
    }
    if (t.depth === 0 && t.value === "import" && tokens[i + 1]?.value !== "(" && tokens[i + 1]?.value !== ".") {
      // Static `import ... from "x"` or `import "x"`: verify import clause grammar & emit `const` bindings so no syntax error hides
      let k = i + 1;
      if (tokens[k]?.type === "string") {
        out.push(";");
        i = k;
        if (tokens[i + 1]?.value === ";") i++;
        continue;
      }
      const boundNames = [];
      let sawFrom = false;
      while (k < tokens.length) {
        if (tokens[k].depth === 0 && tokens[k].value === "from" && tokens[k + 1]?.type === "string") {
          sawFrom = true;
          k += 1;
          // Handle optional `with { type: "json" }` / `assert { type: "json" }`
          if (
            (tokens[k + 1]?.value === "with" || tokens[k + 1]?.value === "assert") &&
            tokens[k + 2]?.value === "{"
          ) {
            const cl = findMatchingCloseIndex(tokens, k + 2);
            if (cl < 0) return { ok: false, reason: "Unclosed import attributes" };
            k = cl;
          }
          break;
        }
        if (tokens[k].depth === 0 && tokens[k].value === ";") break;
        if (tokens[k].value === "*" && tokens[k + 1]?.value === "as" && tokens[k + 2]?.type === "ident") {
          boundNames.push(tokens[k + 2].value);
          k += 3;
          continue;
        }
        if (tokens[k].value === "{") {
          const cl = findMatchingCloseIndex(tokens, k);
          if (cl < 0) return { ok: false, reason: "Unclosed import { ... }" };
          const sp = parseExportBraceSpecifiersStrict(tokens, k + 1, cl);
          if (!sp.ok) return { ok: false, reason: sp.reason };
          for (const item of sp.specifiers) boundNames.push(item.exported);
          k = cl + 1;
          continue;
        }
        if (tokens[k].type === "ident" && tokens[k].value !== ",") {
          boundNames.push(tokens[k].value);
          k++;
          continue;
        }
        if (tokens[k].value === ",") {
          k++;
          continue;
        }
        return { ok: false, reason: `Malformed ESM import syntax at line ${tokens[k].line}` };
      }
      if (!sawFrom) {
        return { ok: false, reason: `Malformed ESM import missing 'from' at line ${t.line}` };
      }
      if (boundNames.length > 0) {
        out.push("var", boundNames.map((n) => `${n} = undefined`).join(" , "), ";");
      } else {
        out.push(";");
      }
      i = k;
      if (tokens[i + 1]?.value === ";") i++;
      continue;
    }

    if (t.depth === 0 && t.value === "export") {
      const next = tokens[i + 1];
      if (!next) return { ok: false, reason: `Dangling 'export' at line ${t.line}` };
      if (next.value === "*") {
        let p = i + 2;
        if (tokens[p]?.value === "as" && tokens[p + 1]?.type === "ident") p += 2;
        if (tokens[p]?.value !== "from" || tokens[p + 1]?.type !== "string") {
          return { ok: false, reason: `Malformed 'export *' at line ${t.line}` };
        }
        i = p + 1;
        if (tokens[i + 1]?.value === ";") i++;
        out.push(";");
        continue;
      }
      if (next.value === "{") {
        const cl = findMatchingCloseIndex(tokens, i + 1);
        if (cl < 0) return { ok: false, reason: `Unclosed 'export {' at line ${t.line}` };
        const sp = parseExportBraceSpecifiersStrict(tokens, i + 2, cl);
        if (!sp.ok) return { ok: false, reason: sp.reason };
        if (tokens[cl + 1]?.value === "from") {
          if (tokens[cl + 2]?.type !== "string") {
            return { ok: false, reason: `Malformed 'export { ... } from' at line ${t.line}` };
          }
          i = cl + 2;
        } else {
          if (sp.specifiers.length > 0) {
            out.push("(", sp.specifiers.map((s) => s.local).join(" , "), ")", ";");
          }
          i = cl;
        }
        if (tokens[i + 1]?.value === ";") i++;
        continue;
      }
      if (next.value === "default") {
        const afterDef = tokens[i + 2];
        if (!afterDef) return { ok: false, reason: `Incomplete 'export default' at line ${t.line}` };
        if (
          afterDef.value === "function" ||
          (afterDef.value === "async" && tokens[i + 3]?.value === "function") ||
          afterDef.value === "class"
        ) {
          // Ensure anonymous `export default function() {}` or `export default class {}` has an expression wrapper or dummy name
          out.push("void", "(");
          // Find matching close brace of the function/class expression!
          let bIdx = i + 2;
          while (bIdx < tokens.length && !(tokens[bIdx].depth === 0 && tokens[bIdx].value === "{")) {
            bIdx++;
          }
          const clBrace = bIdx < tokens.length ? findMatchingCloseIndex(tokens, bIdx) : -1;
          if (clBrace < 0) return { ok: false, reason: `Malformed 'export default' declaration at line ${t.line}` };
          for (let m = i + 2; m <= clBrace; m++) {
            if (
              tokens[m].value === "import" &&
              tokens[m + 1]?.value === "." &&
              tokens[m + 2]?.value === "meta"
            ) {
              out.push("(", "{", "}", ")");
              m += 2;
              continue;
            }
            pushValidationToken(m);
          }
          out.push(")", ";");
          i = clBrace;
          continue;
        }
        anonDefaultCounter++;
        out.push("const", `__bg_default_${anonDefaultCounter}`, "=");
        i += 1; // skip `export default`
        continue;
      }
      // `export function / class / const / let / var / async function` -> drop `export` keyword!
      if (["function", "async", "class", "const", "let", "var"].includes(next.value)) {
        continue;
      }
      return { ok: false, reason: `Unsupported 'export ${next.value}' syntax at line ${t.line}` };
    }

    pushValidationToken(i);
  }

  const lowered = out.join(" ");
  try {
    if (hasTopLevelAwait || ext === ".mjs") {
      new vm.Script(`(async function () {\n${lowered}\n})`);
    } else {
      new vm.Script(lowered);
    }
    return { ok: true };
  } catch (err) {
    return { ok: false, reason: `JavaScript syntax error: ${err.message}` };
  }
}

function readTemplateSegment(source, startIdx, startLine) {
  let i = startIdx;
  let line = startLine;
  let raw = "`";
  const n = source.length;
  while (i < n) {
    const c = source[i];
    if (c === "\\") {
      if (source[i + 1] === "\n") line++;
      raw += c + (source[i + 1] || "");
      i += 2;
      continue;
    }
    if (c === "\n") line++;
    if (c === "`") {
      raw += "`";
      return { ok: true, nextIndex: i + 1, line, enteredExpr: false, placeholder: raw };
    }
    if (c === "$" && source[i + 1] === "{") {
      raw += "${";
      return { ok: true, nextIndex: i + 2, line, enteredExpr: true, placeholder: raw };
    }
    raw += c;
    i++;
  }
  return { ok: false, reason: "Unterminated template literal" };
}

function serializeTokens(tokens, start, endExclusive) {
  return tokens
    .slice(start, endExclusive)
    .map((t) => t.value)
    .join(" ");
}

function findMatchingCloseIndex(tokens, openIdx) {
  const openVal = tokens[openIdx]?.value;
  const closeVal = openVal === "{" ? "}" : openVal === "(" ? ")" : openVal === "[" ? "]" : null;
  if (!closeVal) return -1;
  const targetDepth = tokens[openIdx].depth;
  for (let i = openIdx + 1; i < tokens.length; i++) {
    if (tokens[i].value === closeVal && tokens[i].depth === targetDepth) {
      return i;
    }
  }
  return -1;
}

/**
 * Advance across balanced `< ... >` type parameters starting at `openAngleIdx` (`tokens[openAngleIdx].value === "<"`).
 * Returns index immediately AFTER closing `>` (or `-1` if unbalanced).
 */
function advanceAngleBracketGroup(tokens, openAngleIdx, baseDepth) {
  if (tokens[openAngleIdx]?.value !== "<") return -1;
  let angleDepth = 0;
  let k = openAngleIdx;
  while (k < tokens.length) {
    const t = tokens[k];
    if (t.depth === baseDepth) {
      if (t.value === "<") {
        angleDepth++;
      } else if ([">", ">>", ">>>"].includes(t.value)) {
        angleDepth -= t.value.length;
        if (angleDepth === 0) return k + 1;
        if (angleDepth < 0) return -1;
      } else if (t.value === ">=") {
        // Rare nested default, fail closed
        return -1;
      } else if (t.value === ";") {
        return -1;
      }
    } else if (t.depth < baseDepth) {
      return -1;
    }
    k++;
  }
  return -1;
}

/**
 * Advance across a TS type expression starting after `:` up to `stopValues` (e.g. `{` body, `;`, `=`, `,`, `=>`),
 * distinguishing object type literals `{ a: number }` from function/method implementation bodies `{ return ... }` (`` #3)!
 */
function advanceTypeAnnotation(tokens, startIdx, baseDepth, { allowBodyBraceStop = false, stopTokens = new Set([";"]) } = {}) {
  let p = startIdx;
  while (p < tokens.length) {
    const tok = tokens[p];
    if (tok.depth < baseDepth) return p;
    if (tok.depth > baseDepth) {
      p++;
      continue;
    }

    if (stopTokens.has(tok.value)) {
      return p;
    }

    if (tok.value === "(" || tok.value === "[") {
      const closeIdx = findMatchingCloseIndex(tokens, p);
      if (closeIdx < 0) return -1;
      p = closeIdx + 1;
      continue;
    }

    if (tok.value === "<") {
      const nextAfterAngle = advanceAngleBracketGroup(tokens, p, baseDepth);
      if (nextAfterAngle < 0) return -1;
      p = nextAfterAngle;
      continue;
    }

    if (tok.value === "{") {
      const prev = tokens[p - 1];
      const isObjectTypeLiteral =
        !allowBodyBraceStop ||
        !prev ||
        TYPE_PREFIX_KEYWORDS_OR_OPS.has(prev.value);
      if (isObjectTypeLiteral) {
        const closeBrace = findMatchingCloseIndex(tokens, p);
        if (closeBrace < 0) return -1;
        p = closeBrace + 1;
        continue;
      }
      // Preceded by a completed type atom (`number`, `}`, `]`, `)`, `>`) -> implementation body `{`!
      return p;
    }

    p++;
  }
  return p;
}

/**
 * Parse `[<generics>] ( params ) [: ReturnType]` starting at `startIdx`, returning index of `{` or `;` (or `-1` if invalid).
 */
function advanceCallableSignatureEnd(tokens, startIdx, baseDepth) {
  let k = startIdx;
  if (tokens[k]?.depth === baseDepth && tokens[k]?.value === "<") {
    const afterGen = advanceAngleBracketGroup(tokens, k, baseDepth);
    if (afterGen < 0) return -1;
    k = afterGen;
  }
  if (tokens[k]?.depth !== baseDepth || tokens[k]?.value !== "(") {
    return -1;
  }
  const closeParen = findMatchingCloseIndex(tokens, k);
  if (closeParen < 0) return -1;
  k = closeParen + 1;

  if (tokens[k]?.depth === baseDepth && tokens[k]?.value === ":") {
    const endType = advanceTypeAnnotation(tokens, k + 1, baseDepth, {
      allowBodyBraceStop: true,
      stopTokens: new Set([";"]),
    });
    if (endType < 0) return -1;
    k = endType;
  }
  return k;
}

function extractClassPublicSurface(tokens, braceIdx, closeBraceIdx) {
  const members = [];
  const bodyDepth = tokens[braceIdx].depth + 1;
  let k = braceIdx + 1;
  while (k < closeBraceIdx) {
    if (tokens[k].depth !== bodyDepth) {
      k++;
      continue;
    }
    if (tokens[k].value === ";") {
      k++;
      continue;
    }
    if (tokens[k].value === "@") {
      return { ok: false, reason: "Decorator on class member may dynamically alter public contract." };
    }

    const memStart = k;
    let cursor = k;
    // Skip modifiers (`public`, `protected`, `private`, `readonly`, `static`, `abstract`, `override`, `async`, `get`, `set`)
    while (
      cursor < closeBraceIdx &&
      tokens[cursor].depth === bodyDepth &&
      ["public", "protected", "private", "readonly", "static", "abstract", "override", "async", "get", "set"].includes(
        tokens[cursor].value
      )
    ) {
      cursor++;
    }
    if (tokens[cursor]?.value === "*") cursor++;

    // Computed property `[sym]` on class -> conservative UNKNOWN unless private
    if (tokens[cursor]?.value === "[") {
      return { ok: false, reason: "Computed class member name cannot be statically verified." };
    }

    const memberNameTok = tokens[cursor];
    cursor++;
    if (tokens[cursor]?.value === "?" || tokens[cursor]?.value === "!") cursor++;

    let headerEnd = -1;
    let isMethodMember = false;
    let hasExplicitFieldType = false;
    if (tokens[cursor]?.depth === bodyDepth && (tokens[cursor]?.value === "<" || tokens[cursor]?.value === "(")) {
      // Method or constructor signature (supports object-literal return types `: { a: number }`!)
      isMethodMember = true;
      headerEnd = advanceCallableSignatureEnd(tokens, cursor, bodyDepth);
      if (headerEnd < 0) {
        return { ok: false, reason: "Malformed class method signature." };
      }
    } else {
      // Property field `prop: { a: number } = ...;`
      headerEnd = cursor;
      if (tokens[headerEnd]?.depth === bodyDepth && tokens[headerEnd]?.value === ":") {
        hasExplicitFieldType = true;
        headerEnd = advanceTypeAnnotation(tokens, headerEnd + 1, bodyDepth, {
          allowBodyBraceStop: false,
          stopTokens: new Set(["=", ";"]),
        });
        if (headerEnd < 0) return { ok: false, reason: "Malformed class field type annotation." };
      }
    }

    const headerTokens = tokens.slice(memStart, headerEnd);
    const isPrivate =
      headerTokens.some((t) => t.value === "private" || t.value.startsWith("#")) ||
      memberNameTok?.value?.startsWith("#");

    // Advance `k` past method body `{ ... }` or field initializer up to `;` or next line member
    k = headerEnd;
    let fieldCallableSuffix = "";
    if (
      !isMethodMember &&
      k < closeBraceIdx &&
      tokens[k].depth === bodyDepth &&
      tokens[k].value === "="
    ) {
      const initStart = k + 1;
      let fieldEnd = initStart;
      while (
        fieldEnd < closeBraceIdx &&
        !(
          tokens[fieldEnd].depth === bodyDepth &&
          (tokens[fieldEnd].value === ";" ||
            (fieldEnd > initStart &&
              tokens[fieldEnd].line > tokens[fieldEnd - 1].line &&
              !BINARY_ONLY_OPERATORS.has(tokens[fieldEnd - 1].value)))
        )
      ) {
        if (
          tokens[fieldEnd].depth === bodyDepth &&
          (tokens[fieldEnd].value === "{" || tokens[fieldEnd].value === "(" || tokens[fieldEnd].value === "[")
        ) {
          const cl = findMatchingCloseIndex(tokens, fieldEnd);
          if (cl > fieldEnd) {
            fieldEnd = cl + 1;
            continue;
          }
        }
        fieldEnd++;
      }

      if (!isPrivate && initStart < fieldEnd) {
        const arrowSig = tryExtractArrowSignature(tokens, initStart, fieldEnd, bodyDepth);
        if (arrowSig) {
          fieldCallableSuffix = ` = ${arrowSig}`;
        } else if (
          tokens[initStart]?.value === "function" ||
          (tokens[initStart]?.value === "async" && tokens[initStart + 1]?.value === "function")
        ) {
          const fnDecl = parseDeclarationAt(tokens, initStart, memberNameTok?.value || "field");
          if (!fnDecl) return { ok: false, reason: "Malformed callable class field initializer." };
          fieldCallableSuffix = ` = ${fnDecl.signature}`;
        } else if (
          fieldEnd === initStart + 1 &&
          tokens[initStart]?.type === "ident" &&
          !["true", "false", "null", "undefined", "NaN", "Infinity", "this"].includes(tokens[initStart].value)
        ) {
          fieldCallableSuffix = ` = @@ALIAS:${tokens[initStart].value}@@`;
        } else if (!hasExplicitFieldType) {
          fieldCallableSuffix = ` = expr:${serializeTokens(tokens, initStart, fieldEnd)}`;
        }
      }
      k = fieldEnd;
      if (k < closeBraceIdx && tokens[k].value === ";") k++;
    } else if (k < closeBraceIdx && tokens[k].depth === bodyDepth && tokens[k].value === "{") {
      const endMem = findMatchingCloseIndex(tokens, k);
      if (endMem < 0) return { ok: false, reason: "Unclosed class method body." };
      k = endMem + 1;
    } else {
      while (
        k < closeBraceIdx &&
        !(
          tokens[k].depth === bodyDepth &&
          (tokens[k].value === ";" ||
            (k > headerEnd && tokens[k].line > tokens[k - 1].line && tokens[headerEnd]?.value !== "="))
        )
      ) {
        if (tokens[k].depth === bodyDepth && (tokens[k].value === "{" || tokens[k].value === "(" || tokens[k].value === "[")) {
          const cl = findMatchingCloseIndex(tokens, k);
          if (cl > k) {
            k = cl + 1;
            continue;
          }
        }
        k++;
      }
      if (k < closeBraceIdx && tokens[k].value === ";") k++;
    }

    if (!isPrivate && headerTokens.length > 0) {
      members.push(`${headerTokens.map((t) => t.value).join(" ")}${fieldCallableSuffix}`);
    }
  }
  return { ok: true, surface: members.join(" | ") };
}

function collectImportedBindings(tokens, importIdx) {
  const bindings = new Map();
  const endIdx = findStatementEnd(tokens, importIdx + 1);
  // Find `from "spec"`
  let fromIdx = -1;
  for (let k = importIdx + 1; k < endIdx; k++) {
    if (tokens[k].depth === 0 && tokens[k].value === "from" && tokens[k + 1]?.type === "string") {
      fromIdx = k;
      break;
    }
  }
  if (fromIdx < 0) return { nextIndex: endIdx, bindings };
  const modSpec = tokens[fromIdx + 1].value;

  let k = importIdx + 1;
  let isTypeImport = false;
  if (tokens[k]?.value === "type" && tokens[k + 1]?.value !== "from") {
    isTypeImport = true;
    k++;
  }

  while (k < fromIdx) {
    const t = tokens[k];
    if (t.value === ",") {
      k++;
      continue;
    }
    if (t.value === "*" && tokens[k + 1]?.value === "as" && tokens[k + 2]?.type === "ident") {
      const local = tokens[k + 2].value;
      bindings.set(local, `${isTypeImport ? "type-" : ""}import-ns:${modSpec}`);
      k += 3;
      continue;
    }
    if (t.value === "{") {
      const closeBrace = findMatchingCloseIndex(tokens, k);
      if (closeBrace > k) {
        const specs = parseExportBraceSpecifiers(tokens, k + 1, closeBrace);
        for (const sp of specs) {
          bindings.set(
            sp.exported,
            `${isTypeImport || sp.isType ? "type-" : ""}import(${sp.local}) from ${modSpec}`
          );
        }
        k = closeBrace + 1;
        continue;
      }
    }
    if (t.type === "ident") {
      bindings.set(t.value, `${isTypeImport ? "type-" : ""}import(default) from ${modSpec}`);
    }
    k++;
  }
  return { nextIndex: fromIdx + 1, bindings };
}

const ASSIGN_OR_UPDATE_OPS = new Set([
  "=", "+=", "-=", "*=", "/=", "**=", "%=", "&=", "|=", "^=",
  "<<=", ">>=", ">>>=", "&&=", "||=", "??=", "++", "--",
]);

const CLASS_MEMBER_MODIFIER_TOKENS = new Set([
  "static",
  "public",
  "private",
  "protected",
  "readonly",
  "declare",
  "override",
  "abstract",
  "accessor",
]);

function collectReassignedTopBindings(tokens, declaredNames) {
  const classBodyScopes = [];
  for (let i = 0; i < tokens.length; i++) {
    if (tokens[i].value === "class" && tokens[i - 1]?.value !== ".") {
      let b = i + 1;
      while (b < tokens.length && !(tokens[b].depth === tokens[i].depth && tokens[b].value === "{")) {
        if (tokens[b].value === ";") {
          b = -1;
          break;
        }
        b++;
      }
      if (b >= 0 && b < tokens.length) {
        const closeIdx = findMatchingCloseIndex(tokens, b);
        if (closeIdx > b) {
          classBodyScopes.push({ openIdx: b, closeIdx, memberDepth: tokens[b].depth + 1 });
        }
      }
    }
  }

  const isClassFieldDeclarationLhs = (idx) => {
    const tok = tokens[idx];
    for (const sc of classBodyScopes) {
      if (idx > sc.openIdx && idx < sc.closeIdx && tok.depth === sc.memberDepth) {
        const prev = tokens[idx - 1];
        if (
          !prev ||
          prev.value === "{" ||
          prev.value === ";" ||
          prev.value === "}" ||
          CLASS_MEMBER_MODIFIER_TOKENS.has(prev.value) ||
          (prev.line < tok.line && !ASSIGN_OR_UPDATE_OPS.has(prev.value) && !BINARY_ONLY_OPERATORS.has(prev.value))
        ) {
          return true;
        }
      }
    }
    return false;
  };

  const reassigned = new Set();
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t.type !== "ident" || !declaredNames.has(t.value)) continue;
    const prev = tokens[i - 1];
    const next = tokens[i + 1];

    // Skip declaration site (`const x =`, `let x : T =`, `function x`, `class x`, property `.x`, class field `class A { f = f }`)
    if (prev && [".", "function", "class", "interface", "type", "enum"].includes(prev.value)) continue;
    if (isClassFieldDeclarationLhs(i)) continue;
    if (prev && ["const", "let", "var", ","].includes(prev.value) && t.depth === 0) {
      // Check if part of top-level variable declarator list
      let b = i - 1;
      let isTopVarDecl = false;
      while (b >= 0 && tokens[b].depth === 0) {
        if (["const", "let", "var"].includes(tokens[b].value)) {
          isTopVarDecl = true;
          break;
        }
        if (tokens[b].value === ";") break;
        b--;
      }
      if (isTopVarDecl) continue;
    }

    if (next && ASSIGN_OR_UPDATE_OPS.has(next.value)) {
      reassigned.add(t.value);
    } else if (prev && (prev.value === "++" || prev.value === "--" || prev.value === "delete")) {
      reassigned.add(t.value);
    }
  }
  return reassigned;
}

function detectDynamicExportOrRuntimeHazards(tokens) {
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    // `eval(...)` or `with (...)`
    if (t.type === "ident" && (t.value === "eval" || t.value === "with") && tokens[i + 1]?.value === "(") {
      return { ok: false, reason: `'${t.value}(...)' dynamic scope/code evaluation cannot be statically verified.` };
    }
    // `delete exports...` or `delete module.exports...` anywhere
    if (
      t.type === "ident" &&
      t.value === "delete" &&
      (tokens[i + 1]?.value === "exports" ||
        (tokens[i + 1]?.value === "module" &&
          tokens[i + 2]?.value === "." &&
          tokens[i + 3]?.value === "exports"))
    ) {
      return { ok: false, reason: "Deleting CommonJS exports cannot be statically verified." };
    }
    // Computed `exports[...]` or `module.exports[...]` OR any `depth > 0` mutation of `exports` / `module.exports` (``)!
    if (t.type === "ident" && t.value === "exports" && tokens[i - 1]?.value !== ".") {
      if (tokens[i + 1]?.value === "[") {
        return { ok: false, reason: "Dynamic computed CommonJS 'exports[...]' mutation cannot be statically verified." };
      }
      if (
        t.depth > 0 &&
        (ASSIGN_OR_UPDATE_OPS.has(tokens[i + 1]?.value) ||
          (tokens[i + 1]?.value === "." &&
            tokens[i + 2]?.type === "ident" &&
            ASSIGN_OR_UPDATE_OPS.has(tokens[i + 3]?.value)))
      ) {
        return {
          ok: false,
          reason: "Conditional or nested CommonJS 'exports' mutation (depth > 0) cannot be statically verified.",
        };
      }
      // Passing `exports` directly into a helper call `mutate(exports)`
      if (
        (tokens[i - 1]?.value === "(" || tokens[i - 1]?.value === ",") &&
        (tokens[i + 1]?.value === "," || tokens[i + 1]?.value === ")")
      ) {
        return {
          ok: false,
          reason: "Passing CommonJS 'exports' object as a function argument cannot be statically verified.",
        };
      }
    }
    if (
      t.type === "ident" &&
      t.value === "module" &&
      tokens[i + 1]?.value === "." &&
      tokens[i + 2]?.value === "exports"
    ) {
      if (tokens[i + 3]?.value === "[") {
        return {
          ok: false,
          reason: "Dynamic computed CommonJS 'module.exports[...]' mutation cannot be statically verified.",
        };
      }
      if (
        t.depth > 0 &&
        (ASSIGN_OR_UPDATE_OPS.has(tokens[i + 3]?.value) ||
          (tokens[i + 3]?.value === "." &&
            tokens[i + 4]?.type === "ident" &&
            ASSIGN_OR_UPDATE_OPS.has(tokens[i + 5]?.value)))
      ) {
        return {
          ok: false,
          reason: "Conditional or nested CommonJS 'module.exports' mutation (depth > 0) cannot be statically verified.",
        };
      }
      if (
        (tokens[i - 1]?.value === "(" || tokens[i - 1]?.value === ",") &&
        (tokens[i + 3]?.value === "," || tokens[i + 3]?.value === ")")
      ) {
        return {
          ok: false,
          reason: "Passing CommonJS 'module.exports' as a function argument cannot be statically verified.",
        };
      }
    }
    // `Object.defineProperty(exports / module.exports, ...)` or `Object.assign(exports / module.exports, ...)`
    if (
      t.type === "ident" &&
      t.value === "Object" &&
      tokens[i + 1]?.value === "." &&
      ["defineProperty", "defineProperties", "assign", "setPrototypeOf"].includes(tokens[i + 2]?.value) &&
      tokens[i + 3]?.value === "(" &&
      (tokens[i + 4]?.value === "exports" ||
        (tokens[i + 4]?.value === "module" &&
          tokens[i + 5]?.value === "." &&
          tokens[i + 6]?.value === "exports"))
    ) {
      return {
        ok: false,
        reason: `Dynamic Object.${tokens[i + 2].value} on CommonJS exports cannot be statically verified.`,
      };
    }
  }
  return { ok: true };
}

/**
 * Extract full normalized public export contracts for JS/TS files (``):
 * - V8 syntax validation for `.js`/`.mjs`/`.cjs` + expression sanity check for `.ts`/`.tsx`
 * - Transitive alias resolution (`const g = f; export { g }`) + reassignment detection
 * - Callable class field signatures (`f = (a) => a`)
 * - Rejects nested/conditional or duplicate CommonJS export mutations
 */
export function scanJsTsExports(source, ext = ".ts") {
  if (ext === ".jsx" || ext === ".tsx") {
    if (/<\/[A-Za-z]|<[A-Z][A-Za-z0-9_.]*\s*[^>]*\/>/.test(source)) {
      return {
        verdict: "UNKNOWN",
        reason: "JSX element syntax requires full AST parser; returning conservative UNKNOWN verdict.",
        exports: new Map(),
      };
    }
  }

  const tokRes = tokenizeJsTs(source);
  if (!tokRes.ok) {
    return { verdict: "UNKNOWN", reason: tokRes.reason, exports: new Map() };
  }
  const { tokens } = tokRes;

  const v8Check = validatePureJsSyntaxViaV8(source, tokens, ext);
  if (!v8Check.ok) {
    return { verdict: "UNKNOWN", reason: v8Check.reason, exports: new Map() };
  }

  const dynCheck = detectDynamicExportOrRuntimeHazards(tokens);
  if (!dynCheck.ok) {
    return { verdict: "UNKNOWN", reason: dynCheck.reason, exports: new Map() };
  }

  const localDecls = new Map();
  const importedBindings = new Map();
  const unparseableTopBindings = new Set();

  // ── PASS 1: Collect all top-level imports & declarations (for forward & alias export resolution) ──
  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i];
    if (tok.depth !== 0) continue;

    if (tok.value === "@") {
      return {
        verdict: "UNKNOWN",
        reason: "Decorators on top-level declarations may dynamically alter exported contracts.",
        exports: new Map(),
      };
    }

    if (tok.value === "import" && tokens[i + 1]?.value !== "(" && tokens[i + 1]?.value !== ".") {
      const imp = collectImportedBindings(tokens, i);
      for (const [k, v] of imp.bindings.entries()) {
        importedBindings.set(k, v);
      }
      i = imp.nextIndex;
      continue;
    }

    let declStart = i;
    const isExported = tok.value === "export";
    if (isExported) {
      declStart++;
      if (tokens[declStart]?.value === "default") declStart++;
      if (tokens[declStart]?.value === "declare") declStart++;
    } else if (tok.value === "declare") {
      declStart++;
    }

    const kwTok = tokens[declStart];
    if (
      kwTok?.type === "ident" &&
      ["function", "async", "class", "abstract", "interface", "type", "enum", "const", "let", "var"].includes(
        kwTok.value
      )
    ) {
      if (isExported && kwTok.value === "type" && (tokens[declStart + 1]?.value === "{" || tokens[declStart + 1]?.value === "*")) {
        continue;
      }
      // Anonymous default declarations have no local binding name, but their
      // callable or class surface is still checked as the default export.
      const isDefault = isExported && tokens[i + 1]?.value === "default";
      if (isDefault && kwTok.value === "async" && tokens[declStart + 1]?.value !== "function") {
        i = Math.max(i, findStatementEnd(tokens, declStart + 1) - 1);
        continue;
      }
      const parsed = parseDeclarationAt(tokens, declStart, isDefault ? "default" : null);
      if (!parsed) {
        if (isExported) {
          return {
            verdict: "UNKNOWN",
            reason: `Unsupported or malformed exported declaration near line ${kwTok.line}`,
            exports: new Map(),
          };
        }
        const stmtEnd = findStatementEnd(tokens, declStart + 1);
        for (let m = declStart + 1; m < stmtEnd; m++) {
          if (tokens[m].type === "ident") unparseableTopBindings.add(tokens[m].value);
        }
        continue;
      }
      for (const item of parsed.names) {
        if (localDecls.has(item.name)) {
          // Duplicate top-level declaration / overload / `var` redeclaration -> conservative UNKNOWN if exported
          unparseableTopBindings.add(item.name);
        } else {
          localDecls.set(item.name, item);
        }
      }
      if (parsed.endIndex > i) {
        i = parsed.endIndex - 1;
      }
    }
  }

  const reassignedTopBindings = collectReassignedTopBindings(tokens, new Set(localDecls.keys()));

  // ── PASS 2: Resolve all ESM & CommonJS exports against complete `localDecls` & `importedBindings` ──
  const exportsMap = new Map();
  let sawModuleExportsWholeAssign = false;
  const seenCjsNamedAssigns = new Set();

  const expandSignatureAliases = (rawSig, visited = new Set()) => {
    if (typeof rawSig !== "string") return null;
    let failed = false;
    let expanded = rawSig.replace(/@@ALIAS:([A-Za-z_$][\w$]*)@@/g, (_m, targetIdent) => {
      const targetSig = resolveBindingSig(targetIdent, new Set(visited));
      if (!targetSig) {
        failed = true;
        return "@@UNRESOLVED@@";
      }
      return `alias(${targetIdent}->${targetSig})`;
    });
    if (failed) return null;

    // Also bind top-level symbol references inside `expr:...` or `default:...` initializers (e.g. `export const api = { f }`)
    const exprMarkerIdx = expanded.indexOf("expr:");
    const scanBody =
      exprMarkerIdx >= 0
        ? expanded.slice(exprMarkerIdx + 5)
        : expanded.startsWith("default:")
          ? expanded.slice(8)
          : null;
    if (scanBody !== null) {
      const refTags = [];
      const seenRefs = new Set();
      for (const m of scanBody.matchAll(/\b([A-Za-z_$][\w$]*)\b/g)) {
        const id = m[1];
        if (seenRefs.has(id) || visited.has(id)) continue;
        if (
          localDecls.has(id) ||
          importedBindings.has(id) ||
          unparseableTopBindings.has(id) ||
          reassignedTopBindings.has(id)
        ) {
          seenRefs.add(id);
          const refSig = resolveBindingSig(id, new Set(visited));
          if (!refSig) return null;
          refTags.push(`${id}=>(${refSig})`);
        }
      }
      if (refTags.length > 0) {
        expanded = `${expanded} [refs:${refTags.sort().join(",")}]`;
      }
    }
    return expanded;
  };

  const resolveBindingSig = (identName, visited = new Set()) => {
    if (visited.has(identName)) return null;
    if (unparseableTopBindings.has(identName) || reassignedTopBindings.has(identName)) {
      return null;
    }
    if (localDecls.has(identName)) {
      const item = localDecls.get(identName);
      const nextVisited = new Set(visited);
      nextVisited.add(identName);
      if (item.aliasOf) {
        const targetSig = resolveBindingSig(item.aliasOf, nextVisited);
        if (!targetSig) return null;
        return item.typeAnnot ? `${item.typeAnnot} -> ${targetSig}` : targetSig;
      }
      return expandSignatureAliases(item.signature, nextVisited);
    }
    if (importedBindings.has(identName)) return importedBindings.get(identName);
    return null;
  };

  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i];
    if (tok.depth !== 0) continue;

    // CommonJS: `module.exports.foo = ...` treated equivalently to `exports.foo = ...`
    const isModuleExportsProp =
      tok.value === "module" &&
      tokens[i + 1]?.value === "." &&
      tokens[i + 2]?.value === "exports" &&
      tokens[i + 3]?.value === "." &&
      tokens[i + 4]?.type === "ident";
    if (isModuleExportsProp) {
      if (tokens[i + 5]?.value !== "=") {
        return { verdict: "UNKNOWN", reason: "Dynamic module.exports property mutation", exports: new Map() };
      }
      const expName = tokens[i + 4].value;
      if (seenCjsNamedAssigns.has(expName)) {
        return { verdict: "UNKNOWN", reason: `Duplicate CommonJS assignment to '${expName}'`, exports: new Map() };
      }
      seenCjsNamedAssigns.add(expName);
      const rhsIdx = i + 6;
      const rhs = tokens[rhsIdx];
      if (!rhs) return { verdict: "UNKNOWN", reason: `Incomplete module.exports.${expName}`, exports: new Map() };
      if (rhs.value === "function" || rhs.value === "async" || rhs.value === "class") {
        const parsed = parseDeclarationAt(tokens, rhsIdx, expName);
        if (!parsed) return { verdict: "UNKNOWN", reason: `Unparseable module.exports.${expName}`, exports: new Map() };
        exportsMap.set(expName, { exportedName: expName, kind: parsed.kind, signature: parsed.signature });
        if (parsed.endIndex > i) i = parsed.endIndex - 1;
      } else if (rhs.type === "ident" && (!tokens[rhsIdx + 1] || tokens[rhsIdx + 1].value === ";" || tokens[rhsIdx + 1].line > rhs.line)) {
        const resolved = resolveBindingSig(rhs.value);
        if (!resolved) return { verdict: "UNKNOWN", reason: `Unresolved '${rhs.value}' in module.exports.${expName}`, exports: new Map() };
        exportsMap.set(expName, { exportedName: expName, kind: "cjs-named", signature: resolved });
        i = rhsIdx;
      } else {
        const endExpr = findStatementEnd(tokens, rhsIdx);
        const arrowSig = tryExtractArrowSignature(tokens, rhsIdx, endExpr, 0);
        if (!arrowSig && !(endExpr === rhsIdx + 1 && ["string", "number"].includes(rhs.type))) {
          return { verdict: "UNKNOWN", reason: `Dynamic expression on module.exports.${expName}`, exports: new Map() };
        }
        exportsMap.set(expName, {
          exportedName: expName,
          kind: "cjs-value",
          signature: arrowSig ? `cjs:${expName} = ${arrowSig}` : `cjs:${expName} = ${rhs.value}`,
        });
        i = Math.max(i, endExpr - 1);
      }
      continue;
    }

    // CommonJS: `module.exports = ...`
    if (
      tok.value === "module" &&
      tokens[i + 1]?.value === "." &&
      tokens[i + 2]?.value === "exports" &&
      tokens[i + 3]?.value === "="
    ) {
      if (sawModuleExportsWholeAssign || seenCjsNamedAssigns.size > 0) {
        return {
          verdict: "UNKNOWN",
          reason: "Reassigned or mixed CommonJS module.exports / exports assignments cannot be statically verified.",
          exports: new Map(),
        };
      }
      sawModuleExportsWholeAssign = true;
      const rhs = tokens[i + 4];
      if (!rhs) return { verdict: "UNKNOWN", reason: "Incomplete module.exports assignment", exports: new Map() };
      if (rhs.value === "{") {
        const closeIdx = findMatchingCloseIndex(tokens, i + 4);
        if (closeIdx < 0) return { verdict: "UNKNOWN", reason: "Unclosed module.exports object", exports: new Map() };
        const objRes = parseCjsExportObject(tokens, i + 4, closeIdx, resolveBindingSig);
        if (!objRes.ok) return { verdict: "UNKNOWN", reason: objRes.reason, exports: new Map() };
        for (const [k, sig] of objRes.entries) {
          exportsMap.set(k, sig);
        }
        i = closeIdx;
        continue;
      } else if (rhs.type === "ident" && (rhs.value === "function" || rhs.value === "async" || rhs.value === "class")) {
        const parsed = parseDeclarationAt(tokens, i + 4, "default");
        if (!parsed) return { verdict: "UNKNOWN", reason: "Malformed inline module.exports declaration", exports: new Map() };
        exportsMap.set("default", {
          exportedName: "default",
          kind: `cjs-${parsed.kind}`,
          signature: parsed.signature,
        });
        if (parsed.endIndex > i) i = parsed.endIndex - 1;
        continue;
      } else if (rhs.type === "ident") {
        const resolved = resolveBindingSig(rhs.value);
        const afterRhs = tokens[i + 5];
        const isBareIdent = !afterRhs || afterRhs.value === ";" || afterRhs.line > rhs.line;
        if (resolved && isBareIdent) {
          exportsMap.set("default", {
            exportedName: "default",
            kind: "cjs-default",
            signature: resolved,
          });
          i += 4;
          continue;
        }
        return {
          verdict: "UNKNOWN",
          reason: "Dynamic or unresolved module.exports assignment.",
          exports: new Map(),
        };
      } else {
        return {
          verdict: "UNKNOWN",
          reason: "Dynamic or computed module.exports assignment.",
          exports: new Map(),
        };
      }
    }

    // CommonJS: `exports.foo = ...`
    if (tok.value === "exports" && tokens[i + 1]?.value === "." && tokens[i + 2]?.type === "ident") {
      if (tokens[i + 3]?.value !== "=") {
        return { verdict: "UNKNOWN", reason: "Dynamic CommonJS exports mutation", exports: new Map() };
      }
      const expName = tokens[i + 2].value;
      if (sawModuleExportsWholeAssign || seenCjsNamedAssigns.has(expName)) {
        return {
          verdict: "UNKNOWN",
          reason: `Reassigned or conflicting CommonJS export '${expName}' cannot be statically verified.`,
          exports: new Map(),
        };
      }
      seenCjsNamedAssigns.add(expName);
      const rhs = tokens[i + 4];
      if (!rhs) return { verdict: "UNKNOWN", reason: `Incomplete exports.${expName} assignment`, exports: new Map() };
      if (rhs.value === "function" || rhs.value === "async" || rhs.value === "class") {
        const parsed = parseDeclarationAt(tokens, i + 4, expName);
        if (!parsed) return { verdict: "UNKNOWN", reason: `Unparseable exports.${expName}`, exports: new Map() };
        exportsMap.set(expName, {
          exportedName: expName,
          kind: parsed.kind,
          signature: parsed.signature,
        });
        if (parsed.endIndex > i) i = parsed.endIndex - 1;
      } else if (rhs.type === "ident" && (!tokens[i + 5] || tokens[i + 5].value === ";" || tokens[i + 5].line > rhs.line)) {
        const resolved = resolveBindingSig(rhs.value);
        if (!resolved) {
          return { verdict: "UNKNOWN", reason: `Unresolved binding '${rhs.value}' in exports.${expName}`, exports: new Map() };
        }
        exportsMap.set(expName, {
          exportedName: expName,
          kind: "cjs-named",
          signature: resolved,
        });
      } else {
        const endExpr = findStatementEnd(tokens, i + 4);
        const arrowSig = tryExtractArrowSignature(tokens, i + 4, endExpr, 0);
        if (!arrowSig && !(endExpr === i + 5 && ["string", "number"].includes(rhs.type))) {
          return {
            verdict: "UNKNOWN",
            reason: `Dynamic expression in exports.${expName} cannot be statically verified.`,
            exports: new Map(),
          };
        }
        exportsMap.set(expName, {
          exportedName: expName,
          kind: "cjs-value",
          signature: arrowSig ? `cjs:${expName} = ${arrowSig}` : `cjs:${expName} = ${rhs.value}`,
        });
      }
      continue;
    }

    // ESM `export ...`
    if (tok.value === "export") {
      let cursor = i + 1;
      let isTypeOnly = false;
      if (tokens[cursor]?.value === "type" && (tokens[cursor + 1]?.value === "{" || tokens[cursor + 1]?.value === "*")) {
        isTypeOnly = true;
        cursor++;
      }

      // `export * [as ns] from './mod'`
      if (tokens[cursor]?.value === "*") {
        let ns = "*";
        let p = cursor + 1;
        if (tokens[p]?.value === "as" && tokens[p + 1]?.type === "ident") {
          ns = `* as ${tokens[p + 1].value}`;
          p += 2;
        }
        if (tokens[p]?.value !== "from" || tokens[p + 1]?.type !== "string") {
          return { verdict: "UNKNOWN", reason: "Malformed export * clause", exports: new Map() };
        }
        const fromSpec = tokens[p + 1].value;
        const key = `reexport:${ns}:${fromSpec}`;
        exportsMap.set(key, {
          exportedName: key,
          kind: isTypeOnly ? "type-reexport-all" : "reexport-all",
          signature: `${isTypeOnly ? "type " : ""}${ns} from ${fromSpec}`,
        });
        i = p + 1;
        continue;
      }

      // `export { a, b as c } [from './mod']`
      if (tokens[cursor]?.value === "{") {
        const closeIdx = findMatchingCloseIndex(tokens, cursor);
        if (closeIdx < 0) return { verdict: "UNKNOWN", reason: "Unclosed export { ... }", exports: new Map() };
        let fromSpec = null;
        if (tokens[closeIdx + 1]?.value === "from") {
          if (tokens[closeIdx + 2]?.type !== "string") {
            return { verdict: "UNKNOWN", reason: "Malformed export { ... } from clause", exports: new Map() };
          }
          fromSpec = tokens[closeIdx + 2].value;
        }
        const specRes = parseExportBraceSpecifiersStrict(tokens, cursor + 1, closeIdx);
        if (!specRes.ok) {
          return { verdict: "UNKNOWN", reason: specRes.reason, exports: new Map() };
        }
        for (const sp of specRes.specifiers) {
          let baseSig;
          if (fromSpec) {
            baseSig = `reexport(${sp.local}->${sp.exported}) from ${fromSpec}`;
          } else {
            const resolved = resolveBindingSig(sp.local);
            if (!resolved) {
              return {
                verdict: "UNKNOWN",
                reason: `Export specifier '${sp.local}' could not be resolved to an immutable static top-level declaration.`,
                exports: new Map(),
              };
            }
            baseSig = resolved;
          }
          exportsMap.set(sp.exported, {
            exportedName: sp.exported,
            kind: sp.isType || isTypeOnly ? "type-specifier" : "named-specifier",
            signature: baseSig,
          });
        }
        i = fromSpec ? closeIdx + 2 : closeIdx;
        continue;
      }

      // `export default ...`
      if (tokens[cursor]?.value === "default") {
        const decl = parseDeclarationAt(tokens, cursor + 1, "default");
        if (decl) {
          if (decl.name !== "default" && reassignedTopBindings.has(decl.name)) {
            return { verdict: "UNKNOWN", reason: `Default exported binding '${decl.name}' is reassigned.`, exports: new Map() };
          }
          exportsMap.set("default", {
            exportedName: "default",
            kind: `default-${decl.kind}`,
            signature: decl.signature,
          });
          if (decl.endIndex > i) i = decl.endIndex - 1;
        } else {
          const endExpr = findStatementEnd(tokens, cursor + 1);
          const singleTok = endExpr === cursor + 2 ? tokens[cursor + 1] : null;
          if (singleTok && singleTok.type === "ident") {
            const resolved = resolveBindingSig(singleTok.value);
            if (!resolved) {
              return {
                verdict: "UNKNOWN",
                reason: `Unresolved default export identifier '${singleTok.value}'.`,
                exports: new Map(),
              };
            }
            exportsMap.set("default", {
              exportedName: "default",
              kind: "default-ident",
              signature: `default->${resolved}`,
            });
          } else {
            const arrowSig = tryExtractArrowSignature(tokens, cursor + 1, endExpr, 0);
            exportsMap.set("default", {
              exportedName: "default",
              kind: "default-expr",
              signature: arrowSig
                ? `default:${arrowSig}`
                : `default:${serializeTokens(tokens, cursor + 1, endExpr)}`,
            });
          }
          i = Math.max(i, endExpr - 1);
        }
        continue;
      }

      if (tokens[cursor]?.value === "declare") {
        cursor++;
      }

      const decl = parseDeclarationAt(tokens, cursor);
      if (!decl || !decl.names || decl.names.length === 0) {
        return {
          verdict: "UNKNOWN",
          reason: `Unsupported export construct near line ${tok.line}`,
          exports: new Map(),
        };
      }
      for (const nameItem of decl.names) {
        if (reassignedTopBindings.has(nameItem.name) || unparseableTopBindings.has(nameItem.name)) {
          return {
            verdict: "UNKNOWN",
            reason: `Exported symbol '${nameItem.name}' is reassigned or redeclared.`,
            exports: new Map(),
          };
        }
        let effectiveSig = nameItem.signature;
        if (nameItem.aliasOf) {
          const resolvedAlias = resolveBindingSig(nameItem.name);
          if (!resolvedAlias) {
            return {
              verdict: "UNKNOWN",
              reason: `Exported alias '${nameItem.name}' targets unresolved or mutable symbol '${nameItem.aliasOf}'.`,
              exports: new Map(),
            };
          }
          effectiveSig = `${decl.kind} ${nameItem.name} -> ${resolvedAlias}`;
        }
        exportsMap.set(nameItem.name, {
          exportedName: nameItem.name,
          kind: decl.kind,
          signature: effectiveSig,
        });
      }
      if (decl.endIndex > i) {
        i = decl.endIndex - 1;
      }
    }
  }

  for (const [expKey, expVal] of exportsMap.entries()) {
    const selfSet = new Set([expKey]);
    const finalSig = expandSignatureAliases(expVal.signature, selfSet);
    if (!finalSig) {
      return {
        verdict: "UNKNOWN",
        reason: `Exported declaration '${expKey}' references an unresolved or mutable binding.`,
        exports: new Map(),
      };
    }
    exportsMap.set(expKey, { ...expVal, signature: finalSig });
  }

  return { verdict: "OK", exports: exportsMap };
}

function findStatementEnd(tokens, startIdx) {
  let k = startIdx;
  const baseDepth = tokens[startIdx]?.depth ?? 0;
  while (k < tokens.length) {
    if (tokens[k].depth === baseDepth && tokens[k].value === ";") {
      return k;
    }
    if (
      k > startIdx &&
      tokens[k].depth === 0 &&
      tokens[k].line > tokens[k - 1].line &&
      ["export", "import", "function", "class", "abstract", "interface", "type", "enum", "const", "let", "var"].includes(
        tokens[k].value
      ) &&
      !BINARY_ONLY_OPERATORS.has(tokens[k - 1].value) &&
      tokens[k - 1].value !== "=" &&
      tokens[k - 1].value !== ":"
    ) {
      return k;
    }
    k++;
  }
  return k;
}

function tryExtractArrowSignature(tokens, startIdx, limitIdx, baseDepth) {
  let q = startIdx;
  let prefix = "";
  if (tokens[q]?.depth === baseDepth && tokens[q]?.value === "async") {
    prefix = "async ";
    q++;
  }
  // Single-ident arrow `x => ...`
  if (tokens[q]?.depth === baseDepth && tokens[q]?.type === "ident" && tokens[q + 1]?.value === "=>") {
    return `${prefix}( ${tokens[q].value} ) =>`;
  }
  // `[<T>](a: number): { x: number } => ...`
  const sigStart = q;
  if (tokens[q]?.depth === baseDepth && (tokens[q]?.value === "<" || tokens[q]?.value === "(")) {
    let p = q;
    if (tokens[p].value === "<") {
      const afterGen = advanceAngleBracketGroup(tokens, p, baseDepth);
      if (afterGen < 0 || afterGen >= limitIdx) return null;
      p = afterGen;
    }
    if (tokens[p]?.depth !== baseDepth || tokens[p]?.value !== "(") return null;
    const closeParen = findMatchingCloseIndex(tokens, p);
    if (closeParen < 0 || closeParen >= limitIdx) return null;
    let r = closeParen + 1;
    if (tokens[r]?.depth === baseDepth && tokens[r]?.value === ":") {
      r = advanceTypeAnnotation(tokens, r + 1, baseDepth, {
        allowBodyBraceStop: false,
        stopTokens: new Set(["=>", ",", ";"]),
      });
      if (r < 0 || r > limitIdx) return null;
    }
    if (tokens[r]?.depth === baseDepth && tokens[r]?.value === "=>") {
      return `${prefix}${serializeTokens(tokens, sigStart, r)} =>`;
    }
  }
  return null;
}

function parseDeclarationAt(tokens, idx, fallbackName = null) {
  let k = idx;
  const baseDepth = tokens[idx]?.depth ?? 0;
  let isAsync = false;
  if (tokens[k]?.value === "async" && tokens[k + 1]?.value === "function") {
    isAsync = true;
    k++;
  }
  const kw = tokens[k]?.value;

  if (kw === "function") {
    k++;
    let isGen = false;
    if (tokens[k]?.value === "*") {
      isGen = true;
      k++;
    }
    const name = tokens[k]?.type === "ident" ? tokens[k++].value : fallbackName;
    if (!name) return null;

    const headerStart = k;
    const headerEnd = advanceCallableSignatureEnd(tokens, headerStart, baseDepth);
    if (headerEnd < 0) return null;
    if (tokens[headerEnd]?.value !== "{" && tokens[headerEnd]?.value !== ";") {
      return null;
    }

    let endIndex = headerEnd + 1;
    if (tokens[headerEnd]?.value === "{") {
      const closeBody = findMatchingCloseIndex(tokens, headerEnd);
      if (closeBody < 0) return null;
      // Validate body is not empty garbage if needed; closeBody + 1 ends declaration
      endIndex = closeBody + 1;
    }

    const sig = `${isAsync ? "async " : ""}function${isGen ? "*" : ""} ${name} ${serializeTokens(
      tokens,
      headerStart,
      headerEnd
    )}`.trim();
    return { kind: "function", name, names: [{ name, signature: sig }], signature: sig, endIndex };
  }

  if (kw === "class" || (kw === "abstract" && tokens[k + 1]?.value === "class")) {
    const isAbstract = kw === "abstract";
    k += isAbstract ? 2 : 1;
    const name = tokens[k]?.type === "ident" ? tokens[k++].value : fallbackName;
    if (!name) return null;
    const headerStart = k;
    while (k < tokens.length && !(tokens[k].depth === baseDepth && tokens[k].value === "{")) {
      if (tokens[k].depth === baseDepth && tokens[k].value === ";") return null;
      k++;
    }
    if (k >= tokens.length) return null;
    const closeBrace = findMatchingCloseIndex(tokens, k);
    if (closeBrace < 0) return null;
    const heritage = serializeTokens(tokens, headerStart, k);
    const surf = extractClassPublicSurface(tokens, k, closeBrace);
    if (!surf.ok) return null;
    const sig = `${isAbstract ? "abstract " : ""}class ${name} ${heritage} { ${surf.surface} }`.trim();
    return { kind: "class", name, names: [{ name, signature: sig }], signature: sig, endIndex: closeBrace + 1 };
  }

  if (kw === "interface" || kw === "enum" || (kw === "const" && tokens[k + 1]?.value === "enum")) {
    const isConstEnum = kw === "const";
    const actualKw = isConstEnum ? "const enum" : kw;
    k += isConstEnum ? 2 : 1;
    const name = tokens[k]?.type === "ident" ? tokens[k++].value : null;
    if (!name) return null;
    const headerStart = k;
    while (k < tokens.length && !(tokens[k].depth === baseDepth && tokens[k].value === "{")) {
      if (tokens[k].depth === baseDepth && tokens[k].value === ";") return null;
      k++;
    }
    if (k >= tokens.length) return null;
    const closeBrace = findMatchingCloseIndex(tokens, k);
    if (closeBrace < 0) return null;
    const fullTokens = serializeTokens(tokens, headerStart, closeBrace + 1);
    const sig = `${actualKw} ${name} ${fullTokens}`.trim();
    return { kind: actualKw, name, names: [{ name, signature: sig }], signature: sig, endIndex: closeBrace + 1 };
  }

  if (kw === "type" && tokens[k + 1]?.type === "ident") {
    const name = tokens[k + 1].value;
    let p = k + 2;
    if (tokens[p]?.value === "<") {
      const afterGen = advanceAngleBracketGroup(tokens, p, baseDepth);
      if (afterGen < 0) return null;
      p = afterGen;
    }
    if (tokens[p]?.value !== "=") return null;
    const endType = advanceTypeAnnotation(tokens, p + 1, baseDepth, {
      allowBodyBraceStop: false,
      stopTokens: new Set([";"]),
    });
    const stmtEnd = findStatementEnd(tokens, p + 1);
    const actualEnd = endType > 0 ? Math.min(endType, stmtEnd) : stmtEnd;
    const body = serializeTokens(tokens, k + 2, actualEnd);
    const sig = `type ${name} ${body}`.trim();
    return { kind: "type", name, names: [{ name, signature: sig }], signature: sig, endIndex: actualEnd };
  }

  // Multi-declarator `const a = 1, b = (x: number): string => ...` (`` #2)
  if (kw === "const" || kw === "let" || kw === "var") {
    k++;
    const stmtEnd = findStatementEnd(tokens, k);
    const names = [];
    let cursor = k;

    while (cursor < stmtEnd) {
      if (tokens[cursor]?.depth === baseDepth && tokens[cursor]?.value === ",") {
        cursor++;
        continue;
      }
      if (tokens[cursor]?.depth === baseDepth && tokens[cursor]?.value === "{") {
        const closePattern = findMatchingCloseIndex(tokens, cursor);
        if (closePattern < 0 || tokens[closePattern + 1]?.value !== "=") return null;
        const bindings = [];
        let part = cursor + 1;
        while (part < closePattern) {
          if (tokens[part]?.type !== "ident" || tokens[part].depth !== baseDepth + 1) return null;
          const propertyName = tokens[part++].value;
          let localName = propertyName;
          if (tokens[part]?.value === ":") {
            part++;
            if (tokens[part]?.type !== "ident" || tokens[part].depth !== baseDepth + 1) return null;
            localName = tokens[part++].value;
          }
          bindings.push({ propertyName, localName });
          if (part < closePattern && tokens[part++]?.value !== ",") return null;
        }
        if (bindings.length === 0) return null;

        const initStart = closePattern + 2;
        let declEnd = initStart;
        while (declEnd < stmtEnd) {
          if (tokens[declEnd].depth === baseDepth && tokens[declEnd].value === ",") break;
          if (tokens[declEnd].depth === baseDepth && ["(", "[", "{"].includes(tokens[declEnd].value)) {
            const close = findMatchingCloseIndex(tokens, declEnd);
            if (close < 0) return null;
            declEnd = close + 1;
            continue;
          }
          declEnd++;
        }
        if (initStart >= declEnd) return null;
        const initializer = serializeTokens(tokens, initStart, declEnd);
        for (const binding of bindings) {
          names.push({
            name: binding.localName,
            signature: `${kw} ${binding.localName} = destructure ${binding.propertyName} from ${initializer}`,
            aliasOf: null,
            typeAnnot: "",
          });
        }
        cursor = declEnd;
        if (tokens[cursor]?.depth === baseDepth && tokens[cursor]?.value === ",") {
          cursor++;
          if (cursor >= stmtEnd) return null;
        }
        continue;
      }
      if (tokens[cursor]?.type !== "ident") {
        // Other destructuring forms remain UNKNOWN until they can be checked safely.
        return null;
      }
      const declName = tokens[cursor].value;
      cursor++;
      if (tokens[cursor]?.value === "!") cursor++;

      let typeAnnot = "";
      if (tokens[cursor]?.depth === baseDepth && tokens[cursor]?.value === ":") {
        const typeStart = cursor + 1;
        const typeEnd = advanceTypeAnnotation(tokens, typeStart, baseDepth, {
          allowBodyBraceStop: false,
          stopTokens: new Set(["=", ",", ";"]),
        });
        if (typeEnd < 0) return null;
        typeAnnot = `: ${serializeTokens(tokens, typeStart, Math.min(typeEnd, stmtEnd))}`;
        cursor = Math.min(typeEnd, stmtEnd);
      }

      // Find end of this declarator (next `,` at `baseDepth`, or `stmtEnd`)
      let declEnd = cursor;
      while (declEnd < stmtEnd) {
        if (tokens[declEnd].depth === baseDepth && tokens[declEnd].value === ",") break;
        if (tokens[declEnd].depth === baseDepth && ["(", "[", "{"].includes(tokens[declEnd].value)) {
          const cl = findMatchingCloseIndex(tokens, declEnd);
          if (cl < 0) return null;
          declEnd = cl + 1;
          continue;
        }
        declEnd++;
      }

      let callableInitSig = "";
      let aliasOf = null;
      if (tokens[cursor]?.depth === baseDepth && tokens[cursor]?.value === "=") {
        const initStart = cursor + 1;
        if (initStart >= declEnd) return null;
        const arrowSig = tryExtractArrowSignature(tokens, initStart, declEnd, baseDepth);
        if (arrowSig) {
          callableInitSig = arrowSig;
        } else if (
          tokens[initStart]?.value === "function" ||
          (tokens[initStart]?.value === "async" && tokens[initStart + 1]?.value === "function") ||
          tokens[initStart]?.value === "class"
        ) {
          const fnDecl = parseDeclarationAt(tokens, initStart, declName);
          if (!fnDecl) return null;
          callableInitSig = fnDecl.signature;
        } else if (
          declEnd === initStart + 1 &&
          tokens[initStart]?.type === "ident" &&
          !["true", "false", "null", "undefined", "NaN", "Infinity"].includes(tokens[initStart].value)
        ) {
          // Track alias target `const g = f` (``) so `export { g }` resolves `f`'s full contract!
          aliasOf = tokens[initStart].value;
        } else if (!typeAnnot) {
          // Untyped value/expression initializer: include normalized expression tokens so exported value mutations are detected
          callableInitSig = `expr:${serializeTokens(tokens, initStart, declEnd)}`;
        }
      }

      const sig = `${kw} ${declName}${typeAnnot}${callableInitSig ? ` = ${callableInitSig}` : ""}`.trim();
      names.push({ name: declName, signature: sig, aliasOf, typeAnnot });
      cursor = declEnd;
      if (tokens[cursor]?.depth === baseDepth && tokens[cursor]?.value === ",") {
        cursor++;
        if (cursor >= stmtEnd) return null; // Trailing comma in `const a = 1,` is invalid JS!
      }
    }

    if (names.length === 0) return null;
    return {
      kind: "variable",
      name: names[0].name,
      names,
      signature: names[0].signature,
      endIndex: tokens[stmtEnd]?.value === ";" ? stmtEnd + 1 : stmtEnd,
    };
  }

  return null;
}

function parseExportBraceSpecifiers(tokens, startIdx, closeIdx) {
  const res = parseExportBraceSpecifiersStrict(tokens, startIdx, closeIdx);
  return res.ok ? res.specifiers : [];
}

function parseExportBraceSpecifiersStrict(tokens, startIdx, closeIdx) {
  const specifiers = [];
  let k = startIdx;
  while (k < closeIdx) {
    if (tokens[k].value === ",") {
      k++;
      continue;
    }
    let isType = false;
    if (tokens[k].value === "type" && (tokens[k + 1]?.type === "ident" || tokens[k + 1]?.type === "string")) {
      if (tokens[k + 1]?.value !== "as") {
        isType = true;
        k++;
      }
    }
    const localTok = tokens[k];
    if (!localTok || (localTok.type !== "ident" && localTok.type !== "string")) {
      return { ok: false, reason: "Invalid token in export { ... } specifier list" };
    }
    const local = localTok.type === "string" ? localTok.value.slice(1, -1) : localTok.value;
    k++;
    let exported = local;
    if (tokens[k]?.value === "as") {
      const expTok = tokens[k + 1];
      if (!expTok || (expTok.type !== "ident" && expTok.type !== "string")) {
        return { ok: false, reason: "Invalid alias in export { ... } specifier" };
      }
      exported = expTok.type === "string" ? expTok.value.slice(1, -1) : expTok.value;
      k += 2;
    }
    if (k < closeIdx && tokens[k].value !== ",") {
      return { ok: false, reason: "Unexpected token inside export { ... } specifier" };
    }
    specifiers.push({ local, exported, isType });
  }
  return { ok: true, specifiers };
}

function parseCjsExportObject(tokens, openBraceIdx, closeBraceIdx, resolveBindingSig) {
  const entries = [];
  const innerDepth = tokens[openBraceIdx].depth + 1;
  let k = openBraceIdx + 1;
  while (k < closeBraceIdx) {
    if (tokens[k].value === ",") {
      k++;
      continue;
    }
    if (tokens[k].value === "...") {
      return { ok: false, reason: "Dynamic spread in module.exports object" };
    }
    if (tokens[k].value === "get" || tokens[k].value === "set") {
      return { ok: false, reason: "Getter/setter in module.exports object cannot be statically verified" };
    }
    const keyTok = tokens[k];
    if (!keyTok || (keyTok.type !== "ident" && keyTok.type !== "string")) {
      return { ok: false, reason: "Computed key in module.exports object" };
    }
    const exportedName = keyTok.type === "string" ? keyTok.value.slice(1, -1) : keyTok.value;
    k++;
    if (tokens[k]?.value === "," || k === closeBraceIdx) {
      const resolved = resolveBindingSig(exportedName);
      if (!resolved) {
        return { ok: false, reason: `Unresolved shorthand binding '${exportedName}' in module.exports` };
      }
      entries.push([
        exportedName,
        {
          exportedName,
          kind: "cjs-shorthand",
          signature: resolved,
        },
      ]);
      continue;
    }
    if (tokens[k]?.value === ":") {
      k++;
      const valTok = tokens[k];
      if (valTok?.type === "ident" && (tokens[k + 1]?.value === "," || k + 1 === closeBraceIdx)) {
        const resolved = resolveBindingSig(valTok.value);
        if (!resolved && !["true", "false", "null", "undefined"].includes(valTok.value)) {
          return { ok: false, reason: `Unresolved property binding '${valTok.value}' in module.exports` };
        }
        entries.push([
          exportedName,
          {
            exportedName,
            kind: "cjs-prop",
            signature: resolved || `cjs-lit:${valTok.value}`,
          },
        ]);
        k++;
        continue;
      }
      const valStart = k;
      while (k < closeBraceIdx && !(tokens[k].depth === innerDepth && tokens[k].value === ",")) {
        k++;
      }
      const arrowSig = tryExtractArrowSignature(tokens, valStart, k, innerDepth);
      entries.push([
        exportedName,
        {
          exportedName,
          kind: "cjs-inline",
          signature: arrowSig
            ? `cjs:${exportedName} = ${arrowSig}`
            : `cjs:${exportedName}:${sha256Short(serializeTokens(tokens, valStart, k))}`,
        },
      ]);
      continue;
    }
    if (tokens[k]?.value === "(" || tokens[k]?.value === "<") {
      const headerStart = k;
      const headerEnd = advanceCallableSignatureEnd(tokens, headerStart, innerDepth);
      if (headerEnd < 0 || tokens[headerEnd]?.value !== "{") {
        return { ok: false, reason: "Unbalanced method in module.exports" };
      }
      const closeMethod = findMatchingCloseIndex(tokens, headerEnd);
      if (closeMethod < 0) return { ok: false, reason: "Unclosed method body in module.exports" };
      const paramsSig = serializeTokens(tokens, headerStart, headerEnd);
      entries.push([
        exportedName,
        {
          exportedName,
          kind: "cjs-method",
          signature: `method ${exportedName} ${paramsSig}`,
        },
      ]);
      k = closeMethod + 1;
      continue;
    }
    return { ok: false, reason: "Unsupported syntax in module.exports" };
  }
  return { ok: true, entries };
}

/**
 * Python lexical scanner (`` #4, #5):
 * - Replaces string literals with deterministic `"__STR_<sha256>__"` tokens so string-valued defaults
 *   (`def f(x="a"):` vs `def f(x="b"):`) are preserved while neutralizing inner brackets/colons!
 * - Inspects top-level `class` bodies to extract all public method headers (`def` / `async def` + `__init__`/`__call__`)!
 */
export function scanPythonExports(source) {
  const lexRes = stripPythonStringsAndComments(source);
  if (!lexRes.ok) {
    return { verdict: "UNKNOWN", reason: lexRes.reason, exports: new Map() };
  }
  const cleaned = lexRes.cleaned;

  // Reject dynamic namespace/reflection calls anywhere in module (`globals()`, `setattr()`, `sys.modules`, `exec`, `eval`)
  const dynamicCalls = Array.from(cleaned.matchAll(/\b(globals|locals|setattr|delattr|exec|eval|__import__)\s*\(/g));
  const hasDynamicCall = dynamicCalls.some((match) => {
    // PyTorch's model.eval() is an ordinary zero-argument method. A real
    // evaluator still needs an argument; preserve conservative handling for
    // direct eval(), attribute eval(code), and every other reflective call.
    const before = cleaned.slice(0, match.index);
    const afterOpen = cleaned.slice(match.index + match[0].length);
    return !(match[1] === "eval" && /\.\s*$/.test(before) && !/(?:\b|^)(?:builtins|__builtins__)\s*\.\s*$/.test(before) && /^\s*\)/.test(afterOpen));
  });
  if (hasDynamicCall || /sys\.modules\b|__all__\s*\.\s*(?:append|extend|remove|pop|insert|clear)\b/.test(cleaned)) {
    return {
      verdict: "UNKNOWN",
      reason: "Dynamic Python namespace or reflection mutation detected.",
      exports: new Map(),
    };
  }

  const lines = cleaned.split("\n");
  const exportsMap = new Map();
  const seenTopLevelBindings = new Set();
  const decoratorImports = new Map();
  let pendingDecorators = [];
  let explicitAll = null;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (!trimmed) continue;
    const indent = line.match(/^[ \t]*/)[0];
    if (indent.length > 0) {
      // Unexpected indented line not consumed by a parsed top-level `def`/`class`/`if __name__` suite
      return {
        verdict: "UNKNOWN",
        reason: `Unverified indented statement outside top-level declaration at line ${i + 1}.`,
        exports: new Map(),
      };
    }

    // Semicolon multi-statement on a top-level Python line -> conservative UNKNOWN
    if (trimmed.includes(";")) {
      return {
        verdict: "UNKNOWN",
        reason: `Semicolon compound top-level Python statement at line ${i + 1} cannot be statically verified.`,
        exports: new Map(),
      };
    }

    if (trimmed.startsWith("@")) {
      const decorator = resolvePythonDecorator(trimmed, decoratorImports);
      if (!decorator) return { verdict: "UNKNOWN", reason: "Top-level Python decorator is outside the supported imported decorator subset.", exports: new Map() };
      pendingDecorators.push(decorator);
      continue;
    }

    if (pendingDecorators.length && !/^(?:async\s+def|def|class)\s/.test(trimmed)) {
      return { verdict: "UNKNOWN", reason: "Python decorators are not followed by a declaration.", exports: new Map() };
    }

    if (/^del\b/.test(trimmed)) {
      return {
        verdict: "UNKNOWN",
        reason: "Top-level 'del' mutates Python module namespace.",
        exports: new Map(),
      };
    }

    if (/^from\s+\S+\s+import\s+\*/.test(trimmed)) {
      return {
        verdict: "UNKNOWN",
        reason: "Wildcard 'from ... import *' mutates Python module exports dynamically.",
        exports: new Map(),
      };
    }

    // Top-level control-flow blocks (`if`, `try`, `for`, `while`, `with`, `match`):
    // Allow standard `if __name__ == "__main__":` entrypoint guard; reject any other conditional/dynamic top-level block!
    if (/^(?:if|elif|else|try|except|finally|for|async\s+for|while|with|async\s+with|match)\b/.test(trimmed)) {
      const origLine = lexRes.extractOriginalSlice(i, i).trim();
      const isMainGuard = /^if\s+__name__\s*==\s*['"]__main__['"]\s*:\s*(?:#.*)?$/.test(origLine);
      if (!isMainGuard) {
        return {
          verdict: "UNKNOWN",
          reason: `Conditional or dynamic top-level '${trimmed.split(/\s|:/)[0]}' block cannot be statically verified.`,
          exports: new Map(),
        };
      }
      // Advance past `if __name__ == "__main__":` indented suite
      let m = i + 1;
      while (m < lines.length && (!lines[m].trim() || /^[ \t]/.test(lines[m]))) {
        m++;
      }
      i = m - 1;
      continue;
    }

    if (/^__all__\s*(?:\+=|=|:)/.test(trimmed)) {
      if (!/^__all__\s*=/.test(trimmed)) {
        return { verdict: "UNKNOWN", reason: "Dynamic __all__ mutation", exports: new Map() };
      }
      if (seenTopLevelBindings.has("__all__")) {
        return { verdict: "UNKNOWN", reason: "Duplicate __all__ assignment", exports: new Map() };
      }
      seenTopLevelBindings.add("__all__");
      let acc = line;
      let j = i;
      while (j + 1 < lines.length && !isBalancedBrackets(acc)) {
        j++;
        acc += "\n" + lines[j];
      }
      if (!isBalancedBrackets(acc)) {
        return { verdict: "UNKNOWN", reason: "Unbalanced __all__ definition", exports: new Map() };
      }
      if (/\+|\*/.test(acc)) {
        return { verdict: "UNKNOWN", reason: "Computed __all__ expression", exports: new Map() };
      }
      const origSlice = lexRes.extractOriginalSlice(i, j);
      const strMatches = Array.from(origSlice.matchAll(/['"]([A-Za-z_][A-Za-z0-9_]*)['"]/g)).map((m) => m[1]);
      explicitAll = new Set(strMatches);
      i = j;
      continue;
    }

    // Track top-level `import` / `from ... import ...` bindings to detect rebinding collisions
    if (/^(?:import\s+|from\s+\.*[A-Za-z0-9_.]+\s+import\s+)/.test(trimmed)) {
      let acc = trimmed;
      let j = i;
      while (j + 1 < lines.length && !isBalancedBrackets(acc)) {
        j++;
        acc += " " + lines[j].trim();
      }
      const impNames = extractPythonImportBoundNames(acc);
      if (!impNames) {
        return { verdict: "UNKNOWN", reason: `Unparseable Python import at line ${i + 1}`, exports: new Map() };
      }
      for (const bName of impNames) {
        if (seenTopLevelBindings.has(bName)) {
          return {
            verdict: "UNKNOWN",
            reason: `Top-level Python symbol '${bName}' is rebound by import.`,
            exports: new Map(),
          };
        }
        seenTopLevelBindings.add(bName);
        exportsMap.set(bName, {
          exportedName: bName,
          kind: "import-reexport",
          signature: `import:${acc.replace(/\s+/g, " ")}`,
          isPrivateByUnderscore: true, // plain imports are not public module API unless listed in `__all__`
        });
      }
      recordPythonDecoratorImports(acc, decoratorImports);
      i = j;
      continue;
    }

    const defMatch = trimmed.match(/^(async\s+def|def|class)\s+([A-Za-z_][A-Za-z0-9_]*)\b/);
    if (defMatch) {
      const kind = defMatch[1].replace(/\s+/g, " ");
      const name = defMatch[2];
      if (seenTopLevelBindings.has(name)) {
        return {
          verdict: "UNKNOWN",
          reason: `Duplicate or rebound top-level Python symbol '${name}'.`,
          exports: new Map(),
        };
      }
      seenTopLevelBindings.add(name);

      let header = trimmed;
      let j = i;
      while (j + 1 < lines.length && (!isBalancedBrackets(header) || !header.trimEnd().endsWith(":"))) {
        j++;
        header += " " + lines[j].trim();
      }
      if (!isBalancedBrackets(header) || !header.trimEnd().endsWith(":")) {
        return { verdict: "UNKNOWN", reason: `Malformed Python ${kind} header for ${name}`, exports: new Map() };
      }
      if (kind !== "class" && !header.includes("(")) {
        return { verdict: "UNKNOWN", reason: `Malformed Python def header missing '(' for ${name}`, exports: new Map() };
      }

      let normalizedSig = header.replace(/\s+/g, " ").trim();
      const declarationHeaderEnd = j;
      let dataclassFieldReferences = null;
      const decorators = pendingDecorators;
      pendingDecorators = [];
      if (decorators.some((decorator) => (decorator.kind === "dataclass") !== (kind === "class"))) {
        return { verdict: "UNKNOWN", reason: "Python decorator is attached to an unsupported declaration kind.", exports: new Map() };
      }
      if (decorators.length) normalizedSig = `${decorators.map((decorator) => decorator.signature).join(" ")} ${normalizedSig}`;

      if (kind === "class") {
        const includeFields = decorators.some((decorator) => decorator.kind === "dataclass");
        if (includeFields && !/^class\s+[A-Za-z_][A-Za-z0-9_]*\s*(?:\(\s*\))?\s*:$/.test(header)) return { verdict: "UNKNOWN", reason: "Dataclass inheritance requires resolution of the inherited field contract.", exports: new Map() };
        const classBodyRes = extractPythonClassPublicMethods(lines, j + 1, { decoratorImports, includeFields, moduleBindings: seenTopLevelBindings });
        if (!classBodyRes.ok) {
          return { verdict: "UNKNOWN", reason: classBodyRes.reason, exports: new Map() };
        }
        normalizedSig = `${normalizedSig} [ ${classBodyRes.methods.join(" | ")} ]`;
        if (includeFields) {
          const fieldSource = classBodyRes.fieldLineRanges.map(([start, end]) => lexRes.extractOriginalSlice(start, end)).join(" ");
          dataclassFieldReferences = Array.from(new Set(fieldSource.match(/[A-Za-z_][A-Za-z0-9_]*/g) || []));
        }
        j = classBodyRes.endLineIdx;
      } else {
        // Consume indented `def` / `async def` suite so loop resumes at next column-0 statement
        let bLine = j + 1;
        while (bLine < lines.length && (!lines[bLine].trim() || /^[ \t]/.test(lines[bLine]))) {
          bLine++;
        }
        j = bLine - 1;
      }

      exportsMap.set(name, {
        exportedName: name,
        kind,
        signature: normalizedSig,
        dataclassFieldReferences,
        dependencyNames: kind === "class" ? null : Array.from(new Set(lexRes.extractOriginalSlice(i, declarationHeaderEnd).match(/[A-Za-z_][A-Za-z0-9_]*/g) || [])),
        isPrivateByUnderscore: name.startsWith("_"),
      });
      i = j;
      continue;
    }

    // Top-level variable assignment / alias / rebinding (`f = None`, `g = f`, `X: int = 1`, `a, b = 1, 2`, `x += 1`) (``)!
    let stmtAcc = trimmed;
    let j = i;
    while (j + 1 < lines.length && !isBalancedBrackets(stmtAcc)) {
      j++;
      stmtAcc += " " + lines[j].trim();
    }
    const simpleAssign = stmtAcc.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*([^=]+?))?\s*=\s*(.+)$/);
    const augAssign = stmtAcc.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*(?:\+=|-=|\*=|\/=|\/\/=|%=|\*\*=|&=|\|=|\^=|<<=|>>=)/);
    if (augAssign) {
      return {
        verdict: "UNKNOWN",
        reason: `Top-level augmented assignment to '${augAssign[1]}' mutates Python module binding.`,
        exports: new Map(),
      };
    }
    if (simpleAssign && !stmtAcc.startsWith("assert ")) {
      const lhsName = simpleAssign[1];
      const annotRaw = (simpleAssign[2] || "").trim();
      const rhsRaw = simpleAssign[3].trim();
      if (seenTopLevelBindings.has(lhsName)) {
        // Catches `def f(a): return a\nf = None` (``)!
        return {
          verdict: "UNKNOWN",
          reason: `Top-level Python symbol '${lhsName}' is rebound after declaration.`,
          exports: new Map(),
        };
      }
      seenTopLevelBindings.add(lhsName);
      let varSig = `var ${lhsName}${annotRaw ? `: ${annotRaw}` : ""} = ${rhsRaw}`;
      if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(rhsRaw) && exportsMap.has(rhsRaw)) {
        varSig = `alias ${lhsName} -> ${exportsMap.get(rhsRaw).signature}`;
      }
      exportsMap.set(lhsName, {
        exportedName: lhsName,
        kind: "variable",
        signature: varSig,
        dependencyNames: Array.from(new Set(lexRes.extractOriginalSlice(i, j).match(/[A-Za-z_][A-Za-z0-9_]*/g) || [])).filter((ref) => ref !== lhsName),
        isPrivateByUnderscore: lhsName.startsWith("_"),
      });
      i = j;
      continue;
    }

    // Tuple unpacking or attribute/subscript mutation at top level (`a, b = ...`, `obj.x = ...`)
    if (stmtAcc.includes("=")) {
      return {
        verdict: "UNKNOWN",
        reason: `Complex top-level assignment '${stmtAcc.slice(0, 40)}' cannot be statically verified.`,
        exports: new Map(),
      };
    }
    i = j;
  }

  if (pendingDecorators.length) return { verdict: "UNKNOWN", reason: "Trailing Python decorator has no declaration.", exports: new Map() };

  // Private constants can supply generated constructor defaults as well. Bind
  // their static declaration fingerprints instead of tracking only field text.
  const originalSignatures = new Map(Array.from(exportsMap, ([name, descriptor]) => [name, descriptor.signature]));
  const resolvedDependencies = new Map();
  const resolveDependency = (name, active = new Set()) => {
    if (active.has(name) || active.size > 128) return null;
    if (resolvedDependencies.has(name)) return resolvedDependencies.get(name);
    const descriptor = exportsMap.get(name);
    const next = new Set(active).add(name);
    const references = descriptor.dataclassFieldReferences || descriptor.dependencyNames || [];
    const tags = [];
    for (const ref of references) {
      if (!exportsMap.has(ref) || (ref === name && descriptor.kind !== "variable")) continue;
      const resolved = resolveDependency(ref, next);
      if (resolved === null) return null;
      tags.push(`${ref}=>${resolved}`);
    }
    const signature = crypto.createHash("sha256").update(originalSignatures.get(name) + (tags.length ? ` [binding-refs:${tags.join(" | ")}]` : "")).digest("hex");
    resolvedDependencies.set(name, signature);
    return signature;
  };
  for (const [name, descriptor] of exportsMap) {
    if (!descriptor.dataclassFieldReferences) continue;
    const resolved = resolveDependency(name);
    if (resolved === null) return { verdict: "UNKNOWN", reason: "Cyclic dataclass field binding dependencies cannot be statically verified.", exports: new Map() };
    descriptor.signature += ` [binding-fingerprint:${resolved}]`;
  }

  const publicExports = new Map();
  for (const [name, desc] of exportsMap.entries()) {
    if (explicitAll) {
      if (explicitAll.has(name)) publicExports.set(name, desc);
    } else if (!desc.isPrivateByUnderscore) {
      publicExports.set(name, desc);
    }
  }
  if (explicitAll) {
    for (const expName of explicitAll) {
      if (!publicExports.has(expName)) {
        return {
          verdict: "UNKNOWN",
          reason: `__all__ symbol '${expName}' could not be resolved to a static top-level binding.`,
          exports: new Map(),
        };
      }
    }
  }
  return { verdict: "OK", exports: publicExports };
}

function extractPythonImportBoundNames(joinedImportLine) {
  const clean = joinedImportLine.trim();
  if (clean.startsWith("import ")) {
    const rest = clean.slice("import ".length).trim();
    const parts = rest.split(",").map((p) => p.trim()).filter(Boolean);
    const names = [];
    for (const p of parts) {
      const m = p.match(/^([A-Za-z_][A-Za-z0-9_.]*)(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?$/);
      if (!m) return null;
      names.push(m[2] || m[1].split(".")[0]);
    }
    return names;
  }
  const fromM = clean.match(/^from\s+\.*[A-Za-z0-9_.]+\s+import\s+(.+)$/);
  if (fromM) {
    let specPart = fromM[1].trim();
    if (specPart.startsWith("(") && specPart.endsWith(")")) {
      specPart = specPart.slice(1, -1).trim();
    }
    if (!specPart || specPart.includes("*")) return null;
    const parts = specPart.split(",").map((p) => p.trim()).filter(Boolean);
    const names = [];
    for (const p of parts) {
      const m = p.match(/^([A-Za-z_][A-Za-z0-9_]*)(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?$/);
      if (!m) return null;
      names.push(m[2] || m[1]);
    }
    return names;
  }
  return null;
}

function recordPythonDecoratorImports(statement, bindings) {
  const clean = statement.trim().replace(/\s+/g, " ");
  const from = clean.match(/^from\s+([A-Za-z_][A-Za-z0-9_.]*)\s+import\s+(.+)$/);
  const specs = from ? from[2].replace(/^\(\s*|\s*\)$/g, "") : clean.startsWith("import ") ? clean.slice(7) : null;
  if (specs === null) return;
  for (const spec of specs.split(",").map((value) => value.trim()).filter(Boolean)) {
    const match = spec.match(/^([A-Za-z_][A-Za-z0-9_.]*)(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?$/);
    if (!match) continue;
    const name = match[2] || (from ? match[1] : match[1].split(".")[0]);
    const target = from ? `${from[1]}.${match[1]}` : match[2] ? match[1] : match[1].split(".")[0];
    bindings.set(name, { target, statement: clean });
  }
}

function resolvePythonDecorator(text, imports) {
  const match = text.match(/^@([A-Za-z_][A-Za-z0-9_.]*)(?:\((.*)\))?$/);
  if (!match) return null;
  const [root, ...members] = match[1].split(".");
  const provider = imports.get(root);
  if (!provider) return null;
  const target = [provider.target, ...members].join(".");
  let kind;
  if (target === "dataclasses.dataclass") {
    if (match[2] !== undefined && match[2].trim() !== "") {
      const args = match[2].split(",").map((arg) => arg.trim());
      if (args.at(-1) === "") args.pop();
      const keys = new Set();
      for (const arg of args) {
        const flag = arg.match(/^(init|repr|eq|order|unsafe_hash|frozen|match_args|kw_only|slots|weakref_slot)\s*=\s*(?:True|False)$/);
        if (!flag || keys.has(flag[1])) return null;
        keys.add(flag[1]);
      }
    }
    kind = "dataclass";
  } else if (target === "torch.no_grad" && match[2] !== undefined && match[2].trim() === "") {
    kind = "no-grad";
  } else if (target === "contextlib.contextmanager" && match[2] === undefined) {
    kind = "contextmanager";
  } else {
    return null;
  }
  return { kind, signature: `${text.replace(/\s+/g, " ")} [provider:${provider.statement}]` };
}

function expandTabsIndent(ws) {
  let col = 0;
  for (const ch of ws) {
    col += ch === "\t" ? 4 : 1;
  }
  return col;
}

function extractPythonClassPublicMethods(lines, startLineIdx, { decoratorImports = new Map(), includeFields = false, moduleBindings = new Set() } = {}) {
  const methods = [];
  let memberIndentCol = null;
  let pendingDecorators = [];
  const seenFields = new Set();
  const fields = [];
  const fieldLineRanges = [];
  const classBindings = new Set();
  const seenMethods = new Set();
  let m = startLineIdx;

  while (m < lines.length) {
    const ln = lines[m];
    const trimmed = ln.trim();
    if (!trimmed) {
      m++;
      continue;
    }
    const rawIndent = ln.match(/^[ \t]*/)[0];
    const indentCol = expandTabsIndent(rawIndent);
    if (indentCol === 0) {
      break;
    }

    if (memberIndentCol === null) {
      memberIndentCol = indentCol;
    }

    if (indentCol === memberIndentCol) {
      if (trimmed.startsWith("@")) {
        const decName = trimmed.slice(1).split("(")[0].trim();
        const rootName = decName.split(".")[0];
        if (classBindings.has(rootName) || (["staticmethod", "classmethod", "property"].includes(rootName) && moduleBindings.has(rootName))) return { ok: false, reason: "Python decorator binding is shadowed." };
        const allowedDec =
          /^@(?:staticmethod|classmethod|property|[A-Za-z_][A-Za-z0-9_]*\.(?:setter|deleter))$/.test(trimmed);
        const importedDecorator = resolvePythonDecorator(trimmed, decoratorImports);
        if (!allowedDec && importedDecorator?.kind !== "no-grad") {
          return {
            ok: false,
            reason: `Custom decorator '@${decName}' on Python class member cannot be statically verified.`,
          };
        }
        pendingDecorators.push(importedDecorator?.signature || trimmed);
        m++;
        continue;
      }

      const methodMatch = trimmed.match(/^(async\s+def|def)\s+([A-Za-z_][A-Za-z0-9_]*)\b/);
      if (methodMatch) {
        const mName = methodMatch[2];
        if (seenFields.has(mName) || (seenMethods.has(mName) && !pendingDecorators.some((decorator) => decorator === `@${mName}.setter` || decorator === `@${mName}.deleter`))) return { ok: false, reason: "Python class method binding is rebound." };
        classBindings.add(mName);
        seenMethods.add(mName);
        let mHeader = trimmed;
        let endHdr = m;
        while (endHdr + 1 < lines.length && (!isBalancedBrackets(mHeader) || !mHeader.trimEnd().endsWith(":"))) {
          endHdr++;
          mHeader += " " + lines[endHdr].trim();
        }
        if (!isBalancedBrackets(mHeader) || !mHeader.trimEnd().endsWith(":") || !mHeader.includes("(")) {
          return { ok: false, reason: `Malformed Python class method header for '${mName}'` };
        }
        const isPublicMethod =
          !mName.startsWith("_") ||
          ["__init__", "__post_init__", "__call__", "__enter__", "__exit__", "__aenter__", "__aexit__", "__iter__", "__len__", "__getitem__"].includes(
            mName
          );
        if (isPublicMethod) {
          const decPrefix = pendingDecorators.length ? `${pendingDecorators.join(" ")} ` : "";
          methods.push(`${decPrefix}${mHeader.replace(/\s+/g, " ").trim()}`);
        }
        pendingDecorators = [];
        m = endHdr + 1;
        continue;
      }

      if (pendingDecorators.length) return { ok: false, reason: "Python class decorator is not followed by a method." };
      if (trimmed !== "pass" && !/^"__STR_[a-f0-9]+__"$/.test(trimmed)) {
        let field = trimmed;
        let endField = m;
        while (endField + 1 < lines.length && !isBalancedBrackets(field)) field += " " + lines[++endField].trim();
        const match = field.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*[^=]+)?(?:\s*=\s*.+)?$/);
        if (!match || (!field.includes(":") && !field.includes("=")) || !isBalancedBrackets(field) || field.includes(";") || seenFields.has(match[1]) || seenMethods.has(match[1])) return { ok: false, reason: "Unsupported or rebound Python class-level statement." };
        seenFields.add(match[1]);
        classBindings.add(match[1]);
        if (includeFields) {
          methods.push(`field:${field.replace(/\s+/g, " ")}`);
          fields.push(field);
          fieldLineRanges.push([m, endField]);
        }
        m = endField;
      }

      pendingDecorators = [];
    }

    m++;
  }

  return { ok: true, methods, fields, fieldLineRanges, endLineIdx: m - 1 };
}

function isBalancedBrackets(str) {
  const stack = [];
  for (const ch of str) {
    if (ch === "(" || ch === "[" || ch === "{") {
      stack.push(ch);
    } else if (ch === ")" || ch === "]" || ch === "}") {
      const expected = ch === ")" ? "(" : ch === "]" ? "[" : "{";
      if (stack.length === 0 || stack[stack.length - 1] !== expected) return false;
      stack.pop();
    }
  }
  return stack.length === 0;
}

function stripPythonStringsAndComments(source) {
  const norm = source.replace(/\r\n/g, "\n");
  const origLines = norm.split("\n");
  let out = "";
  let i = 0;
  const n = norm.length;

  while (i < n) {
    const ch = norm[i];
    if (ch === "#") {
      while (i < n && norm[i] !== "\n") i++;
      continue;
    }

    // Handle optional Python string prefix (`r`, `b`, `u`, `f`, `rf`, `fr`, `br`, `rb`) immediately before quote
    if (/[rRbBuUfF]/.test(ch)) {
      const prevCh = i > 0 ? norm[i - 1] : "";
      if (!/[A-Za-z0-9_]/.test(prevCh)) {
        let pLen = 1;
        if (i + 1 < n && /[rRbBuUfF]/.test(norm[i + 1])) pLen = 2;
        const afterPrefix = norm[i + pLen];
        if (afterPrefix === '"' || afterPrefix === "'") {
          const prefixRaw = norm.slice(i, i + pLen);
          // F-strings containing `{...}` expressions inside headers can execute arbitrary expressions; hash full raw f-string token!
          i += pLen;
          const strRes = consumePythonQuotedLiteral(norm, i, prefixRaw);
          if (!strRes.ok) return strRes;
          out += strRes.tokenWithNewlines;
          i = strRes.nextIndex;
          continue;
        }
      }
    }

    if (ch === '"' || ch === "'") {
      const strRes = consumePythonQuotedLiteral(norm, i, "");
      if (!strRes.ok) return strRes;
      out += strRes.tokenWithNewlines;
      i = strRes.nextIndex;
      continue;
    }

    // Handle line continuation backslash `\` followed by `\n`: join logical line while preserving newline count via space?
    // Wait: keeping `\n` inside brackets works automatically; explicit `\\\n` joins lines!
    if (ch === "\\" && norm[i + 1] === "\n") {
      out += " ";
      i += 2;
      continue;
    }

    out += ch;
    i++;
  }

  if (!isBalancedBrackets(out)) {
    return { ok: false, reason: "Unbalanced brackets/parentheses/braces in Python source" };
  }

  return {
    ok: true,
    cleaned: out,
    extractOriginalSlice(startLine, endLine) {
      return origLines.slice(startLine, endLine + 1).join("\n");
    },
  };
}

function consumePythonQuotedLiteral(norm, quoteIdx, prefixRaw) {
  const n = norm.length;
  const triple = norm.slice(quoteIdx, quoteIdx + 3);
  if (triple === '"""' || triple === "'''") {
    let i = quoteIdx + 3;
    let rawBody = "";
    let newlineCount = 0;
    let closed = false;
    while (i < n) {
      if (norm[i] === "\\") {
        rawBody += norm[i] + (norm[i + 1] || "");
        if (norm[i + 1] === "\n") newlineCount++;
        i += 2;
        continue;
      }
      if (norm.slice(i, i + 3) === triple) {
        i += 3;
        closed = true;
        break;
      }
      if (norm[i] === "\n") newlineCount++;
      rawBody += norm[i];
      i++;
    }
    if (!closed) return { ok: false, reason: "Unterminated Python triple-quoted string" };
    const hashTok = `"__STR_${sha256Short(`${prefixRaw}${triple}${rawBody}${triple}`)}__"`;
    return {
      ok: true,
      nextIndex: i,
      tokenWithNewlines: hashTok + "\n".repeat(newlineCount),
    };
  }

  const q = norm[quoteIdx];
  let i = quoteIdx + 1;
  let rawBody = "";
  let newlineCount = 0;
  let closed = false;
  while (i < n) {
    if (norm[i] === "\\") {
      rawBody += norm[i] + (norm[i + 1] || "");
      if (norm[i + 1] === "\n") newlineCount++;
      i += 2;
      continue;
    }
    if (norm[i] === "\n") {
      return { ok: false, reason: "Unterminated Python string literal" };
    }
    if (norm[i] === q) {
      i++;
      closed = true;
      break;
    }
    rawBody += norm[i];
    i++;
  }
  if (!closed) return { ok: false, reason: "Unterminated Python string literal" };
  const hashTok = `"__STR_${sha256Short(`${prefixRaw}${q}${rawBody}${q}`)}__"`;
  return {
    ok: true,
    nextIndex: i,
    tokenWithNewlines: hashTok + "\n".repeat(newlineCount),
  };
}

export function extractPublicContracts(source, filePath) {
  const ext = path.extname(filePath).toLowerCase();
  if (SUPPORTED_JS_TS_EXTS.has(ext)) {
    return scanJsTsExports(source, ext);
  }
  if (SUPPORTED_PYTHON_EXTS.has(ext)) {
    return scanPythonExports(source);
  }
  return {
    verdict: "UNKNOWN",
    reason: `Extension '${ext || "(none)"}' is outside v0.1 parser-backed code languages (.js/.mjs/.cjs/.ts/.tsx/.py).`,
    exports: new Map(),
  };
}

export function compareCodeExports(beforeSource, afterSource, filePath) {
  const beforeScan = extractPublicContracts(beforeSource, filePath);
  const afterScan = extractPublicContracts(afterSource, filePath);

  if (beforeScan.verdict === "UNKNOWN" || afterScan.verdict === "UNKNOWN") {
    return {
      ok: false,
      verdict: "UNKNOWN",
      code: "CONSERVATION_UNCERTAIN",
      reason: beforeScan.reason || afterScan.reason || "Parser could not deterministically verify export conservation.",
      removedOrMutated: [],
    };
  }

  const removedOrMutated = [];
  for (const [expName, beforeDesc] of beforeScan.exports.entries()) {
    const afterDesc = afterScan.exports.get(expName);
    if (!afterDesc) {
      removedOrMutated.push({
        exportedName: expName,
        change: "REMOVED",
        before: beforeDesc.signature,
        after: null,
      });
    } else if (afterDesc.signature !== beforeDesc.signature) {
      removedOrMutated.push({
        exportedName: expName,
        change: "SIGNATURE_MUTATED",
        before: beforeDesc.signature,
        after: afterDesc.signature,
      });
    }
  }

  if (removedOrMutated.length > 0) {
    return {
      ok: false,
      verdict: "VIOLATION",
      code: "PUBLIC_EXPORT_MUTATED",
      reason: `Public export contract broken on ${removedOrMutated.length} symbol(s): ${removedOrMutated
        .slice(0, 4)
        .map((x) => `${x.exportedName} (${x.change})`)
        .join(", ")}`,
      removedOrMutated,
    };
  }

  return { ok: true, verdict: "OK", removedOrMutated: [] };
}

/**
 * Whole-File Setup & Existing-Suite Additive Test Conservation (``):
 * - Supports both modifying existing test files AND newly added test files (`beforeSource === ""`)
 * - Rejects executable semicolon suffixes on `import` statements (`import os; pytest.skip(...)`)
 * - Rejects wildcard `from ... import *`, dynamic `import(...)`, `.only`/`.skip`/`.todo` modifiers, and pytest collection hooks
 * - Rejects duplicate `def test_...` or `test("title")` bindings that shadow existing tests!
 */
export function verifyAdditiveTestConservation(beforeSource, afterSource, filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const baseName = path.basename(filePath).toLowerCase();
  if (baseName === "conftest.py") {
    return {
      ok: false,
      code: "TEST_SETUP_OR_BODY_MUTATED",
      reason: "Pytest collection/fixture configuration file 'conftest.py' cannot be created or mutated without explicit user grant.",
    };
  }
  if (SUPPORTED_JS_TS_EXTS.has(ext)) {
    return verifyJsTsAdditiveTests(beforeSource, afterSource);
  }
  if (SUPPORTED_PYTHON_EXTS.has(ext)) {
    return verifyPythonAdditiveTests(beforeSource, afterSource);
  }
  return {
    ok: false,
    code: "CONSERVATION_UNCERTAIN",
    reason: `Additive test verification unsupported for extension '${ext}'.`,
  };
}

function splitJsTsTopLevelUnits(tokens) {
  const units = [];
  let i = 0;
  while (i < tokens.length) {
    if (tokens[i].value === ";") {
      i++;
      continue;
    }
    const start = i;
    if (
      tokens[i].depth === 0 &&
      tokens[i].type === "ident" &&
      tokens[i].value === "describe" &&
      tokens[i + 1]?.value === "("
    ) {
      const closeParen = findMatchingCloseIndex(tokens, i + 1);
      if (closeParen > i + 1) {
        let bodyBrace = -1;
        for (let p = i + 2; p < closeParen; p++) {
          if (tokens[p].depth === 1 && tokens[p].value === "{") {
            bodyBrace = p;
            break;
          }
        }
        if (bodyBrace > 0) {
          const closeBodyBrace = findMatchingCloseIndex(tokens, bodyBrace);
          if (closeBodyBrace > bodyBrace) {
            const suiteTitle = tokens[i + 2]?.type === "string" ? tokens[i + 2].value : `line:${tokens[i].line}`;
            units.push({
              kind: "describe-open",
              scope: `describe:${suiteTitle}`,
              norm: serializeTokens(tokens, start, bodyBrace + 1),
            });
            const innerUnits = splitJsTsDepthUnits(tokens, bodyBrace + 1, closeBodyBrace, 2, `describe:${suiteTitle}`);
            for (const u of innerUnits) units.push(u);
            units.push({
              kind: "describe-close",
              scope: `describe:${suiteTitle}`,
              norm: serializeTokens(tokens, closeBodyBrace, closeParen + 1),
            });
            i = closeParen + 1;
            if (tokens[i]?.value === ";") i++;
            continue;
          }
        }
      }
    }

    const end = advanceOneStatementAtDepth(tokens, i, 0);
    const info = classifyJsTestUnit(tokens, start, end, 0, "top");
    units.push({
      ...info,
      norm: serializeTokens(tokens, start, end),
    });
    i = end;
    if (tokens[i]?.value === ";") i++;
  }
  return units;
}

function splitJsTsDepthUnits(tokens, startIdx, endIdx, targetDepth, scopeName) {
  const units = [];
  let i = startIdx;
  while (i < endIdx) {
    if (tokens[i].depth === targetDepth && tokens[i].value === ";") {
      i++;
      continue;
    }
    const start = i;
    const end = advanceOneStatementAtDepth(tokens, i, targetDepth, endIdx);
    const info = classifyJsTestUnit(tokens, start, end, targetDepth, scopeName);
    units.push({
      ...info,
      norm: serializeTokens(tokens, start, end),
    });
    i = end;
    if (i < endIdx && tokens[i]?.depth === targetDepth && tokens[i].value === ";") i++;
  }
  return units;
}

function advanceOneStatementAtDepth(tokens, startIdx, depth, limit = tokens.length) {
  let k = startIdx;
  while (k < limit) {
    const t = tokens[k];
    if (t.depth === depth && t.value === ";") {
      return k;
    }
    if (t.depth === depth && (t.value === "(" || t.value === "{")) {
      const close = findMatchingCloseIndex(tokens, k);
      if (close > k) {
        k = close + 1;
        if (
          k >= limit ||
          tokens[k].value === ";" ||
          (tokens[k].depth === depth && tokens[k].line > tokens[k - 1].line && tokens[k].value !== ".")
        ) {
          return k;
        }
        continue;
      }
    }
    k++;
  }
  return k;
}

function extractPureImportLocalNames(tokens, start, end) {
  if (end === start + 2 && tokens[start + 1]?.type === "string") {
    return { ok: true, names: [] };
  }
  const imp = collectImportedBindings(tokens, start);
  return { ok: true, names: Array.from(imp.bindings.keys()) };
}

function isPureTestCallbackArgument(tokens, fnStart, closeParen, callInnerDepth) {
  let k = fnStart;
  if (tokens[k]?.depth === callInnerDepth && tokens[k]?.value === "async") {
    k++;
  }
  // Reject any top-level comma inside `test(title, <callback>)` after `fnStart` (blocks 3rd arg or comma expressions)
  for (let p = fnStart; p < closeParen; p++) {
    if (tokens[p].depth === callInnerDepth && tokens[p].value === ",") {
      return false;
    }
  }

  // Form 1: `function (a, b) { ... }`
  if (tokens[k]?.depth === callInnerDepth && tokens[k]?.value === "function") {
    k++;
    if (tokens[k]?.type === "ident") k++;
    if (tokens[k]?.value !== "(") return false;
    const clParams = findMatchingCloseIndex(tokens, k);
    if (clParams < 0 || clParams >= closeParen) return false;
    for (let p = k + 1; p < clParams; p++) {
      if (tokens[p].type !== "ident" && tokens[p].value !== ",") return false;
    }
    const bodyOpen = clParams + 1;
    if (tokens[bodyOpen]?.value !== "{") return false;
    const bodyClose = findMatchingCloseIndex(tokens, bodyOpen);
    return bodyClose === closeParen - 1;
  }

  // Form 2: `t => ...`
  if (tokens[k]?.depth === callInnerDepth && tokens[k]?.type === "ident" && tokens[k + 1]?.value === "=>") {
    const bodyStart = k + 2;
    if (bodyStart >= closeParen) return false;
    if (tokens[bodyStart]?.value === "{") {
      return findMatchingCloseIndex(tokens, bodyStart) === closeParen - 1;
    }
    return true;
  }

  // Form 3: `(t) => ...` or `() => ...` (with bare identifier parameters only — zero default `=` expressions!)
  if (tokens[k]?.depth === callInnerDepth && tokens[k]?.value === "(") {
    const clParams = findMatchingCloseIndex(tokens, k);
    if (clParams < 0 || clParams >= closeParen) return false;
    for (let p = k + 1; p < clParams; p++) {
      // Allow TS parameter type annotations `t: TestContext` if no `=` default expression, or bare idents
      if (tokens[p].value === "=") return false;
      if (tokens[p].value === "(" || tokens[p].value === "[") return false;
    }
    let arrowIdx = clParams + 1;
    if (tokens[arrowIdx]?.depth === callInnerDepth && tokens[arrowIdx]?.value === ":") {
      arrowIdx = advanceTypeAnnotation(tokens, arrowIdx + 1, callInnerDepth, {
        allowBodyBraceStop: false,
        stopTokens: new Set(["=>"]),
      });
      if (arrowIdx < 0 || arrowIdx >= closeParen) return false;
    }
    if (tokens[arrowIdx]?.depth !== callInnerDepth || tokens[arrowIdx]?.value !== "=>") {
      return false;
    }
    const bodyStart = arrowIdx + 1;
    if (bodyStart >= closeParen) return false;
    if (tokens[bodyStart]?.value === "{") {
      return findMatchingCloseIndex(tokens, bodyStart) === closeParen - 1;
    }
    return true;
  }

  return false;
}

function classifyJsTestUnit(tokens, start, end, depth, scope) {
  const first = tokens[start];
  if (!first) return { kind: "other", scope };

  // Strict static ESM import: `import ... from "spec"` or `import "spec"` (never `import(...)` or `import.meta`)
  if (first.value === "import" && tokens[start + 1]?.value !== "(" && tokens[start + 1]?.value !== ".") {
    const lastTok = tokens[end - 1];
    const isSideEffectImport = end === start + 2 && tokens[start + 1]?.type === "string";
    const isFromImport =
      lastTok?.type === "string" && tokens[end - 2]?.value === "from";
    if (depth === 0 && (isSideEffectImport || isFromImport)) {
      const impInfo = extractPureImportLocalNames(tokens, start, end);
      return { kind: "import", scope, boundNames: impInfo.names };
    }
    return { kind: "setup-or-fixture", scope };
  }

  // Strict standalone `test("static title", () => { ... })` or `it("static title", () => { ... })` (``):
  // - Rejects computed/comma title expressions like `test((process.exit(0), "new"), () => {})`
  // - Rejects options objects, `.only`/`.skip`, 3rd arguments, and parameter default expressions!
  if (
    first.type === "ident" &&
    (first.value === "test" || first.value === "it") &&
    tokens[start + 1]?.value === "("
  ) {
    const closeParen = findMatchingCloseIndex(tokens, start + 1);
    if (closeParen === end - 1) {
      const callInnerDepth = depth + 1;
      const titleTok = tokens[start + 2];
      const commaTok = tokens[start + 3];
      const isStaticTitle =
        titleTok &&
        (titleTok.type === "string" ||
          (titleTok.type === "template" && !titleTok.value.endsWith("${")));
      const innerSlice = serializeTokens(tokens, start + 2, closeParen);
      if (/\b(?:only|skip|todo)\s*:\s*true\b/.test(innerSlice)) {
        return { kind: "focused-or-skipped-test", scope };
      }
      if (
        isStaticTitle &&
        commaTok?.depth === callInnerDepth &&
        commaTok?.value === "," &&
        isPureTestCallbackArgument(tokens, start + 4, closeParen, callInnerDepth)
      ) {
        return { kind: "test-case", scope, testKey: `${scope}::${titleTok.value}` };
      }
      return { kind: "setup-or-fixture", scope };
    }
  }

  if (
    first.type === "ident" &&
    (first.value === "test" || first.value === "it" || first.value === "describe") &&
    tokens[start + 1]?.value === "." &&
    ["only", "skip", "todo"].includes(tokens[start + 2]?.value)
  ) {
    return { kind: "focused-or-skipped-test", scope };
  }

  const sliceStr = serializeTokens(tokens, start, Math.min(end, start + 6));
  if (/^(?:beforeEach|afterEach|beforeAll|afterAll|before|after)\b/.test(sliceStr)) {
    return { kind: "lifecycle-hook", scope };
  }
  return { kind: "setup-or-fixture", scope };
}

function collectJsTopLevelDeclaredIdentifiers(tokens) {
  const names = new Set([
    "test",
    "it",
    "describe",
    "before",
    "after",
    "beforeEach",
    "afterEach",
    "beforeAll",
    "afterAll",
    "expect",
    "assert",
    "vi",
    "jest",
  ]);
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t.depth !== 0) continue;
    if (t.value === "import" && tokens[i + 1]?.value !== "(" && tokens[i + 1]?.value !== ".") {
      const imp = collectImportedBindings(tokens, i);
      for (const k of imp.bindings.keys()) names.add(k);
      i = imp.nextIndex;
      continue;
    }
    if (["function", "class"].includes(t.value) && tokens[i + 1]?.type === "ident") {
      names.add(tokens[i + 1].value);
    } else if (["const", "let", "var"].includes(t.value)) {
      const parsed = parseDeclarationAt(tokens, i);
      if (parsed) {
        for (const item of parsed.names) names.add(item.name);
      } else {
        const end = findStatementEnd(tokens, i + 1);
        for (let m = i + 1; m < end; m++) {
          if (tokens[m].type === "ident") names.add(tokens[m].value);
        }
      }
    }
  }
  return names;
}

function verifyJsTsAdditiveTests(beforeSource, afterSource) {
  const bTok = tokenizeJsTs(beforeSource);
  const aTok = tokenizeJsTs(afterSource);
  if (!bTok.ok || !aTok.ok) {
    return {
      ok: false,
      code: "CONSERVATION_UNCERTAIN",
      reason: bTok.reason || aTok.reason || "Test file failed lexical tokenization.",
    };
  }
  const beforeUnits = splitJsTsTopLevelUnits(bTok.tokens);
  const afterUnits = splitJsTsTopLevelUnits(aTok.tokens);

  const seenTestKeys = new Set();
  for (const bu of beforeUnits) {
    if (bu.kind === "test-case" && bu.testKey) {
      seenTestKeys.add(bu.testKey);
    }
  }
  const seenBindings = collectJsTopLevelDeclaredIdentifiers(bTok.tokens);

  // Find index of first non-import baseline unit so added imports can only appear in the import header (or at EOF)
  let firstNonImportBaselineIdx = beforeUnits.findIndex((u) => u.kind !== "import");
  if (firstNonImportBaselineIdx === -1) firstNonImportBaselineIdx = beforeUnits.length;

  let bIdx = 0;
  for (let aIdx = 0; aIdx < afterUnits.length; aIdx++) {
    const au = afterUnits[aIdx];
    if (bIdx < beforeUnits.length && au.norm === beforeUnits[bIdx].norm && au.kind === beforeUnits[bIdx].kind) {
      bIdx++;
      continue;
    }
    if (au.kind === "import") {
      // Allow adding new static imports ONLY in the import preamble (`bIdx <= firstNonImportBaselineIdx`) or after all baseline units
      if (bIdx > firstNonImportBaselineIdx && bIdx < beforeUnits.length) {
        return {
          ok: false,
          code: "TEST_SETUP_OR_BODY_MUTATED",
          reason: "Added import statements must appear in the top-level import header, not interleaved between existing tests.",
        };
      }
      for (const bName of au.boundNames || []) {
        if (seenBindings.has(bName)) {
          return {
            ok: false,
            code: "TEST_TAMPERING_BLOCKED",
            reason: `Added import binding '${bName}' shadows an existing test-file identifier or test runner global.`,
          };
        }
        seenBindings.add(bName);
      }
      continue;
    }
    if (au.kind === "test-case") {
      // Enforce strict append-only position (``):
      // New test cases may ONLY appear after ALL baseline units (`bIdx === beforeUnits.length`)
      // OR at the tail of the final `describe` suite right before its closing `describe-close`!
      const isAtFinalDescribeTail =
        bIdx === beforeUnits.length - 1 &&
        beforeUnits[bIdx]?.kind === "describe-close" &&
        au.scope === beforeUnits[bIdx].scope;
      if (bIdx < beforeUnits.length && !isAtFinalDescribeTail) {
        return {
          ok: false,
          code: "TEST_SETUP_OR_BODY_MUTATED",
          reason: "New test cases in additive mode must be appended after all existing baseline tests (inserting before existing tests is forbidden).",
        };
      }
      if (au.testKey && seenTestKeys.has(au.testKey)) {
        return {
          ok: false,
          code: "TEST_TAMPERING_BLOCKED",
          reason: `Duplicate test case title (${au.testKey}) collides with an existing test case.`,
        };
      }
      if (au.testKey) seenTestKeys.add(au.testKey);
      continue;
    }
    return {
      ok: false,
      code: "TEST_SETUP_OR_BODY_MUTATED",
      reason:
        au.kind === "focused-or-skipped-test"
          ? "Adding .only/.skip/.todo modifiers in additive test mode can silence existing tests."
          : `Test setup, fixture, hook, or existing test block was modified or added without grant (${au.kind}).`,
    };
  }

  if (bIdx < beforeUnits.length) {
    return {
      ok: false,
      code: "TEST_TAMPERING_BLOCKED",
      reason: `Existing test block, setup fixture, or lifecycle hook was deleted or altered (missing baseline unit #${bIdx + 1}: ${beforeUnits[bIdx].kind}).`,
    };
  }

  return { ok: true };
}

/**
 * Split Python test file into validated top-level blocks (``):
 * Uses comment/string-stripped `cleaned` lines alongside raw lines so `;` suffixes (`import os; pytest.skip(...)`),
 * `from x import *`, collection hooks (`def pytest_...`), import alias collisions, parameter default expressions,
 * and non-append insertions are strictly rejected!
 */
function splitPythonTopLevelBlocks(source) {
  const norm = source.replace(/\r\n/g, "\n");
  if (!norm.trim()) {
    return { ok: true, blocks: [] };
  }
  const check = stripPythonStringsAndComments(norm);
  if (!check.ok) return { ok: false, reason: check.reason };

  const rawLines = norm.split("\n");
  const cleanLines = check.cleaned.split("\n");
  const blocks = [];
  let curRaw = [];
  let curClean = [];

  const flush = () => {
    const rawText = curRaw.join("\n").trim();
    const cleanText = curClean
      .map((l) => l.trimEnd())
      .join("\n")
      .trim();
    if (rawText && cleanText) {
      const classified = classifyPythonTestBlock(cleanText);
      blocks.push({
        kind: classified.kind,
        definedName: classified.definedName || null,
        boundNames: classified.boundNames || (classified.definedName ? [classified.definedName] : []),
        norm: rawText.replace(/[ \t]+$/gm, ""),
      });
    }
    curRaw = [];
    curClean = [];
  };

  for (let idx = 0; idx < rawLines.length; idx++) {
    const rLine = rawLines[idx];
    const cLine = cleanLines[idx] ?? "";
    const cTrim = cLine.trim();
    if (!cTrim) {
      if (curRaw.length > 0) {
        curRaw.push(rLine);
        curClean.push(cLine);
      }
      continue;
    }
    const isTopLevel = !/^[ \t]/.test(cLine);
    if (isTopLevel && curClean.length > 0) {
      const accClean = curClean.join("\n");
      const lastNonEmptyClean = [...curClean].reverse().find((x) => x.trim().length > 0)?.trim() || "";
      if (isBalancedBrackets(accClean) && !lastNonEmptyClean.startsWith("@")) {
        flush();
      }
    }
    curRaw.push(rLine);
    curClean.push(cLine);
  }
  flush();
  return { ok: true, blocks };
}

function classifyPythonTestBlock(cleanText) {
  const nonEmptyLines = cleanText.split("\n").filter((l) => l.trim().length > 0);
  if (nonEmptyLines.length === 0) return { kind: "other" };

  if (/^(?:async\s+def|def)\s+pytest_[A-Za-z0-9_]*\s*\(/.test(nonEmptyLines[0])) {
    const m = nonEmptyLines[0].match(/^(?:async\s+def|def)\s+(pytest_[A-Za-z0-9_]*)/);
    return { kind: "pytest-collection-hook", definedName: m ? m[1] : null };
  }
  if (/^@(?:pytest\.mark\.(?:skip|skipif|xfail)|unittest\.skip)/.test(nonEmptyLines[0])) {
    return { kind: "focused-or-skipped-test" };
  }

  // Strict pure Python import check (``): ZERO semicolons, NO wildcard `import *`, extracts all bound local names!
  if (!cleanText.includes(";") && /^(?:import\s+|from\s+\.*[A-Za-z0-9_.]+\s+import\s+)/.test(nonEmptyLines[0])) {
    const joined = nonEmptyLines.map((l) => l.trim()).join(" ");
    const isPureImport =
      /^import\s+[A-Za-z_][A-Za-z0-9_.]*(?:\s+as\s+[A-Za-z_][A-Za-z0-9_]*)?(?:\s*,\s*[A-Za-z_][A-Za-z0-9_.]*(?:\s+as\s+[A-Za-z_][A-Za-z0-9_]*)?)*$/.test(
        joined
      ) ||
      /^from\s+\.*[A-Za-z0-9_.]+\s+import\s+(?:\(\s*[A-Za-z_][A-Za-z0-9_]*(?:\s+as\s+[A-Za-z_][A-Za-z0-9_]*)?(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*(?:\s+as\s+[A-Za-z_][A-Za-z0-9_]*)?)*\s*,?\s*\)|[A-Za-z_][A-Za-z0-9_]*(?:\s+as\s+[A-Za-z_][A-Za-z0-9_]*)?(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*(?:\s+as\s+[A-Za-z_][A-Za-z0-9_]*)?)*)$/.test(
        joined
      );
    const boundNames = isPureImport ? extractPythonImportBoundNames(joined) : null;
    if (isPureImport && boundNames) {
      return { kind: "import", boundNames };
    }
    return { kind: "setup-or-fixture" };
  }

  // Strict standalone undecorated `def test_<name>(<bare_fixture_idents_only>):` block (``):
  // - Rejects ANY default value `x=<expr>`, type annotation `x:<expr>`, return annotation `-> <expr>`, or `*args`/`**kwargs`
  //   that could execute arbitrary code during pytest collection!
  const testDefMatch = nonEmptyLines[0].match(/^(?:async\s+def|def)\s+(test_[A-Za-z0-9_]*)\s*\(/);
  if (testDefMatch) {
    const testName = testDefMatch[1];
    let hdr = nonEmptyLines[0];
    let hIdx = 0;
    while (hIdx + 1 < nonEmptyLines.length && (!isBalancedBrackets(hdr) || !hdr.trimEnd().endsWith(":"))) {
      hIdx++;
      hdr += " " + nonEmptyLines[hIdx].trim();
    }
    const pureHdrMatch = hdr
      .trim()
      .match(/^(?:async\s+def|def)\s+(test_[A-Za-z0-9_]*)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*)*\s*,?)?\s*\)\s*:$/);
    const bodyLines = nonEmptyLines.slice(hIdx + 1);
    const validBody =
      Boolean(pureHdrMatch) &&
      isBalancedBrackets(hdr) &&
      bodyLines.length > 0 &&
      bodyLines.every((bl) => /^[ \t]+/.test(bl));
    if (validBody) {
      return { kind: "test-case", definedName: testName, boundNames: [testName] };
    }
    return { kind: "setup-or-fixture", definedName: testName, boundNames: [testName] };
  }

  const topBindMatch = nonEmptyLines[0].match(
    /^(?:async\s+def|def|class)\s+([A-Za-z_][A-Za-z0-9_]*)|^([A-Za-z_][A-Za-z0-9_]*)\s*[:=]/
  );
  const definedName = topBindMatch ? topBindMatch[1] || topBindMatch[2] : null;
  return {
    kind: "setup-or-fixture",
    definedName,
    boundNames: definedName ? [definedName] : [],
  };
}

function verifyPythonAdditiveTests(beforeSource, afterSource) {
  const bRes = splitPythonTopLevelBlocks(beforeSource);
  const aRes = splitPythonTopLevelBlocks(afterSource);
  if (!bRes.ok || !aRes.ok) {
    return {
      ok: false,
      code: "CONSERVATION_UNCERTAIN",
      reason: bRes.reason || aRes.reason,
    };
  }

  const seenBindings = new Set(["pytest", "unittest"]);
  for (const bb of bRes.blocks) {
    for (const nm of bb.boundNames || []) {
      seenBindings.add(nm);
    }
  }

  let firstNonImportBaselineIdx = bRes.blocks.findIndex((b) => b.kind !== "import");
  if (firstNonImportBaselineIdx === -1) firstNonImportBaselineIdx = bRes.blocks.length;

  let bIdx = 0;
  for (const au of aRes.blocks) {
    if (bIdx < bRes.blocks.length && au.norm === bRes.blocks[bIdx].norm && au.kind === bRes.blocks[bIdx].kind) {
      bIdx++;
      continue;
    }
    if (au.kind === "import") {
      if (bIdx > firstNonImportBaselineIdx && bIdx < bRes.blocks.length) {
        return {
          ok: false,
          code: "TEST_SETUP_OR_BODY_MUTATED",
          reason: "Added Python imports must appear in the import preamble, not interleaved between existing tests.",
        };
      }
      for (const bName of au.boundNames || []) {
        if (seenBindings.has(bName) || bName.startsWith("test_") || bName.startsWith("pytest_")) {
          return {
            ok: false,
            code: "TEST_TAMPERING_BLOCKED",
            reason: `Added Python import binding '${bName}' shadows an existing binding or injects a test_/pytest_ symbol.`,
          };
        }
        seenBindings.add(bName);
      }
      continue;
    }
    if (au.kind === "test-case") {
      // Enforce strict append-only position (``): new `def test_...` ONLY after all baseline blocks!
      if (bIdx < bRes.blocks.length) {
        return {
          ok: false,
          code: "TEST_SETUP_OR_BODY_MUTATED",
          reason: "New Python test functions in additive mode must be appended after all existing baseline blocks.",
        };
      }
      if (au.definedName && seenBindings.has(au.definedName)) {
        return {
          ok: false,
          code: "TEST_TAMPERING_BLOCKED",
          reason: `Newly added Python test '${au.definedName}' shadows an existing test, import, or fixture binding.`,
        };
      }
      if (au.definedName) seenBindings.add(au.definedName);
      continue;
    }
    return {
      ok: false,
      code: "TEST_SETUP_OR_BODY_MUTATED",
      reason: `Python test setup, collection hook, import statement, or existing test function was mutated (${au.kind}).`,
    };
  }

  if (bIdx < bRes.blocks.length) {
    return {
      ok: false,
      code: "TEST_TAMPERING_BLOCKED",
      reason: "Existing Python test function or fixture was deleted or altered.",
    };
  }
  return { ok: true };
}
