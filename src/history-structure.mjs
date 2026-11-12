import path from "node:path";
import {
  compareCodeExports,
  SUPPORTED_JS_TS_EXTS,
  tokenizeJsTs,
} from "./code-scanner.mjs";

const ASSERT_METHODS = new Set([
  "ok", "equal", "notEqual", "strictEqual", "notStrictEqual", "deepEqual",
  "notDeepEqual", "deepStrictEqual", "notDeepStrictEqual", "partialDeepStrictEqual",
  "match", "doesNotMatch", "throws", "doesNotThrow", "rejects", "doesNotReject",
  "ifError", "fail", "same", "notSame", "true", "false", "is", "isNot",
]);

function literalValue(raw, python = false) {
  if (!/^["']/.test(raw) || raw.startsWith('"""') || raw.startsWith("'''")) return raw;
  return raw.slice(1, -1).replace(
    /\\(?:u\{([\da-f]+)\}|u([\da-f]{4})|x([\da-f]{2})|([\s\S]))/gi,
    (match, wide, unicode, hex, escaped) => {
      if (wide || unicode || hex) {
        const point = Number.parseInt(wide || unicode || hex, 16);
        return point <= 0x10ffff ? String.fromCodePoint(point) : match;
      }
      const decoded = ({ n: "\n", r: "\r", t: "\t", b: "\b", f: "\f", v: "\v", "0": "\0" })[escaped];
      if (decoded !== undefined) return decoded;
      if (python && escaped === "a") return "\x07";
      if (python && !["'", '"', "\\"].includes(escaped)) return match;
      return escaped;
    }
  );
}

function assertion(tokens, start, end, name, family, python = false, scope = "") {
  const values = tokens.slice(start, end).map(token =>
    token.type === "string" ? `string:${literalValue(token.value, python)}` : `${token.type}:${token.value}`
  );
  return {
    name,
    family,
    scope,
    key: JSON.stringify(values),
    text: renderAssertionTokens(tokens.slice(start, end)),
  };
}

function renderAssertionTokens(tokens) {
  const spacedKeywords = new Set(["assert", "return", "await", "new", "throw", "if", "while", "with"]);
  let result = "";
  for (let index = 0; index < tokens.length; index++) {
    const current = tokens[index];
    const previous = tokens[index - 1];
    const closedPunctuation = [".", "?.", ",", ";", ")", "]", "}", ":"].includes(current.value);
    const openPunctuation = [".", "?.", "(", "[", "{", "!", "~"].includes(previous?.value);
    const callOrIndex = ["(", "["].includes(current.value) && previous &&
      (previous.type === "ident" || [")", "]"].includes(previous.value)) && !spacedKeywords.has(previous.value);
    if (previous && !closedPunctuation && !openPunctuation && !callOrIndex) result += " ";
    // Literal tokens are copied intact. Spacing changes apply only between tokens.
    result += current.value;
  }
  return result;
}

function scopeAt(ranges, index) {
  return ranges.filter(range => index > range.start && index < range.end)
    .map(range => range.name).join(" > ");
}

function jsTestScopes(tokens) {
  const ranges = [];
  for (let index = 0; index < tokens.length; index++) {
    if (tokens[index].type !== "ident" || !["describe", "test", "it"].includes(tokens[index].value)) continue;
    let open = index + 1;
    while (tokens[open]?.value === "." && tokens[open + 1]?.type === "ident") open += 2;
    if (tokens[open]?.value !== "(" || tokens[open + 1]?.type !== "string") continue;
    const end = closingIndex(tokens, open);
    if (end >= 0) ranges.push({ start: open, end, name: `${tokens[index].value}:${literalValue(tokens[open + 1].value)}` });
  }
  return ranges;
}

function closingIndex(tokens, start) {
  const closes = { "(": ")", "[": "]", "{": "}" };
  const stack = [];
  for (let index = start; index < tokens.length; index++) {
    const value = tokens[index].value;
    if (closes[value]) stack.push(closes[value]);
    else if ([")", "]", "}"].includes(value)) {
      if (stack.pop() !== value) return -1;
      if (!stack.length) return index;
    }
  }
  return -1;
}

function jsAssertionBindings(tokens) {
  const roots = new Map([["assert", "assert"], ["expect", "expect"]]);
  const direct = new Map();
  for (let index = 0; index < tokens.length; index++) {
    if (tokens[index].value !== "import" || tokens[index + 1]?.value === "(") continue;
    let end = index + 1;
    while (end < tokens.length && tokens[end].type !== "string" && tokens[end].value !== ";") end++;
    if (tokens[end]?.type !== "string") continue;
    const moduleName = literalValue(tokens[end].value);
    const nodeAssert = /^(?:node:)?assert(?:\/strict)?$/.test(moduleName);
    const expectModule = /^(?:vitest|@jest\/globals|chai|expect)$/.test(moduleName);
    if (!nodeAssert && !expectModule) continue;
    const bindings = tokens.slice(index + 1, end);
    if (nodeAssert && bindings[0]?.type === "ident") roots.set(bindings[0].value, "assert");
    for (let item = 0; item < bindings.length; item++) {
      const original = bindings[item].value;
      const local = bindings[item + 1]?.value === "as" ? bindings[item + 2]?.value : original;
      if (nodeAssert && original === "*" && local) roots.set(local, "assert");
      if (nodeAssert && ASSERT_METHODS.has(original)) direct.set(local, `assert.${original}`);
      if (expectModule && original === "expect") roots.set(local, "expect");
    }
  }
  return { roots, direct };
}

function jsAssertions(source) {
  const scan = tokenizeJsTs(source);
  if (!scan.ok) return { assertions: [], partial: true };
  const { tokens } = scan;
  const { roots, direct } = jsAssertionBindings(tokens);
  const scopes = jsTestScopes(tokens);
  const assertions = [];
  let partial = false;
  for (let index = 0; index < tokens.length; index++) {
    const token = tokens[index];
    if (token.type !== "ident" || [".", "?."].includes(tokens[index - 1]?.value)) continue;
    let family = roots.get(token.value);
    let name = token.value;
    let open = index + 1;
    if (direct.has(token.value)) {
      family = "assert";
      name = direct.get(token.value);
    } else if (family === "assert" && tokens[open]?.value === ".") {
      if (!ASSERT_METHODS.has(tokens[open + 1]?.value)) continue;
      name += `.${tokens[open + 1].value}`;
      open += 2;
    } else if (token.value === "t" && tokens[open]?.value === ".") {
      const method = tokens[open + 1]?.value;
      if (!ASSERT_METHODS.has(method)) continue;
      family = "assert";
      name = `t.${method}`;
      open += 2;
    }
    if (!family) continue;
    if (["[", "<"].includes(tokens[open]?.value)) { partial = true; continue; }
    if (tokens[open]?.value !== "(") continue;
    let end = closingIndex(tokens, open) + 1;
    if (!end) { partial = true; continue; }
    if (family === "expect") {
      let matcher = null;
      while ([".", "?."].includes(tokens[end]?.value) && tokens[end + 1]?.type === "ident") {
        const member = tokens[end + 1].value;
        end += 2;
        if (tokens[end]?.value === "(") {
          const close = closingIndex(tokens, end);
          if (close < 0) { partial = true; break; }
          end = close + 1;
          matcher = member;
        }
      }
      if (!matcher) { partial = true; continue; }
      name = `${token.value}.${matcher}`;
    }
    assertions.push(assertion(tokens, index, end, name, family, false, scopeAt(scopes, index)));
    // Keep scanning inside assertion arguments so nested assertions are accounted for.
  }
  return { assertions, partial };
}

/** A bounded lexer, never an evaluator. Export-parser uncertainty is retained by the caller. */
function pythonTokens(source) {
  const tokens = [];
  const stack = [];
  let offset = 0;
  let statement = 0;
  const location = position => {
    const start = source.lastIndexOf("\n", position - 1) + 1;
    const whitespace = source.slice(start).match(/^[ \t]*/)[0];
    return { statement, indent: whitespace.replace(/\t/g, "        ").length };
  };
  while (offset < source.length) {
    const remaining = source.slice(offset);
    const char = source[offset];
    if (char === "#") {
      const newline = source.indexOf("\n", offset);
      offset = newline < 0 ? source.length : newline;
      continue;
    }
    if (char === "\\" && /^\\\r?\n/.test(remaining)) {
      offset += remaining.startsWith("\\\r\n") ? 3 : 2;
      continue;
    }
    if (/\s/.test(char)) {
      if (char === "\n" && !stack.length) statement++;
      offset++;
      continue;
    }
    const stringStart = remaining.match(/^([rubf]{0,2})("""|'''|"|')/i);
    if (stringStart) {
      const [prefix, flags, quote] = stringStart;
      let end = offset + prefix.length;
      let closed = false;
      while (end < source.length) {
        if (source[end] === "\\") { end += 2; continue; }
        if (source.startsWith(quote, end)) { end += quote.length; closed = true; break; }
        if (source[end] === "\n" && quote.length === 1) break;
        end++;
      }
      if (!closed) return { tokens: [], partial: true };
      tokens.push({ type: flags ? "prefixed-string" : "string", value: source.slice(offset, end), ...location(offset) });
      offset = end;
      continue;
    }
    const word = remaining.match(/^[\p{ID_Start}_][\p{ID_Continue}_]*/u);
    const number = remaining.match(/^(?:\d[\w.]*|\.\d[\w.]*)/);
    const value = word?.[0] || number?.[0] || remaining.match(/^(?:==|!=|<=|>=|:=|\*\*|\/\/|<<|>>|->)/)?.[0] || char;
    if (["(", "[", "{"].includes(value)) stack.push({ "(": ")", "[": "]", "{": "}" }[value]);
    else if ([")", "]", "}"].includes(value) && stack.pop() !== value) return { tokens: [], partial: true };
    tokens.push({ type: word ? "ident" : number ? "number" : "punct", value, ...location(offset) });
    if (value === ";" && !stack.length) statement++;
    offset += value.length;
  }
  return { tokens, partial: stack.length > 0 };
}

function pythonScopes(tokens) {
  const ranges = [];
  for (let index = 0; index < tokens.length; index++) {
    const token = tokens[index];
    if (token.type !== "ident" || !["def", "class"].includes(token.value) || tokens[index + 1]?.type !== "ident") continue;
    let end = index + 2;
    while (end < tokens.length && (tokens[end].statement === token.statement || tokens[end].indent > token.indent)) end++;
    ranges.push({ start: index, end, name: `${token.value}:${tokens[index + 1].value}` });
  }
  return ranges;
}

function pythonAssertions(source) {
  const scan = pythonTokens(source);
  if (scan.partial) return { assertions: [], partial: true };
  const { tokens } = scan;
  const scopes = pythonScopes(tokens);
  const assertions = [];
  let partial = false;
  for (let index = 0; index < tokens.length; index++) {
    if (tokens[index].type !== "ident") continue;
    if (tokens[index].value === "assert" && tokens[index - 1]?.value !== ".") {
      let end = index + 1;
      while (end < tokens.length && tokens[end].statement === tokens[index].statement && tokens[end].value !== ";") end++;
      if (end === index + 1 || /^(?:==|!=|<=|>=|=|\+|-|\*|\/|and|or|not|in|is|,)$/.test(tokens[end - 1].value)) {
        partial = true;
        continue;
      }
      assertions.push(assertion(tokens, index, end, "assert", "assert", true, scopeAt(scopes, index)));
      continue;
    }
    if (tokens[index].value !== "self" || tokens[index + 1]?.value !== "." ||
        !/^assert[A-Z_]/.test(tokens[index + 2]?.value || "") || tokens[index + 3]?.value !== "(") continue;
    const end = closingIndex(tokens, index + 3);
    if (end < 0) { partial = true; continue; }
    assertions.push(assertion(tokens, index, end + 1, `self.${tokens[index + 2].value}`, "assert", true, scopeAt(scopes, index)));
  }
  return { assertions, partial };
}

function compareAssertions(before, after) {
  const remaining = after.slice();
  const missing = [];
  for (const previous of before) {
    const exact = remaining.findIndex(current => current.key === previous.key && current.scope === previous.scope);
    if (exact >= 0) remaining.splice(exact, 1);
    else missing.push(previous);
  }
  const replacements = new Map();
  const matcherName = item => item.name.split(".").at(-1);
  function pairUnique(selector) {
    for (const previous of missing) {
      if (replacements.has(previous)) continue;
      const matches = item => item.scope === previous.scope && item.family === previous.family && selector(item) === selector(previous);
      const oldCandidates = missing.filter(item => !replacements.has(item) && matches(item));
      const newCandidates = remaining.filter(matches);
      if (oldCandidates.length !== 1 || newCandidates.length !== 1) continue;
      const current = newCandidates[0];
      replacements.set(previous, current);
      remaining.splice(remaining.indexOf(current), 1);
    }
  }
  pairUnique(matcherName);
  pairUnique(item => item.family);
  return missing.map(previous => {
    const current = replacements.get(previous);
    return current
      ? { kind: "assertion-changed", name: previous.name, before: previous.text, after: current.text }
      : { kind: "assertion-removed", name: previous.name, before: previous.text };
  });
}

/** Compare supplied source only. Findings describe syntax changes, without assigning intent or correctness. */
export function compareHistoricalFile({ path: filePath, before, after, isTest = false }) {
  // TestCase classes and test functions are test implementation, not an API surface.
  const comparison = isTest ? { verdict: "OK", removedOrMutated: [] } : compareCodeExports(before, after, filePath);
  const findings = comparison.removedOrMutated.map(change => ({
    kind: change.change === "REMOVED" ? "export-removed" : "export-changed",
    name: change.exportedName,
    before: change.before,
    ...(change.after === null ? {} : { after: change.after }),
  }));
  let partial = comparison.verdict === "UNKNOWN";
  if (isTest) {
    const extension = path.extname(filePath).toLowerCase();
    const collect = SUPPORTED_JS_TS_EXTS.has(extension) ? jsAssertions : extension === ".py" ? pythonAssertions : null;
    if (!collect) return { findings, partial: true };
    const oldAssertions = collect(before);
    const newAssertions = collect(after);
    partial ||= oldAssertions.partial || newAssertions.partial;
    if (!oldAssertions.partial && !newAssertions.partial) {
      findings.push(...compareAssertions(oldAssertions.assertions, newAssertions.assertions));
    }
  }
  return { findings, partial };
}
