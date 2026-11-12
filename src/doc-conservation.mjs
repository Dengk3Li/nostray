import crypto from "node:crypto";

function sha256Hex(str) {
  return crypto.createHash("sha256").update(str, "utf8").digest("hex");
}

const HTML_BLOCK_TYPE1_OPEN = /^<(?:pre|script|style|textarea)(?:\s|>|$)/i;
const HTML_BLOCK_TYPE1_CLOSE = /<\/(?:pre|script|style|textarea)>/i;
const HTML_BLOCK_TYPE6_TAGS =
  /^<\/?(?:address|article|aside|base|basefont|blockquote|body|caption|center|col|colgroup|dd|details|dialog|dir|div|dl|dt|fieldset|figcaption|figure|footer|form|frame|frameset|h1|h2|h3|h4|h5|h6|head|header|hr|html|iframe|legend|li|link|main|menu|menuitem|nav|noframes|ol|optgroup|option|p|param|search|section|summary|table|tbody|td|tfoot|th|thead|title|tr|track|ul)(?:\s|\/?>|$)/i;
const HTML_BLOCK_TYPE7_SINGLE_LINE =
  /^(?:<[A-Za-z][A-Za-z0-9-]*(?:\s+[A-Za-z_:][A-Za-z0-9_.:-]*(?:\s*=\s*(?:[^\s"'=<>`]+|'[^']*'|"[^"]*"))?)*\s*\/?>|<\/[A-Za-z][A-Za-z0-9-]*\s*>)\s*$/;

function computeLeadingColumns(line) {
  let cols = 0;
  let chars = 0;
  while (chars < line.length) {
    const ch = line[chars];
    if (ch === " ") {
      cols += 1;
      chars += 1;
    } else if (ch === "\t") {
      cols += 4 - (cols % 4);
      chars += 1;
    } else {
      break;
    }
  }
  return { cols, rest: line.slice(chars) };
}

/**
 * CommonMark-aware Markdown structural parser:
 * - Tracks YAML frontmatter (`---` at line 0)
 * - Tracks CommonMark HTML blocks (types 1..7)
 * - Tracks fenced code blocks & indented code blocks
 * - Tracks container blockquotes (`>`) & multi-line list item indentation stacks (``) so indented `# Heading`
 *   lines inside list items NEVER become top-level document section boundaries!
 * - Extracts top-level ATX & Setext headings with ancestry + `#occurrence`, plus `endOffsetShallow` & `endOffsetWithDescendants`
 */
export function parseMarkdownStructure(source) {
  const norm = source.replace(/\r\n/g, "\n");
  const lineOffsets = [];
  const lines = [];
  let pos = 0;
  while (pos <= norm.length) {
    const nl = norm.indexOf("\n", pos);
    if (nl === -1) {
      lineOffsets.push({ start: pos, end: norm.length });
      lines.push(norm.slice(pos));
      break;
    }
    lineOffsets.push({ start: pos, end: nl + 1 });
    lines.push(norm.slice(pos, nl));
    pos = nl + 1;
    if (pos === norm.length && norm.endsWith("\n")) {
      break;
    }
  }

  let frontmatterRange = null;
  let i = 0;
  if (lines[0] && /^---\s*$/.test(lines[0])) {
    for (let j = 1; j < lines.length; j++) {
      if (/^(?:---|\.\.\.)\s*$/.test(lines[j])) {
        frontmatterRange = {
          start: 0,
          end: lineOffsets[j].end,
          startLine: 0,
          endLine: j,
        };
        i = j + 1;
        break;
      }
    }
  }

  const headings = [];
  const linkReferenceLines = [];
  let fence = null; // { char: '`' | '~', len: number }
  let htmlBlock = null; // { type: 1..7 }
  let prevLineWasParagraph = false;
  const listContentCols = []; // stack of active list-item content column indents (``)

  for (; i < lines.length; i++) {
    const rawLine = lines[i];
    const { cols: leadCols, rest: afterIndent } = computeLeadingColumns(rawLine);

    // Inside fenced code block
    if (fence) {
      if (leadCols <= fence.maxCloseIndent) {
        const closeM = afterIndent.match(/^(`{3,}|~{3,})\s*$/);
        if (closeM && closeM[1][0] === fence.char && closeM[1].length >= fence.len) {
          fence = null;
        }
      }
      prevLineWasParagraph = false;
      continue;
    }

    // Inside HTML block
    if (htmlBlock) {
      if (htmlBlock.type === 1 && HTML_BLOCK_TYPE1_CLOSE.test(rawLine)) htmlBlock = null;
      else if (htmlBlock.type === 2 && /-->/.test(rawLine)) htmlBlock = null;
      else if (htmlBlock.type === 3 && /\?>/.test(rawLine)) htmlBlock = null;
      else if (htmlBlock.type === 4 && />/.test(rawLine)) htmlBlock = null;
      else if (htmlBlock.type === 5 && /\]\]>/.test(rawLine)) htmlBlock = null;
      else if ((htmlBlock.type === 6 || htmlBlock.type === 7) && rawLine.trim() === "") htmlBlock = null;
      prevLineWasParagraph = false;
      continue;
    }

    // Blank line: resets paragraph continuation, preserves open loose list containers until next non-blank indent check
    if (rawLine.trim() === "") {
      prevLineWasParagraph = false;
      continue;
    }

    // Pop any list-item containers whose required content indentation exceeds current non-blank line's indentation
    while (listContentCols.length > 0 && leadCols < listContentCols[listContentCols.length - 1]) {
      listContentCols.pop();
    }

    const insideListContainer = listContentCols.length > 0;
    const isIndented4PlusAtRoot = !insideListContainer && leadCols >= 4;

    // Check if this line opens a new list item (at root `leadCols <= 3` or nested inside active list container)
    const listMarkerMatch =
      (leadCols <= 3 || insideListContainer)
        ? afterIndent.match(/^([-*+]|\d{1,9}[.)])([ \t]+)(.*)$/)
        : null;
    if (listMarkerMatch) {
      const markerLen = listMarkerMatch[1].length;
      const wsAfter = computeLeadingColumns(listMarkerMatch[2]).cols;
      const effectiveWs = wsAfter > 4 || listMarkerMatch[3].trim() === "" ? 1 : wsAfter;
      listContentCols.push(leadCols + markerLen + effectiveWs);
      prevLineWasParagraph = false;
      continue;
    }

    // If inside an active list container (e.g. `  # Indented under bullet`), handle inner fences so they don't leak,
    // and NEVER promote container children to top-level document section headings!
    if (insideListContainer) {
      const relIndent = leadCols - listContentCols[listContentCols.length - 1];
      if (relIndent <= 3) {
        const innerFence = afterIndent.startsWith("`")
          ? afterIndent.match(/^(`{3,})([^`]*)$/)
          : afterIndent.match(/^(~{3,})(.*)$/);
        if (innerFence) {
          fence = {
            char: innerFence[1][0],
            len: innerFence[1].length,
            maxCloseIndent: listContentCols[listContentCols.length - 1] + 3,
          };
        }
      }
      prevLineWasParagraph = false;
      continue;
    }

    // Indented code block at document root
    if (isIndented4PlusAtRoot && !prevLineWasParagraph) {
      continue;
    }

    const stripped3 = afterIndent;

    // Blockquote container at root
    if (!isIndented4PlusAtRoot && stripped3.startsWith(">")) {
      prevLineWasParagraph = false;
      continue;
    }

    // Fenced code open at root
    if (!isIndented4PlusAtRoot) {
      const fm = stripped3.startsWith("`")
        ? stripped3.match(/^(`{3,})([^`]*)$/)
        : stripped3.match(/^(~{3,})(.*)$/);
      if (fm) {
        fence = { char: fm[1][0], len: fm[1].length, maxCloseIndent: 3 };
        prevLineWasParagraph = false;
        continue;
      }
    }

    // CommonMark HTML block open (types 1..7)
    if (!isIndented4PlusAtRoot && stripped3.startsWith("<")) {
      if (HTML_BLOCK_TYPE1_OPEN.test(stripped3)) {
        if (!HTML_BLOCK_TYPE1_CLOSE.test(stripped3)) htmlBlock = { type: 1 };
        prevLineWasParagraph = false;
        continue;
      }
      if (stripped3.startsWith("<!--")) {
        if (!/-->/.test(stripped3)) htmlBlock = { type: 2 };
        prevLineWasParagraph = false;
        continue;
      }
      if (stripped3.startsWith("<?")) {
        if (!/\?>/.test(stripped3)) htmlBlock = { type: 3 };
        prevLineWasParagraph = false;
        continue;
      }
      if (/^<![A-Za-z]/.test(stripped3)) {
        if (!/>/.test(stripped3)) htmlBlock = { type: 4 };
        prevLineWasParagraph = false;
        continue;
      }
      if (stripped3.startsWith("<![CDATA[")) {
        if (!/\]\]>/.test(stripped3)) htmlBlock = { type: 5 };
        prevLineWasParagraph = false;
        continue;
      }
      if (HTML_BLOCK_TYPE6_TAGS.test(stripped3)) {
        htmlBlock = { type: 6 };
        prevLineWasParagraph = false;
        continue;
      }
      if (!prevLineWasParagraph && HTML_BLOCK_TYPE7_SINGLE_LINE.test(stripped3)) {
        htmlBlock = { type: 7 };
        prevLineWasParagraph = false;
        continue;
      }
    }

    // Link reference definition `[label]: https://...`
    if (!isIndented4PlusAtRoot && !prevLineWasParagraph && /^\[[^\]]+\]:\s*\S+/.test(stripped3)) {
      linkReferenceLines.push({
        line: i,
        start: lineOffsets[i].start,
        end: lineOffsets[i].end,
        raw: rawLine,
      });
      prevLineWasParagraph = false;
      continue;
    }

    // ATX Heading `#`..`######`
    if (!isIndented4PlusAtRoot) {
      const atx = stripped3.match(/^(#{1,6})(?:[ \t]+(.*?))?(?:[ \t]+#+[ \t]*)?$/);
      if (atx && (atx[2] !== undefined || stripped3.trim() === atx[1])) {
        const level = atx[1].length;
        const title = (atx[2] || "").trim();
        headings.push({
          level,
          title,
          normalizedTitle: normalizeHeadingTitle(title),
          startLine: i,
          headingEndLine: i,
          startOffset: lineOffsets[i].start,
        });
        prevLineWasParagraph = false;
        continue;
      }
    }

    // Setext Heading (`===` or `---` directly under a root paragraph)
    if (!isIndented4PlusAtRoot && prevLineWasParagraph && /^(?:=+|-+)\s*$/.test(stripped3) && i > 0) {
      const level = stripped3.trim()[0] === "=" ? 1 : 2;
      const title = lines[i - 1].trim();
      headings.push({
        level,
        title,
        normalizedTitle: normalizeHeadingTitle(title),
        startLine: i - 1,
        headingEndLine: i,
        startOffset: lineOffsets[i - 1].start,
      });
      prevLineWasParagraph = false;
      continue;
    }

    prevLineWasParagraph = true;
  }

  // Compute ancestry, occurrence index, shallow body end, and descendant subtree end
  const occurrenceCounter = new Map();
  const stack = [];
  for (let idx = 0; idx < headings.length; idx++) {
    const h = headings[idx];
    while (stack.length > 0 && stack[stack.length - 1].level >= h.level) {
      stack.pop();
    }
    const ancestryTitles = [...stack.map((s) => s.title), h.title];
    const ancestryKey = ancestryTitles.map(normalizeHeadingTitle).join(" > ");
    const occ = (occurrenceCounter.get(ancestryKey) || 0) + 1;
    occurrenceCounter.set(ancestryKey, occ);
    h.occurrence = occ;
    h.ancestry = ancestryTitles;
    h.id = `${ancestryKey}#${occ}`;
    stack.push(h);

    let subtreeEndOffset = norm.length;
    for (let nextIdx = idx + 1; nextIdx < headings.length; nextIdx++) {
      if (headings[nextIdx].level <= h.level) {
        subtreeEndOffset = headings[nextIdx].startOffset;
        break;
      }
    }
    h.endOffsetWithDescendants = subtreeEndOffset;
    h.endOffsetShallow = idx + 1 < headings.length ? headings[idx + 1].startOffset : norm.length;
  }

  return {
    normalizedSource: norm,
    frontmatterRange,
    headings,
    linkReferenceLines,
  };
}

function normalizeHeadingTitle(t) {
  return String(t || "")
    .replace(/^#{1,6}\s+/, "")
    .trim()
    .toLowerCase();
}

const CN_NUMERALS = { 一: 1, 二: 2, 三: 3, 四: 4, 五: 5, 六: 6, 七: 7, 八: 8, 九: 9, 十: 10 };

function resolveSectionTargetOnBaseline(parsed, rawTarget) {
  const clean = rawTarget.replace(/^#{1,6}\s+/, "").trim();
  const normTarget = normalizeHeadingTitle(clean);

  const ordMatch = clean.match(/^第([一二三四五六七八九十\d]+)([章节部分])$/);
  if (ordMatch) {
    const numRaw = ordMatch[1];
    const num = /^\d+$/.test(numRaw) ? Number(numRaw) : CN_NUMERALS[numRaw] || null;
    if (!num) {
      return { ok: false, code: "AMBIGUOUS_SECTION_TARGET", reason: `Unresolved ordinal section '${rawTarget}'.` };
    }
    const explicitPrefixMatches = parsed.headings.filter((h) =>
      new RegExp(`^(?:第${numRaw}[章节部分]|0?${num}[.、\\s])`).test(h.title.trim())
    );
    if (explicitPrefixMatches.length === 1) {
      return { ok: true, heading: explicitPrefixMatches[0] };
    }
    if (explicitPrefixMatches.length > 1) {
      return {
        ok: false,
        code: "AMBIGUOUS_SECTION_TARGET",
        reason: `Ordinal target '${rawTarget}' matched ${explicitPrefixMatches.length} headings; specify exact heading title.`,
      };
    }
    const minLevel = Math.min(...parsed.headings.map((h) => h.level));
    const topHeadings = parsed.headings.filter((h) => h.level === minLevel);
    const subHeadings = parsed.headings.filter((h) => h.level === minLevel + 1);
    if (ordMatch[2] === "章" && topHeadings.length >= num && subHeadings.length === 0) {
      return { ok: true, heading: topHeadings[num - 1] };
    }
    return {
      ok: false,
      code: "AMBIGUOUS_SECTION_TARGET",
      reason: `Ordinal section '${rawTarget}' is ambiguous across heading levels; specify exact heading title.`,
    };
  }

  const exact = parsed.headings.filter((h) => h.normalizedTitle === normTarget);
  if (exact.length === 1) {
    return { ok: true, heading: exact[0] };
  }
  if (exact.length > 1) {
    return {
      ok: false,
      code: "AMBIGUOUS_SECTION_TARGET",
      reason: `Heading '${rawTarget}' appears ${exact.length} times in document; disambiguate with parent heading.`,
    };
  }

  const partial = parsed.headings.filter((h) => h.normalizedTitle.includes(normTarget));
  if (partial.length === 1) {
    return { ok: true, heading: partial[0] };
  }
  return {
    ok: false,
    code: "AMBIGUOUS_SECTION_TARGET",
    reason:
      partial.length === 0
        ? `Target section '${rawTarget}' not found in baseline Markdown.`
        : `Target section '${rawTarget}' ambiguously matches ${partial.length} headings.`,
  };
}

function mergeRanges(ranges) {
  if (ranges.length === 0) return [];
  const sorted = [...ranges].sort((a, b) => a.start - b.start);
  const out = [{ ...sorted[0] }];
  for (let i = 1; i < sorted.length; i++) {
    const prev = out[out.length - 1];
    if (sorted[i].start <= prev.end) {
      prev.end = Math.max(prev.end, sorted[i].end);
    } else {
      out.push({ ...sorted[i] });
    }
  }
  return out;
}

function computeComplementRanges(totalLength, authorizedRanges) {
  const merged = mergeRanges(authorizedRanges);
  const comp = [];
  let cursor = 0;
  for (const r of merged) {
    if (r.start > cursor) {
      comp.push({ start: cursor, end: r.start });
    }
    cursor = Math.max(cursor, r.end);
  }
  if (cursor < totalLength) {
    comp.push({ start: cursor, end: totalLength });
  }
  return comp;
}

/**
 * Verify Markdown section complement conservation (``), honoring per-section `shallow` boundaries
 * (`sectionSpecs`) so shallow section grants lock all child subsections byte-for-byte even when combined
 * with non-shallow grants on other sections in the same document!
 */
export function verifyMarkdownSectionConservation(
  beforeSource,
  afterSource,
  {
    sectionSpecs = null,
    sectionTargets = [],
    shallowSection = false,
    allowFullRewrite = false,
  } = {}
) {
  if (allowFullRewrite) return { ok: true };

  const beforeParsed = parseMarkdownStructure(beforeSource);
  const afterParsed = parseMarkdownStructure(afterSource);

  if (beforeParsed.frontmatterRange) {
    const bFm = beforeParsed.normalizedSource.slice(
      beforeParsed.frontmatterRange.start,
      beforeParsed.frontmatterRange.end
    );
    const aFm = afterParsed.frontmatterRange
      ? afterParsed.normalizedSource.slice(afterParsed.frontmatterRange.start, afterParsed.frontmatterRange.end)
      : "";
    if (sha256Hex(bFm) !== sha256Hex(aFm)) {
      return {
        ok: false,
        code: "FRONTMATTER_MUTATED",
        reason: "YAML frontmatter was modified or stripped without explicit rewrite authorization.",
      };
    }
  }

  const effectiveSpecs =
    Array.isArray(sectionSpecs) && sectionSpecs.length > 0
      ? sectionSpecs.map((s) => ({ target: s.target, shallow: Boolean(s.shallow) }))
      : sectionTargets.map((t) => ({ target: t, shallow: Boolean(shallowSection) }));

  if (effectiveSpecs.length > 0) {
    const resolvedRanges = [];
    for (const spec of effectiveSpecs) {
      const res = resolveSectionTargetOnBaseline(beforeParsed, spec.target);
      if (!res.ok) return res;
      resolvedRanges.push({
        start: res.heading.startOffset,
        end: spec.shallow ? res.heading.endOffsetShallow : res.heading.endOffsetWithDescendants,
        heading: res.heading,
        shallow: spec.shallow,
      });
    }

    const afterRanges = [];
    for (const r of resolvedRanges) {
      const matchAfter = afterParsed.headings.find(
        (h) => h.id === r.heading.id && h.level === r.heading.level
      );
      if (!matchAfter) {
        return {
          ok: false,
          code: "TARGET_HEADING_DELETED",
          reason: `Target section heading '${r.heading.title}' was deleted or altered in level/ancestry.`,
        };
      }
      afterRanges.push({
        start: matchAfter.startOffset,
        end: r.shallow ? matchAfter.endOffsetShallow : matchAfter.endOffsetWithDescendants,
      });
    }

    const beforeComplement = computeComplementRanges(beforeParsed.normalizedSource.length, resolvedRanges);
    const afterComplement = computeComplementRanges(afterParsed.normalizedSource.length, afterRanges);

    const beforeCompText = beforeComplement
      .map((c) => beforeParsed.normalizedSource.slice(c.start, c.end))
      .join("\u0000");
    const afterCompText = afterComplement
      .map((c) => afterParsed.normalizedSource.slice(c.start, c.end))
      .join("\u0000");

    if (sha256Hex(beforeCompText) !== sha256Hex(afterCompText)) {
      const desc = effectiveSpecs.map((s) => (s.shallow ? `${s.target} [shallow]` : s.target)).join(", ");
      return {
        ok: false,
        code: "NON_TARGET_SECTION_MUTATED",
        reason: `Content outside authorized section(s) (${desc}) was mutated.`,
      };
    }
  }

  return { ok: true };
}

const EPISTEMIC_HEDGE_PATTERNS = [
  /\bmay\b/i,
  /\bmight\b/i,
  /\bcould\b/i,
  /\bpreliminary\b/i,
  /\bpending\s+verification\b/i,
  /\bunverified\b/i,
  /\bestimated\b/i,
  /\bapproximately\b/i,
  /\breportedly\b/i,
  /可能/,
  /或许/,
  /待核实/,
  /尚待验证/,
  /初步/,
  /预计/,
  /大约/,
  /受访者口述/,
  /据称/,
];

// Full-token numeric & citation extractor (``):
// - Preserves currency prefixes (`$5`, `¥100`), scientific notation (`1e3`, `2.5E-4`), decimals, commas, and units
// - Never drops sentence-final numbers before `.` (`5.` -> `5`, `$5.` -> `$5`) while never matching substrings (`5%` inside `15%`)!
const NUMERIC_AND_CITATION_RE =
  /(?:\[\^\w+\])|(?:\[\d+\])|(?<![A-Za-z0-9_.$¥€£-])(?:[$¥€£]?\s*-?\d+(?:,\d{3})*(?:\.\d+)?(?:[eE][+-]?\d+)?(?:\s*(?:%|bps|x|ms|s|KB|MB|GB|TB|万|亿|美元|元))?)(?![A-Za-z0-9_]|(?:\.\d))/g;

function unescapeMarkdown(value) {
  return value.replace(/\\([!"#$%&'()*+,\-./:;<=>?@[\]^_`{|}~\\])/g, "$1");
}

function referenceLabel(value) {
  return unescapeMarkdown(value).trim().replace(/\s+/g, " ").toLowerCase();
}

function linkDestination(text, start) {
  while (/[ \t]/.test(text[start] || "") && start < text.length) start++;
  const angle = text[start] === "<";
  const contentStart = start + Number(angle);
  let end = contentStart;
  let depth = 0;
  while (end < text.length) {
    const char = text[end];
    if (char === "\\" && end + 1 < text.length) { end += 2; continue; }
    if (angle) {
      if (char === ">") return { start: contentStart, end, next: end + 1, destination: unescapeMarkdown(text.slice(contentStart, end)) };
      if (char === "\n" || char === "<") return null;
    } else {
      if (/\s/.test(char) || (char === ")" && depth === 0)) break;
      if (char === "(") depth++;
      if (char === ")") depth--;
      if (char === "<" || char === ">") return null;
    }
    end++;
  }
  if (angle || depth) return null;
  return { start: contentStart, end, next: end, destination: unescapeMarkdown(text.slice(contentStart, end)) };
}

function referenceDefinitions(markdown) {
  const references = new Map();
  const definitions = [];
  for (const match of markdown.matchAll(/^ {0,3}\[([^\]\n]+)\]:[ \t]*/gm)) {
    const destination = linkDestination(markdown, match.index + match[0].length);
    if (!destination || !destination.destination) continue;
    const label = referenceLabel(match[1]);
    if (!references.has(label)) references.set(label, destination.destination);
    definitions.push(destination);
  }
  return { references, definitions };
}

function closingBracket(text, start) {
  let depth = 1;
  for (let index = start + 1; index < text.length; index++) {
    if (text[index] === "\\") { index++; continue; }
    if (text[index] === "[") depth++;
    if (text[index] === "]" && --depth === 0) return index;
  }
  return -1;
}

function inlineLinkEnd(text, offset) {
  while (/\s/.test(text[offset] || "") && offset < text.length) offset++;
  if (text[offset] === ")") return offset;
  const quote = text[offset];
  if (!["'", '"', "("].includes(quote)) return -1;
  const close = quote === "(" ? ")" : quote;
  for (offset++; offset < text.length; offset++) {
    if (text[offset] === "\\") { offset++; continue; }
    if (text[offset] !== close) continue;
    offset++;
    while (/\s/.test(text[offset] || "") && offset < text.length) offset++;
    return text[offset] === ")" ? offset : -1;
  }
  return -1;
}

function maskRanges(text, ranges) {
  let result = text;
  for (const range of [...ranges].sort((a, b) => b.start - a.start)) {
    result = result.slice(0, range.start) + " ".repeat(range.end - range.start) + result.slice(range.end);
  }
  return result;
}

/** Static Markdown destinations, reference links and HTTP autolinks, without fetching them. */
function citationTokens(text, references) {
  const local = referenceDefinitions(text);
  const ranges = local.definitions.slice();
  const tokens = local.definitions.map(definition => `link:${definition.destination}`);
  for (let index = 0; index < text.length; index++) {
    if (text[index] === "\\") { index++; continue; }
    if (text[index] !== "[") continue;
    const close = closingBracket(text, index);
    if (close < 0) continue;
    if (text[close + 1] === ":") { index = close; continue; }
    if (text[close + 1] === "(") {
      const destination = linkDestination(text, close + 2);
      const end = destination ? inlineLinkEnd(text, destination.next) : -1;
      if (end >= 0) {
        tokens.push(`link:${destination.destination}`);
        ranges.push(destination);
        index = end;
      }
      continue;
    }
    let label = text.slice(index + 1, close);
    let end = close;
    if (text[close + 1] === "[") {
      const referenceEnd = closingBracket(text, close + 1);
      if (referenceEnd < 0) continue;
      label = text.slice(close + 2, referenceEnd) || label;
      end = referenceEnd;
    }
    const destination = references.get(referenceLabel(label));
    if (destination !== undefined) tokens.push(`link:${destination}`);
    index = end;
  }
  const remaining = maskRanges(text, ranges);
  for (const match of remaining.matchAll(/https?:\/\/[^\s<>]+/g)) {
    let url = match[0].replace(/[.,;!?]+$/, "");
    for (const [open, close] of [["(", ")"], ["[", "]"]]) {
      while (url.endsWith(close) && url.split(close).length > url.split(open).length) url = url.slice(0, -1);
    }
    if (!url) continue;
    tokens.push(`link:${unescapeMarkdown(url)}`);
    ranges.push({ start: match.index, end: match.index + match[0].length });
  }
  return { tokens, masked: maskRanges(text, ranges) };
}

function extractAnchorTokenList(sentence, references) {
  const citations = citationTokens(sentence, references);
  return [...citations.tokens, ...Array.from(citations.masked.matchAll(NUMERIC_AND_CITATION_RE), match =>
    match[0].replace(/\s+/g, "")
  )];
}

function multisetEquals(listA, listB) {
  if (listA.length !== listB.length) return false;
  const counts = new Map();
  for (const item of listA) counts.set(item, (counts.get(item) || 0) + 1);
  for (const item of listB) {
    const rem = counts.get(item) || 0;
    if (rem <= 0) return false;
    counts.set(item, rem - 1);
  }
  return true;
}

function extractProseSentences(markdown) {
  const norm = markdown.replace(/\r\n/g, "\n");
  const withoutFences = withoutFencedCode(norm);
  return withoutFences
    .split(/(?:[\n。！？!?]+|\.(?=\s|$)\s*)/)
    .map((s) => s.replace(/[.。!！?？]+$/, "").trim())
    .filter((s) => s.length >= 1 && !/^#{1,6}\s/.test(s));
}

function withoutFencedCode(markdown) {
  return markdown.replace(/^(?:`{3,}|~{3,})[\s\S]*?^(?:`{3,}|~{3,})\s*$/gm, "");
}

function extractWordBigrams(s) {
  const clean = s.toLowerCase().replace(/\s+/g, "");
  const set = new Set();
  if (clean.length === 1) {
    set.add(clean);
    return set;
  }
  for (let i = 0; i < clean.length - 1; i++) {
    set.add(clean.slice(i, i + 2));
  }
  return set;
}

function diceSimilarity(aSet, bSet) {
  if (aSet.size === 0 || bSet.size === 0) return 0;
  let inter = 0;
  for (const x of aSet) {
    if (bSet.has(x)) inter++;
  }
  return (2 * inter) / (aSet.size + bSet.size);
}

/**
 * Passage-aligned 1-to-1 Injective Epistemic Qualifier & Complete Numeric/Citation Token Guard (``):
 * - Retains short claims (`"5%\n"`) and sentence-final / scientific-notation numbers (`"Revenue was 5."`, `"1e3"`)
 * - Enforces injective 1-to-1 sentence matching so two anchored baseline claims can NEVER collapse onto one surviving sentence!
 */
export function verifyEpistemicAndNumericAnchors(beforeSource, afterSource) {
  const beforeProse = withoutFencedCode(beforeSource.replace(/\r\n/g, "\n"));
  const afterProse = withoutFencedCode(afterSource.replace(/\r\n/g, "\n"));
  const beforeReferences = referenceDefinitions(beforeProse).references;
  const afterReferences = referenceDefinitions(afterProse).references;
  const beforeCitations = citationTokens(beforeProse, beforeReferences).tokens;
  const afterCitations = citationTokens(afterProse, afterReferences).tokens;
  const remainingCitations = afterCitations.slice();
  for (const citation of beforeCitations) {
    const index = remainingCitations.indexOf(citation);
    if (index < 0) {
      return { ok: false, code: "EPISTEMIC_OR_NUMERIC_ANCHOR_MUTATED", reason: `Citation destination removed or changed: ${citation.slice(5)}.` };
    }
    remainingCitations.splice(index, 1);
  }
  const beforeSentences = extractProseSentences(beforeSource);
  const afterSentences = extractProseSentences(afterSource).map((text) => ({
    text,
    bigrams: extractWordBigrams(text),
    anchors: extractAnchorTokenList(text, afterReferences),
  }));

  const anchoredBefore = [];
  for (const bSent of beforeSentences) {
    const activeHedges = EPISTEMIC_HEDGE_PATTERNS.filter((re) => re.test(bSent));
    const numericAnchors = extractAnchorTokenList(bSent, beforeReferences);
    if (activeHedges.length === 0 && numericAnchors.length === 0) continue;
    anchoredBefore.push({
      text: bSent,
      activeHedges,
      numericAnchors,
      bigrams: extractWordBigrams(bSent),
      matched: false,
    });
  }

  const consumedAfterIndices = new Set();

  // Pass 1: Consume exact 1-to-1 identical sentences first
  for (const bItem of anchoredBefore) {
    for (let j = 0; j < afterSentences.length; j++) {
      if (!consumedAfterIndices.has(j) && afterSentences[j].text === bItem.text) {
        consumedAfterIndices.add(j);
        bItem.matched = true;
        break;
      }
    }
  }

  // Pass 2: Injective 1-to-1 alignment against remaining unconsumed candidate sentences
  for (const bItem of anchoredBefore) {
    if (bItem.matched) continue;

    let bestIdx = -1;
    let bestScore = 0;
    for (let j = 0; j < afterSentences.length; j++) {
      if (consumedAfterIndices.has(j)) continue;
      const sim = diceSimilarity(bItem.bigrams, afterSentences[j].bigrams);
      if (sim > bestScore) {
        bestScore = sim;
        bestIdx = j;
      }
    }

    if (bestIdx !== -1 && bestScore >= 0.35) {
      consumedAfterIndices.add(bestIdx);
      const best = afterSentences[bestIdx];
      if (bItem.activeHedges.length > 0) {
        const candHasAnyHedge = EPISTEMIC_HEDGE_PATTERNS.some((re) => re.test(best.text));
        if (!candHasAnyHedge) {
          return {
            ok: false,
            code: "EPISTEMIC_OR_NUMERIC_ANCHOR_MUTATED",
            reason: `Epistemic qualifier stripped from claim: "${bItem.text.slice(0, 70)}" -> "${best.text.slice(0, 70)}".`,
          };
        }
      }
      if (bItem.numericAnchors.length > 0 && !multisetEquals(bItem.numericAnchors, best.anchors)) {
        return {
          ok: false,
          code: "EPISTEMIC_OR_NUMERIC_ANCHOR_MUTATED",
          reason: `Numeric or citation anchor token(s) altered ([${bItem.numericAnchors.join(", ")}] -> [${best.anchors.join(", ")}]) in claim: "${best.text.slice(0, 70)}".`,
        };
      }
    } else {
      return {
        ok: false,
        code: "EPISTEMIC_OR_NUMERIC_ANCHOR_MUTATED",
        reason: `Anchored claim containing qualifier, number, or citation was removed during surgical edit: "${bItem.text.slice(0, 70)}".`,
      };
    }
  }

  return { ok: true };
}
