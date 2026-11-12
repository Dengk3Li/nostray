export const FROZEN_SCHEMA_KEYWORDS = new Set([
  "required",
  "type",
  "enum",
  "const",
  "$ref",
  "$defs",
  "definitions",
  "additionalProperties",
  "unevaluatedProperties",
  "minimum",
  "maximum",
  "exclusiveMinimum",
  "exclusiveMaximum",
  "minLength",
  "maxLength",
  "pattern",
  "minItems",
  "maxItems",
  "uniqueItems",
  "minProperties",
  "maxProperties",
  "oneOf",
  "anyOf",
  "allOf",
  "not",
  "if",
  "then",
  "else",
]);

export function escapeJsonPointerSegment(seg) {
  return String(seg).replace(/~/g, "~0").replace(/\//g, "~1");
}

export function validateRfc6901Pointer(ptr) {
  if (ptr === "") return true;
  if (typeof ptr !== "string" || !ptr.startsWith("/")) return false;
  return !/~(?![01])/.test(ptr);
}

/**
 * Strict RFC 8259 JSON recursive-descent parser that:
 * 1. Rejects duplicate keys inside any JSON object (`DUPLICATE_JSON_KEY`)
 * 2. Preserves exact raw numeric lexemes (`raw` string, avoiding JS IEEE-754 precision loss on 64-bit ints / decimals)
 * 3. Rejects trailing commas and comments
 */
export function parseStrictJsonAst(source) {
  const s = String(source);
  const n = s.length;
  let i = 0;

  function skipWs() {
    while (i < n) {
      const c = s[i];
      if (c === " " || c === "\t" || c === "\n" || c === "\r") i++;
      else break;
    }
  }

  function parseValue() {
    skipWs();
    if (i >= n) throw makeErr("Unexpected end of JSON input");
    const c = s[i];
    if (c === "{") return parseObject();
    if (c === "[") return parseArray();
    if (c === '"') return parseStringNode();
    if (c === "t" && s.slice(i, i + 4) === "true") {
      i += 4;
      return { kind: "boolean", value: true, canonical: "true" };
    }
    if (c === "f" && s.slice(i, i + 5) === "false") {
      i += 5;
      return { kind: "boolean", value: false, canonical: "false" };
    }
    if (c === "n" && s.slice(i, i + 4) === "null") {
      i += 4;
      return { kind: "null", value: null, canonical: "null" };
    }
    if (c === "-" || (c >= "0" && c <= "9")) {
      return parseNumberNode();
    }
    throw makeErr(`Unexpected character '${c}' at offset ${i}`);
  }

  function parseStringNode() {
    const start = i;
    i++;
    let decoded = "";
    while (i < n) {
      const ch = s[i];
      if (ch === '"') {
        i++;
        const raw = s.slice(start, i);
        decoded = JSON.parse(raw);
        return { kind: "string", value: decoded, raw, canonical: JSON.stringify(decoded) };
      }
      if (ch === "\\") {
        i += 2;
        continue;
      }
      if (ch.charCodeAt(0) < 0x20) {
        throw makeErr(`Unescaped control character in JSON string at offset ${i}`);
      }
      i++;
    }
    throw makeErr("Unterminated JSON string");
  }

  function parseNumberNode() {
    const start = i;
    if (s[i] === "-") i++;
    if (i >= n) throw makeErr("Invalid JSON number");
    if (s[i] === "0") {
      i++;
      if (i < n && s[i] >= "0" && s[i] <= "9") {
        throw makeErr("Leading zeros are not permitted in JSON numbers");
      }
    } else if (s[i] >= "1" && s[i] <= "9") {
      while (i < n && s[i] >= "0" && s[i] <= "9") i++;
    } else {
      throw makeErr("Invalid JSON number");
    }
    if (i < n && s[i] === ".") {
      i++;
      if (i >= n || s[i] < "0" || s[i] > "9") throw makeErr("Invalid fraction in JSON number");
      while (i < n && s[i] >= "0" && s[i] <= "9") i++;
    }
    if (i < n && (s[i] === "e" || s[i] === "E")) {
      i++;
      if (i < n && (s[i] === "+" || s[i] === "-")) i++;
      if (i >= n || s[i] < "0" || s[i] > "9") throw makeErr("Invalid exponent in JSON number");
      while (i < n && s[i] >= "0" && s[i] <= "9") i++;
    }
    const raw = s.slice(start, i);
    return { kind: "number", raw, canonical: `num:${raw}` };
  }

  function parseArray() {
    i++;
    skipWs();
    const items = [];
    if (i < n && s[i] === "]") {
      i++;
      return { kind: "array", items, canonical: "[]" };
    }
    while (i < n) {
      const elem = parseValue();
      items.push(elem);
      skipWs();
      if (s[i] === ",") {
        i++;
        skipWs();
        if (s[i] === "]") throw makeErr("Trailing comma in JSON array");
        continue;
      }
      if (s[i] === "]") {
        i++;
        return {
          kind: "array",
          items,
          canonical: `[${items.map((x) => x.canonical).join(",")}]`,
        };
      }
      throw makeErr(`Expected ',' or ']' in JSON array at offset ${i}`);
    }
    throw makeErr("Unterminated JSON array");
  }

  function parseObject() {
    i++;
    skipWs();
    const entries = new Map();
    if (i < n && s[i] === "}") {
      i++;
      return { kind: "object", entries, canonical: "{}" };
    }
    while (i < n) {
      skipWs();
      if (s[i] !== '"') throw makeErr(`Expected string key in JSON object at offset ${i}`);
      const keyNode = parseStringNode();
      if (entries.has(keyNode.value)) {
        const dupErr = makeErr(`Duplicate JSON object key '${keyNode.value}'`, "DUPLICATE_JSON_KEY");
        throw dupErr;
      }
      skipWs();
      if (s[i] !== ":") throw makeErr(`Expected ':' after key '${keyNode.value}'`);
      i++;
      const valNode = parseValue();
      entries.set(keyNode.value, valNode);
      skipWs();
      if (s[i] === ",") {
        i++;
        skipWs();
        if (s[i] === "}") throw makeErr("Trailing comma in JSON object");
        continue;
      }
      if (s[i] === "}") {
        i++;
        const sortedKeys = Array.from(entries.keys()).sort();
        const canonical = `{${sortedKeys
          .map((k) => `${JSON.stringify(k)}:${entries.get(k).canonical}`)
          .join(",")}}`;
        return { kind: "object", entries, canonical };
      }
      throw makeErr(`Expected ',' or '}' in JSON object at offset ${i}`);
    }
    throw makeErr("Unterminated JSON object");
  }

  function makeErr(msg, code = "MALFORMED_JSON") {
    const e = new Error(msg);
    e.code = code;
    return e;
  }

  try {
    const root = parseValue();
    skipWs();
    if (i !== n) {
      throw makeErr(`Trailing tokens after JSON root at offset ${i}`);
    }
    return { ok: true, ast: root };
  } catch (err) {
    return {
      ok: false,
      code: err.code || "MALFORMED_JSON",
      reason: err.message,
    };
  }
}

function subtreeContainsFrozenSchemaConstraint(node) {
  if (!node) return false;
  if (node.kind === "object") {
    for (const [k, v] of node.entries.entries()) {
      if (FROZEN_SCHEMA_KEYWORDS.has(k) || k === "properties") return true;
      if (subtreeContainsFrozenSchemaConstraint(v)) return true;
    }
    return false;
  }
  if (node.kind === "array") {
    return node.items.some((item) => subtreeContainsFrozenSchemaConstraint(item));
  }
  return false;
}

/**
 * Independent full-AST Schema Constraint Guard (``):
 * Runs BEFORE ordinary file or pointer grants so deletion of `required`/`type`/etc., addition of new schema constraints,
 * deletion of existing `properties` keys, or replacement of a schema object with boolean `true`/`false` can NEVER slip through!
 */
function collectSchemaConstraintViolations(beforeAst, afterAst) {
  const violations = [];

  function walkSchema(bNode, aNode, ptr, parentKey = null) {
    if (bNode && aNode && bNode.canonical === aNode.canonical) {
      return;
    }

    // Root or sub-schema replaced across node kinds (e.g. `{ "type": "string" }` -> `true`)
    if (!bNode || !aNode || bNode.kind !== aNode.kind) {
      if (
        (bNode && (bNode.kind === "object" || subtreeContainsFrozenSchemaConstraint(bNode))) ||
        (aNode && subtreeContainsFrozenSchemaConstraint(aNode)) ||
        FROZEN_SCHEMA_KEYWORDS.has(parentKey)
      ) {
        violations.push({
          code: "JSON_SCHEMA_CONSTRAINT_MUTATED",
          pointer: ptr || "/",
          reason: `Schema structure or constraint at '${ptr || "/"}' was replaced (${bNode?.kind || "missing"} -> ${aNode?.kind || "missing"}) without explicit constraint authorization.`,
        });
      }
      return;
    }

    if (bNode.kind === "object") {
      const allKeys = new Set([...bNode.entries.keys(), ...aNode.entries.keys()]);
      for (const k of allKeys) {
        const childPtr = `${ptr}/${escapeJsonPointerSegment(k)}`;
        const bVal = bNode.entries.get(k);
        const aVal = aNode.entries.get(k);

        // 1. Frozen schema keyword or `properties` container added, deleted, or modified at ANY depth
        if (FROZEN_SCHEMA_KEYWORDS.has(k)) {
          if (!bVal || !aVal || bVal.canonical !== aVal.canonical) {
            violations.push({
              code: "JSON_SCHEMA_CONSTRAINT_MUTATED",
              pointer: childPtr,
              reason: `Schema constraint keyword '${k}' at '${childPtr}' cannot be ${!bVal ? "added" : !aVal ? "deleted" : "modified"} without explicit constraint authorization.`,
            });
          }
          continue;
        }

        if (k === "properties" && (!bVal || !aVal)) {
          violations.push({
            code: "JSON_SCHEMA_CONSTRAINT_MUTATED",
            pointer: childPtr,
            reason: `Schema 'properties' map at '${childPtr}' cannot be ${!bVal ? "added" : "deleted"} without explicit constraint authorization.`,
          });
          continue;
        }

        // 2. Existing property inside a `properties` map cannot be deleted without constraint authorization
        if (parentKey === "properties" && bVal && !aVal) {
          violations.push({
            code: "JSON_SCHEMA_CONSTRAINT_MUTATED",
            pointer: childPtr,
            reason: `Existing schema property '${k}' at '${childPtr}' was deleted.`,
          });
          continue;
        }

        // 3. Deleted non-keyword object subtree: check whether it contained nested schema constraints!
        if (bVal && !aVal) {
          if (subtreeContainsFrozenSchemaConstraint(bVal)) {
            violations.push({
              code: "JSON_SCHEMA_CONSTRAINT_MUTATED",
              pointer: childPtr,
              reason: `Deleted subtree at '${childPtr}' contained protected JSON Schema constraints.`,
            });
          }
          continue;
        }

        // 4. Added subtree anywhere (including under `properties`, ``): block any new frozen schema constraints!
        if (!bVal && aVal) {
          if (subtreeContainsFrozenSchemaConstraint(aVal)) {
            violations.push({
              code: "JSON_SCHEMA_CONSTRAINT_MUTATED",
              pointer: childPtr,
              reason: `Added subtree at '${childPtr}' introduces new JSON Schema constraints without authorization.`,
            });
          }
          continue;
        }

        walkSchema(bVal, aVal, childPtr, k);
      }
      return;
    }

    if (bNode.kind === "array") {
      const maxLen = Math.max(bNode.items.length, aNode.items.length);
      for (let idx = 0; idx < maxLen; idx++) {
        walkSchema(bNode.items[idx] || null, aNode.items[idx] || null, `${ptr}/${idx}`, null);
      }
    }
  }

  walkSchema(beforeAst, afterAst, "", null);
  return violations;
}

function isPointerCoveredBySpecs(pointer, pointerSpecs = []) {
  for (const sp of pointerSpecs) {
    if (pointer === sp.pointer) return true;
    if (!sp.exact && (sp.pointer === "" || pointer.startsWith(`${sp.pointer}/`))) return true;
  }
  return false;
}

function mayDescendIntoSpecs(pointer, pointerSpecs = []) {
  for (const sp of pointerSpecs) {
    if (sp.pointer === pointer || sp.pointer.startsWith(`${pointer}/`)) {
      return true;
    }
    if (!sp.exact && (sp.pointer === "" || pointer.startsWith(`${sp.pointer}/`))) {
      return true;
    }
  }
  return false;
}

/**
 * Verify JSON / JSON Schema conservation with strict per-pointer RFC 6901 precedence (``, ``):
 * 1. Malformed or duplicate-key JSON -> fail closed (`MALFORMED_JSON` / `DUPLICATE_JSON_KEY`)
 * 2. Invalid RFC 6901 pointer in grant -> fail closed (`INVALID_JSON_POINTER`)
 * 3. Independent full-AST Schema constraint verification when `isSchemaLike && !allowSchemaKeywords`
 * 4. Every subtree outside explicit `pointerSpecs` / `jsonPointers` grants must remain structurally identical (`JSON_SUBTREE_MUTATED`)
 */
export function verifyJsonConservation(
  beforeSource,
  afterSource,
  {
    isSchemaLike = false,
    pointerSpecs = null,
    jsonPointers = [],
    exactJsonPointers = false,
    allowFullFileGrant = false,
    allowSchemaKeywords = false,
  } = {}
) {
  const beforeRes = parseStrictJsonAst(beforeSource);
  if (!beforeRes.ok) {
    return { ok: false, code: beforeRes.code, reason: `Baseline JSON invalid: ${beforeRes.reason}` };
  }
  const afterRes = parseStrictJsonAst(afterSource);
  if (!afterRes.ok) {
    return { ok: false, code: afterRes.code, reason: `Candidate JSON invalid: ${afterRes.reason}` };
  }

  const effectiveSpecs =
    Array.isArray(pointerSpecs) && pointerSpecs.length > 0
      ? pointerSpecs.map((s) => ({ pointer: s.pointer, exact: Boolean(s.exact) }))
      : jsonPointers.map((p) => ({ pointer: p, exact: Boolean(exactJsonPointers) }));

  for (const sp of effectiveSpecs) {
    if (!validateRfc6901Pointer(sp.pointer)) {
      return {
        ok: false,
        code: "INVALID_JSON_POINTER",
        reason: `Invalid RFC 6901 JSON Pointer '${sp.pointer}'.`,
      };
    }
  }

  // Step 1: Independent full-tree Schema Constraint check (``) — never bypassed by whole-file or pointer grants!
  if (isSchemaLike && !allowSchemaKeywords) {
    const schemaViolations = collectSchemaConstraintViolations(beforeRes.ast, afterRes.ast);
    if (schemaViolations.length > 0) {
      return {
        ok: false,
        code: schemaViolations[0].code,
        reason: schemaViolations[0].reason,
        violations: schemaViolations,
      };
    }
  }

  // Step 2: If unconstrained whole-file grant is active (and schema constraints already passed above), allow remaining edits
  if (allowFullFileGrant && effectiveSpecs.length === 0) {
    return { ok: true };
  }

  const violations = [];

  function walk(bNode, aNode, ptr) {
    if (bNode && aNode && bNode.canonical === aNode.canonical) {
      return;
    }

    const coveredHere = isPointerCoveredBySpecs(ptr, effectiveSpecs);

    if (!bNode || !aNode || bNode.kind !== aNode.kind) {
      if (!coveredHere) {
        violations.push({
          code: "JSON_SUBTREE_MUTATED",
          pointer: ptr || "/",
          reason: `Unauthorized JSON value mutation at '${ptr || "/"}'.`,
        });
      }
      return;
    }

    if (bNode.kind === "object") {
      const allKeys = new Set([...bNode.entries.keys(), ...aNode.entries.keys()]);
      for (const k of allKeys) {
        const childPtr = `${ptr}/${escapeJsonPointerSegment(k)}`;
        const bVal = bNode.entries.get(k);
        const aVal = aNode.entries.get(k);

        if (bVal && !aVal) {
          if (!isPointerCoveredBySpecs(childPtr, effectiveSpecs)) {
            violations.push({
              code: "JSON_SUBTREE_MUTATED",
              pointer: childPtr,
              reason: `JSON key '${k}' at '${childPtr}' was deleted outside granted pointers.`,
            });
          }
          continue;
        }

        if (!bVal && aVal) {
          if (!isPointerCoveredBySpecs(childPtr, effectiveSpecs)) {
            violations.push({
              code: "JSON_SUBTREE_MUTATED",
              pointer: childPtr,
              reason: `Unauthorized JSON key '${k}' added at '${childPtr}'.`,
            });
          }
          continue;
        }

        if (bVal.canonical === aVal.canonical) continue;

        if (mayDescendIntoSpecs(childPtr, effectiveSpecs)) {
          walk(bVal, aVal, childPtr);
        } else {
          violations.push({
            code: "JSON_SUBTREE_MUTATED",
            pointer: childPtr,
            reason: `JSON subtree at '${childPtr}' mutated without grant.`,
          });
        }
      }
      return;
    }

    if (!coveredHere) {
      violations.push({
        code: "JSON_SUBTREE_MUTATED",
        pointer: ptr || "/",
        reason: `JSON ${bNode.kind} at '${ptr || "/"}' mutated without grant.`,
      });
    }
  }

  walk(beforeRes.ast, afterRes.ast, "");

  if (violations.length > 0) {
    return {
      ok: false,
      code: violations[0].code,
      reason: violations[0].reason,
      violations,
    };
  }
  return { ok: true };
}
