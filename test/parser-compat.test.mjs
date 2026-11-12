import test from "node:test";
import assert from "node:assert/strict";

import { compareCodeExports, tokenizeJsTs } from "../src/code-scanner.mjs";
import { classifyProtectionRing } from "../src/path-security.mjs";

test("Unicode identifiers allow ordinary edits while preserving other exports", () => {
  const before = [
    "const 一 = 1;",
    "export function 价格(数量) { return 数量 + 一; }",
    "export function 保持() { return 10; }",
    "",
  ].join("\n");
  const normalEdit = before.replace("数量 + 一", "数量 * 一");
  const removedExport = before.replace("export function 保持() { return 10; }\n", "");

  assert.equal(compareCodeExports(before, normalEdit, "app.mjs").ok, true);
  assert.equal(compareCodeExports(before, removedExport, "app.mjs").code, "PUBLIC_EXPORT_MUTATED");
  assert.equal(tokenizeJsTs("const 𐐀 = 1; class 测试 { #私有 = 𐐀; }").ok, true);
});

test("templates, regexes, numeric literals and assignment operators parse in real edits", () => {
  const before = [
    "export function format(项目) {",
    "  let 深度 = 0;",
    "  深度 += /^x/.test(项目) ? 1 : 0;",
    "  const score = 1e-6 + .5;",
    "  const mask = 1 << 3;",
    "  let record = {}; record.value ||= score; record.other ??= mask;",
    "  return `甲 ${/^x/.test(项目) ? `乙 ${项目}` : '丙'} ${深度}`;",
    "}",
    "export function untouched() { return 3; }",
  ].join("\n");
  const after = before.replace("1e-6 + .5", "1e-6 + .6");

  assert.equal(compareCodeExports(before, after, "app.mjs").ok, true);
  assert.equal(
    compareCodeExports(before, after.replace("export function untouched() { return 3; }", ""), "app.mjs").code,
    "PUBLIC_EXPORT_MUTATED"
  );
  assert.equal(tokenizeJsTs("export const x = ;").ok, false);
});

test("nested TypeScript generics and destructured exports retain their contracts", () => {
  const generic = "export function read(x: Map<string, Array<number>>): Map<string, Array<number>> { return x; }";
  assert.equal(compareCodeExports(generic, generic.replace("return x", "return new Map(x)"), "app.ts").ok, true);

  const before = "export const {alpha, beta: second} = source;";
  assert.equal(compareCodeExports(before, before, "app.mjs").ok, true);
  assert.equal(compareCodeExports(before, "export const {alpha} = source;", "app.mjs").code, "PUBLIC_EXPORT_MUTATED");
  assert.equal(
    compareCodeExports(before, "export const {alpha, gamma: second} = source;", "app.mjs").code,
    "PUBLIC_EXPORT_MUTATED"
  );
  assert.equal(compareCodeExports(before, "export const {alpha, beta: second} = other;", "app.mjs").code, "PUBLIC_EXPORT_MUTATED");
  assert.equal(compareCodeExports("export const {nested: {value}} = source;", "", "app.mjs").code, "CONSERVATION_UNCERTAIN");
});

test("anonymous default exports and multiline templates allow body edits without relaxing signatures", () => {
  for (const before of [
    "export default function(x) { return `甲 ${x}`; }",
    "export default async function(x) { return x; }",
    "export default class { value(x) { return x; } }",
    "export default async (x) => x;",
  ]) {
    const after = before.replace("return x", "return x + 1").replace("=> x", "=> x + 1").replace("甲 ${x}", "乙 ${x}");
    assert.equal(compareCodeExports(before, after, "app.mjs").ok, true, before);
    assert.equal(compareCodeExports(before, after.replace("(x)", "(x, y)"), "app.mjs").code, "PUBLIC_EXPORT_MUTATED", before);
  }
  const beforeThrow = "export function f() { throw `甲\n乙`; }";
  assert.equal(compareCodeExports(beforeThrow, beforeThrow.replace("乙", "丙"), "app.mjs").ok, true);
  assert.equal(compareCodeExports(beforeThrow, "export function f() { throw\n`甲`; }", "app.mjs").code, "CONSERVATION_UNCERTAIN");
});

test("Antigravity hook configuration is a protected namespace", () => {
  assert.equal(classifyProtectionRing(".agents/hooks.json").ring, "RING_00");
  assert.equal(classifyProtectionRing(".AGENTS/hooks.json").ring, "RING_00");
});
