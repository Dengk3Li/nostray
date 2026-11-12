import test from "node:test";
import assert from "node:assert/strict";
import { compareHistoricalFile } from "../src/history-structure.mjs";

const compare = (before, after, filePath = "sample.test.mjs", isTest = true) =>
  compareHistoricalFile({ path: filePath, before, after, isTest });

test("reports removed and changed JS/TS contracts, preserving ordinary body edits", () => {
  const before = "export function price(x: number): number { return x * 2; }\nexport function other() { return 1; }";
  assert.deepEqual(compare(before, before.replace("x * 2", "0"), "app.ts", false), { findings: [], partial: false });
  const result = compare(before, "export function price(x: string): number { return 0; }", "app.ts", false);
  assert.equal(result.partial, false);
  assert.deepEqual(result.findings.map(item => [item.kind, item.name]), [["export-changed", "price"], ["export-removed", "other"]]);
});

test("reports Python public signature changes and deletions", () => {
  const before = "def price(x: int) -> int:\n    return x * 2\n\ndef other():\n    return 1\n";
  const result = compare(before, "def price(x: str) -> int:\n    return 0\n", "app.py", false);
  assert.equal(result.partial, false);
  assert.deepEqual(result.findings.map(item => [item.kind, item.name]), [["export-changed", "price"], ["export-removed", "other"]]);
});

test("comments, strings, whitespace, quote style, movement and additions do not become assertion risks", () => {
  const before = "assert.equal(value, 'ok');\nexpect(result).toEqual([1, 2]);\n";
  const after = "// assert.fail('gone');\nconst text = 'expect(x).toBe(false)';\nexpect(result).toEqual([1,2]);\nassert /* note */ . equal(value, \"ok\");\nassert.ok(extra);";
  assert.deepEqual(compare(before, after), { findings: [], partial: false });
});

test("distinguishes removed assertions from changed matchers and retains multiplicity", () => {
  const before = "assert.equal(x, 1); assert.equal(x, 1); expect(y).not.toBe(0);";
  const result = compare(before, "assert.equal(x, 1); expect(y).toEqual(0);");
  assert.equal(result.partial, false);
  assert.deepEqual(result.findings.map(item => item.kind), ["assertion-removed", "assertion-changed"]);
  assert.match(result.findings[1].after, /toEqual/);
});

test("supports Node assertion aliases and an imported expect alias", () => {
  const before = "import { strictEqual as check } from 'node:assert/strict';\nimport { expect as verify } from 'vitest';\ncheck(x, 1); verify(y).toBe(true);";
  const after = before.replace("check(x, 1)", "check(x, 2)").replace("verify(y).toBe(true);", "");
  const result = compare(before, after);
  assert.equal(result.partial, false);
  assert.deepEqual(result.findings.map(item => [item.kind, item.name]), [["assertion-changed", "assert.strictEqual"], ["assertion-removed", "verify.toBe"]]);
});

test("Python assertions ignore comments and triple strings and survive multiline movement", () => {
  const before = 'def test_price():\n    assert (\n        price(1) == 2\n    )\n    self.assertEqual(value, "ok")\n';
  const after = 'def test_price():\n    """assert False\nself.assertEqual(0, 1)"""\n    self.assertEqual(value, \'ok\') # note\n    assert (price(1)==2)\n    assert extra\n';
  const result = compare(before, after, "test_price.py");
  assert.equal(result.findings.some(item => item.kind.startsWith("assertion-")), false);
  assert.equal(result.partial, false);
});

test("Python assert and unittest replacements carry the old and new expression", () => {
  const before = "def test_price():\n    assert price(1) == 2\n\ndef test_value():\n    self.assertEqual(value, 3)\n";
  const after = "def test_price():\n    assert price(1) == 0\n\ndef test_value():\n    self.assertTrue(value)\n";
  const result = compare(before, after, "test_price.py");
  assert.equal(result.partial, false);
  assert.equal(result.findings.filter(item => item.kind === "assertion-changed").length, 2);
  assert.match(result.findings[0].before, /2/);
  assert.match(result.findings[0].after, /0/);
});

test("adding a unittest method never reports a public API mutation", () => {
  const before = "import unittest\nclass TestRevision(unittest.TestCase):\n    def test_existing(self):\n        self.assertEqual(value, 3)\n";
  const after = before + "    def test_added(self):\n        self.assertTrue(extra)\n";
  assert.deepEqual(compare(before, after, "test_revision.py"), { findings: [], partial: false });
});

test("removed assertions cannot pair with assertions added in a different test", () => {
  for (const [before, after, filePath] of [
    ["test('first', () => { assert.equal(x, 1); }); test('second', () => {});", "test('first', () => {}); test('second', () => { assert.equal(x, 2); });", "sample.test.mjs"],
    ["def test_first():\n    assert x == 1\n\ndef test_second():\n    pass\n", "def test_first():\n    pass\n\ndef test_second():\n    assert x == 2\n", "test_sample.py"],
  ]) {
    const result = compare(before, after, filePath);
    assert.deepEqual(result.findings.map(item => item.kind), ["assertion-removed"]);
  }
});

test("ambiguous multiple replacements remain removal candidates instead of invented pairs", () => {
  const result = compare("assert.equal(x, 1); assert.equal(y, 2);", "assert.equal(y, 3); assert.equal(x, 4);");
  assert.deepEqual(result.findings.map(item => item.kind), ["assertion-removed", "assertion-removed"]);
});

test("unique concrete unittest matchers pair independently inside the same test", () => {
  const before = "class TestRevision:\n    def test_thresholds(self):\n        self.assertGreaterEqual(np.linalg.norm(before), 0.2)\n        self.assertGreater(np.linalg.norm(other), 0.1)\n";
  const after = before.replace("norm(before)", "norm(after)").replace("norm(other)", "norm(updated)");
  const result = compare(before, after, "test_revision.py");
  assert.deepEqual(result.findings.map(item => [item.kind, item.name]), [
    ["assertion-changed", "self.assertGreaterEqual"],
    ["assertion-changed", "self.assertGreater"],
  ]);
  assert.equal(result.findings[0].before, "self.assertGreaterEqual(np.linalg.norm(before), 0.2)");
  assert.equal(result.findings[0].after, "self.assertGreaterEqual(np.linalg.norm(after), 0.2)");
});

test("concrete JavaScript matchers pair before the remaining unique family fallback", () => {
  const before = "test('values', () => { assert.equal(x, 1); assert.deepEqual(y, [2]); assert.ok(z); });";
  const after = "test('values', () => { assert.equal(x, 3); assert.deepEqual(y, [4]); assert.strictEqual(z, true); });";
  const result = compare(before, after);
  assert.deepEqual(result.findings.map(item => item.kind), ["assertion-changed", "assertion-changed", "assertion-changed"]);
  assert.equal(result.findings[1].before, "assert.deepEqual(y, [2])");
  assert.equal(result.findings[2].after, "assert.strictEqual(z, true)");
});

test("readable assertion excerpts preserve exact literal contents and comparison keys", () => {
  const before = "assert.equal(value, 'x . y ( z )');";
  const after = "assert.equal(value, 'x.y(z)');";
  const result = compare(before, after);
  assert.equal(result.findings[0].before, "assert.equal(value, 'x . y ( z )')");
  assert.equal(result.findings[0].after, "assert.equal(value, 'x.y(z)')");
  assert.deepEqual(compare(before, "assert /* note */ . equal ( value , \"x . y ( z )\" );"), { findings: [], partial: false });
});

test("partial syntax never creates confident assertion deletions", () => {
  for (const [before, after, filePath] of [
    ["assert.equal(x, 1);", "assert.equal(", "sample.test.mjs"],
    ["def test_x():\n    assert x == 1\n", "def test_x():\n    assert (\n", "test_x.py"],
    ["def test_x():\n    assert x == 1\n", "def test_x():\n    assert x ==\n", "test_x.py"],
    ["x", "", "unknown.rs"],
  ]) {
    const result = compare(before, after, filePath);
    assert.equal(result.partial, true, filePath);
    assert.equal(result.findings.some(item => item.kind.startsWith("assertion-")), false, filePath);
  }
});

test("non-test source receives only export findings and empty files work", () => {
  assert.deepEqual(compare("assert.equal(x, 1);", "", "app.mjs", false), { findings: [], partial: false });
  assert.deepEqual(compare("", "assert.ok(true);"), { findings: [], partial: false });
});
