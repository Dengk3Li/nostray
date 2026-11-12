import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { auditRepository, renderFirstRunSummary, renderAuditTerminalCard } from "../src/repo-auditor.mjs";

test("history compares committed blobs, separates initial imports and reports findings even below the scoring threshold", async t => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "bg-history-"));
  t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const repo = path.join(tmp, "repo");
  fs.mkdirSync(repo);
  const git = (...args) => execFileSync("git", ["-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
    "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", ...args], { cwd: repo, encoding: "utf8" });
  git("init", "-q");
  const oldName = "模块(旧).mjs";
  const testName = "示例.test.mjs";
  const file = path.join(repo, oldName);
  fs.writeFileSync(file, "export function keep(x) { return x; }\nexport function removed() { return 1; }\n");
  fs.writeFileSync(path.join(repo, testName), "import assert from 'node:assert/strict';\nassert.equal(1, 1);\n");
  git("add", "."); git("commit", "-qm", "initial import");
  let h = (await auditRepository(repo)).historicalHygiene;
  assert.equal(h.initialImports.length, 1);
  assert.equal(h.flaggedCommitCount, 0);
  assert.equal(h.comparedCommits, 0);
  fs.writeFileSync(file, "export function keep(x) { return x; }\n");
  fs.writeFileSync(path.join(repo, testName), "import assert from 'node:assert/strict';\n");
  git("add", "."); git("commit", "-qm", "update module");
  // An uncommitted change must never be passed off as historical evidence.
  fs.writeFileSync(file, "export function different() {}\n");
  const report = await auditRepository(repo);
  h = report.historicalHygiene;
  assert.equal(h.score, null);
  assert.equal(h.flaggedCommitCount, 1);
  assert.ok(h.reviewCandidates[0].findings.some(f => f.path === oldName && f.name === "removed"));
  assert.ok(h.reviewCandidates[0].findings.some(f => f.path === testName && f.kind === "assertion-removed"));
  for (const output of [renderFirstRunSummary(report, { lang: "zh" }), renderAuditTerminalCard(report, { useColor: false, lang: "zh" })]) {
    assert.match(output, /移除公开导出 removed/);
    assert.match(output, /原断言不再出现/);
    assert.doesNotMatch(output, /different/);
  }
  git("restore", oldName);
  git("mv", oldName, "新名字.mjs"); git("commit", "-qm", "rename module");
  h = (await auditRepository(repo)).historicalHygiene;
  assert.equal(h.flaggedCommitCount, 1);
  // A shallow tip can look parentless in git log. Only the commit object establishes a true root.
  const clone = path.join(tmp, "shallow");
  git("clone", "-q", "--depth=1", new URL("file://" + repo).href, clone);
  h = (await auditRepository(clone)).historicalHygiene;
  assert.equal(h.initialImports.length, 0);
  assert.equal(h.shallowBoundaries, 1);
});
