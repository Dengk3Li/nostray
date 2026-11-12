import test from "node:test";
import assert from "node:assert/strict";
import {
  verifyEpistemicAndNumericAnchors,
  verifyMarkdownSectionConservation,
} from "../src/doc-conservation.mjs";
import { classifyIntent } from "../src/intent-and-budget.mjs";
import { evaluateCandidateWriteSet } from "../src/conservation-engine.mjs";

function evaluateMarkdown(before, after, prompt) {
  const task = classifyIntent(prompt);
  return evaluateCandidateWriteSet([{
    relPosix: "notes.md",
    changeType: "modify",
    commandBeforeText: before,
    taskBaselineText: before,
    afterText: after,
  }], { budget: task.budget, grants: task.grants, denySet: task.denySet, workingSet: new Set() });
}

test("complete HTTP domains, URL paths, queries and fragments remain citation anchors", () => {
  const destinations = [
    "https://example.com/report",
    "https://example.com/a.v1.pdf?q=study.2#results",
    "https://example.com/a(b)/report.pdf",
    "../reports/source.v1.md#results",
    "./data/report.pdf",
    "#source-details",
  ];
  for (const destination of destinations) {
    const before = `The estimate may improve according to [the study](${destination}).`;
    const after = before.replace(destination, destination.replace(/.$/, "X"));
    assert.equal(verifyEpistemicAndNumericAnchors(before, after).ok, false, destination);
    assert.equal(verifyEpistemicAndNumericAnchors(before, before.replace("the study", "the source")).ok, true, destination);
  }
});

test("bare URLs and angle autolinks retain full targets including ordinary periods", () => {
  for (const before of [
    "Details are available at https://example.com/source.pdf.",
    "Details are available at <https://example.com/source.pdf>.",
    "Details are available at [source](<../reports/source (final).pdf> \"Study title\").",
    "Details are available at [source](../reports/source\\(final\\).pdf 'Study title').",
    "Details are available at ![figure](images/chart.v1.png).",
  ]) {
    assert.equal(verifyEpistemicAndNumericAnchors(before, before.replace(/source|chart/g, "changed")).ok, false, before);
    assert.equal(verifyEpistemicAndNumericAnchors(before, before).ok, true, before);
  }
});

test("full, collapsed and shortcut references protect resolved destinations", () => {
  for (const usage of ["[the study][source]", "[source][]", "[source]"]) {
    const before = `The estimate may improve according to ${usage}.\n\n[source]: ../reports/source.v1.pdf \"Report\"\n`;
    assert.equal(verifyEpistemicAndNumericAnchors(before, before.replace("source.v1.pdf", "source.v2.pdf")).ok, false, usage);
    assert.equal(verifyEpistemicAndNumericAnchors(before, before.replace("may improve", "may increase")).ok, true, usage);
  }
  const before = "See [source][ Study   ID ].\n\n[study id]: https://example.com/report.pdf\n";
  assert.equal(verifyEpistemicAndNumericAnchors(before, before.replace("report.pdf", "other.pdf")).ok, false);
});

test("unchanged citations survive wording edits, while new independent citations are allowed", () => {
  const before = "A preliminary estimate may reach 5% according to [source](https://example.com/report.pdf).\n";
  const after = before.replace("estimate", "assessment") + "Additional context appears in [another report](../context.md).\n";
  assert.equal(verifyEpistemicAndNumericAnchors(before, after).ok, true);
  assert.equal(verifyEpistemicAndNumericAnchors("```md\n[source](https://example.com/old)\n```", "```md\n[source](https://example.com/new)\n```").ok, true);
});

test("section protection, local fact conservation and full rewrite authorization remain distinct", () => {
  const before = "---\ntitle: Study\n---\n# Allowed\nThe estimate may reach 5% according to [source](https://example.com/report.pdf).\n# Protected\nA separate verified statement remains.\n";
  const localPrompt = 'Update section "Allowed" in notes.md';
  const wording = before.replace("estimate", "assessment");
  assert.equal(evaluateMarkdown(before, wording, localPrompt).ok, true);
  for (const [label, after, code] of [
    ["number", before.replace("5%", "15%"), "EPISTEMIC_OR_NUMERIC_ANCHOR_MUTATED"],
    ["qualifier", before.replace("may reach", "will reach"), "EPISTEMIC_OR_NUMERIC_ANCHOR_MUTATED"],
    ["link", before.replace("report.pdf", "other.pdf"), "EPISTEMIC_OR_NUMERIC_ANCHOR_MUTATED"],
    ["protected section", before.replace("verified statement", "changed statement"), "NON_TARGET_SECTION_MUTATED"],
    ["frontmatter", before.replace("title: Study", "title: Changed"), "FRONTMATTER_MUTATED"],
  ]) {
    const result = evaluateMarkdown(before, after, localPrompt);
    assert.equal(result.ok, false, label);
    assert.equal(result.violations.some(item => item.code === code), true, label);
  }
  const rewrite = before.replace("5%", "15%").replace("may reach", "will reach").replace("report.pdf", "other.pdf").replace("verified statement", "changed statement");
  assert.equal(evaluateMarkdown(before, rewrite, "Rewrite the entire notes.md").ok, true);
});

test("a section grant alone preserves its complement while the combined engine preserves local anchors", () => {
  const before = "# Allowed\nThe estimate may reach 5%.\n# Protected\nKeep this paragraph.\n";
  const after = before.replace("5%", "15%");
  assert.equal(verifyMarkdownSectionConservation(before, after, { sectionTargets: ["Allowed"] }).ok, true);
  assert.equal(evaluateMarkdown(before, after, 'Update section "Allowed" in notes.md').ok, false);
});
