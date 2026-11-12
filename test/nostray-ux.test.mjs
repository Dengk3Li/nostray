import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { startUiServer } from "../src/ui-server.mjs";
import { SnapshotStore, executeWrappedCommand } from "../src/snapshot-store.mjs";
import { formatHumanInterceptionCard } from "../src/human-card.mjs";
import { validateSuppliedHostVersion } from "../src/hook-firewall.mjs";

test("release files contain no workstation identifiers or tracking codes", () => {
  const forbidden = new RegExp(["/Users/" + "zita", "AST" + "RA", "P[012]" + "-\\d", "WB-" + "\\d", "MUST-" + "\\d"].join("|"));
  function visit(p) {
    if (!fs.existsSync(p)) return;
    if (fs.statSync(p).isDirectory()) {
      for (const n of fs.readdirSync(p)) visit(path.join(p, n));
    } else {
      assert.doesNotMatch(fs.readFileSync(p, "utf8"), forbidden, p);
    }
  }
  for (const p of ["bin", "src", "test", "bench", "examples", "assets", "README.md", "README.zh-CN.md", "package.json", "LICENSE"]) {
    visit(p);
  }
});

test("demo executes all 5 cases including allowed controls and both doc-drift checks", () => {
  const r = spawnSync(process.execPath, ["bin/nostray.mjs", "demo", "--json"], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  const result = JSON.parse(r.stdout);
  assert.equal(result.results.length, 5);
  assert.ok(result.results.every((x) => x.passed));
  assert.ok(Array.isArray(result.timeline) && result.timeline.length >= 8);
  assert.ok(result.timeline.some((x) => x.status === "ALLOWED"));
  const docCase = result.results.find((x) => x.id === "doc-drift");
  assert.equal(docCase.numericDriftBlocked, true);
  assert.equal(docCase.qualifierDriftBlocked, true);
});

test("local studio endpoints, SQLite workspace session linkage, and path privacy", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nostray-ui-test-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

  fs.mkdirSync(path.join(dir, "test"), { recursive: true });
  fs.writeFileSync(path.join(dir, "test", "sample.test.mjs"), 'test("ok", () => {});\n');

  const store = new SnapshotStore(dir);
  await store.open();
  store.startOrUpdateTurn("Fix calculation bug", { sessionId: "live-ui-sess" });
  store.close();

  await executeWrappedCommand(
    dir,
    [process.execPath, "-e", 'require("node:fs").unlinkSync("test/sample.test.mjs")'],
    { mode: "checkpoint", sessionId: "live-ui-sess" }
  );

  const { server, port } = await startUiServer({ dir, port: 0 });
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const base = `http://127.0.0.1:${port}`;
  const html = await (await fetch(base)).text();
  assert.match(html, /NoStray Studio/);
  assert.match(html, /Unified Diff/);

  const stateText = await (await fetch(base + "/api/state")).text();
  assert.doesNotMatch(stateText, new RegExp(dir));
  const stateJson = JSON.parse(stateText);
  assert.equal(stateJson.workspace, path.basename(dir));
  assert.equal(stateJson.sqliteStoreDetected, true);
  assert.ok(stateJson.recordedSessions >= 1);
  assert.ok(stateJson.counters.filesRecovered >= 1);
  assert.ok(stateJson.events.some((e) => e.source === "workspace"));

  const demo = await (await fetch(base + "/api/demo", { method: "POST", body: '{"lang":"zh"}' })).json();
  assert.ok(demo.passed);
  assert.equal(demo.results.length, 5);

  const svg = await (await fetch(base + "/api/share-card.svg?lang=zh")).text();
  assert.match(svg, /<svg/);
  assert.ok(!svg.includes(dir));
});

test("human cards and explicit newer host override", () => {
  const v = [{ code: "PUBLIC_EXPORT_MUTATED", path: "src/a.mjs" }];
  assert.match(formatHumanInterceptionCard(v, { lang: "en" }), /blocked a stray edit/);
  assert.match(formatHumanInterceptionCard(v, { lang: "zh" }), /拦下了一次越界修改/);
  const old = process.env.NOSTRAY_ALLOW_NEWER_HOST;
  try {
    process.env.NOSTRAY_ALLOW_NEWER_HOST = "1";
    assert.equal(validateSuppliedHostVersion("codex", "999.0.0").warning, "UNVERIFIED_NEWER_HOST_VERSION");
    assert.equal(validateSuppliedHostVersion("codex", "0.0.1").ok, false);
  } finally {
    if (old === undefined) delete process.env.NOSTRAY_ALLOW_NEWER_HOST;
    else process.env.NOSTRAY_ALLOW_NEWER_HOST = old;
  }
});
