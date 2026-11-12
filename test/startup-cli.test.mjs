import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const cli = fileURLToPath(new URL("../bin/blast-guard.mjs", import.meta.url));

test("The first run audits without installing hooks and exposes snapshot limits before editing", t => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "bg-startup-cli-"));
  t.after(() => fs.rmSync(temp, { recursive: true, force: true }));
  const workspace = path.join(temp, "workspace");
  const stateDir = path.join(temp, "state");
  fs.mkdirSync(workspace);
  const file = path.join(workspace, "app.js");
  fs.writeFileSync(file, "export const value = 1;\n");
  fs.writeFileSync(path.join(workspace, "package.json"), "{}\n");
  function run(args, expectedExit = 0) {
    const r = spawnSync(process.execPath, [cli, ...args], {
      cwd: workspace, env: { ...process.env, BLAST_GUARD_STATE_DIR: stateDir }, encoding: "utf8",
    });
    assert.equal(r.status, expectedExit, r.stderr + r.stdout);
    return r.stdout;
  }
  assert.match(run([]), /Contract samples.*package\.json/);
  const fresh = JSON.parse(run(["--host", "codex", "--json"])).readiness;
  assert.equal(fresh.snapshot.coverageComplete, true);
  assert.equal(fresh.hosts.codex.configState, "ABSENT");
  assert.equal(fresh.hosts.codex.observation, null);
  assert.equal(fresh.hosts.codex.shell.mode, "unconfirmed");
  assert.deepEqual(fs.readdirSync(workspace).sort(), ["app.js", "package.json"]);
  assert.equal(fs.existsSync(stateDir), false);

  run(["init", "--host", "codex"]);
  fs.mkdirSync(path.join(workspace, "素材"));
  const asset = path.join(workspace, "素材", "片段.bin");
  fs.closeSync(fs.openSync(asset, "w"));
  fs.truncateSync(asset, 17 * 1024 * 1024);
  const scoped = JSON.parse(run(["audit", ".", "--exclude-dir", "素材", "--host", "codex", "--json"]));
  const selected = scoped.readiness.hosts.codex;
  assert.equal(selected.configState, "VALID");
  assert.equal(selected.observation, null);
  assert.equal(selected.shell.mode, "hook-checkpoint");
  assert.equal(scoped.readiness.snapshot.coverageComplete, false);
  assert.deepEqual(scoped.readiness.snapshot.blockingFile, {
    kind: "file", path: "素材/片段.bin", sizeBytes: 17 * 1024 * 1024, limitBytes: 16 * 1024 * 1024,
  });
  assert.equal(fs.existsSync(stateDir), false);
  const firstTurn = run(["session", "start", "--host", "codex", "--prompt", "修复 app.js"], 1);
  for (const text of ["覆盖不完整", "素材/片段.bin", "17 MiB", "16 MiB", "尚未观察到启动钩子", "写后"]) {
    assert.ok(firstTurn.includes(text), firstTurn);
  }
  assert.equal(fs.readFileSync(file, "utf8"), "export const value = 1;\n");

  fs.unlinkSync(asset);
  run(["init", "--host", "codex", "--wrap-shell"]);
  const nextTurn = JSON.parse(run(["session", "start", "--host", "codex", "--json"]));
  assert.equal(nextTurn.coverageComplete, true);
  assert.equal(nextTurn.readiness.hosts.codex.shell.mode, "wrapped-checkpoint");
  assert.equal(nextTurn.readiness.hosts.codex.observation, null);
});
