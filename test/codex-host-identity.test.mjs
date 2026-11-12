import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { detectInstalledHostBinaryVersion, detectRunningCodexHostVersion, validateSuppliedHostVersion } from "../src/hook-firewall.mjs";

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "bg-host-identity-"));
  const host = (name, version) => {
    const directory = path.join(root, name);
    fs.mkdirSync(directory);
    const binary = path.join(directory, "codex");
    fs.writeFileSync(binary, `#!/bin/sh\nprintf '%s\\n' 'codex-cli ${version}'\n`, { mode: 0o755 });
    return binary;
  };
  return { root, old: host("old", "0.154.0"), current: host("current", "0.167.0"),
    close: () => fs.rmSync(root, { recursive: true, force: true }) };
}

test("Codex hooks bind the nearest running image independently of PATH", () => {
  const f = fixture();
  const previousPath = process.env.PATH;
  try {
    for (const [nearest, other, accepted] of [[f.current, f.old, true], [f.old, f.current, false]]) {
      process.env.PATH = path.dirname(other);
      const records = new Map([
        [process.ppid, { executable: nearest, comm: other, ppid: 1234568 }],
        [1234568, { executable: other, ppid: 1 }],
      ]);
      const info = detectRunningCodexHostVersion({ cacheDir: f.root, _testProcessInspector: (pid) => records.get(pid) });
      assert.equal(info.found, true);
      assert.equal(info.binaryRealpath, fs.realpathSync.native(nearest));
      assert.equal(info.detectionSource, "running-parent");
      assert.equal(info.ancestorPid, process.ppid);
      assert.equal(validateSuppliedHostVersion("codex", info.rawVersion).ok, accepted);
    }
  } finally {
    if (previousPath === undefined) delete process.env.PATH;
    else process.env.PATH = previousPath;
    f.close();
  }
});

test("Codex hooks reject missing, forged, unreadable and cyclic ancestry without PATH fallback", () => {
  const f = fixture();
  const previousPath = process.env.PATH;
  try {
    process.env.PATH = path.dirname(f.current);
    const inspectors = [
      () => ({ executable: process.execPath, comm: f.current, ppid: 1 }),
      () => { throw new Error("process lookup denied"); },
      () => ({ executable: process.execPath, ppid: process.ppid }),
      () => ({ executable: f.current, ppid: NaN }),
      () => ({ executable: "codex", ppid: 1 }),
    ];
    for (const inspect of inspectors) {
      const info = detectRunningCodexHostVersion({ cacheDir: f.root, _testProcessInspector: inspect });
      assert.equal(info.found, false);
      assert.equal(validateSuppliedHostVersion("codex", info.rawVersion).ok, false);
    }
  } finally {
    if (previousPath === undefined) delete process.env.PATH;
    else process.env.PATH = previousPath;
    f.close();
  }
});

test("Codex hook identity ignores poisoned disk and memory version caches", () => {
  const f = fixture();
  try {
    const image = fs.realpathSync.native(f.old);
    const stat = fs.statSync(image);
    const key = `codex|${image}|${stat.dev}:${stat.ino}:${stat.mtimeMs}:${stat.size}`;
    fs.writeFileSync(path.join(f.root, "host-version-cache.json"), JSON.stringify({
      [key]: { rawVersion: "codex-cli 0.167.0", binarySha256: "untrusted-cache" },
    }));
    // Diagnostic lookup loads the deliberately forged record into both caches.
    const diagnostic = detectInstalledHostBinaryVersion("codex", { cacheDir: f.root, binaryPath: image });
    assert.equal(diagnostic.rawVersion, "codex-cli 0.167.0");
    const actual = detectRunningCodexHostVersion({
      cacheDir: f.root,
      _testProcessInspector: () => ({ executable: image, ppid: 1 }),
    });
    assert.equal(actual.rawVersion, "codex-cli 0.154.0");
    assert.equal(validateSuppliedHostVersion("codex", actual.rawVersion).ok, false);
  } finally {
    f.close();
  }
});

test("Deleted nearest Codex images fail closed before a supported outer ancestor", () => {
  const f = fixture();
  try {
    let inspectedOuter = false;
    const info = detectRunningCodexHostVersion({
      cacheDir: f.root,
      _testProcessInspector: (pid) => {
        if (pid === process.ppid) return { executable: `${f.old} (deleted)`, ppid: 1234567 };
        inspectedOuter = true;
        return { executable: f.current, ppid: 1 };
      },
    });
    assert.equal(info.found, false);
    assert.equal(inspectedOuter, false);
    assert.equal(validateSuppliedHostVersion("codex", info.rawVersion).ok, false);
  } finally {
    f.close();
  }
});

test("Renamed agents and interpreter parents cannot borrow an outer supported Codex", () => {
  const f = fixture();
  try {
    for (const executable of ["/opt/codex-legacy", "/opt/custom-agent", "/opt/node", "/opt/bash", process.execPath, "/usr/bin/python3", "/bin/sh"]) {
      let inspectedOuter = false;
      const info = detectRunningCodexHostVersion({
        cacheDir: f.root,
        _testProcessInspector: (pid) => {
          if (pid === process.ppid) return { executable, comm: f.current, ppid: 1234567 };
          inspectedOuter = true;
          return { executable: f.current, ppid: 1 };
        },
      });
      assert.equal(info.found, false, executable);
      assert.equal(inspectedOuter, false, executable);
    }
  } finally {
    f.close();
  }
});
