import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { persistSnapshotBlob } from "../src/snapshot-blob.mjs";

test("reflink or byte-copy snapshots preserve original bytes across later edits and concurrent capture", t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bg-snapshot-blob-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const original = Buffer.alloc(128 * 1024, 0x41);
  const hash = createHash("sha256").update(original).digest("hex");
  const live = path.join(dir, "source");
  const dest = path.join(dir, "store", hash);
  fs.writeFileSync(live, original);
  assert.ok(["reflink", "bytes"].includes(persistSnapshotBlob(live, dest, original, hash)));
  fs.writeFileSync(live, Buffer.alloc(original.length, 0x42));
  assert.deepEqual(fs.readFileSync(dest), original);
  assert.equal(fs.statSync(dest).mode & 0o777, 0o400);
  assert.equal(persistSnapshotBlob(live, path.join(dir, "store", "captured"), original, hash), "bytes");
  assert.deepEqual(fs.readFileSync(path.join(dir, "store", "captured")), original);
  assert.deepEqual(fs.readdirSync(path.dirname(dest)).sort(), [hash, "captured"].sort());
});
