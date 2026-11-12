import test from "node:test";
import assert from "node:assert/strict";
import { runSyntheticAdapterWireProbe } from "../src/init-installer.mjs";

test("Codex adapter self-test is synthetic and independent of running-host ancestry", async () => {
  const result = await runSyntheticAdapterWireProbe("codex");
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.synthetic, true);
  assert.equal(result.validationScope, "adapter-protocol-only");
  assert.equal(result.realHostVerified, false);
});
