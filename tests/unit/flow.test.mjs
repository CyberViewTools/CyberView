import { test } from "node:test";
import assert from "node:assert/strict";
import { flowAlive } from "../../scripts/run-job.mjs";

const now = Date.parse("2026-11-19T17:00:00Z"), up = () => true, down = () => false;
test("a loop with a live process and a recent heartbeat is alive", () => {
  assert.equal(flowAlive({ pid: 5, beat: "2026-11-19T16:55:00Z" }, now, up), true);
});
test("a stale heartbeat, a dead process or no lock means start a new loop", () => {
  assert.equal(flowAlive({ pid: 5, beat: "2026-11-19T16:40:00Z" }, now, up), false);
  assert.equal(flowAlive({ pid: 5, beat: "2026-11-19T16:59:00Z" }, now, down), false);
  assert.equal(flowAlive(null, now, up), false);
});
