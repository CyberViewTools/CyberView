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

// 24 November: the launcher killed every bounded flow before its commit (6 minutes of collecting, then the workers);
// the hard stop (FLOW_HARD_AT) now bounds the collectors and the workers so the commit fits.
test("workerLimitMs: a worker never runs past the hard stop, but always gets 30 s", async () => {
  const { workerLimitMs } = await import("../../scripts/run-job.mjs");
  assert.equal(workerLimitMs(20 * 6e4, Infinity), 20 * 6e4);
  assert.equal(workerLimitMs(20 * 6e4, 3 * 6e4), 3 * 6e4);
  assert.equal(workerLimitMs(20 * 6e4, 5000), 30000);
});
test("collectorMs: network collectors share only the time left above the floor", async () => {
  const { collectorMs } = await import("../../scripts/run-job.mjs");
  assert.equal(collectorMs(Infinity, 3e5), 300000);                // no hard stop: the usual 5 minutes
  assert.equal(collectorMs(7 * 6e4, 5 * 6e4), 2 * 6e4);            // 7 left, 5 kept for the work: 2 minutes
  assert.equal(collectorMs(5 * 6e4 + 10000, 5 * 6e4), 0);          // under 20 s above the floor: skipped
  assert.equal(collectorMs(30 * 6e4, 5 * 6e4, 120000), 120000);    // never over its own limit
});

test("leaveCollectToActions: under a hard stop, a fresh collection is left to collect.yml", async () => {
  const { leaveCollectToActions } = await import("../../scripts/run-job.mjs");
  const now = Date.parse("2026-11-25T17:06:00Z");
  assert.equal(leaveCollectToActions(9 * 6e4, "2026-11-25T16:45:00Z", 25, now), true);     // 21 min old: left to Actions
  assert.equal(leaveCollectToActions(9 * 6e4, "2026-11-25T16:30:00Z", 25, now), false);    // 36 min old: collect here
  assert.equal(leaveCollectToActions(Infinity, "2026-11-25T17:00:00Z", 25, now), false);   // no hard stop: always collect
  assert.equal(leaveCollectToActions(9 * 6e4, undefined, 25, now), false);                 // never collected: collect here
  assert.equal(leaveCollectToActions(9 * 6e4, "2026-11-25T17:00:00Z", 0, now), false);     // 0 turns it off
  assert.equal(leaveCollectToActions(9 * 6e4, "2026-11-25T17:30:00Z", 25, now), false);    // a stamp in the future is not trusted
});
test("minStartMs: a worker starts only with time to finish before the hard stop", async () => {
  const { minStartMs } = await import("../../scripts/run-job.mjs");
  assert.equal(minStartMs("researcher"), 4 * 6e4);
  assert.equal(minStartMs("researcher-deep"), 4 * 6e4);
  assert.equal(minStartMs("reviewer"), 150000);
  assert.equal(minStartMs("updater-deep"), 150000);
  assert.equal(minStartMs("claims"), 90000);
  assert.equal(minStartMs(undefined), 90000);
});
