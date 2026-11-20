// The research loop's usage rules (lane "loop", 2026-11-20): what each budget level may start, gap searchers, idle
// backoff, and one loop at a time (the older loop keeps the lead; one container cannot start two).
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { workAt, overdueOnly, gapCount, idleWaitMs, flowAlive, mixWork } from "../../scripts/run-job.mjs";
import { yieldsTo, takeLock, leaderOf } from "../../scripts/lib/lease.mjs";
import { urgent } from "../../scripts/sweep-plan.mjs";

const NOW = Date.parse("2026-11-20T12:00:00Z"), iso = (ms) => new Date(ms).toISOString().replace(/\.\d+Z$/, "Z");

test("ok starts everything; tight only urgent research and overdue review; stop starts no worker", () => {
  const ok = workAt("ok"), tight = workAt("tight"), stop = workAt("stop");
  assert.ok(Object.entries(ok).filter(([k]) => !/_only$/.test(k)).every(([, v]) => v === true));
  assert.equal(ok.urgent_only, false); assert.equal(ok.overdue_only, false);
  assert.deepEqual([tight.researchers, tight.urgent_only, tight.reviewers, tight.overdue_only], [true, true, true, true]);
  assert.deepEqual([tight.updaters, tight.grid, tight.outage, tight.followup, tight.gap, tight.moderator], [false, false, false, false, false, false]);
  assert.ok(Object.entries(stop).filter(([k]) => !/_only$/.test(k)).every(([, v]) => v === false));
  assert.deepEqual(workAt("anything else"), ok);
});

test("tight research takes only stories that read like incidents or exploited flaws", () => {
  assert.equal(urgent({ incident: true, kinds: [] }), true);
  assert.equal(urgent({ incident: false, kinds: ["exploited"] }), true);
  assert.equal(urgent({ incident: false, kinds: ["cve"] }), false);
  assert.equal(urgent(null), false);
});

test("tight review keeps only events waiting longer than 20 minutes", () => {
  const ev = (id, minAgo, reviewed) => [id, { id, first_seen: iso(NOW - minAgo * 6e4), updated_at: iso(NOW - minAgo * 6e4), ...(reviewed ? { review: { at: iso(NOW - 600 * 6e4) } } : {}) }];
  const byId = new Map([ev("a", 25), ev("b", 5), ev("c", 45, true), ev("d", 21)]);
  assert.deepEqual(overdueOnly([["a", "b"], ["c"], ["b"], ["d", "x"]], byId, NOW), [["a"], ["c"], ["d"]]);
});

test("gap searchers: once per gap_every_minutes, spare ones only while the window has room, none when tight or stopped", () => {
  const sc = { gap_workers: 1, gap_every_minutes: 60, gap_spare_workers: 1, gap_spare_below_pct: 50 };
  assert.equal(gapCount(NOW, NOW - 61 * 6e4, sc, { level: "ok", window_pct: 60 }), 1);
  assert.equal(gapCount(NOW, NOW - 61 * 6e4, sc, { level: "ok", window_pct: 30 }), 2);
  assert.equal(gapCount(NOW, NOW - 59 * 6e4, sc, { level: "ok", window_pct: 30 }), 0, "not due yet");
  assert.equal(gapCount(NOW, 0, sc, { level: "tight", window_pct: 85 }), 0);
  assert.equal(gapCount(NOW, 0, sc, { level: "stop", window_pct: 0 }), 0);
  assert.equal(gapCount(NOW, 0, { ...sc, gap_pass: false }, { level: "ok", window_pct: 0 }), 0);
  assert.equal(gapCount(NOW, 0, { gap_workers: 5, gap_spare_workers: 5, gap_spare_below_pct: 90 }, { level: "ok", window_pct: 0 }), 3, "never more than 3");
  assert.equal(gapCount(NOW, NOW - 31 * 6e4, {}, { level: "ok", window_pct: 0 }), 1, "old config: every 30 minutes, one searcher");
});

test("idle backoff: 4, 8, 12 minutes after 0, 1, 2+ idle cycles; reset by work; never under the base cycle", () => {
  const base = 4 * 6e4;
  assert.deepEqual([0, 1, 2, 3, 9].map((s) => idleWaitMs(s, base, [4, 8, 12]) / 6e4), [4, 8, 12, 12, 12]);
  assert.equal(idleWaitMs(0, 6 * 6e4, [4, 8, 12]), 6 * 6e4);
  assert.equal(idleWaitMs(1, base, undefined), 8 * 6e4, "default steps");
});

// ---- one loop at a time ----
const lease = (run, since, minLeft = 15) => ({ "flow:leader": { run, until: iso(NOW + minLeft * 6e4), host: "h", ...(since ? { since } : {}) } });
test("two loops that both think they lead agree on which one gives way: the older keeps the lead", () => {
  const A = { run: "run-20261120T0235-20224", since: "2026-11-20T02:36:00Z" }, B = { run: "run-20261120T0412-206", since: "2026-11-20T04:13:00Z" };
  // B (newer) sees A's lease: B gives way
  assert.equal(yieldsTo(lease(A.run, A.since), B.run, B.since, NOW).run, A.run);
  // A sees B's lease (B's renewal won the merge): A keeps going and renews over it
  assert.equal(yieldsTo(lease(B.run, B.since), A.run, A.since, NOW), null);
  // its own lease, an expired lease or none: nothing to give way to
  assert.equal(yieldsTo(lease(A.run, A.since), A.run, A.since, NOW), null);
  assert.equal(yieldsTo(lease(A.run, A.since, -1), B.run, B.since, NOW), null);
  assert.equal(yieldsTo({}, B.run, B.since, NOW), null);
  // same start second: the smaller run id keeps it, on both sides
  assert.ok(yieldsTo(lease("run-a", "2026-11-20T04:13:00Z"), "run-b", "2026-11-20T04:13:00Z", NOW));
  assert.equal(yieldsTo(lease("run-b", "2026-11-20T04:13:00Z"), "run-a", "2026-11-20T04:13:00Z", NOW), null);
  // a lease written by code before this check (no since) never gives way itself, so the new loop does
  assert.ok(yieldsTo(lease("run-old"), B.run, B.since, NOW));
});

test("replayed 2026-11-20 04:12: a second loop started on a stale view now stops within its first cycle", () => {
  // what the newer loop's local leases.json held after its first commit merged origin (A renewed at 04:10:54)
  const merged = { "flow:leader": { run: "run-20261120T0235-20224", until: "2026-11-20T04:30:54Z", host: "cse_A", cycle: 23 } };
  const t = Date.parse("2026-11-20T04:16:00Z");
  assert.ok(leaderOf(merged, t), "the older lease was live the whole time");
  assert.equal(yieldsTo(merged, "run-20261120T0412-206", "2026-11-20T04:13:00Z", t).run, "run-20261120T0235-20224");
});

test("one container cannot start two loops: the lock is taken atomically, a dead loop's lock is replaced", () => {
  const dir = mkdtempSync(join(tmpdir(), "cv-lock-")), f = join(dir, "flow.json");
  const alive = (l) => flowAlive(l, Date.now(), (p) => p === process.pid);
  assert.equal(takeLock(f, alive, { note: "starting" }), true);
  assert.equal(JSON.parse(readFileSync(f, "utf8")).pid, process.pid);
  assert.equal(takeLock(f, alive), false, "a second start while the first is still probing the web");
  writeFileSync(f, JSON.stringify({ pid: 999999, beat: new Date().toISOString() }));
  assert.equal(takeLock(f, alive), true, "the loop that held it is gone");
  writeFileSync(f, JSON.stringify({ pid: process.pid, beat: "2026-01-01T00:00:00Z" }));
  assert.equal(takeLock(f, alive), true, "a lock with no heartbeat for 12 minutes is stale");
  assert.ok(existsSync(f));
});

test("reviewers are not held behind a full research queue: reviewer 1 starts first, then they alternate", () => {
  const R = (n) => Array.from({ length: n }, (_, i) => ["researcher", i + 1]), V = (n) => Array.from({ length: n }, (_, i) => ["reviewer", i + 1]);
  const w = mixWork(R(6), V(4));
  assert.equal(w.length, 10);
  assert.deepEqual(w[0], ["reviewer", 1], "the newest events' reviewer is in the first wave");
  assert.equal(w.slice(0, 6).filter((x) => x[0] === "reviewer").length, 3, "with 6 slots, half go to reviewers while both queues are full");
  assert.deepEqual(mixWork(R(2), []), R(2));
  assert.deepEqual(mixWork([], V(3)), V(3));
  assert.deepEqual(mixWork([], []), []);
});
