// The causes of the slow tail in lead -> published -> reviewed (lane "speed", 2026-11-20), one behaviour per test.
import { test } from "node:test";
import assert from "node:assert/strict";
import { latency, startOf, addClosures } from "../../scripts/lib/latency.mjs";
import { leaderBlocks, hostId } from "../../scripts/lib/lease.mjs";
import { clampFuture, cronMinutes, flowDeadline } from "../../scripts/run-job.mjs";
import { order, reviewRecord, waitingSince, flagsFor, passBlockers } from "../../scripts/review.mjs";

const T = (s) => `2026-11-19T${s}:00Z`;

// ---- the metric ----
test("review speed counts the FIRST review, not a re-review after an update", () => {
  const seen = new Map([["https://a/1", T("10:00")]]);
  const ev = [{ id: "x", first_seen: T("10:05"), updated_at: T("18:00"), sources: [{ url: "https://a/1" }], review: { at: T("18:10"), first_at: T("10:12") } }];
  const r = latency(seen, ev, T("00:00"));
  assert.equal(r.review.p50, 12);
  assert.equal(r.rereview.n, 1); assert.equal(r.rereview.p50, 10, "update -> re-review is measured on its own");
});
test("an event reviewed before first_at existed still counts its review.at", () => {
  const r = latency(new Map([["https://a/1", T("10:00")]]), [{ id: "x", first_seen: T("10:05"), sources: [{ url: "https://a/1" }], review: { at: T("10:20") } }], T("00:00"));
  assert.equal(r.review.p50, 20);
});
test("a story closed by rule and reopened by new reporting is timed from the reopening lead; the plain figure is kept", () => {
  const seen = new Map([["https://n/1", T("19:48")], ["https://m/2", T("22:40")]]);
  const closures = new Map(), story = new Map();
  addClosures(closures, story, [
    JSON.stringify({ at: T("22:43"), story: "s", reason: "senate-hearing", urls: ["https://n/1", "https://m/2"] }),
  ].join("\n"), [{ finished_at: T("19:49"), skipped: [{ url: "https://n/1", reason: "a single-source item whose headline reports no incident" }] }], new Set(["senate-hearing"]));
  const e = { id: "senate-hearing", first_seen: T("22:43"), sources: [{ url: "https://n/1" }] };
  assert.deepEqual(story.get("senate-hearing"), ["https://n/1", "https://m/2"]);
  const s = startOf(e, seen, closures, story.get("senate-hearing"));
  assert.equal(s.reopened, true); assert.equal(s.t, T("22:40"));
  const r = latency(seen, [e], T("00:00"), closures, story);
  assert.equal(r.publish.p50, 3); assert.equal(r.publish_from_first_lead.p50, 175); assert.equal(r.reopened, 1);
});
test("a closure with no new lead after it never shortens the clock (a reversed decision is not hidden)", () => {
  const seen = new Map([["https://a/1", T("08:00")]]), closures = new Map([["https://a/1", [{ at: T("09:00"), reason: "not an event: niche" }]]]);
  const s = startOf({ id: "e", first_seen: T("20:00"), sources: [{ url: "https://a/1" }] }, seen, closures);
  assert.equal(s.reopened, false); assert.equal(s.t, T("08:00"));
});
test("the closure that made the event itself is not a reopening", () => {
  const seen = new Map([["https://a/1", T("08:00")]]), closures = new Map([["https://a/1", [{ at: T("08:09"), reason: "acme-breach-2026-11" }]]]);
  assert.equal(startOf({ id: "acme-breach-2026-11", first_seen: T("08:10"), sources: [{ url: "https://a/1" }] }, seen, closures).t, T("08:00"));
});

// ---- writing the real time ----
test("first_seen and updated_at ahead of the clock are set to now; past times are left alone", () => {
  const now = T("13:28");
  assert.deepEqual(clampFuture({ first_seen: T("13:40"), updated_at: T("13:40"), date: "2026-11-19" }, now), { first_seen: now, updated_at: now, date: "2026-11-19" });
  assert.equal(clampFuture({ first_seen: T("13:20"), updated_at: T("13:27") }, now), null);
  assert.equal(clampFuture(null, now), null);
});

// ---- the loop's hand-over ----
test("a dead loop of this same session does not block a restart; another session's lease does", () => {
  const mine = { run: "run-old", host: "sess-A", until: T("23:59") };
  assert.equal(leaderBlocks(mine, "run-new", "sess-A", false), false, "own loop, not running here: take over");
  assert.equal(leaderBlocks(mine, "run-new", "sess-A", true), true, "own loop still running: wait");
  assert.equal(leaderBlocks(mine, "run-new", "sess-B", false), true, "another session's loop: standby");
  assert.equal(leaderBlocks({ run: "run-old", until: T("23:59") }, "run-new", "sess-A", false), true, "no host recorded: respect it");
  assert.equal(leaderBlocks(null, "run-new", "sess-A", false), false);
  assert.equal(hostId({ CLAUDE_CODE_REMOTE_SESSION_ID: "abc" }), "abc"); assert.equal(hostId({}), "local");
});
test("the restart schedule's minutes are read from its cron", () => {
  assert.deepEqual(cronMinutes("5,20,35,50 * * * *"), [5, 20, 35, 50]);
  assert.deepEqual(cronMinutes("*/15 * * * *"), [0, 15, 30, 45]);
  assert.equal(cronMinutes("5 9 * * *"), null); assert.equal(cronMinutes(""), null);
});
test("the loop ends a minute before the last restart schedule inside its life, never later than its life", () => {
  const t0 = Date.parse(T("23:21")), life = 100 * 6e4, ticks = [5, 20, 35, 50];
  assert.equal(new Date(flowDeadline(t0, life, ticks)).toISOString(), "2026-11-20T00:49:00.000Z");   // hard end 01:01; last tick inside 00:50
  assert.equal(flowDeadline(t0, life, null), t0 + life);
  assert.equal(flowDeadline(t0, 5 * 6e4, ticks), t0 + 5 * 6e4, "no tick inside a short life: the life decides");
  assert.ok(flowDeadline(t0, life, ticks) <= t0 + life);
});

// ---- the review queue ----
test("events waiting over 20 minutes are reviewed first, oldest first; the rest by risk", () => {
  const now = Date.parse(T("12:00"));
  const it = (id, fs, risk) => ({ e: { id, first_seen: fs }, risk });
  const q = order([it("fresh-high", T("11:55"), 40), it("old-low", T("10:00"), 10), it("older-low", T("09:00"), 10), it("fresh-low", T("11:50"), 10)], now).map((x) => x.e.id);
  assert.deepEqual(q, ["older-low", "old-low", "fresh-high", "fresh-low"]);
  assert.equal(waitingSince({ first_seen: T("09:00"), updated_at: T("11:00"), review: { at: T("10:00") } }), T("11:00"), "a reviewed event waits from its change");
});
test("the first review time is kept through re-reviews", () => {
  assert.deepEqual(reviewRecord(null, "passed", T("10:00"), "checked", []), { state: "passed", at: T("10:00"), first_at: T("10:00"), note: "checked", flags: [] });
  assert.equal(reviewRecord({ at: T("10:00") }, "corrected", T("18:00"), "fixed", []).first_at, T("10:00"));
  assert.equal(reviewRecord({ at: T("18:00"), first_at: T("10:00") }, "passed", T("20:00"), "ok", []).first_at, T("10:00"));
});

// ---- quality flags in the review (requested by the quality lane) ----
const ev = (o = {}) => ({ id: "acme-breach-2026-11", title: "Acme confirms breach", org: "Acme", date: "2026-11-18", first_seen: "2026-11-18T10:00:00Z", category: "incident", severity: 2, status: "confirmed",
  summary: "Acme said attackers copied a database.", plain: "p", exec: "x", action: "a", lat: 1, lng: 1, country: "Canada", source_tier: "primary", validation: { state: "single_source" }, cves: [],
  sources: [{ url: "https://acme.example/news/statement" }], ...o });
test("the build's event-quality findings appear among the review flags", () => {
  const codes = flagsFor(ev({ status: "confirmed", source_tier: "aggregator", sources: [{ url: "https://ransomware.live/id/abc" }] }), [], "2026-11-18").map((f) => f.code);
  assert.ok(codes.includes("confirmed-on-secondary"));
  assert.ok(flagsFor(ev({ sources: [{ url: "https://news.example/tag/ransomware/" }] }), [], "2026-11-18").some((f) => f.code === "listing-source"));
});
test("a page shared with another event about the same organisation is flagged as a possible duplicate", () => {
  const other = { id: "acme-data-access-2026-11", title: "Hackers reached Acme files", org: "Acme", cves: [], sources: [{ url: "https://acme.example/news/statement" }] };
  const f = flagsFor(ev(), [other], "2026-11-18").filter((x) => x.code === "possible-duplicate");
  assert.equal(f.length, 1, "raised once"); assert.match(f[0].text, /acme-data-access/);
});
test("a pass is refused while a tracker-only confirmation, one-host corroboration or listing page remains", () => {
  assert.deepEqual(passBlockers(["confirmed-on-secondary", "number-check", "corroborated-one-host", "listing-source"]), ["confirmed-on-secondary", "corroborated-one-host", "listing-source"]);
  assert.deepEqual(passBlockers(["number-check", "actor-unsourced"]), []);
});
