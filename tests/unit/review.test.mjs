import { test } from "node:test";
import assert from "node:assert/strict";
import { flagsFor, needsReview, inReviewWindow, risk, order, planBatches, tier, groupByTier } from "../../scripts/review.mjs";

const base = (o = {}) => ({ id: "acme-breach-2026-11", title: "Acme confirms breach of customer database", org: "Acme", date: "2026-11-18", first_seen: "2026-11-18T10:00:00Z", category: "incident", severity: 2, status: "confirmed",
  summary: "Acme said attackers copied a customer database. The company confirmed 4,200,000 records were taken.", plain: "p", exec: "x", action: "Acme advises customers to reset their passwords.", records_affected: 4200000, lat: 1, lng: 1, country: "Canada",
  sources: [{ name: "Acme", url: "https://acme.example/news/statement" }, { name: "Reuters", url: "https://reuters.example/tech/acme-breach" }], source_tier: "primary", validation: { state: "corroborated", note: "Acme and Reuters" }, cves: [], ...o });
const codes = (e, evs) => flagsFor(e, evs, "2026-11-18").map((f) => f.code);

test("a clean, well-sourced event has no flags", () => { assert.deepEqual(codes(base()), []); });
test("source problems are flagged", () => {
  assert.ok(codes(base({ sources: [{ url: "https://news.google.com/rss/articles/ABC" }] })).includes("redirect-source"));
  assert.ok(codes(base({ sources: [{ url: "https://acme.example/" }] })).includes("front-page-source"));
  assert.ok(codes(base({ sources: [] })).includes("no-source"));
  assert.ok(codes(base({ severity: 3, sources: [{ url: "https://one.example/a" }], source_tier: "established", validation: { state: "single_source" } })).includes("single-source-high"));
  assert.ok(codes(base({ sources: [{ url: "https://one.example/a" }, { url: "https://one.example/b" }], source_tier: "established" })).includes("corroborated-one-host"));
});
test("claims, outages and actors are held to the rules", () => {
  assert.ok(codes(base({ status: "claimed", severity: 2, validation: { state: "unconfirmed_claim" } })).includes("claim-severity"));
  assert.ok(codes(base({ status: "claimed", severity: 1 })).includes("claim-corroborated"));
  assert.ok(codes(base({ category: "outage", title: "Bank outage after cyberattack", summary: "Services were down for hours after a cyberattack." })).includes("outage-as-attack"));
  assert.ok(!codes(base({ category: "outage", title: "Bank outage", summary: "Services were down. Cyber cause: ruled out by the bank." })).includes("outage-as-attack"));
  assert.ok(codes(base({ actor: "Scattered Spider", summary: "Attackers copied a database of 4,200,000 records." })).includes("actor-unsourced"));
  assert.ok(!codes(base({ actor: "Scattered Spider", summary: "The FBI attributed it to Scattered Spider; 4,200,000 records." })).includes("actor-unsourced"));
});
test("numbers, dates and severity reasons are checked", () => {
  assert.ok(codes(base({ records_affected: 9900000 })).includes("number-check"));
  assert.ok(codes(base({ date: "2026-11-01" })).includes("old-date"));
  assert.ok(!codes(base({ date: "2026-11-01", date_note: "disclosed later" })).includes("old-date"));
  assert.ok(codes(base({ date: "2026-12-25" })).includes("future-date"));
  assert.ok(codes(base({ category: "vuln", severity: 3, title: "Flaw in Acme Widget", summary: "A flaw was fixed.", action: "Update.", cves: ["CVE-2026-1234"], cve_meta: [{ id: "CVE-2026-1234" }] })).includes("severity-3-reason"));
  assert.ok(codes(base({ cves: ["CVE-26-1"] })).includes("bad-cve"));
  assert.ok(codes(base({ plain: "" })).includes("missing-plain"));
});
test("a likely duplicate is pointed out", () => {
  const other = { id: "acme-database-breach-2026-11", title: "Acme confirms breach of its customer database", org: "Acme", cves: [], category: "incident" };
  assert.ok(flagsFor(base(), [other]).some((f) => f.code === "possible-duplicate" && /acme-database-breach/.test(f.text)));
  assert.ok(!flagsFor(base(), [{ id: "zeta-outage-2026-11", title: "Zeta cloud outage in Europe", org: "Zeta", cves: [] }]).some((f) => f.code === "possible-duplicate"));
});
test("review is needed for new events and for ones changed after their review", () => {
  assert.equal(needsReview(base()), true);
  assert.equal(needsReview(base({ review: { state: "passed", at: "2026-11-18T12:00:00Z" }, updated_at: "2026-11-18T11:00:00Z" })), false);
  assert.equal(needsReview(base({ review: { state: "passed", at: "2026-11-18T12:00:00Z" }, updated_at: "2026-11-18T15:00:00Z" })), true);
  assert.equal(needsReview(base({ review: { state: "passed", at: "2026-11-18T12:00:00Z" }, updated_at: "2026-11-18T12:00:05Z" })), false, "the review's own save does not re-queue it");
  assert.equal(needsReview(base({ duplicate_of: "x-y-z" })), false);
  assert.ok(risk(base({ severity: 3 }), [{ code: "redirect-source" }]) > risk(base({ severity: 3 }), []));
});

test("review plan: with two or more reviewers the first takes the newest events, the rest the oldest first", () => {
  const now = Date.parse("2026-11-20T18:00:00Z");
  const waiting = (n) => order(Array.from({ length: n }, (_, i) => ({ e: { id: `e${i}`, first_seen: new Date(now - (1 + i * 10) * 6e4).toISOString() }, risk: 0 })), now);
  // 40 events waiting from 17:59 back to 11:30 (10 minutes apart): a long tail of old ones and two published this cycle
  const items = waiting(40), b = planBatches(items, 4, 12);
  assert.equal(b.length, 4);
  assert.deepEqual(b[0].slice(-2), ["e1", "e0"], "the events published in the last cycle are in the first reviewer's batch");
  assert.ok(b.every((x) => x.length && x.length <= 12));
  assert.ok(b.slice(1).flat().includes("e39"), "the oldest event is still taken");
  assert.equal(new Set(b.flat()).size, 40, "every event once");
  // more waiting than the reviewers can take: the newest and the oldest are both reviewed, the middle waits
  const m = planBatches(waiting(100), 4, 12).flat();
  assert.equal(m.length, 48);
  assert.ok(m.includes("e0") && m.includes("e99"));
  // one reviewer, or too few events for two: queue order (overdue first, oldest first)
  assert.deepEqual(planBatches(items.slice(0, 3), 4, 12), [items.slice(0, 3).map((x) => x.e.id)]);
  assert.deepEqual(planBatches(items, 1, 5), [items.slice(0, 5).map((x) => x.e.id)]);
  assert.deepEqual(planBatches([], 4, 12), []);
});

test("the review window follows the clock needsReview uses, so a changed old event is re-reviewed", () => {
  const now = Date.parse("2026-11-23T12:00:00Z"), at = (h) => new Date(now - h * 36e5).toISOString(), d = (n) => at(n * 24);
  // first published 5 days ago, reviewed 4 days ago, changed an hour ago: waiting again, so it is in the window (this was invisible to the planner)
  const changed = base({ first_seen: d(5), updated_at: at(1), review: { at: d(4) } });
  assert.equal(needsReview(changed), true); assert.equal(inReviewWindow(changed, now), true);
  // reviewed after its last change: nothing to do
  const done = base({ first_seen: d(5), updated_at: d(4), review: { at: d(3) } });
  assert.equal(needsReview(done), false); assert.equal(inReviewWindow(done, now), false);
  // never reviewed and genuinely old: the 3-day horizon still applies
  assert.equal(inReviewWindow(base({ first_seen: d(10), updated_at: d(10) }), now), false);
  // never reviewed, just published
  assert.equal(inReviewWindow(base({ first_seen: at(1), updated_at: at(1) }), now), true);
  // duplicates are never queued
  assert.equal(inReviewWindow(base({ first_seen: at(1), updated_at: at(1), duplicate_of: "other-2026-11" }), now), false);
});

test("writersFrom reads events_updated, and errorReport leaves pre-logging events out of the writer table", async () => {
  const { writersFrom, errorReport } = await import("../../scripts/review.mjs");
  const logs = [{ at: "2026-11-18T08:00:00Z", job: "sweep-r1", model: "claude-sonnet-5-5", added: ["a-2026-11"] }, { at: "2026-11-19T09:00:00Z", job: "feeds", model: "claude-haiku-5", events_updated: ["b-2026-11", { id: "c-2026-11" }] }];
  const w = writersFrom(logs);
  assert.equal(w.logStart, "2026-11-18T08:00:00Z"); assert.equal(w.get("b-2026-11").how, "events_updated"); assert.equal(w.get("c-2026-11").model, "haiku");
  const at = "2026-11-20T12:00:00Z", rev = (id, first_seen, state) => ({ id, first_seen, review: { state, at, note: "x", categories: state === "corrected" ? ["figure"] : undefined } });
  const events = [rev("a-2026-11", "2026-11-18T08:05:00Z", "corrected"), rev("old1-2026-11", "2026-11-17T20:00:00Z", "corrected"), rev("old2-2026-11", "2026-11-18T07:00:00Z", "passed"), rev("late-2026-11", "2026-11-19T20:00:00Z", "passed")];
  const r = errorReport(events, w, Date.parse("2026-11-21T00:00:00Z"), 7);
  // headline numbers keep every reviewed event; the two pre-logging ones are counted apart, the unlogged late one stays "unknown"
  assert.deepEqual([r.reviewed, r.corrected], [4, 2]);
  assert.deepEqual(r.pre_logging, { before: "2026-11-18T08:00:00Z", reviewed: 2, corrected: 1, flagged: 0, corrected_pct: 50 });
  assert.deepEqual(r.by_writer.map((b) => `${b.role}/${b.model}/${b.reviewed}`).sort(), ["researcher/sonnet/1", "unknown/unknown/1"]);
});

test("queue tiers: severity 3 is critical; exploited, patch-immediately or claimed is high; the rest routine", () => {
  assert.equal(tier(base({ severity: 3 })), "critical");
  assert.equal(tier(base({ severity: 2, title: "Flaw in Widget", summary: "Vendor says it is being exploited in the wild.", action: "Update." })), "high");
  assert.equal(tier(base({ severity: 2, action: "Patch immediately." })), "high");
  assert.equal(tier(base({ severity: 2, cve_meta: [{ id: "CVE-2026-1", kev: true }] })), "high");
  assert.equal(tier(base({ severity: 1, status: "claimed" })), "high");
  assert.equal(tier(base({ severity: 2 })), "routine");
  assert.equal(tier(base({ severity: 3, status: "claimed" })), "critical", "the highest tier that applies");
});
test("queue grouping: counts per tier, queue order kept inside each group, every row in exactly one group", () => {
  const rows = [base({ id: "r1", severity: 2 }), base({ id: "c1", severity: 3 }), base({ id: "h1", severity: 1, status: "claimed" }), base({ id: "c2", severity: 3 })].map((e) => ({ e }));
  const { groups, counts } = groupByTier(rows);
  assert.deepEqual(counts, { critical: 2, high: 1, routine: 1 });
  assert.deepEqual(groups.critical.map((x) => x.e.id), ["c1", "c2"], "queue order kept inside the tier");
  assert.equal(Object.values(counts).reduce((a, b) => a + b, 0), rows.length);
});
test("tier first, with an overdue share: a routine event waiting over 20 minutes is not starved by higher tiers", () => {
  const now = Date.parse("2026-11-24T12:00:00Z"), ago = (m) => new Date(now - m * 6e4).toISOString();
  const crit = Array.from({ length: 9 }, (_, i) => ({ e: { id: `c${i}`, severity: 3, first_seen: ago(5 + i) }, risk: 0 }));   // fresh critical
  const routineOld = Array.from({ length: 3 }, (_, i) => ({ e: { id: `r${i}`, severity: 1, first_seen: ago(60 + i) }, risk: 0 })); // overdue routine
  const items = [...routineOld, ...crit];
  const ids = order(items, now, 3).map((x) => x.e.id);
  assert.equal(ids.length, 12); assert.equal(new Set(ids).size, 12, "every event once");
  // slots 3, 6 and 9 (1-based) are the overdue share: the three overdue routine events each get one
  assert.deepEqual([ids[2], ids[5], ids[8]], ["r2", "r1", "r0"], "the oldest overdue first");
  assert.ok(ids.indexOf("r2") < 3, "an overdue routine event is placed within the first 3 slots");
  // without the share (every 0), tier order holds: the routine events come last
  assert.deepEqual(order(items, now, 0).map((x) => x.e.id).slice(-3), ["r2", "r1", "r0"]);
  // the critical tier still leads the queue
  assert.equal(order(items, now, 3)[0].e.id, "c8");
});
test("tier order: critical before high before routine, overdue first inside a tier", () => {
  const now = Date.parse("2026-11-24T12:00:00Z"), ago = (m) => new Date(now - m * 6e4).toISOString();
  const items = [
    { e: { id: "routine-new", severity: 1, first_seen: ago(1) }, risk: 0 },
    { e: { id: "high", severity: 1, status: "claimed", first_seen: ago(2) }, risk: 0 },
    { e: { id: "crit", severity: 3, first_seen: ago(3) }, risk: 0 },
  ];
  assert.deepEqual(order(items, now, 0).map((x) => x.e.id), ["crit", "high", "routine-new"]);
});
test("skip: an event reviewed after its last change is not queued again; a change after the review queues it", () => {
  const at = "2026-11-18T12:00:00Z";
  assert.equal(needsReview(base({ severity: 3, review: { state: "passed", at }, updated_at: "2026-11-18T11:59:00Z" })), false);
  assert.equal(needsReview(base({ severity: 3, review: { state: "passed", at }, updated_at: "2026-11-18T13:00:00Z" })), true);
});
