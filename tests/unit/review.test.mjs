import { test } from "node:test";
import assert from "node:assert/strict";
import { flagsFor, needsReview, risk, order, planBatches } from "../../scripts/review.mjs";

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
