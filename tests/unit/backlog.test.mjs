// The research backlog rules (scripts/backlog.mjs). Run: node --test tests/unit/
import test from "node:test";
import assert from "node:assert/strict";
import { story } from "../../scripts/fuse.mjs";
import { autoReason, backlog, summary } from "../../scripts/backlog.mjs";

const NOW = Date.parse("2026-11-19T02:00:00Z");
const lead = (o) => ({ title: "x", url: "https://example.org/" + Math.random(), source: "Example", tier: "news", via: "rss", seen_at: "2026-11-19T01:30:00Z", published: "2026-11-19T01:00:00Z", lang: "en", region: "north-america", _open: true, ...o });
const mk = (leads) => story(leads, [], NOW);

test("rules close only what needs no reading: commentary, routine bulletins, database rows, week-old reports", () => {
  assert.match(autoReason(mk([lead({ title: "Why are so many outages happening?" })]), NOW), /commentary/);
  assert.match(autoReason(mk([lead({ title: "Security update for Example Server", tier: "vendor", source: "Vendor" })]), NOW), /routine/);
  assert.match(autoReason(mk([lead({ title: "CVE-2026-1000 (CVSS 7.1): something", kind: "cve", tier: "gov", source: "NVD" })]), NOW), /database row/);
  assert.match(autoReason(mk([lead({ title: "Bank confirms data breach", published: "2026-11-10T00:00:00Z" })]), NOW), /six days/);
});

test("rules never close an incident, an exploited flaw, a well-reported story or a leak-site claim", () => {
  assert.equal(autoReason(mk([lead({ title: "City water utility confirms cyberattack" })]), NOW), "");
  assert.equal(autoReason(mk([lead({ title: "Security update for Example Server fixes exploited flaw", kind: "exploited", tier: "gov", source: "CERT" })]), NOW), "");
  assert.equal(autoReason(mk(["A", "B", "C"].map((s) => lead({ title: "Why the Example outage happened", source: s }))), NOW), "");
  assert.equal(autoReason(mk([lead({ title: "Acme listed by ransomware group", kind: "claim", source: "ransomwarelive" })]), NOW), "");
});

test("the queue puts incidents first and the summary counts only what still needs a decision", () => {
  const inc = mk([lead({ title: "Hospital hit by ransomware attack" })]), adv = mk([lead({ title: "Researchers describe new loader used by a crime group", tier: "vendor", source: "Lab" })]);
  const noise = mk([lead({ title: "Nine steps to protect your money from a cyber attack" })]), claim = mk([lead({ title: "Acme listed", kind: "claim", source: "ransomwarelive" })]);
  const q = backlog([adv, noise, claim, inc], NOW);
  assert.deepEqual(q.map((s) => s.id), [inc.id, adv.id]);
  const s = summary([adv, noise, claim, inc], NOW);
  assert.equal(s.waiting, 2); assert.equal(s.incidents, 1); assert.equal(s.closable_by_rule, 1); assert.equal(s.claims, 1);
});
