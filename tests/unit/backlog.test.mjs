// The research backlog rules (scripts/backlog.mjs). Run: node --test tests/unit/
import test from "node:test";
import assert from "node:assert/strict";
import { story } from "../../scripts/fuse.mjs";
import { autoReason, backlog, summary, closeLines } from "../../scripts/backlog.mjs";

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

test("the age of the queue counts from the oldest lead still open, not from an old lead that was handled hours ago", () => {
  const handled = lead({ title: "Hospital hit by ransomware attack", seen_at: "2026-11-18T10:00:00Z", _open: false });
  const fresh = lead({ title: "Hospital hit by ransomware attack", url: "https://example.org/fresh", seen_at: "2026-11-19T01:40:00Z", _open: true });
  const s = mk([handled, fresh]);
  assert.equal(s.waiting_since, "2026-11-19T01:40:00Z");
  const sum = summary([s], NOW);
  assert.equal(sum.oldest_hours, 0); assert.equal(sum.oldest_incident_hours, 0);
  const old = mk([lead({ title: "Hospital hit by ransomware attack", seen_at: "2026-11-18T22:00:00Z" })]);
  assert.equal(summary([old], NOW).oldest_incident_hours, 4);
});

test("the single-source rule closes English headlines that report nothing, and never judges other languages or official sources", () => {
  assert.match(autoReason(mk([lead({ title: "Nvidia projects AI growth beyond 2027 despite CEO exit" })]), NOW), /single-source/);
  assert.equal(autoReason(mk([lead({ title: "Iran targeted US infrastructure with cyberattacks, Homeland Security chief says" })]), NOW), "");
  assert.equal(autoReason(mk([lead({ title: "New GitDoor backdoors turn GitHub into covert channels" })]), NOW), "");
  assert.equal(autoReason(mk([lead({ title: "Güneş enerjisi santrali hacklendi, 3 aydır çalışamıyor", lang: "tr" })]), NOW), "");
  assert.equal(autoReason(mk([lead({ title: "Quarterly notes from the national centre", lang: "ja" })]), NOW), "");
  assert.equal(autoReason(mk([lead({ title: "Notes on a new loader family", tier: "vendor", source: "Lab" })]), NOW), "");
  assert.equal(autoReason(mk(["A", "B"].map((s) => lead({ title: "Nvidia projects AI growth beyond 2027 despite CEO exit", source: s }))), NOW), "");
});

test("closing a story logs every still-open link, not the first 40 links (closures used to repeat forever)", () => {
  // 45 links already handled, then 5 still open: the old code logged the first 40 (all handled) and never closed the 5
  const handled = Array.from({ length: 45 }, (_, i) => lead({ title: "Acme confirms data breach", url: "https://example.org/h" + i, source: "P" + i, _open: false }));
  const open = Array.from({ length: 5 }, (_, i) => lead({ title: "Acme confirms data breach", url: "https://example.org/o" + i, source: "Q" + i }));
  const s = mk([...handled, ...open]);
  assert.equal(s.urls.length, 50);
  assert.deepEqual(s.open_urls, open.map((l) => l.url));
  const lines = closeLines([{ s, why: "already on file: acme-breach-2026-11" }]);
  assert.deepEqual(lines.map((l) => l.url), open.map((l) => l.url));
  assert.match(lines[0].reason, /^story \w+: already on file: acme-breach-2026-11$/);
  // a story without open_urls (an older plan file) still closes by all its links
  assert.equal(closeLines([{ s: { id: "x", title: "t", urls: ["https://a.example/1"] }, why: "w" }]).length, 1);
});
