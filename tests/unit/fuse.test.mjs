// Story ranking and the "reported, being checked" list (scripts/fuse.mjs). Run: node --test tests/unit/
import test from "node:test";
import assert from "node:assert/strict";
import { story, developing } from "../../scripts/fuse.mjs";

const NOW = Date.parse("2026-11-19T02:00:00Z");
const lead = (o) => ({ title: "x", url: "https://example.org/" + Math.random(), source: "Example", tier: "news", via: "rss", seen_at: "2026-11-19T01:30:00Z", published: "2026-11-19T01:00:00Z", lang: "en", region: "north-america", _open: true, ...o });

test("ranking: a fresh incident outranks an old bulletin met for the first time", () => {
  const fresh = story([lead({ title: "County hospital hit by ransomware attack, officials say", source: "A" }), lead({ title: "Ransomware attack disrupts county hospital", source: "B" })], [], NOW);
  const old = story([lead({ title: "Security update for Example Server", tier: "gov", source: "CERT", published: "2026-11-10T09:00:00Z" })], [], NOW);
  assert.ok(fresh.score > old.score + 8, `${fresh.score} vs ${old.score}`);
  assert.ok(old.why.includes("published more than six days ago"));
  assert.equal(fresh.incident, true);
});

test("ranking: a routine bulletin is marked down unless it reports exploitation", () => {
  const routine = story([lead({ title: "[NEU] [hoch] Example Router: Mehrere Schwachstellen", tier: "gov", source: "BSI", lang: "de" })], [], NOW);
  const hot = story([lead({ title: "Example Router: multiple vulnerabilities actively exploited", tier: "gov", source: "CERT" })], [], NOW);
  assert.equal(routine.routine, true); assert.equal(hot.routine, false);
  assert.ok(hot.score > routine.score);
});

test("ranking: commentary and undated posts earn no freshness or incident points", () => {
  const opinion = story([lead({ title: "If we are under cyber attack, would our government tell us?" })], [], NOW);
  assert.equal(opinion.explainer, true); assert.equal(opinion.incident, false);
  const undated = story([lead({ title: "The Nansh0u Campaign: hackers arsenal grows stronger", published: undefined })], [], NOW);
  assert.equal(undated.dated, false);
  assert.ok(!undated.why.some((w) => /published in the last/.test(w)));
});

test("being checked: only fresh, corroborated or official reports; never claims, database rows, commentary or redirects", () => {
  const mk = (leads) => story(leads, [], NOW);
  const good = mk([lead({ title: "City water utility confirms cyberattack", source: "A", url: "https://a.example/story" }), lead({ title: "Cyberattack on city water utility", source: "B", via: "google-news", url: "https://news.google.com/rss/articles/abc" })]);
  const claim = mk([lead({ title: "Acme listed by ransomware group", kind: "claim", source: "ransomwarelive" })]);
  const row = mk([lead({ title: "CVE-2026-1000 (CVSS 9.8): something", kind: "cve", tier: "gov", source: "NVD" })]);
  const single = mk([lead({ title: "Local firm hacked", source: "C" })]);
  const opinion = mk([lead({ title: "Why are so many outages happening?", source: "D" }), lead({ title: "Why are so many outages happening?", source: "E" })]);
  const stale = mk([lead({ title: "Bank confirms data breach", source: "F", published: "2026-11-16T00:00:00Z" }), lead({ title: "Data breach at bank", source: "G", published: "2026-11-16T00:00:00Z" })]);
  const out = developing([good, claim, row, single, opinion, stale], NOW);
  assert.deepEqual(out.map((x) => x.id), [good.id]);
  assert.equal(out[0].url, "https://a.example/story");   // the publisher's own page, never the search redirect
  assert.equal(out[0].publishers, 2);
  const onlyRedirect = mk([lead({ title: "Port operator confirms cyberattack", source: "H", url: "https://news.google.com/rss/articles/x" }), lead({ title: "Cyberattack at port operator", source: "I", url: "https://www.bing.com/news/apiclick.aspx?u=1" })]);
  assert.equal(developing([onlyRedirect], NOW)[0].url, "");
});

test("already on file: a retold incident matches by organisation plus shared words; a big vendor's name alone does not", async () => {
  const { matchEvent } = await import("../../scripts/triage.mjs");
  const evs = [{ id: "visa-third-party-2026-11", title: "Visa says incident was at an Asia Pacific third-party provider after gang lists it", org: "Visa", category: "incident" },
    { id: "ms-agent-pypi-2026-11", title: "Poisoned Microsoft Agent Framework releases on PyPI steal cloud credentials", org: "Microsoft", category: "incident" }];
  assert.equal((matchEvent("Visa confirms apparent cyberattack at third-party provider, gang claims hit", evs) || {}).id, "visa-third-party-2026-11");
  assert.equal(matchEvent("Microsoft confirms Exchange Online outage across Europe after update", evs), null);
  assert.equal(matchEvent("Regional bank discloses ransomware attack on loan systems", evs), null);
});
