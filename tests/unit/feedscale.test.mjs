// The collector at ~2,500 feeds (scripts/collect.mjs): shard loading, dedupe, cadence, scheduling, per-host politeness and
// conditional GET; and the feed checker (scripts/feed-check.mjs) that every new feed passes. No network: fetch is stubbed.
import { test, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { loadFeedConfig, feedKey, extraFeeds, intervalMin, pickDue, runPolite, fetchFeed, EVERY_MIN } from "../../scripts/collect.mjs";
import { siteOf, robotsRules, robotsAllows, judgeItems, discover, shapeProblem } from "../../scripts/feed-check.mjs";

const realFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = realFetch; });
const NOW = Date.parse("2026-11-24T12:00:00Z");
const ago = (min) => new Date(NOW - min * 6e4).toISOString();

test("loadFeedConfig merges feeds.json with every shard; a shard's first_run_hours reaches its feeds; a broken shard is skipped", () => {
  const root = mkdtempSync(join(tmpdir(), "cv-feeds-"));
  mkdirSync(join(root, "config", "feeds.d"), { recursive: true });
  writeFileSync(join(root, "config", "feeds.json"), JSON.stringify({ retired: [{ name: "x" }], feeds: [{ name: "A", tier: "gov", url: "https://a.example/rss" }] }));
  writeFileSync(join(root, "config", "feeds.d", "b.json"), JSON.stringify({ first_run_hours: 3, feeds: [{ name: "B", tier: "news", url: "https://b.example/rss" }, { name: "C", tier: "news", url: "https://c.example/rss", first_run_hours: 12 }] }));
  writeFileSync(join(root, "config", "feeds.d", "broken.json"), "{ not json");
  writeFileSync(join(root, "config", "feeds.d", "notes.txt"), "ignored");
  const cfg = loadFeedConfig(root);
  assert.deepEqual(cfg.retired, [{ name: "x" }]);
  assert.deepEqual(cfg.feeds.map((f) => f.name), ["A", "B", "C"]);
  assert.equal(cfg.feeds[1].first_run_hours, 3);
  assert.equal(cfg.feeds[1].shard, "b");
  assert.equal(cfg.feeds[2].first_run_hours, 12, "a feed's own value wins");
  assert.equal(cfg.feeds[0].first_run_hours, undefined);
  assert.deepEqual(loadFeedConfig(mkdtempSync(join(tmpdir(), "cv-empty-"))).feeds, []);
});

test("feedKey: the same feed under www., http or a trailing slash is one feed; extraFeeds keeps the first", () => {
  assert.equal(feedKey("https://www.Example.org/feed/"), feedKey("http://example.org/feed"));
  assert.notEqual(feedKey("https://example.org/feed?cat=1"), feedKey("https://example.org/feed?cat=2"));
  const out = extraFeeds({ feeds: [
    { name: "One", tier: "news", url: "https://www.dup.example/feed/" },
    { name: "Two", tier: "news", url: "https://dup.example/feed" },
    { name: "one", tier: "news", url: "https://other.example/feed" },
    { name: "Bad tier", tier: "blog", url: "https://bad.example/feed" },
    { name: "Plain http", tier: "news", url: "http://plain.example/feed" },
  ] });
  assert.deepEqual(out.map((f) => f.name), ["One"]);
});

test("intervalMin: by tier, a feed's own every_minutes, and three times slower after three quiet days", () => {
  assert.equal(intervalMin({ tier: "gov" }, {}, NOW), EVERY_MIN.gov);
  assert.equal(intervalMin({ tier: "news" }, { last_lead_at: ago(60) }, NOW), EVERY_MIN.news);
  assert.equal(intervalMin({ tier: "news" }, { last_lead_at: ago(4 * 1440) }, NOW), EVERY_MIN.news * 3);
  assert.equal(intervalMin({ tier: "vendor" }, { first_ok: ago(5 * 1440) }, NOW), EVERY_MIN.vendor * 3, "never filed a lead since its first success");
  assert.equal(intervalMin({ tier: "news", every_minutes: 60 }, {}, NOW), 60);
  assert.equal(intervalMin({ tier: "unknown" }, null, NOW), 20);
});

test("pickDue: never-asked first, then the most overdue; not yet due and backing-off feeds wait", () => {
  const F = (name, tier = "news") => ({ name, tier, url: `https://${name}.example/rss` });
  const all = [F("fresh"), F("late"), F("later"), F("never"), F("failing"), F("gov", "gov")];
  const health = {
    fresh: { ok: true, at: ago(5) },
    late: { ok: true, at: ago(25) },
    later: { ok: true, at: ago(90) },
    failing: { ok: false, at: ago(60), next_try_at: new Date(NOW + 6e5).toISOString() },
    gov: { ok: true, at: ago(12) },
  };
  assert.deepEqual(pickDue(all, health, NOW).map((f) => f.name), ["never", "later", "late", "gov"]);
});

test("runPolite: one request at a time to any one host, many hosts at once, and nothing new after the deadline", async () => {
  const feeds = [];
  for (const h of ["a", "b", "c"]) for (let i = 0; i < 3; i++) feeds.push({ name: `${h}${i}`, url: `https://${h}.example/${i}` });
  const live = new Map(); let maxPerHost = 0, maxAll = 0, all = 0;
  const out = await runPolite(feeds, async (f) => {
    const h = new URL(f.url).hostname; live.set(h, (live.get(h) || 0) + 1); all++;
    maxPerHost = Math.max(maxPerHost, live.get(h)); maxAll = Math.max(maxAll, all);
    await new Promise((r) => setTimeout(r, 5));
    live.set(h, live.get(h) - 1); all--;
    return { items: [] };
  }, { width: 8 });
  assert.equal(out.length, 9);
  assert.equal(maxPerHost, 1);
  assert.equal(maxAll, 3);
  const late = await runPolite(feeds, async () => ({ items: [] }), { deadline: Date.now() - 1 });
  assert.equal(late.length, 0, "past the deadline nothing starts");
});

test("fetchFeed: sends the validators, a 304 is not modified, and a 200 returns the new validators", async () => {
  const seen = [];
  globalThis.fetch = async (u, o) => { seen.push(o.headers); return { status: 304, ok: false, text: async () => "" }; };
  assert.deepEqual(await fetchFeed({ url: "https://x.example/rss" }, { etag: '"v1"', lastmod: "Mon, 23 Nov 2026 10:00:00 GMT" }), { items: [], notModified: true });
  assert.equal(seen[0]["if-none-match"], '"v1"');
  assert.equal(seen[0]["if-modified-since"], "Mon, 23 Nov 2026 10:00:00 GMT");
  const RSS = '<rss><channel><item><title>t</title><link>https://x.example/a</link></item></channel></rss>';
  const hdr = { etag: '"v2"', "last-modified": "Tue, 24 Nov 2026 10:00:00 GMT" };
  globalThis.fetch = async (u, o) => { seen.push(o.headers); return { status: 200, ok: true, headers: { get: (k) => hdr[k] || null }, text: async () => RSS }; };
  const r = await fetchFeed({ url: "https://x.example/rss" });
  assert.equal(r.items.length, 1);
  assert.equal(r.etag, '"v2"');
  assert.equal(r.lastmod, hdr["last-modified"]);
  assert.equal(seen[1]["if-none-match"], undefined, "no validators on a first fetch");
  globalThis.fetch = async () => ({ status: 200, ok: true, headers: { get: (k) => (k === "content-length" ? "9000000" : null) }, text: async () => RSS });
  assert.match((await fetchFeed({ url: "https://x.example/rss" })).error, /5 MB/);
});

test("siteOf: the registrable site, including two-level country domains", () => {
  assert.equal(siteOf("https://news.bbc.co.uk/a"), "bbc.co.uk");
  assert.equal(siteOf("https://www.cert.br/docs"), "cert.br");
  assert.equal(siteOf("https://www.gov.br/anpd/x"), "www.gov.br", "gov.br is a public suffix");
  assert.equal(siteOf("https://cert.example.com/x"), "example.com");
  assert.equal(siteOf("not a url"), "");
});

test("robots.txt: the named group wins over *, longest rule wins, Allow wins a tie, wildcards and $ work", () => {
  const txt = "User-agent: *\nDisallow: /private\nAllow: /private/feed\n\nUser-agent: ClaudeBot\nUser-agent: GPTBot\nDisallow: /\n";
  assert.equal(robotsAllows(robotsRules(txt, "cyberview-collector"), "/private/feed.xml"), true);
  assert.equal(robotsAllows(robotsRules(txt, "cyberview-collector"), "/private/x"), false);
  assert.equal(robotsAllows(robotsRules(txt, "cyberview-collector"), "/rss"), true);
  assert.equal(robotsAllows(robotsRules(txt, "claudebot"), "/rss"), false);
  const w = robotsRules("User-agent: *\nDisallow: /*.xml$\nDisallow:\n", "x");
  assert.equal(robotsAllows(w, "/feed.xml"), false);
  assert.equal(robotsAllows(w, "/feed.xml?x=1"), true);
  assert.equal(robotsAllows(robotsRules("", "x"), "/anything"), true);
});

test("judgeItems: enough items, dated and recent, linking to the publisher's own site", () => {
  const it = (n, days, host = "pub.example") => Array.from({ length: n }, (_, i) => ({ title: `t${i}`, url: `https://${host}/${i}`, published: new Date(NOW - days * 864e5).toISOString() }));
  assert.match(judgeItems(it(2, 1), { tier: "news", now: NOW }).reason, /only 2/);
  assert.match(judgeItems(it(5, 40), { tier: "news", now: NOW }).reason, /over 30 days/);
  assert.equal(judgeItems(it(5, 40), { tier: "gov", now: NOW }).ok, true, "official feeds may be slower");
  assert.match(judgeItems(it(5, 1, "news.google.com"), { tier: "news", now: NOW }).reason, /aggregator/);
  const mixed = [...it(2, 1, "a.example"), ...it(2, 1, "b.example"), ...it(2, 1, "c.example")];
  assert.match(judgeItems(mixed, { tier: "news", now: NOW }).reason, /many different sites/);
  assert.match(judgeItems(it(4, 1).map((x) => ({ ...x, published: "" })), { tier: "news", now: NOW }).reason, /no dates/);
  const ok = judgeItems(it(6, 2), { tier: "news", now: NOW });
  assert.equal(ok.ok, true);
  assert.equal(ok.site, "pub.example");
});

test("discover: a page's announced RSS/Atom feeds, resolved, without comment feeds", () => {
  const html = '<head><link rel="alternate" type="application/rss+xml" href="/feed/"><link rel="alternate" type="application/rss+xml" href="/comments/feed/">'
    + '<link type="application/atom+xml" rel="alternate" href="https://cdn.example/atom.xml?a=1&amp;b=2"><link rel="stylesheet" href="/s.css"></head>';
  assert.deepEqual(discover(html, "https://site.example/news/"), ["https://site.example/feed/", "https://cdn.example/atom.xml?a=1&b=2"]);
});

test("shapeProblem: candidates must have a name, a tier, an ISO language, a known region and kind", () => {
  assert.equal(shapeProblem({ name: "X", tier: "news", lang: "fr", region: "europe" }), "");
  assert.match(shapeProblem({ name: "", tier: "news" }), /name/);
  assert.match(shapeProblem({ name: "X", tier: "blog" }), /tier/);
  assert.match(shapeProblem({ name: "X", tier: "news", lang: "fr-FR" }), /ISO/);
  assert.match(shapeProblem({ name: "X", tier: "news", region: "mars" }), /region/);
  assert.match(shapeProblem({ name: "X", tier: "news", kind: "blog" }), /kind/);
});
