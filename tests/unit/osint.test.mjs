import { test } from "node:test";
import assert from "node:assert/strict";
import { parseGoogleNews, parseBingNews, parseGdelt, parseHibp, parseEuvd, parseNvd, parseRansomwareLive, parseHn, parseStatuspage, parseGcp, parseRepoSearch, isAggregator, searchedRecently } from "../../scripts/osint.mjs";
import { cluster, story, keyTokens, countPublishers, cvesIn } from "../../scripts/fuse.mjs";
import { compute, regionOf } from "../../scripts/metrics.mjs";
import { extraFeeds, FEEDS } from "../../scripts/collect.mjs";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
const HERE = dirname(fileURLToPath(import.meta.url)), FIX = join(HERE, "..", "fixtures", "grid", "news");

const NOW = Date.parse("2026-11-18T22:00:00Z");
test("google news: publisher split from the headline, redirect link kept", () => {
  const xml = `<rss><channel><item><title>Oleada de ciberataques afecta a empresas - DW.com</title><link>https://news.google.com/rss/articles/ABC?oc=5</link><pubDate>Wed, 18 Nov 2026 10:00:00 GMT</pubDate><source url="https://www.dw.com">DW.com</source></item></channel></rss>`;
  assert.deepEqual(parseGoogleNews(xml), [{ title: "Oleada de ciberataques afecta a empresas", url: "https://news.google.com/rss/articles/ABC?oc=5", published: "2026-11-18T10:00:00Z", source: "DW.com", publisher_url: "https://www.dw.com" }]);
});
test("bing news: the real address is taken out of the redirect; unsafe ones dropped", () => {
  const xml = `<rss><channel><item><title>Bank hit</title><link>http://www.bing.com/news/apiclick.aspx?ref=x&amp;url=https%3a%2f%2fexample.com%2fnews%2fbank-hit&amp;c=1</link><pubDate>Wed, 18 Nov 2026 10:00:00 GMT</pubDate></item><item><title>Bad</title><link>http://www.bing.com/news/apiclick.aspx?url=javascript%3aalert(1)</link></item></channel></rss>`;
  const r = parseBingNews(xml);
  assert.equal(r.length, 1); assert.equal(r[0].url, "https://example.com/news/bank-hit"); assert.equal(r[0].source, "example.com");
});
test("gdelt, hibp, euvd, nvd rows become leads", () => {
  assert.deepEqual(parseGdelt({ articles: [{ url: "https://a.example/x", title: "Hospital attack", seendate: "20261118T101500Z", domain: "a.example", language: "Spanish", sourcecountry: "Mexico" }, { url: "ftp://x", title: "no" }] }),
    [{ title: "Hospital attack", url: "https://a.example/x", published: "2026-11-18T10:15:00Z", source: "a.example", lang: "es", country: "Mexico" }]);
  const h = parseHibp([{ Name: "Acme", Title: "Acme", PwnCount: 179745, BreachDate: "2026-11-12", AddedDate: "2026-11-13T05:41:32Z", IsVerified: true, DataClasses: ["Email addresses"] },
    { Name: "Old", Title: "Old", AddedDate: "2020-01-01T00:00:00Z", IsVerified: true }, { Name: "Fake", Title: "Fake", AddedDate: "2026-11-17T00:00:00Z", IsVerified: true, IsFabricated: true }], 7, NOW);
  assert.equal(h.length, 1); assert.equal(h[0].url, "https://haveibeenpwned.com/Breach/Acme"); assert.match(h[0].title, /179,745 accounts/);
  const e = parseEuvd([{ id: "EUVD-2026-118323", aliases: "CVE-2026-90436\n", baseScore: 9.8, description: "** UNSUPPORTED ** Deserialization flaw", exploitedSince: "Nov 17, 2026, 12:00:00 AM" }, { id: "bad" }]);
  assert.equal(e.length, 1); assert.match(e[0].title, /^CVE-2026-90436 \(CVSS 9\.8\): Deserialization flaw/); assert.equal(e[0].url, "https://euvd.enisa.europa.eu/vulnerability/EUVD-2026-118323");
  const n = parseNvd({ vulnerabilities: [{ cve: { id: "CVE-2026-1", published: "2026-11-18T01:00:00.000", descriptions: [{ lang: "en", value: "x" }] } }, { cve: { id: "CVE-2026-130583", published: "2026-11-18T01:00:00.000", descriptions: [{ lang: "en", value: "Auth bypass" }], metrics: { cvssMetricV40: [{ cvssData: { baseScore: 9.2 } }] } } }] });
  assert.equal(n.length, 1); assert.equal(n[0].title, "CVE-2026-130583 (CVSS 9.2): Auth bypass");
});
test("leak-site listings are marked as claims; old ones dropped", () => {
  const r = parseRansomwareLive([{ victim: "Jackson Walker", group: "SilentRansomGroup", country: "US", activity: "Legal", discovered: "2026-11-18T18:11:05+00:00", url: "https://www.ransomware.live/id/abc" },
    { victim: "Old Co", group: "g", discovered: "2026-11-01T00:00:00+00:00", url: "https://www.ransomware.live/id/old" }, { victim: "X", group: "g", discovered: "2026-11-18T18:00:00+00:00", url: "https://evil.example/x" }], 48, NOW);
  assert.equal(r.length, 1); assert.equal(r[0].kind, "claim"); assert.match(r[0].title, /^Claim: SilentRansomGroup lists Jackson Walker \(US\)/); assert.match(r[0].summary, /Unverified attacker claim/);
});
test("hacker news and status pages: only relevant, major items", () => {
  assert.equal(parseHn({ hits: [{ title: "Big ransomware attack on X", url: "https://a.example/1", points: 120, created_at: "2026-11-18T10:00:00Z" }, { title: "Show HN: my todo app", url: "https://a.example/2", points: 300 }, { title: "CVE-2026-1 exploit", url: "https://a.example/3", points: 5 }] }).length, 1);
  const s = parseStatuspage({ incidents: [{ name: "API down", impact: "major", status: "investigating", created_at: "2026-11-18T20:00:00Z", shortlink: "https://stspg.io/abc" }, { name: "blip", impact: "minor", created_at: "2026-11-18T20:00:00Z", shortlink: "https://stspg.io/def" }] }, "Cloudflare", 48, NOW);
  assert.equal(s.length, 1); assert.equal(s[0].kind, "status"); assert.match(s[0].summary, /an outage, not an attack/);
  assert.equal(parseGcp([{ id: "Xs2XTHzAVC", begin: "2026-11-18T06:00:00+00:00", external_desc: "Outage in europe-west2", status_impact: "SERVICE_OUTAGE", service_name: "Multiple" }, { id: "abcde", begin: "2026-11-18T06:00:00+00:00", status_impact: "SERVICE_INFORMATION", severity: "low" }], 48, NOW).length, 1);
});
test("exploit watch: only repositories that name the CVE, forks left out", () => {
  const r = parseRepoSearch({ items: [{ full_name: "a/CVE-2026-0322-poc", name: "CVE-2026-0322-poc", html_url: "https://github.com/a/CVE-2026-0322-poc", stargazers_count: 40, created_at: "2026-11-10T00:00:00Z" },
    { full_name: "b/notes", name: "notes", description: "misc", html_url: "https://github.com/b/notes" }, { full_name: "c/fork", name: "cve_2026_0322", fork: true, html_url: "https://github.com/c/fork" }] }, "CVE-2026-0322");
  assert.equal(r.repos, 1); assert.deepEqual(r.top[0], { name: "a/CVE-2026-0322-poc", url: "https://github.com/a/CVE-2026-0322-poc", stars: 40, created: "2026-11-10" });
});

const L = (title, source, o = {}) => ({ title, source, tier: "news", via: "rss", url: "https://x.example/" + Math.abs(hash(title + source)), seen_at: "2026-11-18T20:00:00Z", _open: true, ...o });
function hash(s) { let h = 0; for (const c of s) h = (h * 31 + c.charCodeAt(0)) | 0; return h; }
test("fusion: same story from different publishers is one story; generic words do not join stories", () => {
  const g = cluster([L("Cyberattack hits Norwegian energy giant Equinor, disrupting internal services", "The Record"), L("Equinor confirms cyberattack disrupted internal services in Norway", "Security Affairs"),
    L("Ransomware attack hits hospital in Ohio", "A"), L("Ransomware attack hits school district in Texas", "B"), L("Claim: Akira lists Equinor (NO) on its leak site", "ransomware.live", { kind: "claim" })]);
  const sizes = g.map((x) => x.length).sort();
  assert.deepEqual(sizes, [1, 1, 3]);
});
test("fusion: a shared CVE joins leads whatever the wording or language", () => {
  const g = cluster([L("CVE-2026-90436 (CVSS 9.8): Deserialization of an inbound SOAP fault in Apache Axis", "ENISA", { tier: "gov", kind: "exploited" }), L("Axis 1.x 원격 코드 실행 취약점 CVE-2026-90436 보안 권고", "KrCERT/CC", { tier: "gov", lang: "ko" }), L("Unrelated Fortinet patch", "X")]);
  assert.deepEqual(g.map((x) => x.length).sort(), [1, 2]);
  assert.deepEqual(cvesIn("fix for cve-2026-90436 and CVE-2026-1"), ["CVE-2026-90436"]);
});
test("fusion: publishers counted once; claims alone stay low; corroboration raises the score", () => {
  assert.deepEqual(countPublishers(["The Record", "therecord.media", "The Record from Recorded Future News", "BBC"]).sort(), ["bbc", "record"]);
  const now = Date.parse("2026-11-18T21:00:00Z");
  const claim = story([L("Claim: Akira lists Tiny Dental (US) on its leak site", "ransomware.live", { kind: "claim" })], [], now);
  assert.equal(claim.claim_only, true); assert.ok(claim.score <= 2);
  const one = story([L("Equinor confirms cyberattack", "Security Affairs")], [], now);
  const many = story([L("Equinor confirms cyberattack", "Security Affairs"), L("Cyberattack hits Equinor", "The Record"), L("Equinor attack advisory", "NCSC Norway", { tier: "gov" }), L("Equinor attack", "Reuters", { via: "google-news" })], [], now);
  assert.ok(many.score > one.score + 8); assert.equal(many.publishers, 4); assert.ok(many.why.some((w) => /government/.test(w)));
  const row = story([L("CVE-2026-130583 (CVSS 9.2): Magento extension flaw", "NIST NVD", { tier: "gov", kind: "cve" })], [], now);
  assert.ok(!row.why.some((w) => /government/.test(w)), "a bare database row is not an agency report");
  assert.ok(!keyTokens("Ransomware attack hits hospital").has("ransomware"));
});
test("fusion: a story already on file is linked to its event", () => {
  const s = story([L("Cyberattack hits Norwegian energy giant Equinor", "The Record")], [{ id: "equinor-attack-2026-11", title: "Cyberattack hits Norwegian energy giant Equinor", org: "Equinor", cves: [] }]);
  assert.equal(s.event, "equinor-attack-2026-11");
});

test("metrics: yield per source and collector, latency, regions", () => {
  const leads = [{ url: "https://a/1", source: "A", via: "rss", seen_at: "2026-11-18T10:00:00Z" }, { url: "https://a/2", source: "A", via: "rss", seen_at: "2026-11-18T10:00:00Z" }, { url: "https://g/1", source: "G", via: "google-news", seen_at: "2026-11-18T10:00:00Z" }];
  const m = compute(leads, [{ sources: [{ url: "https://a/1" }], first_seen: "2026-11-18T12:00:00Z", country: "Kenya", validation: { state: "single_source" } }, { sources: [{ url: "https://other" }], first_seen: "2026-11-18T12:00:00Z", country: "Atlantis" }], { "https://a/2": "not an event" });
  assert.equal(m.events_from_leads, 1); assert.equal(m.single_source, 1); assert.equal(m.median_hours_lead_to_event, 2);
  assert.deepEqual(m.regions, { africa: 1, other: 1 });
  assert.deepEqual(m.sources[0], { name: "A", leads: 2, used: 1, skipped: 1, yield: 50 });
  assert.equal(regionOf(""), "unplaced");
  // the countries and spellings events in the coverage gap regions use are placed, not counted as "other"
  for (const [c, r] of [["Türkiye", "middle-east"], ["Lebanon", "middle-east"], ["Uzbekistan", "middle-east"], ["Trinidad and Tobago", "latin-america"], ["Venezuela", "latin-america"],
    ["Côte d'Ivoire", "africa"], ["Mozambique", "africa"], ["US", "north-america"], ["Belgium", "europe"], ["North Korea", "east-asia"]]) assert.equal(regionOf(c), r, c);
});
test("extra feeds from config: https only, known tiers, no repeats", () => {
  const ok = extraFeeds({ feeds: [{ name: "New CERT", tier: "gov", url: "https://cert.example/rss" }, { name: "New CERT", tier: "gov", url: "https://cert.example/rss2" }, { name: "Bad", tier: "gov", url: "http://x.example/rss" },
    { name: "Bad tier", tier: "blog", url: "https://x.example/rss" }, { name: "Dup url", tier: "news", url: FEEDS[0].url }, null] });
  assert.deepEqual(ok.map((f) => f.name), ["New CERT"]);
  assert.deepEqual(extraFeeds(null), []);
});

// collectors (2026-11-20): Google News is not collected, Bing News asks every standing search in its own language
test("google news is not collected: robots.txt disallows /rss/ and its links are redirects that can never be cited", () => {
  const src = readFileSync(join(HERE, "..", "..", "scripts", "osint.mjs"), "utf8");
  assert.doesNotMatch(src, /news\.google\.com\/rss/);
  assert.doesNotMatch(src, /"google-news":\s*async/);
});
test("bing news: the publisher's name is kept from a real reply; aggregator copies are recognised", () => {
  const fr = parseBingNews(readFileSync(join(FIX, "bing-fr-fr.xml"), "utf8"), Date.parse("2026-11-20T12:00:00Z"));
  assert.ok(fr.length >= 5);
  assert.ok(fr.some((i) => i.publisher === "Le Monde"));
  assert.ok(fr.every((i) => typeof i.publisher === "string" && i.publisher.length <= 80 && !/&#|&amp;/.test(i.publisher)));
  const de = parseBingNews(readFileSync(join(FIX, "bing-de-de.xml"), "utf8"), Date.parse("2026-11-20T12:00:00Z"));
  const copies = de.filter((i) => isAggregator(i.url));
  assert.ok(copies.length >= 2 && copies.every((i) => /(^|\.)msn\.com$/.test(new URL(i.url).hostname)));
  assert.ok(de.some((i) => !isAggregator(i.url)));
  for (const u of ["https://www.msn.com/de-de/nachrichten/x", "https://finance.yahoo.com/news/x", "https://news.google.com/rss/articles/CBM", "https://news.yahoo.co.jp/articles/1", "not a url"]) assert.equal(isAggregator(u), true, u);
  for (const u of ["https://www.lemonde.fr/pixels/article/2026/11/19/x.html", "https://therecord.media/x", "https://www.yahoo-finance-fake.example/x"]) assert.equal(isAggregator(u), false, u);
});
test("search indexes are asked at most every 10 minutes; other collectors every run", () => {
  const now = Date.parse("2026-11-20T12:00:00Z");
  assert.equal(searchedRecently({ ok: true, at: "2026-11-20T11:55:00Z" }, "bing-news", now), true);
  assert.equal(searchedRecently({ ok: true, at: "2026-11-20T11:49:00Z" }, "bing-news", now), false);
  assert.equal(searchedRecently({ ok: false, at: "2026-11-20T11:59:00Z" }, "bing-news", now), false);   // a failed run is retried
  assert.equal(searchedRecently({ ok: true, at: "2026-11-20T11:59:00Z" }, "ransomware-live", now), false);
  assert.equal(searchedRecently(undefined, "gdelt", now), false);
});
test("gdelt: language names become the codes the backlog rules read", () => {
  const r = parseGdelt({ articles: [{ url: "https://a.example/1", title: "Bank hacked", seendate: "20261118T101500Z", language: "English" }, { url: "https://a.example/2", title: "Ataque", language: "Portuguese" }, { url: "https://a.example/3", title: "X", language: "Klingon" }] });
  assert.deepEqual(r.map((x) => x.lang), ["en", "pt", ""], "an unmapped language name is never passed on as a code");
});
