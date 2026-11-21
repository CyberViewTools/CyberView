import { test } from "node:test";
import assert from "node:assert/strict";
import { checkEventQuality, sharedSourceProblems, isListingPage, isSecondary, QUALITY_STRICT_FROM } from "../../scripts/lib/validate.mjs";

const ev = (o = {}) => ({
  id: "acme-breach-2026-11", title: "Acme confirms breach of 1,200 customer records", date: "2026-11-18", category: "incident", severity: 2, status: "confirmed",
  org: "Acme", summary: "Acme said attackers copied 1,200 customer records on November 17. The company has notified regulators.", impact: "1,200 records",
  exec: "Customer data exposure.", tags: ["data-breach"], cves: [], sources: [{ name: "Acme", url: "https://acme.example/news/security-notice" }, { name: "Reuters", url: "https://reuters.example/tech/acme-breach-2026-11-18/" }],
  source_tier: "primary", validation: { state: "corroborated", note: "Acme's notice and Reuters each state it" }, first_seen: "2026-11-21T08:00:00Z", updated_at: "2026-11-21T08:00:00Z", ...o,
});
const NOW = { now: Date.parse("2026-11-22T00:00:00Z") };   // after the fixture's first_seen, so it is not a future timestamp
const codes = (e) => checkEventQuality(e, NOW).map((x) => x.code);
const levelOf = (e, code) => (checkEventQuality(e, NOW).find((x) => x.code === code) || {}).level;

test("a clean event has no quality problems", () => {
  assert.deepEqual(checkEventQuality(ev(), NOW), []);
  assert.deepEqual(checkEventQuality(null), []);
});

test("date: more than 7 days before first_seen needs a date_note (error)", () => {
  assert.equal(levelOf(ev({ date: "2026-11-05" }), "old-date-no-note"), "error");
  assert.ok(!codes(ev({ date: "2026-11-05", date_note: "Attack on Nov 5; disclosed in a filing on Nov 20." })).includes("old-date-no-note"));
  assert.ok(!codes(ev({ date: "2026-11-15" })).includes("old-date-no-note"));
});

test("occurred_at: needs time_basis (error); a 12:00 or 00:00 UTC time looks like a placeholder (error, refused for new events)", () => {
  assert.equal(levelOf(ev({ occurred_at: "2026-11-17T20:35:00Z" }), "occurred-no-basis"), "error");
  assert.deepEqual(codes(ev({ occurred_at: "2026-11-17T20:35:00Z", time_basis: "occurred" })), []);
  assert.equal(levelOf(ev({ occurred_at: "2026-11-17T12:00:00Z", time_basis: "published" }), "occurred-placeholder"), "error");
  assert.equal(levelOf(ev({ occurred_at: "2026-11-17T00:00:00+00:00", time_basis: "occurred" }), "occurred-placeholder"), "error");
  assert.equal(levelOf(ev({ occurred_at: "2026-11-17T12:00:00.000Z", time_basis: "reported" }), "occurred-placeholder"), "error");
  assert.ok(!codes(ev({ occurred_at: "2026-11-17T12:00:00Z", time_basis: "approx" })).includes("occurred-placeholder"));
});

test("validation: corroborated with one publisher is an error unless the source is primary", () => {
  const one = { sources: [{ name: "Ynet", url: "https://ynetnews.example/article/abc123" }] };
  assert.equal(levelOf(ev({ ...one, source_tier: "established" }), "corroborated-one-host"), "error");
  assert.ok(!codes(ev({ ...one, source_tier: "established", validation: { state: "single_source" } })).includes("corroborated-one-host"));
  assert.ok(!codes(ev({ ...one, source_tier: "primary" })).includes("corroborated-one-host"));
});

test("status: confirmed resting only on trackers and roundups is an error", () => {
  const e = ev({ status: "confirmed", source_tier: "aggregator", validation: { state: "single_source" }, sources: [{ name: "SharkStriker", url: "https://sharkstriker.com/blog/data-breaches-in-november-2026/" }] });
  assert.equal(levelOf(e, "confirmed-on-secondary"), "error");
  assert.equal(levelOf({ ...e, status: "developing" }, "confirmed-on-secondary"), undefined);
  assert.equal(levelOf({ ...e, validation: { state: "corroborated" }, sources: [...e.sources, { name: "PG", url: "https://www.privacyguides.org/news/2026/11/13/data-breach-roundup/" }] }, "corroborated-on-secondary"), "error");
  assert.equal(levelOf({ ...e, source_tier: "established" }, "tier-secondary"), "warn");
  // a tracker next to the organisation's own notice is fine
  assert.equal(levelOf({ ...e, source_tier: "primary", sources: [...e.sources, { name: "Notice", url: "https://chowsangsang.example/notice/2026-11" }] }, "confirmed-on-secondary"), undefined);
  assert.equal(levelOf(ev({ source_tier: "aggregator", validation: { state: "single_source" }, sources: [{ name: "X", url: "https://news.example/a/b" }] }), "confirmed-on-aggregator"), "warn");
});

test("sources: tag, category, label and search pages are refused", () => {
  assert.ok(isListingPage("https://thehackernews.com/search/label/Vulnerability"));
  assert.ok(isListingPage("https://example.com/tag/ransomware/"));
  assert.ok(isListingPage("https://example.com/category/news/page/2/"));
  assert.ok(isListingPage("https://example.com/?s=acme"));
  assert.ok(!isListingPage("https://cloud.google.com/blog/topics/threat-intelligence/armory-castle-exploits-vsphere"));
  assert.ok(!isListingPage("https://www.boho.or.kr/kr/bbs/view.do?searchCnd=&bbsId=B0000133&searchWrd=&nttId=72314"));
  assert.equal(levelOf(ev({ sources: [{ name: "THN", url: "https://thehackernews.com/search/label/Vulnerability" }, ev().sources[0]] }), "listing-source"), "error");
});

test("secondary hosts are matched by host, subdomains included", () => {
  assert.ok(isSecondary("https://www.redpacketsecurity.com/x-ransomware-victim-acme/"));
  assert.ok(isSecondary("https://news.privacyguides.org/2026/11/roundup"));
  assert.ok(!isSecondary("https://www.bleepingcomputer.com/news/security/acme/"));
  assert.ok(!isSecondary("not a url"));
});

test("tags must be supported by the text", () => {
  assert.equal(levelOf(ev({ tags: ["zero-day"] }), "tag-unsupported"), "warn");
  assert.ok(!codes(ev({ tags: ["zero-day"], summary: "Google says the flaw was exploited before a patch was released." })).includes("tag-unsupported"));
  assert.equal(levelOf(ev({ tags: ["poc-public"] }), "tag-unsupported"), "warn");
  assert.ok(!codes(ev({ tags: ["poc-public"], summary: "Rapid7 published a proof of concept." })).includes("tag-unsupported"));
  assert.equal(levelOf(ev({ tags: ["supply-chain"] }), "tag-unsupported"), "warn");
});

test("an actor needs the summary to say who attributed it", () => {
  assert.equal(levelOf(ev({ actor: "APT29", summary: "APT29 broke into Acme and copied 1,200 records." }), "actor-unsourced"), "warn");
  assert.ok(!codes(ev({ actor: "APT29", summary: "According to Mandiant, APT29 was behind it." })).includes("actor-unsourced"));
  assert.ok(!codes(ev({ actor: "Qilin (claimed)" })).includes("actor-unsourced"));
});

test("every figure in title and exec appears in the summary or impact", () => {
  assert.equal(levelOf(ev({ title: "Acme breach hits 35,000 apps" }), "figure-not-in-summary"), "warn");
  assert.equal(levelOf(ev({ exec: "About 80 million raised." }), "figure-not-in-summary"), "warn");
  assert.ok(!codes(ev({ title: "Acme breach exposes 1,200 records" })).includes("figure-not-in-summary"));
  assert.ok(!codes(ev({ title: "Acme raises 80 million", summary: "Acme raised $80 million in a Series B." })).includes("figure-not-in-summary"));
  assert.ok(!codes(ev({ title: "Firefox 160 fixes CVE-2026-125350 in 2026" })).includes("figure-not-in-summary"));
});

test("shared source pages: same organisation means a possible duplicate; three or more events means a roundup", () => {
  const a = ev({ id: "atticus-a-2026-11", org: "Atticus", sources: [{ name: "Infobae", url: "https://www.infobae.com/x/atticus/" }] });
  const b = ev({ id: "atticus-b-2026-11", org: "Atticus", sources: [{ name: "Infobae", url: "http://infobae.com/x/atticus" }] });
  const r = (id, org) => ev({ id, org, sources: [{ name: "PG", url: "https://www.privacyguides.org/news/2026/11/13/data-breach-roundup" }] });
  const out = sharedSourceProblems([a, b, r("x-2026-11", "X"), r("y-2026-11", "Y"), r("z-2026-11", "Z"), { ...r("w-2026-11", "W"), duplicate_of: "z-2026-11" }]);
  assert.match(out.get("atticus-b-2026-11")[0].text, /atticus-a-2026-11/);
  assert.equal(out.get("atticus-b-2026-11")[0].code, "possible-duplicate");
  assert.equal(out.get("x-2026-11")[0].code, "roundup-source");
  assert.match(out.get("x-2026-11")[0].text, /2 other events/);   // the duplicate is not counted
  assert.ok(!out.has("w-2026-11"));
  // one government bulletin covering several flaws is not a roundup
  const g = (id) => ev({ id, org: id, sources: [{ name: "CISA", url: "https://www.cisa.gov/news-events/alerts/2026/11/18/cisa-adds-four" }] });
  assert.equal(sharedSourceProblems([g("p-2026-11"), g("q-2026-11"), g("s-2026-11")]).size, 0);
  assert.deepEqual([...sharedSourceProblems([a, b], ["atticus-a-2026-11"]).keys()], ["atticus-a-2026-11"]);
});

test("strict date is a full ISO time", () => {
  assert.match(QUALITY_STRICT_FROM, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
});

test("timestamps: first_seen or updated_at in the future is a warning; a date after first_seen is an error", () => {
  const now = Date.parse("2026-11-21T09:00:00Z");
  const q = (o) => checkEventQuality(ev(o), { now });
  assert.equal((q({ first_seen: "2026-11-21T12:00:00Z", updated_at: "2026-11-21T12:00:00Z" }).find((x) => x.code === "future-timestamp") || {}).level, "warn");
  assert.equal(q({ first_seen: "2026-11-21T09:05:00Z", updated_at: "2026-11-21T09:05:00Z" }).filter((x) => x.code === "future-timestamp").length, 0);   // a few minutes of clock skew
  assert.ok(!q({}).some((x) => x.code === "future-timestamp"));
  // visa-third-party-provider-incident-n0n-claim-2026-11: date 19 Nov, first seen 18 Nov 01:16 UTC
  assert.equal(levelOf(ev({ date: "2026-11-19", first_seen: "2026-11-18T01:16:00Z" }), "date-after-seen"), "error");
  // php-critical-security-release-announced-2026-11: first seen 18 Nov 23:11 UTC, already 19 Nov east of UTC: allowed
  assert.equal(levelOf(ev({ date: "2026-11-19", first_seen: "2026-11-18T23:11:53Z" }), "date-after-seen"), undefined);
});

test("figures keep the source's qualifier wherever they appear; plain may round with 'about' but never add a figure", () => {
  // hydro-quebec-espace-client-credential-stuffing-2026-11: the review corrected "about 2,500" against "nearly 2,500"
  assert.equal(levelOf(ev({ summary: "Hydro-Quebec said nearly 2,500 accounts were accessed.", exec: "About 2,500 accounts accessed." }), "figure-qualifier"), "warn");
  assert.equal(levelOf(ev({ summary: "Over 125 million SMS were exposed.", impact: "", title: "Acme exposes about 125 million SMS" }), "figure-qualifier"), "warn");
  assert.ok(!codes(ev({ summary: "Over 125 million SMS were exposed.", impact: "", title: "Acme exposes over 125 million SMS" })).includes("figure-qualifier"));
  assert.ok(!codes(ev({ plain: "Acme says about 1,200 records were copied.", summary: "Acme said attackers copied about 1,200 records." })).includes("figure-qualifier"));
  assert.equal(levelOf(ev({ plain: "Around 30,000 people may be affected." }), "figure-not-in-summary"), "warn");
  assert.ok(!codes(ev({ summary: "Acme said 341,234 patients were notified.", impact: "", title: "Acme breach", plain: "About 341,000 patients were told." })).includes("figure-not-in-summary"));
  assert.equal(levelOf(ev({ summary: "Acme said 341,234 patients were notified.", impact: "", title: "Acme breach", plain: "341,000 patients were told." }), "figure-not-in-summary"), "warn");
});

test("possible duplicates: one other event on the same page, same category, within 3 days; or the same victim within 3 days", () => {
  const a = ev({ id: "infoblox-sharepoint-2026-11", org: "Infoblox", date: "2026-11-18", sources: [{ name: "TC", url: "https://techcrunch.example/2026/11/18/infoblox/" }] });
  const b = ev({ id: "infoblox-vendor-2026-11", org: "Infoblox Inc.", date: "2026-11-19", sources: [{ name: "Reg", url: "https://register.example/2026/11/19/infoblox/" }] });
  assert.match((sharedSourceProblems([a, b]).get("infoblox-vendor-2026-11") || [])[0].text, /same organisation .* within 3 days as infoblox-sharepoint-2026-11/);
  // a publisher's own advisories are not duplicates of each other (vuln and report are left out of the same-organisation rule)
  const v = (id) => ev({ id, org: "Canadian Centre for Cyber Security", category: "vuln", date: "2026-11-18", sources: [{ name: "CCCS", url: `https://cyber.gc.ca/en/alerts-advisories/${id}` }] });
  assert.equal(sharedSourceProblems([v("av26-1166"), v("av26-1167")]).size, 0);
  // the same incident 5 days apart is a different event
  assert.equal(sharedSourceProblems([a, { ...b, date: "2026-11-24" }]).size, 0);
  // two records on one article, different organisation names, same category, a day apart
  const p = ev({ id: "atticus-nyc-retirees-2026-11", org: "Atticus Administration (for New York City retirees)", sources: [{ name: "Infobae", url: "https://infobae.example/2026/11/17/atticus/" }] });
  const q = ev({ id: "nyc-retirees-claims-2026-11", org: "NYC retirees claims database", date: "2026-11-17", sources: [{ name: "Infobae", url: "https://infobae.example/2026/11/17/atticus/" }] });
  assert.equal((sharedSourceProblems([p, q]).get("nyc-retirees-claims-2026-11") || [])[0].code, "possible-duplicate");
  // ...but not when the page is a government or CERT bulletin
  const gp = { ...p, sources: [{ name: "JPCERT", url: "https://www.jpcert.or.jp/at/2026/at260018.html" }] }, gq = { ...q, sources: gp.sources };
  assert.equal(sharedSourceProblems([gp, gq]).size, 0);
});

test("aliases: a short list of names is fine, anything else is flagged", () => {
  assert.ok(!codes(ev({ aliases: ["富岳", "理研"] })).includes("aliases-shape"));
  assert.ok(codes(ev({ aliases: "Fugaku" })).includes("aliases-shape"));
  assert.ok(codes(ev({ aliases: ["x".repeat(61)] })).includes("aliases-shape"));
});

test("old records are not blocked: errors apply only to events first seen from QUALITY_STRICT_FROM", () => {
  // the build and the validate.mjs CLI lower an error to a warning for an event first seen before the strict date
  const old = ev({ first_seen: "2026-11-19T08:00:00Z", updated_at: "2026-11-19T08:00:00Z", occurred_at: "2026-11-17T12:00:00Z", time_basis: "published" });
  assert.ok(String(old.first_seen) < QUALITY_STRICT_FROM);
  assert.ok(String(ev().first_seen) >= QUALITY_STRICT_FROM);
  assert.equal(levelOf(old, "occurred-placeholder"), "error");
});

test('"400+" is flagged: figures go in the source\'s own words (warning)', () => {
  assert.equal(levelOf(ev({ summary: "Acme said 400+ customers were affected on November 17." }), "figure-plus"), "warn");
  assert.equal(levelOf(ev({ title: "Acme breach hits 1,200+ customer records" }), "figure-plus"), "warn");
  assert.equal(levelOf(ev({ plain: "About 1.5 million+ people affected." }), "figure-plus"), "warn");
  assert.ok(!codes(ev({ summary: "Acme said more than 400 customers were affected. A C++ library was involved." })).includes("figure-plus"));
  assert.ok(!codes(ev({ action: "Update to version 10.3.27+ or later." })).includes("figure-plus"));   // a version number, not a count
});
