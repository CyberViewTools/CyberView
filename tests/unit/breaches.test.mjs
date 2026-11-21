// Official breach notification registers (scripts/breaches.mjs): parsers, dedupe, and how fuse and the backlog rules treat the leads.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parseCalifornia, parseWashington, parseIowa, parseIco, parseSec, orgKey, usDate, fresh, askedRecently, secContact, KIND } from "../../scripts/breaches.mjs";
import { cluster, story, developing, keyTokens } from "../../scripts/fuse.mjs";
import { autoReason } from "../../scripts/backlog.mjs";

const FIX = join(dirname(fileURLToPath(import.meta.url)), "..", "fixtures", "breaches"), fx = (f) => readFileSync(join(FIX, f), "utf8");
const NOW = Date.parse("2026-11-21T12:00:00Z");

test("dates and organisation keys", () => {
  assert.equal(usDate("11/20/2026"), "2026-11-20T00:00:00Z");
  assert.equal(usDate("1-6-2026"), "2026-01-06T00:00:00Z");
  assert.equal(usDate("Date Reported"), "");
  assert.equal(usDate("13/40/2026"), "");
  assert.equal(orgKey("Uber Technologies, Inc."), "uber technologies");
  assert.equal(orgKey("Uber Technologies, Inc"), orgKey("Uber Technologies Inc."));
  assert.equal(orgKey("Kern Medical, owned by Kern County (\"Kern Medical\")"), "kern medical owned by kern county");
  assert.equal(orgKey("Mercadien, P.C. CPAs"), "mercadien cpas");
});

test("California: each notice with its own page on the register, only oag.ca.gov links", () => {
  const r = parseCalifornia(fx("ca-list.html"));
  assert.equal(r.length, 3);
  assert.deepEqual({ ...r[0], summary: undefined }, { kind: KIND, tier: "gov", lang: "en", org: "OPN Healthcare, Inc.", url: "https://oag.ca.gov/ecrime/databreach/reports/sb24-633250", published: "2026-11-20T00:00:00Z",
    source: "California Attorney General", country: "US", title: "OPN Healthcare, Inc.: data breach notification filed with California's Attorney General", summary: undefined });
  assert.match(r[0].summary, /date\(s\) of breach: 06\/03\/2026/);
  assert.doesNotMatch(r[2].summary, /date\(s\) of breach/, "no breach date given: none invented");
  assert.equal(r[2].org, "Mercadien, P.C. CPAs");
});

test("Washington open data: cause and figures from the row; theft or mistakes and rows without an id left out", () => {
  const r = parseWashington(JSON.parse(fx("wa.json")));
  assert.deepEqual(r.map((x) => x.org), ["Prism Medical Products, LLC", "Dexcom, Inc.", "Telecare Health"]);
  assert.equal(r[1].url, "https://data.wa.gov/resource/sb4j-ca4h.json?id=26284");
  assert.equal(r[1].published, "2026-11-13T00:00:00Z");
  assert.match(r[1].title, /\(Cyberattack: phishing\)$/);
  assert.match(r[0].summary, /Washingtonians affected: 16,307\./);
  assert.match(r[2].title, /\(Cyberattack\)$/, "an attack type of 'Other' is not repeated");
  assert.equal(parseWashington({ error: true }).length, 0);
});

test("Iowa: the notice letter the Attorney General posted; the page's template card is skipped", () => {
  const r = parseIowa(fx("ia-2026.html"));
  assert.equal(r.length, 2);
  assert.equal(r[1].url, "https://www.iowaattorneygeneral.gov/media/cms/11102026_Uber_Technologies_Inc_089721E61CBAB.pdf");
  assert.equal(r[1].published, "2026-11-10T00:00:00Z");
  assert.match(r[0].summary, /Sector: Professional Services\./);
});

test("ICO: cyber and data security actions only, one per action, ICO pages only", () => {
  const r = parseIco(JSON.parse(fx("ico.json")));
  assert.equal(r.length, 1, "marketing calls, FOI, a duplicate penalty notice and a foreign link are left out");
  assert.equal(r[0].url, "https://ico.org.uk/action-weve-taken/enforcement/2026/10/ogi-networks-limited/");
  assert.equal(r[0].country, "GB");
  assert.match(r[0].title, /^ICO reprimand: Ogi Networks Limited: Welsh organisation reprimanded after cyber-attack/);
  assert.equal(r[0].published, "2026-10-19T18:59:03Z");
});

test("SEC: Item 1.05 filings only, the filing's own EDGAR address; idle without a project contact address", () => {
  const r = parseSec(JSON.parse(fx("sec-efts.json")));
  assert.equal(r.length, 1);
  assert.equal(r[0].url, "https://www.sec.gov/Archives/edgar/data/12345/000119312526401234/d901234d8k.htm");
  assert.equal(r[0].org, "Example Holdings Corp  (EXHC)".replace(/\s+/g, " "));
  assert.match(r[0].title, /Item 1\.05, material cybersecurity incident/);
  assert.equal(secContact({ contact_email: "" }), "");
  assert.equal(secContact({ contact_email: "not an address" }), "");
  assert.equal(secContact({ contact_email: "contact@cyberview.example" }), "contact@cyberview.example");
});

test("dedupe: known address, same organisation on the same register, too old; a breach on file is kept and named", () => {
  const items = parseWashington(JSON.parse(fx("wa.json")));
  const known = { urls: new Set(["https://data.wa.gov/resource/sb4j-ca4h.json?id=26286"]), orgs: new Set(["breach-wa|telecare health"]) };
  const evs = [{ id: "dexcom-phishing-breach-2026-11", title: "Dexcom data breach after phishing attack", org: "Dexcom", category: "incident", date: "2026-11-12", first_seen: "2026-11-12T10:00:00Z" }];
  const out = fresh(items, "breach-wa", known, evs, NOW);
  assert.deepEqual(out.map((x) => x.org), ["Dexcom, Inc."]);
  assert.match(out[0].summary, /^Matches event dexcom-phishing-breach-2026-11 on file\. Official notice/);
  assert.equal(fresh(items, "breach-wa", known, evs, NOW).length, 0, "a second run files nothing again");
  assert.equal(fresh(items, "breach-wa", { urls: new Set(), orgs: new Set() }, [], Date.parse("2026-12-20T00:00:00Z")).length, 0, "older than the window");
  // the same organisation on ANOTHER register is filed (corroboration)
  assert.equal(fresh([{ ...items[1], url: "https://oag.ca.gov/ecrime/databreach/reports/sb24-1" }], "breach-ca", known, [], NOW).length, 1);
});

test("throttle: a register answered under an hour ago is not asked again", () => {
  assert.equal(askedRecently({ ok: true, at: "2026-11-21T11:30:00Z" }, NOW), true);
  assert.equal(askedRecently({ ok: true, at: "2026-11-21T10:30:00Z" }, NOW), false);
  assert.equal(askedRecently({ ok: false, at: "2026-11-21T11:59:00Z" }, NOW), false);
});

const N = (org, via, source, o = {}) => ({ title: `${org}: data breach notification filed with ${source.replace(/ Attorney General$/, "'s Attorney General")}`, source: source, tier: "gov", via, kind: KIND, org: orgKey(org),
  url: `https://${via}.example/${orgKey(org).replace(/ /g, "-")}`, seen_at: "2026-11-21T10:00:00Z", published: "2026-11-20T00:00:00Z", lang: "en", _open: true, ...o });

test("fusion: the same organisation on several registers is one story; different filers never join on the register's words", () => {
  const leads = [N("Uber Technologies, Inc.", "breach-ca", "California Attorney General"), N("Uber Technologies, Inc", "breach-ia", "Iowa Attorney General"),
    N("Bausch Health Companies Inc.", "breach-ca", "California Attorney General"), N("Valley Family Health Care, Inc.", "breach-ca", "California Attorney General"),
    N("Colla Health, Inc.", "breach-ca", "California Attorney General"), N("AltaMed Health Services Corporation", "breach-ca", "California Attorney General")];
  assert.deepEqual(cluster(leads).map((g) => g.length).sort(), [1, 1, 1, 1, 2]);
  assert.deepEqual([...keyTokens(leads[2].title)], ["bausch"], "only the filer's distinctive name counts");
});

test("fuse and backlog: a breach notice is an official source agents read, never closed as a bare database row", () => {
  const s = story([N("Hitachi Vantara LLC", "breach-ca", "California Attorney General")], [], NOW);
  assert.ok(s.why.includes("a government or CERT source"), "scored as a government report, not a database entry");
  assert.ok(!s.why.includes("a primary database entry"));
  assert.equal(s.incident, true);
  assert.equal(autoReason(s, NOW), "", "single source, but official: an agent reads it");
  const db = story([{ ...N("Hitachi Vantara LLC", "hibp", "Have I Been Pwned"), tier: "vendor", kind: "breach-db" }], [], NOW);
  assert.match(autoReason(db, NOW), /bare database row/, "the HIBP row next to it still is one");
  const old = story([N("Old Filer LLC", "breach-wa", "Washington Attorney General", { published: "2026-11-10T00:00:00Z" })], [], NOW);
  assert.match(autoReason(old, NOW), /older than the map window/);
});

test("being checked list: a breach notice never heads it (its headline is the collector's, not a publisher's)", () => {
  const s = story([N("Hitachi Vantara LLC", "breach-ca", "California Attorney General"), N("Hitachi Vantara LLC", "breach-wa", "Washington Attorney General")], [], NOW);
  assert.equal(s.publishers, 2);
  assert.deepEqual(developing([s], NOW), []);
  const withNews = story([N("Hitachi Vantara LLC", "breach-ca", "California Attorney General"), { title: "Hitachi Vantara confirms ransomware attack, data stolen", source: "The Record", tier: "news", via: "rss", url: "https://therecord.media/hitachi-vantara", seen_at: "2026-11-21T10:00:00Z", published: "2026-11-21T09:00:00Z", _open: true }], [], NOW);
  const d = developing([withNews], NOW);
  assert.equal(d.length, 1); assert.equal(d[0].url, "https://therecord.media/hitachi-vantara"); assert.match(d[0].title, /^Hitachi Vantara confirms/);
});
