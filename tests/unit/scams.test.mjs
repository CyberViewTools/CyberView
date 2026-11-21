// Unit tests for the scam warning collector (scripts/scams.mjs): parsers on real responses saved 2026-11-21
// (tests/fixtures/scams/, trimmed), the fixed keyword type map, links, merging and leads.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { PARSERS, parseHkma, toWarnings, scamTypes, isScam, isIncident, ownLink, merge, toLead, clean, TYPE_KEYS, CONFIG, NOT_WARNING } from "../../scripts/scams.mjs";

const FX = join(dirname(fileURLToPath(import.meta.url)), "..", "fixtures", "scams");
const fx = (f) => readFileSync(join(FX, f), "utf8");
const NOW = Date.parse("2026-11-21T12:00:00Z");
const src = (key, extra = {}) => ({ ...CONFIG().sources.find((s) => s.key === key), ...extra });

test("config: every issuer has its own https hosts, a known format and an ISO country", () => {
  const c = CONFIG();
  assert.ok(c.sources.length >= 10);
  const keys = new Set();
  for (const s of c.sources) {
    assert.ok(!keys.has(s.key), `duplicate ${s.key}`); keys.add(s.key);
    assert.match(s.key, /^[a-z0-9-]{2,30}$/);
    assert.match(s.country, /^[A-Z]{2}$/);
    assert.ok(PARSERS[s.format], `${s.key}: format`);
    assert.match(s.url, /^https:\/\//);
    assert.match(s.home, /^https:\/\//);
    assert.ok(Array.isArray(s.hosts) && s.hosts.length, `${s.key}: hosts`);
    assert.ok(s.hosts.includes(new URL(s.home).hostname), `${s.key}: home on its own hosts`);
    assert.ok(["government", "police", "regulator", "cert", "consumer"].includes(s.kind), `${s.key}: kind`);
  }
});

test("IC3 RSS: only the scam warnings pass the title filter", () => {
  const w = toWarnings(src("ic3"), PARSERS.rss(fx("ic3.xml")), NOW);
  assert.deepEqual(w.map((x) => x.title), ["Scammers Exploit 2026 U.S. Midterm Election to Perpetrate Multiple Fraud Schemes"]);
  assert.equal(w[0].country, "US");
  assert.equal(w[0].issuer, "ic3");
  assert.equal(w[0].published, "2026-10-15T13:00:00Z");
  assert.equal(w[0].types_by, "keyword");
  assert.match(w[0].url, /^https:\/\/www\.ic3\.gov\/PSA\/2026\//);
  assert.match(w[0].id, /^ic3-[0-9a-f]{12}$/);
});

test("Watchlist Internet RSS (dedicated feed): every warning kept, webinars left out, German keywords typed", () => {
  const w = toWarnings(src("watchlist-internet"), PARSERS.rss(fx("watchlist.xml")), NOW);
  assert.equal(w.length, 3);
  assert.ok(!w.some((x) => /Webinar/.test(x.title)));
  const pension = w.find((x) => /Pensionsleistung/.test(x.title));
  assert.ok(pension.types.includes("bank_sms") || pension.types.includes("impersonation"));
  assert.ok(w.find((x) => /Fake-Anw/.test(x.title)).types.includes("impersonation"));
  assert.ok(w.every((x) => x.lang === "de" && x.country === "AT"));
});

test("Anti-Phishing Japan Atom: only urgent alerts (url_match), the section suffix stripped, Japanese typed", () => {
  const w = toWarnings(src("antiphishing-jp"), PARSERS.rss(fx("antiphishing.xml")), NOW);
  assert.ok(w.length >= 1);
  assert.ok(w.every((x) => /^https:\/\/www\.antiphishing\.jp\/news\/alert\//.test(x.url)));
  assert.ok(w.every((x) => !/ニュース$/.test(x.title)));
  const sec = w.find((x) => /証券会社/.test(x.title));
  assert.deepEqual(sec.types, ["impersonation", "investment"]);
});

test("HKMA open API: press releases filtered to fraud warnings; a wrong shape throws", () => {
  const w = toWarnings(src("hkma"), parseHkma(JSON.parse(fx("hkma.json"))), NOW, 400);
  assert.equal(w.length, 3);
  assert.ok(!w.some((x) => /Tender/.test(x.title)));
  assert.ok(w.find((x) => /purported/.test(x.title)).types.includes("impersonation"));
  assert.ok(w.find((x) => /payment cards/.test(x.title)).types.includes("bank_sms"));
  assert.throws(() => parseHkma({ header: { success: false } }), (e) => e.code === "bad_shape");
  assert.equal(PARSERS.hkma(fx("hkma.json")).length, 5);
});

test("a block or error page served with 200 is an error, not an empty feed", () => {
  assert.throws(() => PARSERS.rss("<html><head><script src=\"/_Incapsula_Resource\"></script></head></html>"), (e) => e.code === "not_a_feed");
  assert.equal(PARSERS.rss('<?xml version="1.0"?><rss version="2.0"><channel></channel></rss>').length, 0);
});

test("type map: one example per type in several languages, and none for plain text", () => {
  const cases = {
    impersonation: ["Criminals impersonating HMRC", "Suplantan a la Policía Nacional", "FALSI SMS A NOME NEXI", "国税庁をかたるメール", "검찰 사칭 문자", "Fake-Anwälte versenden Trojaner"],
    investment: ["Beware of investment scams on social media", "Fraude a la inversión en criptomonedas", "Anlagebetrug im Internet", "投資詐欺に注意"],
    delivery: ["Fake parcel delivery texts", "Falsi SMS del corriere", "Paket-Zustellung: Phishing", "宅配便の不在通知を装う", "Fałszywe SMS o przesyłce"],
    bank_sms: ["Smishing campaign targets bank customers", "Datenaktualisierung per SMS", "銀行を装うフィッシング", "은행 사칭 문자"],
    tech_support: ["Tech support scam calls", "Falso soporte técnico de Microsoft", "サポート詐欺に注意"],
    romance: ["Romance scams cost victims millions", "Liebesbetrug auf Dating-Plattformen", "国際ロマンス詐欺"],
    job: ["Task scams and fake job offers", "Ofertas de empleo falsas", "副業詐欺"],
    crypto: ["Bitcoin ATM scams", "Krypto-Betrug", "暗号資産を狙う詐欺", "가상자산 투자 사기"],
  };
  for (const [type, texts] of Object.entries(cases)) for (const t of texts) assert.ok(scamTypes(t).includes(type), `${type}: ${t} -> ${scamTypes(t)}`);
  assert.deepEqual(scamTypes("Annual report published"), []);
  assert.deepEqual(TYPE_KEYS, ["impersonation", "investment", "delivery", "bank_sms", "tech_support", "romance", "job", "crypto"]);
  assert.ok(!scamTypes("Cardinal health update").includes("bank_sms"), "word boundaries for short words");
});

test("scam filter and non-warnings", () => {
  for (const t of ["Phishing campaign", "Estafa telefónica", "Arnaque au faux conseiller", "Truffa online", "フィッシング", "스미싱 주의", "Huijausviestit", "Oszustwo"]) assert.ok(isScam(t), t);
  for (const t of ["Critical Vulnerability Alert: PHP Core", "Bank of Canada interest rate", "Tender of RMB bonds"]) assert.ok(!isScam(t), t);
  for (const t of ["Webinar: Sicheres Online-Shopping", "Kyberturvallisuuskeskuksen viikkokatsaus – 47/2026"]) assert.ok(NOT_WARNING.test(t), t);
});

test("incident words make a lead, warnings alone do not", () => {
  assert.ok(isIncident("Phishing emails after the data breach at ASOS"));
  assert.ok(isIncident("Datenleck bei Versandhändler: Vorsicht vor Phishing"));
  assert.ok(isIncident("情報漏えいに便乗したフィッシング"));
  assert.ok(!isIncident("Fake parcel delivery texts"));
  const w = toWarnings(src("ic3"), [{ title: "Fraudsters use data stolen in the Acme breach", url: "https://www.ic3.gov/PSA/2026/PSA261101", published: "2026-11-01T00:00:00Z", summary: "" }], NOW)[0];
  assert.equal(w.incident, true);
  const l = toLead(w, "2026-11-21T12:00:00Z");
  assert.equal(l.kind, "advisory"); assert.equal(l.tier, "gov"); assert.equal(l.via, "scams"); assert.equal(l.url, w.url);
});

test("links: https on the issuer's own hosts only, tracking parameters dropped", () => {
  assert.equal(ownLink("https://www.ic3.gov/PSA/2026/x", ["www.ic3.gov"]), "https://www.ic3.gov/PSA/2026/x");
  assert.equal(ownLink("http://www.ic3.gov/PSA/2026/x", ["www.ic3.gov"]), "");
  assert.equal(ownLink("https://evil.example/PSA", ["www.ic3.gov"]), "");
  assert.equal(ownLink("https://user:pw@www.ic3.gov/x", ["www.ic3.gov"]), "");
  assert.equal(ownLink("javascript:alert(1)", ["www.ic3.gov"]), "");
  assert.equal(ownLink("https://www.kyberturvallisuuskeskus.fi/fi/x?mtm_campaign=rss&id=3", ["www.kyberturvallisuuskeskus.fi"]), "https://www.kyberturvallisuuskeskus.fi/fi/x?id=3");
  const w = toWarnings(src("ic3"), [{ title: "Scam warning", url: "https://elsewhere.example/a", published: "2026-11-01T00:00:00Z" }], NOW);
  assert.equal(w.length, 0, "an item linking off the issuer's hosts is dropped");
});

test("dates: old and future-dated items are left out; text is cleaned", () => {
  const s = src("watchlist-internet");
  const w = toWarnings(s, [
    { title: "Old scam", url: "https://www.watchlist-internet.at/news/a/", published: "2026-08-01T00:00:00Z" },
    { title: "Future scam", url: "https://www.watchlist-internet.at/news/b/", published: "2026-12-30T00:00:00Z" },
    { title: "Phishing &rsquo;now&rsquo; <b>here</b>\u0007", url: "https://www.watchlist-internet.at/news/c/", published: "2026-11-20T00:00:00Z" },
  ], NOW);
  assert.deepEqual(w.map((x) => x.title), ["Phishing ’now’ here"]);
  assert.equal(clean("a<script>b", 50), "a b");
});

test("merge: first_seen and lead_at kept, old warnings dropped, per-issuer cap", () => {
  const mk = (id, issuer, published) => ({ id, issuer, published, title: id, url: `https://x/${id}`, types: [] });
  const old = [{ ...mk("a", "ic3", "2026-11-01T00:00:00Z"), first_seen: "2026-11-01T01:00:00Z", lead_at: "2026-11-01T01:00:00Z" }, { ...mk("old", "ic3", "2026-07-01T00:00:00Z"), first_seen: "2026-07-01T00:00:00Z" }];
  const out = merge(old, [mk("a", "ic3", "2026-11-01T00:00:00Z"), mk("b", "ic3", "2026-11-20T00:00:00Z"), mk("c", "ic3", "2026-11-19T00:00:00Z")], "2026-11-21T12:00:00Z", { keep_days: 90, per_issuer: 2 });
  assert.deepEqual(out.map((x) => x.id), ["b", "c"]);
  const all = merge(old, [mk("a", "ic3", "2026-11-01T00:00:00Z")], "2026-11-21T12:00:00Z", { keep_days: 90, per_issuer: 10 });
  assert.equal(all.find((x) => x.id === "a").first_seen, "2026-11-01T01:00:00Z");
  assert.equal(all.find((x) => x.id === "a").lead_at, "2026-11-01T01:00:00Z");
  assert.ok(!all.some((x) => x.id === "old"));
});
