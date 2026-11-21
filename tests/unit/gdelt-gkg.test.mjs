// GDELT GKG 15-minute files as leads (scripts/gdelt-gkg.mjs). The fixture is 8 real rows from the files of 2026-11-21
// (GCAM and related-image columns emptied to keep it small), zipped as GDELT ships them: an English cyber story, a
// Swedish one (translation stream), a row without a cyber theme, a sports story GDELT tagged CYBER_ATTACK once, an http-only
// page, a power-outage row, and a Serbian story whose first place is the demonym "Americans".
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { deflateRawSync, crc32 } from "node:zlib";
import { unzipSingle, parseLastUpdate, slotsToRead, srcLang, decodeEntities, cleanTitle, cleanUrl, themeCounts, firstCountry, orgsOf,
  parseRow, parseGkg, select, dedupeAndCap, cyberTitle } from "../../scripts/gdelt-gkg.mjs";

const FIX = new URL("../fixtures/gdelt/sample.gkg.csv.zip", import.meta.url);
const CFG = JSON.parse(readFileSync(new URL("../../config/gdelt.json", import.meta.url), "utf8"));
const rows = () => parseGkg(unzipSingle(readFileSync(FIX)).toString("utf8"));

/** A single-entry zip with a data descriptor (sizes 0 in the local header), as streaming writers make them. */
function zipOf(name, data, { stored = false } = {}) {
  const body = stored ? data : deflateRawSync(data), n = Buffer.from(name), crc = crc32(data) >>> 0;
  const loc = Buffer.alloc(30); loc.writeUInt32LE(0x04034b50, 0); loc.writeUInt16LE(20, 4); loc.writeUInt16LE(8, 6); loc.writeUInt16LE(stored ? 0 : 8, 8); loc.writeUInt16LE(n.length, 26);
  const cd = Buffer.alloc(46); cd.writeUInt32LE(0x02014b50, 0); cd.writeUInt16LE(stored ? 0 : 8, 10); cd.writeUInt32LE(crc, 16); cd.writeUInt32LE(body.length, 20); cd.writeUInt32LE(data.length, 24); cd.writeUInt16LE(n.length, 28); cd.writeUInt32LE(0, 42);
  const cdOff = loc.length + n.length + body.length, eocd = Buffer.alloc(22); eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(1, 8); eocd.writeUInt16LE(1, 10); eocd.writeUInt32LE(cd.length + n.length, 12); eocd.writeUInt32LE(cdOff, 16);
  return Buffer.concat([loc, n, body, cd, n, eocd]);
}

test("unzip: the real GKG zip, a streamed (data descriptor) and a stored entry; damage and oversize are refused", () => {
  const t = unzipSingle(readFileSync(FIX)).toString("utf8");
  assert.equal(t.trim().split("\n").length, 8);
  const data = Buffer.from("a\tb\nc\td\n".repeat(50));
  assert.deepEqual(unzipSingle(zipOf("x.csv", data)), data);
  assert.deepEqual(unzipSingle(zipOf("x.csv", data, { stored: true })), data);
  const bad = zipOf("x.csv", data); bad[40] ^= 0xff;   // a flipped byte in the compressed data
  assert.throws(() => unzipSingle(bad));
  assert.throws(() => unzipSingle(zipOf("x.csv", data), 100), /cap/);
  assert.throws(() => unzipSingle(Buffer.from("not a zip at all, not at all")), /zip/);
});

test("lastupdate.txt: the GKG lines only, always over https; slots after a gap, capped, with pending retries", () => {
  const u = parseLastUpdate(`33287 99e984fd826497ae5765484af3b11521 http://data.gdeltproject.org/gdeltv2/20261121234500.export.CSV.zip
2361330 0804c7df5b359f177aeff85cad63d539 http://data.gdeltproject.org/gdeltv2/20261121234500.gkg.csv.zip
3512083 5569616e64fe2c63cc800848adce07d6 http://data.gdeltproject.org/gdeltv2/20261121233000.translation.gkg.csv.zip
1 x http://evil.example/20261121233000.gkg.csv.zip`);
  assert.deepEqual(u.map((x) => [x.ts, x.url, x.size]), [["20261121234500", "https://data.gdeltproject.org/gdeltv2/20261121234500.gkg.csv.zip", 2361330],
    ["20261121233000", "https://data.gdeltproject.org/gdeltv2/20261121233000.translation.gkg.csv.zip", 3512083]]);
  assert.deepEqual(slotsToRead("20261121234500", ""), ["20261121234500"], "first run: the latest file only");
  assert.deepEqual(slotsToRead("20261121234500", "20261121234500"), [], "nothing new");
  assert.deepEqual(slotsToRead("20261121234500", "20261121231500"), ["20261121233000", "20261121234500"]);
  const now = Date.UTC(2026, 10, 21, 23, 50);
  assert.deepEqual(slotsToRead("20261121234500", "20261120000000", 3, [], 3, now), ["20261121231500", "20261121233000", "20261121234500"], "a long gap: the newest `cap`");
  assert.deepEqual(slotsToRead("20261121234500", "20261121234500", 8, ["20261121223000", "20261121100000"], 3, now), ["20261121223000"], "a pending file is retried only while young");
});

test("rows: columns, source language, country by FIPS code (not a demonym), organisations", () => {
  const r = rows();
  assert.equal(r.length, 8);
  const by = Object.fromEntries(r.map((x) => [x.source, x]));
  assert.equal(by["komonews.com"].lang, "en");
  assert.equal(by["komonews.com"].date, "2026-11-21T20:00:00Z");
  assert.equal(by["komonews.com"].themes.get("CYBER_ATTACK"), 4);
  assert.equal(by["aftonbladet.se"].lang, "sv");
  assert.equal(by["aftonbladet.se"].country, "Sweden");
  assert.equal(by["telegraf.rs"].lang, "sr");
  assert.equal(by["telegraf.rs"].country, "United States", "first place written 'Americans': named by its FIPS code");
  assert.equal(srcLang(""), "en");
  assert.equal(srcLang("srclc:tur;eng:GT-TUR 1.0"), "tr");
  assert.equal(srcLang("srclc:xyz;eng:GT-XYZ 1.0"), "", "an unknown code is never passed on as a code");
  assert.equal(firstCountry("1#Britons#UK#UK##54#-2#UK#40;2#Kent, United Kingdom#UK#UKG5##51#1#UKG5#90"), "United Kingdom");
  assert.equal(firstCountry("1#Turkish#TU#TU##39#35#TU#12", "1#Turkey#TU#TU#39#35#TU"), "Turkey");
  assert.equal(firstCountry("1#Martian#ZZ#ZZ##0#0#ZZ#12"), "", "no canonical name: nothing rather than a demonym");
  assert.deepEqual(orgsOf("Reuters,10;Fbi,50;reuters,99;Nato,5;1234,3"), ["Nato", "Reuters", "Fbi"]);
  assert.equal(parseRow("too\tfew\tcolumns"), null);
  assert.deepEqual([...themeCounts("CYBER_ATTACK,10;CYBER_ATTACK,99;bad theme,3;TAX_FNCACT_HACKERS,5")], [["CYBER_ATTACK", 2], ["TAX_FNCACT_HACKERS", 1]]);
});

test("titles and addresses: entities decoded, the site's own name dropped, only the publisher's https page", () => {
  assert.equal(decodeEntities("Trump &#x2013; &#233;t&eacute; &amp; more"), "Trump – ét&eacute; & more");
  assert.equal(cleanTitle("<PAGE_TITLE>The FBI Database Behind America&#x27;s Manhunts May Have Been Hacked | News Talk WBAP 820 AM</PAGE_TITLE>", "wbap.com"),
    "The FBI Database Behind America's Manhunts May Have Been Hacked");
  assert.equal(cleanTitle("<PAGE_TITLE>Hackers hit city hall - Reuters analysis</PAGE_TITLE>", "example.com"), "Hackers hit city hall - Reuters analysis", "a tail that is not the site's name stays");
  assert.equal(cleanTitle("<PAGE_LINKS>x</PAGE_LINKS>"), "");
  assert.equal(cleanUrl("https://komonews.com/news/a"), "https://komonews.com/news/a");
  for (const u of ["http://www.japanherald.com/news/1", "https://api.gdeltproject.org/api/v2/doc", "https://www.msn.com/en-us/news/x", "https://user:pw@example.com/", "https://a.com/x y", "javascript:alert(1)"])
    assert.equal(cleanUrl(u), "", u);
});

test("theme filter: cyber themes plus a cyber headline or enough mentions; grid rows only counted", () => {
  const { leads, stats } = select(rows(), CFG, "2026-11-21T23:50:00Z");
  assert.deepEqual(stats, { rows: 8, themed: 6, weak: 2, no_https: 1, no_title: 0, grid_rows: 1 });
  assert.deepEqual(leads.map((l) => l.source), ["komonews.com", "aftonbladet.se", "wkzo.com"]);
  const sv = leads.find((l) => l.lang === "sv");
  assert.equal(sv.title, "Uppgifter: Polisen drabbad av taxijättens dataintrång");
  assert.equal(sv.orgs, undefined, "no machine-translated organisation names");
  const en = leads[0];
  assert.deepEqual({ via: en.via, tier: en.tier, kind: en.kind, country: en.country, region: en.region }, { via: "gdelt-gkg", tier: "news", kind: "news", country: "United States", region: "north-america" });
  assert.ok(en.orgs.includes("National Crime Information Center"));
  assert.match(en.summary, /not checked/);
  assert.ok(leads.every((l) => /^https:\/\//.test(l.url) && !/gdelt/.test(l.url)));
  assert.ok(!leads.some((l) => l.source === "comicbook.com"), "one stray CYBER_ATTACK tag in a film story is not a lead");
  assert.ok(cyberTitle("Χάκαραν ξανά το FBI", CFG.title_words));
  assert.ok(!cyberTitle("Nuthatch is music to the ears", CFG.title_words));
});

test("dedupe against known leads and within the batch; the cap keeps the most mentioned", () => {
  const mk = (i, hits, extra = {}) => ({ source: "s" + i, title: "Title " + i, url: "https://p.example/" + i, published: "2026-11-21T20:00:00Z", lang: "en", _hits: hits, ...extra });
  const norm = (t) => String(t).toLowerCase();
  const known = { known: new Set(["https://p.example/1"]), knownTitle: new Set(["s2|title 2"]), norm };
  const r = dedupeAndCap([mk(1, 9), mk(2, 9), mk(3, 1), mk(4, 5), mk(4, 5, { url: "https://p.example/4b" }), mk(5, 7), mk(6, 2, { lang: "" })], known, 2);
  assert.equal(r.dupes, 3, "a known url, a known publisher and headline, and the same headline twice in one batch");
  assert.deepEqual(r.leads.map((l) => l.url), ["https://p.example/5", "https://p.example/4"]);
  assert.equal(r.capped, 2);
  assert.ok(r.leads.every((l) => !("_hits" in l)));
  assert.ok(!("lang" in dedupeAndCap([mk(6, 2, { lang: "" })], { known: new Set(), knownTitle: new Set(), norm }, 5).leads[0]), "an unknown language is left out, not written empty");
  const fox = ["fox10phoenix.com", "foxla.com", "fox2detroit.com", "fox5dc.com"].map((s, i) => ({ ...mk(10 + i, 7), source: s, title: "FBI's NCIC criminal database hacked, Trump confirms" }));
  const s = dedupeAndCap(fox, { known: new Set(), knownTitle: new Set(), norm }, 60, 2);
  assert.equal(s.leads.length, 2); assert.equal(s.syndicated, 2);
});

test("a file that is not published yet cannot open the circuit breaker for the other files", () => {
  const src = readFileSync(new URL("../../scripts/gdelt-gkg.mjs", import.meta.url), "utf8");
  assert.match(src, /key: `gdelt-file:\$\{ts\}:\$\{stream\}`/);
  assert.match(src, /e\.code === "http_404"/);
});

test("config: real theme names, caps, and the DOC API retirement date", () => {
  assert.ok(CFG.cyber_themes.includes("CYBER_ATTACK"));
  assert.ok(!CFG.cyber_themes.includes("SOC_RANSOM"), "kidnap ransoms are not cyber");
  assert.ok(CFG.max_leads_per_run > 0 && CFG.max_leads_per_run <= 200);
  assert.ok(CFG.catch_up_files >= 1 && CFG.catch_up_files <= 96);
  assert.match(CFG.doc_api_retire_after, /^\d{4}-\d{2}-\d{2}$/);
});

test("collect.yml runs it as an optional step and commits its state; the research loop runs it", () => {
  const wf = readFileSync(new URL("../../.github/workflows/collect.yml", import.meta.url), "utf8");
  const at = wf.indexOf("else node scripts/gdelt-gkg.mjs"), step = wf.slice(wf.lastIndexOf("- name:", at), at);
  assert.ok(at > 0, "the step runs the script");
  assert.match(step, /continue-on-error: true/);
  assert.match(step, /timeout-minutes: \d/);
  assert.match(wf, /data\/gdelt-gkg\.json/);
  const rj = readFileSync(new URL("../../scripts/run-job.mjs", import.meta.url), "utf8");
  assert.match(rj, /scripts\/gdelt-gkg\.mjs/);
});
