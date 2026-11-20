// The RSS feed list (scripts/collect.mjs) and its config (config/feeds.json). Run: node --test tests/unit/
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { FEEDS, CYBER, activeFeeds, extraFeeds } from "../../scripts/collect.mjs";
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CFG = JSON.parse(readFileSync(join(ROOT, "config", "feeds.json"), "utf8"));
const REGIONS = new Set(["africa", "latin-america", "middle-east", "south-asia", "southeast-asia", "east-asia", "europe", "oceania", "north-america"]);

test("every built-in feed is well formed: unique, https, a tier, an ISO language code and a known region", () => {
  assert.equal(new Set(FEEDS.map((f) => f.name.toLowerCase())).size, FEEDS.length);
  assert.equal(new Set(FEEDS.map((f) => f.url)).size, FEEDS.length);
  for (const f of FEEDS) {
    assert.match(f.url, /^https:\/\//, f.name);
    assert.ok(["gov", "vendor", "news"].includes(f.tier), f.name);
    // a region written into lang made the English-only rules misjudge a feed (Daily Sabah, El Pais, TechCabal, iThome, RNZ)
    if (f.lang) assert.match(f.lang, /^[a-z]{2}$/, `${f.name}: lang is a language code`);
    if (f.region) assert.ok(REGIONS.has(f.region), `${f.name}: region ${f.region}`);
    if (f.kind) assert.ok(["cve", "exploit"].includes(f.kind), f.name);
  }
});

test("feeds whose robots.txt disallows them, or that are dead, are not collected", () => {
  const gone = /theregister\.com|securelist\.com|csoonline\.com|grahamcluley\.com|lobste\.rs|ke-cirt\.go\.ke|news\.google\.com/;
  assert.deepEqual(FEEDS.filter((f) => gone.test(f.url)).map((f) => f.name), []);
  for (const r of CFG.retired) assert.ok(r.name && r.why && /^\d{4}-\d{2}-\d{2}$/.test(r.retired), JSON.stringify(r));
});

test("the config can retire a built-in feed by name; extra feeds are added once", () => {
  const all = activeFeeds({ retired: [{ name: FEEDS[0].name.toUpperCase() }], feeds: [{ name: "New CERT", tier: "gov", url: "https://cert.example/rss" }] });
  assert.ok(!all.some((f) => f.name === FEEDS[0].name));
  assert.equal(all.length, FEEDS.length);
  assert.ok(all.some((f) => f.name === "New CERT"));
  assert.equal(activeFeeds({}).length, FEEDS.length);
  assert.equal(activeFeeds(null).length, FEEDS.length);
  assert.deepEqual(extraFeeds({ feeds: [{ name: FEEDS[1].name, tier: "gov", url: "https://other.example/rss" }] }), [], "a name already built in");
});

test("every watched feed exists and carries its evidence and a review date", () => {
  const names = new Set(activeFeeds(CFG).map((f) => f.name));
  for (const w of CFG.watch) {
    assert.ok(names.has(w.name), `watch: ${w.name} is not a feed`);
    assert.ok(w.evidence && /^\d{4}-\d{2}-\d{2}$/.test(w.review), w.name);
  }
});

test("the cyber filter for broad feeds reads the languages they are written in, and not ordinary news", () => {
  for (const t of ["Hospital hit by ransomware", "Ciberataque a la Federación Internacional de Hockey", "iFood confirma vazamento de dados de clientes",
    "Fuite de données chez Chargemap", "Avrupa Komisyonuna siber saldırı", "スパコン「富岳」に不正アクセス", "PHP釋出安全更新修補18個漏洞",
    "美 '이란, 핵심인프라 사이버 공격'", "هجوم سيبراني على شركة", "Serangan siber lumpuhkan email", "Cyberangriff auf Equinor"]) assert.ok(CYBER.test(t), t);
  for (const t of ["Liga : le Real Madrid prolonge Tchouaméni", "Siberia braces for a winter storm", "Kenyan-Nigerian team wins Africa Hackathon 2026",
    "GTA 6 passa de 40 bilhões de views", "Morena inhabilita a regidor de Tulum"]) assert.ok(!CYBER.test(t), t);
});

test("a lead's language is an ISO 639-1 code or nothing, never a language name or a region", async () => {
  const { gdeltLang, parseGdelt } = await import("../../scripts/osint.mjs");
  assert.equal(gdeltLang("Spanish"), "es");
  assert.equal(gdeltLang("Swahili"), "sw");
  assert.equal(gdeltLang("Klingon"), "", "an unmapped name is dropped, not passed on");
  assert.equal(parseGdelt({ articles: [{ url: "https://a.example/x", title: "Ataque", seendate: "20261118T101500Z", domain: "a.example", language: "Hungarian" }] })[0].lang, "hu");
});
