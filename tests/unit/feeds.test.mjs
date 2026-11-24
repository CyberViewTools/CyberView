// The RSS feed list (scripts/collect.mjs) and its config (config/feeds.json). Run: node --test tests/unit/
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { FEEDS, CYBER, activeFeeds, extraFeeds, loadFeedConfig } from "../../scripts/collect.mjs";
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CFG = JSON.parse(readFileSync(join(ROOT, "config", "feeds.json"), "utf8"));
// config/feeds.json plus the bulk source lists in config/feeds.d/*.json (each feed tagged with its shard)
const ALL_CFG = loadFeedConfig(ROOT);
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

test("the cyber filter reads the fifth batch's languages (fa, he, hi, hu, uz, et, da), from those feeds' real titles", () => {
  for (const t of ["فرمانده عملیات سایبری بریتانیا از عملیات تهاجمی علیه جمهوری اسلامی خبر داد", "باج‌افزار جدید", "מתקפת סייבר עולמית ב-178 אתרים",
    "בזמן שישנתם: חולשת אבטחה קריטית ב-Java. לכו לעדכן", "हैकर्स की चाल नाकाम करने गूगल ने बिछाया जाल", "क्या एआई बन सकता है साइबर खतरा?",
    "Kibertámadást észlelt az Equinor, a termelés zavartalan maradt", "Qilin-zsarolóvírus-támadás során azonosítottak egy eszközt",
    "Adatszivárgás miatt napokra leállt a LEGO népszerű online piactere", "NGINX dasturidagi kritik zaifliklar sababli serverlar kiberhujumlar xavfi ostida",
    "RIA küberreserv harjutas Tallinna lennujaama tabanud küberrünnaku lahendamist", "Uus ID-tarkvara versioon parandab kaks olulist turvanõrkust",
    "August küberruumis: teenusetõrked, lunavararünne ja õngitsussõnumid", "Råd til borgere ved datalæk af personoplysninger"]) assert.ok(CYBER.test(t), t);
  // ordinary news from the same feeds: sport, prices, power cuts, service faults and Nairobi's Kibera are not cyber items
  for (const t of ["پرسپولیس ۳-۰ پیکان؛ تارتار هم از بحران خارج شد", "سخنگوی صنعت برق: پیامک آغاز قطعی‌های برق در تهران مربوط به تعمیرات شبکه است",
    "הסוללה התפוצצה בסלון: רגעי האימה שתועדו במצלמה", "תקלה עולמית במיקרוסופט: ניסיונות התיקון נכשלו, השרתים שוב קרסו",
    "शाओमी 18 प्रो की कीमत लीक: अल्ट्रा-प्रीमियम सेगमेंट में एंट्री", "छात्रों ने हैकथॉन जीता", "A NATO egy orosz taxialkalmazás használatát javasolta, majd visszavonta",
    "Esines tõrkeid riigi autentimisteenuse kasutamisel", "Flere myndigheders hjemmesider var midlertidigt utilgængelige",
    "Kibera residents protest evictions", "Kibera, Nairobi: floods displace families"]) assert.ok(!CYBER.test(t), t);
});

test("the cyber filter reads Swahili, Hausa, Amharic and Afrikaans, more Arabic, Turkish and Portuguese, and no longer takes Kubernetes for kuber-", () => {
  // real titles from the new regional feeds (BBC Amharic, Euronews Turkce, Youm7 via Bing News, 2026-11-21); the Swahili, Hausa
  // and Afrikaans lines are standard phrasing (no real cyber headline was in those feeds or in Bing News that day)
  for (const t of ["አሜሪካ \"ስልታዊ የሳይበር ጥቃት ተፈጽሞባታል\" መባሉን የውጭ ጉዳይ ሚኒስትሯ አስተባበሉ", "çalışanların veri ihlalini basından öğrenmek zorunda kalmasına tepki",
    "الاتحاد الأوروبى يكشف تعرضه لهجوم إلكترونى أدى لتعطيل أنظمة رقمية لأسابيع", "هجمات إلكترونية تستهدف البنوك", "Prefeitura sofre sequestro de dados",
    "Benki yashambuliwa na wadukuzi", "Tovuti za serikali zimedukuliwa", "Mashambulizi ya kimtandao yaongezeka Afrika Mashariki", "Uhalifu wa mtandaoni waongezeka",
    "Masu kutse sun kai hari kan bankin", "Harin intanet ya tsayar da ayyukan hukumar", "Losprysware-aanval tref munisipaliteit", "Kuberaanval op hospitaal"]) assert.ok(CYBER.test(t), t);
  // ordinary news from the same feeds (real titles), Swahili "dukuduku" (curiosity), and the container platform
  for (const t of ["Yadda Putin ke yawo da akwatin makamin nukiliya a asirce", "Wananchi wana dukuduku kuhusu matokeo ya uchaguzi", "Kubernetes 1.35 released with a new scheduler",
    "Zambia welcomes S&P sovereign credit rating upgrade", "Burkina : Faso Academy 2026 : Sylvain Pardevan remporte la première place"]) assert.ok(!CYBER.test(t), t);
});

test("every extra feed (config/feeds.json and every shard in config/feeds.d) is well formed: a tier, https, an ISO language, a known region, the date added and why", () => {
  for (const f of ALL_CFG.feeds) {
    assert.ok(typeof f.name === "string" && f.name.trim() && f.name.length <= 80, `${f.shard || "feeds.json"}: ${f.name}`);
    if (f.kind) assert.ok(["cve", "exploit"].includes(f.kind), f.name);
    assert.ok(["gov", "vendor", "news"].includes(f.tier), f.name);
    assert.match(f.url, /^https:\/\/[^\s"'<>]+$/, f.name);
    if (f.lang) assert.match(f.lang, /^[a-z]{2}$/, `${f.name}: lang is a language code`);
    if (f.region) assert.ok(REGIONS.has(f.region), `${f.name}: region ${f.region}`);
    assert.ok(/^\d{4}-\d{2}-\d{2}$/.test(f.added || "") && f.why, `${f.name}: added and why`);
  }
  assert.equal(extraFeeds(ALL_CFG).length, ALL_CFG.feeds.length, "every extra feed is collected (none repeats a built-in one or another shard, or passes the cap)");
});

// normalised host and path: the same feed under www. or with a trailing slash is still the same feed
const feedKey = (u) => { const x = new URL(u); return `${x.hostname.replace(/^www\./, "")}${x.pathname.replace(/\/$/, "")}${x.search}`; };
// hosts whose robots.txt disallows the feed (for every reader, or for ClaudeBot or anthropic-ai), recorded by the regional
// source research of 2026-11-20; a feed from one of them is never added, however good its items
const ROBOTS_DISALLOWED = new Set(["3news.com", "4hou.com", "agenceecofin.com", "aljazeera.com", "antaranews.com", "aps.sn", "baguete.com.br",
  "beckershospitalreview.com", "bernama.com", "brecorder.com", "ciokorea.com", "civil.ge", "connectingafrica.com", "cumhuriyet.com.tr", "dawn.com",
  "eluniversal.com.mx", "eluniverso.com", "emol.com", "en.yna.co.kr", "english.ahram.org.eg", "estadao.com.br", "eurasianet.org", "fayerwayer.com",
  "feeds.folha.uol.com.br", "feeds.japan.zdnet.com", "focustaiwan.tw", "fortinet.com", "gulf-times.com", "gulfbusiness.com", "haaretz.com", "health-isac.org",
  "healthcareinfosecurity.com", "healthcareittoday.com", "htxt.co.za", "hurriyet.com.tr", "innovationaus.com", "investiraucameroun.com", "iol.co.za",
  "iranwire.com", "jornada.com.mx", "kenyans.co.ke", "khaleejtimes.com", "kun.uz", "kuwaittimes.com", "mobiletime.com.br", "monitor.co.ug", "myjoyonline.com",
  "nation.africa", "news24.com", "newtimes.co.rw", "nhk.or.jp", "www3.nhk.or.jp", "nsm.no", "ntv.com.tr", "olhardigital.com.br", "portafolio.co", "radiofarda.com",
  "railjournal.com", "rappler.com", "rss.uol.com.br", "sabq.org", "seneweb.com", "smart-energy.com", "taipeitimes.com", "technews.tw", "tekno.kompas.com",
  "teletime.com.br", "thecable.ng", "thehindu.com", "thereporterethiopia.com", "tiinside.com.br", "webrazzi.com", "xtech.nikkei.com", "ynetnews.com",
  // the regional coverage research of 2026-11-21
  "addisfortune.news", "cert.ncc.gov.ng", "france24.com", "jeuneafrique.com", "latercera.com", "lemonde.fr", "lorientlejour.com", "maroelamedia.co.za",
  "milliyet.com.tr", "ncsc.jo", "rfi.fr", "stabroeknews.com", "techeconomy.ng", "tecnoblog.net", "trinidadexpress.com", "tynmagazine.com"]);

test("no two feeds read the same host and path, and none comes from a host whose robots.txt disallows it", () => {
  const all = activeFeeds(ALL_CFG), keys = all.map((f) => feedKey(f.url));
  const names = all.map((f) => f.name.toLowerCase());
  assert.deepEqual(names.filter((n, i) => names.indexOf(n) !== i), [], "the same name twice");
  assert.deepEqual(keys.filter((k, i) => keys.indexOf(k) !== i), [], "the same feed twice");
  assert.deepEqual(all.filter((f) => ROBOTS_DISALLOWED.has(new URL(f.url).hostname.replace(/^www\./, ""))).map((f) => f.name), []);
});

test("the fifth batch: every new feed has an ISO language, a known region and a tier, and per-CVE advisory feeds are tagged", () => {
  const byName = new Map(FEEDS.map((f) => [f.name, f]));
  for (const [name, lang, region] of [["UzCERT (Uzbekistan)", "uz", "middle-east"], ["Iran International (Persian)", "fa", "middle-east"],
    ["Walla Tech (Israel)", "he", "middle-east"], ["Amar Ujala technology (India)", "hi", "south-asia"], ["NKI Hungary news", "hu", "europe"],
    ["RIA (Estonia)", "et", "europe"], ["CERT-PY (Paraguay)", "es", "latin-america"], ["ANCS Tunisia", "fr", "africa"], ["piyolog (Japan)", "ja", "east-asia"]]) {
    const f = byName.get(name);
    assert.ok(f, name);
    assert.equal(f.lang, lang, name); assert.equal(f.region, region, name);
  }
  for (const n of ["Synology security advisories", "Moxa security advisories", "SolarWinds security advisories", "ABB PSIRT", "CERT@VDE"]) assert.equal(byName.get(n).kind, "cve", n);
  // broad general-news feeds only ever add cyber items
  for (const n of ["Nile Post (Uganda)", "Asharq Al-Awsat (Arabic)", "G1 tecnologia (Brazil)", "CNN Indonesia teknologi"]) assert.equal(byName.get(n).filter, true, n);
});

test("a lead's language is an ISO 639-1 code or nothing, never a language name or a region", async () => {
  const { gdeltLang, parseGdelt } = await import("../../scripts/osint.mjs");
  assert.equal(gdeltLang("Spanish"), "es");
  assert.equal(gdeltLang("Swahili"), "sw");
  assert.equal(gdeltLang("Klingon"), "", "an unmapped name is dropped, not passed on");
  assert.equal(parseGdelt({ articles: [{ url: "https://a.example/x", title: "Ataque", seendate: "20261118T101500Z", domain: "a.example", language: "Hungarian" }] })[0].lang, "hu");
});
