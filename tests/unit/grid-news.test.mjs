// Unit tests for power outages from news reporting (scripts/grid-news.mjs; node --test, no dependencies).
// tests/fixtures/grid/news/ holds real Bing News and Google News RSS replies saved once on 2026-11-20 (bing-ar-eg.xml is
// the HTML page Bing sent instead of a feed); the other inputs are headlines written here in the shapes the indexes return.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  classify, figure, figures, parseCount, causeWords, gazetteer, locate, publisherUrl, resolveGoogle, toReport, assess, group,
  checkNews, newsLeads, parseBing, loadConfig, langCode, fold, asciiDigits, splitAlternatives, UNITS,
} from "../../scripts/grid-news.mjs";
import { parseGoogleNews } from "../../scripts/osint.mjs";
import { corroborate } from "../../scripts/grid-analysis.mjs";

const FIX = join(dirname(fileURLToPath(import.meta.url)), "..", "fixtures", "grid", "news");
const fx = (f) => readFileSync(join(FIX, f), "utf8");
const CFG = loadConfig();
const ENTS = gazetteer(CFG);
const NOW = Date.parse("2026-11-20T00:30:00Z");
const H = 3600e3;
const iso = (t) => new Date(t).toISOString().replace(/\.\d+Z$/, "Z");

test("config: many languages, countries and utilities; every place and utility has a valid centre", () => {
  assert.ok(CFG.queries.length >= 100, `${CFG.queries.length} queries`);
  const langs = new Set(CFG.queries.map((q) => q.hl.split("-")[0]));
  for (const l of ["en", "fr", "es", "pt", "de", "it", "nl", "pl", "uk", "ru", "tr", "ar", "hi", "ur", "bn", "id", "ja", "ko", "zh", "vi", "sw"]) assert.ok(langs.has(l), `no ${l} query`);
  for (const u of ["Hydro One", "Toronto Hydro", "Georgia Power", "Oncor", "DTE", "PG&E", "Con Edison", "ComEd", "PECO", "AEP", "Duke Energy", "FPL", "Dominion Energy", "Entergy", "CenterPoint", "Ausgrid", "Energex", "Hydro Ottawa", "NIE Networks", "Enedis", "i-DE", "e-distribuzione", "東京電力"])
    assert.ok(CFG.queries.some((q) => q.q.includes(u)), `no query for ${u}`);
  for (const p of CFG.places) assert.ok(/^[A-Z]{2}$/.test(p[1]) && Math.abs(p[2]) <= 90 && Math.abs(p[3]) <= 180 && ["city", "region"].includes(p[4]), JSON.stringify(p));
  for (const u of CFG.utilities) assert.ok(/^[A-Z]{2}$/.test(u[1]) && Math.abs(u[3]) <= 90 && Math.abs(u[4]) <= 180, JSON.stringify(u));
  assert.ok(ENTS.length > 900);
});

test("text helpers: folding, other digits, alternatives split at the top level only", () => {
  assert.equal(fold("Apagón ÉLECTRIQUE"), "apagon electrique");
  assert.equal(asciiDigits("١٢٠ ألف و ३ लाख"), "120 ألف و 3 लाख");
  assert.deepEqual(splitAlternatives("a|(b|c)|[|]d|停電"), ["a", "(b|c)", "[|]d", "停電"]);
  assert.equal(langCode("en-US"), "en"); assert.equal(langCode("Spanish"), "es"); assert.equal(langCode("Klingon"), "");
});

test("classify: current power outages in many languages are kept", () => {
  for (const t of [
    "120,000 without power as storm hits Ontario", "Power cut leaves thousands in the dark in Glasgow", "Load shedding returns: Eskom moves to stage 4",
    "Apagón deja sin luz a 10.000 clientes en Valencia", "Coupure de courant : 2 900 clients privés d'électricité à Angers", "Stromausfall in Berlin-Köpenick: 30.000 Haushalte ohne Strom",
    "Apagão atinge São Paulo e deixa 2 milhões sem luz", "Blackout elettrico a Palermo, migliaia senza corrente", "Stroomstoring in Utrecht: duizenden huishoudens zonder stroom",
    "Awaria prądu we Wrocławiu. Tysiące odbiorców bez prądu", "Через атаку дронів у Києві знеструмлення", "В Белгороде отключение электричества после обстрела",
    "İstanbul'da elektrik kesintisi: binlerce abone etkilendi", "انقطاع الكهرباء عن مناطق واسعة في بغداد", "लखनऊ में घंटों बिजली गुल, लोग परेशान",
    "کراچی میں بجلی بند، شہری پریشان", "ঢাকায় লোডশেডিং, ভোগান্তি", "Pemadaman listrik melanda Jakarta", "秋田で約100軒停電中 降雪の影響",
    "서울 강남 일대 정전 3천 가구 피해", "台北大停電 數萬戶受影響", "Mất điện diện rộng tại Hà Nội", "Kukatika kwa umeme Nairobi kwaathiri wakazi",
    "Oncor outage leaves 40,000 customers in the dark",
  ]) assert.ok(classify(t, "", { utility: /Oncor/.test(t) }).ok, `${t} -> ${classify(t).reason}`);
});

test("classify: false-positive guards fire with their reason", () => {
  const cases = [
    ["AWS outage takes down thousands of websites", "no_power_words"],
    ["Microsoft 365 outage: Outlook and Teams down for users", "no_power_words"],
    ["Internet blackout in Iran enters third day", "not_grid"],
    ["Apagón digital: la TDT deja de emitir en analógico", "not_grid"],
    ["NFL blackout rules: why the game is not on TV", "not_grid"],
    ["Call of Duty Blackout map returns in Warzone", "not_grid"],
    ["Blackout: the new Netflix thriller everyone is watching", "entertainment"],
    ["Utility shares fall after power outage earnings miss", "market"],
    ["PG&E stock drops as investors weigh outage costs", "market", { utility: true }],
    ["Best generators for a power outage: Black Friday deals", "product"],
    ["Planned power outage in Munster on Friday morning", "planned"],
    ["Corte de luz programado este sábado en Lima", "planned"],
    ["Geplante Stromabschaltung in Dresden am Montag", "planned"],
    ["Debunking the viral claim of a 90-day blackout", "explainer"],
    ["What to do in a power outage: food safety tips", "explainer"],
    ["Apagão mundial: entenda a teoria conspiratória", "explainer"],
    ["One year after the Iberian blackout, lessons from the grid", "past"],
    ["Aniversario del apagón: hace un año España se quedó sin luz", "past"],
    ["Storm could leave 100,000 without power, utility warns", "future"],
    ["Eskom suspends load shedding for the weekend", "none_now"],
    ["Sponsored: Power outage protection and energy savings", "ad"],
    ["Is a blackout coming to Texas this week?", "question"],
    ["정전협정 73주년 기념식 열려", "no_power_words"],
    ["Water outage in Spartanburg County after main breaks", "no_power_words"],
    ["Διακοπή ρεύματος την Τρίτη και την Πέμπτη – Δείτε που", "planned"],
    ["Corte de luz en Santiago HOY, jueves 19 de noviembre: Enel confirma interrupción del servicio", "planned"],
    ["¿Michoacán se quedará sin luz este sábado? Estos son los municipios", "question"],
    ["Сонячні панелі взимку: чи врятують українців від блекаутів", "explainer"],
  ];
  const fired = {};
  for (const [t, why, o] of cases) { const c = classify(t, "", o); assert.equal(c.ok, false, t); assert.equal(c.reason, why, `${t}: ${c.reason}`); fired[why] = (fired[why] || 0) + 1; }
  assert.ok(Object.keys(fired).length >= 12);
});

test("classify: a cyberattack in a headline is flagged (shown as the headline's words, reported, not confirmed)", () => {
  const c = classify("Cyberattack blamed for blackout in western Ukraine, officials say");
  assert.ok(c.ok && c.cyber);
  assert.equal(classify("Storm knocks out power to 20,000 in Texas").cyber, false);
});

test("figures: the number as reported, with its unit, never converted", () => {
  assert.deepEqual(figure("120,000 without power as storm hits Ontario"), { n: 120000, unit: "unstated" });
  assert.deepEqual(figure("Apagón deja sin luz a 10.000 clientes en Valencia"), { n: 10000, unit: "customers" });
  assert.deepEqual(figure("Аварія: 3 млн абонентів без світла"), { n: 3000000, unit: "customers" });
  assert.deepEqual(figure("Storm leaves 1.2 million homes without power"), { n: 1200000, unit: "homes" });
  assert.deepEqual(figure("Blackout leaves 120,000 people in the dark"), { n: 120000, unit: "people" });
  assert.deepEqual(figure("Coupure : 2 900 clients privés de courant à Angers"), { n: 2900, unit: "customers" });
  assert.deepEqual(figure("Panne : les 160.000 foyers touchés ont été réalimentés"), { n: 160000, unit: "homes" });
  assert.deepEqual(figure("More than 120,000 Hydro One customers without power"), { n: 120000, unit: "customers" });
  assert.deepEqual(figure("Washoe County power outages drop to 650+ customers"), { n: 650, unit: "customers" });
  assert.deepEqual(figure("秋田で約1万2000戸が停電"), { n: 12000, unit: "homes" });
  assert.deepEqual(figure("鹿角市八幡平の約100軒停電中"), { n: 100, unit: "homes" });
  assert.deepEqual(figure("서울 정전 3만 가구 피해"), { n: 30000, unit: "homes" });
  assert.deepEqual(figure("انقطاع الكهرباء عن ١٢٠ ألف مشترك"), { n: 120000, unit: "customers" });
  assert.deepEqual(figure("Storm kills 3 people, leaves 50,000 customers without power"), { n: 50000, unit: "customers" });
  assert.equal(figure("40% of customers lost power in the storm"), null);
  assert.equal(figure("Utility to pay $5 million to customers"), null);
  assert.equal(figure("Power outage hits downtown"), null);
  // a summary's figure counts only near the power words
  assert.equal(figure("Power cut in Leeds", "Meanwhile 4 people were at the cinema. Unrelated."), null);
  assert.deepEqual(figure("Power cut in Leeds", "Northern Powergrid said 3,400 customers were without power after a fault."), { n: 3400, unit: "customers" });
  assert.equal(parseCount("1,5", "млн"), 1500000); assert.equal(parseCount("10 000"), 10000); assert.equal(parseCount("2.5"), 3);
  assert.ok(figures("2 lakh consumers without power in Patna").length === 0 || figures("2 lakh customers without power").some((f) => f.n === 200000));
  assert.deepEqual(UNITS, ["customers", "homes", "people", "unstated"]);
});

test("cause words: as reported, translated not inferred; a cyberattack is not also counted as an attack", () => {
  assert.deepEqual(causeWords("Storm and high winds knock out power in Halifax"), ["storm", "wind"]);
  assert.deepEqual(causeWords("Rayo provoca corte de luz en Quito"), ["lightning"]);
  assert.deepEqual(causeWords("Cyberattack blamed for blackout"), ["cyberattack"]);
  assert.ok(causeWords("Russian missile and drone attack leaves Kyiv without power").includes("attack"));
  assert.ok(!causeWords("Lightning strike knocks out power in Tampa").includes("strike"));
  assert.ok(causeWords("Eskom load shedding stage 6").includes("load shedding"));
  assert.deepEqual(causeWords("Power outage in Castleford restored"), []);
  assert.ok(causeWords("鹿角市八幡平の約100軒停電中 降雪の影響").includes("snow"));
});

test("locate: gazetteer, utility service area, country; the most specific place wins", () => {
  const at = (t, s = "") => { const l = locate(t, s, ENTS); return l ? `${l.place}|${l.country}|${l.how}` : null; };
  assert.equal(at("Oncor outage leaves 40,000 customers in the dark"), "North and Central Texas|US|utility");
  assert.equal(at("Oncor outage hits Dallas"), "Dallas|US|place");
  assert.equal(at("Georgia Power restores service after storm"), "Georgia|US|utility");
  assert.equal(at("Power cut across Northern Ireland"), "Northern Ireland|GB|place");
  assert.equal(at("Outage in New Mexico"), "New Mexico|US|place");
  assert.equal(at("In Zaporizhzhia, 7,500 customers were left without power due to Russian shelling"), "Zaporizhzhia|UA|place");
  assert.equal(at("Cuba's national grid collapses"), "Cuba|CU|country");
  assert.equal(at("Russia has left consumers in five regions of Ukraine without power"), "Ukraine|UA|country", "the country after 'of' is where the outage is");
  assert.equal(at("Apagón en Valencia, Venezuela"), "Venezuela|VE|country");
  assert.equal(at("Знеструмлення у Києві після атаки"), "Kyiv|UA|place");
  assert.equal(at("秋田で停電"), "Akita|JP|place");
  assert.equal(at("広島市中区の一部地域で停電発生", "中国電力ネットワークによると"), "Hiroshima|JP|place", "中国 in 中国電力 is Japan's Chugoku region, not China");
  assert.equal(at("انقطاع الكهرباء في بغداد"), "Baghdad|IQ|place");
  assert.equal(at("Power outage hits downtown", "Crews in Toronto restored power."), "Toronto|CA|place");
  assert.equal(at("Power outage hits downtown"), null);
  assert.equal(at("Une panne de courant prive une commune"), null, "French 'une' is not a utility");
  const l = locate("Power cut in Glasgow", "", ENTS);
  assert.ok(Math.abs(l.lat - 55.86) < 0.01 && Math.abs(l.lng + 4.25) < 0.01);
});

test("publisher pages only: no aggregator, redirect, plain http or front page", () => {
  assert.equal(publisherUrl("https://www.kmvt.com/2026/11/19/power-outage-castleford/"), "https://www.kmvt.com/2026/11/19/power-outage-castleford/");
  for (const u of ["https://news.google.com/rss/articles/CBMi123?oc=5", "https://www.bing.com/news/apiclick.aspx?url=x", "https://www.msn.com/en-us/news/ar-AA1",
    "http://www.kmvt.com/2026/11/19/x", "https://www.pbs.org", "https://www.pbs.org/", "https://user:pw@example.com/a", "javascript:alert(1)", ""])
    assert.equal(publisherUrl(u), "", u);
});

test("Google News: a headline is kept only when Bing returns it on the publisher's own host", () => {
  const g = { title: "Power outage in Castleford affects about 220 people", source: "KMVT", publisher_url: "https://www.kmvt.com" };
  const r = resolveGoogle(g, [{ title: "Power outage in Castleford affects about 220 people", url: "https://www.kmvt.com/2026/11/19/power-outage-castleford-affects-about-220-people/" }]);
  assert.equal(r.url, "https://www.kmvt.com/2026/11/19/power-outage-castleford-affects-about-220-people/");
  assert.equal(resolveGoogle(g, [{ title: g.title, url: "https://www.msn.com/en-us/news/ar-AA1" }]), null);
  assert.equal(resolveGoogle(g, [{ title: g.title, url: "https://other.example/2026/x" }]), null);
  assert.equal(resolveGoogle(g, [{ title: "Something else entirely about power", url: "https://www.kmvt.com/2026/11/19/y" }]), null);
  // the real Google News reply links only to news.google.com: none of it is kept as it is
  const items = parseGoogleNews(fx("google-en-us.xml"));
  assert.ok(items.length > 50);
  assert.ok(items.every((i) => !toReport({ title: i.title, url: i.url, name: i.source, published: i.published }, ENTS, NOW).ok));
  assert.ok(items.every((i) => toReport({ title: i.title, url: i.url, name: i.source, published: i.published }, ENTS, NOW).reason === "no_publisher_page"));
});

test("real Bing replies: publishers named, own pages, outages found and noise rejected", () => {
  const bing = (f) => parseBing(fx(f));
  assert.deepEqual(bing("bing-ar-eg.xml"), [], "an HTML page instead of a feed gives nothing");
  const us = bing("bing-en-us.xml");
  assert.ok(us.length >= 5 && us.every((i) => i.name && /^https:\/\//.test(i.url)));
  const rep = (i) => toReport({ title: i.title, summary: i.summary, url: i.url, name: i.name, published: i.published, lang: "en" }, ENTS, NOW);
  const up = us.find((i) => /UPPCO outage map/.test(i.title)), r = rep(up);
  assert.ok(r.ok, r.reason); assert.equal(r.report.place, "Upper Michigan"); assert.deepEqual(r.report.figure, { n: 5000, unit: "customers" });
  assert.equal(r.report.name, "Upper Michigan's Source");
  assert.equal(rep(us.find((i) => /90-day blackout/.test(i.title))).reason, "explainer");
  const mx = bing("bing-es-mx.xml").map(rep);
  assert.ok(mx.every((x) => !x.ok), "the 'world blackout' hoax and announced cuts are all rejected");
  const ja = bing("bing-ja-jp.xml").map(rep).filter((x) => x.ok).map((x) => x.report);
  assert.ok(ja.some((x) => x.place === "Akita" && x.figure && x.figure.n === 100 && x.figure.unit === "homes" && x.causes.includes("snow")));
  const de = bing("bing-de-de.xml"), jackery = de.find((i) => /Jackery/.test(i.title));
  assert.equal(assess({ title: jackery.title, summary: jackery.summary, name: jackery.name, published: jackery.published }, ENTS, NOW).reason, "product");
  const pt = bing("bing-pt-br.xml").map(rep);
  assert.ok(pt.filter((x) => x.ok).length <= 1, "Brazil's 'apagão mundial' rumour pieces are rejected");
  const ua = bing("bing-uk-ua.xml").map(rep).filter((x) => x.ok).map((x) => x.report);
  assert.ok(ua.some((x) => x.place === "Dnipro") && ua.some((x) => x.place === "Zaporizhzhia"));
  const fr = bing("bing-fr-fr.xml").map(rep).filter((x) => x.ok).map((x) => x.report);
  assert.ok(fr.some((x) => x.place === "Mayotte" && x.country === "YT"));
});

test("toReport: old reports and missing dates are refused", () => {
  const raw = { title: "Power cut leaves thousands in the dark in Glasgow", url: "https://www.bbc.co.uk/news/articles/x1", name: "BBC", published: iso(NOW - 2 * H) };
  assert.ok(toReport(raw, ENTS, NOW).ok);
  assert.equal(toReport({ ...raw, published: iso(NOW - 80 * H) }, ENTS, NOW).reason, "too_old");
  assert.equal(toReport({ ...raw, published: "" }, ENTS, NOW).reason, "no_date");
  assert.equal(assess({ ...raw, title: "Power cut leaves thousands in the dark" }, ENTS, NOW).reason, "no_place");
});

const rp = (o) => ({ title: "Power cut in Glasgow", url: `https://pub${o.i}.example/a/${o.i}`, name: `Publisher ${o.i}`, lang: "en", published: iso(o.t),
  country: "GB", region: "", place: o.place || "Glasgow", lat: 55.86, lng: -4.25, how: "place", utility: "", figure: o.figure || null, causes: o.causes || [], cyber: !!o.cyber });

test("group: same place within 12 h is one reported outage; more publishers, stronger", () => {
  const items = group([], [rp({ i: 1, t: NOW - 5 * H, figure: { n: 3000, unit: "customers" } }), rp({ i: 2, t: NOW - 2 * H, figure: { n: 9000, unit: "homes" }, causes: ["storm"] }),
    rp({ i: 3, t: NOW - 1 * H, causes: ["storm", "wind"], cyber: true }), rp({ i: 4, t: NOW - 30 * H }), rp({ i: 5, t: NOW - 3 * H, place: "Edinburgh" })], NOW);
  assert.equal(items.length, 3);
  const top = items[0];
  assert.equal(top.count, 3); assert.equal(top.publishers.length, 3);
  assert.equal(top.first_seen, iso(NOW - 5 * H));
  assert.deepEqual(top.figure, { n: 9000, unit: "homes", by: "Publisher 2" }, "the largest figure, with its own unit");
  assert.deepEqual(top.cause_words, ["storm", "wind"]);
  assert.equal(top.cyber_headline, "Power cut in Glasgow");
  assert.equal(top.approx, true);
  assert.match(top.id, /^gn-gb-glasgow-\d{10}$/);
  // the same publisher twice is listed once; a later run keeps the id and adds new publishers
  const again = group(items, [rp({ i: 1, t: NOW - 4 * H }), { ...rp({ i: 6, t: NOW }), name: "Publisher 1" }, rp({ i: 7, t: NOW })], NOW + H);
  const same = again.find((x) => x.id === top.id);
  assert.equal(same.count, 4); assert.ok(same.publishers.some((p) => p.name === "Publisher 7"));
  // outages older than the 72-hour window are dropped
  assert.equal(group(items, [], NOW + 80 * H).length, 0);
  assert.deepEqual(checkNews({ updated_at: iso(NOW), items: again }), []);
});

test("checkNews: shape, publisher's own https pages, units", () => {
  const good = { updated_at: iso(NOW), items: group([], [rp({ i: 1, t: NOW - H })], NOW) };
  assert.deepEqual(checkNews(good), []);
  const bad = JSON.parse(JSON.stringify(good));
  bad.items[0].publishers[0].url = "https://news.google.com/rss/articles/x"; bad.items[0].figure = { n: 5, unit: "souls" }; bad.items[0].approx = false;
  const e = checkNews(bad);
  assert.ok(e.some((x) => /own https page/.test(x)) && e.some((x) => /bad figure/.test(x)) && e.some((x) => /approx/.test(x)), e.join("; "));
  assert.deepEqual(checkNews({}), ["items must be a list"]);
});

test("grid-analysis counts the news reports as news signals for a grid incident", () => {
  const items = group([], [{ ...rp({ i: 1, t: NOW - 2 * H }), title: "Power outage hits British Columbia as storm rolls in", country: "CA", place: "British Columbia", region: "British Columbia" },
    { ...rp({ i: 2, t: NOW - H }), title: "BC Hydro: blackout across British Columbia", country: "CA", place: "British Columbia", region: "British Columbia" }], NOW);
  const leads = newsLeads({ items });
  assert.equal(leads.length, 2); assert.ok(leads.every((l) => l.via === "grid-news" && /^https:\/\//.test(l.url)));
  const inc = { id: "grid-bchydro-bc-1", source: "bchydro", country: "CA", region: "British Columbia", name: "BC Hydro: 60,000 customers without power", opened_at: iso(NOW - 3 * H), closed_at: "", url: "" };
  const c = corroborate(inc, { leads, now: NOW });
  assert.equal(c.signals.filter((s) => s.kind === "news").length, 2);
  assert.equal(c.score, 2);
  assert.deepEqual(newsLeads(null), []);
});
