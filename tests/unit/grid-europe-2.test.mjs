// Unit tests for the second European grid lane (scripts/grid-sources/europe-2.mjs; node --test, no dependencies).
// Fixtures in tests/fixtures/grid/europe-2/ are real replies saved 2026-11-24 (Lvivoblenergo's Today / Tomorrow menu
// items, Khmelnytskoblenergo's schedule page and Rivneoblenergo's schedule table trimmed to the schedule, Elenia's
// outage table). Synthetic variants are built inside the tests and say so.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { ADAPTERS, PLUGIN_ERRORS, SOURCES, REGIONS, checkItem, zonedToIso, str } from "../../scripts/grid.mjs";
import eu2, {
  parseLoe, parseHoe, parseRoe, parseElenia, ranges, mergeRanges, LOE_REGION, HOE_REGION, ROE_REGION, ELENIA_REGION,
} from "../../scripts/grid-sources/europe-2.mjs";

const FX = join(dirname(fileURLToPath(import.meta.url)), "..", "fixtures", "grid", "europe-2");
const txt = (f) => readFileSync(join(FX, f), "utf8");
const json = (f) => JSON.parse(txt(f));
const isoOf = (s) => { const t = Date.parse(s || ""); return isFinite(t) ? new Date(Math.floor(t / 1000) * 1000).toISOString().replace(".000Z", "Z") : ""; };
const h = { item: (o) => o, str, isoOf, zonedToIso };
// 00:00 Kyiv time on 24 November 2026: the fixtures' own day starts
const NOW = Date.parse("2026-11-23T22:00:00Z");

const realFetch = globalThis.fetch, realNow = Date.now;
after(() => { globalThis.fetch = realFetch; Date.now = realNow; });
function serve(bodies, seen = []) {
  let i = 0;
  globalThis.fetch = async (url, opts) => {
    seen.push({ url: String(url), headers: (opts && opts.headers) || {} });
    const b = Array.isArray(bodies) ? bodies[Math.min(i++, bodies.length - 1)] : bodies;
    return new Response(b, { status: 200 });
  };
  return seen;
}
async function viaAdapter(k, bodies) {
  Date.now = () => NOW;
  try {
    const seen = serve(bodies);
    const items = await ADAPTERS[k]();
    for (const x of items) assert.deepEqual(checkItem(x), [], `${k} ${x.id}`);
    for (const s of seen) assert.ok(SOURCES[k].hosts.includes(new URL(s.url).host) || new URL(s.url).host === new URL(SOURCES[k].url).host, s.url);
    return items;
  } finally { Date.now = realNow; }
}
const scheduleShape = (x, src, region) => {
  assert.equal(x.source, src); assert.equal(x.region, region);
  assert.equal(x.kind, "load_shedding"); assert.equal(x.planned, true);
  assert.equal(x.customers, null); assert.equal(x.level, null);
  assert.match(x.started_at, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/); assert.match(x.restore_est, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
  assert.ok(Date.parse(x.restore_est) > Date.parse(x.started_at), x.id);
  assert.ok(!/attack/i.test(x.cause + x.area), x.id);
};

test("europe-2.mjs loads with no plugin errors and every source has the README shape", () => {
  assert.deepEqual(PLUGIN_ERRORS.filter((e) => e.startsWith("europe-2.mjs")), []);
  for (const [k, s] of Object.entries(eu2.sources)) {
    assert.equal(SOURCES[k].file, "europe-2.mjs", k);
    for (const f of ["name", "country", "url", "page", "hosts", "terms_url", "terms_ok"]) assert.ok(s[f], `${k}.${f}`);
    assert.ok("customers_served" in s, k);
    assert.match(s.url, /^https:\/\//); assert.match(s.page, /^https:\/\//);
    assert.ok(s.hosts.includes(new URL(s.page).host), `${k}: page on its own hosts`);
    assert.ok(s.hosts.includes(new URL(s.url).host), `${k}: feed on its own hosts`);
    assert.ok(["allowed", "silent"].includes(s.terms_ok), k);
    assert.equal(typeof eu2.adapters[k], "function", k);
  }
  assert.equal(SOURCES["elenia-katkokartta"].customers_served, 442000);
  for (const rk of Object.keys(eu2.regions)) assert.ok(REGIONS[rk], rk);
});

test("interval helpers: ranges read both dash styles and 'з .. до', merge unions overlaps and keeps the addition flag", () => {
  assert.deepEqual(ranges("04:00-07:00; 12:00-16:00"), [[240, 420], [720, 960]]);
  assert.deepEqual(ranges("з 22:00 до 24:00"), [[1320, 1440]]);
  assert.deepEqual(ranges("22:00 - 23:59"), [[1320, 1439]]);
  assert.deepEqual(ranges("без відключень"), []);
  assert.deepEqual(mergeRanges([[600, 840, false], [480, 720, true], [900, 960, true]]), [[480, 840, false], [900, 960, true]]);
});

// ---------- Lvivoblenergo ----------
test("LOE: one item per group interval, Kyiv times, data time from 'Інформація станом на'", () => {
  const items = parseLoe(json("loe-today.json"), h, NOW);
  assert.equal(items.length, 8); // 12 groups, 4 with "Електроенергія є"
  assert.equal(items.data_at, "2026-11-23T17:44:00Z");
  for (const x of items) scheduleShape(x, "loe-gpv", LOE_REGION);
  const g11 = items.find((x) => x.id === "loe-gpv:2026-11-24-1.1-0800");
  assert.equal(g11.area, "Lviv oblast, group 1.1");
  assert.equal(g11.cause, "Hourly outage schedule (Графік погодинних відключень), group 1.1");
  assert.equal(g11.started_at, "2026-11-24T06:00:00Z"); assert.equal(g11.restore_est, "2026-11-24T10:30:00Z");
  assert.equal(g11.url, "https://poweron.loe.lviv.ua/");
  // "до 24:00" ends at midnight Kyiv
  assert.equal(items.find((x) => x.id === "loe-gpv:2026-11-24-2.1-2200").restore_est, "2026-11-24T22:00:00Z");
  assert.ok(!items.some((x) => /group (2\.2|3\.1|4\.1|4\.2)$/.test(x.area)), "groups with power have no item");
  // intervals that have ended are dropped
  assert.equal(parseLoe(json("loe-today.json"), h, Date.parse("2026-11-24T21:00:00Z")).length, 1);
  // Tomorrow, not yet published: empty rawHtml -> no items, not an error
  assert.deepEqual([...parseLoe(json("loe-tomorrow.json"), h, NOW)], []);
  assert.throws(() => parseLoe({ hydra: [] }, h, NOW), { code: "bad_shape" });
  assert.throws(() => parseLoe({ rawHtml: "<p>щось інше</p>" }, h, NOW), { code: "bad_shape" });
});

test("LOE adapter: Today and Tomorrow through grid.mjs pass checkItem", async () => {
  const items = await viaAdapter("loe-gpv", [txt("loe-today.json"), txt("loe-tomorrow.json")]);
  assert.equal(items.length, 8);
  assert.equal(items.data_at, "2026-11-23T17:44:00Z");
  assert.ok(items.every((x) => x.country === "UA" && x.lat === null && x.url === "https://poweron.loe.lviv.ua/"));
});

// ---------- Khmelnytskoblenergo ----------
test("HOE: newest full schedule per day plus later additions, merged; additions say so", () => {
  const items = parseHoe(txt("hoe.html"), h, NOW);
  for (const x of items) scheduleShape(x, "hoe-gpv", HOE_REGION);
  assert.equal(items.length, 31);
  const a = items.find((x) => x.id === "hoe-gpv:2026-11-24-1.1-0400");
  assert.equal(a.area, "Khmelnytskyi oblast, subqueue 1.1");
  assert.equal(a.cause, "Hourly outage schedule (ГПВ) ordered by NEK Ukrenergo, subqueue 1.1");
  assert.equal(a.started_at, "2026-11-24T02:00:00Z"); assert.equal(a.restore_est, "2026-11-24T05:00:00Z");
  assert.equal(a.url, "https://hoe.com.ua/page/pogodinni-vidkljuchennja");
  // the 23:20 addition "Підчерга 5.2 – 01:00-04:00" on top of the 24.11 schedule (10:00-14:00; 17:00-20:00)
  const add = items.find((x) => x.id === "hoe-gpv:2026-11-24-5.2-0100");
  assert.match(add.cause, /subqueue 5\.2 \(additional hours\)$/);
  assert.equal(add.restore_est, "2026-11-24T02:00:00Z");
  assert.ok(!/additional/.test(items.find((x) => x.id === "hoe-gpv:2026-11-24-5.2-1000").cause));
  // 6.2: addition 00:00-01:00 plus schedule 10:00-14:00; 18:00-22:00
  assert.deepEqual(items.filter((x) => / 6\.2$/.test(x.area)).map((x) => x.id.split("-").pop()), ["0000", "1000", "1800"]);
  // a day earlier, the 23 November notices apply: the 20:00 replacement (no "Години" line) wins over the 11:00 one, and the
  // 21:30 additions are added to it
  const d23 = parseHoe(txt("hoe.html"), h, Date.parse("2026-11-23T17:30:00Z")).filter((x) => x.id.includes("2026-11-23"));
  const g21 = d23.filter((x) => / 2\.1$/.test(x.area));
  assert.deepEqual(g21.map((x) => [x.started_at, x.restore_est]), [["2026-11-23T19:00:00Z", "2026-11-23T22:00:00Z"]]);
  const g52 = d23.find((x) => / 5\.2$/.test(x.area));
  assert.equal(g52.started_at, "2026-11-23T20:00:00Z"); assert.match(g52.cause, /additional hours/);
  assert.throws(() => parseHoe("<html><body>no post</body></html>", h, NOW), { code: "bad_shape" });
  assert.throws(() => parseHoe('<div class="post"><p>Новини</p></div>', h, NOW), { code: "bad_shape" });
});

test("HOE adapter through grid.mjs passes checkItem", async () => {
  const items = await viaAdapter("hoe-gpv", txt("hoe.html"));
  assert.equal(items.length, 31);
});

// ---------- Rivneoblenergo ----------
test("ROE: table cells by subqueue, empty and 'Очікується' cells give nothing, data time from 'Оновлено'", () => {
  const items = parseRoe(txt("roe.html"), h, NOW);
  for (const x of items) scheduleShape(x, "roe-gpv", ROE_REGION);
  assert.equal(items.length, 10); // 24.11: 12 subqueues, 3.1 and 3.2 empty; 25.11 all "Очікується"
  assert.equal(items.data_at, "2026-11-24T06:00:00Z");
  const a = items.find((x) => x.id === "roe-gpv:2026-11-24-1.1-2200");
  assert.equal(a.area, "Rivne oblast, subqueue 1.1"); assert.equal(a.cause, "Hourly outage schedule (ГПВ), subqueue 1.1");
  assert.equal(a.started_at, "2026-11-24T20:00:00Z"); assert.equal(a.restore_est, "2026-11-24T21:59:00Z");
  assert.equal(a.url, "https://www.roe.vsei.ua/disconnections");
  assert.equal(items.find((x) => x.id === "roe-gpv:2026-11-24-6.2-0800").restore_est, "2026-11-24T09:00:00Z");
  assert.ok(!items.some((x) => x.id.includes("2026-11-25")));
  assert.ok(!items.some((x) => / 3\.[12]$/.test(x.area)));
  assert.throws(() => parseRoe("<html></html>", h, NOW), { code: "bad_shape" });
});

test("ROE adapter through grid.mjs passes checkItem", async () => {
  assert.equal((await viaAdapter("roe-gpv", txt("roe.html"))).length, 10);
});

// ---------- Elenia ----------
test("Elenia: one item per municipality and type with customers, outage count in the cause", () => {
  const items = parseElenia(json("elenia-table.json"), h);
  assert.equal(items.length, 2);
  const x = items.find((i) => i.id === "elenia-katkokartta:Itä-Häme-Hartola-fault");
  assert.equal(x.customers, 2); assert.equal(x.planned, false); assert.equal(x.kind, "outage");
  assert.equal(x.area, "Hartola (Itä-Häme)"); assert.equal(x.region, ELENIA_REGION);
  assert.equal(x.cause, "Ongoing faults (Viat), outages: 1");
  assert.equal(x.started_at, ""); assert.equal(x.restore_est, ""); assert.equal(x.url, "https://katkokartta.elenia.fi/kartta/");
  assert.equal(items.find((i) => i.area === "Sysmä (Itä-Häme)").customers, 1);
  // synthetic: a planned outage row is planned true
  const d = json("elenia-table.json");
  d.p.mainAreas[0].areas[0].planrunning = { customers: "40", nr: "2" };
  const p = parseElenia(d, h).find((i) => i.id.endsWith("Hartola-plan"));
  assert.equal(p.planned, true); assert.equal(p.customers, 40); assert.equal(p.cause, "Ongoing planned outages (Huollot), outages: 2");
  assert.throws(() => parseElenia({ p: {} }, h), { code: "bad_shape" });
});

test("Elenia adapter through grid.mjs passes checkItem", async () => {
  const items = await viaAdapter("elenia-katkokartta", txt("elenia-table.json"));
  assert.equal(items.length, 2);
  assert.ok(items.every((x) => x.country === "FI"));
});
