// Unit tests for the "africa-mideast" grid source file (scripts/grid-sources/africa-mideast.mjs; node --test, no
// dependencies). Fixtures in tests/fixtures/grid/africa-mideast/ are real replies saved on 2026-11-24, trimmed of page
// chrome (the NMB page keeps its whole "current" tab and one resolved alert).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { zonedToIso, checkItem, PLUGIN_ERRORS, SOURCES as ALL, REGIONS as ALL_REGIONS, OPERATORS } from "../../scripts/grid.mjs";
import plugin, {
  SOURCES, REGIONS, RW_DISTRICTS, CEB_DISTRICTS, htmlText, regTime, parseReg, cebWindow, parseCeb, parseNmb,
} from "../../scripts/grid-sources/africa-mideast.mjs";

const FX = join(dirname(fileURLToPath(import.meta.url)), "..", "fixtures", "grid", "africa-mideast");
const txt = (f) => readFileSync(join(FX, f), "utf8");
const noErrors = (items) => items.forEach((x) => {
  assert.deepEqual(checkItem(x), [], x.id);
  assert.ok(REGIONS[`${x.source}|${x.region}`], `${x.id} region ${x.region}`);
});

test("africa-mideast: the file loads into grid.mjs with every source, adapter and region", () => {
  assert.deepEqual(PLUGIN_ERRORS.filter((e) => e.startsWith("africa-mideast.mjs")), []);
  for (const k of Object.keys(SOURCES)) {
    assert.equal(ALL[k].file, "africa-mideast.mjs", k);
    assert.ok(OPERATORS.includes(k), k);
    assert.equal(typeof plugin.adapters[k], "function", k);
    for (const f of ["name", "country", "url", "page", "terms_url", "terms_ok"]) assert.ok(SOURCES[k][f], `${k}.${f}`);
    assert.ok(["allowed", "silent"].includes(SOURCES[k].terms_ok), k);
    assert.ok(SOURCES[k].hosts.includes(new URL(SOURCES[k].page).host), `${k} page on its own host`);
    assert.ok(SOURCES[k].hosts.includes(new URL(SOURCES[k].url).host), `${k} url on its own host`);
  }
  for (const k of Object.keys(REGIONS)) assert.ok(ALL_REGIONS[k], k);
  assert.equal(Object.keys(RW_DISTRICTS).length, 30);
  assert.equal(Object.keys(CEB_DISTRICTS).length, 10);
  assert.match(SOURCES["nmb-electricity"].attribution, /Nelson Mandela Bay Municipality.*non-commercial/);
});

test("htmlText: tags, line breaks and entities", () => {
  assert.equal(htmlText("&quot;Master steel&quot; feeder &amp; more<br>next&nbsp;line"), '"Master steel" feeder & more\nnext line');
  assert.equal(htmlText("<p>a</p><p>b &#8211; &#x2014;</p>"), "a\nb – —");
});

test("REG Rwanda: scheduled notices with times, feeder, districts and the notice page", () => {
  assert.equal(regTime("25 Nov 2026, 12:00 CAT", zonedToIso), "2026-11-25T10:00:00Z");
  assert.equal(regTime("nonsense", zonedToIso), "");
  const html = txt("reg-planned.html");
  // 24 h before the first notice (25 Nov 12:00 CAT): only it shows
  const early = parseReg(html, zonedToIso, Date.parse("2026-11-24T12:00:00Z"));
  noErrors(early);
  assert.deepEqual(early.map((x) => x.id), ["reg-rwanda:notice-1350"]);
  assert.equal(early.data_at, "2026-11-22T08:03:00Z");   // "Last updated: 22 Nov 2026, 10:03 CAT"
  const a = early[0];
  assert.equal(a.started_at, "2026-11-25T10:00:00Z");
  assert.equal(a.restore_est, "2026-11-25T12:00:00Z");
  assert.equal(a.planned, true);
  assert.equal(a.kind, "outage");
  assert.equal(a.cause, "Planned maintenance: Maintenance works");
  assert.equal(a.area, '"Master steel" feeder — Nyarugenge');
  assert.equal(a.region, "Nyarugenge");
  assert.deepEqual([a.lat, a.lng], RW_DISTRICTS.Nyarugenge);
  assert.equal(a.url, "https://www.reg.rw/outages/notice-1350");
  assert.equal(a.customers, null);
  assert.equal(a.country, "RW");
  // a week earlier nothing is near; after all ends nothing is left
  assert.equal(parseReg(html, zonedToIso, Date.parse("2026-11-18T00:00:00Z")).length, 0);
  assert.equal(parseReg(html, zonedToIso, Date.parse("2026-11-30T00:00:00Z")).length, 0);
  // 28 Nov 12:00 CAT: Rebero (28 Nov 12:00-15:00) is under way and Pylon 20 (29 Nov 11:00) starts within 24 h
  const late = parseReg(html, zonedToIso, Date.parse("2026-11-28T10:00:00Z"));
  noErrors(late);
  assert.deepEqual(late.map((x) => x.id), ["reg-rwanda:notice-1353", "reg-rwanda:notice-1354"]);
  // a transmission line across six districts sits on the country, with every district named in the area
  const line = parseReg(html, zonedToIso, Date.parse("2026-11-27T10:00:00Z")).find((x) => /Musha/.test(x.area));
  assert.equal(line.region, "Rwanda");
  assert.match(line.area, /^Transmission line "Musha-Kabarondo-Rwinkwavu-Gabiro" — Gatsibo, Kayonza, Kirehe, Ngoma, Nyagatare, Rwamagana$/);
});

test("REG Rwanda: a notice awaiting confirmation is left out; a page without the outage centre is a bad shape", () => {
  const got = parseReg(txt("reg-current.html"), zonedToIso, Date.parse("2026-11-23T11:00:00Z"));
  assert.equal(got.length, 0);
  assert.equal(got.data_at, "2026-11-22T07:07:00Z");
  assert.throws(() => parseReg("<html>maintenance</html>", zonedToIso), { code: "bad_shape" });
});

test("CEB Mauritius: planned outages by district, French date windows, locality and streets", () => {
  assert.deepEqual(cebWindow("Le dimanche 22 novembre 2026 de  08:15:00 à  17:00:00", zonedToIso),
    { start: "2026-11-22T04:15:00Z", end: "2026-11-22T13:00:00Z" });
  assert.deepEqual(cebWindow("bientôt", zonedToIso), { start: "", end: "" });
  const html = txt("ceb-outages.html");
  const items = parseCeb(html, zonedToIso, Date.parse("2026-11-22T06:00:00Z"));
  noErrors(items);
  assert.deepEqual(items.map((x) => x.region), ["Flacq", "Pamplemousses"]);
  const f = items[0];
  assert.equal(f.started_at, "2026-11-22T04:15:00Z");
  assert.equal(f.restore_est, "2026-11-22T13:00:00Z");
  assert.equal(f.planned, true);
  assert.match(f.area, /^MEDINE CAMP DE MASQUE: MEDINE dans les périmètres de la Route Royale/);
  assert.ok(f.area.length <= 120);
  assert.deepEqual([f.lat, f.lng], [CEB_DISTRICTS.flacq[1], CEB_DISTRICTS.flacq[2]]);
  assert.equal(f.cause, "");   // the page states no cause
  assert.equal(f.url, SOURCES["ceb-mauritius"].page);
  // 29 November: two Plaines Wilhems rows (CANDOS VACOAS to 17:00, PHOENIX to 16:00)
  const later = parseCeb(html, zonedToIso, Date.parse("2026-11-29T06:00:00Z"));
  noErrors(later);
  assert.deepEqual(later.map((x) => x.area.split(":")[0]), ["CANDOS VACOAS", "PHOENIX"]);
  assert.equal(later[1].restore_est, "2026-11-29T12:00:00Z");
  assert.throws(() => parseCeb("<html></html>", zonedToIso), { code: "bad_shape" });
});

test("Nelson Mandela Bay: current electricity alerts only, planned windows, tripped breakers in the operator's words", () => {
  const html = txt("nmb-alerts.html");
  const items = parseNmb(html, zonedToIso, Date.parse("2026-11-22T08:00:00Z"));
  noErrors(items);
  // water alerts and the resolved alert are left out; the Kwikkie Street shutdown (21 Nov) has ended
  assert.ok(!items.some((x) => /WATER|CHATTY|REDHOUSE|NEAL STREET|KWIKKIE/i.test(x.id + x.area)));
  assert.equal(items.filter((x) => x.planned).length, 2);
  assert.equal(items.filter((x) => !x.planned).length, 5);
  const ke = items.find((x) => x.id === "nmb-electricity:20261119-king-edward-mini-substation");
  assert.equal(ke.started_at, "2026-11-22T07:00:00Z");   // Sunday, 22 November 2026, 09:00 SAST
  assert.equal(ke.restore_est, "2026-11-22T09:00:00Z");
  assert.equal(ke.cause, "Planned power shutdown, to facilitate maintenance work");
  assert.equal(ke.area, "KING EDWARD MINI SUBSTATION: Section of King Edward Street, 7th Avenue, Newton Park, Surrounding areas");
  const walmer = items.find((x) => x.id === "nmb-electricity:20261117-walmer");
  assert.equal(walmer.cause, "Planned power shutdown, to facilitate the network conversion of six substations in the Walmer area");
  const sos = items.find((x) => x.id === "nmb-electricity:20261119-soweto-on-sea");
  assert.equal(sos.planned, false);
  assert.equal(sos.cause, "The Soweto 2 and Soweto 3 11kV circuit breakers at KwaMagxaki Main Substation have tripped.");
  assert.equal(sos.area, "SOWETO ON SEA: Soweto on Sea, Surrounding areas");
  assert.equal(sos.started_at, "");   // the alert states no start time
  assert.equal(sos.restore_est, "");
  const kf = items.find((x) => /KWAFORD/.test(x.area));
  assert.match(kf.area, /^KWAFORD & STRUANDALE SUBSTATIONS: KwaFord, New Brighton/);
  assert.ok(items.every((x) => x.region === "Nelson Mandela Bay" && x.country === "ZA" && x.customers === null));
  // an unplanned alert still listed as current a week after it was published is no longer shown
  assert.equal(parseNmb(html, zonedToIso, Date.parse("2026-11-25T00:00:00Z")).filter((x) => !x.planned).length, 3);   // 16 Nov alerts out
  assert.equal(parseNmb(html, zonedToIso, Date.parse("2026-12-01T00:00:00Z")).length, 0);
  assert.throws(() => parseNmb("<html></html>", zonedToIso), { code: "bad_shape" });
});

test("adapters: fetch with h.get and pass every item through h.item", async () => {
  const pages = {
    "https://www.reg.rw/outages/current": txt("reg-current.html"), "https://www.reg.rw/outages/planned": txt("reg-planned.html"),
    [SOURCES["ceb-mauritius"].url]: txt("ceb-outages.html"), [SOURCES["nmb-electricity"].url]: txt("nmb-alerts.html"),
  };
  const asked = [];
  const h = { get: async (u) => { asked.push(u); if (!(u in pages)) throw new Error("unexpected " + u); return pages[u]; },
    item: (x) => ({ ...x, cleaned: true }), zonedToIso, SOURCES: ALL };
  for (const k of Object.keys(SOURCES)) {
    const got = await plugin.adapters[k](h);
    assert.ok(Array.isArray(got), k);
    assert.ok(got.every((x) => x.cleaned), k);
  }
  assert.deepEqual(asked.sort(), Object.keys(pages).sort());
});
