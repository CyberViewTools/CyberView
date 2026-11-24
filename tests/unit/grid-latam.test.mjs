// Unit tests for the "latam" grid source file (scripts/grid-sources/latam.mjs; node --test, no dependencies). Fixtures in
// tests/fixtures/grid/latam/ are real replies fetched on 2026-11-24, trimmed (rows and panes cut, structure kept; each
// file's first line says what was kept). Other clocks than NOW are synthetic and say so.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { zonedToIso, checkItem, PLUGIN_ERRORS, SOURCES as ALL, REGIONS as ALL_REGIONS, OPERATORS } from "../../scripts/grid.mjs";
import plugin, { SOURCES, REGIONS, text, esDate, clock12, windowIso, parseCnfl, parseEdesurDo, parseEegsa } from "../../scripts/grid-sources/latam.mjs";

const FX = join(dirname(fileURLToPath(import.meta.url)), "..", "fixtures", "grid", "latam");
const txt = (f) => readFileSync(join(FX, f), "utf8");
const noErrors = (items) => items.forEach((x) => assert.deepEqual(checkItem(x), [], x.id));
const regionsKnown = (items) => items.forEach((x) => assert.ok(ALL_REGIONS[`${x.source}|${x.region}`], `${x.id} region ${x.region}`));
const NOW = Date.parse("2026-11-24T16:00:00Z");   // Tuesday 24 Nov: 10:00 in Costa Rica and Guatemala, 12:00 in Santo Domingo

test("latam: the file loads into grid.mjs with every source, adapter and region", () => {
  assert.deepEqual(PLUGIN_ERRORS.filter((e) => e.startsWith("latam.mjs")), []);
  for (const k of Object.keys(SOURCES)) {
    assert.equal(ALL[k].file, "latam.mjs", k);
    assert.ok(OPERATORS.includes(k), k);
    assert.equal(typeof plugin.adapters[k], "function", k);
    for (const f of ["name", "country", "url", "page", "terms_url", "terms_ok"]) assert.ok(SOURCES[k][f], `${k}.${f}`);
    assert.ok(SOURCES[k].hosts.includes(new URL(SOURCES[k].page).host), `${k} page on its own host`);
    assert.ok(SOURCES[k].hosts.includes(new URL(SOURCES[k].url).host), `${k} url on its own host`);
  }
  for (const k of Object.keys(REGIONS)) assert.ok(ALL_REGIONS[k], k);
});

test("Spanish dates, 12-hour clocks and windows", () => {
  assert.equal(esDate("24 de noviembre, 2026"), "2026-11-24");
  assert.equal(esDate("Martes, 24 de noviembre de 2026"), "2026-11-24");
  assert.equal(esDate("24 de Noviembre del 2026"), "2026-11-24");
  assert.equal(esDate("32 de noviembre de 2026"), "");
  assert.equal(clock12("07:00 a. m."), "07:00");
  assert.equal(clock12("12:00 p. m."), "12:00");
  assert.equal(clock12("12:30 AM"), "00:30");
  assert.equal(clock12("04:00 PM"), "16:00");
  assert.equal(clock12("13:00 PM"), "");
  assert.deepEqual(windowIso("2026-11-24", "08:00 AM", "04:00 PM", "America/Costa_Rica", zonedToIso),
    { started_at: "2026-11-24T14:00:00Z", restore_est: "2026-11-24T22:00:00Z" });
  // an end that is not after the start is on the next day (synthetic)
  assert.equal(windowIso("2026-11-24", "10:00 p. m.", "02:00 a. m.", "America/Santo_Domingo", zonedToIso).restore_est, "2026-11-25T06:00:00Z");
  assert.equal(text("San Jos&#233; &amp; <b>Ocoa</b>&nbsp;"), "San José & Ocoa");
});

test("CNFL: suspensions under way, with number, place, category, customers and window", () => {
  const items = parseCnfl(txt("cnfl.html"), zonedToIso, NOW);
  noErrors(items); regionsKnown(items);
  // 5 rows in the fixture: three on 24 Nov 08:00-16:00 (under way at NOW), one on 27 Nov, one on 8 Dec
  assert.deepEqual(items.map((x) => x.id), ["cnfl-suspensiones:6226-166-2026", "cnfl-suspensiones:6205-188-2026", "cnfl-suspensiones:7020-021-2026"]);
  const a = items[0];
  assert.equal(a.area, "SAN JOSÉ, ESCAZÚ, ESCAZÚ (PARCIAL)");
  assert.equal(a.region, "San José");
  assert.equal(a.cause, "MANTENIMIENTO DE OBRAS ELÉCTRICAS");
  assert.equal(a.customers, 46);                                // "Cantidad de servicios afectados: 46"
  assert.equal(a.started_at, "2026-11-24T14:00:00Z");           // 08:00 AM, UTC-6
  assert.equal(a.restore_est, "2026-11-24T22:00:00Z");          // 04:00 PM
  assert.equal(a.planned, true);
  assert.equal(a.kind, "outage");
  assert.equal(a.url, SOURCES["cnfl-suspensiones"].page);       // each suspension opens by a POST form: no own link
  assert.equal(items[1].region, "Heredia");
  assert.equal(items[1].customers, 1490);                       // "Cantidad de Servicios afectados: 1490"
  assert.equal(items[1].cause, "OBRAS POR CONTRATO DE REDES ELÉCTRICAS");
  assert.equal(items[2].customers, null);                       // no count in that row's detail
  assert.equal(items[2].id, "cnfl-suspensiones:7020-021-2026");  // the trailing "." of "7020-021-2026." left out
  // synthetic clock on 27 Nov 09:00 local: only that day's row, with its own count
  const later = parseCnfl(txt("cnfl.html"), zonedToIso, Date.parse("2026-11-27T15:00:00Z"));
  assert.deepEqual(later.map((x) => [x.id, x.customers, x.area]), [["cnfl-suspensiones:6226-163-2026", 25, "SAN JOSÉ, ESCAZÚ, SAN ANTONIO, BARRIO EL CARMEN, CALLE HIGUERONES (PARCIAL)"]]);
  assert.throws(() => parseCnfl("<html>maintenance</html>", zonedToIso, NOW), /unexpected shape/);
});

test("Edesur Dominicana: each province's time block under way, zones as the area", () => {
  const items = parseEdesurDo(txt("edesur-do.html"), zonedToIso, NOW);
  noErrors(items); regionsKnown(items);
  assert.deepEqual(items.map((x) => x.id), ["edesur-do-mantenimientos:2026-11-24-azua-1",
    "edesur-do-mantenimientos:2026-11-24-distrito-nacional-1", "edesur-do-mantenimientos:2026-11-24-elias-pina-1"]);
  const dn = items[1];
  assert.equal(dn.region, "Distrito Nacional");
  assert.equal(dn.cause, "Mantenimiento Programado");
  assert.equal(dn.started_at, "2026-11-24T12:00:00Z");          // 08:00 a. m., UTC-4
  assert.equal(dn.restore_est, "2026-11-25T00:00:00Z");         // 08:00 p. m.
  assert.match(dn.area, /^Altos de Arroyo Hondo, Los Ríos, La Yuca \(Los Rios\), Nuevo Arroyo Hondo/);
  assert.ok(dn.area.length <= 120 && dn.area.endsWith("…"));   // long list cut at a comma
  assert.equal(dn.planned, true);
  assert.equal(dn.customers, null);                             // the badge counts zones, not customers
  assert.equal(items[0].area, "Azua, Proyecto 2-C");
  assert.equal(items[0].restore_est, "2026-11-24T19:00:00Z");   // 03:00 p. m.
  assert.equal(items[2].region, "Elías Piña");
  assert.equal(items[2].area, "Hato Viejo, Sabana Larga");
  // synthetic clock, 25 Nov 15:00 local: the 14:00-18:00 blocks, not Bahoruco's 12:00-15:00 that just ended
  const later = parseEdesurDo(txt("edesur-do.html"), zonedToIso, Date.parse("2026-11-25T19:00:00Z"));
  assert.deepEqual(later.map((x) => x.region), ["Azua", "Independencia"]);
  assert.equal(later[1].area, "El Limón de Jimaní, Mal Paso, Las Baitoas");
  assert.throws(() => parseEdesurDo("<html></html>", zonedToIso, NOW), /unexpected shape/);
});

test("EEGSA: maintenance cards under way, with number, place, circuit and window", () => {
  const items = parseEegsa(txt("eegsa.html"), zonedToIso, NOW);
  noErrors(items); regionsKnown(items);
  // 9 cards from 22 to 27 Nov; two on 24 Nov are under way at NOW
  assert.deepEqual(items.map((x) => x.id), ["eegsa-mantenimientos:8299", "eegsa-mantenimientos:9791"]);
  const a = items[0];
  assert.equal(a.region, "Guatemala");
  assert.equal(a.area, "Zona 1 de Villa Nueva, Guatemala, circuito 96");
  assert.equal(a.started_at, "2026-11-24T13:00:00Z");           // 07:00 AM, UTC-6
  assert.equal(a.restore_est, "2026-11-25T01:00:00Z");          // 07:00 PM
  assert.equal(a.cause, "Mantenimiento programado");
  assert.equal(a.planned, true);
  assert.equal(items[1].area, "Zona 9 de Mixco, Guatemala, circuito 19");
  assert.equal(items[1].restore_est, "2026-11-24T19:00:00Z");   // 01:00 PM
  // an empty list is no outage, not a broken page
  assert.deepEqual(parseEegsa('<p id="no-results">No se encontraron avisos.</p><div class="wrap_card"></div>', zonedToIso, NOW), []);
  assert.throws(() => parseEegsa("<html></html>", zonedToIso, NOW), /unexpected shape/);
});

test("adapters fetch the source url and return checked items (real clock: may be empty)", async () => {
  const h = { SOURCES: ALL, zonedToIso, item: (x) => ({ ...x }),
    get: async (u) => (u.includes("cnfl") ? txt("cnfl.html") : u.includes("edesur") ? txt("edesur-do.html") : txt("eegsa.html")) };
  for (const k of Object.keys(SOURCES)) {
    const got = await plugin.adapters[k](h);
    assert.ok(Array.isArray(got), k);
    noErrors(got);
  }
});
