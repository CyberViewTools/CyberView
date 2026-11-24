// Grid sources, lane "latam": Latin America and the Caribbean. Loaded by scripts/grid.mjs (see the comment above
// PLUGIN_ERRORS there). Every parser is pure and exported, tested on real saved replies in tests/fixtures/grid/latam/
// (tests/unit/grid-latam.test.mjs). Parsers return complete Items (the grid contract's shape); the adapters still pass
// each one through h.item, which cleans it again. Local wall-clock times go through zonedToIso (h.zonedToIso at run time,
// the same function imported from scripts/grid.mjs in the tests). Nothing here sends a key, a cookie or a browser header:
// h.get sends CyberView's own user agent, and a refusal fails the source, which grid.mjs reports.
//
// All three operators publish planned work (scheduled maintenance suspensions) as HTML lists, not live fault maps. An
// item is kept only while its window is under way (start <= now < end), the same rule world.mjs uses for Endeavour's
// planned work, so the map shows power that is off now, labelled planned, never an upcoming schedule.
//
// What each one's terms say (checked 2026-11-24):
//   cnfl-suspensiones          CNFL "Términos y condiciones": the user may not copy or republish the content "para fines
//                              comerciales o contrarios a la ley" nor alter it. CyberView is non-commercial, cites CNFL and
//                              restates the rows unchanged, so "silent" on automated reading; robots.txt allows the page.
//   edesur-do-mantenimientos   Edesur "Términos de uso": an intellectual-property notice only; robots.txt allows all.
//   eegsa-mantenimientos       no terms page anywhere on eegsa.com (site search and footer); robots.txt disallows only
//                              /wp-content/uploads/wpforms/ and /author/.

// ---------- local helpers (same rules as scripts/grid.mjs item(), so h.item leaves the result unchanged) ----------
const str = (s, n) => String(s == null ? "" : s).replace(/[\u0000-\u001f\u007f<>]/g, " ").replace(/\s+/g, " ").trim().slice(0, n);
const intOrNull = (x) => (x === null || x === undefined || x === "" || !isFinite(Number(x)) ? null : Math.max(0, Math.round(Number(x))));
const slug = (s, n = 50) => String(s || "").toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, n).replace(/-$/, "") || "x";
const badShape = (why = "") => Object.assign(new Error(`unexpected shape${why ? `: ${why}` : ""}`), { code: "bad_shape" });
const ENT = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " " };
/** HTML fragment -> plain text (tags out, entities decoded, white space collapsed). */
export function text(html) {
  return String(html || "").replace(/<br\s*\/?>/gi, " ").replace(/<[^>]*>/g, " ")
    .replace(/&#(\d{1,7});/g, (_, d) => String.fromCodePoint(+d)).replace(/&#x([0-9a-f]{1,6});/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&([a-z]+);/gi, (m, n) => ENT[n.toLowerCase()] ?? m).replace(/\s+/g, " ").trim();
}
/** Cut a list at a comma so it fits n characters (the operator's words, shortened, never reworded). */
const fit = (s, n = 120) => { s = str(s, 10000); if (s.length <= n) return s; const cut = s.slice(0, n - 2); const i = cut.lastIndexOf(","); return `${(i > 40 ? cut.slice(0, i) : cut).trim()} …`; };

const MONTHS = { enero: 1, febrero: 2, marzo: 3, abril: 4, mayo: 5, junio: 6, julio: 7, agosto: 8, septiembre: 9, setiembre: 9, octubre: 10, noviembre: 11, diciembre: 12 };
const pad = (n) => String(n).padStart(2, "0");
/** "24 de noviembre, 2026" / "22 de noviembre de 2026" / "24 de Noviembre del 2026" -> "2026-11-24" (or ""). */
export function esDate(s) {
  const m = String(s || "").toLowerCase().normalize("NFC").match(/(\d{1,2})\s+de\s+([a-záéíóú]+),?\s+(?:del?\s+)?(\d{4})/);
  if (!m || !MONTHS[m[2]] || +m[1] < 1 || +m[1] > 31) return "";
  return `${m[3]}-${pad(MONTHS[m[2]])}-${pad(+m[1])}`;
}
/** "07:00 a. m." / "04:00 PM" -> "07:00" / "16:00" (or ""). 12 a.m. is midnight, 12 p.m. is noon. */
export function clock12(s) {
  const m = String(s || "").toLowerCase().replace(/[.\s]/g, "").match(/^(\d{1,2}):(\d{2})(am|pm)$/);
  if (!m || +m[1] < 1 || +m[1] > 12 || +m[2] > 59) return "";
  const h = (+m[1] % 12) + (m[3] === "pm" ? 12 : 0);
  return `${pad(h)}:${m[2]}`;
}
const nextDay = (d) => new Date(Date.parse(`${d}T00:00:00Z`) + 864e5).toISOString().slice(0, 10);
/** A day and a "from - to" pair of 12-hour clock times in a zone -> { started_at, restore_est } (end on the next day when
 *  it is not after the start). */
export function windowIso(day, from, to, tz, zonedToIso) {
  const a = clock12(from), b = clock12(to);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(day) || !a) return { started_at: "", restore_est: "" };
  const started_at = zonedToIso(`${day} ${a}:00`, tz);
  let restore_est = b ? zonedToIso(`${day} ${b}:00`, tz) : "";
  if (restore_est && Date.parse(restore_est) <= Date.parse(started_at)) restore_est = zonedToIso(`${nextDay(day)} ${b}:00`, tz);
  return { started_at, restore_est };
}
const underWay = (w, now) => w.started_at && w.restore_est && Date.parse(w.started_at) <= now && now < Date.parse(w.restore_est);

/** A complete Item (swarm/handoff/grid-contract.md). These lists carry no coordinates: lat/lng stay null and the map
 *  places the item at its region. */
function mk(o) {
  return {
    id: str(o.id, 120), source: o.source, country: SOURCES[o.source].country, region: str(o.region, 60), area: str(o.area, 120),
    lat: null, lng: null, customers: intOrNull(o.customers), kind: "outage", planned: true, cause: str(o.cause, 120), level: null,
    started_at: o.started_at || "", restore_est: o.restore_est || "", url: SOURCES[o.source].page,
  };
}

// ---------- sources ----------
export const SOURCES = {
  "cnfl-suspensiones": { name: "Compañía Nacional de Fuerza y Luz (CNFL)", country: "CR", kind: "outages",
    url: "https://www.cnfl.go.cr/servicios/autogestion/suspensiones",
    page: "https://www.cnfl.go.cr/servicios/autogestion/suspensiones", hosts: ["www.cnfl.go.cr"],
    terms_url: "https://www.cnfl.go.cr/interes/informativo-general/politicas-terminos-condiciones/terminos", terms_ok: "silent" },
  "edesur-do-mantenimientos": { name: "Edesur Dominicana", country: "DO", kind: "outages",
    url: "https://edesur.com.do/enlaces-empresa/mantenimientos-programados/",
    page: "https://edesur.com.do/enlaces-empresa/mantenimientos-programados/", hosts: ["edesur.com.do"],
    terms_url: "https://edesur.com.do/empresa/terminos-de-uso/", terms_ok: "silent" },
  "eegsa-mantenimientos": { name: "Empresa Eléctrica de Guatemala (EEGSA)", country: "GT", kind: "outages",
    url: "https://eegsa.com/prensa/", page: "https://eegsa.com/prensa/", hosts: ["eegsa.com"],
    terms_url: "https://eegsa.com/", terms_ok: "silent" },  // no terms page on the site; the home page is the nearest
};

// ---------- regions (approximate centres: the provincial or departmental capital) ----------
const CR_PROV = {  // CNFL serves the Greater Metropolitan Area; all seven provinces so a new one still has a place
  "san-jose": ["San José", 9.933, -84.083], alajuela: ["Alajuela", 10.016, -84.214], heredia: ["Heredia", 9.998, -84.117],
  cartago: ["Cartago", 9.864, -83.919], limon: ["Limón", 9.99, -83.033], puntarenas: ["Puntarenas", 9.976, -84.838],
  guanacaste: ["Guanacaste", 10.635, -85.437],
};
const DO_PROV = {  // Edesur's provinces (south and west of the Dominican Republic)
  "distrito-nacional": ["Distrito Nacional", 18.486, -69.931], "santo-domingo": ["Santo Domingo", 18.488, -69.857],
  "san-cristobal": ["San Cristóbal", 18.417, -70.107], peravia: ["Peravia", 18.28, -70.331], azua: ["Azua", 18.453, -70.735],
  "san-jose-de-ocoa": ["San José de Ocoa", 18.546, -70.506], "san-juan": ["San Juan", 18.806, -71.229],
  "elias-pina": ["Elías Piña", 18.876, -71.707], barahona: ["Barahona", 18.208, -71.1], bahoruco: ["Bahoruco", 18.481, -71.419],
  independencia: ["Independencia", 18.493, -71.85], pedernales: ["Pedernales", 18.038, -71.744],
};
const GT_DEPT = {  // EEGSA's departments
  guatemala: ["Guatemala", 14.641, -90.513], sacatepequez: ["Sacatepéquez", 14.557, -90.733], escuintla: ["Escuintla", 14.305, -90.785],
};
const regionOf = (table, raw) => (table[slug(raw)] || [str(raw, 60)])[0];
export const REGIONS = {
  ...Object.fromEntries(Object.values(CR_PROV).map(([n, lat, lng]) => [`cnfl-suspensiones|${n}`, { name: `${n}, Costa Rica`, lat, lng }])),
  ...Object.fromEntries(Object.values(DO_PROV).map(([n, lat, lng]) => [`edesur-do-mantenimientos|${n}`, { name: `${n}, Dominican Republic`, lat, lng }])),
  ...Object.fromEntries(Object.values(GT_DEPT).map(([n, lat, lng]) => [`eegsa-mantenimientos|${n}`, { name: `${n}, Guatemala`, lat, lng }])),
};

// ---------- CNFL (Costa Rica) ----------
// One <tr> per suspension in <table id='datos'>: td 1 data-sort='YYYY-MM-DD HH:MM:SS' (start), check_susp(<id>) and the
// "08:00 AM - 04:00 PM" window; td 2 "PROVINCIA, CANTÓN, DISTRITO (PARCIAL)", the category (susp_categoria) and
// "Número de Suspensión: 6226-166-2026"; td 4 (hidden) the detail, sometimes with "Cantidad de servicios afectados: 46".
export function parseCnfl(html, zonedToIso, now = Date.now()) {
  const s = String(html || "");
  const a = s.search(/id=['"]datos['"]/);
  if (a < 0) throw badShape("no suspensions table");
  const out = [];
  for (const row of s.slice(a, s.indexOf("</table>", a) > 0 ? s.indexOf("</table>", a) : undefined).split(/<tr\b[^>]*>/).slice(1)) {
    const tds = [...row.matchAll(/<td\b[^>]*>([\s\S]*?)<\/td>/g)].map((m) => m[1]);
    const sort = row.match(/data-sort=['"](\d{4}-\d{2}-\d{2}) (\d{2}:\d{2})/);
    if (tds.length < 3 || !sort) continue;
    const win = text(tds[0]).match(/(\d{1,2}:\d{2}\s*[AP]\.?\s*M\.?)\s*-\s*(\d{1,2}:\d{2}\s*[AP]\.?\s*M\.?)/i);
    const w = win ? windowIso(sort[1], win[1], win[2], "America/Costa_Rica", zonedToIso) : { started_at: zonedToIso(`${sort[1]} ${sort[2]}:00`, "America/Costa_Rica"), restore_est: "" };
    if (!underWay(w, now)) continue;
    const place = text(tds[1].split(/<br\s*\/?>/i)[0]);
    const cat = text((tds[1].match(/susp_categoria['"][^>]*>([\s\S]*?)<\/small>/) || [])[1]);
    const num = (text(tds[1]).match(/Suspensi[oó]n:\s*([0-9][0-9-]*[0-9])/) || [])[1] || (row.match(/check_susp\((\d+)\)/) || [])[1];
    const cust = (text(tds[3] || "").match(/servicios afectados:\s*(\d[\d.,]*)/i) || [])[1];
    if (!num || !place) continue;
    out.push(mk({ source: "cnfl-suspensiones", id: `cnfl-suspensiones:${num}`, region: regionOf(CR_PROV, place.split(",")[0]),
      area: place, customers: cust ? cust.replace(/[.,]/g, "") : null, cause: cat, ...w }));
  }
  return out;
}

// ---------- Edesur Dominicana ----------
// Day tabs (<button ... data-bs-target="#pills-<uuid>"> ... <small>24 de noviembre, 2026</small>) and one tab pane per day;
// in a pane one accordion item per province (<h3>Azua</h3>, the type "Mantenimiento Programado") holding one or more
// "<h4 class="h5 title-zona">Zonas en mantenimiento 07:00 a. m. a 01:00 p. m.</h4>" blocks, each followed by its zone list.
export function parseEdesurDo(html, zonedToIso, now = Date.now()) {
  const s = String(html || "");
  const tabs = s.match(/id=["']pills-tab["'][\s\S]*?<\/ul>/);
  if (!tabs) throw badShape("no day tabs");
  const days = {};
  for (const m of tabs[0].matchAll(/data-bs-target="#(pills-[0-9a-f-]+)"[\s\S]*?<small[^>]*>([^<]+)<\/small>/g)) days[m[1]] = esDate(text(m[2]));
  const out = [];
  for (const pane of s.split(/(?=<div class="tab-pane\b)/).slice(1)) {
    const day = days[(pane.match(/id="(pills-[0-9a-f-]+)"/) || [])[1]];
    if (!day) continue;
    for (const acc of pane.split(/(?=<div class="accordion-item")/).slice(1)) {
      const prov = text((acc.match(/<h3\b[^>]*>([\s\S]*?)<\/h3>/) || [])[1]);
      const kind = text((acc.match(/small-document-accordion[^>]*>([\s\S]*?)<\/p>/) || [])[1]) || "Mantenimiento Programado";
      if (!prov) continue;
      acc.split(/(?=<h4\b[^>]*title-zona)/).slice(1).forEach((blk, i) => {
        const h = text((blk.match(/<h4\b[^>]*>([\s\S]*?)<\/h4>/) || [])[1]);
        const t = h.match(/(\d{1,2}:\d{2}\s*[ap]\.?\s*m\.?)\s+a\s+(\d{1,2}:\d{2}\s*[ap]\.?\s*m\.?)/i);
        if (!t) return;
        const w = windowIso(day, t[1], t[2], "America/Santo_Domingo", zonedToIso);
        if (!underWay(w, now)) return;
        const zones = text(blk.replace(/<h4\b[\s\S]*?<\/h4>/, "").split(/<\/div>/)[0]);
        out.push(mk({ source: "edesur-do-mantenimientos", id: `edesur-do-mantenimientos:${day}-${slug(prov, 30)}-${i + 1}`,
          region: regionOf(DO_PROV, prov), area: fit(zones), cause: kind, ...w }));
      });
    }
  }
  return out;
}

// ---------- EEGSA (Guatemala) ----------
// <div class="wrap_card"> of <div class="card" data-departamento="1" data-fecha="Martes, 24 de noviembre de 2026, 07:00 AM
// a 07:00 PM">, each with the department (<h2>), "No. de mantenimiento: 8299", "Lugares afectados: <place>: <streets>"
// and "Circuitos(s) Afectado(s): 96". The page shows "No se encontraron avisos." when the list is empty.
export function parseEegsa(html, zonedToIso, now = Date.now()) {
  const s = String(html || "");
  if (!/class="wrap_card"|id="no-results"/.test(s)) throw badShape("no maintenance list");
  const out = [];
  for (const m of s.matchAll(/<div class="card" data-departamento="\d*" data-fecha="([^"]*)">([\s\S]*?)<\/div>\s*<\/div>/g)) {
    const f = text(m[1]).match(/^(.*?\d{4}),\s*(\d{1,2}:\d{2}\s*[AP]M)\s+a\s+(\d{1,2}:\d{2}\s*[AP]M)/i);
    if (!f) continue;
    const w = windowIso(esDate(f[1]), f[2], f[3], "America/Guatemala", zonedToIso);
    if (!underWay(w, now)) continue;
    const body = m[2];
    const num = (text(body).match(/No\. de mantenimiento:\s*(\d+)/i) || [])[1];
    const dept = text((body.match(/<h2\b[^>]*>([\s\S]*?)<\/h2>/) || [])[1]);
    const places = text((body.match(/Lugares afectados:\s*<\/strong>([\s\S]*?)<\/p>/i) || [])[1]);
    const circuit = text((body.match(/Afectado\(s\):\s*<\/strong>([\s\S]*?)<\/p>/i) || [])[1]);
    if (!num || !dept) continue;
    const where = places.split(":")[0].trim();
    out.push(mk({ source: "eegsa-mantenimientos", id: `eegsa-mantenimientos:${num}`, region: regionOf(GT_DEPT, dept),
      area: fit(`${where}${circuit ? `, circuito ${circuit}` : ""}`), cause: "Mantenimiento programado", ...w }));
  }
  return out;
}

// ---------- adapters ----------
export const ADAPTERS = {
  "cnfl-suspensiones": async (h) => parseCnfl(await h.get(h.SOURCES["cnfl-suspensiones"].url, { as: "text" }), h.zonedToIso),
  "edesur-do-mantenimientos": async (h) => parseEdesurDo(await h.get(h.SOURCES["edesur-do-mantenimientos"].url, { as: "text" }), h.zonedToIso),
  "eegsa-mantenimientos": async (h) => parseEegsa(await h.get(h.SOURCES["eegsa-mantenimientos"].url, { as: "text", timeoutMs: 60000 }), h.zonedToIso),
};

export default {
  sources: SOURCES,
  regions: REGIONS,
  adapters: Object.fromEntries(Object.entries(ADAPTERS).map(([k, fn]) => [k, async (h) => (await fn(h)).map((x) => h.item(x))])),
};
