// Grid sources for Europe, second lane (swarm/grid-sources-20261124, "europe-2"): three Ukrainian oblenergos' hourly
// outage schedules (Lvivoblenergo, Khmelnytskoblenergo, Rivneoblenergo) and Elenia's live outage table (Finland).
// Loaded by scripts/grid.mjs (see the comment above PLUGIN_ERRORS there). This file must not import scripts/grid.mjs
// (it is imported BY it): every parser takes the helpers `h` (item, str, isoOf, zonedToIso) as an argument, so it stays
// pure and testable.
//
// The Ukrainian schedules (ГПВ, графік погодинних відключень) are ordered by NEK Ukrenergo and published by each oblast
// distributor for its subqueues (підчерги / групи 1.1 .. 6.2). They are planned rotating outages, never attacks:
// kind "load_shedding", planned true, one item per subqueue per published interval that has not ended yet. The
// operators publish no customer counts and no stage number, so customers and level stay null.
//
// robots.txt and terms, checked 2026-11-24 for every feed path below:
//   api.loe.lviv.ua           no robots.txt (404); poweron.loe.lviv.ua robots.txt has an empty "Disallow:"; no terms page
//   hoe.com.ua                no robots.txt (404); the page carries only "© 2026 — Всі права захищено", no terms of use
//   www.roe.vsei.ua           robots.txt disallows only WordPress paths (/wp-admin/ and the like), not /disconnections
//   katkokartta.elenia.fi     no robots.txt (404); elenia.fi publishes no terms of use for the map or its data
// No source sends a key, a cookie or a browser-imitating header: h.get sends only CyberView's own user agent.

const badShape = (what) => Object.assign(new Error(`unexpected reply shape (${what})`), { code: "bad_shape" });
// the operator's own data time travels with the items (scripts/grid.mjs collect marks a source stale when it is old)
export const stamp = (arr, at) => Object.defineProperty(arr, "data_at", { value: at || "", enumerable: false, configurable: true });

const KYIV = "Europe/Kyiv";
const UA_MONTHS = ["січня", "лютого", "березня", "квітня", "травня", "червня", "липня", "серпня", "вересня", "жовтня", "листопада", "грудня"];
const pad = (n) => String(n).padStart(2, "0");
/** html -> text lines: <br> and block ends become newlines, tags go, the few entities these pages use are decoded. */
export function textOf(html) {
  return String(html || "").replace(/<br\s*\/?>/gi, "\n").replace(/<\/(p|div|tr|li|h\d)>/gi, "\n").replace(/<[^>]*>/g, " ")
    .replace(/&nbsp;/g, " ").replace(/&laquo;/g, "«").replace(/&raquo;/g, "»").replace(/&ndash;/g, "–").replace(/&amp;/g, "&")
    .replace(/[ \t ]+/g, " ");
}
/** "08:00-12:30; 19:00 - 24:00" -> [[480, 750], [1140, 1440]] (minutes after local midnight). */
export function ranges(s) {
  const out = [];
  for (const m of String(s || "").matchAll(/(\d{1,2}):(\d{2})\s*(?:-|–|до)\s*(\d{1,2}):(\d{2})/g)) {
    const a = +m[1] * 60 + +m[2], b = +m[3] * 60 + +m[4];
    if (a >= 0 && b > a && b <= 1440) out.push([a, b]);
  }
  return out;
}
/** Sorted, overlapping or touching intervals merged (an update adds hours to a schedule: the union is what is off). */
export function mergeRanges(list) {
  const s = list.slice().sort((x, y) => x[0] - y[0]), out = [];
  for (const r of s) {
    const last = out[out.length - 1];
    // third element (optional): the hours came from an addition; a merged interval is "additional" only if all of it is
    if (last && r[0] <= last[1]) { last[1] = Math.max(last[1], r[1]); last[2] = last[2] && !!r[2]; } else out.push([r[0], r[1], !!r[2]]);
  }
  return out;
}
const hhmm = (m) => `${pad(Math.floor(m / 60))}:${pad(m % 60)}`;

/** Schedule -> items. sched: [{ date: "YYYY-MM-DD", group: "1.1", ranges: [[a, b]] }]. Intervals that ended before
 *  `now` are dropped; the rest (under way or later today / tomorrow) are kept with their local times as ISO UTC. */
function scheduleItems(h, o, sched, now) {
  const out = [];
  for (const s of sched) {
    for (const [a, b, extra] of mergeRanges(s.ranges)) {
      const start = h.zonedToIso(`${s.date} ${hhmm(a)}`, KYIV), end = h.zonedToIso(`${s.date} ${hhmm(b)}`, KYIV);
      if (!start || !end || Date.parse(end) <= now) continue;
      out.push(h.item({
        source: o.source, id: `${o.source}:${s.date}-${s.group}-${hhmm(a).replace(":", "")}`, region: o.region,
        area: `${o.oblast}, ${o.unit} ${s.group}`, lat: null, lng: null, customers: null, kind: "load_shedding", planned: true,
        cause: h.str(`${o.cause}, ${o.unit} ${s.group}${extra ? " (additional hours)" : ""}`, 120), level: null,
        started_at: start, restore_est: end, url: o.url,
      }));
    }
  }
  return out;
}

// ---------- Lvivoblenergo (poweron.loe.lviv.ua) ----------
// api.loe.lviv.ua/api/menu_items/238 ("Today") and /256 ("Tomorrow") are JSON-LD menu items whose rawHtml is the
// schedule as the site shows it: "Графік погодинних відключень на 24.11.2026", "Інформація станом на 19:44 23.11.2026",
// then one line per group: "Група 1.1. Електроенергії немає з 08:00 до 12:30." or "Група 2.2. Електроенергія є." (power
// on all day). An empty rawHtml means the schedule is not published yet (Tomorrow, most of the day): no items.
export const LOE_REGION = "Lviv oblast";
export function parseLoe(d, h, now = Date.now()) {
  if (!d || typeof d !== "object" || typeof d.rawHtml !== "string") throw badShape("loe");
  const t = textOf(d.rawHtml);
  if (!t.trim()) return stamp([], "");
  const dm = t.match(/відключень на (\d{2})\.(\d{2})\.(\d{4})/);
  if (!dm) throw badShape("loe: no schedule date");
  const date = `${dm[3]}-${dm[2]}-${dm[1]}`;
  const am = t.match(/станом на (\d{1,2}):(\d{2}) (\d{2})\.(\d{2})\.(\d{4})/);
  const at = am ? h.zonedToIso(`${am[5]}-${am[4]}-${am[3]} ${pad(am[1])}:${am[2]}`, KYIV) : "";
  const sched = [];
  for (const line of t.split("\n")) {
    const m = line.match(/Група (\d\.\d)\.(.*)/);
    if (m) sched.push({ date, group: m[1], ranges: /немає/.test(m[2]) ? ranges(m[2]) : [] });
  }
  if (!sched.length) throw badShape("loe: no groups");
  return stamp(scheduleItems(h, { source: "loe-gpv", region: LOE_REGION, oblast: "Lviv oblast", unit: "group",
    cause: "Hourly outage schedule (Графік погодинних відключень)", url: "https://poweron.loe.lviv.ua/" }, sched, now), at);
}

// ---------- Khmelnytskoblenergo (hoe.com.ua/page/pogodinni-vidkljuchennja) ----------
// The page's <div class="post"> holds notices newest first, separated by <hr />:
//   a full schedule: "За розпорядженням НЕК «Укренерго» 24.11.2026 р. ... будуть застосовані графіки погодинних
//     відключень (ГПВ)." or "... оновлено графік погодинних відключень (ГПВ) на 23 листопада (оновлено з 20:00).", then
//     "Підчерга 1.1 – 04:00-07:00; 12:00-16:00." per subqueue ("– без відключень." = none);
//   an addition: the same update header followed by "Додаткові години відсутності електроенергії:" (additional hours).
// For each day the newest full schedule applies, plus every addition published after it (they are newer, so above it).
export const HOE_REGION = "Khmelnytskyi oblast";
function dayOf(text, nowMs) {
  let m = text.match(/(\d{2})\.(\d{2})\.(\d{4})/);
  if (m) return `${m[3]}-${m[2]}-${m[1]}`;
  m = text.match(new RegExp(`на (\\d{1,2}) (${UA_MONTHS.join("|")})`));
  if (!m) return "";
  const kyiv = new Date(Date.parse(h0(nowMs)));
  const month = UA_MONTHS.indexOf(m[2]) + 1;
  let year = kyiv.getUTCFullYear();
  if (month - (kyiv.getUTCMonth() + 1) > 6) year--; else if ((kyiv.getUTCMonth() + 1) - month > 6) year++;
  return `${year}-${pad(month)}-${pad(m[1])}`;
}
// now as a Kyiv wall-clock date (so a notice read just after midnight UTC gets the right year)
function h0(ms) {
  const p = Object.fromEntries(new Intl.DateTimeFormat("en-CA", { timeZone: KYIV, year: "numeric", month: "2-digit", day: "2-digit" })
    .formatToParts(new Date(ms)).map((x) => [x.type, x.value]));
  return `${p.year}-${p.month}-${p.day}T12:00:00Z`;
}
export function parseHoe(html, h, now = Date.now()) {
  const s = String(html || ""), i = s.indexOf('<div class="post">');
  if (i < 0) throw badShape("hoe: no post");
  let body = s.slice(i);
  const end = body.search(/shutdown\/queue|Файли співставлення/);
  if (end > 0) body = body.slice(0, end);
  const days = new Map(); // date -> { base: bool, groups: Map(group -> {ranges, extra}) }
  let blocks = 0;
  for (const raw of body.split(/<hr\s*\/?>/i)) {
    const t = textOf(raw);
    if (!/графік\S* погодинних відключень/i.test(t)) continue;
    const date = dayOf(t, now);
    if (!date) continue;
    blocks++;
    const extra = /Додаткові години/.test(t);
    const day = days.get(date) || { base: false, groups: new Map() };
    days.set(date, day);
    if (day.base) continue; // an older notice than the full schedule already taken
    for (const m of t.matchAll(/Підчерга (\d\.\d)\s*[–-]\s*([^\n]*)/g)) {
      const g = day.groups.get(m[1]) || [];
      g.push(...ranges(m[2]).map(([a, b]) => [a, b, extra]));
      day.groups.set(m[1], g);
    }
    if (!extra) day.base = true;
  }
  if (!blocks) throw badShape("hoe: no schedule notices");
  const sched = [];
  for (const [date, day] of days) for (const [group, g] of day.groups) sched.push({ date, group, ranges: g });
  sched.sort((a, b) => (a.date + a.group).localeCompare(b.date + b.group));
  return stamp(scheduleItems(h, { source: "hoe-gpv", region: HOE_REGION, oblast: "Khmelnytskyi oblast", unit: "subqueue",
    cause: "Hourly outage schedule (ГПВ) ordered by NEK Ukrenergo", url: "https://hoe.com.ua/page/pogodinni-vidkljuchennja" }, sched, now), "");
}

// ---------- Rivneoblenergo (www.roe.vsei.ua/disconnections) ----------
// <div id="fetched-data-container"> holds one table: a header row of subqueues "1.1" .. "6.2", then one row per day
// whose first cell is the date "24.11.2026" and whose next cells (same order) hold "22:00 - 23:59" lines, " " (no hours)
// or "Очікується" (expected: not published yet, skipped). Below it: "Оновлено: 24.11.2026 08:00".
export const ROE_REGION = "Rivne oblast";
const cells = (row) => [...row.matchAll(/<td\b[^>]*>([\s\S]*?)<\/td>/gi)].map((m) => textOf(m[1]).trim());
export function parseRoe(html, h, now = Date.now()) {
  const s = String(html || ""), i = s.indexOf('id="fetched-data-container"');
  if (i < 0) throw badShape("roe: no schedule table");
  const j = s.indexOf("</table>", i);
  const table = s.slice(i, j > 0 ? j : undefined);
  const rows = [...table.matchAll(/<tr\b[^>]*>([\s\S]*?)<\/tr>/gi)].map((m) => cells(m[1]));
  const head = rows.find((r) => r.filter((c) => /^\d\.\d$/.test(c)).length >= 2);
  if (!head) throw badShape("roe: no subqueue header");
  const groups = head.filter((c) => /^\d\.\d$/.test(c));
  const sched = [];
  for (const r of rows) {
    const dm = (r[0] || "").match(/^(\d{2})\.(\d{2})\.(\d{4})$/);
    if (!dm) continue;
    const date = `${dm[3]}-${dm[2]}-${dm[1]}`;
    r.slice(1).forEach((c, k) => { if (groups[k] && !/Очікується/.test(c)) sched.push({ date, group: groups[k], ranges: ranges(c) }); });
  }
  const um = s.match(/Оновлено:\s*(\d{2})\.(\d{2})\.(\d{4}) (\d{1,2}):(\d{2})/);
  const at = um ? h.zonedToIso(`${um[3]}-${um[2]}-${um[1]} ${pad(um[4])}:${um[5]}`, KYIV) : "";
  return stamp(scheduleItems(h, { source: "roe-gpv", region: ROE_REGION, oblast: "Rivne oblast", unit: "subqueue",
    cause: "Hourly outage schedule (ГПВ)", url: "https://www.roe.vsei.ua/disconnections" }, sched, now), at);
}

// ---------- Elenia (katkokartta.elenia.fi) ----------
// outageTableData.json: { p: { mainAreas: [{ area: "Itä-Häme", areas: [{ area: "Hartola", faultrunning: { customers:
// "2", nr: "1" }, planrunning: { customers, nr } }], faultrunning, planrunning }], summary } } - the table under the
// public outage map: ongoing faults ("Viat" / "Faults") and ongoing planned outages ("Huollot" / "Planned") per
// municipality, with customers without power and the number of outages. One item per municipality and type with
// customers > 0; no coordinates or times are published, so the item sits on the Elenia area.
export const ELENIA_REGION = "Elenia area";
const ELENIA_TYPE = { faultrunning: ["fault", false, "Ongoing faults (Viat)"], planrunning: ["plan", true, "Ongoing planned outages (Huollot)"] };
export function parseElenia(d, h) {
  const mains = d && d.p && d.p.mainAreas;
  if (!Array.isArray(mains)) throw badShape("elenia");
  const out = [];
  for (const m of mains) for (const a of (m && Array.isArray(m.areas) ? m.areas : [])) {
    for (const [k, [tag, planned, label]] of Object.entries(ELENIA_TYPE)) {
      const r = a && a[k], cust = r ? Number(r.customers) : NaN, nr = r ? Number(r.nr) : NaN;
      if (!(cust > 0)) continue;
      out.push(h.item({
        source: "elenia-katkokartta", id: `elenia-katkokartta:${h.str(m.area, 40)}-${h.str(a.area, 40)}-${tag}`,
        region: ELENIA_REGION, area: `${h.str(a.area, 60)} (${h.str(m.area, 50)})`, lat: null, lng: null, customers: cust,
        kind: "outage", planned, cause: Number.isFinite(nr) ? `${label}, outages: ${nr}` : label, level: null, started_at: "", restore_est: "",
        url: "https://katkokartta.elenia.fi/kartta/",
      }));
    }
  }
  return stamp(out, "");
}

const SOURCES = {
  "loe-gpv": {
    name: "Lvivoblenergo", country: "UA", kind: "outages",
    url: "https://api.loe.lviv.ua/api/menu_items/238",
    page: "https://poweron.loe.lviv.ua/", hosts: ["poweron.loe.lviv.ua", "api.loe.lviv.ua"],
    terms_url: "https://poweron.loe.lviv.ua/", terms_ok: "silent", customers_served: null,
  },
  "hoe-gpv": {
    name: "Khmelnytskoblenergo", country: "UA", kind: "outages",
    url: "https://hoe.com.ua/page/pogodinni-vidkljuchennja",
    page: "https://hoe.com.ua/page/pogodinni-vidkljuchennja", hosts: ["hoe.com.ua"],
    terms_url: "https://hoe.com.ua/", terms_ok: "silent", customers_served: null,
  },
  "roe-gpv": {
    name: "Rivneoblenergo", country: "UA", kind: "outages",
    url: "https://www.roe.vsei.ua/disconnections",
    page: "https://www.roe.vsei.ua/disconnections", hosts: ["www.roe.vsei.ua"],
    terms_url: "https://www.roe.vsei.ua/", terms_ok: "silent", customers_served: null,
  },
  "elenia-katkokartta": {
    name: "Elenia", country: "FI", kind: "outages",
    url: "https://katkokartta.elenia.fi/kartta/geoserver-api/content/outageTableData.json",
    page: "https://katkokartta.elenia.fi/kartta/", hosts: ["katkokartta.elenia.fi", "www.elenia.fi"],
    // "provides services to 442,000 customers" (https://www.elenia.fi/en/elenia/company/about-us, read 2026-11-24)
    terms_url: "https://www.elenia.fi/en", terms_ok: "silent", customers_served: 442000,
  },
};

// Approximate centres, used only when items have no coordinates of their own.
const REGIONS = {
  [`loe-gpv|${LOE_REGION}`]: { name: "Lviv oblast (Lvivoblenergo)", lat: 49.8, lng: 23.9 },
  [`hoe-gpv|${HOE_REGION}`]: { name: "Khmelnytskyi oblast (Khmelnytskoblenergo)", lat: 49.4, lng: 27.0 },
  [`roe-gpv|${ROE_REGION}`]: { name: "Rivne oblast (Rivneoblenergo)", lat: 51.0, lng: 26.3 },
  [`elenia-katkokartta|${ELENIA_REGION}`]: { name: "Elenia area (Häme, Pirkanmaa, Central Finland and neighbours)", lat: 61.8, lng: 24.3 },
};

const LOE_TOMORROW = "https://api.loe.lviv.ua/api/menu_items/256";
const adapters = {
  "loe-gpv": async (h) => {
    const now = Date.now();
    const today = parseLoe(await h.get(h.SOURCES["loe-gpv"].url, { retries: 1 }), h, now);
    const next = parseLoe(await h.get(LOE_TOMORROW, { retries: 1 }), h, now);
    const seen = new Set(today.map((x) => x.id));
    return stamp([...today, ...next.filter((x) => !seen.has(x.id))], today.data_at || next.data_at);
  },
  "hoe-gpv": async (h) => parseHoe(await h.get(h.SOURCES["hoe-gpv"].url, { as: "text", retries: 1 }), h, Date.now()),
  "roe-gpv": async (h) => parseRoe(await h.get(h.SOURCES["roe-gpv"].url, { as: "text", retries: 1 }), h, Date.now()),
  "elenia-katkokartta": async (h) => parseElenia(await h.get(h.SOURCES["elenia-katkokartta"].url, { retries: 1 }), h),
};

export default { sources: SOURCES, regions: REGIONS, adapters };
