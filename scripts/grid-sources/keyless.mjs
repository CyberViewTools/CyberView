// Key-free grid-stress signals from system operators (lane "keyless", 2026-11-20). Every route here was checked on
// 2026-11-20: the operator's own terms allow reuse, robots.txt does not disallow the path (or there is none), and the
// host answered a plain request with no key, cookie, challenge or login. Findings and the routes that failed:
// swarm/REQUESTS.md, section "keyless". Signals only (no customer counts): each source gives one current condition.
//
//   neso-warnings  GB transmission system warnings issued by NESO, read from Elexon's BMRS (dataset SYSWARN).
//                  supply_warning: Electricity Margin Notice 1, High Risk of Demand Reduction 2, Demand Control
//                  Imminent 3; 0 when none is in force. Licence: BMRS open data, attribution required.
//   fingrid        Finland's power system state (the traffic light on fingrid.fi). grid_emergency: normal 0,
//                  endangered 1, disturbed (load shedding or serious blackout risk) 2, serious disturbance or
//                  blackout 3, restoration after one 2. Electricity shortage indicator as a second item:
//                  possible 1, high 2 (supply_warning), active 3 (load_shedding).
//   rte-ecowatt    France's Ecowatt signal for the current hour (the file monecowatt.fr itself loads).
//                  supply_warning: green / decarbonised 0, orange "système électrique tendu" 1, red "très tendu,
//                  coupures inévitables si nous ne baissons pas notre consommation" 2.
//   kpx            South Korea's real-time supply reserve (KPX table) against KPX's own emergency thresholds:
//                  supply_warning 0 at 5,500 MW or more, 준비 1 (< 5,500), 관심 2 (< 4,500), 주의 3 (< 3,500),
//                  경계 4 (< 2,500), 심각 5 (< 1,500). Derived from the published reserve, not a declared stage.
// Parsers are pure (tests/unit/grid-keyless.test.mjs, real replies in tests/fixtures/grid/keyless/).

const ELEXON = "https://data.elexon.co.uk/bmrs/api/v1/datasets/SYSWARN";
const ECOWATT = "https://monecowatt-data.s3.amazonaws.com";
const STALE_HOURS = 3;   // a "current" reading older than this is not current: the source reports an error instead

const str = (s, n) => String(s == null ? "" : s).replace(/[\u0000-\u001f\u007f<>]/g, " ").replace(/\s+/g, " ").trim().slice(0, n);
const isoS = (ms) => new Date(ms).toISOString().replace(/\.\d+Z$/, "Z");
const badShape = (why) => Object.assign(new Error(`unexpected shape: ${why}`), { code: "bad_shape" });
const stale = (what) => Object.assign(new Error(`stale: ${what}`), { code: "stale" });

function zoneOffset(ms, tz) {
  const p = Object.fromEntries(new Intl.DateTimeFormat("en-US", { timeZone: tz, hourCycle: "h23", year: "numeric", month: "2-digit",
    day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" }).formatToParts(new Date(ms)).map((x) => [x.type, x.value]));
  return Date.UTC(+p.year, +p.month - 1, +p.day, +p.hour % 24, +p.minute, +p.second) - Math.floor(ms / 1000) * 1000;
}
/** Wall-clock y-m-d h:m in zone tz -> epoch ms (NaN when unreadable). Same method as zonedToIso in scripts/grid.mjs. */
export function zonedMs(y, mo, d, h, mi, tz) {
  const guess = Date.UTC(+y, +mo - 1, +d, +h, +mi, 0);
  if (!isFinite(guess)) return NaN;
  let t = guess - zoneOffset(guess, tz);
  t = guess - zoneOffset(t, tz);
  return +y > 1900 && isFinite(t) ? t : NaN;
}
/** The wall-clock parts of instant ms in zone tz. */
function localParts(ms, tz) {
  const p = Object.fromEntries(new Intl.DateTimeFormat("en-US", { timeZone: tz, hourCycle: "h23", year: "numeric", month: "2-digit",
    day: "2-digit", hour: "2-digit" }).formatToParts(new Date(ms)).map((x) => [x.type, x.value]));
  return { y: +p.year, m: +p.month, d: +p.day, h: +p.hour % 24 };
}
const signal = (source, country, region, o) => ({ id: `${source}:${o.id}`, source, country, region, area: str(o.area, 120), lat: null, lng: null,
  customers: null, kind: o.kind, planned: false, cause: str(o.cause, 120), level: o.level, started_at: o.started_at || "", restore_est: o.restore_est || "",
  url: o.url });

// ---------- NESO system warnings (Elexon BMRS SYSWARN) ----------
// Reply (tests/fixtures/grid/keyless/neso-syswarn.json): { data: [{ publishTime (UTC ISO), warningType, warningText }] }.
// warningType seen 2025-10 .. 2026-11: "ELECTRICITY MARGIN NOTICE", "NEGATIVE RESERVE ACTIVE POWER MARGIN", "IT SYSTEMS
// OUTAGE", "SO-SO TRADES", "OTHER". A notice text says "For the period: from 08:00 hrs to 11:00 hrs on Monday 09/11/2026"
// (UK time); its cancellation says "issued for the period from 08:00 hrs to 11:00 hrs on Monday 09/11/2026 has been
// cancelled" and lists "The following GB Transmission System Warnings remain in force". Negative reserve (NRAPM: too
// much generation in a region), IT outages, trades and emergency instructions to single units are not supply stress.
export const NESO_PAGE = "https://bmrs.elexon.co.uk/system-warnings";
const NESO_CLASSES = [
  { re: /DEMAND CONTROL IMMINENT/i, level: 3, name: "Demand Control Imminent" },
  { re: /HIGH RISK OF DEMAND REDUCTION/i, level: 2, name: "High Risk of Demand Reduction" },
  { re: /ELECTRICITY MARGIN NOTICE|INADEQUATE SYSTEM MARGIN/i, level: 1, name: "Electricity Margin Notice" },
];
const NESO_KEEP_H = 24;   // a notice whose period cannot be read stays current this long after it was published
/** "from HH:MM hrs to HH:MM hrs on <weekday> DD/MM/YYYY" -> { key, start, end } (ms, UK time), or null. */
export function nesoPeriod(text) {
  const m = String(text || "").replace(/\\[rn]|[\r\n]/g, " ").match(/from\s+(\d{1,2}):(\d{2})\s*hrs\s+to\s+(\d{1,2}):(\d{2})\s*hrs\s+on\s+(?:[A-Za-z]+\s+)?(\d{2})\/(\d{2})\/(\d{4})/i);
  if (!m) return null;
  const [, h1, m1, h2, m2, d, mo, y] = m;
  const start = zonedMs(y, mo, d, h1, m1, "Europe/London");
  let end = zonedMs(y, mo, d, h2, m2, "Europe/London");
  if (end <= start) {   // "from 23:00 to 05:00": the end is the next morning (read as that day's wall clock, across a clock change)
    const n = new Date(Date.UTC(+y, +mo - 1, +d + 1));
    end = zonedMs(n.getUTCFullYear(), n.getUTCMonth() + 1, n.getUTCDate(), h2, m2, "Europe/London");
  }
  return isFinite(start) && isFinite(end) ? { key: `${y}${mo}${d}`, start, end } : null;
}
export function parseNesoWarnings(d, now = Date.now()) {
  if (!d || !Array.isArray(d.data)) throw badShape("neso system warnings");
  const state = new Map();   // "<level>|<period day>" -> { level, name, period, at, text } (latest notice wins)
  const rows = d.data.filter((r) => r && typeof r.warningText === "string" && Date.parse(r.publishTime || "") <= now)
    .sort((a, b) => Date.parse(a.publishTime) - Date.parse(b.publishTime));
  for (const r of rows) {
    const text = r.warningText.replace(/\\[rn]|[\r\n]/g, " ");
    const cancel = /CANCELLATION|has been cancelled/i.test(text);
    if (cancel && /remain in force[\s.:]*None\b/i.test(text)) state.clear();   // "remain in force: None" clears everything
    const head = text.split(/remain in force/i)[0];   // the list of warnings still in force names other classes
    const cls = NESO_CLASSES.find((c) => c.re.test(`${r.warningType} ${head}`));
    if (!cls) continue;
    const period = nesoPeriod(head), k = `${cls.level}|${period ? period.key : r.publishTime.slice(0, 10)}`;
    if (cancel) { state.delete(k); continue; }
    const shortfall = (text.match(/shortfall\s+(\d[\d,]*)\s*MW/i) || [])[1];
    state.set(k, { ...cls, period, at: Date.parse(r.publishTime), shortfall });
  }
  const out = [];
  for (const w of state.values()) {
    const end = w.period ? w.period.end : w.at + NESO_KEEP_H * 3600e3;
    if (now >= end) continue;
    out.push(signal("neso-warnings", "GB", "Great Britain", { id: `${w.level}-${isoS(w.at).replace(/\D/g, "").slice(0, 12)}`, kind: "supply_warning",
      level: w.level, area: `GB transmission system: ${w.name}`,
      cause: `${w.name}${w.period ? ` for ${isoS(w.period.start).slice(0, 16).replace("T", " ")} to ${isoS(w.period.end).slice(11, 16)} UTC` : ""}${w.shortfall ? `, margin shortfall ${w.shortfall} MW` : ""}`,
      started_at: isoS(w.at), restore_est: w.period ? isoS(w.period.end) : "", url: NESO_PAGE }));
  }
  if (!out.length) out.push(signal("neso-warnings", "GB", "Great Britain", { id: "system", kind: "supply_warning", level: 0,
    area: "GB transmission system: no margin warning in force", cause: "", started_at: "", url: NESO_PAGE }));
  return out;
}

// ---------- Fingrid power system state ----------
// /api/graph/power-system-state?language=en is what fingrid.fi's own power-system pages poll every 10 s. Status 1-5 and
// Shortage 0-3 are read with the site's own tables (static/dist/bundle.js, 2026-11-20): status names
// ["normal","weakened","danger","interference","resuming"] = Status-1, shortages ["","possible","great","active"] =
// Shortage; colours and meanings from fingrid.fi "Different states of the power system - traffic lights" (green normal,
// yellow endangered, red disturbed = manual load shedding or serious risk of a wide blackout, black = extremely serious
// disturbance or wide blackout, blue = network being restored). LastModified is "DD.MM.YYYY HH:MM", Finnish time.
export const FINGRID_PAGE = "https://www.fingrid.fi/en/electricity-market/power-system/";
const FG_STATUS = [null, { level: 0, name: "normal (green)" }, { level: 1, name: "endangered (yellow)" },
  { level: 2, name: "disturbed (red): load shedding or serious risk of a wide blackout" },
  { level: 3, name: "extremely serious disturbance or wide blackout (black)" }, { level: 2, name: "network being restored after a blackout (blue)" }];
const FG_SHORTAGE = [null, { kind: "supply_warning", level: 1, name: "electricity shortage possible" },
  { kind: "supply_warning", level: 2, name: "high risk of electricity shortage" }, { kind: "load_shedding", level: 3, name: "electricity shortage: rotating outages" }];
export function parseFingrid(d, now = Date.now()) {
  if (!d || typeof d !== "object" || !Number.isInteger(d.Status) || !FG_STATUS[d.Status]) throw badShape("fingrid status");
  const m = String(d.LastModified || "").match(/^(\d{1,2})\.(\d{1,2})\.(\d{4}) (\d{1,2}):(\d{2})$/);
  const at = m ? zonedMs(m[3], m[2], m[1], m[4], m[5], "Europe/Helsinki") : NaN;
  if (!isFinite(at)) throw badShape("fingrid LastModified");
  if (now - at > STALE_HOURS * 3600e3) throw stale(`fingrid state last updated ${isoS(at)}`);
  const st = FG_STATUS[d.Status], started = isoS(at);
  const out = [signal("fingrid", "FI", "Finland", { id: "state", kind: "grid_emergency", level: st.level, area: `Finnish power system: ${st.name}`,
    cause: d.AreValuesValid === false ? "Fingrid marks the latest values as not valid" : "", started_at: started, url: FINGRID_PAGE })];
  const sh = Number.isInteger(d.Shortage) ? FG_SHORTAGE[d.Shortage] : null;
  if (sh) out.push(signal("fingrid", "FI", "Finland", { id: "shortage", kind: sh.kind, level: sh.level, area: `Finland: ${sh.name}`, cause: "",
    started_at: started, url: FINGRID_PAGE }));
  return out;
}

// ---------- RTE Ecowatt ----------
// monecowatt.fr loads <bucket>/data<N>/ecowatt-version-2 (N random 1-100, the same files) and then app_signal_<first 3
// characters of the version>: "YYMMDD|<4 days>|<message>...", each day "<day value><letter><value>..." ending at "X<v>",
// letters A-X = the hour a period ends (1-24), values 0 decarbonised, 1 green, 2 orange, 3 red (the site's own
// parseSignal / getPeriodValues, 2026-11-20). Like the site, a file more than 3 days old means green (no signal).
export const ECOWATT_PAGE = "https://www.monecowatt.fr/";
const EW_LEVEL = [0, 0, 1, 2];
const EW_NAME = ["production décarbonée (green)", "pas d'alerte (green)", "système électrique tendu (orange)", "système électrique très tendu (red)"];
export function ecowattVersion(text) {
  const s = String(text == null ? "" : text).trim();
  if (!/^\d{3,20}$/.test(s)) throw badShape("ecowatt version");
  return s.slice(0, 3);
}
/** One day's code -> { day, hours: [24 values] }. */
export function ecowattDay(code) {
  const s = String(code || "");
  if (!/^[0-3](?:[A-X][0-3])+$/.test(s)) throw badShape("ecowatt day");
  const hours = [];
  for (let i = 1; i < s.length; i += 2) { const end = s.charCodeAt(i) - 64; while (hours.length < end) hours.push(+s[i + 1]); }
  if (hours.length !== 24) throw badShape("ecowatt hours");
  return { day: +s[0], hours };
}
export function parseEcowatt(text, now = Date.now()) {
  const parts = String(text || "").trim().split("|");
  if (parts.length < 2 || !/^\d{6}$/.test(parts[0])) throw badShape("ecowatt signal");
  const days = parts[1].match(/[0-3](?:[A-W][0-3])*X[0-3]/g) || [];
  if (days.join("") !== parts[1] || days.length < 1) throw badShape("ecowatt days");
  const p = localParts(now, "Europe/Paris");
  const fileDay = Date.UTC(2000 + +parts[0].slice(0, 2), +parts[0].slice(2, 4) - 1, +parts[0].slice(4, 6)), today = Date.UTC(p.y, p.m - 1, p.d);
  const diff = Math.round((today - fileDay) / 864e5);
  const fileIso = new Date(fileDay).toISOString().slice(0, 10);
  if (diff < 0 || diff > 3 || diff >= days.length) {
    return [signal("rte-ecowatt", "FR", "France", { id: "national", kind: "supply_warning", level: 0,
      area: "France: no current Ecowatt signal (green)", cause: `latest Ecowatt file is for ${fileIso}`, started_at: "", url: ECOWATT_PAGE })];
  }
  const day = ecowattDay(days[diff]), v = day.hours[p.h];
  return [signal("rte-ecowatt", "FR", "France", { id: "national", kind: "supply_warning", level: EW_LEVEL[v],
    area: `France, this hour: ${EW_NAME[v]}`, cause: str(parts[2 + diff] || "", 120) || `day signal: ${EW_NAME[day.day]}`,
    started_at: isoS(zonedMs(p.y, p.m, p.d, p.h, 0, "Europe/Paris")), url: ECOWATT_PAGE })];
}

// ---------- KPX real-time supply ----------
// new.kpx.or.kr "실시간 전력수급현황" (refreshed every 5 minutes) is one table with fixed cell ids: avil (공급능력, supply
// capacity), load (현재수요, demand), supPow (공급예비력, supply reserve), supPer (공급예비율, reserve rate), and the time
// in <p class="info_top">YYYY.MM.DD(요일) HH:MM (Korea time). Thresholds: KPX "비상시 절전참여요령"
// (menu.es?mid=a10606050000): 예비전력 below 5,500 / 4,500 / 3,500 / 2,500 / 1,500 MW = 준비 / 관심 / 주의 / 경계 / 심각.
export const KPX_PAGE = "https://new.kpx.or.kr/powerinfoSubmain.es?mid=a10404030000";
const KPX_STAGES = [[1500, 5, "심각 (serious)"], [2500, 4, "경계 (alert)"], [3500, 3, "주의 (caution)"], [4500, 2, "관심 (attention)"], [5500, 1, "준비 (preparation)"]];
const kpxMw = (html, id) => {
  const m = String(html).match(new RegExp(`<td id="${id}">\\s*(\\d{1,3}(?:,\\d{3})*|\\d+)(?:\\.\\d+)?\\s*(MW|%)\\s*</td>`));
  return m ? Number(m[1].replace(/,/g, "")) : NaN;
};
export function parseKpx(html, now = Date.now()) {
  const s = String(html || "");
  const t = s.match(/<p class="info_top">\s*(\d{4})\.(\d{2})\.(\d{2})\([^)]{1,3}\)\s+(\d{2}):(\d{2})/);
  const cap = kpxMw(s, "avil"), load = kpxMw(s, "load"), reserve = kpxMw(s, "supPow");
  if (!t || ![cap, load, reserve].every((x) => isFinite(x) && x >= 0) || cap < load || Math.abs(cap - load - reserve) > 50) throw badShape("kpx table");
  const at = zonedMs(t[1], t[2], t[3], t[4], t[5], "Asia/Seoul");
  if (!isFinite(at)) throw badShape("kpx time");
  if (now - at > STALE_HOURS * 3600e3) throw stale(`kpx table last updated ${isoS(at)}`);
  const stage = KPX_STAGES.find(([mw]) => reserve < mw);
  const fmt = (n) => n.toLocaleString("en-US");
  return [signal("kpx", "KR", "South Korea", { id: "national", kind: "supply_warning", level: stage ? stage[1] : 0,
    area: stage ? `South Korea: supply reserve below the ${stage[2]} threshold` : "South Korea: supply reserve normal",
    cause: `supply reserve ${fmt(reserve)} MW (demand ${fmt(load)} of ${fmt(cap)} MW)`, started_at: isoS(at), url: KPX_PAGE })];
}

// ---------- source definitions ----------
const sig = { kind: "signal", customers_served: null };
export default {
  sources: {
    "neso-warnings": { ...sig, name: "NESO system warnings (Elexon BMRS)", country: "GB", url: `${ELEXON}?format=json`, page: NESO_PAGE,
      hosts: ["bmrs.elexon.co.uk"], terms_url: "https://www.elexon.co.uk/bsc/data/balancing-mechanism-reporting-agent/copyright-licence-bmrs-data/",
      terms_ok: "allowed", attribution: "Contains BMRS data © Elexon Limited copyright and database right 2026" },
    fingrid: { ...sig, name: "Fingrid power system state", country: "FI", url: "https://www.fingrid.fi/api/graph/power-system-state?language=en",
      page: FINGRID_PAGE, hosts: ["www.fingrid.fi"], terms_url: "https://www.fingrid.fi/en/legal-terms/", terms_ok: "allowed", attribution: "Source: Fingrid" },
    "rte-ecowatt": { ...sig, name: "RTE Ecowatt", country: "FR", url: `${ECOWATT}/data1/ecowatt-version-2`, page: ECOWATT_PAGE,
      hosts: ["www.monecowatt.fr"], terms_url: "https://www.monecowatt.fr/mentions-legales/", terms_ok: "allowed", attribution: "Source: RTE, Ecowatt" },
    kpx: { ...sig, name: "KPX real-time supply (Korea Power Exchange)", country: "KR", url: KPX_PAGE, page: KPX_PAGE, hosts: ["new.kpx.or.kr"],
      terms_url: "https://new.kpx.or.kr/", terms_ok: "silent", attribution: "Source: Korea Power Exchange (KPX)" },
  },
  regions: {
    "neso-warnings|Great Britain": { name: "Great Britain", lat: 54.0, lng: -2.5 },
    "fingrid|Finland": { name: "Finland", lat: 62.5, lng: 25.5 },
    "rte-ecowatt|France": { name: "France", lat: 46.6, lng: 2.4 },
    "kpx|South Korea": { name: "South Korea", lat: 36.4, lng: 127.9 },
  },
  adapters: {
    "neso-warnings": async (h) => {
      const now = Date.now(), q = (ms) => new Date(ms).toISOString().slice(0, 16) + "Z";
      return parseNesoWarnings(await h.get(`${ELEXON}?publishDateTimeFrom=${q(now - 4 * 864e5)}&publishDateTimeTo=${q(now + 3600e3)}&format=json`), now).map(h.item);
    },
    fingrid: async (h) => parseFingrid(await h.get(h.SOURCES.fingrid.url)).map(h.item),
    "rte-ecowatt": async (h) => {
      const dir = `${ECOWATT}/data${1 + Math.floor(Math.random() * 100)}`;   // as the site does: 100 copies of the same files
      const v = ecowattVersion(await h.get(`${dir}/ecowatt-version-2`, { as: "text", key: "monecowatt-data" }));
      return parseEcowatt(await h.get(`${dir}/app_signal_${v}`, { as: "text", key: "monecowatt-data" })).map(h.item);
    },
    kpx: async (h) => parseKpx(await h.get(KPX_PAGE, { as: "text" })).map(h.item),
  },
};
