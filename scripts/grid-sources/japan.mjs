// Grid source, lane "japan" (2026-11-21): Japan's supply reserve per area from OCCTO (電力広域的運営推進機関, the
// Organization for Cross-regional Coordination of Transmission Operators), read from its public 広域予備率Web公表システム
// (wide-area reserve rate publication system). A signal (no customer counts): one item per supply area with a level.
// Loaded by scripts/grid.mjs (see the comment above PLUGIN_ERRORS there). Parser pure and exported, tested on a real reply
// saved on 2026-11-21 (tests/fixtures/grid/japan/, trimmed to the fields read; tests/unit/grid-japan.test.mjs).
//
// Route checked 2026-11-21: web-kohyo.occto.or.jp answers a plain request with no key, cookie or login and publishes no
// robots.txt (404). Terms ("系統情報サービス・広域予備率Web公表システムのご利用に際して", linked from the system's notice
// page): the content "は自由に利用できますが、その際は出典を記載してください。また、コンテンツを編集・加工等して利用する場合
// は、出典とは別に編集・加工等を行ったことを記載してください" (free to use with the source named; a use that edits or
// processes it must say so as well): `attribution` below says both. Links are free in principle.
//
// Level (supply_warning), derived from the published wide-area reserve rate (広域予備率) of the current half hour, not a
// declared alert: the government's tight-supply alerts are issued on this rate, 注意報 (advisory) below 5% and 警報
// (warning) below 3%; below 1% planned rolling outages are considered. 0 at 5% or more, 1 below 5%, 2 below 3%, 3 below 1%.
// The Japanese distribution companies' own outage maps block automated readers or could not be reached
// (config/data-access.json: tepco-pg, kansai-td, chubu-pg, kyushu-td, okiden, tohoku-nw), so this is CyberView's Japan view.

const str = (s, n) => String(s == null ? "" : s).replace(/[\u0000-\u001f\u007f<>]/g, " ").replace(/\s+/g, " ").trim().slice(0, n);
const isoS = (ms) => new Date(ms).toISOString().replace(/\.\d+Z$/, "Z");
const badShape = (why = "") => Object.assign(new Error(`unexpected shape${why ? `: ${why}` : ""}`), { code: "bad_shape" });
export const stamp = (arr, at) => Object.defineProperty(arr, "data_at", { value: at || "", enumerable: false, configurable: true });
const JST = 9 * 3600e3;   // Japan has no daylight-saving time
/** "YYYY/MM/DD HH:MM" Japan time -> ISO UTC, or "". */
export const jstToIso = (s) => {
  const m = String(s || "").match(/^(\d{4})\/(\d{2})\/(\d{2})(?:\s+(\d{1,2}):(\d{2}))?/);
  if (!m) return "";
  const t = Date.UTC(+m[1], +m[2] - 1, +m[3], +(m[4] || 0), +(m[5] || 0)) - JST;
  return isFinite(t) ? isoS(t) : "";
};
/** The Japan-time calendar day ("YYYY/MM/DD") and half-hour slot (0..47) of instant ms. */
export function jstSlot(ms) {
  const d = new Date(ms + JST);
  const day = `${d.getUTCFullYear()}/${String(d.getUTCMonth() + 1).padStart(2, "0")}/${String(d.getUTCDate()).padStart(2, "0")}`;
  return { day, slot: Math.floor((d.getUTCHours() * 60 + d.getUTCMinutes()) / 30) };
}

export const OCCTO_BASE = "https://web-kohyo.occto.or.jp/kks-web-public/";
export const OCCTO_AREAS = {   // areaCd -> English name, approximate centre of the supply area
  "01": ["Hokkaido", 43.4, 142.8], "02": ["Tohoku", 39.0, 140.9], "03": ["Tokyo", 35.9, 139.7], "04": ["Chubu", 35.3, 137.3],
  "05": ["Hokuriku", 36.7, 136.9], "06": ["Kansai", 34.8, 135.6], "07": ["Chugoku", 34.7, 133.0], "08": ["Shikoku", 33.7, 133.5],
  "09": ["Kyushu", 32.6, 130.8], "10": ["Okinawa", 26.3, 127.8],
};
export const OCCTO_STAGES = [[1, 3, "below 1%: planned rolling outages are considered"], [3, 2, "below 3%: the government's tight-supply warning (警報) range"],
  [5, 1, "below 5%: the government's tight-supply advisory (注意報) range"]];

export const SOURCES = {
  "occto-reserve": { name: "OCCTO wide-area reserve (Japan)", country: "JP", kind: "signal", signal: true,
    url: `${OCCTO_BASE}home/dailyData`, page: OCCTO_BASE, hosts: ["web-kohyo.occto.or.jp", "www.occto.or.jp"],
    terms_url: "https://www.occto.or.jp/assets/keitoujouhou/files/0.keitou_webkohyo_menseki.pdf", terms_ok: "allowed", customers_served: null,
    // the same-day plan is revised through the day but not every half hour; overnight it can stand for hours
    data_stale_min: 12 * 60,
    attribution: "Source: OCCTO (電力広域的運営推進機関), 広域予備率Web公表システム. Changes: CyberView reads the current half hour's wide-area reserve rate per area and turns it into a level (5%, 3%, 1%)." },
};
export const REGIONS = Object.fromEntries(Object.values(OCCTO_AREAS).map(([name, lat, lng]) => [`occto-reserve|${name}`, { name, lat, lng }]));

/** dailyData reply -> one item per supply area for the current half hour (Japan time). Throws bad_shape when the reply is
 *  not today's or has no rates. */
export function parseOccto(d, now = Date.now()) {
  if (!d || !Array.isArray(d.todayAreaRsvRateList) || !d.todayRangeItem) throw badShape("occto");
  const { day, slot } = jstSlot(now);
  if (d.todayRangeItem.tgtDate !== day) throw badShape(`occto: reply is for ${str(d.todayRangeItem.tgtDate, 12)}, not ${day}`);
  const at = jstToIso(d.todayLastUpdate), out = [];
  const slotStart = isoS(Date.UTC(+day.slice(0, 4), +day.slice(5, 7) - 1, +day.slice(8, 10), Math.floor(slot / 2), (slot % 2) * 30) - JST);
  for (const a of d.todayAreaRsvRateList) {
    const area = OCCTO_AREAS[a && a.areaCd];
    const x = area && Array.isArray(a.areaRsvRateItems) ? a.areaRsvRateItems[slot] : null;
    const rate = x ? Number(x.koikRsvRate) : NaN;
    if (!area || x == null || x.koikRsvRate == null || !isFinite(rate)) continue;
    const stage = OCCTO_STAGES.find(([pct]) => rate < pct);
    const demand = Number(x.areaJyyu), supply = Number(x.areaKyu);
    out.push({ id: `occto-reserve:${a.areaCd}`, source: "occto-reserve", country: "JP", region: area[0], area: `${area[0]} supply area`,
      lat: null, lng: null, customers: null, kind: "supply_warning", planned: false, level: stage ? stage[1] : 0,
      cause: str(`wide-area reserve ${rate}%${stage ? ` (${stage[2]})` : ""}${isFinite(demand) && isFinite(supply) ? `; area demand ${Math.round(demand).toLocaleString("en-US")} of ${Math.round(supply).toLocaleString("en-US")} MW` : ""}`, 120),
      started_at: slotStart, restore_est: "", url: OCCTO_BASE });
  }
  if (!out.length) throw badShape("occto: no area has a reserve rate for the current half hour");
  return stamp(out, at);
}

export const ADAPTERS = {
  "occto-reserve": async (h) => {
    const { day } = jstSlot(Date.now());
    return parseOccto(await h.get(`${OCCTO_BASE}home/dailyData?inputDate=${encodeURIComponent(day)}`, { timeoutMs: 40000 }));
  },
};

export default {
  sources: SOURCES,
  regions: REGIONS,
  adapters: Object.fromEntries(Object.entries(ADAPTERS).map(([k, fn]) => [k, async (h) => { const got = await fn(h); return stamp(got.map((x) => h.item(x)), got.data_at); }])),
};
