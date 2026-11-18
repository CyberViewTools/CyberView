// Pure market helpers shared by scripts/markets.mjs (fetch) and scripts/build.mjs (computations). No network here.
// Prices are end-of-day closes from Alpha Vantage's TIME_SERIES_DAILY, which is NOT adjusted for splits:
// any day-to-day move beyond SPLIT_LIMITS is treated as a probable split and no return is computed across it.
export const SYMBOL_RE = /^[A-Z][A-Z0-9.\-]{0,9}$/;
const SPLIT_LIMITS = [0.6, 1.6];
const MAX_DAYS = 400;

/** Alpha Vantage daily CSV (timestamp,open,high,low,close,volume) -> [[date, close, volume]] oldest first. */
export function parseDailyCsv(csv) {
  const lines = String(csv || "").trim().split(/\r?\n/);
  if (!/^timestamp,open,high,low,close,volume/i.test(lines[0] || "")) throw Object.assign(new Error("not a daily CSV"), { code: "bad_shape" });
  return lines.slice(1).map((l) => l.split(",")).filter((c) => /^\d{4}-\d{2}-\d{2}$/.test(c[0]) && isFinite(+c[4]) && +c[4] > 0)
    .map((c) => [c[0], Math.round(+c[4] * 10000) / 10000, Math.round(+c[5]) || 0]).sort((a, b) => (a[0] < b[0] ? -1 : 1));
}

/** Merge new rows into old ones by date (new wins), keep the latest MAX_DAYS. */
export function mergeDays(old = [], add = []) {
  const m = new Map(old.map((r) => [r[0], r]));
  for (const r of add) m.set(r[0], r);
  return [...m.values()].sort((a, b) => (a[0] < b[0] ? -1 : 1)).slice(-MAX_DAYS);
}

/** Dates on which the close jumped by more than a split-sized ratio from the previous close. */
export function splitDays(days) {
  const out = [];
  for (let i = 1; i < days.length; i++) { const r = days[i][1] / days[i - 1][1]; if (r < SPLIT_LIMITS[0] || r > SPLIT_LIMITS[1]) out.push(days[i][0]); }
  return out;
}

const idxOnOrAfter = (days, d) => days.findIndex((r) => r[0] >= d);

/**
 * Share move around a disclosure date.
 * Day 0 = first trading day on or after the event date; base = the close before day 0.
 * Returns stock and benchmark returns to day 0 and day +4 (five trading days), the difference (abnormal return),
 * and both series indexed to 100 at the base for days -10..+10. Null when data is missing or a split falls inside.
 */
export function impact(stock, bench, date) {
  const i = idxOnOrAfter(stock, date);
  if (i < 1) return null;
  const lo = Math.max(0, i - 11), hi = Math.min(stock.length - 1, i + 10);
  const win = stock.slice(lo, hi + 1);
  if (splitDays(win).length) return { split: true };
  const base = stock[i - 1][1], bmap = new Map(bench.map((r) => [r[0], r[1]]));
  const bBase = bmap.get(stock[i - 1][0]);
  const ret = (k) => (stock[i + k] ? stock[i + k][1] / base - 1 : null);
  const bret = (k) => (stock[i + k] && bBase && bmap.get(stock[i + k][0]) ? bmap.get(stock[i + k][0]) / bBase - 1 : null);
  const r0 = ret(0), r4 = ret(4), b0 = bret(0), b4 = bret(4);
  const round = (x) => (x == null ? null : Math.round(x * 10000) / 10000);
  return {
    day0: stock[i][0], base_date: stock[i - 1][0],
    ret0: round(r0), ret5: round(r4), mkt0: round(b0), mkt5: round(b4),
    abn0: r0 != null && b0 != null ? round(r0 - b0) : null, abn5: r4 != null && b4 != null ? round(r4 - b4) : null,
    series: win.map((r, j) => {
      const b = bmap.get(r[0]);
      return [r[0], lo + j - i, Math.round((r[1] / base) * 10000) / 100, b && bBase ? Math.round((b / bBase) * 10000) / 100 : null];
    }),
  };
}

/** Percentage change over the last n trading days, ignoring windows that contain a split. */
export function change(days, n) {
  if (days.length <= n) return null;
  const a = days[days.length - 1 - n], b = days[days.length - 1];
  if (splitDays(days.slice(-n - 1)).length) return null;
  return Math.round((b[1] / a[1] - 1) * 10000) / 10000;
}

/** Closes for the last n trading days, rescaled through splits so the line is continuous (for drawing only). */
export function chartSeries(days, n = 90) {
  const w = days.slice(-n), out = [];
  let k = 1;
  for (let i = w.length - 1; i >= 0; i--) {
    out.unshift([w[i][0], Math.round(w[i][1] * k * 100) / 100]);
    if (i > 0) { const r = w[i][1] / w[i - 1][1]; if (r < SPLIT_LIMITS[0] || r > SPLIT_LIMITS[1]) k *= r; }
  }
  return out;
}
