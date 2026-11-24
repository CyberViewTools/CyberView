// Run-log helpers shared by the build (public run list in site/data/ops.json).
/** Pure: when a run log was written, for the public run list. The log's own time (finished_at, ended_at, started_at,
 *  at) when it is a real ISO time on that day; else the HHMM prefix of its file name; never a made-up or future time
 *  (some workers name their logs "sweep-r1.json", which used to read as "2026-11-23Tsw:ee:00Z"). "" = leave it out. */
export function runLogAt(day, file, r, now = Date.now()) {
  const iso = (v) => typeof v === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?Z$/.test(v) && !isNaN(Date.parse(v)) ? v : "";
  let at = "";
  for (const k of ["finished_at", "ended_at", "started_at", "at"]) { const v = iso(r && r[k]); if (v && v.slice(0, 10) === day) { at = v.replace(/\.\d+Z$/, "Z"); break; } }
  if (!at) { const m = /^(\d{2})(\d{2})-/.exec(file); if (m && +m[1] < 24 && +m[2] < 60) at = `${day}T${m[1]}:${m[2]}:00Z`; }
  if (!at || isNaN(Date.parse(at)) || Date.parse(at) > now + 5 * 60000) return "";
  return at.length === 17 ? at.replace("Z", ":00Z") : at;
}

/** Pure: a copy with every money figure removed, for the public status files (ops.json, efficiency.json). Keys that
 *  name a cost or a dollar amount (cost, cost_usd, cost_per_event, usd_month, window_cost, PRICES ...) are dropped at any
 *  depth; token counts, run counts and rates stay, so the status page still shows how much work ran (owner, 2026-11-24:
 *  the pen test found spend figures published; the owner's own view is `node scripts/budget.mjs status`). */
export const COST_KEY = /(^|_)(cost|costs|usd|price|prices|spend|dollars?)($|_)|^cost[A-Z]|Usd$|Cost$/i;
export function stripCosts(v) {
  if (Array.isArray(v)) return v.map(stripCosts);
  if (!v || typeof v !== "object") return v;
  const o = {};
  for (const k of Object.keys(v)) if (!COST_KEY.test(k)) o[k] = stripCosts(v[k]);
  return o;
}
