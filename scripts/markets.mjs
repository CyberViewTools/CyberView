// End-of-day share prices for the Markets page. No AI model. Run: node scripts/markets.mjs
// Source: Alpha Vantage TIME_SERIES_DAILY (needs ALPHAVANTAGE_API_KEY; the free key allows 25 calls a day).
// Each run spends at most MARKETS_MAX_CALLS calls (default 6), in this order:
//   1. symbols never fetched, 2. tickers on events from the last 14 days (breach victims), 3. the stalest of the rest.
// Writes data/markets/prices/<SYMBOL>.json ({symbol, source, fetched_at, days:[[date, close, volume]]}),
// data/status.json last_markets_at, and a run log. Never deletes price history.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { DATA, ROOT, readJson, writeJson, nowIso, writeRunLog, listEventFiles, dayAgo } from "./lib/store.mjs";
import { get } from "./lib/net.mjs";
import { parseDailyCsv, mergeDays, SYMBOL_RE } from "./lib/markets.mjs";

const KEY = process.env.ALPHAVANTAGE_API_KEY || "";
const MAX = Number(process.env.MARKETS_MAX_CALLS || 6);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
if (!KEY) { console.log("markets: ALPHAVANTAGE_API_KEY is not set; skipping"); process.exit(0); }

const cfg = JSON.parse(readFileSync(join(ROOT, "config", "markets.json"), "utf8"));
const dir = join(DATA, "markets", "prices");
const victims = new Set(listEventFiles().map((f) => f.e).filter((e) => e && e.ticker && e.date >= dayAgo(14) && !e.duplicate_of).map((e) => e.ticker));
const all = [...new Set([cfg.benchmark, ...cfg.tracked.map((t) => t.symbol), ...victims])].filter((s) => SYMBOL_RE.test(s));
const age = (s) => { const d = readJson(join(dir, `${s}.json`), null); return d && d.fetched_at ? Date.parse(d.fetched_at) : 0; };
const fresh = (s) => Date.now() - age(s) < 18 * 36e5;   // fetched in the last 18 h: skip
const queue = [
  ...all.filter((s) => !age(s)),
  ...all.filter((s) => victims.has(s) && age(s) && !fresh(s)),
  ...all.filter((s) => age(s) && !fresh(s) && !victims.has(s)).sort((a, b) => age(a) - age(b)),
].filter((s, i, a) => a.indexOf(s) === i).slice(0, MAX);

const log = { started_at: nowIso(), fetched: [], failed: [], skipped_fresh: all.filter(fresh).length };
for (const s of queue) {
  const url = `https://www.alphavantage.co/query?function=TIME_SERIES_DAILY&symbol=${encodeURIComponent(s)}&outputsize=compact&datatype=csv&apikey=${encodeURIComponent(KEY)}`;
  try {
    const body = await get(url, { as: "text", key: "alphavantage", retries: 1 });
    if (/"(Note|Information|Error Message)"/.test(body)) {
      // rate limit or unknown symbol: Alpha Vantage answers 200 with a JSON message
      const msg = (body.match(/"(?:Note|Information|Error Message)"\s*:\s*"([^"]{0,140})/) || [])[1] || "message";
      log.failed.push(`${s}: ${msg}`);
      if (/rate|limit|premium|per day|per minute/i.test(msg)) break;
      continue;
    }
    const p = join(dir, `${s}.json`), old = readJson(p, { days: [] });
    writeJson(p, { symbol: s, source: "Alpha Vantage", fetched_at: nowIso(), days: mergeDays(old.days, parseDailyCsv(body)) });
    log.fetched.push(s);
  } catch (e) { log.failed.push(`${s}: ${e.code || e.message}`); }
  await sleep(13000);   // the free tier allows 5 calls a minute
}
const sp = join(DATA, "status.json"), st = readJson(sp, {});
if (log.fetched.length) st.last_markets_at = nowIso();
writeJson(sp, st);
log.finished_at = nowIso(); log.queue_left = Math.max(0, all.filter((s) => !fresh(s)).length);
writeRunLog("markets", log);
console.log(`markets: fetched ${log.fetched.join(", ") || "none"}; ${log.skipped_fresh} fresh; ${log.queue_left} still due` + (log.failed.length ? `; failed: ${log.failed.join("; ")}` : ""));
