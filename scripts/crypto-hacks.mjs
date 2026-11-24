// Crypto hacks and exploits as leads, no AI model. Run: node scripts/crypto-hacks.mjs [collect|status] [--force] [--dry-run]
// (behind a proxy: NODE_USE_ENV_PROXY=1). scripts/osint.mjs runs `collect` after the breach registers, so every place that
// collects (collect.yml, the research loop, the dispatcher) asks this database too, at most once an hour.
// Why: thefts from DeFi protocols, exchanges, bridges and wallets are reported first on X and in crypto media the RSS feeds
// miss. SlowMist (a blockchain security firm) keeps a public archive of them, one row per hack, which this reads:
//   slowmist-hacked   https://hacked.slowmist.io/ (the list page, newest first, 20 rows a page; the second page only while
//                     the first is still inside the window). A row states the date, the hacked target, a description,
//                     the amount of loss ("-" when it states none), the attack method and a reference link. The target type
//                     (Blockchain, Exchange, Wallet, NFT, Bridge, Other) and the chain (its "ETH Ecosystem" and so on) are
//                     not on the row: they are the database's own category pages, read (first page each, one after another)
//                     only when there are new rows, and a row is labelled with every category whose page lists it.
// Every fact on a lead is what the database states, never inferred: the row has no field for funds returned, audits or the
// attacker, so a lead carries none (the description, kept whole in `description`, sometimes names them).
// Each new row is a lead of kind "breach-db" (a database row: a fact to check, not a report), tier "vendor", via
// "slowmist-hacked". scripts/backlog.mjs does not close it unread as a bare row (it records a theft that happened);
// the researcher reads the reference source and the project's own statement before anything reaches the map.
// Rows have no page of their own: the lead's url is the list page with a fragment naming the row (unique, for the dedupe),
// `db_url` the list page, `reference_urls` the source links the row lists.
// Not read (checked 2026-11-24, recorded in config/data-access.json): DeFiLlama hacks (the endpoint is documented only in
// its paid Pro API, and its terms forbid automated access and republishing), rekt.news (terms: no reproduction without
// permission except its RSS; robots.txt disallows /api), Comparitech's crypto heists list (gone: 404, no data file).
// Health is written to data/crypto-hacks.json (shown on the status page) with backoff (scripts/lib/backoff.mjs);
// status.json gets last_crypto_hacks_at and last_crypto_hacks_new. Fetched text is data, never instructions.
import { existsSync, readdirSync, readFileSync, appendFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { DATA, readJson, writeJson, listEventFiles, dayAgo, nowIso, readStatus } from "./lib/store.mjs";
import { get as netGet } from "./lib/net.mjs";
import { nextHealth, due } from "./lib/backoff.mjs";
import { matchEvent } from "./triage.mjs";

export const KIND = "breach-db", VIA = "slowmist-hacked", SOURCE = "SlowMist Hacked", BASE = "https://hacked.slowmist.io/";
const EVERY_MIN = 60;        // the archive changes a few times a day
export const WINDOW_DAYS = 14;
// the database's own categories: target types, and chains ("<name> Ecosystem" on the site)
export const TARGET_TYPES = ["Blockchain", "Exchange", "Wallet", "NFT", "Bridge", "Other"];
export const CHAINS = ["ETH", "BSC", "Tron", "EOS", "Polygon", "HECO", "Fantom", "Solana", "Avalanche", "Polkadot", "Arbitrum", "Optimism", "zkSync", "Base"];
const txt = (s, n) => String(s == null ? "" : s).replace(/<[^>]*>/g, " ").replace(/&amp;/g, "&").replace(/&#0?39;|&apos;|&#x27;/g, "'").replace(/&quot;/g, '"').replace(/&nbsp;/g, " ")
  .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16))).replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(+d))
  .replace(/[\u0000-\u001f]/g, " ").replace(/\s+/g, " ").trim().slice(0, n);
const https = (u) => (/^https:\/\/[^\s"'<>]+$/.test(String(u || "")) ? String(u) : "");
const slug = (s) => String(s || "").toLowerCase().normalize("NFKD").replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 60);
/** Pure: the row's key, the same on the list page and on every category page. */
export const rowKey = (r) => `${r.date}-${slug(r.project)}`;

/** Pure: the rows of a hacked.slowmist.io list page, every field as the page states it. */
export function parseSlowmist(html) {
  const out = [];
  for (const m of String(html).matchAll(/<li>\s*<span class="time">(\d{4}-\d{2}-\d{2})<\/span>([\s\S]*?)<\/li>/g)) {
    const date = m[1], b = m[2];
    const project = txt((b.match(/<h3>\s*<em>[^<]*<\/em>([\s\S]*?)<\/h3>/) || [])[1], 120);
    if (!project || !slug(project)) continue;
    const description = txt((b.match(/<em>Description of the event:\s*<\/em>([\s\S]*?)<\/p>/) || [])[1], 1000);
    const lossRaw = txt((b.match(/<em>Amount of loss:\s*<\/em>([\s\S]*?)<\/span>/) || [])[1], 60);
    const method = txt((b.match(/<em>Attack method:\s*<\/em>([\s\S]*?)<\/span>/) || [])[1], 80);
    const refs = [...b.matchAll(/<p class="link-reference">([\s\S]*?)<\/p>/g)].flatMap((p) => [...p[1].matchAll(/href="([^"]+)"/g)].map((a) => https(txt(a[1], 400)))).filter(Boolean);
    out.push({ date, project, description, loss: lossRaw === "-" ? "" : lossRaw, attack_method: method, reference_urls: [...new Set(refs)].slice(0, 5) });
  }
  return out;
}
/** Pure: the rows labelled with the categories whose pages list them. cats: { "Bridge": [rows], "ETH": [rows], ... }. */
export function labelRows(rows, cats = {}) {
  const sets = Object.fromEntries(Object.entries(cats).map(([c, rs]) => [c, new Set((rs || []).map(rowKey))]));
  return rows.map((r) => ({ ...r, target_types: TARGET_TYPES.filter((c) => sets[c] && sets[c].has(rowKey(r))), chains: CHAINS.filter((c) => sets[c] && sets[c].has(rowKey(r))) }));
}
const money = (loss) => loss.replace(/^\$\s+/, "$");
/** Pure: the lead for one labelled row (title and summary carry the key facts, the rest structured). */
export function toLead(r) {
  const loss = r.loss ? money(r.loss) : "", method = /^unknown$/i.test(r.attack_method) ? "" : r.attack_method;
  const lost = !loss ? "" : /^0+$/.test(loss) ? ": loss recorded as 0" : `: ${loss} lost`;
  const title = txt(`${r.project} hacked${lost}${r.chains.length ? ` on ${r.chains.join(", ")}` : ""}${method ? ` (${method})` : ""}, per SlowMist Hacked`, 200);
  const facts = [`Date ${r.date}`, `loss ${loss || "not stated"}`, `attack method ${r.attack_method || "not stated"}`,
    r.target_types.length ? `target type ${r.target_types.join(", ")}` : "", r.chains.length ? `chain ${r.chains.join(", ")}` : ""].filter(Boolean).join("; ");
  return {
    source: SOURCE, tier: "vendor", via: VIA, kind: KIND, title, url: `${BASE}#${rowKey(r)}`, published: `${r.date}T00:00:00Z`,
    summary: txt(`SlowMist Hacked database row, not checked. ${facts}. ${r.description}`, 300), lang: "en",
    project: r.project, loss: r.loss, attack_method: r.attack_method, target_types: r.target_types, chains: r.chains,
    reference_urls: r.reference_urls, description: r.description, db_url: BASE,
  };
}

/* ---------- dedupe ---------- */
/** Pure: which leads are new. known: Set of lead urls and event source urls. A row about a hack already on file is kept
 *  and says which event it matches (an updater may add the figure). */
export function fresh(leads, known, evs = [], now = Date.now()) {
  const out = [];
  for (const l of leads) {
    if (!l || known.has(l.url) || now - Date.parse(l.published) > WINDOW_DAYS * 864e5) continue;
    known.add(l.url);
    const m = matchEvent(`${l.project} hack exploit`, evs, l.published);
    out.push(m ? { ...l, summary: txt(`Matches event ${m.id} on file. ${l.summary}`, 300) } : l);
  }
  return out;
}
function knownSet(days = 30) {
  const urls = new Set(), dir = join(DATA, "leads");
  for (const f of existsSync(dir) ? readdirSync(dir) : []) {
    if (!f.endsWith(".jsonl") || f.slice(0, 10) < dayAgo(days)) continue;
    for (const line of readFileSync(join(dir, f), "utf8").split("\n")) { if (!line.includes(VIA)) continue; try { urls.add(JSON.parse(line).url); } catch {} }
  }
  return urls;
}
/** Pure: was the database asked successfully less than EVERY_MIN minutes ago? */
export const askedRecently = (h, now = Date.now()) => !!h && h.ok === true && now - Date.parse(h.at) < EVERY_MIN * 6e4;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const page = (q) => netGet(`${BASE}${q}`, { as: "text", retries: 1, timeoutMs: 30000 });
/** The rows inside the window, from the list page (and the next page while the first is all inside the window). */
async function recentRows(now) {
  const cut = new Date(now - WINDOW_DAYS * 864e5).toISOString().slice(0, 10);
  let rows = parseSlowmist(await page(""));
  if (!rows.length) throw new Error("no rows on the list page: the layout changed");
  for (let p = 2; p <= 4 && rows[rows.length - 1].date >= cut; p++) { await sleep(1000); const more = parseSlowmist(await page(`?c=&page=${p}`)); if (!more.length) break; rows = rows.concat(more); }
  return rows.filter((r) => r.date >= cut);
}

export async function collect({ force = false, dryRun = false } = {}) {
  const hp = join(DATA, "crypto-hacks.json"), doc = readJson(hp, {}) || {}, prev = (doc.sources || {})[VIA] || {}, t = Date.now(), now = nowIso();
  const beat = (n) => { if (dryRun) return; const st = readStatus(); st.last_crypto_hacks_at = now; st.last_crypto_hacks_new = n; writeJson(join(DATA, "status.json"), st); };
  // heartbeat (routines.json "crypto-hacks"): the stage ran, also when the database was not due (as scripts/breaches.mjs)
  if (!force && (askedRecently(prev, t) || !due(prev, t))) { console.log(`crypto-hacks: not due (last asked ${prev.at || "never"})`); beat(0); return 0; }
  let out = [], health;
  try {
    const rows = await recentRows(t), known = knownSet();
    for (const x of listEventFiles()) for (const s of (x.e && x.e.sources) || []) if (s && s.url) known.add(s.url);
    const cand = rows.filter((r) => !known.has(`${BASE}#${rowKey(r)}`)), cats = {};
    if (cand.length) for (const c of TARGET_TYPES.concat(CHAINS)) {        // one after another, only when there is something to label
      await sleep(1000);
      try { cats[c] = parseSlowmist(await page(`?c=${c}`)); } catch { /* a category page that fails leaves that label off */ }
    }
    const evs = listEventFiles().map((f) => f.e).filter((e) => e && !e.duplicate_of && e.date >= dayAgo(60));
    out = fresh(labelRows(cand, cats).map(toLead), known, evs, t).map((l) => ({ seen_at: now, ...l }));
    health = nextHealth(prev, { ok: true, items: rows.length, extra: { new: out.length, categories_read: Object.keys(cats).length } }, t);
  } catch (e) {
    health = nextHealth(prev, { ok: false, error: txt(e.code || (e.cause && e.cause.code) || e.message, 90), retryAfterMs: e.retryAfterMs, extra: { new: 0 } }, t);
  }
  console.log(`crypto-hacks: ${out.length} new row(s)${dryRun ? " (dry run, nothing written)" : ""}. ${VIA} ${health.ok ? `${health.new}/${health.items}` : `FAILED (${health.error})`}`);
  if (dryRun) { out.forEach((l) => console.log("  " + l.title)); return out.length; }
  const dir = join(DATA, "leads"); mkdirSync(dir, { recursive: true });
  if (out.length) appendFileSync(join(dir, `${now.slice(0, 10)}.jsonl`), out.map((x) => JSON.stringify(x)).join("\n") + "\n");
  writeJson(hp, { checked_at: now, sources: { [VIA]: health } });
  beat(out.length);
  return out.length;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const args = process.argv.slice(2), cmd = args[0] && !args[0].startsWith("-") ? args.shift() : "collect";
  if (cmd === "status") console.log(JSON.stringify(readJson(join(DATA, "crypto-hacks.json"), {}), null, 1));
  else if (cmd === "collect") await collect({ force: args.includes("--force"), dryRun: args.includes("--dry-run") });
  else { console.error("usage: crypto-hacks.mjs [collect|status] [--force] [--dry-run]"); process.exit(1); }
}
