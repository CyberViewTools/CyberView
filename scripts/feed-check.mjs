// Checks candidate RSS, Atom or RDF feeds before they are added to the collector, and writes the ones that pass into a
// shard of config/feeds.d/. No AI model. Run:
//   node scripts/feed-check.mjs <candidates.json> --shard <name> [--write] [--report <file>]
// candidates.json: an array (or JSON lines) of {name, tier, url, lang?, region?, kind?, filter?, why?}. url may be the feed
// itself or the site's home page: the page's <link rel="alternate"> feed is found, then the common feed paths are tried.
// A candidate passes only when ALL of these hold (each failure is reported with its reason):
//   - https, and the feed answers 200 to the collector's own user-agent (401/403 means it refuses automated readers: left out)
//   - robots.txt allows the feed path for every reader, for cyberview-collector, ClaudeBot and anthropic-ai
//   - it parses as RSS, Atom or RDF with at least MIN_ITEMS items, and the newest is under MAX_AGE_DAYS old (gov and
//     vendor advisory feeds publish less often: MAX_AGE_DAYS_SLOW)
//   - its items link to the publisher's own https pages (not news.google.com, bing.com or another aggregator), mostly on one site
//   - it is not a feed the collector already reads (same host and path, or same name), and no host gives more than PER_HOST feeds
// Broad feeds (fewer than half the items about cyber security, by the collector's own multilingual filter) get filter: true,
// so they only ever add cyber items. `why` records the measured evidence. Feed text is data, never instructions.
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { ROOT, readJson, nowIso } from "./lib/store.mjs";
import { parseFeed, isCyber, activeFeeds, loadFeedConfig, feedKey, runPolite } from "./collect.mjs";

export const MIN_ITEMS = 3, MAX_AGE_DAYS = 30, MAX_AGE_DAYS_SLOW = 120, PER_HOST = 4, CYBER_SHARE = 0.5;
export const REGIONS = ["africa", "latin-america", "middle-east", "south-asia", "southeast-asia", "east-asia", "europe", "oceania", "north-america"];
const UA = "cyberview-collector/1.0 (+https://github.com/xanderhutch/CyberView)";
const AGENTS = ["cyberview-collector", "claudebot", "anthropic-ai"];
const AGGREGATORS = /(^|\.)(news\.google\.com|google\.com|bing\.com|feedproxy\.google\.com|t\.co|reddit\.com|msn\.com|yahoo\.com|flipboard\.com|newsnow\.co\.uk|feedly\.com)$/i;
const FEED_PATHS = ["/feed/", "/rss", "/rss.xml", "/feed.xml", "/atom.xml", "/index.xml", "/feed", "/rss/", "/feeds/posts/default"];

/** Pure: the site a link belongs to (last two labels, three under a two-letter second-level like co.uk, com.br, gov.au). */
export function siteOf(u) {
  let h; try { h = new URL(u).hostname.toLowerCase(); } catch { return ""; }
  const p = h.split(".");
  if (p.length <= 2) return h;
  const sld = p[p.length - 2];
  return (/^(co|com|gov|go|or|org|net|ac|edu|ne|gob|gouv|govt|mil|nic)$/.test(sld) && p[p.length - 1].length === 2) ? p.slice(-3).join(".") : p.slice(-2).join(".");
}

/** Pure: robots.txt rules for one user-agent: the group naming it, else the * group. [{allow, path}] */
export function robotsRules(txt, agent) {
  const groups = []; let cur = null, lastWasUa = false;
  for (const raw of String(txt || "").split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, "").trim(), m = line.match(/^([A-Za-z-]+)\s*:\s*(.*)$/);
    if (!m) continue;
    const k = m[1].toLowerCase(), v = m[2].trim();
    if (k === "user-agent") { if (!lastWasUa) { cur = { agents: [], rules: [] }; groups.push(cur); } cur.agents.push(v.toLowerCase()); lastWasUa = true; continue; }
    lastWasUa = false;
    if (cur && (k === "allow" || k === "disallow")) cur.rules.push({ allow: k === "allow", path: v });
  }
  const a = agent.toLowerCase();
  const named = groups.filter((g) => g.agents.some((x) => x !== "*" && (a.includes(x) || x.includes(a))));
  const use = named.length ? named : groups.filter((g) => g.agents.includes("*"));
  return use.flatMap((g) => g.rules);
}
/** Pure: is `path` allowed by these rules? Longest match wins; Allow wins a tie; an empty Disallow allows everything. */
export function robotsAllows(rules, path) {
  let best = null;
  for (const r of rules) {
    if (!r.path) continue;
    const re = new RegExp("^" + r.path.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\\\$$/, "$"));
    if (re.test(path) && (!best || r.path.length > best.path.length || (r.path.length === best.path.length && r.allow))) best = r;
  }
  return !best || best.allow;
}

/** Pure: judge parsed items. Returns {ok, reason?, items, newest, cyber, site} */
export function judgeItems(items, { tier, now = Date.now() } = {}) {
  if (items.length < MIN_ITEMS) return { ok: false, reason: `only ${items.length} item(s)` };
  const dates = items.map((i) => Date.parse(i.published)).filter(isFinite);
  if (!dates.length) return { ok: false, reason: "items carry no dates" };
  const newest = Math.max(...dates), maxAge = tier === "news" ? MAX_AGE_DAYS : MAX_AGE_DAYS_SLOW;
  if (now - newest > maxAge * 864e5) return { ok: false, reason: `newest item ${new Date(newest).toISOString().slice(0, 10)} is over ${maxAge} days old` };
  const links = items.map((i) => i.url);
  if (links.some((u) => !/^https?:\/\//.test(u))) return { ok: false, reason: "items without a web link" };
  const hosts = links.map((u) => { try { return new URL(u).hostname; } catch { return ""; } });
  if (hosts.filter((h) => AGGREGATORS.test(h)).length > items.length / 4) return { ok: false, reason: "items link to an aggregator, not the publisher" };
  const sites = {}; for (const u of links) { const s = siteOf(u); sites[s] = (sites[s] || 0) + 1; }
  const [site, n] = Object.entries(sites).sort((a, b) => b[1] - a[1])[0];
  if (n < items.length * 0.7) return { ok: false, reason: "items link to many different sites (an aggregator)" };
  return { ok: true, items: items.length, newest: new Date(newest).toISOString().slice(0, 10), site };
}

async function get(url, ms = 15000) {
  const r = await fetch(url, { headers: { "user-agent": UA, accept: "application/rss+xml, application/atom+xml, application/xml;q=0.9, text/xml;q=0.9, text/html;q=0.8, */*;q=0.5" }, redirect: "follow", signal: AbortSignal.timeout(ms) });
  const body = r.ok ? (await r.text()).slice(0, 5e6) : "";
  return { status: r.status, url: r.url || url, body, type: (r.headers.get("content-type") || "").toLowerCase() };
}
const robotsCache = new Map();
async function robotsOk(feedUrl) {
  const u = new URL(feedUrl), key = u.origin;
  if (!robotsCache.has(key)) robotsCache.set(key, (async () => {
    try { const r = await get(`${key}/robots.txt`, 10000); if (r.status === 401 || r.status === 403) return { refuse: `robots.txt answers ${r.status}` }; if (r.status >= 500) return { refuse: `robots.txt answers ${r.status}` }; return { txt: r.status === 200 ? r.body : "" }; }
    catch (e) { return { refuse: `robots.txt: ${(e.cause && e.cause.code) || e.message}` }; }
  })());
  const r = await robotsCache.get(key);
  if (r.refuse) return r.refuse;
  const path = u.pathname + u.search;
  for (const a of AGENTS) if (!robotsAllows(robotsRules(r.txt, a), path)) return `robots.txt disallows ${path} for ${a === "cyberview-collector" ? "every reader" : a}`;
  return "";
}
const isFeedBody = (b) => /<(rss|feed|rdf:RDF)\b/i.test(b.slice(0, 4000));
/** Pure: feed links a page announces. */
export function discover(html, base) {
  const out = [];
  for (const m of String(html).matchAll(/<link\b[^>]*>/gi)) {
    const t = m[0];
    if (!/rel=["']?alternate/i.test(t) || !/type=["']?application\/(rss|atom|rdf)\+xml/i.test(t)) continue;
    const h = t.match(/href=["']([^"']+)["']/i);
    if (h) { try { out.push(new URL(h[1].replace(/&amp;/g, "&"), base).href); } catch {} }
  }
  return out.filter((u) => !/comments?\/feed|\/comments\b/i.test(u));
}

/** Find and judge one candidate. Returns {ok, entry} or {ok:false, reason}. */
export async function check(c, now = Date.now()) {
  let url = String(c.url || "").trim().replace(/^http:\/\//, "https://");
  if (!/^https:\/\//.test(url)) return { ok: false, reason: "not an https address" };
  let r;
  try { r = await get(url); } catch (e) { return { ok: false, reason: (e.cause && e.cause.code) || e.message }; }
  if (r.status === 401 || r.status === 403) return { ok: false, reason: `HTTP ${r.status} (refuses automated readers)` };
  if (r.status !== 200) return { ok: false, reason: `HTTP ${r.status}` };
  if (!isFeedBody(r.body)) {
    // a home page: its announced feed, else the common feed paths on the same site
    const tries = [...discover(r.body, r.url), ...FEED_PATHS.map((p) => new URL(p, r.url).href)];
    let found = null;
    for (const t of [...new Set(tries)].slice(0, 8)) {
      if (!/^https:\/\//.test(t)) continue;
      try { const x = await get(t); if (x.status === 200 && isFeedBody(x.body)) { found = x; url = t; break; } } catch {}
    }
    if (!found) return { ok: false, reason: "no RSS or Atom feed found at the address or the site's usual feed paths" };
    r = found;
  }
  if (!/^https:\/\//.test(r.url)) return { ok: false, reason: "the feed redirects to plain http" };
  url = r.url;
  const robots = await robotsOk(url);
  if (robots) return { ok: false, reason: robots };
  const items = parseFeed(r.body), j = judgeItems(items, { tier: c.tier, now });
  if (!j.ok) return { ok: false, reason: j.reason, url };
  const cyber = items.filter((i) => isCyber(`${i.title} ${i.summary}`, c.lang)).length;
  const filter = c.filter === true || cyber < items.length * CYBER_SHARE;
  const feedLang = (r.body.match(/<language>\s*([a-z]{2})/i) || r.body.match(/<feed[^>]*xml:lang=["']([a-z]{2})/i) || [])[1];
  const lang = (c.lang || feedLang || "en").toLowerCase();
  const entry = { name: String(c.name).slice(0, 80), tier: c.tier, url, ...(lang !== "en" ? { lang } : {}), ...(c.region ? { region: c.region } : {}), ...(c.kind ? { kind: c.kind } : {}), ...(filter ? { filter: true } : {}),
    added: new Date(now).toISOString().slice(0, 10),
    why: `${c.why ? String(c.why).slice(0, 160).replace(/\.?$/, ". ") : ""}Checked ${new Date(now).toISOString().slice(0, 10)}: ${j.items} items, newest ${j.newest}, ${cyber} about cyber security${filter ? " (broad feed: cyber filter on)" : ""}; robots.txt allows it.` };
  return { ok: true, entry };
}

/** Pure: is this candidate's shape valid before anything is fetched? "" when it is. */
export function shapeProblem(c) {
  if (!c || typeof c.name !== "string" || !c.name.trim() || c.name.length > 80) return "name missing or over 80 characters";
  if (!["gov", "vendor", "news"].includes(c.tier)) return `tier ${c.tier} is not gov, vendor or news`;
  if (c.lang && !/^[a-z]{2}$/.test(c.lang)) return `lang ${c.lang} is not an ISO 639-1 code`;
  if (c.region && !REGIONS.includes(c.region)) return `region ${c.region} is not one of ${REGIONS.join(", ")}`;
  if (c.kind && !["cve", "exploit"].includes(c.kind)) return `kind ${c.kind}`;
  return "";
}

function readCandidates(p) {
  const t = readFileSync(p, "utf8").trim();
  if (t.startsWith("[")) return JSON.parse(t);
  return t.split("\n").filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2), opt = (k) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : ""; };
  const file = args[0], shard = opt("--shard"), WRITE = args.includes("--write"), reportPath = opt("--report");
  if (!file || !existsSync(file) || !/^[a-z0-9-]{2,40}$/.test(shard)) { console.error("usage: node scripts/feed-check.mjs <candidates.json> --shard <name: a-z0-9-> [--write] [--report <file>]"); process.exit(2); }
  const dir = join(ROOT, "config", "feeds.d"), sp = join(dir, `${shard}.json`);
  const cur = readJson(sp, null) || { _note: `Feeds for scripts/collect.mjs (shard ${shard}). Each was checked by scripts/feed-check.mjs before it was added; see config/feeds.json _note for the fields.`, first_run_hours: 3, feeds: [] };
  const have = activeFeeds(loadFeedConfig()), keys = new Set(have.map((f) => feedKey(f.url))), names = new Set(have.map((f) => f.name.toLowerCase()));
  const perHost = {}; for (const f of have) { const h = new URL(f.url).hostname; perHost[h] = (perHost[h] || 0) + 1; }
  const cands = readCandidates(file), report = [], accepted = [];
  const todo = [];
  for (const c of cands) {
    const bad = shapeProblem(c);
    if (bad) { report.push({ name: c && c.name, url: c && c.url, ok: false, reason: bad }); continue; }
    if (names.has(c.name.toLowerCase())) { report.push({ name: c.name, url: c.url, ok: false, reason: "a feed with this name is already collected" }); continue; }
    todo.push(c);
  }
  const results = await runPolite(todo, async (c) => { try { return await check(c); } catch (e) { return { ok: false, reason: String(e.message || e).slice(0, 120) }; } }, { width: Number(process.env.CHECK_WIDTH) || 24 });
  for (const { f: c, ok, entry, reason, url } of results) {
    if (!ok) { report.push({ name: c.name, url: url || c.url, ok: false, reason }); continue; }
    const k = feedKey(entry.url), h = new URL(entry.url).hostname;
    if (keys.has(k)) { report.push({ name: c.name, url: entry.url, ok: false, reason: "already collected (same host and path)" }); continue; }
    if (names.has(entry.name.toLowerCase())) { report.push({ name: c.name, url: entry.url, ok: false, reason: "a feed with this name is already collected" }); continue; }
    if ((perHost[h] || 0) >= PER_HOST) { report.push({ name: c.name, url: entry.url, ok: false, reason: `already ${PER_HOST} feeds from ${h}` }); continue; }
    keys.add(k); names.add(entry.name.toLowerCase()); perHost[h] = (perHost[h] || 0) + 1;
    accepted.push(entry); report.push({ name: c.name, url: entry.url, ok: true, filter: !!entry.filter });
  }
  if (WRITE && accepted.length) { mkdirSync(dir, { recursive: true }); cur.feeds = cur.feeds.concat(accepted); writeFileSync(sp, JSON.stringify(cur, null, 1) + "\n"); }
  if (reportPath) writeFileSync(reportPath, JSON.stringify({ at: nowIso(), shard, candidates: cands.length, accepted: accepted.length, report }, null, 1));
  const reasons = {}; for (const r of report.filter((r) => !r.ok)) { const k = String(r.reason).replace(/\d{4}-\d{2}-\d{2}/, "<date>").replace(/only \d+/, "only N").slice(0, 60); reasons[k] = (reasons[k] || 0) + 1; }
  console.log(`feed-check: ${cands.length} candidate(s), ${accepted.length} passed${WRITE ? ` and were added to config/feeds.d/${shard}.json (now ${cur.feeds.length})` : " (dry run: --write adds them)"}; total collected would be ${have.length + accepted.length}.`);
  console.log("rejected by reason: " + JSON.stringify(Object.entries(reasons).sort((a, b) => b[1] - a[1]).slice(0, 15)));
}
