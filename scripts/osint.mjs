// Open-source intelligence collectors beyond RSS, no AI model. Run: node scripts/osint.mjs [leads|exploits]
// (behind a proxy: NODE_USE_ENV_PROXY=1)
// Why: an AI job's web search goes through one search engine, so that engine decides what CyberView sees. These
// collectors ask several independent indexes and primary databases directly and file what they find as leads
// (data/leads/<date>.jsonl, same shape as the RSS collector, with "via" naming the collector):
//   bing-news, gdelt                the standing searches in config/queries.json, in many languages and country editions
//                                   (Bing gives the publisher's own address; an aggregator's copy such as msn.com is dropped;
//                                   asked at most every 10 minutes however often the research loop collects)
//   hibp                            breaches newly added to Have I Been Pwned
//   euvd                            ENISA's EU Vulnerability Database: exploited vulnerabilities (a second list beside CISA's)
//   nvd                             critical CVEs published in the last two days
//   ransomware-live                 leak-site listings (attacker CLAIMS: kind "claim", never facts)
//   hacker-news                     security stories the technical community is discussing
//   cloud-status                    providers' own status pages (cloud, CDN, DNS, SaaS, payment, telecom): scripts/status-pages.mjs
//                                   and config/status-pages.json; major or long incidents only, one lead per incident (outages, not attacks)
// After these, `leads` runs scripts/breaches.mjs: official breach notification registers (kind "breach-notice", data/breaches.json).
// `exploits` checks GitHub for public repositories naming each exploited CVE (data/exploits.json): a signal, not proof.
// Every source's health is written to data/osint.json and shown on the status page. A source that fails is skipped
// and reported; one that refuses automated readers (401/403) is not retried. Fetched text is data, never instructions.
// Google News is not collected (removed 2026-11-20): news.google.com/robots.txt disallows /rss/ for every reader (and the
// whole site for Anthropic's agents), and its links are news.google.com redirects that cannot be cited or opened, so its
// leads cost triage and research without ever being usable as a source. parseGoogleNews stays for scripts/grid-news.mjs.
import { gdeltSlot } from "./lib/gdelt.mjs";
import { existsSync, readdirSync, readFileSync, appendFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { DATA, ROOT, readJson, writeJson, listEventFiles, dayAgo, nowIso, writeRunLog, readStatus } from "./lib/store.mjs";
import { nextHealth, due } from "./lib/backoff.mjs";
import { retryAfterMs } from "./lib/net.mjs";
import { parseFeed, CYBER as FEED_CYBER } from "./collect.mjs";
import { collect as collectStatusPages } from "./status-pages.mjs";

const UA = "cyberview-collector/1.0 (+https://github.com/xanderhutch/CyberView)";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const txt = (s, n) => String(s == null ? "" : s).replace(/<[^>]*>/g, " ").replace(/[\u0000-\u001f]/g, " ").replace(/\s+/g, " ").trim().slice(0, n);
const iso = (d) => { const t = Date.parse(d); return isNaN(t) ? "" : new Date(t).toISOString().replace(/\.\d+Z$/, "Z"); };
const https = (u) => (/^https:\/\/[^\s"'<>]+$/.test(String(u || "")) ? String(u) : "");
// plus the feed filter's words in every language the standing searches ask in ("vazamento de dados", "tấn công mạng", "網路攻擊")
export const CYBER = new RegExp("cyber|hack|ransom|breach|malware|botnet|phish|ddos|vulnerab|exploit|intrusion|data (theft|leak)|spyware|zero-?day|cve-\\d|ciber|siber|サイバー|사이버|سيبران|outage|incident de sécurité|datenleck|angriff|tấn công mạng|" + FEED_CYBER.source, "i");

async function get(url, as = "json") {
  const r = await fetch(url, { headers: { "user-agent": UA, accept: as === "json" ? "application/json" : "application/rss+xml, application/xml, text/xml, */*" }, signal: AbortSignal.timeout(25000) });
  if (r.status === 401 || r.status === 403) throw Object.assign(new Error(`HTTP ${r.status} (refuses automated readers; not retried)`), { final: true });
  if (r.status === 429) throw Object.assign(new Error("HTTP 429 (busy; backing off)"), { final: true, retryAfterMs: retryAfterMs(r.headers.get("retry-after")) });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const body = await r.text();
  return as === "json" ? JSON.parse(body) : body;
}

/* ---------- parsers (exported for unit tests) ---------- */
/** Google News RSS: "Headline - Publisher" titles; the link is Google's redirect, the publisher is in <source>. */
export function parseGoogleNews(xml) {
  const out = [];
  for (const m of String(xml).matchAll(/<item>[\s\S]*?<\/item>/g)) {
    const b = m[0], it = parseFeed(b)[0]; if (!it) continue;
    const src = b.match(/<source\b[^>]*url="([^"]+)"[^>]*>([\s\S]*?)<\/source>/);
    const publisher = txt(src ? src[2] : "", 80).replace(/&amp;/g, "&").replace(/&#39;|&apos;/g, "'").replace(/&quot;/g, '"'), title = publisher && it.title.endsWith(" - " + publisher) ? it.title.slice(0, -publisher.length - 3) : it.title;
    if (https(it.url)) out.push({ title: txt(title, 200), url: it.url, published: it.published, source: publisher || "Google News", publisher_url: https(src ? src[1] : "") });
  }
  return out;
}
/** Bing News RSS pubDate is US Pacific wall-clock time labelled "GMT" (checked 2026-11-20: WLUC's UPPCO wind story is
 *  "10:53:00 GMT" on Bing and 18:53 GMT on Google News and on the publisher's page; KOLO 07:16 on Bing, 15:16Z on its page).
 *  parseFeed read it as UTC: read the same wall-clock time in America/Los_Angeles (8 h in PST, 7 h in PDT), never later
 *  than now. "" stays "". */
export function bingTime(isoAsUtc, now = Date.now()) {
  const t = Date.parse(isoAsUtc || "");
  if (!isFinite(t)) return "";
  const off = (ms) => { const p = Object.fromEntries(new Intl.DateTimeFormat("en-US", { timeZone: "America/Los_Angeles", hourCycle: "h23", year: "numeric",
    month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" }).formatToParts(new Date(ms)).map((x) => [x.type, x.value]));
    return Date.UTC(+p.year, +p.month - 1, +p.day, +p.hour % 24, +p.minute, +p.second) - Math.floor(ms / 1000) * 1000; };
  let u = t - off(t); u = t - off(u);                       // second pass settles daylight-saving edges
  return new Date(Math.min(u, now)).toISOString().replace(/\.\d+Z$/, "Z");
}
/** Bing News RSS: the real article address is inside the redirect link's url= parameter; times as bingTime().
 *  publisher is the name Bing gives (<News:Source>), "" when it gives none. */
export function parseBingNews(xml, now = Date.now()) {
  const out = [];
  for (const m of String(xml).matchAll(/<item\b[\s\S]*?<\/item>/gi)) {
    const it = parseFeed(m[0])[0]; if (!it) continue;
    let url = it.url; try { const u = new URL(it.url); const real = u.searchParams.get("url"); if (/bing\.com$/.test(u.hostname) && real) url = real; } catch {}
    let host = ""; try { host = new URL(url).hostname.replace(/^www\./, ""); } catch {}
    const src = (m[0].match(/<News:Source>([\s\S]*?)<\/News:Source>/i) || [])[1] || "";
    const publisher = txt(src.replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(+n)).replace(/&quot;/g, '"').replace(/&#0?39;|&apos;/g, "'").replace(/&amp;/g, "&"), 80);
    if (https(url)) out.push({ title: it.title, url, published: bingTime(it.published, now), summary: it.summary, source: host || "Bing News", publisher });
  }
  return out;
}

/* ---------- publishers' own pages ---------- */
// sites that republish other publishers' articles: their copy is not the publisher's page, and researchers could not
// open msn.com copies at all (bing-news, 2026-11-18 to 20: 98 msn.com leads, none became an event, 14 closed as unreadable)
const AGGREGATOR = /^(?:[a-z0-9-]+\.)*(google\.[a-z.]+|bing\.com|msn\.com|yahoo\.com|news\.yahoo\.co\.jp|flipboard\.com|newsbreak\.com|ground\.news|smartnews\.com|newsnow\.co\.uk|feedly\.com|inoreader\.com|apple\.news|gdeltproject\.org)$/i;
/** Is this address an aggregator's copy (or not a usable address at all)? */
export function isAggregator(u) { try { return AGGREGATOR.test(new URL(u).hostname); } catch { return true; } }
// GDELT names the language in English ("Spanish"); the other collectors and the backlog rules use ISO codes ("es")
const GDELT_LANG = { english: "en", spanish: "es", french: "fr", portuguese: "pt", german: "de", italian: "it", dutch: "nl", polish: "pl", ukrainian: "uk", russian: "ru", turkish: "tr", arabic: "ar",
  hindi: "hi", indonesian: "id", japanese: "ja", korean: "ko", chinese: "zh", vietnamese: "vi", hebrew: "he", persian: "fa", greek: "el", romanian: "ro", czech: "cs", swedish: "sv", thai: "th", malay: "ms",
  hungarian: "hu", finnish: "fi", danish: "da", norwegian: "no", bulgarian: "bg", croatian: "hr", serbian: "sr", slovak: "sk", slovenian: "sl", lithuanian: "lt", latvian: "lv",
  estonian: "et", bengali: "bn", urdu: "ur", tamil: "ta", swahili: "sw", catalan: "ca", tagalog: "tl", filipino: "tl", afrikaans: "af", albanian: "sq", armenian: "hy", azerbaijani: "az",
  georgian: "ka", kazakh: "kk", macedonian: "mk", marathi: "mr", nepali: "ne", punjabi: "pa", telugu: "te", gujarati: "gu", kannada: "kn", malayalam: "ml", bosnian: "bs", galician: "gl", basque: "eu" };
// an ISO 639-1 code or nothing: a language name that is not mapped is never passed on as if it were a code
export const gdeltLang = (s) => GDELT_LANG[txt(s, 20).toLowerCase()] || "";
/** GDELT DOC 2.0 artlist. */
export function parseGdelt(d) {
  return (d && Array.isArray(d.articles) ? d.articles : []).map((a) => {
    const s = String(a.seendate || ""), when = /^\d{8}T\d{6}Z$/.test(s) ? `${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)}T${s.slice(9, 11)}:${s.slice(11, 13)}:${s.slice(13, 15)}Z` : "";
    return https(a.url) && a.title ? { title: txt(a.title, 200), url: a.url, published: when, source: txt(a.domain, 80) || "GDELT", lang: gdeltLang(a.language), country: txt(a.sourcecountry, 40) } : null;
  }).filter(Boolean);
}
/** Have I Been Pwned breaches added in the last `days` days (real, verified ones only). */
export function parseHibp(list, days = 7, now = Date.now()) {
  return (Array.isArray(list) ? list : []).filter((b) => b && b.IsVerified && !b.IsFabricated && !b.IsSpamList && !b.IsRetired && now - Date.parse(b.AddedDate) < days * 864e5 && /^[\w.-]{1,80}$/.test(b.Name || ""))
    .map((b) => ({ title: txt(`Have I Been Pwned adds ${b.Title}: ${Number(b.PwnCount || 0).toLocaleString("en-US")} accounts${b.BreachDate ? ", breach dated " + b.BreachDate : ""}${b.IsMalware ? " (malware or stealer data)" : ""}`, 200),
      url: `https://haveibeenpwned.com/Breach/${b.Name}`, published: iso(b.AddedDate), summary: txt(`Data: ${(b.DataClasses || []).slice(0, 8).join(", ")}.${b.Domain ? " Domain: " + b.Domain + "." : ""}`, 300), source: "Have I Been Pwned" }));
}
/** ENISA EUVD exploited or critical vulnerabilities. */
export function parseEuvd(list) {
  return (Array.isArray(list) ? list : []).map((v) => {
    const id = txt(v && v.id, 30); if (!/^EUVD-\d{4}-\d+$/.test(id)) return null;
    const cve = (String(v.aliases || "").match(/CVE-\d{4}-\d{4,}/) || [""])[0], score = Number(v.baseScore);
    return { title: txt(`${cve || id}${isFinite(score) && score > 0 ? ` (CVSS ${score})` : ""}: ${String(v.description || "").replace(/\*\*[^*]*\*\*/g, "")}`, 200), url: `https://euvd.enisa.europa.eu/vulnerability/${id}`,
      published: iso(v.exploitedSince || v.datePublished), summary: txt(v.description, 300), source: "ENISA EU Vulnerability Database" };
  }).filter(Boolean);
}
/** NVD CVE API 2.0 -> critical CVEs. */
export function parseNvd(d) {
  return (d && Array.isArray(d.vulnerabilities) ? d.vulnerabilities : []).map((x) => {
    const c = x && x.cve; if (!c || !/^CVE-\d{4}-\d{4,}$/.test(c.id || "") || /^(Rejected|Deferred)$/i.test(c.vulnStatus || "")) return null;
    const desc = ((c.descriptions || []).find((y) => y.lang === "en") || {}).value || "", m = c.metrics || {}, s = ((m.cvssMetricV40 || m.cvssMetricV31 || m.cvssMetricV30 || [])[0] || {}).cvssData || {};
    return { title: txt(`${c.id}${s.baseScore ? ` (CVSS ${s.baseScore})` : ""}: ${desc}`, 200), url: `https://nvd.nist.gov/vuln/detail/${c.id}`, published: iso(c.published), summary: txt(desc, 300), source: "NIST NVD" };
  }).filter(Boolean);
}
/** ransomware.live recent victims: leak-site listings. These are attackers' claims. */
export function parseRansomwareLive(list, hours = 48, now = Date.now()) {
  return (Array.isArray(list) ? list : []).filter((v) => v && v.victim && v.group && now - Date.parse(v.discovered || v.attackdate) < hours * 36e5 && /^https:\/\/www\.ransomware\.live\//.test(v.url || ""))
    .map((v) => ({ title: txt(`Claim: ${v.group} lists ${v.victim}${v.country ? " (" + v.country + ")" : ""} on its leak site`, 200), url: v.url, published: iso(v.discovered || v.attackdate),
      summary: txt(`Unverified attacker claim tracked by ransomware.live. Sector: ${v.activity || "unknown"}.`, 300), source: "ransomware.live", kind: "claim", country: txt(v.country, 4) }));
}
/** Hacker News (Algolia): stories with real discussion. */
export function parseHn(d, minPoints = 40) {
  return (d && Array.isArray(d.hits) ? d.hits : []).filter((h) => h && h.title && https(h.url) && (h.points || 0) >= minPoints && CYBER.test(h.title) && !/ransomware\.live/.test(h.url))
    .map((h) => ({ title: txt(h.title, 200), url: h.url, published: iso(h.created_at), summary: txt(`${h.points} points, ${h.num_comments || 0} comments on Hacker News.`, 300), source: "Hacker News" }));
}
/** Statuspage.io incidents (Cloudflare, GitHub): major and critical only. */
export function parseStatuspage(d, name, hours = 48, now = Date.now()) {
  return (d && Array.isArray(d.incidents) ? d.incidents : []).filter((i) => i && /^(major|critical)$/.test(i.impact) && now - Date.parse(i.created_at) < hours * 36e5 && https(i.shortlink))
    .map((i) => ({ title: txt(`${name} outage: ${i.name}`, 200), url: i.shortlink, published: iso(i.started_at || i.created_at), summary: txt(`${i.impact} impact, status ${i.status}. From the provider's own status page; an outage, not an attack, unless the provider says otherwise.`, 300), source: `${name} status`, kind: "status" }));
}
/** Google Cloud incidents.json: outages and high severity only. */
export function parseGcp(list, hours = 48, now = Date.now()) {
  return (Array.isArray(list) ? list : []).filter((i) => i && (i.status_impact === "SERVICE_OUTAGE" || i.severity === "high") && now - Date.parse(i.begin) < hours * 36e5 && /^[\w-]{5,40}$/.test(i.id || ""))
    .map((i) => ({ title: txt(`Google Cloud outage: ${i.external_desc}`, 200), url: `https://status.cloud.google.com/incidents/${i.id}`, published: iso(i.begin), summary: txt(`${i.service_name || ""}. From Google Cloud's status page; an outage, not an attack, unless Google says otherwise.`, 300), source: "Google Cloud status", kind: "status" }));
}

/* ---------- collectors ---------- */
const queries = () => (readJson(join(ROOT, "config", "queries.json"), {}).queries || []).filter((q) => q && typeof q.q === "string" && q.q.length <= 120).slice(0, 60);
let aggregatorCopies = 0;   // bing-news results dropped as aggregator copies in this run (shown in data/osint.json)
const two = (d) => new Date(Date.now() - d * 864e5).toISOString().slice(0, 19) + ".000";
const COLLECTORS = {
  // every standing search, in its own language and country edition (Google News, which used to cover the other
  // languages, is not collected: see the top of this file). Bing sometimes answers with an empty list: asked once more.
  // An aggregator's copy (msn.com and the like) is dropped: it is not the publisher's page, researchers could not open it,
  // and looking its headline up again on Bing News found the publisher's own page for none of 8 tried (2026-11-20).
  "bing-news": async () => {
    const out = [];
    let err = null, fails = 0; aggregatorCopies = 0;
    for (const q of queries()) {
      const hl = /^[\w-]{2,8}$/.test(q.hl || "") ? q.hl : "en", lang = hl.split("-")[0].toLowerCase(), cc = /^[A-Z]{2}$/.test(q.gl || "") ? q.gl : "US";
      const url = `https://www.bing.com/news/search?q=${encodeURIComponent(q.q)}&format=rss&qft=${encodeURIComponent('interval="7"')}&cc=${cc}&setlang=${lang}`;
      try {
        let items = parseBingNews(await get(url, "text"));
        if (!items.length) { await sleep(3000); items = parseBingNews(await get(url, "text")); }
        for (const { publisher, ...i } of items.slice(0, 12)) { if (isAggregator(i.url)) aggregatorCopies++; else out.push({ ...i, tier: "news", lang, region: q.region || "" }); }
        fails = 0;
      } catch (e) { err = e; fails++; if (e.final || fails >= 3) break; }   // a refusal or three failures in a row end the run
      await sleep(1200);
    }
    if (err && !out.length) throw err;
    return out;
  },
  // TO BE RETIRED: scripts/gdelt-gkg.mjs reads GDELT's raw 15-minute files instead (owner, 2026-11-21); this DOC API
  // collector stays until gdelt-gkg has run cleanly for a week, then goes (config/gdelt.json doc_api_retire_after, 2026-11-28)
  "gdelt": async () => {   // GDELT allows one request every 5 seconds
    const out = [], Q = ['(ransomware OR cyberattack OR "data breach" OR "cyber attack")', '(ciberataque OR cyberattaque OR Cyberangriff OR "ataque cibernético")', '("zero-day" OR "actively exploited" OR "hackers" OR "hacked")'];
    // the gate spaces this machine's requests; GDELT still answers 429 at times (other users behind the same address),
    // so a busy answer waits once and tries that query again, and the other queries still run
    let ok = 0, last = null;
    for (const q of Q) {
      const url = `https://api.gdeltproject.org/api/v2/doc/doc?query=${encodeURIComponent(q)}&mode=artlist&maxrecords=60&format=json&timespan=3h&sort=datedesc`;
      for (let t = 0; t < 2; t++) {
        await gdeltSlot(t ? 12000 : undefined);
        try { parseGdelt(await get(url)).forEach((i) => out.push({ ...i, tier: "news" })); ok++; break; }
        catch (e) { last = e; if (!/429/.test(e.message)) break; }
      }
    }
    if (!ok && last) throw last;
    return out;
  },
  "hibp": async () => parseHibp(await get("https://haveibeenpwned.com/api/v3/breaches")).map((i) => ({ ...i, tier: "vendor", kind: "breach-db" })),
  "euvd": async () => parseEuvd(await get("https://euvdservices.enisa.europa.eu/api/exploitedvulnerabilities")).map((i) => ({ ...i, tier: "gov", kind: "exploited" })),
  "nvd": async () => parseNvd(await get(`https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${two(2)}&pubEndDate=${two(0)}&cvssV3Severity=CRITICAL&resultsPerPage=40`)).slice(0, 25).map((i) => ({ ...i, tier: "gov", kind: "cve" })),
  "ransomware-live": async () => parseRansomwareLive(await get("https://api.ransomware.live/v2/recentvictims")).slice(0, 60).map((i) => ({ ...i, tier: "news" })),
  "hacker-news": async () => parseHn(await get("https://hn.algolia.com/api/v1/search_by_date?tags=story&numericFilters=points%3E40&hitsPerPage=100")).map((i) => ({ ...i, tier: "news" })),
  // every provider in config/status-pages.json that is due (each page at most every poll_minutes); one lead per incident
  "cloud-status": async () => {
    const r = await collectStatusPages();
    if (r.asked && r.failed.length === r.asked) throw new Error(`every status page failed: ${r.failed[0]}`);
    return r.leads;
  },
};

// the search indexes are asked at most every SEARCH_EVERY minutes, however often the research loop collects (each run is
// one request per standing search): polite to the index, and a story does not move faster than that anyway
const SEARCH = new Set(["bing-news", "gdelt"]), SEARCH_EVERY = 10;
/** Pure: did this search collector run successfully less than SEARCH_EVERY minutes ago? (h = its health entry) */
export function searchedRecently(h, name, now = Date.now()) {
  return SEARCH.has(name) && !!h && h.ok === true && now - Date.parse(h.at) < SEARCH_EVERY * 6e4;
}
/** What is already on file: every event's source addresses, and every lead of the last `days` days by address and (for
 *  collectors other than RSS) by publisher plus headline. Shared with scripts/gdelt-gkg.mjs. */
export const normTitle = (t) => String(t).toLowerCase().replace(/[^\p{L}\p{N}]+/gu, " ").trim().slice(0, 90);
export function knownLeads(days = 14) {
  const leadsDir = join(DATA, "leads"), known = new Set(), knownTitle = new Set();
  for (const x of listEventFiles()) for (const s of (x.e && x.e.sources) || []) if (s && s.url) known.add(s.url);
  for (const f of existsSync(leadsDir) ? readdirSync(leadsDir) : []) {
    if (!f.endsWith(".jsonl") || f.slice(0, 10) < dayAgo(days)) continue;
    for (const line of readFileSync(join(leadsDir, f), "utf8").split("\n")) { try { const l = JSON.parse(line); known.add(l.url); if (l.via && l.via !== "rss") knownTitle.add(l.source + "|" + normTitle(l.title)); } catch {} }
  }
  return { known, knownTitle, norm: normTitle };
}
async function leads() {
  const leadsDir = join(DATA, "leads"); mkdirSync(leadsDir, { recursive: true });
  const { known, knownTitle, norm } = knownLeads(14);
  const now = nowIso(), cutoff = Date.now() - 72 * 36e5, out = [], only = process.argv.slice(3);
  // health only for collectors that still exist (a removed one would sit on the status page forever)
  const health = Object.fromEntries(Object.entries(readJson(join(DATA, "osint.json"), { sources: {} }).sources || {}).filter(([k]) => k in COLLECTORS));
  // a collector that failed FAIL_RUNS runs in a row waits out its backoff (scripts/lib/backoff.mjs; a Retry-After is honoured)
  await Promise.all(Object.entries(COLLECTORS).filter(([n]) => (!only.length || only.includes(n)) && (only.includes(n) || (!searchedRecently(health[n], n) && due(health[n])))).map(async ([name, fn]) => {
    const prev = health[name] || {};
    try {
      const items = await fn(); let n = 0;
      for (const it of items) {
        if (!it.title || !https(it.url) || known.has(it.url)) continue;
        if (it.published && Date.parse(it.published) < cutoff && !it.status_id) continue;   // a long outage can have started earlier
        // search engines hand back the same story under changing redirect links: one lead per publisher and headline
        const tk = it.source + "|" + norm(it.title); if (knownTitle.has(tk)) continue;
        if (SEARCH.has(name) && !CYBER.test(it.title + " " + (it.summary || ""))) continue;
        known.add(it.url); knownTitle.add(tk); n++;
        out.push({ seen_at: now, source: txt(it.source, 80), tier: it.tier, via: name, title: it.title, url: it.url, published: it.published || "", summary: it.summary || "",
          ...(it.kind ? { kind: it.kind } : {}), ...(it.lang || name !== "gdelt" ? { lang: it.lang || "en" } : {}), ...(it.region ? { region: it.region } : {}), ...(it.country ? { country: it.country } : {}),
          ...(it.status_id ? { status_id: it.status_id, priority: it.priority, ...(it.category ? { category: it.category } : {}) } : {}) });   // every lead names its language (database rows and claims are in English)
      }
      health[name] = nextHealth(prev, { ok: true, items: items.length, extra: { new: n, ...(name === "bing-news" ? { aggregator_copies_dropped: aggregatorCopies } : {}) } }, Date.parse(now));
    } catch (e) {
      health[name] = nextHealth(prev, { ok: false, error: txt((e.cause && e.cause.code) || e.message, 90), retryAfterMs: e.retryAfterMs, extra: { new: 0 } }, Date.parse(now));
    }
  }));
  if (out.length) appendFileSync(join(leadsDir, `${now.slice(0, 10)}.jsonl`), out.map((x) => JSON.stringify(x)).join("\n") + "\n");
  const old = readJson(join(DATA, "osint.json"), {});
  writeJson(join(DATA, "osint.json"), { ...old, checked_at: now, sources: health });
  const sp = join(DATA, "status.json"), st = readStatus(); st.last_osint_at = now; st.last_osint_new = out.length; writeJson(sp, st);
  console.log(`osint: ${out.length} new lead(s). ` + Object.entries(health).map(([k, v]) => `${k} ${v.ok ? v.new + "/" + v.items : "FAILED (" + v.error + ")"}`).join("; "));
}

/* ---------- exploit watch: public repositories that name an exploited CVE ---------- */
export function parseRepoSearch(d, cve) {
  const items = (d && Array.isArray(d.items) ? d.items : []).filter((r) => r && !r.fork && https(r.html_url) && new RegExp(cve.replace(/-/g, "[-_ ]?"), "i").test(`${r.name} ${r.description || ""}`));
  return { repos: items.length, top: items.sort((a, b) => (b.stargazers_count || 0) - (a.stargazers_count || 0)).slice(0, 3).map((r) => ({ name: txt(r.full_name, 100), url: r.html_url, stars: r.stargazers_count || 0, created: String(r.created_at || "").slice(0, 10) })) };
}
async function exploits() {
  const p = join(DATA, "exploits.json"), db = readJson(p, { cves: {} }); db.cves ||= {};
  const cves = new Set();
  for (const f of existsSync(join(DATA, "kev")) ? readdirSync(join(DATA, "kev")) : []) { const k = readJson(join(DATA, "kev", f), {}); if ((k.added || "") >= dayAgo(45)) cves.add(k.cve); }
  for (const x of listEventFiles()) if (x.e && !x.e.duplicate_of && x.e.category === "vuln" && x.e.severity >= 3 && x.e.date >= dayAgo(14)) (x.e.cves || []).forEach((c) => /^CVE-\d{4}-\d{4,}$/.test(c) && cves.add(c));
  // oldest check first; 12 per run keeps well inside GitHub's unauthenticated search limit (10 a minute)
  const todo = [...cves].filter(Boolean).sort((a, b) => ((db.cves[a] || {}).checked_at || "").localeCompare((db.cves[b] || {}).checked_at || "")).slice(0, Number(process.env.EXPLOIT_MAX || 12));
  let done = 0, failed = "";
  for (const cve of todo) {
    try { db.cves[cve] = { ...parseRepoSearch(await get(`https://api.github.com/search/repositories?q=${encodeURIComponent(cve)}&per_page=20`), cve), checked_at: nowIso() }; done++; }
    catch (e) { failed = e.message; break; }
    await sleep(7000);
  }
  db.checked_at = nowIso(); writeJson(p, db);
  const sp = join(DATA, "status.json"), st = readStatus(); st.last_exploits_at = nowIso(); writeJson(sp, st);
  console.log(`exploit watch: checked ${done} of ${cves.size} CVEs; ${Object.values(db.cves).filter((v) => v.repos > 0).length} have public repositories naming them` + (failed ? `; stopped: ${failed}` : ""));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const cmd = process.argv[2] || "leads";
  if (cmd === "exploits") await exploits(); else {
    await leads();
    // official breach notification registers (scripts/breaches.mjs; each asked at most hourly): a failure there never fails this run
    if (cmd === "leads" && process.argv.length <= 3) try { await (await import("./breaches.mjs")).collect(); } catch (e) { console.log(`breaches: skipped (${String(e && e.message).slice(0, 120)})`); }
  }
}
