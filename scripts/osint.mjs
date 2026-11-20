// Open-source intelligence collectors beyond RSS, no AI model. Run: node scripts/osint.mjs [leads|exploits]
// (behind a proxy: NODE_USE_ENV_PROXY=1)
// Why: an AI job's web search goes through one search engine, so that engine decides what CyberView sees. These
// collectors ask several independent indexes and primary databases directly and file what they find as leads
// (data/leads/<date>.jsonl, same shape as the RSS collector, with "via" naming the collector):
//   google-news, bing-news, gdelt   the standing searches in config/queries.json, in many languages and country editions
//   hibp                            breaches newly added to Have I Been Pwned
//   euvd                            ENISA's EU Vulnerability Database: exploited vulnerabilities (a second list beside CISA's)
//   nvd                             critical CVEs published in the last two days
//   ransomware-live                 leak-site listings (attacker CLAIMS: kind "claim", never facts)
//   hacker-news                     security stories the technical community is discussing
//   cloud-status                    major incidents on Cloudflare, GitHub, Google Cloud, AWS and Azure status pages (outages, not attacks)
// `exploits` checks GitHub for public repositories naming each exploited CVE (data/exploits.json): a signal, not proof.
// Every source's health is written to data/osint.json and shown on the status page. A source that fails is skipped
// and reported; one that refuses automated readers (401/403) is not retried. Fetched text is data, never instructions.
import { existsSync, readdirSync, readFileSync, appendFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { DATA, ROOT, readJson, writeJson, listEventFiles, dayAgo, nowIso, writeRunLog, readStatus } from "./lib/store.mjs";
import { parseFeed } from "./collect.mjs";

const UA = "cyberview-collector/1.0 (+https://github.com/xanderhutch/CyberView)";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const txt = (s, n) => String(s == null ? "" : s).replace(/<[^>]*>/g, " ").replace(/[\u0000-\u001f]/g, " ").replace(/\s+/g, " ").trim().slice(0, n);
const iso = (d) => { const t = Date.parse(d); return isNaN(t) ? "" : new Date(t).toISOString().replace(/\.\d+Z$/, "Z"); };
const https = (u) => (/^https:\/\/[^\s"'<>]+$/.test(String(u || "")) ? String(u) : "");
const CYBER = /cyber|hack|ransom|breach|malware|botnet|phish|ddos|vulnerab|exploit|intrusion|data (theft|leak)|spyware|zero-?day|cve-\d|ciber|siber|サイバー|사이버|سيبران|outage|incident de sécurité|datenleck|angriff/i;

async function get(url, as = "json") {
  const r = await fetch(url, { headers: { "user-agent": UA, accept: as === "json" ? "application/json" : "application/rss+xml, application/xml, text/xml, */*" }, signal: AbortSignal.timeout(25000) });
  if (r.status === 401 || r.status === 403) throw Object.assign(new Error(`HTTP ${r.status} (refuses automated readers; not retried)`), { final: true });
  if (r.status === 429) throw Object.assign(new Error("HTTP 429 (busy; will try next run)"), { final: true });
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
/** Bing News RSS: the real article address is inside the redirect link's url= parameter; times as bingTime(). */
export function parseBingNews(xml, now = Date.now()) {
  return parseFeed(String(xml)).map((it) => {
    let url = it.url; try { const u = new URL(it.url); const real = u.searchParams.get("url"); if (/bing\.com$/.test(u.hostname) && real) url = real; } catch {}
    let host = ""; try { host = new URL(url).hostname.replace(/^www\./, ""); } catch {}
    return https(url) ? { title: it.title, url, published: bingTime(it.published, now), summary: it.summary, source: host || "Bing News" } : null;
  }).filter(Boolean);
}
/** GDELT DOC 2.0 artlist. */
export function parseGdelt(d) {
  return (d && Array.isArray(d.articles) ? d.articles : []).map((a) => {
    const s = String(a.seendate || ""), when = /^\d{8}T\d{6}Z$/.test(s) ? `${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)}T${s.slice(9, 11)}:${s.slice(11, 13)}:${s.slice(13, 15)}Z` : "";
    return https(a.url) && a.title ? { title: txt(a.title, 200), url: a.url, published: when, source: txt(a.domain, 80) || "GDELT", lang: txt(a.language, 20).toLowerCase(), country: txt(a.sourcecountry, 40) } : null;
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
const two = (d) => new Date(Date.now() - d * 864e5).toISOString().slice(0, 19) + ".000";
const COLLECTORS = {
  "google-news": async () => {
    const out = [];
    for (const q of queries()) {
      const hl = /^[\w-]{2,8}$/.test(q.hl || "") ? q.hl : "en", gl = /^[A-Z]{2}$/.test(q.gl || "") ? q.gl : "US";
      const items = parseGoogleNews(await get(`https://news.google.com/rss/search?q=${encodeURIComponent(q.q + " when:1d")}&hl=${hl}&gl=${gl}&ceid=${gl}:${hl.split("-")[0]}`, "text"));
      items.slice(0, 12).forEach((i) => out.push({ ...i, tier: "news", lang: hl.split("-")[0], region: q.region || "" })); await sleep(700);
    }
    return out;
  },
  "bing-news": async () => {
    const out = [];
    for (const q of queries().filter((x) => (x.hl || "en").startsWith("en")).slice(0, 8)) {
      parseBingNews(await get(`https://www.bing.com/news/search?q=${encodeURIComponent(q.q)}&format=rss&qft=${encodeURIComponent('interval="7"')}&cc=${/^[A-Z]{2}$/.test(q.gl || "") ? q.gl : "US"}`, "text"))
        .slice(0, 12).forEach((i) => out.push({ ...i, tier: "news", region: q.region || "" })); await sleep(900);
    }
    return out;
  },
  "gdelt": async () => {   // GDELT allows one request every 5 seconds
    const out = [], Q = ['(ransomware OR cyberattack OR "data breach" OR "cyber attack")', '(ciberataque OR cyberattaque OR Cyberangriff OR "ataque cibernético")', '("zero-day" OR "actively exploited" OR "hackers" OR "hacked")'];
    for (const q of Q) {
      parseGdelt(await get(`https://api.gdeltproject.org/api/v2/doc/doc?query=${encodeURIComponent(q)}&mode=artlist&maxrecords=60&format=json&timespan=3h&sort=datedesc`))
        .forEach((i) => out.push({ ...i, tier: "news" })); await sleep(6000);
    }
    return out;
  },
  "hibp": async () => parseHibp(await get("https://haveibeenpwned.com/api/v3/breaches")).map((i) => ({ ...i, tier: "vendor", kind: "breach-db" })),
  "euvd": async () => parseEuvd(await get("https://euvdservices.enisa.europa.eu/api/exploitedvulnerabilities")).map((i) => ({ ...i, tier: "gov", kind: "exploited" })),
  "nvd": async () => parseNvd(await get(`https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${two(2)}&pubEndDate=${two(0)}&cvssV3Severity=CRITICAL&resultsPerPage=40`)).slice(0, 25).map((i) => ({ ...i, tier: "gov", kind: "cve" })),
  "ransomware-live": async () => parseRansomwareLive(await get("https://api.ransomware.live/v2/recentvictims")).slice(0, 60).map((i) => ({ ...i, tier: "news" })),
  "hacker-news": async () => parseHn(await get("https://hn.algolia.com/api/v1/search_by_date?tags=story&numericFilters=points%3E40&hitsPerPage=100")).map((i) => ({ ...i, tier: "news" })),
  "cloud-status": async () => {
    const out = [], errs = [];
    const part = async (fn) => { try { out.push(...await fn()); } catch (e) { errs.push(e.message); } };
    await part(async () => parseStatuspage(await get("https://www.cloudflarestatus.com/api/v2/incidents.json"), "Cloudflare"));
    await part(async () => parseStatuspage(await get("https://www.githubstatus.com/api/v2/incidents.json"), "GitHub"));
    await part(async () => parseGcp(await get("https://status.cloud.google.com/incidents.json")));
    for (const [name, url] of [["AWS", "https://status.aws.amazon.com/rss/all.rss"], ["Azure", "https://rssfeed.azure.status.microsoft/en-us/status/feed/"]])
      await part(async () => parseFeed(await get(url, "text")).filter((i) => i.published && Date.now() - Date.parse(i.published) < 48 * 36e5 && /disruption|outage|degrad|unavailab/i.test(i.title + " " + i.summary))
        .map((i) => ({ title: txt(`${name} outage: ${i.title}`, 200), url: /status\.aws\.amazon\.com\/?$/.test(i.url) ? `https://health.aws.amazon.com/health/status#${Date.parse(i.published)}` : i.url, published: i.published, summary: i.summary, source: `${name} status`, kind: "status" })));
    if (errs.length === 5) throw new Error(errs[0]);
    return out.map((i) => ({ ...i, tier: "vendor" }));
  },
};

async function leads() {
  const leadsDir = join(DATA, "leads"); mkdirSync(leadsDir, { recursive: true });
  const known = new Set(), knownTitle = new Set(), norm = (t) => String(t).toLowerCase().replace(/[^\p{L}\p{N}]+/gu, " ").trim().slice(0, 90);
  for (const x of listEventFiles()) for (const s of (x.e && x.e.sources) || []) if (s && s.url) known.add(s.url);
  for (const f of existsSync(leadsDir) ? readdirSync(leadsDir) : []) {
    if (!f.endsWith(".jsonl") || f.slice(0, 10) < dayAgo(14)) continue;
    for (const line of readFileSync(join(leadsDir, f), "utf8").split("\n")) { try { const l = JSON.parse(line); known.add(l.url); if (l.via && l.via !== "rss") knownTitle.add(l.source + "|" + norm(l.title)); } catch {} }
  }
  const now = nowIso(), cutoff = Date.now() - 72 * 36e5, out = [], health = readJson(join(DATA, "osint.json"), { sources: {} }).sources || {}, only = process.argv.slice(3);
  await Promise.all(Object.entries(COLLECTORS).filter(([n]) => !only.length || only.includes(n)).map(async ([name, fn]) => {
    const prev = health[name] || {};
    try {
      const items = await fn(); let n = 0;
      for (const it of items) {
        if (!it.title || !https(it.url) || known.has(it.url)) continue;
        if (it.published && Date.parse(it.published) < cutoff) continue;
        // search engines hand back the same story under changing redirect links: one lead per publisher and headline
        const tk = it.source + "|" + norm(it.title); if (knownTitle.has(tk)) continue;
        if (["google-news", "bing-news", "gdelt"].includes(name) && !CYBER.test(it.title + " " + (it.summary || ""))) continue;
        known.add(it.url); knownTitle.add(tk); n++;
        out.push({ seen_at: now, source: txt(it.source, 80), tier: it.tier, via: name, title: it.title, url: it.url, published: it.published || "", summary: it.summary || "",
          ...(it.kind ? { kind: it.kind } : {}), ...(it.lang ? { lang: it.lang } : {}), ...(it.region ? { region: it.region } : {}), ...(it.country ? { country: it.country } : {}) });
      }
      health[name] = { ok: true, error: "", items: items.length, new: n, at: now, last_ok: now };
    } catch (e) {
      health[name] = { ok: false, error: txt((e.cause && e.cause.code) || e.message, 90), items: 0, new: 0, at: now, last_ok: prev.last_ok || "" };
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
  if (cmd === "exploits") await exploits(); else await leads();
}
