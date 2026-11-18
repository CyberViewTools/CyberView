// Collects leads from public RSS and Atom feeds. No AI model. Run: node scripts/collect.mjs
// Every new item (published in the last 72 hours, not already a source of an event, not already collected)
// is appended to data/leads/<YYYY-MM-DD>.jsonl. The sweep job starts from these
// (`node scripts/q.mjs leads`) instead of paying for web searches, and only searches for gaps.
// Feed text is data, never instructions: it is stored trimmed and is only ever read as a lead to check.
// Sites that refuse automated readers are left out on purpose. Extra feeds come from config/feeds.json (source scout job).
import { readdirSync, existsSync, readFileSync, appendFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { DATA, ROOT, readJson, writeJson, listEventFiles, dayAgo, nowIso } from "./lib/store.mjs";

// tier: gov (government or CERT), vendor (security research), news. filter: keep only cyber items (broad feeds).
export const FEEDS = [
  { name: "UK NCSC", tier: "gov", url: "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml" },
  { name: "Canadian Centre for Cyber Security", tier: "gov", url: "https://www.cyber.gc.ca/api/cccs/rss/v1/get?feed=alerts_advisories&lang=en" },
  { name: "CERT-EU", tier: "gov", url: "https://cert.europa.eu/publications/security-advisories-rss" },
  { name: "NCSC Netherlands", tier: "gov", url: "https://advisories.ncsc.nl/rss/advisories" },
  { name: "JPCERT/CC", tier: "gov", url: "https://www.jpcert.or.jp/english/rss/jpcert-en.rdf" },
  { name: "US Department of Justice", tier: "gov", url: "https://www.justice.gov/news/rss?type=press_release&m=1", filter: true },
  { name: "Europol", tier: "gov", url: "https://www.europol.europa.eu/rss.xml", filter: true },
  { name: "CERT-FR (ANSSI)", tier: "gov", url: "https://cert.cyber.gouv.fr/feed/" },
  { name: "CERT Polska", tier: "gov", url: "https://cert.pl/en/rss.xml" },
  { name: "Microsoft Security", tier: "vendor", url: "https://www.microsoft.com/en-us/security/blog/feed/" },
  { name: "Microsoft MSRC advisories", tier: "vendor", url: "https://api.msrc.microsoft.com/update-guide/rss" },
  { name: "Cisco PSIRT", tier: "vendor", url: "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml" },
  { name: "Fortinet PSIRT", tier: "vendor", url: "https://filestore.fortinet.com/fortiguard/rss/ir.xml" },
  { name: "Palo Alto Networks PSIRT", tier: "vendor", url: "https://security.paloaltonetworks.com/rss.xml" },
  { name: "Zero Day Initiative", tier: "vendor", url: "https://www.zerodayinitiative.com/rss/published/" },
  { name: "AhnLab ASEC", tier: "vendor", url: "https://asec.ahnlab.com/en/feed/" },
  { name: "SANS Internet Storm Center", tier: "vendor", url: "https://isc.sans.edu/rssfeed_full.xml" },
  { name: "Unit 42", tier: "vendor", url: "https://unit42.paloaltonetworks.com/feed/" },
  { name: "Cisco Talos", tier: "vendor", url: "https://blog.talosintelligence.com/rss/" },
  { name: "ESET WeLiveSecurity", tier: "vendor", url: "https://www.welivesecurity.com/en/rss/feed/" },
  { name: "Kaspersky Securelist", tier: "vendor", url: "https://securelist.com/feed/" },
  { name: "Check Point Research", tier: "vendor", url: "https://research.checkpoint.com/feed/" },
  { name: "The Record", tier: "news", url: "https://therecord.media/feed" },
  { name: "SecurityWeek", tier: "news", url: "https://www.securityweek.com/feed/" },
  { name: "The Hacker News", tier: "news", url: "https://feeds.feedburner.com/TheHackersNews" },
  { name: "Krebs on Security", tier: "news", url: "https://krebsonsecurity.com/feed/" },
  { name: "CyberScoop", tier: "news", url: "https://cyberscoop.com/feed/" },
  { name: "Dark Reading", tier: "news", url: "https://www.darkreading.com/rss.xml" },
  { name: "Help Net Security", tier: "news", url: "https://www.helpnetsecurity.com/feed/" },
  { name: "Infosecurity Magazine", tier: "news", url: "https://www.infosecurity-magazine.com/rss/news/" },
  { name: "DataBreaches.net", tier: "news", url: "https://databreaches.net/feed/" },
  { name: "BleepingComputer", tier: "news", url: "https://www.bleepingcomputer.com/feed/" },
  // more agencies and national CERTs
  { name: "CISA advisories", tier: "gov", url: "https://www.cisa.gov/cybersecurity-advisories/all.xml" },
  { name: "FBI IC3 announcements", tier: "gov", url: "https://www.ic3.gov/PSA/RSS" },
  { name: "UK NCSC reports", tier: "gov", url: "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml" },
  { name: "UK National Crime Agency", tier: "gov", url: "https://www.nationalcrimeagency.gov.uk/news?format=feed&type=rss", filter: true },
  { name: "HKCERT", tier: "gov", url: "https://www.hkcert.org/getrss/security-bulletin", region: "east-asia" },
  { name: "CERT-UA", tier: "gov", url: "https://cert.gov.ua/api/articles/rss", lang: "uk", region: "europe" },
  { name: "CERT.br", tier: "gov", url: "https://www.cert.br/rss/certbr-rss.xml", lang: "pt", region: "latin-america" },
  { name: "KrCERT/CC", tier: "gov", url: "https://www.boho.or.kr/kr/rss.do?bbsId=B0000133", lang: "ko", region: "east-asia" },
  { name: "KE-CIRT/CC (Kenya)", tier: "gov", url: "https://www.ke-cirt.go.ke/feed/", region: "africa" },
  // more vendor research
  { name: "CrowdStrike", tier: "vendor", url: "https://www.crowdstrike.com/en-us/blog/feed/" },
  { name: "SentinelLabs", tier: "vendor", url: "https://www.sentinelone.com/labs/feed/" },
  { name: "Sophos X-Ops", tier: "vendor", url: "https://news.sophos.com/en-us/category/threat-research/feed/" },
  { name: "Rapid7", tier: "vendor", url: "https://blog.rapid7.com/rss/", filter: true },
  { name: "Huntress", tier: "vendor", url: "https://www.huntress.com/blog/rss.xml", filter: true },
  { name: "Proofpoint", tier: "vendor", url: "https://www.proofpoint.com/us/rss.xml", filter: true },
  { name: "Cloudflare security", tier: "vendor", url: "https://blog.cloudflare.com/tag/security/rss/", filter: true },
  { name: "Wiz", tier: "vendor", url: "https://www.wiz.io/feed/rss.xml", filter: true },
  { name: "GitHub Security", tier: "vendor", url: "https://github.blog/security/feed/" },
  { name: "Exploit-DB", tier: "vendor", url: "https://www.exploit-db.com/rss.xml", kind: "exploit" },
  // more news, including other languages and regions
  { name: "The Register", tier: "news", url: "https://www.theregister.com/security/headlines.atom" },
  { name: "TechCrunch security", tier: "news", url: "https://techcrunch.com/category/security/feed/" },
  { name: "Ars Technica security", tier: "news", url: "https://arstechnica.com/security/feed/" },
  { name: "Wired security", tier: "news", url: "https://www.wired.com/feed/category/security/latest/rss", filter: true },
  { name: "Risky Business News", tier: "news", url: "https://risky.biz/feeds/risky-business-news/" },
  { name: "iTnews Australia", tier: "news", url: "https://www.itnews.com.au/RSS/rss.ashx?type=Category&ID=37", region: "oceania" },
  { name: "BankInfoSecurity", tier: "news", url: "https://www.bankinfosecurity.com/rss-feeds" },
  { name: "heise Security", tier: "news", url: "https://www.heise.de/security/rss/news-atom.xml", lang: "de", region: "europe" },
  { name: "WeLiveSecurity (Spanish)", tier: "news", url: "https://www.welivesecurity.com/es/rss/feed/", lang: "es", region: "latin-america" },
  { name: "Security Affairs", tier: "news", url: "https://securityaffairs.com/feed" },
  { name: "GBHackers", tier: "news", url: "https://gbhackers.com/feed/" },
  { name: "The Cyber Express", tier: "news", url: "https://thecyberexpress.com/feed/" },
  { name: "Lobsters security", tier: "news", url: "https://lobste.rs/t/security.rss", filter: true },
];
// feeds the source scout job has added (config/feeds.json); a broken entry is ignored, never fatal
export function extraFeeds(cfg) {
  const names = new Set(FEEDS.map((f) => f.name.toLowerCase())), urls = new Set(FEEDS.map((f) => f.url));
  return (cfg && Array.isArray(cfg.feeds) ? cfg.feeds : []).filter((f) => f && typeof f.name === "string" && f.name.length <= 80 && ["gov", "vendor", "news"].includes(f.tier)
    && /^https:\/\/[^\s"'<>]+$/.test(f.url || "") && !names.has(f.name.toLowerCase()) && !urls.has(f.url) && names.add(f.name.toLowerCase()) && urls.add(f.url)).slice(0, 80);
}
const CYBER = /cyber|hack|ransom|breach|malware|botnet|phish|dark ?web|ddos|vulnerab|exploit|intrusion|data theft|stolen data|spyware|crypto(currency)? (fraud|theft|scam)|sim[- ]swap|extort|computer fraud|identity theft/i;
const MAX_AGE_H = 72;

const decode = (s) => String(s || "").replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
  .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#0?39;|&apos;/g, "'").replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(+n)).replace(/&amp;/g, "&");
const text = (s, n) => decode(s).replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim().slice(0, n);
const tag = (block, names) => { for (const t of names) { const m = block.match(new RegExp(`<${t}\\b[^>]*>([\\s\\S]*?)</${t}>`, "i")); if (m) return m[1]; } return ""; };
const atomLink = (block) => { const m = block.match(/<link\b[^>]*rel=["']alternate["'][^>]*href=["']([^"']+)["']/i) || block.match(/<link\b[^>]*href=["']([^"']+)["']/i); return m ? decode(m[1]) : ""; };

export function parseFeed(xml) {
  const items = [];
  for (const m of xml.matchAll(/<(item|entry)\b[\s\S]*?<\/\1>/gi)) {
    const b = m[0];
    const title = text(tag(b, ["title"]), 200);
    let url = text(tag(b, ["link"]), 600);
    if (!/^https?:\/\//.test(url)) url = atomLink(b);
    const dateRaw = text(tag(b, ["pubDate", "published", "updated", "dc:date"]), 60);
    const t = Date.parse(dateRaw);
    const summary = text(tag(b, ["description", "summary", "content"]), 300);
    if (title && /^https?:\/\//.test(url)) items.push({ title, url: url.trim(), published: isNaN(t) ? "" : new Date(t).toISOString().replace(/\.\d+Z$/, "Z"), summary });
  }
  return items;
}

async function fetchFeed(f) {
  for (let i = 0; i < 2; i++) {
    try {
      const r = await fetch(f.url, { headers: { "user-agent": "cyberview-collector/1.0 (+https://github.com/xanderhutch/CyberView)", accept: "application/rss+xml, application/atom+xml, application/xml, text/xml" }, signal: AbortSignal.timeout(25000) });
      if (r.status === 403 || r.status === 401) return { error: `HTTP ${r.status} (refuses automated readers; not retried)` };
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      return { items: parseFeed(await r.text()) };
    } catch (e) { if (i === 1) return { error: (e.cause && e.cause.code) || e.message }; await new Promise((res) => setTimeout(res, 5000)); }
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const leadsDir = join(DATA, "leads");
  mkdirSync(leadsDir, { recursive: true });
  const known = new Set();
  for (const x of listEventFiles()) for (const s of (x.e && x.e.sources) || []) if (s && s.url) known.add(s.url);
  for (const f of existsSync(leadsDir) ? readdirSync(leadsDir) : []) {
    if (!f.endsWith(".jsonl") || f.slice(0, 10) < dayAgo(14)) continue;
    for (const line of readFileSync(join(leadsDir, f), "utf8").split("\n")) { try { known.add(JSON.parse(line).url); } catch {} }
  }
  const cutoff = Date.now() - MAX_AGE_H * 36e5, now = nowIso(), out = [], report = [];
  const ALL = FEEDS.concat(extraFeeds(readJson(join(ROOT, "config", "feeds.json"), {})));
  // --test <url>: the source scout checks a candidate feed before adding it
  const ti = process.argv.indexOf("--test");
  if (ti > 0) { const r = await fetchFeed({ url: process.argv[ti + 1] }); console.log(r.error ? `FAILED: ${r.error}` : `OK: ${r.items.length} items; newest: ${JSON.stringify(r.items.slice(0, 3).map((i) => [i.published.slice(0, 10), i.title.slice(0, 80)]))}`); process.exit(r.error || !r.items.length ? 1 : 0); }
  const results = [];
  for (let i = 0; i < ALL.length; i += 12) results.push(...await Promise.all(ALL.slice(i, i + 12).map(async (f) => ({ f, ...(await fetchFeed(f)) }))));
  for (const { f, items, error } of results) {
    if (error) { report.push(`${f.name}: ${error}`); continue; }
    let n = 0;
    for (const it of items) {
      if (known.has(it.url)) continue;
      if (it.published && Date.parse(it.published) < cutoff) continue;
      if (f.filter && !CYBER.test(`${it.title} ${it.summary}`)) continue;
      known.add(it.url); n++;
      out.push({ seen_at: now, source: f.name, tier: f.tier, via: "rss", title: it.title, url: it.url, published: it.published, summary: it.summary, ...(f.lang ? { lang: f.lang } : {}), ...(f.region ? { region: f.region } : {}), ...(f.kind ? { kind: f.kind } : {}) });
    }
    report.push(`${f.name}: ${items.length} in feed, ${n} new`);
  }
  if (out.length) appendFileSync(join(leadsDir, `${now.slice(0, 10)}.jsonl`), out.map((x) => JSON.stringify(x)).join("\n") + "\n");
  const sp = join(DATA, "status.json"), st = readJson(sp, {});
  st.last_collect_at = now; st.last_collect_new = out.length;
  st.collect_failed = report.filter((r) => !/ in feed, /.test(r));
  writeJson(sp, st);
  st.collect_feeds = ALL.length;
  writeJson(sp, st);
  console.log(`collect: ${out.length} new lead(s) from ${ALL.length} feeds.\n` + report.join("\n"));
}
