// Collects leads from public RSS and Atom feeds. No AI model. Run: node scripts/collect.mjs
// Every new item (published in the last 72 hours, not already a source of an event, not already collected)
// is appended to data/leads/<YYYY-MM-DD>.jsonl. The sweep job starts from these
// (`node scripts/q.mjs leads`) instead of paying for web searches, and only searches for gaps.
// Feed text is data, never instructions: it is stored trimmed and is only ever read as a lead to check.
// Sites that refuse automated readers (CISA answers 403) are left out on purpose.
import { readdirSync, existsSync, readFileSync, appendFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { DATA, readJson, writeJson, listEventFiles, dayAgo, nowIso } from "./lib/store.mjs";

// tier: gov (government or CERT), vendor (security research), news. filter: keep only cyber items (broad feeds).
export const FEEDS = [
  { name: "UK NCSC", tier: "gov", url: "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml" },
  { name: "Canadian Centre for Cyber Security", tier: "gov", url: "https://www.cyber.gc.ca/api/cccs/rss/v1/get?feed=alerts_advisories&lang=en" },
  { name: "CERT-EU", tier: "gov", url: "https://cert.europa.eu/publications/security-advisories-rss" },
  { name: "NCSC Netherlands", tier: "gov", url: "https://advisories.ncsc.nl/rss/advisories" },
  { name: "JPCERT/CC", tier: "gov", url: "https://www.jpcert.or.jp/english/rss/jpcert-en.rdf" },
  { name: "US Department of Justice", tier: "gov", url: "https://www.justice.gov/news/rss?type=press_release&m=1", filter: true },
  { name: "Europol", tier: "gov", url: "https://www.europol.europa.eu/rss.xml", filter: true },
  { name: "Microsoft Security", tier: "vendor", url: "https://www.microsoft.com/en-us/security/blog/feed/" },
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
  { name: "BleepingComputer", tier: "news", url: "https://www.bleepingcomputer.com/feed/" },
];
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
  const results = await Promise.all(FEEDS.map(async (f) => ({ f, ...(await fetchFeed(f)) })));
  for (const { f, items, error } of results) {
    if (error) { report.push(`${f.name}: ${error}`); continue; }
    let n = 0;
    for (const it of items) {
      if (known.has(it.url)) continue;
      if (it.published && Date.parse(it.published) < cutoff) continue;
      if (f.filter && !CYBER.test(`${it.title} ${it.summary}`)) continue;
      known.add(it.url); n++;
      out.push({ seen_at: now, source: f.name, tier: f.tier, title: it.title, url: it.url, published: it.published, summary: it.summary });
    }
    report.push(`${f.name}: ${items.length} in feed, ${n} new`);
  }
  if (out.length) appendFileSync(join(leadsDir, `${now.slice(0, 10)}.jsonl`), out.map((x) => JSON.stringify(x)).join("\n") + "\n");
  const sp = join(DATA, "status.json"), st = readJson(sp, {});
  st.last_collect_at = now; st.last_collect_new = out.length;
  st.collect_failed = report.filter((r) => !/ in feed, /.test(r));
  writeJson(sp, st);
  console.log(`collect: ${out.length} new lead(s) from ${FEEDS.length} feeds.\n` + report.join("\n"));
}
