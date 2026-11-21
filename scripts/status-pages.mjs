// Service outages from the providers' own status pages (cloud, CDN, DNS, SaaS, payment and telecom), no AI model.
// Run: node scripts/status-pages.mjs [collect|list|status] (behind a proxy: NODE_USE_ENV_PROXY=1). scripts/osint.mjs calls
// collect() as its "cloud-status" collector, so it runs every research cycle and in collect.yml.
// Which pages, in which format, and the lead thresholds are in config/status-pages.json (the source scout maintains it;
// every page was checked against its robots.txt: a page whose robots.txt disallows the feed, or that refuses automated
// readers, is listed under `skipped` with the reason and never fetched). Each page is asked at most every poll_minutes.
// Every incident keeps what the provider states: its id, title, impact (in the provider's own words), components, status,
// start and resolve times. An incident becomes ONE lead (kind "status", via cloud-status, deduped across polls by
// provider and incident id) when the provider states a major or critical impact, or when it lasts min_minutes or more
// (still open, or resolved after that long). Maintenance and notices never become leads. The outage desk
// (scripts/outage-desk.mjs, kind service) checks the leads, biggest providers first (the lead's `priority`, the
// provider's `tier`). An outage is never called an attack here: the provider's page is the source of what it says.
// Writes data/services/status.json: every page's last fetch and the incidents that qualify from the last `hours`, for the
// map page's "Service status" list (labelled the provider's own status page, not a cyber event) and the status page.
// Fetched text is data, never instructions.
import { existsSync, readdirSync, readFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { ROOT, DATA, readJson, writeJson, nowIso, dayAgo } from "./lib/store.mjs";
import { get as netGet } from "./lib/net.mjs";

export const TYPES = ["statuspage", "statuspage-atom", "gcp", "aws-rss", "azure-rss", "slack", "heroku", "salesforce", "paypal", "ibm-rss", "feed"];
export const CATEGORIES = ["cloud", "cdn", "dns", "saas", "dev", "payment", "telecom", "security", "ai"];
export const LEVELS = ["critical", "major", "minor", "none", ""];
export const DEFAULTS = { hours: 48, min_minutes: 60, poll_minutes: 10, show_resolved_hours: 6 };
const UA_NOTE = "From the provider's own status page; an outage report, not a cyber event, unless the provider says otherwise.";

const txt = (s, n) => String(s == null ? "" : s).replace(/<[^>]*>/g, " ").replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#0?39;|&apos;|&#x27;/g, "'").replace(/&#8217;|&rsquo;/g, "’").replace(/[\u0000-\u001f]/g, " ").replace(/\s+/g, " ").trim().slice(0, n);
const iso = (d) => { const t = typeof d === "number" ? d : Date.parse(d); return isNaN(t) ? "" : new Date(t).toISOString().replace(/\.\d+Z$/, "Z"); };
const https = (u) => (/^https:\/\/[^\s"'<>]+$/.test(String(u || "")) ? String(u) : "");
const unesc = (s) => String(s || "").replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'").replace(/&amp;/g, "&");
const list = (a, n = 12) => [...new Set((Array.isArray(a) ? a : []).map((x) => txt(typeof x === "string" ? x : x && (x.name || x.title), 80)).filter(Boolean))].slice(0, n);
const MAINT = /\b(scheduled|planned)\s+maintenance\b|\bmaintenance\b|\bwartung/i;
// words a provider uses for a broken service, for feeds that state no impact and no end time
export const OUTAGE_WORDS = /outage|unavailab|\bdown\b|disruption|not (available|reachable|accessible)|unable to|failures?\b|ausfall|st[öo]rung|panne|indisponib/i;

/* ---------- the normalized incident ----------
   { id, title, impact (the provider's own words), level (critical|major|minor|none|""), components [], status,
     started_at, resolved_at, mitigated_at (when the provider moved it to monitoring), updated_at, url, maintenance } */
const inc = (o) => ({ id: txt(o.id, 120), title: txt(o.title, 200), impact: txt(o.impact, 40), level: LEVELS.includes(o.level) ? o.level : "", components: list(o.components),
  status: txt(o.status, 40).toLowerCase(), started_at: iso(o.started_at), resolved_at: iso(o.resolved_at), mitigated_at: iso(o.mitigated_at), updated_at: iso(o.updated_at), url: https(o.url), maintenance: !!o.maintenance });

/* ---------- parsers, one per format (exported for unit tests; fixtures in tests/unit/fixtures/status-pages/) ---------- */
/** Atlassian Statuspage (and incident.io's compatible) /api/v2/incidents.json: impact none|minor|major|critical|maintenance. */
export function parseStatuspage(d, page = "") {
  return (d && Array.isArray(d.incidents) ? d.incidents : []).filter((i) => i && i.id).map((i) => inc({
    id: i.id, title: i.name, impact: i.impact, level: i.impact === "maintenance" ? "none" : i.impact, components: i.components, status: i.status,
    started_at: i.started_at || i.created_at, resolved_at: i.resolved_at, mitigated_at: i.monitoring_at, updated_at: i.updated_at,
    url: https(i.shortlink) || (https(page) && /^[\w-]{4,40}$/.test(i.id) ? `${page.replace(/\/+$/, "")}/incidents/${i.id}` : ""), maintenance: i.impact === "maintenance" || !!i.scheduled_for }));
}

// time zones Statuspage writes after an update's time ("Nov 19, 18:17 UTC"); an unknown one leaves the time unread
const TZ = { UTC: 0, GMT: 0, BST: 60, IST: 330, CET: 60, CEST: 120, EET: 120, EEST: 180, PST: -480, PDT: -420, MST: -420, MDT: -360, CST: -360, CDT: -300, EST: -300, EDT: -240, JST: 540, KST: 540, SGT: 480, AEST: 600, AEDT: 660, NZST: 720, NZDT: 780 };
const MON = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };
/** One Statuspage update line's time ("Nov 19, 18:17 UTC", the year from the entry's own date) -> ISO or "". */
export function updateTime(mon, day, hm, tz, refIso) {
  const m = MON[String(mon).slice(0, 3).toLowerCase()], off = TZ[String(tz || "").toUpperCase()], ref = Date.parse(refIso);
  const [h, mi] = String(hm).split(":").map(Number);
  if (m == null || off == null || !isFinite(ref) || !(h >= 0 && h < 24 && mi >= 0 && mi < 60)) return "";
  let y = new Date(ref).getUTCFullYear(), t = Date.UTC(y, m, Number(day), h, mi) - off * 6e4;
  if (t > ref + 2 * 864e5) t = Date.UTC(y - 1, m, Number(day), h, mi) - off * 6e4;   // a December update read in January
  return iso(t);
}
/** Statuspage /history.atom (for pages whose robots.txt disallows /api/): each entry is one incident with its updates in
 *  the content, newest first ("<small>Nov 19, 18:17 UTC</small><strong>Resolved</strong> - text"). No impact is stated:
 *  level "". Start = the first update, resolved = the Resolved (or Completed) update. */
export function parseStatuspageAtom(xml) {
  const out = [];
  for (const m of String(xml).matchAll(/<entry>([\s\S]*?)<\/entry>/g)) {
    const b = m[1], tag = (t) => { const x = b.match(new RegExp(`<${t}[^>]*>([\\s\\S]*?)</${t}>`)); return x ? unesc(x[1]) : ""; };
    const idRaw = tag("id"), link = (b.match(/<link[^>]*href="([^"]+)"/) || [])[1] || "", published = tag("published") || tag("updated");
    const id = (idRaw.match(/Incident\/(\d+)/) || [])[1] || (link.match(/\/incidents\/([\w-]+)/) || [])[1] || "";
    if (!id) continue;
    const html = tag("content"), ups = [];
    for (const u of html.matchAll(/<small>\s*([A-Za-z]{3})\w*\s*<var[^>]*>\s*(\d{1,2})\s*<\/var>,\s*(?:(\d{4})\s*)?<var[^>]*>\s*(\d{1,2}:\d{2})\s*<\/var>\s*([A-Z]{2,5})?\s*<\/small>\s*(?:<br\s*\/?>)?\s*<strong>([^<]{1,40})<\/strong>/g))
      ups.push({ at: updateTime(u[1], u[2], u[4], u[5] || "UTC", u[3] ? `${u[3]}-12-31T00:00:00Z` : published), stage: u[6].trim() });
    const times = ups.map((u) => u.at).filter(Boolean).sort(), stages = ups.map((u) => u.stage.toLowerCase());
    const done = ups.find((u) => /^(resolved|completed|postmortem)$/i.test(u.stage) && u.at), mon = ups.find((u) => /^monitoring$/i.test(u.stage) && u.at);
    const affected = (txt(html, 4000).match(/This incident affected:\s*([^.]{1,400})\./) || [])[1] || "";
    out.push(inc({ id, title: tag("title"), impact: "", level: "", components: affected ? affected.split(/,\s*|\s+and\s+/) : [], status: (ups[0] && ups[0].stage) || "",
      started_at: times[0] || published, resolved_at: done ? done.at : "", mitigated_at: mon ? mon.at : "", updated_at: tag("updated"),
      url: https(link), maintenance: stages.includes("scheduled") || MAINT.test(tag("title")) }));
  }
  return out;
}
/** Google Cloud incidents.json: severity low|medium|high, status_impact SERVICE_INFORMATION|SERVICE_DISRUPTION|SERVICE_OUTAGE. */
export function parseGcp(arr) {
  const LV = { SERVICE_OUTAGE: "critical", SERVICE_DISRUPTION: "minor", SERVICE_INFORMATION: "none" };
  return (Array.isArray(arr) ? arr : []).filter((i) => i && /^[\w-]{5,40}$/.test(i.id || "")).map((i) => inc({
    id: i.id, title: i.external_desc, impact: [i.status_impact, i.severity].filter(Boolean).join(", "),
    level: i.severity === "high" || i.status_impact === "SERVICE_OUTAGE" ? (LV[i.status_impact] === "critical" ? "critical" : "major") : (LV[i.status_impact] || ""),
    components: (i.affected_products || []).map((p) => p && p.title), status: i.end ? "resolved" : ((i.most_recent_update || {}).status || "ongoing"),
    started_at: i.begin, resolved_at: i.end, updated_at: i.modified, url: `https://status.cloud.google.com/incidents/${i.id}` }));
}

/** RSS <item> and Atom <entry> blocks -> { title, link, id, date, body, categories }. */
export function feedEntries(xml) {
  const out = [];
  for (const m of String(xml).matchAll(/<(item|entry)\b[^>]*>([\s\S]*?)<\/\1>/g)) {
    const b = m[2], tag = (t) => { const x = b.match(new RegExp(`<${t}\\b[^>]*>([\\s\\S]*?)</${t}>`)); return x ? unesc(x[1]).trim() : ""; };
    const link = (b.match(/<link[^>]*href="([^"]+)"/) || [])[1] || tag("link");
    out.push({ title: txt(tag("title"), 300), link: unesc(link).trim(), id: tag("guid") || tag("id"), date: tag("pubDate") || tag("published") || tag("updated"),
      updated: tag("updated") || tag("pubDate"), body: tag("description") || tag("content") || tag("summary"),
      categories: [...b.matchAll(/<category\b[^>]*?(?:term="([^"]*)"[^>]*\/?>|>([\s\S]*?)<\/category>)/g)].map((c) => txt(unesc(c[1] || c[2]), 60)).filter(Boolean) });
  }
  return out;
}
/** AWS Health RSS: one item per posted update, "Service disruption: ..." / "Service impact: ..." / "Informational
 *  message: ..." / "Service is operating normally: [RESOLVED] ...". The guid ("#ec2-us-east-1_1789468030") names the
 *  service, the region and the event: the incident id. AWS's own words are the impact. */
export function parseAws(xml) {
  const byId = new Map();
  for (const e of feedEntries(xml)) {
    const g = (e.id.match(/#([\w-]+_\d+)$/) || [])[1]; if (!g) continue;
    const [, word = "", rest = e.title] = e.title.match(/^([^:]{3,40}):\s*(.*)$/) || [];
    const t = e.date ? iso(e.date) : "", resolved = /operating normally|\[RESOLVED\]/i.test(e.title);
    const lv = /disruption|outage/i.test(word) ? "major" : /impact|degradation|performance/i.test(word) ? "minor" : /informational/i.test(word) ? "minor" : "";
    const prev = byId.get(g);
    const cur = prev || { id: g, title: rest.replace(/^\[RESOLVED\]\s*/i, ""), impact: "", level: "", components: [g.replace(/_\d+$/, "")], status: "", started_at: t, resolved_at: "", updated_at: t,
      url: `https://health.aws.amazon.com/health/status#${g}` };
    if (t && (!cur.started_at || t < cur.started_at)) cur.started_at = t;
    if (t && t >= (cur.updated_at || "")) { cur.updated_at = t; cur.status = resolved ? "resolved" : "ongoing"; }
    if (resolved && t) cur.resolved_at = t > (cur.resolved_at || "") ? t : cur.resolved_at;
    if (!resolved && lv && LEVELS.indexOf(lv) < LEVELS.indexOf(cur.level || "")) { cur.level = lv; cur.impact = word; }
    if (!resolved && !cur.impact) { cur.impact = word; cur.level = lv; }
    byId.set(g, cur);
  }
  return [...byId.values()].map(inc);
}
/** Azure status RSS: Azure posts only widespread issues there (its own status page says so), so each item is an incident
 *  of impact "widespread" (level major), open while it is listed. */
export function parseAzure(xml) {
  return feedEntries(xml).filter((e) => e.title).map((e) => inc({ id: e.id || e.link || e.title, title: e.title, impact: "widespread issue (Azure status page)", level: "major",
    components: e.categories, status: "ongoing", started_at: e.date, updated_at: e.updated, url: https(e.link) || "https://azure.status.microsoft/en-us/status", maintenance: MAINT.test(e.title) }));
}
/** Slack status API v2.0.0 history: type incident|outage|notice, status active|resolved, services, date_created/updated. */
export function parseSlack(arr) {
  return (Array.isArray(arr) ? arr : []).filter((i) => i && i.id != null).map((i) => inc({ id: String(i.id), title: i.title, impact: i.type,
    level: i.type === "outage" ? "major" : i.type === "incident" ? "minor" : "none", components: i.services, status: i.status,
    started_at: i.date_created, resolved_at: i.status === "resolved" ? i.date_updated : "", updated_at: i.date_updated, url: https(i.url), maintenance: i.type === "notice" }));
}
/** Heroku status API v4 incidents: systems green|yellow|red per update; the worst colour is the impact. */
export function parseHeroku(arr) {
  const RANK = { red: "major", yellow: "minor", green: "none" };
  return (Array.isArray(arr) ? arr : []).filter((i) => i && i.id != null).map((i) => {
    const ups = Array.isArray(i.updates) ? i.updates : [], cols = [...(i.systems || []), ...ups.flatMap((u) => u.systems || [])].map((s) => s && s.status);
    const worst = cols.includes("red") ? "red" : cols.includes("yellow") ? "yellow" : cols.length ? "green" : "";
    const res = ups.filter((u) => u && u.update_type === "resolved").map((u) => iso(u.created_at)).filter(Boolean).sort()[0] || iso(i.resolved_at);
    return inc({ id: String(i.id), title: i.title, impact: worst, level: RANK[worst] || "", components: [...(i.systems || []).map((s) => s && s.name), ...(i.tags || [])], status: i.state,
      started_at: i.created_at, resolved_at: i.state === "resolved" ? res || iso(i.updated_at) : "", updated_at: i.updated_at, url: https(i.full_url), maintenance: /maintenance/i.test(i.title || "") });
  });
}
/** Salesforce Trust API v1 incidents: IncidentImpacts with severity minor|major and start/end times; services and instances. */
export function parseSalesforce(arr) {
  return (Array.isArray(arr) ? arr : []).filter((i) => i && i.id != null).map((i) => {
    const imp = Array.isArray(i.IncidentImpacts) ? i.IncidentImpacts : [], sev = imp.some((x) => x && x.severity === "major") ? "major" : imp.some((x) => x && x.severity === "minor") ? "minor" : "";
    const starts = imp.map((x) => iso(x && x.startTime)).filter(Boolean).sort(), ends = imp.map((x) => iso(x && x.endTime));
    const inst = Array.isArray(i.instanceKeys) ? i.instanceKeys : [], svc = Array.isArray(i.serviceKeys) ? i.serviceKeys : [];
    return inc({ id: String(i.id), title: `${i.type || "Incident"} on ${svc.join(", ") || "Salesforce services"}${inst.length ? ` (${i.affectsAll ? "all instances" : inst.length + " instance" + (inst.length === 1 ? "" : "s")})` : ""}`,
      impact: [sev, i.type].filter(Boolean).join(", "), level: sev, components: svc, status: i.status,
      started_at: starts[0] || i.createdAt, resolved_at: /resolved|closed/i.test(i.status || "") && ends.every(Boolean) ? ends.sort().pop() : "", updated_at: i.updatedAt,
      url: `https://status.salesforce.com/incidents/${encodeURIComponent(String(i.id))}`, maintenance: /maintenance/i.test(i.type || "") });
  });
}
/** PayPal status API v1 events (production only): severity "Degraded Performance" | "Service Disruption" | "Major Outage". */
export function parsePaypal(d) {
  const LV = { "major outage": "critical", "service disruption": "major", "degraded performance": "minor" };
  return (d && Array.isArray(d.result) ? d.result : []).filter((i) => i && i.id != null && i.environment === "production").map((i) => inc({
    id: String(i.id), title: String(i.summary || "").replace(/^Detected (Resolved|Investigating|Identified|Monitoring|Update)?:?\s*/i, "").replace(/\s*\(PP-[A-Z]+-\d+\)$/, ""),
    impact: i.severity || i.type, level: LV[String(i.severity || "").toLowerCase()] || "", components: i.impactedComponents, status: i.state === "closed" ? "resolved" : i.state,
    started_at: i.startDate || i.pubDate, resolved_at: i.state === "closed" ? i.endDate : "", updated_at: i.pubDate,
    url: `https://www.paypal-status.com/history/eventdetails/${encodeURIComponent(String(i.id))}`, maintenance: /maintenance/i.test(i.type || "") }));
}
/** IBM Cloud notifications RSS: only category "incident" (the rest are release notes and announcements); the STATUS lines
 *  ("- 2026-10-22 15:13 UTC - RESOLVED - ...") give the start and the resolution. */
export function parseIbm(xml) {
  return feedEntries(xml).filter((e) => e.categories.some((c) => /^incident$/i.test(c))).map((e) => {
    const lines = [...e.body.matchAll(/(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}) UTC - ([A-Z ]{3,30}) -/g)].map((x) => ({ at: `${x[1]}T${x[2]}:00Z`, stage: x[3].trim() }));
    const times = lines.map((l) => l.at).sort(), res = lines.filter((l) => l.stage === "RESOLVED").map((l) => l.at).sort().pop() || "";
    const comp = (txt(e.body, 2000).match(/SERVICES\/COMPONENTS AFFECTED:\s*(.*?)\s*IMPACT:/) || [])[1] || "";
    return inc({ id: e.id, title: e.title.replace(/^(RESOLVED|INVESTIGATING|IDENTIFIED|MITIGATING|MONITORING):\s*/i, ""), impact: "", level: "",
      components: comp.split(/\s*-\s+/).filter(Boolean), status: (e.title.match(/^([A-Z]+):/) || [])[1] || (res ? "resolved" : ""), started_at: times[0] || e.date,
      resolved_at: res || (/^RESOLVED:/i.test(e.title) ? iso(e.date) : ""), updated_at: e.date, url: https(e.link), maintenance: /maintenance/i.test(e.title) });
  });
}
/** Any other RSS or Atom status feed (Hetzner, Better Uptime pages ...): no impact stated, a "Start:"/"Ends on:" line when
 *  given. Maintenance and notices (by title or category) are marked, never leads. */
export function parseFeedPage(xml, now = Date.now()) {
  return feedEntries(xml).filter((e) => e.title).map((e) => {
    const plain = txt(e.body, 3000), start = (plain.match(/\bStart(?:ed)?:\s*(\d{4}-\d{2}-\d{2}T[\d:]+(?:Z|[+-]\d{2}:?\d{2}))/i) || [])[1];
    const end = (plain.match(/\b(?:End|Ends on|Ended|Resolved):\s*(\d{4}-\d{2}-\d{2}T[\d:]+(?:Z|[+-]\d{2}:?\d{2}))/i) || [])[1];
    const id = ((e.link.match(/\/(?:incident|incidents)\/([\w-]{4,80})/) || [])[1]) || e.id.replace(/#.*$/, "") || e.link;
    return inc({ id, title: e.title.replace(/^(Resolved|Investigating|Identified|Monitoring):\s*/i, ""), impact: "", level: "", components: e.categories.filter((c) => !/^(general|maintenance|incident)$/i.test(c)),
      status: /^resolved\b/i.test(e.title) || (end && Date.parse(end) <= now) ? "resolved" : "", started_at: start || e.date, resolved_at: end && Date.parse(end) <= now ? end : /^resolved\b/i.test(e.title) ? e.updated : "",
      updated_at: e.updated, url: https(e.link), maintenance: MAINT.test(e.title) || e.categories.some((c) => /maintenance/i.test(c)) || (start && Date.parse(start) > now) });
  });
}
export const PARSERS = { statuspage: (b, p) => parseStatuspage(b, p.page), "statuspage-atom": parseStatuspageAtom, gcp: parseGcp, "aws-rss": parseAws, "azure-rss": parseAzure,
  slack: parseSlack, heroku: parseHeroku, salesforce: parseSalesforce, paypal: parsePaypal, "ibm-rss": parseIbm, feed: (b, p, n) => parseFeedPage(b, n) };
const AS = { statuspage: "json", gcp: "json", slack: "json", heroku: "json", salesforce: "json", paypal: "json" };

/* ---------- which incidents become leads ---------- */
export const cfgOf = (c) => ({ ...DEFAULTS, ...(c || {}) });
/** Pure: minutes an incident has lasted: to its resolution; to the provider's move to monitoring while it is monitoring
 *  (the fix is in, it is watching); to now while open. null when no start is known or a closed incident has no end time. */
export function minutesOf(i, now = Date.now()) {
  const s = Date.parse(i.started_at); if (!isFinite(s)) return null;
  const e = i.resolved_at ? Date.parse(i.resolved_at) : /resolved|completed|closed|postmortem/.test(i.status || "") ? NaN
    : i.status === "monitoring" && i.mitigated_at ? Date.parse(i.mitigated_at) : i.status ? now : NaN;   // no stated state: a notice, length unknown
  return isFinite(e) && e >= s ? Math.round((e - s) / 6e4) : null;
}
/** Pure: does this incident qualify (and why)? A stated major or critical impact; or min_minutes or more; or, for a page
 *  that states neither impact nor times, the provider's own title saying the service is out. Maintenance never. */
export function qualifies(i, cfg = {}, now = Date.now()) {
  const c = cfgOf(cfg);
  if (!i || i.maintenance || i.level === "none") return "";
  const last = Math.max(...[i.updated_at, i.resolved_at, i.started_at].map((t) => Date.parse(t || "")).filter(isFinite)); if (!isFinite(last) || now - last > c.hours * 36e5) return "";
  if (i.level === "major" || i.level === "critical") return `${i.level} impact stated`;
  const m = minutesOf(i, now);
  if (m != null && m >= c.min_minutes) return `lasted ${m} minutes${i.resolved_at ? "" : " so far"}`;
  if (m == null && !i.level && OUTAGE_WORDS.test(i.title)) return "the provider's title reports an outage";
  return "";
}
const fmtMin = (m) => (m >= 120 ? `${Math.round(m / 60)} h` : `${m} min`);
/** Pure: the lead an incident becomes (kind status, priority = the provider's tier: 1 the biggest). */
export function leadOf(p, i, why, now = Date.now()) {
  const m = minutesOf(i, now), name = txt(p.name, 60);
  const parts = [i.impact ? `Impact as the provider states it: ${i.impact}` : "No impact level stated", i.components.length ? `Affected: ${i.components.slice(0, 6).join(", ")}` : "",
    [i.started_at ? `Started ${i.started_at.replace("T", " ").replace("Z", " UTC")}` : "", i.resolved_at ? `resolved ${i.resolved_at.replace("T", " ").replace("Z", " UTC")}${m != null ? ` (${fmtMin(m)})` : ""}` : m != null ? `still open after ${fmtMin(m)}` : ""].filter(Boolean).join(", "),
    `Status: ${i.status || "not stated"}`].filter(Boolean);
  return { title: txt(`${name} status page: ${i.title}`, 200), url: i.url, published: i.started_at || i.updated_at, summary: txt(`${parts.join(". ")}. ${UA_NOTE}`, 300),
    source: `${name} status`, tier: "vendor", kind: "status", status_id: `${p.id}:${i.id}`.slice(0, 160), priority: Math.min(3, Math.max(1, Number(p.tier) || 3)),
    category: CATEGORIES.includes(p.category) ? p.category : "", why: txt(why, 80) };
}
/** Pure: one provider's parsed incidents -> the leads not filed before (seen: Set of status_id). */
export function leadsFor(p, incidents, seen = new Set(), cfg = {}, now = Date.now()) {
  const out = [];
  for (const i of incidents || []) {
    if (!i || !i.id || !i.url) continue;
    const why = qualifies(i, cfg, now); if (!why) continue;
    const l = leadOf(p, i, why, now); if (seen.has(l.status_id)) continue;
    seen.add(l.status_id); out.push(l);
  }
  return out;
}
/** Pure: is a provider due for a fetch (not asked in the last poll_minutes)? */
export const due = (h, cfg = {}, now = Date.now()) => !h || !h.at || now - Date.parse(h.at) >= cfgOf(cfg).poll_minutes * 6e4 - 30e3;
/** Pure: a provider entry is usable: known type, https url, an id. */
export function validProvider(p) {
  return !!(p && /^[a-z0-9-]{2,40}$/.test(p.id || "") && typeof p.name === "string" && p.name.trim() && TYPES.includes(p.type) && https(p.url) && (p.page == null || https(p.page)));
}

/* ---------- files ---------- */
export const STATUS = join(DATA, "services", "status.json");
export const readConfig = () => readJson(join(ROOT, "config", "status-pages.json"), {}) || {};
/** status_id of every status lead filed in the last days (dedupe across polls). */
export function seenOnFile(days = 4) {
  const dir = join(DATA, "leads"), ids = new Set(), since = dayAgo(days);
  if (existsSync(dir)) for (const f of readdirSync(dir).filter((f) => f.endsWith(".jsonl") && f.slice(0, 10) >= since)) {
    for (const line of readFileSync(join(dir, f), "utf8").split("\n")) { if (!line.includes('"status_id"')) continue; try { const l = JSON.parse(line); if (l.status_id) ids.add(l.status_id); } catch {} }
  }
  return ids;
}
/** Pure: the incidents the map page lists: qualifying ones still open, or resolved in the last show_resolved_hours. */
export function shownIncidents(byProvider, providers, cfg = {}, now = Date.now()) {
  const c = cfgOf(cfg), out = [];
  for (const p of providers) for (const i of byProvider[p.id] || []) {
    const why = qualifies(i, c, now); if (!why) continue;
    if (i.resolved_at && now - Date.parse(i.resolved_at) > c.show_resolved_hours * 36e5) continue;
    out.push({ provider: p.id, name: p.name, category: p.category || "", tier: Number(p.tier) || 3, page: p.page || "", ...i, minutes: minutesOf(i, now), why });
  }
  return out.sort((a, b) => (a.resolved_at ? 1 : 0) - (b.resolved_at ? 1 : 0) || a.tier - b.tier || String(b.started_at).localeCompare(String(a.started_at))).slice(0, 60);
}

/** Fetch every due page and return the new leads (osint.mjs files them). Writes data/services/status.json. */
export async function collect({ now = Date.now(), seen = seenOnFile(), only = [] } = {}) {
  const cfg = readConfig(), c = cfgOf(cfg), providers = (cfg.providers || []).filter(validProvider).filter((p) => p.active !== false);
  mkdirSync(join(DATA, "services"), { recursive: true });
  const prev = readJson(STATUS, {}) || {}, health = { ...(prev.providers || {}) }, cache = { ...(prev.cache || {}) }, leads = [], at = nowIso();
  for (const k of Object.keys(health)) if (!providers.some((p) => p.id === k)) { delete health[k]; delete cache[k]; }
  const todo = only.length ? providers.filter((p) => only.includes(p.id)) : providers.filter((p) => due(health[p.id], c, now));
  let i = 0;
  const worker = async () => {
    while (i < todo.length) {
      const p = todo[i++], h = health[p.id] || {};
      try {
        const body = await netGet(p.url, { as: AS[p.type] || "text", retries: 1, delayMs: 1500, timeoutMs: 20000 });
        const incidents = PARSERS[p.type](body, p, now);
        cache[p.id] = incidents.filter((x) => qualifies(x, c, now) || !x.resolved_at).slice(0, 40);
        const mine = leadsFor(p, incidents, seen, c, now); leads.push(...mine);
        health[p.id] = { name: p.name, ok: true, error: "", at, last_ok: at, incidents: incidents.length, qualifying: cache[p.id].filter((x) => qualifies(x, c, now)).length, new: mine.length };
      } catch (e) {
        health[p.id] = { name: p.name, ok: false, error: txt(e.code || e.message, 90), at, last_ok: h.last_ok || "", incidents: 0, qualifying: (cache[p.id] || []).length, new: 0 };
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(6, todo.length) }, worker));
  const incidents = shownIncidents(cache, providers, c, now);
  writeJson(STATUS, { updated_at: at, note: "Providers' own status pages (scripts/status-pages.mjs, no AI model): outage reports, not cyber events.", providers: health, cache, incidents });
  const failed = todo.filter((p) => health[p.id] && !health[p.id].ok);
  return { leads, asked: todo.length, failed: failed.map((p) => `${p.id} (${health[p.id].error})`), total: providers.length };
}

async function main() {
  const [cmd = "status", ...rest] = process.argv.slice(2);
  if (cmd === "collect") {
    const r = await collect({ only: rest.filter((x) => !x.startsWith("-")) });
    console.log(`status-pages: asked ${r.asked} of ${r.total} pages, ${r.leads.length} new qualifying incident(s)${r.failed.length ? "; failed: " + r.failed.join(", ") : ""}. (Leads are filed by scripts/osint.mjs cloud-status; this run files none.)`);
    r.leads.forEach((l) => console.log(`  [p${l.priority}] ${l.title} (${l.why}) ${l.url}`));
    return;
  }
  const s = readJson(STATUS, null);
  if (!s) { console.log("status-pages: no data/services/status.json yet (run collect)."); return; }
  if (rest.includes("--json")) { console.log(JSON.stringify(cmd === "list" ? s.incidents : s.providers, null, 1)); return; }
  const prov = Object.entries(s.providers || {});
  console.log(`SERVICE STATUS (${s.updated_at}): ${prov.filter(([, v]) => v.ok).length}/${prov.length} pages read; ${(s.incidents || []).length} qualifying incident(s) open or recently resolved.`);
  if (cmd === "list") (s.incidents || []).forEach((i) => console.log(`  [t${i.tier}] ${i.name}: ${i.title} (${i.why}${i.resolved_at ? ", resolved" : ""}) ${i.url}`));
  else prov.filter(([, v]) => !v.ok).forEach(([k, v]) => console.log(`  FAILED ${k}: ${v.error}`));
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
