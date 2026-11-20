// Mechanical lead triage, no AI model. Run: node scripts/triage.mjs [--dry-run]
// Clears leads the AI jobs would only throw away, and logs each one with its reason in a run log
// (data/runs/<date>/<HHMM>-triage.json, "skipped"), which is how q.mjs leads already hides handled leads:
//   1. already on file: the title strongly matches an event from the last 30 days (same words, same CVE, or a name only
//      that event is known by, in a headline from the days around it, in any language)
//   2. not an event: webinars, podcasts, sponsored posts, round-ups, how-to guides, job posts
//   3. expired: published more than 6 days ago, too old for the seven-day map
// Conservative on purpose: anything uncertain stays open for the triage desk and the sweep. A lead matched to an event is
// not lost: scripts/updates.mjs uses the same matchEvent() and hands a newer page the event does not cite to an updater.
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { DATA, readJson, listEventFiles, dayAgo, writeRunLog, nowIso } from "./lib/store.mjs";
import { forEachSkipped } from "./lib/store.mjs";

const STOP = new Set("the a an of in on to for and or by with from at as is was are be its it this that new after over into says said us uk how why what".split(" "));
export const tokens = (s) => new Set(String(s || "").toLowerCase().replace(/[^a-z0-9-]+/g, " ").split(" ").filter((w) => w.length > 2 && !STOP.has(w)));
export const NOT_EVENT = /\b(\d+ (steps|ways|tips|things|lessons)|webinar|podcast|episode|sponsored|partner content|week in review|weekly recap|this week in|newsletter|round-?up|how to|tips for|best practices|buyer'?s guide|explained|what is|deal|discount|% off|hiring|job opening|career|interview with|q&a|book review|top \d+|ebook|whitepaper download|register now|save the date)\b/i;

// vendors so large that their name alone says nothing about which story this is
const COMMON_ORG = new Set(["microsoft", "google", "apple", "amazon", "meta", "cisco", "oracle", "adobe", "linux", "windows", "android", "chrome", "nvidia", "intel", "amd", "ibm", "samsung", "huawei", "sap", "vmware", "broadcom", "dell", "lenovo", "salesforce", "openai", "github", "gitlab", "cloudflare", "akamai", "fortinet", "ivanti", "citrix", "juniper", "sophos", "crowdstrike", "okta", "zoom", "atlassian", "wordpress", "mozilla", "firefox", "azure", "aws", "outlook", "exchange", "sharepoint", "falcon", "kernel", "facebook", "instagram", "whatsapp", "tiktok", "youtube", "telegram", "linkedin", "gmail", "iphone", "ipad", "chatgpt", "gemini", "copilot", "government", "ministry", "university", "hospital", "bank", "city", "county", "police", "group", "services", "systems", "technologies", "international", "national"]);

// Names, in any language. A foreign-language retelling shares almost no ASCII words with the event's English title, but it
// keeps the names: the victim, the product, the actor, a domain. norm() folds case and diacritics and keeps the letters of
// every script, so "Équinor", "EQUINOR" and "Equinor'un" all read "equinor".
export const norm = (s) => String(s || "").normalize("NFKD").replace(/\p{M}+/gu, "").toLowerCase().replace(/[^\p{L}\p{N}]+/gu, " ").trim();
const LATIN = /^[a-z0-9 ]+$/;
/** A whole-word phrase in a normalised text; a name written in a script without spaces (Japanese, Chinese, Thai) as a substring. */
export const hasName = (text, name) => !!name && (LATIN.test(name) ? ` ${text} `.includes(` ${name} `) : text.includes(name));
// words that name nothing in particular, even capitalised inside a product or organisation name
const PLAIN = new Set(("about access account accounts agency agent agents alert alliance application applications attack authority bank banking board bureau business " +
  "center centre central client cloud code command commission committee community company congress control corporation council court data database defense defence department " +
  "desktop device devices digital directorate division edge education electric electronics energy engine enterprise express federal federation finance financial firm " +
  "force foundation framework gateway general global health healthcare holdings home hospital industries industry institute insurance intelligence internet it laboratory " +
  "library limited mail management manager media medical ministry mobile municipal network networks news office online open operations pay payments plan " +
  "platform plus police portal power private pro product products public research school security server servers service services software solutions source state " +
  "station store studio suite support system systems team teams technologies technology telecom threat tools trust union united university update utility web " +
  "wireless workspace world").split(" "));
const SUFFIX = /\b(co|corp|corporation|inc|incorporated|ltd|limited|llc|plc|gmbh|ag|sa|spa|nv|bv|ab|asa|oy|kk|pty|group|holdings)\b/g;
const plainWord = (x) => PLAIN.has(x) || STOP.has(x) || COMMON_ORG.has(x) || /^\d+$/.test(x) || x.length < 2;

/** Name phrases an event is known by, each written in its own title: the victim (incidents and outages only: for a report or a
 *  flaw `org` is who published it), its products (not those of a roll-up advisory of three or more), the actor, domains, and
 *  `aliases` (names in other scripts) when a record has them. A multi-word name also gives each word it writes in capitals
 *  ("F5 NGINX Open Source" -> "nginx", "RIKEN Center for Computational Science" -> "riken"), never an ordinary first word
 *  ("Deutsche Bank", "Quantum Systems" stay whole); nameIndex() keeps only coined names among the one-word ones. */
export function eventNames(e) {
  const victim = e.category === "incident" || e.category === "outage", raw = [], title = norm(e.title);
  const split = (s) => String(s || "").replace(/\((claimed|alleged|suspected)\)/gi, "").split(/\s*[(),;]\s*|\s+\/\s+/).map((x) => x.trim()).filter(Boolean);
  if (victim) raw.push(...split(e.org).map((x) => ["org", x]));
  const products = Array.isArray(e.products) ? e.products : [];
  if (products.length <= 2 || !/^(vuln|advisory)$/.test(e.category || "")) for (const p of products.slice(0, 6)) raw.push(["product", String(p)]);
  raw.push(...split(e.actor).map((x) => ["actor", x]));
  for (const d of String(`${e.title} ${e.org || ""}`).match(/\b[a-z0-9-]+(\.[a-z0-9-]+)*\.(com|org|net|io|gov|edu|co|ai|app|dev|info)(\.[a-z]{2})?\b/gi) || []) raw.push(["domain", d]);
  const out = new Map();
  const add = (c, kind, orig) => { if (c && !c.split(" ").every(plainWord) && !out.has(c) && (kind === "alias" || hasName(title, c))) out.set(c, { kind, orig }); };
  for (const [kind, r] of raw) {
    const full = norm(r).replace(SUFFIX, " ").replace(/\s+/g, " ").trim();
    if (!full) continue;
    const words = full.split(" ");
    add(full, kind, r);
    if (kind !== "actor" && words.length > 1) for (const w of words) if (w.length >= 3 && new RegExp(`(^|[^A-Za-z0-9])${w.toUpperCase()}([^A-Za-z0-9]|$)`).test(r)) add(w, kind, r);
  }
  for (const a of Array.isArray(e.aliases) ? e.aliases.slice(0, 10) : []) add(norm(a), "alias", String(a));
  return [...out].map(([name, x]) => ({ name, ...x }));
}
/** A one-word name has to be a coined one: an acronym written in capitals (PHP, IIHF, NGINX) or a word of five letters or more
 *  that the events' own prose never writes in lower case ("Equinor", "Fugaku" yes; "rising", "bridge", "credit" no). */
function coined(name, orig, lower) {
  if (name.includes(" ") || !LATIN.test(name)) return true;
  const caps = name.length >= 3 && new RegExp(`(^|[^A-Za-z0-9])${name.toUpperCase()}([^A-Za-z0-9]|$)`).test(orig);
  return caps ? !lower.has(name) || name.length >= 4 : name.length >= 5 && !lower.has(name);
}
// a name identifies an event only when no other event in the window is known by it, and at most one other event's text mentions it
function nameIndex(evs) {
  let ix = nameIndex.cache.get(evs);
  if (ix && ix.n === evs.length) return ix;
  const texts = evs.map((e) => norm(`${e.title} ${e.org || ""} ${(e.products || []).join(" ")} ${e.actor || ""} ${(e.aliases || []).join(" ")}`));
  const bodies = evs.map((e, i) => `${texts[i]} ${norm(e.summary || "")}`);
  // every word the events' prose writes in lower case is an ordinary word, whatever a product happens to be called
  const lower = new Set();
  for (const e of evs) for (const w of `${e.title} ${e.summary || ""} ${e.plain || ""} ${e.impact || ""} ${e.exec || ""} ${e.action || ""}`.match(/[\p{L}\p{N}]+/gu) || [])
    if (w === w.toLowerCase() && /\p{Ll}/u.test(w)) lower.add(norm(w));
  const names = new Map();
  evs.forEach((e, i) => { for (const { name, orig } of eventNames(e)) if (coined(name, orig, lower)) { if (!names.has(name)) names.set(name, new Set()); names.get(name).add(i); } });
  const unique = new Map();
  for (const [name, own] of names) {
    if (own.size !== 1) continue;
    const i = [...own][0];
    if (texts.some((t, j) => j !== i && hasName(t, name))) continue;                        // another event is about it too
    if (bodies.filter((t, j) => j !== i && hasName(t, name)).length > 1) continue;           // or several others mention it
    unique.set(name, i);
  }
  ix = { n: evs.length, unique };
  nameIndex.cache.set(evs, ix);
  return ix;
}
nameIndex.cache = new WeakMap();
const DAY = 864e5;
/** The lead is from the days around the event: from two days before its date to five days after it was first filed. */
export function nearInTime(e, at) {
  const t = typeof at === "number" ? at : Date.parse(at || "");
  const d = Date.parse(e.date || ""), f = Date.parse(e.first_seen || "");
  if (!isFinite(t) || !isFinite(d)) return false;
  return t >= d - 2 * DAY && t <= Math.max(d, isFinite(f) ? f : d) + 5 * DAY;
}
const CVE_RE = /CVE-\d{4}-\d{4,}/g;
/** The event a headline names by a name only that event is known by, if the headline is from the days around it.
 *  Never for a leak-site claim (a gang's name is on hundreds of victims), and never when the headline names a CVE the event lacks. */
export function matchByName(title, evs, at = Date.now()) {
  const t = String(title || ""), text = norm(t);
  if (!text || /^Claim: /.test(t)) return null;
  const cves = t.toUpperCase().match(CVE_RE) || [];
  const { unique } = nameIndex(evs);
  let best = null;
  for (const [name, i] of unique) {
    if (!hasName(text, name) || !nearInTime(evs[i], at)) continue;
    if (cves.some((c) => !(evs[i].cves || []).includes(c))) continue;
    const len = name.length + (name.includes(" ") ? 4 : 0);
    if (!best || len > best.len) best = { id: evs[i].id, name, len };
  }
  return best ? { id: best.id, score: 1.5, by: `name "${best.name}"` } : null;
}

/** Strong match only: most of the lead's words appear in one event, they share a CVE, or (matchByName) the lead names
 *  something only that event is known by. at: when the lead was published (ISO or ms); defaults to now. */
export function matchEvent(title, evs, at = Date.now()) {
  const q = tokens(title);
  const named = () => matchByName(title, evs, at);
  if (q.size < 3) return named();   // a headline in a script without ASCII words can still carry a name
  let best = null;
  for (const e of evs) {
    const t = e._tok || (e._tok = tokens(`${e.title} ${e.org || ""} ${(e.cves || []).join(" ")} ${e.actor || ""}`));
    let inter = 0; q.forEach((w) => t.has(w) && inter++);
    const cve = [...q].some((w) => /^cve-\d{4}-\d+$/.test(w) && t.has(w));
    const score = inter / Math.min(q.size, t.size || 1);
    // the organisation named in a recent incident or outage, plus a fair share of the same words, is the same story told again
    const org = e._org || (e._org = [...tokens(e.org || "")].filter((w) => w.length >= 4 && !COMMON_ORG.has(w)));
    const sameOrg = org.length > 0 && org.every((w) => q.has(w)) && (e.category === "incident" || e.category === "outage") && score >= 0.4;
    if (cve || score >= 0.75 || sameOrg) { if (!best || score > best.score) best = { id: e.id, score: cve ? 2 : score }; }
  }
  return best || named();
}

/** Reason to clear a lead, or "" to leave it open. */
export function reason(lead, evs, today = new Date().toISOString().slice(0, 10)) {
  const t = String(lead.title || "");
  if (NOT_EVENT.test(t)) return "not an event (webinar, promotion, round-up or guide)";
  const pub = String(lead.published || lead.seen_at || "").slice(0, 10);
  if (/^\d{4}-\d{2}-\d{2}$/.test(pub) && pub < new Date(Date.parse(today) - 6 * 864e5).toISOString().slice(0, 10)) return "expired: published more than 6 days ago";
  const m = matchEvent(t, evs, lead.published || lead.seen_at || Date.parse(today));
  return m ? `already on file as ${m.id}` : "";
}

function openFeedLeads() {
  const used = new Set(), rejected = new Set();
  const evs = listEventFiles().map((f) => f.e).filter((e) => e && !e.duplicate_of);
  evs.forEach((e) => (e.sources || []).forEach((s) => used.add(s.url)));
  forEachSkipped(14, (u) => rejected.add(u));
  const out = [], dir = join(DATA, "leads");
  if (existsSync(dir)) for (const f of readdirSync(dir).filter((f) => f.endsWith(".jsonl") && f.slice(0, 10) >= dayAgo(10)))
    for (const line of readFileSync(join(dir, f), "utf8").split("\n")) {
      try { const l = JSON.parse(line); if (l.url && !used.has(l.url) && !rejected.has(l.url)) out.push(l); } catch {}
    }
  return { leads: [...new Map(out.map((l) => [l.url, l])).values()], evs: evs.filter((e) => e.date >= dayAgo(30)) };
}

async function main() {
  const dry = process.argv.includes("--dry-run");
  const { leads, evs } = openFeedLeads();
  const skipped = [];
  for (const l of leads) { const r = reason(l, evs); if (r) skipped.push({ title: String(l.title).slice(0, 200), url: l.url, reason: r }); }
  const by = (k) => skipped.filter((s) => s.reason.startsWith(k)).length;
  console.log(`triage: ${leads.length} open feed leads; cleared ${skipped.length} (already on file ${by("already")}, not events ${by("not an event")}, expired ${by("expired")}); ${leads.length - skipped.length} left for the desks`);
  if (!dry && skipped.length) writeRunLog("triage", { started_at: nowIso(), finished_at: nowIso(), model: null, skipped, open_left: leads.length - skipped.length });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
