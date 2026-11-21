// The claims desk: which ransomware and extortion leak-site claims a claims checker should verify, who checks them, and what
// they found. No AI model in this script. A leak-site claim (a lead of kind "claim", today from ransomware.live, written by
// scripts/osint.mjs) is an attacker's claim, never a fact: it reached CyberView only as a lead, and fuse.mjs keeps a story
// made of claims alone out of the research queue ("leak-site claims are tracked separately"), so nobody read them.
// This plans them for claims checkers (role "claims", the "Claims checker" brief in docs/jobs.md), most notable victim first,
// validates what the checkers write, and keeps the result in data/claims/checks.json (written only here). A check says:
//   confirmed_by_victim  the organisation's own statement, a regulator filing or a government notice confirms an incident; the
//                        checker wrote or updated the event (status confirmed, the group's claim named, the confirmation cited)
//   reported             two credible publishers report it, the organisation has not confirmed: an event with status claimed,
//                        severity 1 (hidden by default), never confirmed
//   denied               the organisation denies it (a claimed event on file says so, or no event)
//   unconfirmed          nothing beyond the leak site: checked again after recheck_hours, up to max_tries
//   not_found            the victim cannot be identified (or is a private person, who is never researched)
// Leak sites, claim trackers and .onion addresses are never a source and never linked: only the group's name and the claim's
// date are recorded. Stolen data, samples and their contents never appear in any text.
//   plan [--max N] [--per K] [--file F] [--dry-run]   batches for N checkers, K claims each; leases kind "claim"
//   apply <out file> [--plan F]                       validate a checker's out file and record it (idempotent)
//   list [--json]                                     what is waiting and what was checked
//   status [--json]                                   waiting, checked in 24 h, oldest waiting (the build and the status page)
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, mkdirSync } from "node:fs";
import { join, isAbsolute, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { ROOT, DATA, readJson, writeJson, nowIso, dayAgo, readStatus, listEventFiles } from "./lib/store.mjs";
import { claim, readLeases, RUN_ID } from "./lib/lease.mjs";
import { badSource, regDomain, OFFICIAL_HOST } from "./grid-desk.mjs";
import { norm, hasName } from "./triage.mjs";

export const BY = "CyberView AI (a Claude model)";
export const DECISIONS = ["confirmed_by_victim", "reported", "denied", "unconfirmed", "not_found"];
export const FINAL = new Set(["confirmed_by_victim", "reported", "denied", "not_found"]);
export const DEPTHS = ["full", "summary", "secondary"];
export const DEFAULTS = { window_days: 10, new_hours: 168, recheck_hours: 24, max_tries: 3, match_days: 45 };
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?Z$/;
const ID = /^cl-[0-9a-f]{12}$/;
const EVENT_ID = /^[a-z0-9][a-z0-9-]{2,150}$/;
const PLAN_FILE = /^claims-plan(-[A-Za-z0-9-]+)?\.json$/;
const CLAIM_TITLE = /^Claim: (.+?) lists (.+?)(?: \(([A-Z]{2})\))? on its leak site$/;

// never a source: leak sites and their mirrors, claim trackers that repeat them, criminal forums and social media
export const LEAK_HOST = /(^|\.)(onion|ransomware\.live|ransomlook\.io|ransomwatch\.telemetry\.ltd|ransomfeed\.it|ransom-db\.com|ransomdb\.io|dexpose\.io|hackmanac\.com|falconfeeds\.io|darkfeed\.io|deepwebkonek\.com|redpacketsecurity\.com|hookphish\.com|breachforums\.[a-z]+|leakbase\.[a-z]+|xss\.is|exploit\.in|doxbin\.[a-z]+|x\.com|twitter\.com|t\.me|telegram\.(me|org)|mastodon\.social|bsky\.app|linkedin\.com|facebook\.com|reddit\.com)$/;
// regulators, data-protection authorities and exchange filings that are not on a government domain
export const REGULATOR_HOST = /(^|\.)(ico\.org\.uk|cnil\.fr|garanteprivacy\.it|aepd\.es|autoriteitpersoonsgegevens\.nl|dataprotection\.ie|datatilsynet\.(no|dk)|imy\.se|edpb\.europa\.eu|edps\.europa\.eu|enisa\.europa\.eu|ppc\.go\.jp|pipc\.go\.kr|asx\.com\.au|londonstockexchange\.com|sedarplus\.ca|hkexnews\.hk|sgx\.com|jpx\.co\.jp|nasdaq\.com|cert\.[a-z]{2}|ncsc\.(nl|ch|gov\.uk))$/;
export const officialHost = (h) => !!h && (OFFICIAL_HOST.test(h) || REGULATOR_HOST.test(h) || /\.mil$|\.europa\.eu$/.test(h));

// what a claim's victim and sector tell us about how much it matters (ransomware.live sector names)
const SECTOR_W = [[/health|\bhospitals?\b|medical|pharma/i, 8], [/government|defen[cs]e|public sector|military/i, 8], [/energy|utilit|water|oil|gas/i, 8],
  [/transport|logistic|aviation|airline|maritime/i, 6], [/telecom/i, 6], [/financ|bank|insurance/i, 5], [/education|universit|school/i, 5],
  [/technology|manufactur|chemical|food|agricultur/i, 2]];
const NAME_W = [[/\b(hospitals?|health|clinics?|medical|healthcare|pharma)\b/i, 7], [/\b(city of|county|municipal|ministry|government|council|police|sheriff|court|department of|state of|gouvernement|regierung|ayuntamiento|prefeitura|comune)\b/i, 8],
  [/\b(water|energy|power|electric|utilit|gas|airport|port of|railway|transit)/i, 8], [/\b(bank|insurance|credit union)\b/i, 4], [/\b(university|school district|college)\b/i, 4]];
const BIG = /\b(inc|corp|corporation|plc|ag|se|s\.a\.|n\.v\.|holdings|group|ltd|limited)\b\.?/i;
const SUFFIX = /\b(co|corp|corporation|inc|incorporated|ltd|limited|llc|pllc|plc|gmbh|ag|sa|spa|nv|bv|ab|asa|oy|kk|pty|group|holdings|the)\b/g;
// ransomware.live masks private individuals ("J... W..."): never researched
const MASKED = /\.\.\.|\*{2,}|…/;
// stolen data or samples in a checker's text: refused, whoever published them
export const DATA_CONTENT = [
  [/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i, "an e-mail address"],
  [/(\+\d{1,3}[ .-]?)\(?\d{2,4}\)?[ .-]\d{3,4}[ .-]\d{3,4}|\(\d{3}\) ?\d{3}-\d{4}/, "a phone number"],
  [/\b\d{3}-\d{2}-\d{4}\b/, "an identity number"],
  [/\b\d{4}([ -])\d{4}\1\d{4}\1\d{1,7}\b|\b\d{15,19}\b/, "a card or account number"],
  [/\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/, "an account number (IBAN)"],
  [/\b[\w-]+\.(xlsx?|csv|docx?|sql|bak|zip|rar|7z|pst|mdb|db|tar|gz)\b/i, "a file name from the stolen data"],
  [/\b(password|passwd|pwd)s?\s*[:=]/i, "a password"],
  [/\b(samples?|proof[- ]?(pack|of[- ]hack)|screenshots?|file[- ]?trees?|file listings?|data dumps?)\b/i, "the stolen data's samples or contents"],
  [/\.onion\b/i, "a .onion address"],
  [/https?:\/\//i, "a link (sources go in sources)"],
];

export const cfgOf = (c) => ({ ...DEFAULTS, ...(c || {}) });
const s = (v, n) => String(v ?? "").replace(/[\u0000-\u001f]/g, " ").slice(0, n);
const hostOf = (u) => { try { return new URL(u).hostname.toLowerCase(); } catch { return ""; } };
const live = (l, now) => l && Date.parse(l.until) > now;
const isoAt = (ms) => new Date(ms).toISOString().replace(/\.\d+Z$/, "Z");
const hex = (x) => createHash("sha1").update(x).digest("hex").slice(0, 12);

/** Pure: "Claim: <group> lists <victim> (<CC>) on its leak site" -> { group, victim, country } or null. */
export function parseClaim(lead) {
  const m = CLAIM_TITLE.exec(String((lead && lead.title) || "").trim()); if (!m) return null;
  return { group: m[1].trim(), victim: m[2].trim(), country: m[3] || s(lead.country, 2) };
}
/** Pure: the name a victim is known by, for matching: suffixes and a domain's TLD dropped ("AutoZone, Inc." -> "autozone"). */
export function coreName(victim) {
  const v = String(victim || "").replace(/\s*\([^)]*\)/g, " ").trim();   // "FAIR Health, Inc. (fairhealth.com)" -> "FAIR Health, Inc."
  if (/^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(v)) return norm(regDomain(v.toLowerCase()).split(".")[0]);
  return norm(v).replace(SUFFIX, " ").replace(/\s+/g, " ").trim();
}
export const claimKey = (group, victim) => `cl-${hex(`${norm(group)}|${coreName(victim) || norm(victim)}`)}`;

/** Pure: the event on file this claim is already matched to (same victim named in an incident from the days around it), or "". */
export function matchedEvent(victim, events, at, cfg = {}) {
  const c = cfgOf(cfg), core = coreName(victim), t = Date.parse(at || "");
  if (!core || core.length < 4) return "";
  for (const e of events || []) {
    if (!e || e.duplicate_of || e.category !== "incident") continue;
    const d = Date.parse(e.date || ""); if (isFinite(t) && isFinite(d) && Math.abs(t - d) > c.match_days * 864e5) continue;
    const text = norm(`${e.org || ""} ${e.title || ""} ${(e.aliases || []).join(" ")}`);
    if (hasName(text, core)) return e.id;
  }
  return "";
}
/** Pure: other reports (not claims) that name this victim in an incident headline: corroboration, and where a checker starts. */
export function reportsOf(victim, leads) {
  const core = coreName(victim); if (!core || core.length < 4 || core.split(" ").every((w) => w.length < 4)) return [];
  const out = [], seen = new Set();
  for (const l of leads || []) {
    if (!l || l.kind === "claim" || !/^https:\/\//.test(l.url || "") || LEAK_HOST.test(hostOf(l.url)) || seen.has(l.url)) continue;
    if (!/ransom|attack|breach|hack|leak|extort|stolen|incident|cyber|outage|disrupt/i.test(l.title || "") || !hasName(norm(l.title), core)) continue;
    seen.add(l.url); out.push({ source: s(l.source, 80), title: s(l.title, 200), url: s(l.url, 400) });
  }
  return out.slice(0, 5);
}
/** Pure: the group's track record: confirmed events on file naming it as the actor, and earlier checks of its claims. */
export function trackRecord(group, events, checks = {}) {
  const g = norm(group); if (!g) return { events: 0, confirmed: 0, checked: 0 };
  const evs = (events || []).filter((e) => e && !e.duplicate_of && (e.status === "confirmed" || e.status === "official") && hasName(norm(e.actor), g)).length;
  const mine = Object.values(checks || {}).filter((v) => v && norm(v.group) === g);
  return { events: evs, confirmed: mine.filter((v) => v.decision === "confirmed_by_victim" || v.decision === "reported").length, checked: mine.length };
}
/** Pure: how notable a claim's victim is, with the reasons. */
export function notability(it) {
  const why = []; let n = 0;
  const sw = SECTOR_W.find(([re]) => re.test(it.sector || "")), nw = NAME_W.find(([re]) => re.test(it.victim || ""));
  const w = Math.max(sw ? sw[1] : 0, nw ? nw[1] : 0); if (w) { n += w; why.push(w >= 8 ? "critical sector, government or health" : w >= 5 ? "an important sector" : "an industrial sector"); }
  if ((it.reports || []).length) { n += Math.min(3, it.reports.length) * 5; why.push(`${it.reports.length} other report(s) name the victim`); }
  const tr = it.track || {}, t = Math.min(4, (tr.events || 0) + (tr.confirmed || 0)); if (t) { n += t; why.push("the group's claims have been confirmed before"); }
  if (BIG.test(it.victim || "")) { n += 1; why.push("a company"); }
  return { score: n, why };
}

/** Pure: claim leads -> one item per group and victim (the first listing), with notability. Left out: masked or unnamed
 *  victims (private people), claims already matched to an event, and first checks of claims older than new_hours. */
export function claimItems(leads, events = [], checks = {}, cfg = {}, now = Date.now()) {
  const c = cfgOf(cfg), byKey = new Map(), others = (leads || []).filter((l) => l && l.kind !== "claim");
  for (const l of leads || []) {
    if (!l || l.kind !== "claim") continue;
    const p = parseClaim(l); if (!p || !p.victim || !p.group || MASKED.test(p.victim) || p.victim.length < 3) continue;
    const at = Date.parse(l.published || l.seen_at || ""); if (!isFinite(at) || now - at > c.window_days * 864e5) continue;
    const id = claimKey(p.group, p.victim), prev = byKey.get(id);
    if (prev && Date.parse(prev.claimed_at) <= at) continue;
    const sector = (/Sector: ([^.]{1,60})\./.exec(l.summary || "") || [])[1] || "";
    byKey.set(id, { id, key: id, kind: "claim", group: s(p.group, 60), victim: s(p.victim, 160), country: s(p.country, 2), sector: /^(not found|unknown)$/i.test(sector) ? "" : s(sector, 60),
      claimed_at: isoAt(at), first_seen: s(l.seen_at || isoAt(at), 20), title: s(`${p.group} claims ${p.victim} on its leak site`, 200) });
  }
  const out = [];
  for (const it of byKey.values()) {
    if (!checks[it.id] && now - Date.parse(it.claimed_at) > c.new_hours * 36e5) continue;
    if (matchedEvent(it.victim, events, it.claimed_at, c)) continue;
    it.reports = reportsOf(it.victim, others); it.track = trackRecord(it.group, events, checks);
    const n = notability(it); it.why = n.why;
    it.rank = n.score * 10 + (now - Date.parse(it.claimed_at) < 864e5 ? 2 : 0) - (Number(checks[it.id] && checks[it.id].tries) || 0) * 3;
    out.push(it);
  }
  return out.sort((a, b) => b.rank - a.rank || b.claimed_at.localeCompare(a.claimed_at) || a.id.localeCompare(b.id));
}

/** Pure: is a claim due for a check? Not when a final result is on file, max_tries is reached, it was checked in the last
 *  recheck_hours, or another run holds its lease. */
export function due(it, checks = {}, leases = {}, now = Date.now(), cfg = {}) {
  const c = cfgOf(cfg), r = checks[it.id];
  if (r && (r.final || FINAL.has(r.decision) || (Number(r.tries) || 0) >= c.max_tries)) return false;
  if (r && now - Date.parse(r.checked_at) < c.recheck_hours * 36e5) return false;
  const l = leases[`claim:${it.id}`]; if (live(l, now) && l.run !== c.run) return false;
  return true;
}
/** Pure: the queue, most notable first. */
export const queue = (items, checks = {}, leases = {}, now = Date.now(), cfg = {}) => (items || []).filter((it) => it && ID.test(it.id) && due(it, checks, leases, now, cfg));

/** Pure: the facts a checker needs about one claim (and what an earlier try found). Never the leak site's or tracker's link. */
export function brief(it, r) {
  const { rank, ...rest } = it;
  return { ...rest, earlier: r ? { decision: r.decision, summary: s(r.summary, 300), sources: (r.sources || []).slice(0, 6), tries: r.tries || 0 } : null };
}
/** Pure: a stable id for a plan: the same claims in the same batches at the same try give the same id. */
export function planId(batches) {
  const map = []; batches.forEach((b, k) => (b.items || b).forEach((x) => map.push([x.id || x, k + 1, (x && x.earlier && Number(x.earlier.tries)) || 0])));
  map.sort((a, b) => a[0].localeCompare(b[0]));
  return "cp-" + createHash("sha256").update(JSON.stringify(map)).digest("hex").slice(0, 16);
}
/** Pure: the queue -> { plan_id, batches: [{ batch, out, items }] } for at most max checkers, per each. */
export function makePlan(q, checks = {}, max = 1, per = 4, tag = "") {
  const take = q.slice(0, max * per), k = Math.min(max, Math.ceil(take.length / per)), lists = Array.from({ length: k }, () => []);
  take.forEach((it, i) => lists[i % k].push(brief(it, checks[it.id])));
  const plan_id = planId(lists), t = String(tag).replace(/[^A-Za-z0-9-]/g, "-").slice(0, 80);
  return { plan_id, batches: lists.map((items, j) => ({ batch: j + 1, out: `claims-out${t ? "-" + t : ""}-${j + 1}.json`, items })) };
}

/** Pure: why a source cannot be cited for a claim, or "". */
export function claimSourceProblem(u) {
  const b = badSource(u); if (b) return b;
  const h = hostOf(u);
  if (/\.onion$/.test(h)) return "a .onion address: never cite or link a leak site";
  if (LEAK_HOST.test(h)) return "a leak site, claim tracker, forum or social-media post: record the group and the claim date only and cite the organisation's, a regulator's, a government's or a publisher's own page";
  return "";
}
const mentions = (e, group) => { const g = norm(group); return !!g && hasName(norm(`${e.actor || ""} ${e.title || ""} ${e.summary || ""} ${e.impact || ""}`), g); };

/** Pure: check a checker's out file against its plan. events: Map of event id -> event (to check event_id).
 *  -> { ok, errors: [file-level problems: nothing is applied], bad: { id: [reasons] }, good: [results] } */
export function validate(plan, out, events = new Map()) {
  const errors = [], bad = {}, good = [];
  if (!plan || !plan.plan_id) return { ok: false, errors: ["no plan"], bad, good };
  if (!out || typeof out !== "object") return { ok: false, errors: ["out file is not a JSON object"], bad, good };
  if (out.plan_id !== plan.plan_id) errors.push(`plan_id ${JSON.stringify(out.plan_id ?? null)} does not match the plan (${plan.plan_id})`);
  const batches = plan.batches || [], mine = out.batch != null ? batches.filter((b) => String(b.batch) === String(out.batch)) : batches;
  if (out.batch != null && !mine.length) errors.push(`batch ${out.batch} is not in the plan`);
  const planned = new Map(); mine.forEach((b) => (b.items || []).forEach((i) => planned.set(i.id, i)));
  if (!Array.isArray(out.results)) errors.push("results is not an array");
  const count = new Map();
  for (const r of Array.isArray(out.results) ? out.results : []) {
    const id = r && r.id; count.set(id, (count.get(id) || 0) + 1);
    if (!planned.has(id)) errors.push(`${JSON.stringify(id ?? null)} was not planned`);
  }
  for (const [id, n] of count) if (n > 1) errors.push(`${id} appears ${n} times`);
  if (errors.length) return { ok: false, errors, bad, good };
  for (const id of planned.keys()) if (!count.has(id)) bad[id] = ["no result for this planned claim"];
  for (const r of out.results) {
    const why = [], it = planned.get(r.id), src = Array.isArray(r.sources) ? r.sources : null;
    if (!DECISIONS.includes(r.decision)) why.push(`decision ${JSON.stringify(r.decision ?? null)} is not one of ${DECISIONS.join(", ")}`);
    if (typeof r.summary !== "string" || !r.summary.trim()) why.push("summary is empty");
    else if (r.summary.length > 300) why.push(`summary is ${r.summary.length} characters (at most 300)`);
    for (const [k, n] of [["victim", 160], ["confirmed_by", 120], ["victim_site", 100]]) if (r[k] != null && (typeof r[k] !== "string" || r[k].length > n)) why.push(`${k} must be text of at most ${n} characters`);
    for (const k of ["summary", "victim", "confirmed_by"]) for (const [re, what] of DATA_CONTENT) if (typeof r[k] === "string" && re.test(r[k])) why.push(`${k} contains ${what}: never repeat stolen data or describe its samples; say only what the organisation, a regulator or a publisher states about the incident`);
    if (!DEPTHS.includes(r.read_depth)) why.push(`read_depth ${JSON.stringify(r.read_depth ?? null)} is not one of ${DEPTHS.join(", ")}`);
    const site = typeof r.victim_site === "string" && r.victim_site.trim() ? r.victim_site.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "") : "";
    if (site && (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(site) || LEAK_HOST.test(site))) why.push("victim_site must be the organisation's own domain, like example.com");
    if (!src) why.push("sources is not an array");
    else {
      if (src.length > 8) why.push("more than 8 sources");
      src.forEach((u) => { const b = claimSourceProblem(u); if (b) why.push(`source ${String(u).slice(0, 120)}: ${b}`); });
      const hosts = src.map(hostOf).filter(Boolean), own = site ? hosts.filter((h) => regDomain(h) === regDomain(site)) : [];
      const official = hosts.some(officialHost), pubs = new Set(hosts.filter((h) => !officialHost(h) && !(site && regDomain(h) === regDomain(site))).map(regDomain));
      const victim = typeof r.victim === "string" && r.victim.trim();
      if (["confirmed_by_victim", "reported", "denied"].includes(r.decision) && !victim) why.push(`${r.decision} needs victim (the organisation as its own pages name it)`);
      if (r.decision === "confirmed_by_victim") {
        if (!(typeof r.confirmed_by === "string" && r.confirmed_by.trim())) why.push("confirmed_by_victim needs confirmed_by (who confirmed it: the organisation, a regulator or a government)");
        if (!own.length && !official) why.push("confirmed_by_victim needs the organisation's own page (victim_site) or a regulator's or government's page among the sources; a news report or a tracker is not a confirmation");
      }
      if (r.decision === "reported") {
        if (pubs.size < 2) why.push("reported needs two independent credible publishers among the sources");
        if (!/not confirmed|has not confirmed|have not confirmed|unconfirmed|did not (confirm|respond)|no confirmation/i.test(r.summary || "")) why.push("a reported claim must say in the summary that the organisation has not confirmed it");
      }
      if (r.decision === "denied") {
        if (!src.length) why.push("denied needs the page that carries the denial");
        if (!/den(y|ies|ied|ial)|not (affected|breached|hacked|compromised|attacked)|no evidence|rejects?|refuted?/i.test(r.summary || "")) why.push("a denial must say in the summary who denies what");
      }
      if (r.decision === "unconfirmed" && (own.length || official) && /confirm/i.test(r.summary || "") && !/not confirm|no confirm|unconfirm/i.test(r.summary || "")) why.push("an official or victim page that confirms it is confirmed_by_victim, not unconfirmed");
    }
    // the event the checker wrote or updated through the event checklist
    const eid = r.event_id != null && r.event_id !== "" ? String(r.event_id) : "";
    if (["unconfirmed", "not_found"].includes(r.decision) && eid) why.push(`${r.decision} never writes an event: leave event_id out`);
    if (["confirmed_by_victim", "reported"].includes(r.decision) && !eid) why.push(`${r.decision} needs event_id: the event written or updated through the event checklist`);
    if (eid && !["unconfirmed", "not_found"].includes(r.decision)) {
      const e = events.get(eid);
      if (!EVENT_ID.test(eid)) why.push("event_id is not an event id");
      else if (!e) why.push(`event ${eid} is not on file`);
      else if (e.duplicate_of) why.push(`event ${eid} is a duplicate of ${e.duplicate_of}: name that one`);
      else {
        if (e.category !== "incident") why.push(`event ${eid} is category ${e.category}, not incident`);
        if (it && !mentions(e, it.group)) why.push(`event ${eid} does not name ${it.group}'s claim (actor or summary)`);
        if (r.decision === "confirmed_by_victim") {
          if (!["confirmed", "official"].includes(e.status)) why.push(`event ${eid} has status ${e.status}: a confirmed claim is status confirmed`);
          const cited = new Set((e.sources || []).map((x) => (x && typeof x === "object" ? x.url : x)));
          if (src && !src.some((u) => cited.has(u) && (officialHost(hostOf(u)) || (site && regDomain(hostOf(u)) === regDomain(site))))) why.push(`event ${eid} does not cite the confirming page (the organisation's, regulator's or government's)`);
        } else {
          if (e.status !== "claimed") why.push(`event ${eid} has status ${e.status}: a claim the organisation has not confirmed is status claimed`);
          if (Number(e.severity) !== 1) why.push(`event ${eid} has severity ${e.severity}: a claimed event is severity 1`);
          if (r.decision === "denied" && !/den(y|ies|ied|ial)|not (affected|breached|hacked|compromised)|no evidence|rejects?|refuted?/i.test(`${e.summary || ""} ${e.impact || ""}`)) why.push(`event ${eid} does not say the organisation denies it`);
        }
        const leak = (e.sources || []).map((x) => (x && typeof x === "object" ? x.url : x)).find((u) => /\.onion\b/i.test(String(u)) || LEAK_HOST.test(hostOf(u)));
        if (leak) why.push(`event ${eid} cites a leak site or claim tracker (${String(leak).slice(0, 80)}): remove it`);
      }
    }
    if (why.length) bad[r.id] = why; else good.push(r);
  }
  return { ok: !Object.keys(bad).length, errors, bad, good };
}

/** Pure: one checks.json entry from a valid result. Idempotent: the same plan_id for the same claim returns null. */
export function entryFor(r, it, prev, plan_id, now = Date.now(), cfg = {}) {
  const c = cfgOf(cfg);
  if (prev && prev.plan_id === plan_id) return null;
  const tries = (Number(prev && prev.tries) || 0) + 1, final = FINAL.has(r.decision) || tries >= c.max_tries;
  const site = s(r.victim_site, 100).trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  const e = { key: it.key || it.id, group: s(it.group, 60), claimed_victim: s(it.victim, 160), victim: s(r.victim, 160).trim() || s(it.victim, 160), country: s(it.country, 2), sector: s(it.sector, 60),
    claimed_at: s(it.claimed_at, 20), decision: r.decision, summary: r.summary.trim().slice(0, 300), confirmed_by: r.decision === "confirmed_by_victim" ? s(r.confirmed_by, 120).trim() : "",
    victim_site: site, sources: [...new Set(r.sources)].slice(0, 8), read_depth: r.read_depth, checked_at: isoAt(now), tries, by: BY, final, plan_id };
  if (r.event_id && !["unconfirmed", "not_found"].includes(r.decision)) e.event_id = String(r.event_id);
  return e;
}
/** Pure: apply valid results. -> { checks, changed: [ids] } */
export function applyResults(checks, plan, good, now = Date.now(), cfg = {}) {
  const next = { ...checks }, changed = [], items = new Map();
  (plan.batches || []).forEach((b) => (b.items || []).forEach((i) => items.set(i.id, i)));
  for (const r of good) {
    const it = items.get(r.id) || { id: r.id, key: r.id };
    const e = entryFor(r, it, checks[r.id], plan.plan_id, now, cfg); if (!e) continue;
    next[r.id] = e; changed.push(r.id);
  }
  return { checks: next, changed };
}

/** Pure: the numbers the status page shows: waiting now, checked in the last 24 h by decision, the oldest wait. */
export function stats(q, checks = {}, now = Date.now()) {
  const day = Object.values(checks).filter((v) => v && now - Date.parse(v.checked_at) < 864e5), n = (d) => day.filter((v) => v.decision === d).length;
  const ages = q.map((it) => (now - Date.parse(it.first_seen || it.claimed_at)) / 6e4).filter((m) => isFinite(m) && m >= 0);
  return { waiting: q.length, checked_24h: day.length, confirmed_24h: n("confirmed_by_victim"), reported_24h: n("reported"), denied_24h: n("denied"), unconfirmed_24h: n("unconfirmed"), not_found_24h: n("not_found"),
    oldest_min: ages.length ? Math.round(Math.max(...ages)) : 0 };
}
/** Pure: what the site shows for a check (scripts/build.mjs attaches it to the event it names): the decision, the group and
 *  the claim's date, who confirmed it, the confirming page (never a leak site), the summary, when, and who wrote it. */
export function siteCheck(e) {
  if (!e || !DECISIONS.includes(e.decision)) return null;
  const srcs = (e.sources || []).filter((u) => u && !claimSourceProblem(u));
  const pick = e.decision === "confirmed_by_victim" ? srcs.find((u) => officialHost(hostOf(u)) || (e.victim_site && regDomain(hostOf(u)) === regDomain(e.victim_site))) : null;
  return { decision: e.decision, summary: s(e.summary, 300), group: s(e.group, 60), claimed_at: s(e.claimed_at, 10), confirmed_by: s(e.confirmed_by, 120), url: s(pick || srcs[0] || "", 400), at: s(e.checked_at, 20), by: BY };
}
/** Pure: event id -> its newest check. */
export function checksByEvent(checks) {
  const out = {};
  for (const v of Object.values(checks || {})) if (v && v.event_id && (!out[v.event_id] || String(v.checked_at) > String(out[v.event_id].checked_at))) out[v.event_id] = v;
  return out;
}

// ---------- files ----------
export const CHECKS = join(DATA, "claims", "checks.json");
export const readCfg = () => cfgOf((readJson(join(ROOT, "config", "pipeline.json"), {}) || {}).claims_desk);
function recentLeads(days) {
  const dir = join(DATA, "leads"), out = [], since = dayAgo(days + 1);
  if (existsSync(dir)) for (const f of readdirSync(dir).filter((f) => f.endsWith(".jsonl") && f.slice(0, 10) >= since)) {
    for (const line of readFileSync(join(dir, f), "utf8").split("\n")) { if (!line) continue; try { out.push(JSON.parse(line)); } catch {} }
  }
  return out;
}
/** Everything the desk needs from disk: the claims (with the other leads for corroboration) and the checks on file. */
export function load(now = Date.now()) {
  const cfg = readCfg(), events = listEventFiles().map((f) => f.e).filter(Boolean), checks = readJson(CHECKS, {}) || {};
  return { cfg, events, checks, items: claimItems(recentLeads(cfg.window_days), events, checks, cfg, now) };
}
function releaseClaims(ids, run) {
  const p = join(DATA, "leases.json"), l = readLeases(), out = {}; let n = 0;
  for (const [k, v] of Object.entries(l)) { if (k.startsWith("claim:") && ids.includes(k.slice(6)) && (!run || (v && v.run === run))) { n++; continue; } out[k] = v; }
  if (n) writeJson(p, out);
}
const findPlan = (plan_id) => {
  if (!existsSync(DATA)) return null;
  for (const f of readdirSync(DATA).filter((f) => PLAN_FILE.test(f))) { const p = readJson(join(DATA, f), null); if (p && p.plan_id === plan_id) return p; }
  return null;
};

function main() {
  const [cmd, ...rest] = process.argv.slice(2), arg = (k, d) => { const i = rest.indexOf("--" + k); return i >= 0 ? rest[i + 1] : d; };
  const now = Date.now();
  if (cmd === "plan") {
    const { cfg, items, checks } = load(now), dry = rest.includes("--dry-run");
    const N = Math.max(1, Math.min(4, Number(arg("max", 1)) || 1)), K = Math.max(1, Math.min(8, Number(arg("per", 4)) || 4));
    const file = PLAN_FILE.test(arg("file", "")) ? arg("file") : "claims-plan.json", run = RUN_ID();
    const q = queue(items, checks, readLeases(), now, { ...cfg, run }), p = makePlan(q, checks, N, K, file.replace(/^claims-plan-?|\.json$/g, ""));
    const ids = p.batches.flatMap((b) => b.items.map((i) => i.id));
    if (dry) {
      console.log(`CLAIMS PLAN (dry run, nothing leased or written): ${ids.length} claim(s) for ${p.batches.length} checker(s); ${q.length} waiting.`);
      q.slice(0, 20).forEach((i) => console.log(`  ${i.id}  [${i.rank}] ${i.group} claims ${i.victim}${i.country ? " (" + i.country + ")" : ""}${i.sector ? " · " + i.sector : ""} · ${i.claimed_at.slice(0, 16)}${i.why.length ? " · " + i.why.join("; ") : ""}`));
      return;
    }
    if (ids.length) claim("claim", ids, run, 45);
    writeJson(join(DATA, file), { plan_id: p.plan_id, planned_at: nowIso(), run, batches: p.batches });
    console.log(`CLAIMS PLAN: ${ids.length} claim(s) for ${p.batches.length} claims checker(s); ${q.length} waiting.`);
    return;
  }
  if (cmd === "apply") {
    const f = rest.find((x) => !x.startsWith("--") && x !== arg("plan")); if (!f) { console.error("usage: claims-desk.mjs apply <out file> [--plan F]"); process.exit(1); }
    const path = [isAbsolute(f) ? f : resolve(f), join(DATA, f)].find((p) => existsSync(p));
    const out = path ? readJson(path, null) : null;
    const pf = arg("plan"), plan = pf && PLAN_FILE.test(pf) ? readJson(join(DATA, pf), null) : out && out.plan_id ? findPlan(out.plan_id) : null;
    const events = new Map(listEventFiles().map((x) => x.e).filter((e) => e && e.id).map((e) => [e.id, e]));
    const v = validate(plan, out, events);
    if (v.errors.length) { console.error(`CLAIMS APPLY REFUSED (${f}): ${v.errors.slice(0, 6).join("; ")}`); process.exit(1); }
    const cfg = readCfg(), checks = readJson(CHECKS, {}) || {}, started = nowIso(), r = applyResults(checks, plan, v.good, now, cfg);
    if (r.changed.length) writeJson(CHECKS, r.checks);
    releaseClaims([...v.good.map((x) => x.id), ...Object.keys(v.bad)], plan.run || process.env.CYBERVIEW_RUN || "");
    if (r.changed.length) {
      const st = readStatus(); st.last_claims_at = started; writeJson(join(DATA, "status.json"), st);
      const dir = join(DATA, "runs", started.slice(0, 10)); mkdirSync(dir, { recursive: true });
      writeJson(join(dir, `${started.slice(11, 13)}${started.slice(14, 16)}-claims-desk-${String(out.batch ?? "x").replace(/[^A-Za-z0-9]/g, "")}.json`), {
        job: "claims-desk", started_at: started, finished_at: nowIso(), model: "none (script)", plan_id: plan.plan_id, batch: out.batch ?? null,
        updated: r.changed, decisions: Object.fromEntries(r.changed.map((id) => [id, r.checks[id].decision])),
        pages_read: r.changed.flatMap((id) => r.checks[id].sources.map((url) => ({ url, title: "", used_in: id }))),
        added: r.changed.map((id) => r.checks[id].event_id).filter(Boolean), skipped: Object.entries(v.bad).map(([id, why]) => ({ title: id, url: "", reason: "rejected by claims-desk validate: " + why.join("; ").slice(0, 300) })),
        open_leads: [], failed_sites: [], notes: `${r.changed.length} recorded, ${Object.keys(v.bad).length} rejected` });
    }
    const badN = Object.keys(v.bad).length;
    console.log(`CLAIMS APPLY: ${r.changed.length} recorded, ${v.good.length - r.changed.length} already on file, ${badN} rejected.`);
    for (const [id, why] of Object.entries(v.bad)) console.log(`  rejected ${id}: ${why.join("; ").slice(0, 300)}`);
    if (badN) process.exitCode = 1;
    return;
  }
  if (cmd === "list" || cmd === "status") {
    const { cfg, items, checks } = load(now), q = queue(items, checks, readLeases(), now, cfg), st = stats(q, checks, now);
    if (rest.includes("--json")) { console.log(JSON.stringify(cmd === "status" ? st : { ...st, waiting_items: q.map((i) => brief(i, checks[i.id])), checks })); return; }
    console.log(`CLAIMS DESK: ${st.waiting} waiting, ${st.checked_24h} checked in 24 h (${st.confirmed_24h} confirmed by the victim, ${st.reported_24h} reported, ${st.denied_24h} denied, ${st.unconfirmed_24h} unconfirmed, ${st.not_found_24h} not found).`);
    if (cmd === "status") return;
    q.slice(0, 30).forEach((i) => console.log(`  ${i.id}  [${i.rank}] ${i.group} claims ${i.victim}${i.country ? " (" + i.country + ")" : ""}${i.sector ? " · " + i.sector : ""}`));
    const done = Object.entries(checks).sort((a, b) => String(b[1].checked_at).localeCompare(String(a[1].checked_at))).slice(0, 15);
    if (done.length) { console.log("Recently checked:"); done.forEach(([id, r]) => console.log(`  ${id}  ${r.decision} ${r.group} / ${r.victim}${r.event_id ? " -> " + r.event_id : ""}: ${String(r.summary).slice(0, 100)}`)); }
    return;
  }
  console.error("usage: claims-desk.mjs plan [--max N] [--per K] [--file F] [--dry-run] | apply <out file> [--plan F] | list [--json] | status [--json]"); process.exit(1);
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
