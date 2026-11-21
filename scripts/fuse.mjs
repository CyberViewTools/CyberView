// Story fusion, no AI model. Run: node scripts/fuse.mjs [list|show|done]
// Hundreds of leads a day arrive from RSS feeds, several news indexes and primary databases. Many describe the same thing.
// This groups leads from the last 72 hours into stories, so a job researches a story once with every source in hand,
// and so corroboration (how many independent publishers, and of what kind, report it) decides what is looked at first.
//   node scripts/fuse.mjs                         group, print a summary, write data/stories.json (working file, not committed)
//   node scripts/fuse.mjs list [--limit 25] [--claims] [--region africa] [--min 2] [--json]   open stories, strongest first
//   node scripts/fuse.mjs show <id>               one story with all its leads
//   node scripts/fuse.mjs done <id> "<event id, or why it is not an event>"   close a story: every lead in it is logged as handled
// Grouping is by shared CVE id, or by shared distinctive words in the headline (names, products, places), never by
// generic words like "ransomware attack". Leak-site claims are grouped too but a story made only of claims stays low.
import { existsSync, readdirSync, readFileSync, appendFileSync, mkdirSync, rmSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { DATA, readJson, writeJson, listEventFiles, dayAgo, writeRunLog, nowIso, forEachSkipped, readStatus } from "./lib/store.mjs";
import { tokens, matchEvent, NOT_EVENT } from "./triage.mjs";

// words too common in this field to tell two stories apart
const GENERIC = new Set(("cyber cyberattack cyberattacks attack attacks attacked attacker attackers hack hacked hacker hackers hacking breach breaches breached data security ransomware malware vulnerability vulnerabilities flaw flaws bug exploit exploited exploits exploitation " +
  "incident incidents threat threats group gang claim claims lists leak site critical high severity patch patches update updates advisory alert warns warning report reports reported says said confirms confirmed company firm customers users million thousands systems system network " +
  "information personal stolen theft access remote code execution rce zero-day zero day actively cve cvss online services service outage disruption after over via using used could allows allow unauthenticated authentication bypass phishing campaign targets targeting new latest major " +
  "ciberataque cyberattaque angriff hit hits impact impacted affected affecting following amid against more than its their has have been were will " +
  // breach notices from regulators' registers (scripts/breaches.mjs): the register's words and legal forms say nothing about which breach
  // (nor do the words most filers' names share: two clinics' notices are not one story because both say "Health Care")
  "notice notices notification notifications filed filing attorney general inc llc llp ltd corp plc pllc limited companies holdings technologies health healthcare care medical management solutions investigation").split(/\s+/));
const THIN = new Set(["africa", "latin-america", "middle-east", "south-asia", "southeast-asia"]);
const TIER_RANK = { gov: 3, vendor: 2, news: 1 };
const SEARCH = new Set(["google-news", "bing-news", "gdelt"]);

/** One name per publisher: "The Record", "therecord.media" and "The Record from Recorded Future News" are the same outlet. */
export function publisherKey(name) {
  return String(name || "").toLowerCase().replace(/&amp;/g, "and").replace(/^www\./, "").replace(/\.(com|org|net|co|io|media|news|gov|edu|info|au|uk|ca|in|de|fr|es|jp|kr|br|id|ke|za|ng)(\.[a-z]{2})?$/, "").replace(/^the\s+/, "").replace(/[^a-z0-9]+/g, "");
}
export function countPublishers(names) {
  const keys = [...new Set(names.map(publisherKey).filter(Boolean))].sort((a, b) => a.length - b.length), kept = [];
  for (const k of keys) if (!kept.some((x) => x.length >= 5 && k.includes(x))) kept.push(k);
  return kept;
}
export const cvesIn = (s) => [...new Set((String(s || "").toUpperCase().match(/CVE-\d{4}-\d{4,}/g) || []))];
export const keyTokens = (title) => new Set([...tokens(String(title).replace(/^Claim: \S+ lists /, "").replace(/ on its leak site$/, "").replace(/: data breach notification filed with .*$/, ""))].filter((w) => !GENERIC.has(w) && !/^\d+$/.test(w)));

/** Group leads into stories. leads: [{title,url,source,tier,via,kind,seen_at,published,lang,region}] -> [[lead,...],...] */
export function cluster(leads) {
  const n = leads.length, parent = leads.map((_, i) => i);
  const find = (i) => { while (parent[i] !== i) { parent[i] = parent[parent[i]]; i = parent[i]; } return i; };
  const join2 = (a, b) => { a = find(a); b = find(b); if (a !== b) parent[Math.max(a, b)] = Math.min(a, b); };
  const toks = leads.map((l) => keyTokens(l.title)), byCve = new Map(), byTok = new Map();
  leads.forEach((l, i) => {
    cvesIn(l.title).forEach((c) => { if (byCve.has(c)) join2(byCve.get(c), i); else byCve.set(c, i); });
    // the same organisation's notices on several breach registers are one breach (corroboration, not new stories)
    if (l.kind === "breach-notice" && l.org) { const k = "org:" + l.org; if (byCve.has(k)) join2(byCve.get(k), i); else byCve.set(k, i); }
    toks[i].forEach((w) => { if (!byTok.has(w)) byTok.set(w, []); byTok.get(w).push(i); });
  });
  // only compare leads that share a distinctive word that is not everywhere
  const seen = new Set();
  for (const [, ids] of byTok) {
    if (ids.length < 2 || ids.length > 40) continue;
    for (let x = 0; x < ids.length; x++) for (let y = x + 1; y < ids.length; y++) {
      const a = ids[x], b = ids[y], k = a * n + b; if (seen.has(k) || find(a) === find(b)) continue; seen.add(k);
      let inter = 0; toks[a].forEach((w) => toks[b].has(w) && inter++);
      const small = Math.min(toks[a].size, toks[b].size), union = toks[a].size + toks[b].size - inter;
      // a leak-site claim carries only the victim's name: it joins a report when the whole name is in the headline
      const claim = (leads[a].kind === "claim") !== (leads[b].kind === "claim"), claimTok = leads[a].kind === "claim" ? toks[a] : toks[b];
      const other = leads[a].kind === "claim" ? leads[b] : leads[a];
      const nameHit = claim && inter === claimTok.size && /ransom|attack|breach|hack|leak|extort|stolen|incident/i.test(other.title) && (inter >= 2 || [...claimTok][0].length >= 6);
      if ((inter >= 2 && inter / union >= 0.4) || (inter >= 2 && small <= 5 && inter / small >= 0.5 && inter / union >= 0.25) || (inter >= 3 && inter / small >= 0.6) || nameHit) join2(a, b);
    }
  }
  const groups = new Map();
  leads.forEach((l, i) => { const r = find(i); if (!groups.has(r)) groups.set(r, []); groups.get(r).push(l); });
  return [...groups.values()];
}

const INCIDENT = /\b(breach(ed|es)?|ransomware|hack(ed|ers?|ing)?|cyber[- ]?attacks?|attack(ed|s)?|stolen|leak(ed|s)?|data theft|extortion|outages?|disrupt(ed|ion|s)|interruptions?|shut ?down|compromised?|intrusion|espionage|malware|phishing campaign|backdoor|botnet|wiper|ddos)\b|ciberataque|ciberseguridad: ataque|ataque (hacker|cibern)|cyberangriff|hackerangriff|datenleck|cyberattaque|piratage|attacco (hacker|informatico)|siber sald|hacklendi|サイバー攻撃|不正アクセス|情報漏えい|流出|해킹|사이버 공격|유출|网络攻击|黑客|هجوم سيبراني|اختراق|кибератак|взлом/i;
export const ROUTINE = /weekly report|multiple vulnerabilit|mehrere schwachstellen|schwachstelle ermöglicht|security (update|advisory|bulletin|release)s?\b|patch tuesday|複数|脆弱性|vulnerabilità|vulnérabilités? dans|\[(neu|update)\]|vulnerabilidad(es)? en\b|vulnerabilidades? (no|na|em)\b|zaifliklar|zaiflik|уязвимост|ranjivost|ranljivost|sérülékenység|podatnoś|zranitelnost|güvenlik açığ|kwetsbaarhe|sårbarhe[dt]|haavoittuvuu|kerentanan|lỗ hổng|ثغرات|ثغرة|취약점|漏洞/i;
// a routine bulletin about a critical flaw still goes to an agent, in any of these languages
export const CRITICAL = /exploit|zero-day|0-day|actively|critical|kritisch|critique|kritik|kriti[čc]n|kritikus|cr[ií]tic|критич|krytycz|kritisk|kriittinen|nghiêm trọng|حرج|긴급|심각|緊急|严重/i;
const EVENTLIKE = /\b(expos(ed|es|ure)|unauthori[sz]ed access|deface(d|ment)?|taken (down|offline)|knocked offline|offline|down for|arrest(ed|s)?|sentenced|charged|indict(ed|ment)|extradit\w+|sanction(s|ed)?|fined|fine of|seiz(ed|ure|es)|takedown|dismantl\w+|zero-day|0-day|exploit(ed|s|ation|ing)?|emergency (patch|update|directive)|out-of-band|spyware|trojan|stealer|rootkit|campaign|threat (actor|group)|apt[- ]?\d+|state-backed|state-sponsored|confirms?|discloses?|notif(y|ies|ying)|investigat(es|ing|ion)|lawsuit|class action|settle(s|ment)|regulator|directive|orders?|bans?|mandate(s|d)?|recall(s|ed)?|warns? of|advisory warns|urges|sues?|sued|targets?|targeted|targeting|critical (bug|flaw|hole|vulnerabilit\w+)s?|flaws?|vulnerabilit(y|ies)|patch(es|ed)?|scam(s|mers)?|fraud|phishing|typosquat\w*|payloads?|poisoned|hijack\w*|steal(s|ing)?|backdoors?|shuts? ?down|rce|remote code execution|trojani[sz]ed|snooping|regulators?|reports? of)\b/i;
const EXPLAINER = /\?\s*$|^(how|why|what|when|who|is|are|can|should|if|no,)\b|\b(op-?ed|opinion|explained|explainer|\d+ (steps|ways|tips|things)|nine steps|tips (to|for)|guide to|lessons? (from|learned)|podcast|webinar|what (we|you) (know|need)|believes|truth is|don[’']t let)\b/i;
const REDIRECT = /^https?:\/\/(news\.google\.com|(www\.)?bing\.com|(www\.)?msn\.com)\b/i;

/** Pure: the stories worth showing on the site as "reported, being checked" before any research has happened.
 *  No AI model: publishers' own headlines, named, linked to the publisher's own page when a collector has it.
 *  Never a leak-site claim, never a bare database row, never something already on the map. A regulator's breach notice
 *  (kind "breach-notice", scripts/breaches.mjs) is an official filing that agents read, but its headline is the
 *  collector's, not a publisher's: it never heads this list. */
export function developing(stories, now = Date.now(), max = 30) {
  return stories.filter((s) => isOpen(s) && !s.claim_only && !s.kinds.includes("claim") && (now - Date.parse(s.published)) < 36 * 36e5
      && s.leads.some((l) => !["cve", "breach-db", "status", "claim", "breach-notice"].includes(l.kind) && (!l.lang || l.lang === "en"))
      && !s.explainer && (s.dated || s.publishers >= 2) && (s.publishers >= 2 || s.kinds.includes("exploited") || (s.incident && s.tiers.some((t) => t === "gov" || t === "vendor"))) && !(s.routine && s.publishers < 3))
    .sort((a, b) => b.score - a.score || (a.published < b.published ? 1 : -1)).slice(0, max)
    .map((s) => {
      const en = s.leads.filter((l) => (!l.lang || l.lang === "en") && !["cve", "breach-db", "status", "claim", "breach-notice"].includes(l.kind)), head = en[0] || s.leads[0], direct = en.find((l) => /^https:\/\//.test(l.url) && !REDIRECT.test(l.url));
      return { id: s.id, title: String(head.title).slice(0, 180), sources: [...new Set(s.leads.filter((l) => l.kind !== "claim").map((l) => String(l.source)))].slice(0, 4), publishers: s.publishers, url: direct ? direct.url : "", at: s.published, exploited: s.kinds.includes("exploited") };
    });
}

/** One story from its leads. now is a timestamp (ms). */
export function story(group, evs = [], now = Date.now()) {
  const best = group.slice().sort((a, b) => (a.kind === "claim") - (b.kind === "claim") || (TIER_RANK[b.tier] || 0) - (TIER_RANK[a.tier] || 0) || SEARCH.has(a.via) - SEARCH.has(b.via) || String(a.seen_at).localeCompare(String(b.seen_at)))[0];
  const publishers = new Set(countPublishers(group.map((l) => l.source))), vias = new Set(group.map((l) => l.via || "rss")), tiers = new Set(group.map((l) => l.tier));
  // a vendor's or CISA's own "exploited" statement on an advisory lead (scripts/psirt.mjs, scripts/ics.mjs) counts as listed exploited
  const kinds = new Set(group.flatMap((l) => (l.kind === "advisory" && l.exploited === true ? [l.kind, "exploited"] : [l.kind])).filter(Boolean)), regions = [...new Set(group.map((l) => l.region).filter(Boolean))], langs = [...new Set(group.map((l) => l.lang).filter(Boolean))];
  const cves = [...new Set(group.flatMap((l) => cvesIn(l.title)))].slice(0, 8);
  const times = group.map((l) => Date.parse(l.seen_at)).filter(isFinite), first = Math.min(...times), last = Math.max(...times);
  const claimOnly = group.every((l) => l.kind === "claim"), open = group.filter((l) => l._open).length;
  // how long this story has waited: from its oldest lead that is still open, not from an old lead that was handled hours ago
  const openTimes = group.filter((l) => l._open).map((l) => Date.parse(l.seen_at)).filter(isFinite), waitingSince = openTimes.length ? Math.min(...openTimes) : first;
  // a match by name alone (any language) needs the lead's own date near the event's: leadAt is when it was published
  const leadAt = (l) => l.published || l.seen_at || now;
  const ev = matchEvent(best.title, evs, leadAt(best)) || group.slice(0, 8).map((l) => l !== best && matchEvent(l.title, evs, leadAt(l))).filter(Boolean).sort((a, b) => b.score - a.score)[0] || cves.map((c) => evs.find((e) => (e.cves || []).includes(c))).filter(Boolean).map((e) => ({ id: e.id }))[0] || null;
  const pts = [];
  const add = (p, why) => { if (p) pts.push([p, why]); };
  const indep = [...publishers].filter((p) => p !== "ransomwarelive").length;
  // a bare database row (a new CVE, a breach-list entry, a status page) is a fact to check, not yet a report by an agency or vendor
  const reported = (t) => group.some((l) => l.tier === t && !["cve", "breach-db", "status"].includes(l.kind));
  add(Math.min(indep, 8) * 2, `${indep} publisher${indep === 1 ? "" : "s"}`);
  add(reported("gov") ? 6 : 0, "a government or CERT source"); add(reported("vendor") ? 3 : 0, "a vendor or research source");
  add(!reported("gov") && !reported("vendor") && group.some((l) => ["cve", "breach-db", "status"].includes(l.kind)) ? 2 : 0, "a primary database entry");
  add(kinds.has("exploited") ? 6 : 0, "listed as exploited"); add(cves.length ? 2 : 0, "names a CVE");
  add(vias.size >= 2 ? 3 : 0, `${vias.size} independent collectors`);
  // how new the report itself is (its publication time), not when a collector first happened to see it: an old bulletin
  // met for the first time is not news, and researchers were spending most of their slots rejecting those
  const pubs = group.map((l) => Date.parse(l.published)).filter((t) => isFinite(t) && t <= now + 36e5), dated = pubs.length > 0, newest = dated ? Math.max(...pubs) : last;
  const ageH = (now - newest) / 36e5;
  // a feed that gives no publication time earns nothing here: old posts met for the first time looked brand new
  add(!dated ? 0 : ageH < 6 ? 4 : ageH < 24 ? 2 : 0, ageH < 6 ? "published in the last 6 hours" : "published in the last day");
  add(ageH > 6 * 24 ? -10 : ageH > 3 * 24 ? -4 : 0, ageH > 6 * 24 ? "published more than six days ago" : "published more than three days ago");
  const titles = group.map((l) => l.title || "").join(" \n ");
  const incident = INCIDENT.test(titles), routine = ROUTINE.test(best.title || "") && !kinds.has("exploited") && !CRITICAL.test(titles);
  const explainer = EXPLAINER.test(best.title || "");
  add(incident && !explainer ? 4 : 0, "reads like an incident");
  add(explainer ? -6 : 0, "reads like commentary or advice, not an event");
  add(routine && indep <= 2 ? -5 : 0, "a routine bulletin with no sign of exploitation");
  add(group.every((l) => THIN.has(l.region)) ? 3 : 0, "found only through a thinly covered region");
  add(kinds.has("claim") && !claimOnly ? 2 : 0, "matches a leak-site claim");
  let score = pts.reduce((s, p) => s + p[0], 0); if (claimOnly) score = Math.min(score, 2);
  return {
    id: createHash("sha1").update(group.map((l) => l.url).sort()[0]).digest("hex").slice(0, 8), title: String(best.title).slice(0, 200), score, why: pts.map((p) => p[1]),
    publishers: publishers.size, vias: [...vias], tiers: [...tiers], kinds: [...kinds], cves, regions, langs, first_seen: new Date(first).toISOString().replace(/\.\d+Z$/, "Z"), waiting_since: new Date(waitingSince).toISOString().replace(/\.\d+Z$/, "Z"), last_seen: new Date(last).toISOString().replace(/\.\d+Z$/, "Z"),
    claim_only: claimOnly, event: ev ? ev.id : "", open, published: new Date(newest).toISOString().replace(/\.\d+Z$/, "Z"), dated, incident: incident && !explainer, eventlike: (incident || EVENTLIKE.test(titles)) && !explainer, routine, explainer,
    leads: group.slice().sort((a, b) => (TIER_RANK[b.tier] || 0) - (TIER_RANK[a.tier] || 0)).slice(0, 14).map((l) => ({ source: l.source, tier: l.tier, via: l.via || "rss", ...(l.kind ? { kind: l.kind } : {}), ...(l.lang ? { lang: l.lang } : {}), title: String(l.title).slice(0, 160), url: l.url, open: !!l._open })),
    more: Math.max(0, group.length - 14), urls: group.map((l) => l.url),
  };
}

export function build() {
  const used = new Set(), rejected = new Set();
  const evs = listEventFiles().map((f) => f.e).filter((e) => e && !e.duplicate_of);
  evs.forEach((e) => (e.sources || []).forEach((s) => used.add(s.url)));
  forEachSkipped(14, (u) => rejected.add(u));
  const cutoff = Date.now() - 72 * 36e5, map = new Map(), dir = join(DATA, "leads");
  if (existsSync(dir)) for (const f of readdirSync(dir).filter((f) => f.endsWith(".jsonl") && f.slice(0, 10) >= dayAgo(4)))
    for (const line of readFileSync(join(dir, f), "utf8").split("\n")) {
      try { const l = JSON.parse(line); if (!l.url || Date.parse(l.seen_at) < cutoff || NOT_EVENT.test(l.title || "")) continue; l._open = !used.has(l.url) && !rejected.has(l.url); map.set(l.url, l); } catch {}
    }
  const recent = evs.filter((e) => e.date >= dayAgo(30));
  const stories = cluster([...map.values()]).map((g) => story(g, recent)).sort((a, b) => b.score - a.score || (a.last_seen < b.last_seen ? 1 : -1));
  return { built_at: nowIso(), leads: map.size, stories };
}
export const isOpen = (s) => s.open > 0 && !s.event;

function fmt(s) {
  const tags = [s.cves.slice(0, 2).join(" "), s.regions.join(","), s.langs.filter((l) => l !== "en").join(","), s.claim_only ? "CLAIM ONLY" : s.kinds.includes("claim") ? "has claim" : "", s.kinds.includes("status") ? "status page" : ""].filter(Boolean).join(" · ");
  return `[${String(s.score).padStart(2)}] ${s.id}  ${s.title.slice(0, 110)}\n       ${s.publishers} publisher(s): ${[...new Set(s.leads.map((l) => l.source))].slice(0, 6).join(", ")}${s.more ? " +" + s.more + " more" : ""}${tags ? "  |  " + tags : ""}`;
}

function main() {
  const [cmd, ...rest] = process.argv.slice(2), opt = (k, d) => { const i = rest.indexOf("--" + k); return i >= 0 ? rest[i + 1] : d; };
  const d = build(), open = d.stories.filter(isOpen);
  if (cmd === "show") {
    const s = d.stories.find((x) => x.id === rest[0]); if (!s) { console.error("no such story (ids change as leads arrive; run list again)"); process.exit(1); }
    console.log(fmt(s) + `\n       why: ${s.why.join("; ")}${s.event ? "\n       ON FILE as " + s.event : ""}`);
    s.leads.forEach((l) => console.log(`  - [${l.tier}${l.kind ? "/" + l.kind : ""}${l.lang && l.lang !== "en" ? "/" + l.lang : ""}] ${l.source}: ${l.title}\n    ${l.url}${l.open ? "" : "  (already handled)"}`));
    return;
  }
  if (cmd === "done") {
    const s = d.stories.find((x) => x.id === rest[0]), why = String(rest.slice(1).join(" ")).replace(/\s+/g, " ").trim().slice(0, 200);
    if (!s || !why) { console.error('usage: fuse.mjs done <id> "<event id, or why it is not an event>"'); process.exit(1); }
    // one line per closure in a daily file (a file per closure was hundreds of tiny files a day, all re-read by every plan)
    const day = nowIso().slice(0, 10), dir = join(DATA, "runs", day); mkdirSync(dir, { recursive: true });
    appendFileSync(join(dir, "closures.jsonl"), JSON.stringify({ at: nowIso(), story: s.id, title: s.title.slice(0, 120), reason: why, urls: s.urls }) + "\n");
    console.log(`story ${s.id} closed (${s.urls.length} lead${s.urls.length === 1 ? "" : "s"}): ${why}`); return;
  }
  if (cmd === "compact") {
    // fold the old one-file-per-closure logs (<HHMM>-stories*.json) into each day's closures.jsonl; nothing is lost
    let files = 0, lines = 0;
    for (const d of readdirSync(join(DATA, "runs"))) {
      const dir = join(DATA, "runs", d), old = readdirSync(dir).filter((f) => /^\d{4}-stories(-\d+)?\.json$/.test(f)).sort(); if (!old.length) continue;
      const out = [];
      for (const f of old) { const r = readJson(join(dir, f), {}), sk = r.skipped || []; if (!sk.length) { rmSync(join(dir, f)); files++; continue; }
        const why = String(sk[0].reason || "").replace(/^story [0-9a-f]+: /, ""); out.push(JSON.stringify({ at: r.finished_at || r.started_at || "", story: r.story || "", title: String(sk[0].title || "").slice(0, 120), reason: why, urls: sk.map((x) => x.url).filter(Boolean) })); rmSync(join(dir, f)); files++; }
      if (out.length) { appendFileSync(join(dir, "closures.jsonl"), out.join("\n") + "\n"); lines += out.length; }
    }
    console.log(`compacted ${files} closure file(s) into ${lines} line(s) of closures.jsonl`); return;
  }
  if (cmd === "list") {
    const min = Number(opt("min", 0)), region = opt("region", ""), claims = rest.includes("--claims");
    const list = open.filter((s) => (claims || !s.claim_only) && s.score >= min && (!region || s.regions.includes(region))).slice(0, Number(opt("limit", 25)));
    if (rest.includes("--json")) { console.log(JSON.stringify(list.map(({ urls, ...s }) => s))); return; }
    console.log(`${open.length} open stories from ${d.leads} leads in the last 72 hours (${open.filter((s) => s.claim_only).length} are leak-site claims only, hidden unless --claims). Strongest first:`);
    list.forEach((s) => console.log(fmt(s)));
    console.log(`\nnode scripts/fuse.mjs show <id> lists a story's sources; done <id> "<event id or reason>" closes it.`); return;
  }
  writeJson(join(DATA, "stories.json"), { built_at: d.built_at, leads: d.leads, stories: d.stories.map(({ urls, ...s }) => s).slice(0, 400) });
  const multi = open.filter((s) => s.publishers >= 2 && !s.claim_only).length;
  const sp = join(DATA, "status.json"), st = readStatus();
  Object.assign(st, { last_fuse_at: d.built_at, stories_open: open.length, stories_corroborated: multi, stories_claims: open.filter((s) => s.claim_only).length, leads_72h: d.leads }); writeJson(sp, st);
  console.log(`fuse: ${d.leads} leads in 72 h -> ${d.stories.length} stories; ${open.length} open (${multi} reported by two or more publishers, ${open.filter((s) => s.claim_only).length} claims only); ${d.stories.filter((s) => s.event).length} already on file`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
