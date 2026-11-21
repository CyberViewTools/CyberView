// Validation for the newer record shapes, kept here so unit tests can reach them without running the build.
// Each function returns a list of problems (strings); an empty list means the record is fine.
// checkEventQuality and sharedSourceProblems return [{level, code, text}] instead (see there).
import { pathToFileURL } from "node:url";
import { SECTOR, SURFACE, BASES, MAX_SECTORS } from "./taxonomy.mjs";

const https = (u) => typeof u === "string" && /^https:\/\/[^\s"'<>]+$/.test(u) && (() => { try { const x = new URL(u); return x.pathname !== "/" || !!x.search; } catch { return false; } })();
const text = (v, max) => typeof v === "string" && v.trim().length > 0 && v.length <= max;
const ID = /^[a-z0-9][a-z0-9-]{2,119}$/;

/**
 * Event "attribution": who a government or the investigating firm says did it, and where the actor is said to be based.
 * Drawn on the globe as a dashed arc from the attributed origin to the victim, labelled with who attributed it.
 * { actor, origin_country, lat, lng, by, by_type: government | investigator, url, stated_at? }
 */
// The controlled vocabulary for event `tags` (kinds of threat); sector, country and product belong in their own fields. Keep docs/schema.md in step.
export const TAGS = ["ransomware","data-breach","supply-chain","zero-day","ddos","espionage","critical-infrastructure","ai-enabled","third-party","phishing","insider","hacktivism","ot-ics","cloud","identity","fraud","takedown","regulation","funding","acquisition","malware","rce","poc-public"];

export function checkAttribution(a) {
  if (a == null) return [];
  if (typeof a !== "object" || Array.isArray(a)) return ["attribution must be an object"];
  const p = [];
  if (!text(a.actor, 120)) p.push("attribution.actor is required (as named in the attribution)");
  if (!text(a.origin_country, 60)) p.push("attribution.origin_country is required");
  if (typeof a.lat !== "number" || a.lat < -90 || a.lat > 90 || typeof a.lng !== "number" || a.lng < -180 || a.lng > 180) p.push("attribution.lat and lng must be numbers in range (the origin country's capital or centre)");
  if (!["government", "investigator"].includes(a.by_type)) p.push('attribution.by_type must be "government" or "investigator" (attacker boasts and press speculation do not count)');
  if (!text(a.by, 120)) p.push("attribution.by must name the government body or investigating firm");
  if (!https(a.url)) p.push("attribution.url must be the https page where the attribution is made (not a front page)");
  return p;
}

/**
 * Event "links": stated relationships to other events, e.g. a breached supplier and a customer hit through it.
 * [{ to: <event id>, rel: "customer of breached supplier", url: <page that states the link> }]
 * `known` is a Set of event ids on file, so a link to a missing event is caught.
 */
export function checkLinks(links, selfId, known) {
  if (links == null) return [];
  if (!Array.isArray(links)) return ["links must be a list"];
  const p = [];
  if (links.length > 40) p.push("links: at most 40");
  links.forEach((l, i) => {
    if (!l || typeof l !== "object") { p.push(`links[${i}] must be an object`); return; }
    if (!ID.test(l.to || "")) p.push(`links[${i}].to must be an event id`);
    else if (l.to === selfId) p.push(`links[${i}] points at the event itself`);
    else if (known && !known.has(l.to)) p.push(`links[${i}].to "${l.to}" is not an event on file`);
    if (!text(l.rel, 60)) p.push(`links[${i}].rel must say how they are linked (at most 60 characters)`);
    if (!https(l.url)) p.push(`links[${i}].url must be the https page that states the link`);
  });
  return p;
}

/**
 * The weekly tabletop exercise (data/tabletop.json and data/snapshots/tabletop/<date>.json). See docs/schema.md.
 * `known` is a Set of event ids on file.
 */
export function checkTabletop(t, known) {
  if (!t || typeof t !== "object" || Array.isArray(t)) return ["not an object"];
  const p = [];
  if (t.label !== "exercise") p.push('label must be "exercise"');
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(t.generated_at || "")) p.push("generated_at must be an ISO time");
  if (!/^\d{4}-\d{2}-\d{2}$/.test(t.date || "")) p.push("date must be YYYY-MM-DD");
  if (!text(t.title, 120)) p.push("title is required (at most 120 characters)");
  if (!Array.isArray(t.based_on) || !t.based_on.length) p.push("based_on must list the real event id(s) the exercise is built from");
  else t.based_on.forEach((id) => { if (!ID.test(id || "")) p.push(`based_on: "${id}" is not an event id`); else if (known && !known.has(id)) p.push(`based_on: "${id}" is not an event on file`); });
  if (!text(t.real_story, 900)) p.push("real_story is required: what really happened, from the event record (at most 900 characters)");
  if (!Array.isArray(t.facts) || t.facts.length < 2) p.push("facts: list at least 2 verified facts, each with the source it came from");
  else t.facts.forEach((f, i) => { if (!f || !text(f.text, 300)) p.push(`facts[${i}].text is required (at most 300 characters)`); if (!f || !https(f.source_url)) p.push(`facts[${i}].source_url must be the https page the fact is from`); });
  if (!text(t.scenario, 1200)) p.push("scenario is required (at most 1200 characters)");
  if (!Number.isInteger(t.duration_min) || t.duration_min < 20 || t.duration_min > 180) p.push("duration_min must be a whole number from 20 to 180");
  if (!Array.isArray(t.roles) || !t.roles.length || t.roles.some((r) => !text(r, 60))) p.push("roles: list who should be in the room (each at most 60 characters)");
  if (!Array.isArray(t.injects) || t.injects.length < 3 || t.injects.length > 10) p.push("injects: 3 to 10 timed updates");
  else {
    let last = -1;
    t.injects.forEach((x, i) => {
      if (!x || typeof x !== "object") { p.push(`injects[${i}] must be an object`); return; }
      if (!Number.isInteger(x.at_min) || x.at_min < 0 || x.at_min > (t.duration_min || 180)) p.push(`injects[${i}].at_min must be a minute within the exercise`);
      else if (x.at_min < last) p.push(`injects[${i}] is out of time order`); else last = x.at_min;
      if (!text(x.title, 90)) p.push(`injects[${i}].title is required (at most 90 characters)`);
      if (!text(x.text, 600)) p.push(`injects[${i}].text is required (at most 600 characters)`);
      if (x.ask != null && !text(x.ask, 300)) p.push(`injects[${i}].ask must be text (at most 300 characters)`);
    });
  }
  for (const [k, min, max, len] of [["questions", 4, 12, 300], ["good_looks_like", 3, 10, 300]]) {
    if (!Array.isArray(t[k]) || t[k].length < min || t[k].length > max || t[k].some((q) => !text(q, len))) p.push(`${k}: ${min} to ${max} items, each at most ${len} characters`);
  }
  if (t.adapt != null && !text(t.adapt, 600)) p.push("adapt must be text (at most 600 characters)");
  if (!Array.isArray(t.sources) || !t.sources.length) p.push("sources: list the pages read");
  else t.sources.forEach((s, i) => { if (!s || !text(s.name, 80) || !https(s.url)) p.push(`sources[${i}] needs a name and the https url of the page read`); });
  return p;
}

export const HUNT_FORMATS = ["stix", "sigma", "yara", "snort", "suricata", "kql", "spl", "csv", "json", "misp", "openioc", "text", "pdf"];
/**
 * Detection resources published by the original advisory or report: indicator files and detection rules.
 * [{ name, format, url, publisher }]. Links only: CyberView never copies indicators themselves.
 */
export function checkHunt(list) {
  if (list == null) return [];
  if (!Array.isArray(list)) return ["hunt must be a list"];
  const p = [];
  if (list.length > 12) p.push("hunt: at most 12");
  list.forEach((h, i) => {
    if (!h || typeof h !== "object") { p.push(`hunt[${i}] must be an object`); return; }
    if (!text(h.name, 100)) p.push(`hunt[${i}].name is required (what the file is, at most 100 characters)`);
    if (!HUNT_FORMATS.includes(h.format)) p.push(`hunt[${i}].format must be one of ${HUNT_FORMATS.join(", ")}`);
    if (!https(h.url)) p.push(`hunt[${i}].url must be the https address of the file or the page that publishes it`);
    if (h.publisher != null && !text(h.publisher, 80)) p.push(`hunt[${i}].publisher must be text (at most 80 characters)`);
  });
  return p;
}

/**
 * A fix guide for one CVE (data/guides/<CVE>.json), written by the advisory desk from the vendor's own advisory.
 * { cve, advisory: {name, url}, read_at, read_depth: full | summary, check[], fixed[], workaround[], compromise_signs[],
 *   exposure: internet | internal | local, exploit_public: bool, hunt[] }
 */
export function checkGuide(g, id) {
  if (!g || typeof g !== "object" || Array.isArray(g)) return ["not an object"];
  const p = [];
  if (!/^CVE-\d{4}-\d{4,}$/.test(g.cve || "")) p.push("cve must be a CVE id");
  else if (id && g.cve !== id) p.push(`cve "${g.cve}" does not match the file name`);
  if (!g.advisory || !text(g.advisory.name, 100) || !https(g.advisory.url)) p.push("advisory needs a name and the https url of the vendor or agency advisory that was read");
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(g.read_at || "")) p.push("read_at must be an ISO time");
  if (!["full", "summary"].includes(g.read_depth)) p.push('read_depth must be "full" or "summary" (a guide is never written from secondary coverage)');
  for (const [k, max, len] of [["check", 6, 320], ["fixed", 8, 160], ["workaround", 5, 320], ["compromise_signs", 6, 320]]) {
    if (g[k] == null) continue;
    if (!Array.isArray(g[k]) || g[k].length > max || g[k].some((x) => !text(x, len))) p.push(`${k}: at most ${max} items, each at most ${len} characters`);
  }
  if (!(g.check || []).length && !(g.fixed || []).length && !(g.workaround || []).length) p.push("a guide needs at least one of check, fixed or workaround");
  if (g.exposure != null && !["internet", "internal", "local"].includes(g.exposure)) p.push("exposure must be internet, internal or local");
  if (g.exploit_public != null && typeof g.exploit_public !== "boolean") p.push("exploit_public must be true or false");
  return p.concat(checkHunt(g.hunt));
}

/**
 * An exploitation analysis (data/analyses/<CVE>.json), written by the exploit analyst job (an Opus agent) from public sources.
 * It explains how attackers use a flaw at the level of an advisory, so defenders can find exposure, detect use and fix it.
 * It never contains exploit code, payloads, request strings, commands that attack a system, or reproduction steps:
 * NOCODE rejects text that looks like any of those, so a record carrying them is refused by the build.
 * { cve, analyzed_at, model, exploitation_status, how_exploited, preconditions[], attack_path[], exposure, who_is_exposed[],
 *   detect[], remediation: { priority, steps[], fixed_versions[], workarounds[], verify[], if_compromised[] },
 *   confidence, caveats, sources: [{ name, url, kind, read_depth }] }
 */
export const NOCODE = /`|<\/?(script|iframe|svg|img|object|embed)\b|\$\{|\$\(|\b(curl|wget|nc|ncat|netcat|powershell|bash|sh|python3?|perl|ruby|php|msfconsole|sqlmap|nmap)\s+-|\b(curl|wget)\s+https?:|\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\/\S|\.\.\/\.\.|%2e%2e|%00|\\x[0-9a-f]{2}|\b0x[0-9a-f]{8,}|[A-Za-z0-9+\/]{60,}={0,2}|\b(payload|shellcode|proof[- ]of[- ]concept code|exploit code)\s*:|\bUNION\s+SELECT\b|\bOR\s+1\s*=\s*1\b|\/bin\/(ba)?sh\b|\bcmd\.exe\s*\/c\b|\bjndi:|\{\{.*\}\}|\bchmod\s+\+x\b/i;
const SRC_KINDS = ["vendor", "government", "research", "news", "database"];
export function checkAnalysis(a, id) {
  if (!a || typeof a !== "object" || Array.isArray(a)) return ["not an object"];
  const p = [], strs = [];
  const one = (k, max, req = true) => { const v = a[k]; if ((v == null || v === "") && !req) return; if (!text(v, max)) p.push(`${k}: required text, at most ${max} characters`); else strs.push([k, v]); };
  const many = (o, k, min, max, len, label = k) => { const v = o[k]; if (v == null && !min) return;
    if (!Array.isArray(v) || v.length < min || v.length > max || v.some((x) => !text(x, len))) p.push(`${label}: ${min ? min + " to " : "at most "}${max} items, each at most ${len} characters`); else v.forEach((x) => strs.push([label, x])); };
  if (!/^CVE-\d{4}-\d{4,}$/.test(a.cve || "")) p.push("cve must be a CVE id"); else if (id && a.cve !== id) p.push(`cve "${a.cve}" does not match the file name`);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(a.analyzed_at || "")) p.push("analyzed_at must be an ISO time");
  if (!text(a.model, 60)) p.push("model must name the model that wrote it");
  one("exploitation_status", 240); one("how_exploited", 900);
  many(a, "preconditions", 1, 6, 260); many(a, "attack_path", 1, 6, 280); many(a, "who_is_exposed", 0, 5, 260); many(a, "detect", 1, 6, 300);
  if (!["internet", "internal", "local"].includes(a.exposure)) p.push("exposure must be internet, internal or local");
  const r = a.remediation;
  if (!r || typeof r !== "object" || Array.isArray(r)) p.push("remediation is required");
  else {
    if (!["immediate", "urgent", "planned"].includes(r.priority)) p.push("remediation.priority must be immediate, urgent or planned");
    many(r, "steps", 1, 8, 320, "remediation.steps"); many(r, "fixed_versions", 0, 8, 160, "remediation.fixed_versions"); many(r, "workarounds", 0, 5, 320, "remediation.workarounds");
    many(r, "verify", 1, 5, 300, "remediation.verify"); many(r, "if_compromised", 0, 6, 300, "remediation.if_compromised");
  }
  if (!["high", "medium", "low"].includes(a.confidence)) p.push("confidence must be high, medium or low");
  one("caveats", 500, false);
  const src = a.sources;
  if (!Array.isArray(src) || src.length < 2 || src.length > 10) p.push("sources: 2 to 10 pages that were read");
  else {
    src.forEach((x, i) => { if (!x || !text(x.name, 100) || !https(x.url) || !SRC_KINDS.includes(x.kind) || !["full", "summary"].includes(x.read_depth)) p.push(`sources[${i}] needs name, https url (a specific page), kind (${SRC_KINDS.join(", ")}) and read_depth (full or summary)`); });
    if (!src.some((x) => x && (x.kind === "vendor" || x.kind === "government"))) p.push("sources must include the vendor's advisory or a government source");
  }
  for (const [k, v] of strs) if (NOCODE.test(v)) { p.push(`${k}: looks like code, a payload, a request or an attack command; describe the technique in words instead`); break; }
  return p;
}

/**
 * A published community post (data/chat/<YYYY-MM>/<issue>.json), written only by scripts/chat.mjs approve after review.
 * { id, at, author, kind: comment | tip | question, text, event_id, links[], reviewed_at, note?, removed?, removed_reason? }
 */
export function checkChat(c, known) {
  if (!c || typeof c !== "object" || Array.isArray(c)) return ["not an object"];
  const p = [];
  if (!Number.isInteger(c.id) || c.id < 1) p.push("id must be the issue number");
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(c.at || "")) p.push("at must be an ISO time");
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/.test(c.author || "")) p.push("author must be a GitHub login");
  if (!["comment", "tip", "question"].includes(c.kind)) p.push("kind must be comment, tip or question");
  if (!text(c.text, 600) || /[<>\u0000-\u001f]/.test(c.text)) p.push("text is required: plain text, at most 600 characters, no markup");
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(c.reviewed_at || "")) p.push("reviewed_at is required: a post is never published unreviewed");
  if (!Array.isArray(c.links) || c.links.length > 2 || c.links.some((u) => typeof u !== "string" || !/^https:\/\/[^\s"'<>]+$/.test(u))) p.push("links: at most 2, https only");
  if (c.event_id && (!ID.test(c.event_id) || (known && !known.has(c.event_id)))) p.push(`event_id "${c.event_id}" is not an event on file`);
  if (c.note != null && !text(c.note, 200)) p.push("note must be text (at most 200 characters)");
  if (c.removed != null && typeof c.removed !== "boolean") p.push("removed must be true or false");
  return p;
}

/**
 * Event quality: the mistakes the second review kept correcting (reviews of 13-20 November 2026: 118 of 346 corrected or
 * flagged; by 20 November 141 of 412 corrected), where a rule can decide. Returns [{level: "error"|"warn", code, text}]. The build fails on "error" only for
 * events first seen from QUALITY_STRICT_FROM (older records get it as a warning, so history never blocks a commit);
 * "warn" is always a warning. `node scripts/lib/validate.mjs <event id...>` prints them for chosen events.
 * Checks that need the other events (shared source pages, possible duplicates) are in sharedSourceProblems().
 */
export const QUALITY_STRICT_FROM = "2026-11-21T00:00:00Z";
// Pages that relay other publishers' reporting: breach trackers, weekly roundups, leak-site mirrors, law-firm lead pages,
// forums. They can point to a story; on their own they cannot carry "confirmed", "official" or "corroborated".
export const SECONDARY_HOSTS = ["ransomware.live", "ransomlook.io", "redpacketsecurity.com", "sharkstriker.com", "privacyguides.org", "agentbeam.com", "claimdepot.com", "classaction.org", "hookphish.com", "windowsforum.com", "mlq.ai", "letsdatascience.com", "hackmanac.com", "breachsense.com"];
// a tag, category, label, author, topic or search listing rather than one article (e.g. thehackernews.com/search/label/X)
const LISTING = /\/(tag|tags|category|categories|label|labels|author|authors|topic|topics|archive|archives)\/[^/]+\/?(page\/\d+\/?)?$|\/search\/?$/i;
const hostOf = (u) => { try { return new URL(u).hostname.toLowerCase().replace(/^www\./, ""); } catch { return ""; } };
export const isSecondary = (u) => { const h = hostOf(u); return !!h && SECONDARY_HOSTS.some((x) => h === x || h.endsWith("." + x)); };
export function isListingPage(u) {
  try { const x = new URL(u); return LISTING.test(x.pathname) || ((x.pathname === "/" || /\/search\b/i.test(x.pathname)) && /[?&](s|q|query|search)=/i.test(x.search)); } catch { return false; }
}
// figures a reader acts on: 1,234 / 4.5 million / 2 billion (not years, versions or ids)
const FIGURE = /\b\d{1,3}(?:,\d{3})+\b|\b\d+(?:\.\d+)?\s?(?:million|billion|bn)\b/gi;
const TAG_NEEDS = {
  "zero-day": [/zero[- ]day|0-day|before (a |any )?(patch|fix)|no (patch|fix) (was |is )?available|unpatched|exploited/i, "a source must say it was exploited before a fix existed"],
  "poc-public": [/proof[- ]of[- ]concept|\bpoc\b|exploit code|public(ly)? (available )?exploit|exploit (is |was |has been )?(public|released|published)/i, "the text must say exploit code or a proof of concept is public"],
  "supply-chain": [/supply[- ]chain|third[- ]party|supplier|vendor|package|dependenc|npm|pypi|update (server|mechanism|channel)|library|plugin|extension/i, "the text must say the attack came through a supplier, package or update"],
};
// a figure with the word in front of it that says how exact it is; the class is what a reader takes from it
const QFIG = /\b(about|around|approximately|roughly|some|nearly|almost|under|less than|fewer than|up to|over|more than|at least)?\s*(\d{1,3}(?:,\d{3})+|\d+(?:\.\d+)?\s?(?:million|billion|bn))\b/gi;
const QCLASS = { about: "about", around: "about", approximately: "about", roughly: "about", some: "about", nearly: "below", almost: "below", under: "below", "less than": "below", "fewer than": "below", "up to": "below", over: "above", "more than": "above", "at least": "above" };
const figValue = (s) => { const m = String(s).toLowerCase().replace(/,/g, "").match(/([\d.]+)\s?(million|billion|bn)?/); return m ? Number(m[1]) * (m[2] === "million" ? 1e6 : m[2] ? 1e9 : 1) : NaN; };
/** Pure: the figures in a text, each with its qualifier class (exact, about, below, above) and its value. */
export const figuresIn = (t) => [...String(t || "").matchAll(QFIG)].map((m) => ({ raw: m[0].trim(), value: figValue(m[2]), q: m[1] ? QCLASS[m[1].toLowerCase()] : "exact" })).filter((x) => Number.isFinite(x.value));
// how much later than first_seen (UTC) the event's own date may be: the date is local to where it happened (UTC+14 at most)
const LOCAL_AHEAD_MS = 14 * 36e5;

export function checkEventQuality(e, { now = Date.now() } = {}) {
  const out = [], add = (level, code, text) => out.push({ level, code, text });
  if (!e || typeof e !== "object") return out;
  const src = (Array.isArray(e.sources) ? e.sources : []).filter((s) => s && typeof s.url === "string");
  const hosts = new Set(src.map((s) => hostOf(s.url)).filter(Boolean));
  // timestamps come from `date -u` at the moment of writing; a time ahead of the clock was estimated or typed by hand
  for (const k of ["first_seen", "updated_at"]) { const t = Date.parse(e[k] || ""); if (Number.isFinite(t) && t - now > 10 * 6e4) add("warn", "future-timestamp", `${k} ${e[k]} is in the future: write it from \`date -u +%Y-%m-%dT%H:%M:%SZ\` at the time of writing, never an estimate`); }
  if (/^\d{4}-\d{2}-\d{2}$/.test(e.date || "") && Number.isFinite(Date.parse(e.first_seen || "")) && e.date > new Date(Date.parse(e.first_seen) + LOCAL_AHEAD_MS).toISOString().slice(0, 10))
    add("error", "date-after-seen", `date ${e.date} is after the event was first seen (${String(e.first_seen).slice(0, 16)}Z): the date is when it happened or was disclosed, which cannot be later than the moment it was recorded`);
  // dates: the day it happened, not the day an article (or a roundup) was published
  const seen = String(e.first_seen || "").slice(0, 10);
  if (/^\d{4}-\d{2}-\d{2}$/.test(seen) && /^\d{4}-\d{2}-\d{2}$/.test(e.date || "") && (Date.parse(seen) - Date.parse(e.date)) / 864e5 > 7 && !String(e.date_note || "").trim())
    add("error", "old-date-no-note", `date ${e.date} is more than 7 days before first_seen ${seen}: write "date_note" saying what the date is (attack, disclosure, filing) and why the event is added now`);
  if (e.occurred_at != null && e.occurred_at !== "") {
    if (!["occurred", "reported", "published", "approx"].includes(e.time_basis)) add("error", "occurred-no-basis", 'occurred_at needs "time_basis": occurred, reported, published or approx (which time the source states)');
    // a 00:00 or 12:00 UTC time is how a made-up time looks (the second review kept correcting it): an error for events first
    // seen from QUALITY_STRICT_FROM, a warning for older ones (the build and the CLI lower it)
    if (/T(00|12):00(:00(\.0+)?)?(Z|[+-]00:?00)$/.test(String(e.occurred_at)) && e.time_basis !== "approx")
      add("error", "occurred-placeholder", `occurred_at ${e.occurred_at} looks like a placeholder: use the time a source states, mark it time_basis "approx", or leave occurred_at out`);
  }
  // validation and status must match what the sources can carry
  const v = e.validation && e.validation.state;
  if (v === "corroborated" && hosts.size < 2 && e.source_tier !== "primary")
    add("error", "corroborated-one-host", '"corroborated" needs two independent publishers, each stating the core fact; with one publisher it is "single_source"');
  const allSecondary = src.length > 0 && src.every((s) => isSecondary(s.url));
  if (allSecondary && (e.status === "confirmed" || e.status === "official"))
    add("error", "confirmed-on-secondary", `status "${e.status}" rests only on trackers or roundups (${[...hosts].join(", ")}): read and cite the organisation's own notice, a regulator filing or the original report, or set status "developing"`);
  if (allSecondary && v === "corroborated") add("error", "corroborated-on-secondary", "trackers and roundups relay one report; they cannot corroborate it");
  if (allSecondary && e.source_tier && e.source_tier !== "aggregator") add("warn", "tier-secondary", `every source is a tracker or roundup, so source_tier is "aggregator", not "${e.source_tier}"`);
  if (e.status === "confirmed" && e.source_tier === "aggregator" && !allSecondary) add("warn", "confirmed-on-aggregator", '"confirmed" needs the organisation\'s or an authority\'s own statement among the sources; an aggregator relaying it is not enough');
  for (const s of src) if (isListingPage(s.url)) add("error", "listing-source", `source ${s.url.slice(0, 100)} is a tag, category, search or listing page: cite the specific article`);
  // tags only for what the text (and so the source) says
  const words = `${e.title || ""} ${e.summary || ""} ${e.plain || ""} ${e.exec || ""}`;
  // optional names in other scripts or languages (docs/schema.md; scripts/triage.mjs matches retellings with them)
  if (e.aliases !== undefined && !(Array.isArray(e.aliases) && e.aliases.length <= 8 && e.aliases.every((a) => typeof a === "string" && a.trim() && a.length <= 60)))
    add("warn", "aliases-shape", "aliases must be a list of at most 8 names of up to 60 characters");
  for (const [t, [re, why]] of Object.entries(TAG_NEEDS)) if ((e.tags || []).includes(t) && !re.test(words)) add("warn", "tag-unsupported", `tag "${t}": ${why}; otherwise remove the tag`);
  // an actor named in CyberView's own voice
  if (e.actor && !e.attribution && e.status !== "claimed" && !/claim|unattributed|unknown|suspected/i.test(e.actor) && !/attribut|according to|\bsaid\b|\bsays\b|linked|tracks|blamed|assess/i.test(e.summary || ""))
    add("warn", "actor-unsourced", `actor "${String(e.actor).slice(0, 40)}" is named but the summary does not say who attributed it ("according to <firm or agency>")`);
  // "400+" is CyberView's shorthand, not a source's qualifier: the second review kept rewriting it to the source's own words
  for (const k of ["title", "summary", "plain", "exec", "action"]) {
    const m = String(e[k] || "").match(/(?<![\w.])\d{1,3}(?:,\d{3})*(?:\.\d+)?\s?(?:million|billion|bn|k)?\+(?![\w+])/i);
    if (m) { add("warn", "figure-plus", `"${m[0]}" in ${k}: write the figure in the source's own words ("more than 400", "about 400", "at least 400"); keep "+" only if the source itself writes it`); break; }
  }
  // every figure in the title and exec is in the summary or impact, as stated there
  const base = `${e.summary || ""} ${e.impact || ""}`.replace(/,/g, "").toLowerCase();
  for (const k of ["title", "exec"]) {
    const miss = (String(e[k] || "").match(FIGURE) || []).find((n) => !base.includes(n.replace(/,/g, "").toLowerCase().match(/[\d.]+/)[0]));
    if (miss) add("warn", "figure-not-in-summary", `"${miss}" in ${k} is not in the summary or impact: every figure goes in the summary exactly as the source states it (with its "about", "over", "at least")`);
  }
  // the same figure carries the same qualifier everywhere: "over 125 million" in the summary is never "about 125 million"
  // in the title (the second review corrected this again and again); "plain" may round, but only with "about" and only
  // within 5% of a figure in the summary
  const stated = figuresIn(`${e.summary || ""} ${e.impact || ""}`);
  for (const k of ["title", "exec", "plain", "action"]) {
    for (const f of figuresIn(e[k])) {
      const same = stated.filter((s) => s.value === f.value);
      if (same.length && f.q !== "exact" && !same.some((s) => s.q === f.q)) { add("warn", "figure-qualifier", `"${f.raw}" in ${k} but the summary says "${same[0].raw}": keep the source's qualifier ("about", "over", "up to", "nearly") wherever the figure appears`); break; }
      if (k === "plain" && !same.length && f.value >= 1000 && !stated.some((s) => Math.abs(s.value - f.value) <= 0.05 * s.value && (f.q === "about" || (f.q === s.q && f.q !== "exact")))) { add("warn", "figure-not-in-summary", `"${f.raw}" in plain is not in the summary or impact: plain may round a stated figure ("about 341,000"), never add one`); break; }
    }
  }
  out.push(...checkClassification(e));
  return out;
}

/**
 * Event "sectors" and "surface": who was hit and through what, from fixed lists (scripts/lib/taxonomy.mjs), each with a basis
 * (stated by a source, or inferred). A value off the list or a missing basis is an error for events first seen from
 * QUALITY_STRICT_FROM (a warning before); a missing field is a warning for events first seen from CLASSIFY_FROM (older
 * events are filled by `node scripts/classify.mjs`). Returns [{level, code, text}].
 */
export const CLASSIFY_FROM = "2026-11-22T00:00:00Z";
export function checkClassification(e) {
  const out = [], add = (level, code, text) => out.push({ level, code, text });
  if (!e || typeof e !== "object") return out;
  const basis = (b, k) => { if (!BASES.includes(b)) add("error", "classify-basis", `${k}.basis must be "stated" (a page in sources says it) or "inferred" (concluded from what the sources say)`); };
  const s = e.sectors;
  if (s != null) {
    if (typeof s !== "object" || Array.isArray(s)) add("error", "sectors-shape", 'sectors must be {"values": [<sector>...], "basis": "stated" | "inferred"}');
    else {
      if (!Array.isArray(s.values) || !s.values.length || s.values.length > MAX_SECTORS) add("error", "sectors-shape", `sectors.values must list 1 to ${MAX_SECTORS} sectors, the most affected first`);
      else {
        const bad = s.values.filter((k) => !Object.prototype.hasOwnProperty.call(SECTOR, k));
        if (bad.length) add("error", "sectors-value", `sectors.values: ${bad.map((x) => JSON.stringify(x).slice(0, 40)).join(", ")} not on the list (${Object.keys(SECTOR).join(", ")})`);
        if (new Set(s.values).size !== s.values.length) add("error", "sectors-value", "sectors.values lists a sector twice");
        if (s.values.length > 1 && s.values.some((k) => k === "unknown" || k === "cross-sector")) add("error", "sectors-value", '"unknown" and "cross-sector" stand alone in sectors.values');
      }
      basis(s.basis, "sectors");
    }
  }
  const u = e.surface;
  if (u != null) {
    if (typeof u !== "object" || Array.isArray(u)) add("error", "surface-shape", 'surface must be {"value": <surface>, "basis": "stated" | "inferred"}');
    else {
      if (!Object.prototype.hasOwnProperty.call(SURFACE, u.value)) add("error", "surface-value", `surface.value ${JSON.stringify(u.value).slice(0, 40)} is not on the list (${Object.keys(SURFACE).join(", ")})`);
      basis(u.basis, "surface");
    }
  }
  if ((s == null || u == null) && String(e.first_seen || "") >= CLASSIFY_FROM && !e.duplicate_of)
    add("warn", "unclassified", `${s == null ? "sectors" : ""}${s == null && u == null ? " and " : ""}${u == null ? "surface" : ""} missing: say who was hit and through what, from the fixed lists in docs/schema.md, with basis "stated" or "inferred"`);
  return out;
}

/**
 * Checks across events: a source page cited by another event about the same organisation or CVE is a possible duplicate;
 * a page cited by three or more events is a roundup or tracker, not the report itself (government and CERT pages excepted:
 * one bulletin can cover several flaws). events: [{id, org, cves, sources, duplicate_of}]. Returns Map(id -> [{level, code,
 * text}]) for the ids in `only` (all when omitted). Warnings only.
 */
// an organisation name without legal suffixes and bracketed notes, so "Acme Ltd" and "Acme (for its retirees)" compare equal
export const orgKey = (o) => String(o || "").toLowerCase().replace(/\([^)]*\)/g, " ").replace(/\b(inc|ltd|llc|corp|corporation|plc|gmbh|ag|sa|nv|bv|co|company|holdings?|group|the)\b\.?/g, " ").replace(/[^a-z0-9]+/g, " ").trim();
// government, CERT and agency pages: one bulletin or listing covers several flaws or incidents
const OFFICIAL_HOST = /\.gov(\.[a-z]{2})?$|\.go\.[a-z]{2}$|\.mil$|cisa|cert|ncsc|githubusercontent/i;
const GENERIC_ORG = /^(unknown|multiple|various|several|many|n a|none|undisclosed|unnamed|not named|)$/;
const near = (a, b, days) => Math.abs(Date.parse(a.date) - Date.parse(b.date)) <= days * 864e5;
export function sharedSourceProblems(events, only) {
  const by = new Map(), want = only ? new Set(only) : null, out = new Map();
  const norm = (u) => String(u || "").replace(/#.*$/, "").replace(/\/+$/, "").replace(/^http:/, "https:").replace(/\/\/www\./, "//");
  const pages = (e) => [...new Set((Array.isArray(e.sources) ? e.sources : []).map((x) => x && norm(x.url)).filter(Boolean))];
  const live = events.filter((e) => e && e.id && !e.duplicate_of);
  for (const e of live) for (const s of pages(e)) (by.get(s) || by.set(s, []).get(s)).push(e);
  const org = (e) => orgKey(e.org);
  const sameOrg = (a, b) => { const x = org(a), y = org(b); return !!x && !!y && !GENERIC_ORG.test(x) && (x === y || (x.length >= 5 && y.length >= 5 && (x.startsWith(y + " ") || y.startsWith(x + " ")))); };
  const byOrg = new Map();
  for (const e of live) if (["incident", "outage"].includes(e.category) && org(e) && !GENERIC_ORG.test(org(e))) (byOrg.get(org(e).split(" ")[0]) || byOrg.set(org(e).split(" ")[0], []).get(org(e).split(" ")[0])).push(e);
  const dup = (o, why) => ({ level: "warn", code: "possible-duplicate", text: `${why} ${o.id}: if it is the same event, keep the earlier record, merge sources into it and set "duplicate_of" on the later` });
  for (const e of live) {
    if (want && !want.has(e.id)) continue;
    const p = [];
    let flagged = false;
    for (const s of pages(e)) {
      const others = (by.get(s) || []).filter((o) => o.id !== e.id);
      const same = others.find((o) => sameOrg(o, e) || (e.cves || []).some((c) => (o.cves || []).includes(c)));
      // one other event on the same page, same kind, within 3 days: a second record of one story far more often than two stories
      const twin = !same && !OFFICIAL_HOST.test(hostOf(s)) && others.length === 1 && others[0].category === e.category && near(others[0], e, 3) ? others[0] : null;
      if (same && !flagged) { flagged = true; p.push(dup(same, "cites the same page as")); }
      else if (twin && !flagged) { flagged = true; p.push(dup(twin, "cites the same page as (same category, within 3 days)")); }
      else if (!same && !twin && others.length >= 2 && !OFFICIAL_HOST.test(hostOf(s))) p.push({ level: "warn", code: "roundup-source", text: `${s.slice(0, 90)} is also cited by ${others.length} other events: a roundup or tracker; cite the article or notice it summarises and take the date from that` });
    }
    // the same victim organisation, an incident or outage of the same kind within 3 days, from different pages
    if (!flagged && ["incident", "outage"].includes(e.category) && org(e) && !GENERIC_ORG.test(org(e))) {
      const o = (byOrg.get(org(e).split(" ")[0]) || []).find((x) => x.id !== e.id && x.category === e.category && org(x) === org(e) && near(x, e, 3));
      if (o) p.push(dup(o, `is about the same organisation (${String(e.org).slice(0, 40)}) within 3 days as`));
    }
    if (p.length) out.set(e.id, p);
  }
  return out;
}

// CLI: node scripts/lib/validate.mjs <event id...>   the quality checks for those events, as the build will report them
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { listEventFiles } = await import("./store.mjs");
  const ids = process.argv.slice(2);
  if (!ids.length) { console.error("usage: node scripts/lib/validate.mjs <event id...>"); process.exit(1); }
  const all = listEventFiles().filter((f) => f.e).map((f) => ({ ...f.e, id: f.id })), shared = sharedSourceProblems(all, ids);
  let errs = 0;
  for (const id of ids) {
    const e = all.find((x) => x.id === id);
    if (!e) { console.log(`${id}: no such event`); errs++; continue; }
    const strict = String(e.first_seen || "") >= QUALITY_STRICT_FROM;
    const p = checkEventQuality(e).concat(shared.get(id) || []).map((x) => ({ ...x, level: x.level === "error" && !strict ? "warn" : x.level }));
    errs += p.filter((x) => x.level === "error").length;
    console.log(p.length ? p.map((x) => `${id}: ${x.level === "error" ? "ERROR" : "warning"} ${x.code}: ${x.text}`).join("\n") : `${id}: no quality problems found`);
  }
  process.exit(errs ? 1 : 0);
}
