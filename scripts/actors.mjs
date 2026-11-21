// Threat actor profiles, built only from what CyberView already holds and checked. No AI model.
//
// Three kinds of link between a group and an event, never mixed:
//   attributed  the event's `attribution`: a government or the investigating firm says the group did it (who said so,
//               and the page where they said it, are kept with every row)
//   named       the event's `actor` field: the group as named in the reporting the event cites (the sources' words,
//               not an attribution by CyberView)
//   claimed     the group claimed the attack on its leak site (event status `claimed`, or the actor text says
//               "claimed"): an attacker's claim, never shown as fact and never counted in sectors, countries or CVEs
//
// Names are merged only on a stated basis:
//   - the same name written differently (case, spaces, punctuation, accents: "APT 28" = "APT28")
//   - MITRE ATT&CK lists one name as an alias of the other (config/attack-groups.json: names, aliases and IDs only)
//   - one event's own actor text states the names as one group ("Sapphire Sleet / UNC1069", "X (also Y, Z)")
// A name ATT&CK lists under two groups is ambiguous and merges nothing; a merge that would join two different ATT&CK
// groups is refused and shown as a stated link instead. Every alias says where it comes from.
//
// Run: node scripts/actors.mjs            print the profiles' summary (the build writes site/data/actors.json)
//      node scripts/actors.mjs attack     refresh config/attack-groups.json from mitre-attack/attack-stix-data
//                                         (raw.githubusercontent.com, keyless; its robots.txt sets no limits)
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { ROOT, readJson, listEventFiles, nowIso } from "./lib/store.mjs";

export const ATTACK_FILE = join(ROOT, "config", "attack-groups.json");
export const ATTACK_NOTICE = "MITRE ATT&CK® group names, aliases and IDs. © The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.";
const STIX = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master";
const DOMAINS = ["enterprise-attack", "mobile-attack", "ics-attack"];

const clip = (v, n) => (typeof v === "string" ? v.replace(/\s+/g, " ").trim().slice(0, n) : "");
const https = (u) => { try { const x = new URL(u); return x.protocol === "https:" ? x.href : ""; } catch { return ""; } };

/** The key two spellings of one name share: "APT 28", "apt28" and "APT-28" are one name; accents are dropped. */
export function norm(name) {
  return String(name || "").normalize("NFKD").replace(/[̀-ͯ]/g, "").toLowerCase().replace(/[^a-z0-9]+/g, "");
}
export const slug = (name) => String(name || "").normalize("NFKD").replace(/[̀-ͯ]/g, "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 60) || "actor";

// Not a group's name: unnamed or generic descriptions, countries, sentences.
const GENERIC = /\b(unnamed|unknown|unattributed|unidentified|not attributed|none|n\/a)\b|^(suspected |possible |likely |alleged )?(state[- ]sponsored|china|chinese|prc|russia|russian|iran|iranian|north korea|north korean|dprk|pakistan|india|israel|vietnam|belarus)\b|^overlaps?\b|\b(actors|operators|workers?|affiliates|hackers)$|\bactor$/i;
export function isName(s) {
  const t = clip(s, 200);
  return !!t && t.length <= 40 && t.split(" ").length <= 5 && norm(t).length >= 2 && !GENERIC.test(t);
}

// split on `sep` only outside parentheses ("REF3364 (Elastic's name; unattributed)" stays one part)
function splitTop(s, sep) {
  const out = []; let depth = 0, cur = "";
  for (const ch of s) {
    if (ch === "(") depth++; else if (ch === ")") depth = Math.max(0, depth - 1);
    if (ch === sep && depth === 0) { out.push(cur); cur = ""; } else cur += ch;
  }
  out.push(cur);
  return out.map((x) => x.trim()).filter(Boolean);
}

/**
 * An event's `actor` text -> the groups it names. Each: { name, aliases[] (stated in this same text), claimed (the text
 * says the group claimed it), qualifier (the rest, as written) }. Generic descriptions name no group and are dropped.
 */
export function parseActor(text) {
  const t = clip(text, 300);
  if (!t) return [];
  const out = [];
  for (const part of splitTop(t, ";")) {
    // a bracket after a space is a qualifier ("Qilin (ransomware)"); one stuck to the name is part of it ("NoName057(16)")
    const quals = [...part.matchAll(/(?:^|\s)\(([^()]*)\)/g)].map((m) => m[1].trim());
    let base = part.replace(/(^|\s)\([^()]*\)/g, " ").replace(/,\s*(per|according to|as stated by|as cited by|said by)\b.*$/i, "").replace(/\s+/g, " ").trim().replace(/[,.:]+$/, "");
    const stated = [];
    for (const q of quals) { const m = /^(also|aka|a\.k\.a\.|also known as|formerly)\s+(.+)$/i.exec(q); if (m) stated.push(...m[2].split(/,|\band\b/).map((x) => x.trim())); }
    const names = base.split(/\s+\/\s+/).map((x) => x.trim()).filter(isName);
    if (!names.length) continue;
    out.push({ name: names[0], aliases: [...new Set([...names.slice(1), ...stated.filter(isName)])], claimed: quals.some((q) => /\bclaim(ed|s)?\b/i.test(q)), qualifier: clip(quals.join("; "), 200) });
  }
  return out;
}

/** ATT&CK collection (STIX 2.1 bundle) -> [{id: "G0007", name, aliases[], url}] for live intrusion sets only. */
export function attackGroups(bundle) {
  const out = [];
  for (const o of (bundle && bundle.objects) || []) {
    if (!o || o.type !== "intrusion-set" || o.revoked || o.x_mitre_deprecated) continue;
    const ref = (o.external_references || []).find((r) => r && r.source_name === "mitre-attack" && /^G\d{4}$/.test(r.external_id || ""));
    if (!ref || !clip(o.name, 80)) continue;
    const name = clip(o.name, 80);
    const aliases = [...new Set([...(o.aliases || []), ...(o.x_mitre_aliases || [])].map((a) => clip(a, 80)).filter((a) => a && norm(a) !== norm(name)))].slice(0, 40);
    out.push({ id: ref.external_id, name, aliases, url: `https://attack.mitre.org/groups/${ref.external_id}/` });
  }
  return out.sort((a, b) => (a.id < b.id ? -1 : 1));
}

/** The stored ATT&CK list, checked: only well-formed {id, name, aliases, url}. Missing file -> []. */
export function loadAttack(file = ATTACK_FILE) {
  const j = readJson(file, null);
  if (!j || !Array.isArray(j.groups)) return { version: "", groups: [] };
  const groups = j.groups.filter((g) => g && /^G\d{4}$/.test(g.id) && clip(g.name, 80)).map((g) => ({ id: g.id, name: clip(g.name, 80), aliases: (Array.isArray(g.aliases) ? g.aliases : []).map((a) => clip(a, 80)).filter(Boolean).slice(0, 40), url: `https://attack.mitre.org/groups/${g.id}/` }));
  return { version: clip(j.version, 20), groups };
}

// union-find over normalised names; each set remembers which ATT&CK group(s) it holds
function makeSets() {
  const parent = new Map(), attack = new Map();
  const find = (k) => { if (!parent.has(k)) { parent.set(k, k); attack.set(k, new Set()); } let r = k; while (parent.get(r) !== r) r = parent.get(r); parent.set(k, r); return r; };
  // refuses to join two different ATT&CK groups; returns false when refused
  const union = (a, b) => {
    const ra = find(a), rb = find(b); if (ra === rb) return true;
    const ga = attack.get(ra), gb = attack.get(rb);
    if (ga.size && gb.size && [...ga].some((g) => !gb.has(g))) return false;
    parent.set(rb, ra); gb.forEach((g) => ga.add(g)); attack.delete(rb); return true;
  };
  return { find, union, groupsOf: (k) => attack.get(find(k)) };
}

const STATUS = new Set(["confirmed", "official", "developing", "claimed"]);
const count = (rows, key) => { const m = new Map(); for (const r of rows) for (const v of key(r)) { const k = v.toLowerCase(); const x = m.get(k) || { k: v, n: 0 }; x.n++; m.set(k, x); } return [...m.values()].sort((a, b) => b.n - a.n || (a.k < b.k ? -1 : 1)).slice(0, 12); };

/**
 * Pure: events (duplicates already left out) + ATT&CK groups -> { profiles[], ... } for site/data/actors.json.
 */
export function buildActors(events, attack = { version: "", groups: [] }, built_at = nowIso()) {
  const sets = makeSets(), mentions = [], related = [], ambiguous = new Map();
  // ATT&CK first: a name listed under exactly one group joins it; a name under two groups is ambiguous
  const owners = new Map();
  for (const g of attack.groups) for (const n of [g.name, ...g.aliases]) { const k = norm(n); if (!k) continue; const s = owners.get(k) || new Set(); s.add(g.id); owners.set(k, s); }
  const byId = new Map(attack.groups.map((g) => [g.id, g]));
  for (const [k, ids] of owners) if (ids.size > 1) ambiguous.set(k, [...ids].sort());
  for (const g of attack.groups) {
    const gk = "attack:" + g.id; sets.find(gk); sets.groupsOf(gk).add(g.id);
    for (const n of [g.name, ...g.aliases]) { const k = norm(n); if (k && !ambiguous.has(k)) sets.union(gk, k); }
  }
  // read every event first: which names the checked events use (attributed or named), and which appear only in claims
  const raw = [];
  for (const e of events) {
    if (!e || e.duplicate_of || !e.id) continue;
    const ev = { event_id: clip(e.id, 120), title: clip(e.title, 160), date: /^\d{4}-\d{2}-\d{2}$/.test(e.date || "") ? e.date : "", status: STATUS.has(e.status) ? e.status : "" };
    const att = e.attribution && typeof e.attribution === "object" ? e.attribution : null;
    if (att) for (const p of parseActor(att.actor)) raw.push({ p, tier: "attributed", e, ev, att, as_written: clip(att.actor, 160) });
    for (const p of parseActor(e.actor)) raw.push({ p, tier: e.status === "claimed" || p.claimed ? "claimed" : "named", e, ev, att: null, as_written: clip(e.actor, 200) });
  }
  const checkedKeys = new Set();
  for (const r of raw) if (r.tier !== "claimed") for (const n of [r.p.name, ...r.p.aliases]) checkedKeys.add(norm(n));
  // a leak-site brand can share its name with an unrelated group ATT&CK tracks ("Inception"), so a name seen only in
  // claims is never joined to ATT&CK: it gets a key of its own, and the profile names the namesake instead
  const keyOf = (n) => { const k = norm(n); return owners.has(k) && !checkedKeys.has(k) ? "claim:" + k : k; };
  const aliasStated = new Map();   // key -> [{name, event_id, title}] (stated as one group in one event's text)
  for (const { p, tier, e, ev, att, as_written } of raw) {
    const k = keyOf(p.name); sets.find(k);
    mentions.push({ key: k, name: p.name, tier, e, ev, att, qualifier: p.qualifier, as_written });
    for (const a of p.aliases) {
      const ak = keyOf(a); if (!norm(a) || ak === k) continue;
      const row = { name: a, event_id: ev.event_id, title: ev.title };
      if (sets.union(k, ak)) { const l = aliasStated.get(ak) || []; l.push(row); aliasStated.set(ak, l); const l2 = aliasStated.get(k) || []; l2.push({ ...row, name: p.name }); aliasStated.set(k, l2); }
      else related.push({ a: p.name, b: a, ka: k, kb: ak, event_id: ev.event_id, title: ev.title });
    }
  }
  // one profile per set that holds at least one event mention
  const groups = new Map();
  for (const m of mentions) { const r = sets.find(m.key); const g = groups.get(r) || []; g.push(m); groups.set(r, g); }
  const profiles = [];
  for (const [root, ms] of groups) {
    const ids = [...(sets.groupsOf(root) || [])], at = ids.length === 1 ? byId.get(ids[0]) : null;
    // the name used most in CyberView's own events is the title; ATT&CK's name is listed with its ID
    const tally = new Map();
    for (const m of ms) tally.set(m.name, (tally.get(m.name) || 0) + (m.tier === "claimed" ? 1 : 2));
    const name = [...tally].sort((a, b) => b[1] - a[1] || a[0].length - b[0].length || (a[0] < b[0] ? -1 : 1))[0][0];
    const own = new Set(ms.map((m) => m.key));
    const aliases = [], seenA = new Set([norm(name)]);
    // names differing only in spelling share one key, so every other name here was joined by a stated basis
    for (const k of [...own, ...aliasStated.keys()]) {
      if (sets.find(k) !== root) continue;
      for (const s of aliasStated.get(k) || []) { const nk = norm(s.name); if (seenA.has(nk)) continue; seenA.add(nk); aliases.push({ name: s.name, source: `named as one group in "${s.title}"`, basis: "event", event_id: s.event_id }); }
    }
    if (at) for (const n of [at.name, ...at.aliases]) { const nk = norm(n); if (seenA.has(nk) || ambiguous.has(nk)) continue; seenA.add(nk); aliases.push({ name: n, source: `MITRE ATT&CK ${at.id}`, basis: "attack", url: at.url }); }
    // the same event can mention a group twice (attribution and actor text): keep the strongest link once
    const rank = { attributed: 0, named: 1, claimed: 2 }, best = new Map();
    for (const m of ms) { const cur = best.get(m.ev.event_id); if (!cur || rank[m.tier] < rank[cur.tier]) best.set(m.ev.event_id, m); }
    const rows = [...best.values()].sort((a, b) => (a.ev.date < b.ev.date ? 1 : a.ev.date > b.ev.date ? -1 : 0));
    const attributed = rows.filter((m) => m.tier === "attributed").map((m) => ({ ...m.ev, by: clip(m.att.by, 120), by_type: m.att.by_type === "government" ? "government" : "investigator", url: https(m.att.url), origin_country: clip(m.att.origin_country, 60), note: clip(m.att.note || m.att.claim || (m.att.confidence ? m.att.confidence + " confidence" : ""), 200), as_written: m.as_written }));
    const named = rows.filter((m) => m.tier === "named").map((m) => ({ ...m.ev, as_written: m.as_written }));
    const claimed = rows.filter((m) => m.tier === "claimed").map((m) => ({ ...m.ev, org: clip(m.e.org, 80), as_written: m.as_written }));
    const checked = rows.filter((m) => m.tier !== "claimed").map((m) => m.e);
    const cves = new Map();
    for (const e of checked) for (const c of e.cves || []) if (/^CVE-\d{4}-\d{4,7}$/.test(c)) { const l = cves.get(c) || []; l.push(clip(e.id, 120)); cves.set(c, l); }
    const adv = [], seenU = new Set();
    for (const m of rows) {
      if (m.tier === "claimed") continue;
      const r = m.e.report;
      if (r && r.publisher_type === "government" && https(r.url) && !seenU.has(r.url)) { seenU.add(r.url); adv.push({ publisher: clip(r.publisher, 120), doc_id: clip(r.doc_id, 60), url: https(r.url), event_id: m.ev.event_id }); }
      if (m.tier === "attributed" && m.att.by_type === "government" && https(m.att.url) && !seenU.has(m.att.url)) { seenU.add(m.att.url); adv.push({ publisher: clip(m.att.by, 120), doc_id: "", url: https(m.att.url), event_id: m.ev.event_id }); }
    }
    const dates = rows.map((m) => m.ev.date).filter(Boolean).sort();
    const rel = related.filter((r) => sets.find(r.ka) === root || sets.find(r.kb) === root).map((r) => ({ name: sets.find(r.ka) === root ? r.b : r.a, event_id: r.event_id, title: r.title }));
    const amb = [...own].filter((k) => ambiguous.has(k)).map((k) => ({ name: ms.find((m) => m.key === k).name, attack_ids: ambiguous.get(k) }));
    // a claims-only name that ATT&CK also lists: shown as a namesake, never as the same group
    const ns = [...own].filter((k) => k.startsWith("claim:") && !ambiguous.has(k.slice(6))).map((k) => byId.get([...owners.get(k.slice(6))][0])).filter(Boolean);
    const namesake = ns.length ? { id: ns[0].id, name: ns[0].name, url: ns[0].url } : null;
    profiles.push({
      id: "", name, attack: at ? { id: at.id, name: at.name, url: at.url } : null,
      aliases: aliases.slice(0, 60), attributed, named, claimed,
      origins: [...new Map(attributed.filter((a) => a.origin_country).map((a) => [a.origin_country + "|" + a.by, { country: a.origin_country, by: a.by, by_type: a.by_type, url: a.url }])).values()],
      sectors: count(checked, (e) => String(e.sector || "").split(/[,;/]| and /i).map((x) => clip(x, 40)).filter((x) => x && x.length < 40)),
      countries: count(checked, (e) => [clip(e.country, 60)].filter((x) => x && !/^(global|worldwide|multiple|international|unknown)/i.test(x))),
      cves: [...cves].map(([id, ev]) => ({ id, event_ids: ev.slice(0, 10) })).sort((a, b) => b.event_ids.length - a.event_ids.length || (a.id < b.id ? 1 : -1)).slice(0, 40),
      advisories: adv.slice(0, 20), related: rel.slice(0, 10), ambiguous: amb, attack_namesake: namesake,
      first_seen: dates[0] || "", last_seen: dates[dates.length - 1] || "",
      claims_only: !attributed.length && !named.length,
    });
  }
  // stable, unique ids for links (actors.html#a=<id>)
  const used = new Set();
  for (const p of profiles) { let id = slug(p.attack ? p.attack.id + "-" + p.name : p.name), i = 2; while (used.has(id)) id = slug(p.name) + "-" + i++; used.add(id); p.id = id; }
  profiles.sort((a, b) => Number(a.claims_only) - Number(b.claims_only) || (a.last_seen < b.last_seen ? 1 : a.last_seen > b.last_seen ? -1 : 0) || (b.attributed.length + b.named.length) - (a.attributed.length + a.named.length) || (a.name < b.name ? -1 : 1));
  return { built_at, attack_version: attack.version, attack_notice: attack.groups.length ? ATTACK_NOTICE : "", profiles,
    counts: { profiles: profiles.length, checked: profiles.filter((p) => !p.claims_only).length, claims_only: profiles.filter((p) => p.claims_only).length, attack_matched: profiles.filter((p) => p.attack).length } };
}

async function refreshAttack() {
  const { get } = await import("./lib/net.mjs");
  const all = new Map(); let version = "";
  for (const d of DOMAINS) {
    const b = await get(`${STIX}/${d}/${d}.json`, { timeoutMs: 180000, retries: 2, delayMs: 60000, factor: 2 });
    const coll = (b.objects || []).find((o) => o.type === "x-mitre-collection");
    if (d === "enterprise-attack" && coll) version = clip(coll.x_mitre_version, 20);
    for (const g of attackGroups(b)) { const x = all.get(g.id); if (x) x.aliases = [...new Set([...x.aliases, ...g.aliases])]; else all.set(g.id, g); }
  }
  const groups = [...all.values()].sort((a, b) => (a.id < b.id ? -1 : 1)).map((g) => ({ id: g.id, name: g.name, aliases: g.aliases }));
  if (groups.length < 50) throw new Error(`only ${groups.length} groups read; config/attack-groups.json left as it was`);
  const head = JSON.stringify({ _note: "Names, aliases and IDs only (never descriptions), from " + STIX + " (enterprise, mobile, ics). Refresh: node scripts/actors.mjs attack. " + ATTACK_NOTICE, version, fetched_at: nowIso() });
  writeFileSync(ATTACK_FILE, head.slice(0, -1) + ',"groups":[\n' + groups.map((g) => JSON.stringify(g)).join(",\n") + "\n]}\n");   // one group per line, so a refresh reads well as a diff
  console.log(`config/attack-groups.json: ${groups.length} groups, ATT&CK v${version}`);
}

async function main() {
  if (process.argv[2] === "attack") return refreshAttack();
  const events = listEventFiles().filter((f) => f.e && !f.e.duplicate_of).map((f) => f.e);
  const a = buildActors(events, loadAttack());
  console.log(`actors: ${a.counts.profiles} profiles (${a.counts.checked} named or attributed, ${a.counts.claims_only} only in claims, ${a.counts.attack_matched} matched to MITRE ATT&CK)`);
  for (const p of a.profiles.slice(0, 40)) console.log(`  ${p.name}${p.attack ? ` [${p.attack.id}]` : ""}: ${p.attributed.length} attributed, ${p.named.length} named, ${p.claimed.length} claimed; last ${p.last_seen}`);
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
