// Pure: what gets a story in the Library. Every ORKL actor gets one (a catalogue-only profile when no report is read yet);
// reports that name no resolvable actor get a "subject" story (a malware, campaign, vulnerability or incident) when their cards
// hold enough detail. Nothing here does I/O.
import { createHash } from "node:crypto";

const sha1 = (s) => createHash("sha1").update(String(s)).digest("hex");
const isObj = (x) => x && typeof x === "object" && !Array.isArray(x);
const SAFE_ID = /^[0-9A-Za-z-]{1,64}$/;
const FACT_LISTS = ["tools", "techniques", "sectors", "countries", "dates", "cves"];
const NOT_LOOSE = ["overview", "not-a-threat-report"];
const MIN_FACTS = 3, MIN_NAME = 3;

/** Lower-case, NFKC, letters and digits only. */
export const nameKey = (s) => String(s == null ? "" : s).normalize("NFKC").toLowerCase().replace(/[^\p{L}\p{N}]+/gu, "");

const namesOf = (a) => [a && a.name, ...(a && Array.isArray(a.aliases) ? a.aliases : [])].map((x) => (isObj(x) ? x.name : x)).filter((x) => typeof x === "string");

/** byKey: nameKey of every name and alias -> actor id; a key two actors claim maps to null (joins neither). */
export function actorIndex(actors) {
  const byKey = new Map();
  for (const a of actors || []) {
    if (!isObj(a)) continue;
    for (const k of new Set(namesOf(a).map(nameKey).filter(Boolean))) {
      if (!byKey.has(k)) byKey.set(k, a.id);
      else if (byKey.get(k) !== a.id) byKey.set(k, null);
    }
  }
  return { byKey };
}

/** The actor ids a report's `actors` list resolves to. */
function resolveActors(report, ix) {
  const ids = new Set();
  for (const n of Array.isArray(report && report.actors) ? report.actors : []) {
    const id = ix.byKey.get(nameKey(isObj(n) ? n.name : n));
    if (id != null) ids.add(id);
  }
  return ids;
}
const stamp = (r) => String(r.created || r.file_date || "");
// a card the owner withdrew (library-review.mjs withdraw) counts as not read: it feeds no story and no basedOn
const readCard = (cards, s) => { const c = cards && cards.get ? cards.get(s) : null; return c && c.status === "read" && c.withdrawn !== true ? c : null; };

/** One subject per actor, with or without read reports. sha1s: read cards of the reports that resolve to the actor, newest report first. */
export function actorSubjects(actors, reports, cards) {
  const ix = actorIndex(actors), mine = new Map();
  for (const r of [...(reports || [])].sort((a, b) => stamp(b).localeCompare(stamp(a)) || String(a.sha1).localeCompare(String(b.sha1)))) {
    if (!readCard(cards, r.sha1)) continue;
    for (const id of resolveActors(r, ix)) (mine.get(id) || mine.set(id, []).get(id)).push(r.sha1);
  }
  return (actors || []).filter((a) => isObj(a) && (a.name || (a.id != null && String(a.id)))).map((a) => {
    const name = String(a.name || a.id), actor = a.name ? a : { ...a, name };
    return {
      key: "a-" + (SAFE_ID.test(String(a.id)) ? a.id : sha1(a.id != null ? `${a.id}\0${name}` : name).slice(0, 16)),
      kind: "actor", name, actor, sha1s: mine.get(a.id) || [],
    };
  });
}

/** A card detailed enough to carry a story without an actor. */
export function eligibleLoose(card) {
  if (!isObj(card) || card.status !== "read" || card.withdrawn === true || NOT_LOOSE.includes(card.kind)) return false;
  if (!isObj(card.subject) || String(card.subject.name || "").trim().length < MIN_NAME) return false;
  const f = isObj(card.facts) ? card.facts : {};
  return FACT_LISTS.reduce((n, k) => n + (Array.isArray(f[k]) ? f[k].length : 0), 0) >= MIN_FACTS;
}

/** Eligible cards of reports naming no resolvable actor, grouped by subject type and name. */
export function looseSubjects(reports, cards, actorIdx) {
  const groups = new Map();
  for (const r of [...(reports || [])].sort((a, b) => stamp(b).localeCompare(stamp(a)) || String(a.sha1).localeCompare(String(b.sha1)))) {
    const c = cards && cards.get ? cards.get(r.sha1) : null;
    if (!eligibleLoose(c) || resolveActors(r, actorIdx).size) continue;
    const id = c.subject.type + ":" + nameKey(c.subject.name);
    if (!nameKey(c.subject.name)) continue;
    const g = groups.get(id) || groups.set(id, { name: c.subject.name, sha1s: [] }).get(id);
    g.sha1s.push(r.sha1);
  }
  return [...groups].map(([id, g]) => ({ key: "s-" + sha1(id).slice(0, 16), kind: "subject", name: g.name, actor: null, sha1s: g.sha1s }));
}

/** What a story rests on: the read cards (sha1 + read_at) and the actor record's aliases and tools. A card no longer `read` is not counted. */
export function basedOn(subject, cards) {
  const pairs = [...new Set(subject.sha1s || [])].map((s) => readCard(cards, s)).filter(Boolean).map((c) => `${c.sha1}@${c.read_at || ""}`).sort();
  const a = subject.actor || {};
  const list = (x) => (Array.isArray(x) ? x : []).map(String).sort();
  return sha1(JSON.stringify([pairs, list(a.aliases), list(a.tools)]));
}
