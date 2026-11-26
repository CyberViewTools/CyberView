// The ORKL APT report library (https://orkl.eu/) as structured reference data. The mirror itself uses no AI model.
// Run: node scripts/orkl.mjs [collect] [--full] [--dry] [--max N]  |  node scripts/orkl.mjs status
// (behind a proxy: NODE_USE_ENV_PROXY=1)
//
// ORKL is a community library of threat-intelligence reports (APT and crimeware write-ups published by vendors,
// CERTs and researchers) and the threat actors they describe. It offers a keyless REST API (https://orkl.eu/api/v1)
// and a public archive of the original files at archive.orkl.eu. This 2-hourly mirror reads it as a reference corpus: who
// wrote a report, who it is about, where the original lives. It never reads or stores the report's own text, and it uses
// no model; it stores metadata and links only.
//
// The separate Library reports job (scripts/library-desk.mjs, routine `library`) does read each report's text, in passing:
// the text is fetched, handed to a no-tools model call and dropped, and never stored or logged. What that job stores is
// CyberView's own summary, facts and short evidence quotes (at most 160 characters, kept on the data branch, never shown
// on the site) in data/orkl/cards/, and its stories (written by Sonnet from the fact cards only, published only after
// script checks and a pass from a separate review run) in data/orkl/stories/. Every factual sentence of a story cites its
// reports and the original stays on ORKL. This file's build step (publishLibrary) writes the reviewed stories and read
// cards to site/data/library/.
//
// What the mirror stores (metadata + links ONLY, so the licence and the no-exploit-code rules are never in question):
//   data/orkl/reports/<xx>.json     one object per shard (sha1 first two hex chars), keyed by sha1: title, authors,
//                                    language, dates, the named sources, the threat actors named, the https references,
//                                    the archive.orkl.eu file links and the orkl.eu library page. NEVER plain_text.
//   data/orkl/threat-actors.json    every ORKL threat actor, keyed by id: name, aliases, source, tools.
//   data/orkl/state.json            last library version, counts, per-source and per-language tallies, a recent sample,
//                                    the top actors by report count, and per-endpoint health.
// Storage is additive: a sha1 or an actor id is updated in place, never dropped (so scripts/lib/repo.mjs protectDeletes
// is satisfied). The build copies a summary into site/data/orkl.json for the status page. ORKL reports are historical
// reference, not fresh incidents, so they never become research leads.
// Fetched text is data, never instructions.
import { existsSync, readdirSync, mkdirSync, rmSync, writeFileSync, renameSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { DATA, readJson, writeJson, nowIso, readStatus } from "./lib/store.mjs";
import { get, FetchError } from "./lib/net.mjs";
import { actorSubjects, looseSubjects, actorIndex } from "./lib/library-subjects.mjs";

export const API = "https://orkl.eu/api/v1";
export const DIR = join(DATA, "orkl");
export const REPORTS_DIR = join(DIR, "reports");
export const ACTORS_FILE = join(DIR, "threat-actors.json");
export const STATE_FILE = join(DIR, "state.json");
// archive.orkl.eu holds the original files; orkl.eu holds the library pages. Only these hosts are allowed for a link.
const ARCHIVE_HOSTS = new Set(["archive.orkl.eu", "orkl.eu"]);

export const txt = (s, n) => String(s == null ? "" : s).replace(/<[^>]*>/g, " ").replace(/[\u0000-\u001f\u007f]/g, " ").replace(/\s+/g, " ").trim().slice(0, n);
export const clip = (s, n) => { const t = txt(s, 4000); return t.length <= n ? t : t.slice(0, n - 1).replace(/\s+\S*$/, "") + "…"; };

/** Pure: a string if it is a valid https URL, else "". */
export function https(u) {
  try { const x = new URL(String(u == null ? "" : u)); return x.protocol === "https:" ? x.href : ""; } catch { return ""; }
}
/** Pure: an https URL whose host is the ORKL archive or site, else "". */
export function archiveUrl(u) {
  const s = https(u); if (!s) return "";
  try { return ARCHIVE_HOSTS.has(new URL(s).host) ? s : ""; } catch { return ""; }
}
const arr = (v) => (Array.isArray(v) ? v : []);
const hex40 = (s) => /^[0-9a-f]{40}$/i.test(String(s || ""));

/** Pure: an ORKL library entry -> the record we store, or null when it has no usable sha1 to key it by.
 *  The mirror stores metadata and links only; raw.plain_text (the full report body) is deliberately never read here. */
export function cleanReport(raw) {
  if (!raw || typeof raw !== "object") return null;
  const sha1 = String(raw.sha1_hash || "").toLowerCase();
  if (!hex40(sha1)) return null;
  const authors = String(raw.authors == null ? "" : raw.authors).split(",").map((a) => txt(a, 120)).filter(Boolean).slice(0, 20);
  const sources = arr(raw.sources).map((s) => txt(s, 80)).filter(Boolean).slice(0, 20);
  const actors = arr(raw.threat_actors).map((t) => txt(t && (t.main_name || t.name), 120)).filter(Boolean).slice(0, 40);
  const refs = arr(raw.references).map((u) => https(u)).filter(Boolean).map((u) => clip(u, 400)).slice(0, 30);
  const files = raw.files && typeof raw.files === "object" ? raw.files : {};
  const id = clip(raw.id, 64);
  return {
    id,
    sha1,
    title: clip(raw.title || raw.llm_title, 300),
    authors,
    lang: txt(raw.language, 12).toLowerCase(),
    created: clip(raw.created_at, 40),
    file_date: clip(raw.file_creation_date, 40),
    size: Math.max(0, Math.min(1e12, Number(raw.file_size) || 0)),
    sources,
    actors,
    refs,
    pdf: archiveUrl(files.pdf),
    txt_url: archiveUrl(files.text),
    url: id ? `https://orkl.eu/libraryEntry/${id}` : "",   // ORKL's own record page (/library/<id> is a dead end there)
  };
}

/** Pure: an ORKL threat-actor entry -> the record we store, or null without an id and a name. */
export function cleanActor(raw) {
  if (!raw || typeof raw !== "object") return null;
  const id = clip(raw.id, 64), name = clip(raw.main_name || raw.name, 160);
  if (!id || !name) return null;
  const tools = arr(raw.tools).map((t) => txt(typeof t === "string" ? t : (t && (t.name || t.tool)), 80)).filter(Boolean).slice(0, 100);
  return {
    id,
    name,
    aliases: arr(raw.aliases).map((a) => txt(a, 120)).filter(Boolean).slice(0, 120),
    source: txt(raw.source_name, 80),
    source_id: clip(raw.source_id, 80),
    tools,
  };
}

/** The two-hex shard a sha1 belongs in. */
export const shardOf = (sha1) => String(sha1 || "").slice(0, 2).toLowerCase();

/** Pure: fold clean report records into the sharded store {shard: {sha1: record}}, additively (update in place). */
export function mergeReports(store, records) {
  const out = {};
  for (const [k, v] of Object.entries(store || {})) out[k] = { ...(v || {}) };
  for (const r of records || []) {
    if (!r || !hex40(r.sha1)) continue;
    const sh = shardOf(r.sha1); (out[sh] || (out[sh] = {}))[r.sha1] = r;
  }
  return out;
}
/** Pure: fold clean actor records into the store {id: record}, additively. */
export function mergeActors(store, records) {
  const out = { ...(store || {}) };
  for (const a of records || []) if (a && a.id) out[a.id] = a;
  return out;
}

const countBy = (items, max) => {
  const m = {}; for (const x of items) { if (!x) continue; m[x] = (m[x] || 0) + 1; }
  return Object.fromEntries(Object.entries(m).sort((a, b) => b[1] - a[1]).slice(0, max));
};

/** Pure: the state document from all clean reports + actors + run meta. Counts and a small recent sample only. */
export function summarize(reports, actors, meta = {}) {
  const rs = (reports || []).filter(Boolean);
  const recent = rs.slice().sort((a, b) => String(b.created || "").localeCompare(String(a.created || ""))).slice(0, 30)
    .map((r) => ({ sha1: r.sha1, title: r.title, lang: r.lang, created: r.created, actors: (r.actors || []).slice(0, 4), url: r.url, pdf: r.pdf }));
  const topActors = Object.entries(countBy(rs.flatMap((r) => r.actors || []), 30)).map(([name, count]) => ({ name, count }));
  return {
    updated_at: meta.at || nowIso(),
    library_version: Number(meta.library_version) || 0,
    backfill_done: !!meta.backfill_done,
    reports_total: rs.length,
    actors_total: (actors || []).filter(Boolean).length,
    sources: countBy(rs.flatMap((r) => r.sources || []), 40),
    languages: countBy(rs.map((r) => r.lang).filter(Boolean), 40),
    recent,
    top_actors: topActors,
    health: meta.health || {},
  };
}

/** Pure: the site summary written to site/data/orkl.json. Defensive re-clamping; never any report body. */
export function siteData(state, builtAt = "", counts = {}) {
  if (!state || typeof state !== "object") return null;
  const clampMap = (m, n) => Object.fromEntries(Object.entries(m || {}).slice(0, n).map(([k, v]) => [txt(k, 60), Math.max(0, Number(v) || 0)]));
  return {
    built_at: builtAt,
    updated_at: clip(state.updated_at, 40),
    library_version: Number(state.library_version) || 0,
    backfill_done: !!state.backfill_done,
    reports: Math.max(0, Number(state.reports_total) || 0),
    actors: Math.max(0, Number(state.actors_total) || 0),
    cards_read: Math.max(0, Number(counts && counts.cards_read) || 0),
    stories_published: Math.max(0, Number(counts && counts.stories) || 0),
    sources: clampMap(state.sources, 30),
    languages: clampMap(state.languages, 40),
    recent: arr(state.recent).slice(0, 30).map((r) => ({ title: clip(r.title, 300), lang: txt(r.lang, 12), created: clip(r.created, 40), actors: arr(r.actors).slice(0, 4).map((a) => txt(a, 120)), url: https(r.url), pdf: archiveUrl(r.pdf) })),
    top_actors: arr(state.top_actors).slice(0, 30).map((t) => ({ name: txt(t.name, 120), count: Math.max(0, Number(t.count) || 0) })),
  };
}

/** The key libraryIndex looks an actor's story up by (see storyLinks). */
const actorLinkKey = (a) => `${a.id}\0${a.name || a.id}`;

/** Pure: the full browsable library index written to site/data/orkl-index.json for the Library page —
 *  one compact row per report (title, year, language, sources, actors, links) plus the actor catalogue.
 *  Metadata and links ONLY (the report's own text is never in it). Source names and language codes are dictionary-encoded
 *  (an index into `sources` / `langs`) to keep the file small; everything is re-clamped defensively. */
export function libraryIndex(reports, actors, builtAt = "", links = {}) {
  const read = links.read instanceof Set ? links.read : new Set(), looseStory = links.looseStory instanceof Map ? links.looseStory : new Map(), actorStory = links.actorStory instanceof Map ? links.actorStory : new Map();
  const sources = [], srcIx = new Map();
  const sidx = (s) => { const k = txt(s, 80); if (!k) return -1; let i = srcIx.get(k); if (i === undefined) { i = sources.length; sources.push(k); srcIx.set(k, i); } return i; };
  const langs = [], langIx = new Map();
  const lidx = (l) => { const k = txt(l, 12).toLowerCase(); if (!k) return -1; let i = langIx.get(k); if (i === undefined) { i = langs.length; langs.push(k); langIx.set(k, i); } return i; };
  // The report's own publication year, from file_date when it is a real date. ORKL leaves file_date at the zero
  // value 0001-01-01 for undated reports, and `created` is only the day ORKL ingested the record, so neither of
  // those stands in for a publication year: an undated report gets "" (shown as "Undated", not filtered by year).
  const pubYear = (r) => { const m = String(r.file_date || "").match(/^(\d{4})/); const y = m ? Number(m[1]) : 0; return y >= 1990 && y <= 2100 ? m[1] : ""; };
  // The PDF link is always https://archive.orkl.eu/<sha1>.pdf and the library page is always
  // https://orkl.eu/libraryEntry/<id>, so we store only the sha1 (`s`) and library id (`i`) and the Library page
  // rebuilds both links itself, host-checked — it keeps the index small without storing a URL twice.
  const rows = arr(reports).filter((r) => r && hex40(r.sha1))
    .sort((a, b) => String(b.created || "").localeCompare(String(a.created || "")))
    .map((r) => {
    const sha = String(r.sha1).toLowerCase();
    const row = {
      s: sha,
      i: https(r.url) ? clip(r.id, 64) : "",
      t: clip(r.title, 300),
      y: pubYear(r),
      l: lidx(r.lang),
      c: arr(r.sources).map(sidx).filter((n) => n >= 0).slice(0, 12),
      // every actor the report names, once each (ORKL lists a group once per catalogue); a cap of 6 used to drop the
      // rest, so an actor's record undercounted its reports (TraderTraitor: 21 of 34)
      a: [...new Set(arr(r.actors).map((x) => txt(x, 120)).filter(Boolean))].slice(0, 40),
    };
    if (read.has(sha)) row.k = 1;                       // a fact card is published for this report (cardPublished)
    if (looseStory.has(sha)) row.st = looseStory.get(sha);   // the report belongs to a live subject story
    return row;
  });
  // actor catalogue: name, up to 6 stated aliases, and the catalogue it comes from (source_id is the clean system
  // name — MISPGALAXY, ETDA, MITRE, Secureworks — whereas `source` is that prefixed onto the name).
  const acts = arr(actors).filter(Boolean)
    .map((a) => {
      const o = { n: clip(a.name, 160), al: arr(a.aliases).map((x) => txt(x, 120)).filter(Boolean).slice(0, 12), s: txt(a.source_id, 40) };
      // the ORKL actor id (its profile is https://orkl.eu/taEntry/<id>, rebuilt and host-checked by the page) and its tools
      const id = clip(a.id, 64); if (/^[0-9A-Za-z-]{1,64}$/.test(id)) o.i = id;
      const tl = arr(a.tools).map((x) => txt(x, 80)).filter(Boolean).slice(0, 20); if (tl.length) o.tl = tl;
      const st = actorStory.get(actorLinkKey(a)); if (st) o.st = st;   // the actor has a live story
      return o;
    })
    .filter((a) => a.n)
    .sort((a, b) => a.n.localeCompare(b.n));
  return { built_at: builtAt, reports_total: rows.length, actors_total: acts.length, sources, langs, reports: rows, actors: acts };
}

/* ---------- Library output: reviewed stories and read fact cards (values only), written to site/data ---------- */
// the one byline every Library story carries (the same constant as BY in scripts/lib/library-check.mjs, which a test pins)
export const STORY_BY = "CyberView AI (a Claude model)";
const SHA1 = /^[0-9a-f]{40}$/;
const SKEY = /^[A-Za-z0-9-]{1,70}$/;
const isObj = (x) => x && typeof x === "object" && !Array.isArray(x);
const FACT_KEYS = { actors: "a", sectors: "s", countries: "c", dates: "d", tools: "t", techniques: "q", cves: "v", figures: "g" };

/** Pure: is this card shown on the site? Only a read card whose CURRENT audit is the auditor's and passed (owner's ruling, final review
 *  2026-11-25: a summary is shown only after the audit has checked it against the report). */
export const cardPublished = (card) => isObj(card) && card.status === "read" && card.withdrawn !== true && isObj(card.audit) && card.audit.by === "auditor" && card.audit.ok === true;
/** Pure: a card as the site may show it, or null unless cardPublished. Values only: never a quote, hedge, audit, reason, tries or model. */
export function siteCard(card) {
  if (!cardPublished(card)) return null;
  const facts = isObj(card.facts) ? card.facts : {}, f = {};
  for (const [list, k] of Object.entries(FACT_KEYS)) {
    const items = arr(facts[list]).filter(isObj).map((x) => {
      const v = clip(x.v, 200); if (!v) return null;
      if (list === "actors") return { v, by: clip(x.by, 120) };
      if (list === "dates") return { v, what: clip(x.what, 120) };
      return v;
    }).filter(Boolean).slice(0, 20);
    if (items.length) f[k] = items;
  }
  const out = { sm: clip(card.summary, 600), k: txt(card.kind, 40), p: card.partial === true, f };
  if (isObj(card.subject) && txt(card.subject.name, 120)) out.su = { type: txt(card.subject.type, 20), name: txt(card.subject.name, 120) };
  return out;
}

const reportMap = (reports) => (reports instanceof Map ? reports : new Map(arr(reports).filter((r) => r && hex40(r.sha1)).map((r) => [String(r.sha1).toLowerCase(), r])));
const yearOf = (r) => { const m = String(r.file_date || r.created || "").match(/^(\d{4})/); return m && Number(m[1]) >= 1990 && Number(m[1]) <= 2100 ? m[1] : ""; };

/** Pure: a story file { live, next } as the site may show it, or null. Only `live`, only when reviewed and published or stale.
 *  Every cited sha1 must be a report in the library (it becomes a `src` entry); an unresolvable cite is dropped, and a sentence
 *  outside "takeaway" left with no cite stops the whole story (warn(message) names its key). */
export function siteStory(file, reports, warn = () => {}) {
  const live = file && file.live;
  if (!isObj(live) || !live.reviewed_at || !["published", "stale"].includes(live.status)) return null;
  const key = txt(live.key, 70), byHash = reportMap(reports), cited = [], seen = new Set(), sections = [];
  if (!SKEY.test(key)) return null;
  if (live.by !== STORY_BY) { warn(`orkl story ${key}: the byline is not "${STORY_BY}", so the story is not published`); return null; }
  for (const sec of arr(live.sections)) {
    if (!isObj(sec)) continue;
    const sentences = [];
    for (const sn of arr(sec.sentences)) {
      if (!isObj(sn)) continue;
      const t = clip(sn.t, 400); if (!t) continue;
      const cites = [];
      for (const c of arr(sn.cites).map((x) => String(x).toLowerCase())) {
        if (c === "catalogue") { if (!cites.includes(c)) cites.push(c); continue; }
        if (!SHA1.test(c) || !byHash.has(c)) continue;
        if (!cites.includes(c)) cites.push(c);
        if (!seen.has(c)) { seen.add(c); cited.push(c); }
      }
      if (!cites.length && sec.h !== "takeaway") { warn(`orkl story ${key}: a sentence in "${txt(sec.h, 20)}" has no source that resolves, so the story is not published`); return null; }
      sentences.push({ t, cites });
    }
    if (sentences.length) sections.push({ h: txt(sec.h, 20), sentences });
  }
  if (!sections.length) return null;
  const src = cited.map((sha) => { const r = byHash.get(sha); return { sha1: sha, title: clip(r.title, 300), authors: arr(r.authors).map((a) => txt(a, 120)).filter(Boolean).slice(0, 5), year: yearOf(r) }; });
  const out = { key, kind: txt(live.kind, 20), name: txt(live.name, 120), headline: clip(live.headline, 120), in_short: clip(live.in_short, 240), sections, by: STORY_BY, reviewed_at: txt(live.reviewed_at, 40), n: src.length, src };
  // the rules verify-build applies to library/stories.json (a key, a headline and a review time on every listed story) are enforced
  // here, so a story that would fail them is left out with a warning instead of stopping every deploy
  if (!out.headline) { warn(`orkl story ${key}: the headline is empty, so the story is not published`); return null; }
  if (!out.in_short) { warn(`orkl story ${key}: the in short line is empty, so the story is not published`); return null; }
  if (!out.reviewed_at) { warn(`orkl story ${key}: no review time, so the story is not published`); return null; }
  if (live.status === "stale") out.stale = true;
  return out;
}

/** Pure: the story list for the Library, newest review first. `published` is siteStory output. */
export function storyIndex(published) {
  return arr(published).filter(isObj)
    .map((s) => ({ key: s.key, kind: s.kind, name: s.name, headline: s.headline, in_short: s.in_short, reviewed_at: s.reviewed_at, n: s.n }))
    .sort((a, b) => String(b.reviewed_at).localeCompare(String(a.reviewed_at)) || a.key.localeCompare(b.key));
}

/** Pure: which actors and reports have a live story or a read card, for libraryIndex. liveKeys: keys of published stories. */
export function storyLinks(reports, actors, cards, liveKeys) {
  const read = new Set(), actorStory = new Map(), looseStory = new Map();
  for (const [sha, c] of cards) if (cardPublished(c)) read.add(sha);     // `k` on a row = this card is published (the same gate as siteCard)
  for (const s of actorSubjects(actors, reports, cards)) if (liveKeys.has(s.key)) actorStory.set(actorLinkKey({ id: s.actor.id, name: s.name }), s.key);
  for (const s of looseSubjects(reports, cards, actorIndex(actors))) if (liveKeys.has(s.key)) for (const sha of s.sha1s) looseStory.set(sha, s.key);
  return { read, actorStory, looseStory };
}

/** Remove what an earlier or crashed publish left in outDir (any pid, and the round-1 layout); if `library` is missing and exactly one
 *  `library.old-*` exists (a crash between the two renames) it is renamed back first. */
function tidyLibraryOutput(outDir, io) {
  const names = existsSync(outDir) ? readdirSync(outDir) : [];
  const olds = names.filter((n) => /^library\.old-/.test(n));
  if (!names.includes("library") && olds.length === 1) { io.renameSync(join(outDir, olds[0]), join(outDir, "library")); }
  for (const n of readdirSync(outDir)) if (/^library\.(tmp|old)-/.test(n) || /^orkl-(cards|stories)(\.|$)/.test(n)) io.rmSync(join(outDir, n), { recursive: true, force: true });
}

/** Write the Library's reviewed stories and read cards into ONE folder, outDir/library (site/data/library): cards/<xx>.json,
 *  stories/<key>.json and stories.json (the story index). Everything is built in memory, written into library.tmp-<pid>, then swapped
 *  in by rename (library -> library.old-<pid>, tmp -> library, old removed), so a failure leaves the previous folder untouched (and a
 *  warn() message), never a partial site. A story that cannot be published is a warn() message too. `io` (writeFileSync, renameSync,
 *  rmSync, mkdirSync) and `linksFn` are injectable for tests. Returns the counts and the links libraryIndex needs. */
export function writeLibrarySite({ reports, actors, cards, stories, outDir, builtAt = "", warn = () => {}, io = {}, linksFn = storyLinks }) {
  const fsx = { writeFileSync, renameSync, rmSync, mkdirSync, ...io }, shards = {}, published = [];
  const cardMap = cards instanceof Map ? cards : new Map();
  for (const [sha, c] of cardMap) {
    const o = SHA1.test(sha) ? siteCard(c) : null;
    if (o) (shards[shardOf(sha)] || (shards[shardOf(sha)] = {}))[sha] = o;
  }
  for (const [key, file] of stories instanceof Map ? stories : new Map()) {
    try { const s = siteStory(file, reports, warn); if (s && s.key === key) published.push(s); } catch (e) { warn(`orkl story ${txt(key, 70)}: ${txt(e && e.message, 80)}`); }
  }
  const counts = { cards_read: Object.values(shards).reduce((n, sh) => n + Object.keys(sh).length, 0), stories: published.length };
  const target = join(outDir, "library"), tmp = join(outDir, `library.tmp-${process.pid}`), old = join(outDir, `library.old-${process.pid}`);
  try {
    mkdirSync(outDir, { recursive: true });
    tidyLibraryOutput(outDir, fsx);
    fsx.mkdirSync(join(tmp, "cards"), { recursive: true }); fsx.mkdirSync(join(tmp, "stories"), { recursive: true });
    for (const [sh, obj] of Object.entries(shards)) fsx.writeFileSync(join(tmp, "cards", `${sh}.json`), JSON.stringify(obj));
    for (const s of published) fsx.writeFileSync(join(tmp, "stories", `${s.key}.json`), JSON.stringify(s));
    fsx.writeFileSync(join(tmp, "stories.json"), JSON.stringify({ built_at: builtAt, stories: storyIndex(published) }));
    const had = existsSync(target);
    if (had) fsx.renameSync(target, old);
    try { fsx.renameSync(tmp, target); }
    catch (e) {
      if (had) {
        try { fsx.renameSync(old, target); } catch { throw new Error(`${txt(e && e.message, 60)}; the previous Library output could not be restored and is missing`); }
      }
      throw e;
    }
    try { fsx.rmSync(old, { recursive: true, force: true }); } catch {}
  } catch (e) {
    for (const d of [tmp, old]) { try { if (d === tmp || existsSync(target)) fsx.rmSync(d, { recursive: true, force: true }); } catch {} }
    warn(`orkl library output: ${txt(e && e.message, 140)}`);
    return { counts: {}, links: {} };
  }
  let links = {};
  try { links = linksFn(arr(reports), arr(actors), cardMap, new Set(published.map((s) => s.key))); } catch (e) { warn(`orkl links: ${txt(e && e.message, 80)}`); }
  return { counts, links };
}

/** The whole Library site step: stories and cards, then the browsable index. A failure in the new story/card code is a warning and
 *  leaves the existing index unchanged in shape; a failure writing the index is a warning too. Loaders are injected (see build.mjs). */
export function publishLibrary({ reports, actors, loadCards, loadStories, outDir, builtAt = "", warn = () => {}, io = {} }) {
  let lib = { counts: {}, links: {} };
  try {
    const badCards = [], badStories = [];
    const cards = loadCards(badCards), stories = loadStories(badStories);
    for (const sh of badCards) warn(`orkl/cards/${sh}.json: not readable, its fact cards are left out`);
    for (const k of badStories) warn(`orkl/stories/${k}.json: not readable, the story is left out`);
    lib = writeLibrarySite({ reports, actors, cards, stories, outDir, builtAt, warn, io });
  } catch (e) { warn(`orkl stories and cards: ${txt(e && e.message, 80)}`); }
  let indexed = false;
  try {
    if (arr(reports).length) { (io.writeFileSync || writeFileSync)(join(outDir, "orkl-index.json"), JSON.stringify(libraryIndex(reports, actors, builtAt, lib.links || {}))); indexed = true; }
  } catch (e) { warn(`orkl index: ${txt(e && e.message, 80)}`); }
  return { counts: lib.counts || {}, indexed };
}

/* ---------- collection ---------- */
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function api(path, params = {}) {
  const u = new URL(API + path);
  for (const [k, v] of Object.entries(params)) u.searchParams.set(k, String(v));
  return get(u.href, { timeoutMs: 30000, retries: 3, delayMs: 2000, key: "orkl.eu" });
}

/** Read the whole sharded report store back from disk into a flat array. */
function loadReports() {
  const store = {};
  if (existsSync(REPORTS_DIR)) for (const f of readdirSync(REPORTS_DIR)) if (/^[0-9a-f]{2}\.json$/.test(f)) store[f.slice(0, 2)] = readJson(join(REPORTS_DIR, f), {}) || {};
  return store;
}
const flat = (store) => Object.values(store || {}).flatMap((shard) => Object.values(shard || {}));

/** Load the whole stored library off the data branch for the build: a flat array of report records plus the actors. */
export function loadLibrary() {
  const reports = flat(loadReports());
  const raw = existsSync(ACTORS_FILE) ? (readJson(ACTORS_FILE, {}) || {}) : {};
  const actors = Array.isArray(raw) ? raw : Object.values(raw);
  return { reports, actors };
}

/** Page through an ORKL list endpoint; stopWhen(record) ends the walk early (for incremental runs). */
async function pageAll(path, { limit = 100, max = Infinity, stopWhen = null, extra = {} } = {}) {
  const out = []; let offset = 0;
  for (;;) {
    const body = await api(path, { limit, offset, order_by: "created_at", order: "desc", ...extra });
    const rows = Array.isArray(body) ? body : (body && Array.isArray(body.data) ? body.data : []);
    if (!rows.length) break;
    for (const row of rows) { if (stopWhen && stopWhen(row)) return { out, stopped: true }; out.push(row); if (out.length >= max) return { out, stopped: false }; }
    offset += rows.length;
    if (rows.length < limit) break;
    await sleep(250);
  }
  return { out, stopped: false };
}

async function libraryVersion() {
  try { const v = await api("/library/version"); return Number((v && (v.data && v.data.id)) || (v && v.id) || 0) || 0; } catch { return 0; }
}

export async function collect({ full = false, dry = false, max = Infinity } = {}) {
  const at = nowIso();
  const prevState = readJson(STATE_FILE, {}) || {};
  const health = {};
  let reportStore = loadReports(), actorStore = readJson(ACTORS_FILE, {}) || {};
  const backfillDone = prevState.backfill_done === true && !full;

  // Threat actors: small (~2k), always refreshed in full.
  let actors = Object.values(actorStore);
  try {
    const { out } = await pageAll("/ta/entries", { limit: 100 });
    const clean = out.map(cleanActor).filter(Boolean);
    if (clean.length) { actorStore = mergeActors(actorStore, clean); actors = Object.values(actorStore); }
    health.actors = { ok: true, fetched: out.length, total: actors.length };
    console.log(`orkl actors: ok, ${out.length} fetched, ${actors.length} on file`);
  } catch (e) { health.actors = { ok: false, error: String((e && e.code) || (e && e.message) || "failed").slice(0, 160) }; console.log(`orkl actors: FAILED (${health.actors.error})`); }

  // Library reports: full backfill the first time (newest first), then incremental — stop at the first sha1 already on file.
  const have = new Set(flat(reportStore).map((r) => r.sha1));
  try {
    const { out, stopped } = await pageAll("/library/entries", {
      limit: 100, max,
      stopWhen: backfillDone ? (row) => have.has(String(row && row.sha1_hash || "").toLowerCase()) : null,
    });
    const clean = out.map(cleanReport).filter(Boolean);
    reportStore = mergeReports(reportStore, clean);
    const added = clean.filter((r) => !have.has(r.sha1)).length;
    health.reports = { ok: true, fetched: out.length, added, total: flat(reportStore).length, mode: backfillDone ? "incremental" : "backfill", stopped };
    console.log(`orkl reports: ok, ${out.length} fetched, ${added} new, ${flat(reportStore).length} on file (${health.reports.mode}${stopped ? ", reached known" : ""})`);
  } catch (e) { health.reports = { ok: false, error: String((e && e.code) || (e && e.message) || "failed").slice(0, 160) }; console.log(`orkl reports: FAILED (${health.reports.error})`); }

  const libVersion = (await libraryVersion()) || Number(prevState.library_version) || 0;
  // backfill is "done" once a reports pass completed without the per-run cap cutting it short
  const didBackfill = backfillDone || (health.reports && health.reports.ok && !(max < Infinity));
  const state = summarize(flat(reportStore), Object.values(actorStore), { at, library_version: libVersion, health, backfill_done: didBackfill });

  if (dry) { console.log(`DRY: ${state.reports_total} reports, ${state.actors_total} actors; nothing written.`); return { state, reportStore, actorStore }; }
  if (!(health.reports && health.reports.ok) && !(health.actors && health.actors.ok) && (prevState.reports_total || prevState.actors_total)) {
    console.log("orkl: both endpoints failed; the last copy is kept unchanged."); return null;
  }
  for (const [sh, obj] of Object.entries(reportStore)) writeJson(join(REPORTS_DIR, `${sh}.json`), obj);
  writeJson(ACTORS_FILE, actorStore);
  writeJson(STATE_FILE, state);
  const st = readStatus(); st.last_orkl_at = at; writeJson(join(DATA, "status.json"), st);
  console.log(`orkl: ${state.reports_total} reports, ${state.actors_total} actors on file (library version ${libVersion}).`);
  return { state, reportStore, actorStore };
}

function status() {
  const s = readJson(STATE_FILE, null);
  if (!s) { console.log("orkl: no data/orkl/state.json yet."); return; }
  console.log(`ORKL library, updated ${s.updated_at}: ${s.reports_total} reports, ${s.actors_total} actors (version ${s.library_version}, backfill ${s.backfill_done ? "done" : "pending"}).`);
  for (const [k, h] of Object.entries(s.health || {})) console.log(`  ${k.padEnd(8)} ${h.ok ? "ok    " : "FAILED"} ${h.error || ""}`);
}

async function main() {
  const cmd = process.argv[2] && !process.argv[2].startsWith("--") ? process.argv[2] : "collect";
  if (cmd === "status") return status();
  if (cmd !== "collect") { console.error("usage: orkl.mjs [collect] [--full] [--dry] [--max N] | status"); process.exit(1); }
  const mi = process.argv.indexOf("--max");
  const max = mi >= 0 && process.argv[mi + 1] ? Number(process.argv[mi + 1]) : Infinity;
  await collect({ full: process.argv.includes("--full"), dry: process.argv.includes("--dry"), max });
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
