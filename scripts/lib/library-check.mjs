// Pure checks for the Library's fact cards and stories (no I/O, no model calls).
// A card's facts are only kept if each quote is found in the report text; a story sentence is only kept if what it names is held by a card it cites.
import { NOCODE, figuresIn } from "./validate.mjs";
import { txt, clip } from "../orkl.mjs";

export const BY = "CyberView AI (a Claude model)";
export const KINDS = ["actor-campaign", "malware-analysis", "vulnerability", "incident", "overview", "not-a-threat-report"];
export const SECTIONS = ["who", "targets", "methods", "operations", "takeaway"];
export const QUOTE_MAX = 160;

const LISTS = ["actors", "sectors", "countries", "dates", "tools", "techniques", "cves", "figures"];
const CARD_STATUS = ["read", "no-text", "unread"];
const STORY_STATUS = ["draft", "published", "stale", "rejected", "parked"];
const SUBJECT_TYPES = ["malware", "campaign", "vulnerability", "incident"];
const LIST_MAX = 20;
const SHA1 = /^[0-9a-f]{40}$/;
const CVE = /^CVE-\d{4}-\d{4,7}$/;
const STATE_WORDS = /state[- ]sponsored|backed by|linked to|works for|intelligence|military|government/i;
const HEDGE_WORDS = /according to|assess|attribut|says|said|reports?|tracks|believes?/i;
const isObj = (x) => x && typeof x === "object" && !Array.isArray(x);

/** Text as compared for quotes: PDF noise (soft hyphens, line-break hyphens, curly quotes, runs of space) removed. */
export function normText(s) {
  return String(s == null ? "" : s)
    .normalize("NFKC")
    .replace(/[‘’‚‛′]/g, "'")
    .replace(/[“”„‟″]/g, '"')
    .replace(/­/g, "")
    .replace(/-[ \t]*\r?\n[ \t]*/g, "")
    .toLowerCase()
    .replace(/\s+/g, " ")
    .trim();
}

/** True when the quote (at least 12 characters once normalised) appears in the text. */
export function quoteInText(quote, text) {
  const q = normText(quote);
  return q.length >= 12 && normText(text).includes(q);
}

const cleanFacts = (list, extra) => (Array.isArray(list) ? list : []).filter(isObj).slice(0, LIST_MAX).map((f) => {
  const o = { v: txt(f.v, 200), q: txt(f.q, 400) };
  for (const k of extra) o[k] = txt(f[k], 120);
  return o;
}).filter((f) => f.v);

/** A card as stored: every string clipped, unknown keys dropped, lists capped. null when the shape is wrong. */
export function cleanCard(raw, sha1) {
  if (!isObj(raw)) return null;
  const id = String(sha1 || "").toLowerCase();
  if (!SHA1.test(id) || !CARD_STATUS.includes(raw.status)) return null;
  const f = isObj(raw.facts) ? raw.facts : {};
  const extra = { actors: ["by"], dates: ["what"] };
  const facts = {};
  for (const k of LISTS) facts[k] = cleanFacts(f[k], extra[k] || []);
  const s = isObj(raw.subject) && SUBJECT_TYPES.includes(raw.subject.type) && txt(raw.subject.name, 120)
    ? { type: raw.subject.type, name: txt(raw.subject.name, 120) } : null;
  const card = {
    sha1: id, status: raw.status, partial: raw.partial === true, read_at: txt(raw.read_at, 40), model: txt(raw.model, 60),
    summary: clip(raw.summary, 600), kind: txt(raw.kind, 40), facts, subject: s,
    hedges: (Array.isArray(raw.hedges) ? raw.hedges : []).map((h) => clip(h, 200)).filter(Boolean).slice(0, 8),
  };
  if (raw.reason) card.reason = clip(raw.reason, 200);
  if (isObj(raw.audit)) card.audit = { at: txt(raw.audit.at, 40), ok: raw.audit.ok === true, note: clip(raw.audit.note, 300) };
  return card;
}

const hasCode = (...parts) => parts.some((p) => NOCODE.test(String(p == null ? "" : p)));

/** Why a card cannot be kept (empty = pass). `text` is the report text, in memory only. */
export function cardProblems(card, text) {
  const p = [];
  const c = isObj(card) ? card : {};
  const facts = isObj(c.facts) ? c.facts : {};
  if (!c.summary || !String(c.summary).trim()) p.push("empty-summary");
  if (!KINDS.includes(c.kind)) p.push("bad-kind");
  const strs = [c.summary, c.subject && c.subject.name, ...(c.hedges || [])];
  for (const k of LISTS) {
    (Array.isArray(facts[k]) ? facts[k] : []).forEach((f, i) => {
      const at = `${k}[${i}]`, v = String(f.v == null ? "" : f.v), q = String(f.q == null ? "" : f.q);
      strs.push(v, q);
      if (q.length > QUOTE_MAX) p.push(`quote-too-long: ${at}`);
      if (!quoteInText(q, text)) p.push(`quote-not-in-text: ${at}`);
      if (k === "dates") {
        const y = v.match(/\b\d{4}\b/);
        if (y && !normText(q).includes(y[0])) p.push(`value-not-in-quote: ${at}`);
      } else if (["actors", "tools", "cves", "figures"].includes(k) && !normText(q).includes(normText(v))) p.push(`value-not-in-quote: ${at}`);
      if (k === "cves" && !CVE.test(v)) p.push(`cve-malformed: ${at}`);
    });
  }
  if (hasCode(...strs)) p.push("code");
  return p;
}

/** A story as stored. null when the shape is wrong. */
export function cleanStory(raw) {
  if (!isObj(raw)) return null;
  const key = txt(raw.key, 120);
  if (!key || !["actor", "subject"].includes(raw.kind) || !STORY_STATUS.includes(raw.status)) return null;
  const sections = (Array.isArray(raw.sections) ? raw.sections : []).filter((s) => isObj(s) && SECTIONS.includes(s.h)).slice(0, SECTIONS.length).map((s) => ({
    h: s.h,
    sentences: (Array.isArray(s.sentences) ? s.sentences : []).filter(isObj).slice(0, 12).map((x) => ({
      t: clip(x.t, 400),
      cites: (Array.isArray(x.cites) ? x.cites : []).map((c) => String(c).toLowerCase()).filter((c) => SHA1.test(c) || c === "catalogue").slice(0, 8),
    })).filter((x) => x.t),
  }));
  const story = {
    key, kind: raw.kind, name: txt(raw.name, 120), headline: clip(raw.headline, 120), in_short: clip(raw.in_short, 240), sections,
    status: raw.status, based_on: txt(raw.based_on, 80), tries: Number.isFinite(raw.tries) ? Math.max(0, Math.min(99, Math.floor(raw.tries))) : 0,
    by: txt(raw.by, 80), written_at: txt(raw.written_at, 40), writer_model: txt(raw.writer_model, 60),
  };
  if (raw.reviewed_at) story.reviewed_at = txt(raw.reviewed_at, 40);
  if (raw.reviewer_model) story.reviewer_model = txt(raw.reviewer_model, 60);
  return story;
}

const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const holds = (normSentence, term) => {
  const t = normText(term);
  return t.length >= 3 && new RegExp(`(?<![a-z0-9])${esc(t)}(?![a-z0-9])`).test(normSentence);
};
const allFacts = (card) => LISTS.flatMap((k) => (isObj(card && card.facts) && Array.isArray(card.facts[k]) ? card.facts[k] : []));

/** Why a story cannot be published (empty = pass). `cards` maps sha1 to Card; `actor` is the catalogue entry for an actor story, or null. */
export function storyProblems(story, cards, actor) {
  const p = [];
  const s = isObj(story) ? story : {};
  const sections = Array.isArray(s.sections) ? s.sections : [];
  const cardMap = cards instanceof Map ? cards : new Map();
  if (s.by !== BY) p.push("no-byline");
  if (!sections.length) p.push("missing-section");

  const catalogue = actor ? [actor.name, ...(actor.aliases || []), ...(actor.tools || [])].filter((x) => typeof x === "string" && x.trim()) : [];
  const vocab = new Set();
  const countries = new Set();
  for (const c of cardMap.values()) {
    for (const f of allFacts(c)) if (f && f.v) vocab.add(String(f.v));
    for (const f of (c && c.facts && c.facts.countries) || []) if (f && f.v) countries.add(String(f.v));
  }
  catalogue.forEach((t) => vocab.add(t));

  const citedAll = new Set();
  let coded = hasCode(s.headline, s.in_short);
  for (const sec of sections) {
    for (const [i, sn] of (Array.isArray(sec.sentences) ? sec.sentences : []).entries()) {
      const t = String(sn.t == null ? "" : sn.t), cites = Array.isArray(sn.cites) ? sn.cites : [];
      const at = `${sec.h}[${i}]`;
      if (hasCode(t)) coded = true;
      if (!cites.length && sec.h !== "takeaway") p.push(`uncited: ${at}`);
      const held = []; // cards cited
      let useCatalogue = false;
      for (const c of cites) {
        if (c === "catalogue") { if (!actor) p.push(`bad-cite: ${at} catalogue`); else useCatalogue = true; }
        else if (cardMap.has(c)) { held.push(cardMap.get(c)); citedAll.add(c); }
        else p.push(`bad-cite: ${at} ${String(c).slice(0, 12)}`);
      }
      const cf = held.flatMap(allFacts);
      const cardHas = (term) => cf.some((f) => normText(f.v) === normText(term) || holds(normText(f.v), term) || holds(normText(term), f.v));
      const catHas = (term) => useCatalogue && catalogue.some((c) => normText(c) === normText(term));
      const bad = [];
      const bare = t.replace(CVE_ANY, " ");
      for (const m of t.matchAll(CVE_ANY)) if (!cf.some((f) => normText(f.v) === normText(m[0]))) bad.push(m[0]);
      for (const m of bare.matchAll(/\b(?:19|20)\d{2}\b/g)) {
        const ok = held.some((c) => ((c.facts && c.facts.dates) || []).some((d) => `${d.v} ${d.q}`.includes(m[0])));
        if (!ok) bad.push(m[0]);
      }
      const figs = figuresIn(t);
      const heldFigs = cf.flatMap((f) => figuresIn(f.v).map((x) => x.value));
      for (const f of figs) if (!heldFigs.includes(f.value)) bad.push(f.raw);
      const ns = normText(t);
      for (const term of vocab) {
        if (!holds(ns, term) || CVE_EXACT.test(term) || /^\d+$/.test(term)) continue;
        if (!cardHas(term) && !catHas(term)) bad.push(term);
      }
      if (bad.length) p.push(`unbacked: ${at} ${[...new Set(bad)].slice(0, 4).join(", ")}`);
      if (STATE_WORDS.test(t) && !HEDGE_WORDS.test(t) && [...countries].some((c) => holds(ns, c))) p.push(`bare-attribution: ${at}`);
    }
  }
  if (coded) p.push("code");
  if (s.kind === "actor" && citedAll.size >= 2) {
    const have = new Set(sections.filter((x) => Array.isArray(x.sentences) && x.sentences.length).map((x) => x.h));
    for (const h of ["who", "targets", "methods"]) if (!have.has(h)) p.push(`missing-section: ${h}`);
  }
  return p;
}
const CVE_ANY = /CVE-\d{4}-\d{4,7}/gi;
const CVE_EXACT = /^CVE-\d{4}-\d{4,7}$/i;
