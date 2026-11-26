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
const STORY_STATUS = ["draft", "published", "stale", "rejected", "parked", "withdrawn"];
export const STALE_REASONS = ["card-wrong", "new-report"];
const SUBJECT_TYPES = ["malware", "campaign", "vulnerability", "incident"];
const LIST_MAX = 20;
const SHA1 = /^[0-9a-f]{40}$/;
const CVE = /^CVE-\d{4}-\d{4,7}$/;
const STATE_WORDS = /state[- ]sponsored|backed by|linked to|works for|intelligence|military|government/i;
const HEDGE_WORDS = /according to|assess|attribut|says|said|reports?|tracks|believes?/i;
const isObj = (x) => x && typeof x === "object" && !Array.isArray(x);

const DASHES = /[‐‑‒–—−]/g;
const fold = (s) => String(s == null ? "" : s).replace(DASHES, "-");
const norm = (s, join) => fold(String(s == null ? "" : s).normalize("NFKC"))
  .replace(/[‘’‚‛′]/g, "'")
  .replace(/[“”„‟″]/g, '"')
  .replace(/­/g, "")
  .replace(/-[ \t]*\r?\n[ \t]*/g, join ? "" : "-")
  .toLowerCase()
  .replace(/\s+/g, " ")
  .trim();

/** Text as compared for quotes: PDF noise (soft hyphens, line-break hyphens, curly quotes, typographic dashes, runs of space) removed. */
export const normText = (s) => norm(s, true);

/** True when the quote (at least 12 characters once normalised) appears in the text; a hyphen at a line break counts as joined or as a real hyphen. */
export function quoteInText(quote, text) {
  return [true, false].some((join) => {
    const q = norm(quote, join);
    return q.length >= 12 && norm(text, join).includes(q);
  });
}

const cleanFacts = (list, extra) => (Array.isArray(list) ? list : []).filter(isObj).slice(0, LIST_MAX).map((f) => {
  const o = { v: txt(f.v, 200), q: txt(f.q, 400) };
  for (const k of extra) o[k] = txt(f[k], 120);
  return o;
}).filter((f) => f.v);

const AUDIT_BY = ["auditor", "reviewer"];
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
  // fields later stages read: the reader's tries, the one no-text retry, and the owner's withdrawal (library-review.mjs withdraw)
  if (Number.isFinite(raw.tries)) card.tries = Math.max(0, Math.min(9, Math.floor(raw.tries)));
  if (raw.retried === true) card.retried = true;
  if (raw.withdrawn === true) { card.withdrawn = true; card.withdrawn_at = txt(raw.withdrawn_at, 40); card.withdrawn_reason = clip(raw.withdrawn_reason, 200); }
  const aud = (a) => { const o = { at: txt(a.at, 40), ok: a.ok === true, note: clip(a.note, 160) }; if (AUDIT_BY.includes(a.by)) o.by = a.by; return o; };
  if (isObj(raw.audit)) card.audit = aud(raw.audit);
  if (Array.isArray(raw.audit_history) && raw.audit_history.length) card.audit_history = raw.audit_history.filter(isObj).map(aud).slice(-5);
  return card;
}

const hasCode = (...parts) => parts.some((p) => NOCODE.test(String(p == null ? "" : p)));

// A link, a domain-like token (also defanged, evil[.]com) or an email address. The summary and the fact values are shown to visitors,
// and indicators are linked, never copied: none of these may sit in them. Top-level domains are matched in lower case only, so
// framework names such as ASP.NET are not taken for a domain; words like "e.g." and "U.S." are not.
const TLDS = "com|net|org|info|biz|io|co|xyz|top|site|online|club|shop|live|app|dev|cloud|ru|cn|su|ir|kp|uk|de|fr|jp|kr|tk|ml|ga|cf|gq|pw|cc|ws|onion|gov|edu|mil|int|ca|au|br|nl|pl|ua|by|kz|tw|hk|vn|tv|eu|ch|se|es|ro|tr|il|sg";
const LINKISH = [
  /\b(?:https?|hxxps?|ftp|sftp):\/\//i,
  /\bwww\[?\.\]?[a-z0-9-]+/i,
  /[A-Za-z0-9._%+-]+(?:@|\[at\]|\[@\])[A-Za-z0-9-]+(?:\[?\.\]?[A-Za-z0-9-]+)*\[?\.\]?[A-Za-z]{2,}/,
  new RegExp(`(?<![A-Za-z0-9-])[A-Za-z0-9][A-Za-z0-9-]*(?:(?:\\[\\.\\]|\\(\\.\\)|\\.)[A-Za-z0-9-]+)*(?:\\[\\.\\]|\\(\\.\\)|\\.)(?:${TLDS})(?![A-Za-z0-9-])`),
];
/** True when the text holds a URL, a domain-like token or an email address. */
export const hasLink = (s) => { const t = String(s == null ? "" : s); return LINKISH.some((re) => re.test(t)); };

/** Why a card cannot be kept (empty = pass). `text` is the report text, in memory only. */
export function cardProblems(card, text) {
  const p = [];
  const c = isObj(card) ? card : {};
  const facts = isObj(c.facts) ? c.facts : {};
  if (!c.summary || !String(c.summary).trim()) p.push("empty-summary");
  if (!KINDS.includes(c.kind)) p.push("bad-kind");
  const strs = [c.summary, c.subject && c.subject.name, ...(Array.isArray(c.hedges) ? c.hedges : [])];
  for (const k of LISTS) {
    (Array.isArray(facts[k]) ? facts[k] : []).forEach((f, i) => {
      if (!isObj(f)) return;
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
  // what the site may show: the summary, the subject's name and every fact value (quotes and hedges are never shown)
  const shown = [c.summary, c.subject && c.subject.name, ...LISTS.flatMap((k) => (Array.isArray(facts[k]) ? facts[k] : []).filter(isObj).flatMap((f) => [f.v, f.by, f.what]))];
  if (shown.some(hasLink)) p.push("link-in-text");
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
  if (Array.isArray(raw.reasons) && raw.reasons.length) story.reasons = raw.reasons.slice(0, 10).map((x) => txt(x, 40)).filter(Boolean);
  if (raw.corrected_by) story.corrected_by = txt(raw.corrected_by, 60);
  if (Number.isFinite(raw.corrections) && raw.corrections > 0) story.corrections = Math.min(9, Math.floor(raw.corrections));
  if (raw.written_run) story.written_run = txt(raw.written_run, 40);
  // why a live story is stale: "card-wrong" (a card it cites was found wrong: the site takes it down) or "new-report" (new reports arrived)
  if (raw.status === "stale" && STALE_REASONS.includes(raw.stale_reason)) story.stale_reason = raw.stale_reason;
  if (raw.status === "withdrawn") { story.withdrawn_at = txt(raw.withdrawn_at, 40); story.withdrawn_reason = clip(raw.withdrawn_reason, 200); }
  return story;
}

const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const holds = (normSentence, term) => {
  const t = normText(term);
  return t.length >= 3 && new RegExp(`(?<![a-z0-9])${esc(t)}(?![a-z0-9])`).test(normSentence);
};
const allFacts = (card) => LISTS.flatMap((k) => (isObj(card && card.facts) && Array.isArray(card.facts[k]) ? card.facts[k] : [])).filter((f) => isObj(f) && f.v);

// Countries and what people call their governments: any member of a group stands for the whole group.
const COUNTRY_GROUPS = [
  ["russia", "russian"], ["china", "chinese", "prc"], ["iran", "iranian"], ["north korea", "north korean", "dprk", "d.p.r.k."],
  ["pakistan", "pakistani"], ["india", "indian"], ["vietnam", "vietnamese"], ["turkey", "turkish", "turkiye"], ["israel", "israeli"],
  ["belarus", "belarusian"], ["ukraine", "ukrainian"], ["syria", "syrian"], ["lebanon", "lebanese"],
  ["united states", "american", "usa", "u.s.", "u.s.a."], ["united kingdom", "british", "britain"],
  ["germany", "german"], ["poland", "polish"], ["spain", "spanish"], ["france", "french"], ["netherlands", "dutch"],
  ["saudi arabia", "saudi"], ["united arab emirates", "emirati", "uae"], ["south korea", "south korean"], ["taiwan", "taiwanese"], ["myanmar", "burmese"],
];
const CODE_GROUP = { uk: "united kingdom", us: "united states", usa: "united states" };
const CODES = { "united states": ["US"], "united kingdom": ["UK"] };
/** Words (lower-case, whole-word) and 2-letter codes (case-sensitive) that name a country in a sentence. */
function countryNames(country) {
  const n = normText(country);
  const g = COUNTRY_GROUPS.find((x) => x.includes(CODE_GROUP[n] || n));
  const words = new Set(g || [n]), codes = new Set(g ? CODES[g[0]] || [] : []);
  if (/^[A-Z]{2}$/.test(String(country).trim())) { codes.add(String(country).trim()); words.delete(n); }
  if (!g) { // generic stem rule: Peru/Peruvian is not guessed, but Chad -> Chadian, Cuba -> Cuban, Japan -> Japanese
    const base = n.replace(/[aeiy]$/, "");
    if (base.length >= 3 && !words.has(n + "x")) for (const suf of ["ian", "an", "ese", "i", "ish"]) words.add(base + suf);
  }
  return { words: [...words], codes: [...codes] };
}
const mentions = (rawText, country) => {
  const { words, codes } = countryNames(country), ns = normText(rawText);
  return words.some((w) => holds(ns, w)) || codes.some((c) => new RegExp(`(?<![A-Za-z0-9])${esc(c)}(?![A-Za-z0-9])`).test(rawText));
};

/** Why a story cannot be published (empty = pass). `cards` maps sha1 to Card; `actor` is the catalogue entry for an actor story, or null. */
export function storyProblems(story, cards, actor) {
  const p = [];
  const s = isObj(story) ? story : {};
  const sections = (Array.isArray(s.sections) ? s.sections : []).filter(isObj);
  const filled = sections.filter((x) => (Array.isArray(x.sentences) ? x.sentences : []).some(isObj));
  const cardMap = cards instanceof Map ? cards : new Map();
  if (s.by !== BY) p.push("no-byline");
  if (!filled.length) p.push("missing-section");
  // the site lists a story by its headline and in_short: either one empty once cleaned would fail verify-build and stop the deploy
  if (!clip(s.headline, 120)) p.push("no-headline");
  if (!clip(s.in_short, 240)) p.push("no-in-short");

  const catalogue = actor ? [actor.name, ...(actor.aliases || []), ...(actor.tools || [])].filter((x) => typeof x === "string" && x.trim()) : [];
  const vocab = new Set();
  const countries = new Set();
  for (const c of cardMap.values()) {
    for (const f of allFacts(c)) vocab.add(String(f.v));
    for (const f of (isObj(c) && isObj(c.facts) && Array.isArray(c.facts.countries) ? c.facts.countries : [])) if (isObj(f) && f.v) countries.add(String(f.v));
  }
  catalogue.forEach((t) => vocab.add(t));

  // What a piece of text names that none of the given cards (or the catalogue, when allowed) holds.
  const unbackedIn = (t, held, useCatalogue) => {
    const text = fold(t), cf = held.flatMap(allFacts), bad = [];
    const cardHas = (term) => cf.some((f) => normText(f.v) === normText(term) || holds(normText(f.v), term) || holds(normText(term), f.v));
    const catHas = (term) => useCatalogue && catalogue.some((c) => normText(c) === normText(term));
    for (const m of text.matchAll(CVE_ANY)) if (!cf.some((f) => normText(f.v) === normText(m[0]))) bad.push(m[0]);
    const figureTexts = held.flatMap((c) => (isObj(c.facts) && Array.isArray(c.facts.figures) ? c.facts.figures : [])).filter(isObj).map((f) => fold(f.v).trim()).filter((v) => /\d/.test(v));
    // a held figure's own number is not a year: mask each whole occurrence of the figure, then check what is left
    let rest = text.replace(CVE_ANY, " ");
    for (const v of figureTexts) rest = rest.replace(new RegExp(`(?<![\\w.,])${esc(v).replace(/\s+/g, "\\s+")}(?![\\w]|,\\d)`, "gi"), " ");
    for (const m of rest.matchAll(/\b(?:19|20)\d{2}\b/g)) {
      const inDates = held.some((c) => (isObj(c.facts) && Array.isArray(c.facts.dates) ? c.facts.dates : []).some((d) => isObj(d) && `${d.v} ${d.q}`.includes(m[0])));
      if (!inDates) bad.push(m[0]);
    }
    const heldFigs = cf.flatMap((f) => figuresIn(f.v).map((x) => x.value));
    for (const f of figuresIn(text)) if (!heldFigs.includes(f.value)) bad.push(f.raw);
    const ns = normText(text);
    for (const term of vocab) {
      if (!holds(ns, term) || CVE_EXACT.test(term) || /^\d+$/.test(term)) continue;
      if (!cardHas(term) && !catHas(term)) bad.push(term);
    }
    return [...new Set(bad)].slice(0, 4);
  };
  const bareAttribution = (t) => STATE_WORDS.test(t) && !HEDGE_WORDS.test(t) && [...countries].some((c) => mentions(t, c));

  const citedAll = new Set();
  let anyCatalogue = false, coded = hasCode(s.headline, s.in_short);
  for (const sec of sections) {
    for (const [i, sn] of (Array.isArray(sec.sentences) ? sec.sentences : []).entries()) {
      if (!isObj(sn)) continue;
      const t = String(sn.t == null ? "" : sn.t), cites = Array.isArray(sn.cites) ? sn.cites : [];
      const at = `${sec.h}[${i}]`;
      if (hasCode(t)) coded = true;
      if (!cites.length && sec.h !== "takeaway") p.push(`uncited: ${at}`);
      const held = [];
      let useCatalogue = false;
      for (const c of cites) {
        if (c === "catalogue") { if (!actor) p.push(`bad-cite: ${at} catalogue`); else useCatalogue = anyCatalogue = true; }
        else if (typeof c === "string" && isObj(cardMap.get(c))) { held.push(cardMap.get(c)); citedAll.add(c); }
        else p.push(`bad-cite: ${at} ${String(c).slice(0, 12)}`);
      }
      const bad = unbackedIn(t, held, useCatalogue);
      if (bad.length) p.push(`unbacked: ${at} ${bad.join(", ")}`);
      if (bareAttribution(t)) p.push(`bare-attribution: ${at}`);
    }
  }
  // headline and in_short rest on every card the story cites, and on the catalogue when any sentence cites it
  const union = [...citedAll].map((c) => cardMap.get(c));
  for (const field of ["headline", "in_short"]) {
    const t = String(s[field] == null ? "" : s[field]);
    const bad = unbackedIn(t, union, anyCatalogue);
    if (bad.length) p.push(`unbacked: ${field} ${bad.join(", ")}`);
    if (bareAttribution(t)) p.push(`bare-attribution: ${field}`);
  }
  if (coded) p.push("code");
  if (s.kind === "actor" && citedAll.size >= 2) {
    const have = new Set(filled.map((x) => x.h));
    for (const h of ["who", "targets", "methods"]) if (!have.has(h)) p.push(`missing-section: ${h}`);
  }
  return p;
}
const CVE_ANY = /CVE-\d{4}-\d{4,7}/gi;
const CVE_EXACT = /^CVE-\d{4}-\d{4,7}$/i;
