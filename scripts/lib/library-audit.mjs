// The Library's reader accuracy gate and the Library's correction counts. Pure apart from loadConfig/loadCorrections (reads only).
// Shared by the reader, writer and review desks so none of them imports another (no cycle).
// The pause: only the AUDITOR's verdicts count (card.audit.by === "auditor"); a reviewer's flag marks the card for re-reading but is not
// in the rate. Each card counts once, by its latest auditor verdict. When a card is read again its old `audit` moves into
// `audit_history` (the last 5) and the new card has no current audit; such a card is always audited again (auditPick), and until
// then its failed verdict still counts. While paused: the writer and the review run do nothing; the reader reads only cards queued
// by a failed audit (auditFailed); the audit run audits at 100% so the failed cards are checked again. See pauseHelp.
// The rate measures cards in use: a card that ends `no-text`, or `unread` with its tries spent, is retired and counts as neither audited nor wrong.
import { join } from "node:path";
import { existsSync, readdirSync } from "node:fs";
import { ROOT, readJson } from "./store.mjs";
import { DIR } from "../orkl.mjs";

export const DEFAULTS = { reread: 3, audit_pct: 100, audit_pause_pct: 5, audit_min: 50, rewrite_hours: 0 };   // audit_pct 100: every card is audited before the site may show it; rewrite_hours 0: no rewrite cool-down
/** The writer's rewrite cool-down in ms (library.rewrite_hours). */
export const rewriteMsOf = (cfg) => Math.max(0, Number((cfg || {}).rewrite_hours) || 0) * 3600000;
export const WINDOW = 500;                                // the most recent audited cards that count
export const PAUSE_MESSAGE = "Library reader accuracy below target";
export const pauseHelp = "Clears when the failed cards are read again and audited ok by the auditor, or when the owner raises library.audit_pause_pct in config/pipeline.json.";
export const CORRECTIONS_DIR = join(DIR, "corrections");

/** config/pipeline.json `library` over the defaults (numbers only; anything else is ignored). */
export function loadConfig(file = join(ROOT, "config", "pipeline.json")) {
  const lib = (readJson(file, {}) || {}).library;
  const out = { ...DEFAULTS };
  if (lib && typeof lib === "object") for (const k of Object.keys(DEFAULTS)) if (Number.isFinite(lib[k]) && lib[k] >= 0) out[k] = lib[k];
  return out;
}

const list = (cards) => (cards instanceof Map ? [...cards.values()] : Array.isArray(cards) ? cards : Object.values(cards || {}));
const failedEntry = (x) => x && typeof x === "object" && x.ok !== true;

/** A card's latest AUDITOR verdict: its current audit when the auditor made it, else the newest auditor entry in audit_history
 *  (a card read again after a failed audit has no current audit and still counts as wrong until the auditor passes it). */
export function auditorVerdict(card) {
  if (card && card.audit && card.audit.by === "auditor") return card.audit;
  const h = (card && Array.isArray(card.audit_history) ? card.audit_history : []).filter((e) => e && e.by === "auditor");
  return h.length ? h[h.length - 1] : null;
}
/** A card queued for the reader because an audit (the auditor's or the reviewer's) found it wrong: unread, with a failed current audit or history. */
export const auditFailed = (c) => !!c && c.status === "unread" && (failedEntry(c.audit) || (Array.isArray(c.audit_history) && c.audit_history.some(failedEntry)));

/** The cards the rate measures: those in use. A card counts by its latest auditor verdict when it is `read` (or has no status); one
 *  awaiting a re-read (`unread`, tries < 2) counts only as wrong, if its auditor verdict failed. A `no-text` card, or an `unread`
 *  one with its tries spent (>= 2), is retired: the reader will not read it again, so it counts as neither audited nor wrong. */
function counted(cards) {
  const out = [];
  for (const x of list(cards)) {
    const v = auditorVerdict(x);
    if (!v) continue;
    const st = x.status, tries = Number(x.tries) || 0;
    if (st === "no-text" || (st === "unread" && tries >= 2)) continue;
    if (st === "unread" && v.ok === true) continue;
    out.push({ sha1: x.sha1, v });
  }
  return out;
}
const recent = (cards) => counted(cards)
  .sort((a, b) => String(b.v.at || "").localeCompare(String(a.v.at || "")) || String(a.sha1 || "").localeCompare(String(b.sha1 || "")))
  .slice(0, WINDOW);

/** Over the WINDOW most recent audited cards in use, each counted once by its latest AUDITOR verdict (a reviewer's flag does not
 *  count): how many, how many wrong, the wrong share, and whether the Library is paused. */
export function auditState(cards, cfg = DEFAULTS) {
  const c = { ...DEFAULTS, ...(cfg || {}) };
  const all = recent(cards);
  const wrong = all.filter((x) => x.v.ok !== true).length, audited = all.length;
  const pct = audited ? (100 * wrong) / audited : 0;
  return { audited, wrong, pct, paused: audited >= c.audit_min && pct > c.audit_pause_pct };
}
/** The sha1s of cards retired after a failed audit: found wrong again after being read again, so the reader does not read them a third
 *  time (markCardWrong sets their tries to the reader's limit). Counted for the pipeline check and status; a person decides what next. */
export const retiredAfterAudit = (cards) => list(cards).filter((c) => c && c.status === "unread" && (Number(c.tries) || 0) >= 2 && c.reason === "audit-wrong").map((c) => c.sha1).sort();
/** The sha1s of the cards currently counted as wrong. */
export const wrongCards = (cards) => recent(cards).filter((x) => x.v.ok !== true).map((x) => x.sha1);
export const paused = (cards, cfg = DEFAULTS) => auditState(cards, cfg).paused;

/** Pure: corrections files ({key: [{at, role, model, code, note}]}) -> counts by role and model for the last `days` days. */
export function libraryErrorReport(files, now = Date.now(), days = 7) {
  const since = new Date(now - days * 864e5).toISOString(), by = {};
  let n = 0;
  for (const list of Object.values(files || {})) {
    for (const c of Array.isArray(list) ? list : []) {
      if (!c || typeof c !== "object" || String(c.at || "") < since) continue;
      const role = String(c.role || "unknown"), model = String(c.model || "unknown"), code = String(c.code || "other");
      const b = by[`${role}|${model}`] ||= { role, model, corrected: 0, types: {} };
      b.corrected++; b.types[code] = (b.types[code] || 0) + 1; n++;
    }
  }
  return { days, corrections: n, by_writer: Object.values(by).sort((a, b) => b.corrected - a.corrected).map((b) => ({ ...b, types: Object.fromEntries(Object.entries(b.types).sort((x, y) => y[1] - x[1])) })) };
}

/** Every corrections file under the directory ({key: list}); an unreadable file is skipped. */
export function loadCorrections(dir = CORRECTIONS_DIR) {
  const out = {};
  if (!existsSync(dir)) return out;
  for (const f of readdirSync(dir)) {
    if (!/^[A-Za-z0-9-]{1,70}\.json$/.test(f)) continue;
    const j = readJson(join(dir, f), null);
    if (Array.isArray(j)) out[f.slice(0, -5)] = j;
  }
  return out;
}

/** What every desk prints when it is paused: the message and how the pause clears. */
export const PAUSE_NOTICE = `${PAUSE_MESSAGE}. ${pauseHelp}`;
