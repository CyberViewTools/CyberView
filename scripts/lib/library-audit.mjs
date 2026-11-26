// The Library's reader accuracy gate and the Library's correction counts. Pure apart from loadConfig/loadCorrections (reads only).
// Shared by the reader, writer and review desks so none of them imports another (no cycle). A card the reviewer or auditor found
// wrong keeps `audit: { at, ok: false }` for good: re-reading it makes a new card, but the error stays on the record (the reader
// carries it forward), so a re-read cannot make the reader's error rate look better than it was.
import { join } from "node:path";
import { existsSync, readdirSync } from "node:fs";
import { ROOT, readJson } from "./store.mjs";
import { DIR } from "../orkl.mjs";

export const DEFAULTS = { reread: 3, audit_pct: 10, audit_pause_pct: 5, audit_min: 50 };
export const WINDOW = 500;                                // the most recent audited cards that count
export const PAUSE_MESSAGE = "Library reader accuracy below target";
export const CORRECTIONS_DIR = join(DIR, "corrections");

/** config/pipeline.json `library` over the defaults (numbers only; anything else is ignored). */
export function loadConfig(file = join(ROOT, "config", "pipeline.json")) {
  const lib = (readJson(file, {}) || {}).library;
  const out = { ...DEFAULTS };
  if (lib && typeof lib === "object") for (const k of Object.keys(DEFAULTS)) if (Number.isFinite(lib[k]) && lib[k] >= 0) out[k] = lib[k];
  return out;
}

const list = (cards) => (cards instanceof Map ? [...cards.values()] : Array.isArray(cards) ? cards : Object.values(cards || {}));

/** Over the most recent WINDOW audited cards: how many, how many wrong, the wrong share, and whether the Library is paused. */
export function auditState(cards, cfg = DEFAULTS) {
  const c = { ...DEFAULTS, ...(cfg || {}) };
  const all = list(cards).filter((x) => x && x.audit && typeof x.audit === "object")
    .sort((a, b) => String(b.audit.at || "").localeCompare(String(a.audit.at || "")) || String(a.sha1 || "").localeCompare(String(b.sha1 || "")))
    .slice(0, WINDOW);
  const wrong = all.filter((x) => x.audit.ok !== true).length, audited = all.length;
  const pct = audited ? (100 * wrong) / audited : 0;
  return { audited, wrong, pct, paused: audited >= c.audit_min && pct > c.audit_pause_pct };
}
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
