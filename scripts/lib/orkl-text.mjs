// Fetching one ORKL report's text for the Library's reader desk (scripts/library-read.mjs). The text is returned to the caller's
// local variable and nowhere else: it is never written to disk, logged or put in a record (only the fact card made from it is stored).
// Sources, in order: (1) the archive's text file (report.txt_url, https://archive.orkl.eu/<sha1>.txt); (2) the API entry
// GET https://orkl.eu/api/v1/library/entry/<ORKL entry id>, expected to answer { data: { ..., plain_text } }. The API path is
// UNVERIFIED (never reached from the build sandbox), so it is second; a 4xx from either source falls through to the other. Fetches are one at a time per caller and
// go through scripts/lib/net.mjs, so its retries, Retry-After waits and per-host circuit breaker apply.
import { API, archiveUrl } from "../orkl.mjs";
import { get } from "./net.mjs";

export const TEXT_CAP = 120000;   // characters kept; a longer report is read in part and the card says partial
export const TEXT_MIN = 400;      // fewer characters than this is not a report (an empty or error page): the card is no-text

/** Pure: strip control characters (keeping tab and line breaks) and cap at TEXT_CAP. partial = something was cut off. */
export function prepText(raw) {
  const s = String(raw == null ? "" : raw).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "");
  return s.length > TEXT_CAP ? { text: s.slice(0, TEXT_CAP), partial: true } : { text: s, partial: false };
}

// A 4xx is an answer ("not here", "not for you"): try the next source. A throttle (408, 425, 429) is not an answer: it is an outage.
const answered = (e) => e && /^http_4\d\d$/.test(e.code) && !/^http_(408|425|429)$/.test(e.code);

/** The report's text: the archive text file first (report.txt_url, only when archiveUrl() accepts it), then the API entry's plain_text.
 *  Any 4xx from one source falls through to the other, and so does text shorter than TEXT_MIN (an empty or error page is not an answer).
 *  { error: "unreachable" } when a source failed (network, timeout, circuit open, 5xx, throttle) and none produced usable text; when every
 *  available source answered, the longest short text they gave (the reader records it as no-text, too short), else { error: "none" }. */
export async function fetchText(report, { getter = get } = {}) {
  const r = report || {};
  let failed = false, short = "";
  const take = (t) => { const p = prepText(t); if (p.text.trim().length >= TEXT_MIN) return p; if (p.text.trim().length > short.trim().length) short = p.text; return null; };
  const u = archiveUrl(r.txt_url);
  if (u) {
    try {
      const t = await getter(u, { as: "text", timeoutMs: 30000, retries: 2, delayMs: 2000 });
      if (typeof t === "string" && t.trim()) { const p = take(t); if (p) return p; }
    } catch (e) { if (!answered(e)) failed = true; }
  }
  if (r.id) {
    try {
      const body = await getter(`${API}/library/entry/${encodeURIComponent(r.id)}`, { timeoutMs: 30000, retries: 2, delayMs: 2000, key: "orkl.eu" });
      const d = body && typeof body === "object" ? (body.data && typeof body.data === "object" ? body.data : body) : null;
      if (d && typeof d.plain_text === "string" && d.plain_text.trim()) { const p = take(d.plain_text); if (p) return p; }
    } catch (e) { if (!answered(e)) failed = true; }
  }
  if (failed) return { error: "unreachable" };
  return short.trim() ? { text: short, partial: false } : { error: "none" };
}
