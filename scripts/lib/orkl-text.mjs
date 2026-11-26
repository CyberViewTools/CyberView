// Fetching one ORKL report's text for the Library's reader desk (scripts/library-read.mjs). The text is returned to the caller's
// local variable and nowhere else: it is never written to disk, logged or put in a record (only the fact card made from it is stored).
// Endpoint: GET https://orkl.eu/api/v1/library/entry/<ORKL entry id> answers { data: { ..., plain_text } } (the same entry shape the
// list endpoint /library/entries returns, which scripts/orkl.mjs mirrors without plain_text). If the entry has no plain_text, the
// archive's text file (report.txt_url, https://archive.orkl.eu/<sha1>.txt) is read instead. Fetches are one at a time per caller and
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

// ORKL answered with "no such thing" (404, 410): that is an answer, not an outage
const gone = (e) => e && (e.code === "http_404" || e.code === "http_410");

/** The report's text: the API entry's plain_text first, then the archive text file. { error: "none" } only when ORKL answered and has
 *  no text; { error: "unreachable" } for any network, timeout, circuit-open or 5xx/429 failure (the record stays queued). */
export async function fetchText(report, { getter = get } = {}) {
  const r = report || {};
  if (r.id) {
    try {
      const body = await getter(`${API}/library/entry/${encodeURIComponent(r.id)}`, { timeoutMs: 30000, retries: 2, delayMs: 2000, key: "orkl.eu" });
      const d = body && typeof body === "object" ? (body.data && typeof body.data === "object" ? body.data : body) : null;
      if (d && typeof d.plain_text === "string" && d.plain_text.trim()) return prepText(d.plain_text);
    } catch (e) { if (!gone(e)) return { error: "unreachable" }; }
  }
  const u = archiveUrl(r.txt_url);
  if (!u) return { error: "none" };
  try {
    const t = await getter(u, { as: "text", timeoutMs: 30000, retries: 2, delayMs: 2000 });
    return typeof t === "string" && t.trim() ? prepText(t) : { error: "none" };
  } catch (e) { return gone(e) ? { error: "none" } : { error: "unreachable" }; }
}
