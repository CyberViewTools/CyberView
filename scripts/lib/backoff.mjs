// Source health with a "failing" state and backoff, no AI model. Used by the feed collector (scripts/collect.mjs) and the
// other open-source collectors (scripts/osint.mjs), and read by the pipeline check (scripts/pipecheck.mjs).
// Why (2026-11-21): a feed that answered 403 was asked again on 158 runs before anyone noticed, and GDELT answered 429 to
// every request the research loop sent every few minutes. Now:
//   - FAIL_RUNS failures in a row move a source to state "failing" (failing_since = its first failure in the run of fails)
//   - a failing source is asked again only after a backoff: BASE_MIN minutes, doubled for every further failure, at most
//     MAX_MIN (and never sooner than a Retry-After the source sent); one success puts it back to "ok" at once
//   - a source failing for PROPOSE_DAYS days is proposed for the config/feeds.json watch list (scripts/pipecheck.mjs
//     propose-feeds, run by the source scout, whose finish step opens the pull request); after RETIRE_DAYS on the watch
//     list it is proposed for "retired". Never silently: the pipeline check also opens a pipeline-alert issue.
export const FAIL_RUNS = 3, BASE_MIN = 30, MAX_MIN = 12 * 60, PROPOSE_DAYS = 7, RETIRE_DAYS = 28;
const iso = (t) => new Date(t).toISOString().replace(/\.\d+Z$/, "Z");

/** Pure: minutes to wait before the next try after `fails` failures in a row (0 while under FAIL_RUNS). */
export function backoffMin(fails) {
  if (!(fails >= FAIL_RUNS)) return 0;
  return Math.min(MAX_MIN, BASE_MIN * 2 ** Math.min(10, fails - FAIL_RUNS));
}

/** Pure: the next health entry. prev: the stored entry (or {}); r: { ok, error, items, retryAfterMs, extra }.
 *  Keeps every field the collectors already write (ok, error, items, at, last_ok, fails) and adds state, failing_since,
 *  next_try_at. */
export function nextHealth(prev, r, now = Date.now()) {
  prev = prev && typeof prev === "object" ? prev : {};
  const at = iso(now);
  if (r && r.ok) {
    return { ...(r.extra || {}), ok: true, error: "", items: r.items || 0, at, last_ok: at, fails: 0, state: "ok" };
  }
  const fails = (Number(prev.fails) || 0) + 1, wait = Math.max(backoffMin(fails) * 6e4, Number(r && r.retryAfterMs) || 0);
  // the first failure of this run of failures (an entry written before this field existed: its last success, else its last try)
  const failingSince = fails > 1 ? prev.failing_since || prev.last_ok || prev.at || at : at;
  return { ...(r && r.extra || {}), ok: false, error: String((r && r.error) || "error").slice(0, 90), items: 0, at, last_ok: prev.last_ok || "", fails,
    state: fails >= FAIL_RUNS ? "failing" : "ok", failing_since: failingSince, ...(wait > 0 ? { next_try_at: iso(now + wait) } : {}) };
}

/** Pure: may this source be asked now? A failing source waits for next_try_at; everything else is always due. */
export function due(h, now = Date.now()) {
  if (!h || h.ok !== false || !h.next_try_at) return true;
  const t = Date.parse(h.next_try_at);
  return !isFinite(t) || now >= t;
}

/** Pure: days a source has been failing (0 when it is not failing). */
export function failingDays(h, now = Date.now()) {
  if (!h || h.ok !== false || h.state !== "failing") return 0;
  const t = Date.parse(h.failing_since || h.at || "");
  return isFinite(t) ? Math.max(0, (now - t) / 864e5) : 0;
}

/** Pure: what to propose for config/feeds.json. feeds: osint.json "feeds" ({name: health}); cfg: config/feeds.json.
 *  -> { watch: [{name, since, review, evidence, reason}], retire: [{name, retired, why}] } */
export function feedProposals(feeds, cfg, now = Date.now()) {
  const day = (t) => iso(t).slice(0, 10), watch = [], retire = [];
  const watched = new Map((cfg && Array.isArray(cfg.watch) ? cfg.watch : []).filter((w) => w && w.name).map((w) => [String(w.name).toLowerCase(), w]));
  const retired = new Set((cfg && Array.isArray(cfg.retired) ? cfg.retired : []).map((r) => String((r && r.name) || "").toLowerCase()));
  for (const [name, h] of Object.entries(feeds || {})) {
    const d = failingDays(h, now), k = name.toLowerCase();
    if (d < PROPOSE_DAYS || retired.has(k)) continue;
    const w = watched.get(k), evidence = `failing since ${String(h.failing_since || "").slice(0, 10)} (${h.fails} runs in a row): ${h.error}`;
    if (!w) watch.push({ name, since: day(now), review: day(now + 14 * 864e5), evidence, reason: "failing" });
    else if (w.reason === "failing" && d >= RETIRE_DAYS) retire.push({ name, retired: day(now), why: `${evidence}. On the watch list since ${w.since}; proposed by the pipeline check (scripts/pipecheck.mjs).` });
  }
  return { watch, retire };
}
