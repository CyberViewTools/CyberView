// Every stage of the data pipeline and where its heartbeat lives, in one table. No AI model.
// Read by the pipeline check (scripts/pipecheck.mjs, on the data branch), the build (health.json "stages", for the guard and
// the status page) and the guard (scripts/guard.mjs, from the live site). A stage whose heartbeat is older than its limit
// is "late"; `heal` names the workflow that restarts it (dispatched on main), or "" when only the ops session can.
// The limit comes from routines.json max_age_hours when the stage is a routine, so the two can never disagree again
// (2026-11-21: the guard warned about the brief after 7 hours while it runs every 12).
//   key        stage name (also the problem id: "stage-<key>")
//   status     the data/status.json key that holds its last run (the build copies it into health.json stages)
//   routine    routines.json key whose max_age_hours is the limit (else max_min)
//   when_work  only judged while there is work for it (researchers, reviewers, updaters, grid desk): their queues are
//              checked on their own (unreviewed events, the research queue, grid outages waiting)
export const STAGES = [
  { key: "collect", label: "the lead collector (RSS feeds)", status: "last_collect_at", routine: "collect", heal: "collect.yml" },
  { key: "osint", label: "the other open-source collectors", status: "last_osint_at", routine: "osint", heal: "collect.yml" },
  { key: "lead-triage", label: "the rules that clear leads already on file", status: "last_lead_triage_at", routine: "lead-triage", heal: "collect.yml" },
  { key: "fuse", label: "grouping leads into stories", status: "last_fuse_at", max_min: 180, heal: "collect.yml" },
  { key: "backlog-auto", label: "the rules that close routine items", status: "last_backlog_auto_at", max_min: 180, heal: "collect.yml" },
  { key: "sweep", label: "the research loop (commits)", status: "last_sweep_at", routine: "sweep", heal: "" },
  { key: "researchers", label: "researchers", status: "last_researcher_at", max_min: 24 * 60, heal: "", when_work: true },
  { key: "reviewers", label: "second reviewers in the loop", status: "last_reviewer_at", max_min: 24 * 60, heal: "", when_work: true },
  { key: "review-desk", label: "the review desk", status: "last_review_at", routine: "review", heal: "" },
  { key: "updaters", label: "updaters", status: "last_updater_at", max_min: 48 * 60, heal: "", when_work: true },
  { key: "followup", label: "the follow-up desk", status: "last_followup_at", routine: "followup", heal: "" },
  { key: "grid", label: "the power grid collector", status: "last_grid_at", routine: "grid", heal: "collect.yml" },
  { key: "grid-news", label: "power outages in the news", status: "last_grid_news_at", max_min: 120, heal: "collect.yml" },
  { key: "grid-analysis", label: "the power grid analysis", file: "grid/analysis.json", field: "updated_at", health: "grid_analysis_at", max_min: 120, heal: "collect.yml" },
  { key: "grid-desk", label: "the grid researchers", status: "last_grid_research_at", max_min: 24 * 60, heal: "", when_work: true },
  { key: "outage", label: "the outage desk", status: "last_outage_at", routine: "outage", heal: "" },
  { key: "cve", label: "the CVE corpus", status: "last_cve_at", routine: "cve", heal: "cve.yml" },
  { key: "feeds", label: "the vulnerability feeds", status: "last_feeds_at", routine: "feeds", heal: "feeds.yml" },
  { key: "kev", label: "CISA's known-exploited catalog", status: "last_kev_at", max_min: 8 * 60, heal: "feeds.yml" },
  { key: "context", label: "the map context layers (IODA, GDACS)", status: "last_context_at", max_min: 6 * 60, heal: "feeds.yml" },
  { key: "exploits", label: "the exploit watch", status: "last_exploits_at", routine: "exploit-watch", heal: "feeds.yml" },
  { key: "linkcheck", label: "the source link check", status: "last_linkcheck_at", routine: "link-check", heal: "linkcheck.yml" },
  { key: "pipecheck", label: "the pipeline check", status: "last_pipecheck_at", routine: "pipecheck", heal: "pipecheck.yml" },
];

/** Pure: each stage's limit in minutes (routines.json max_age_hours wins over the table's max_min). */
export function limits(routines) {
  const by = new Map((routines || []).map((r) => [r.key, r]));
  return Object.fromEntries(STAGES.map((s) => { const r = s.routine && by.get(s.routine); return [s.key, r && r.max_age_hours ? r.max_age_hours * 60 : s.max_min || 24 * 60]; }));
}

/** Pure: the stage table. last: {stageKey: iso or ""}; routines: routines.json routines; busy: {stageKey: true} for the
 *  when_work stages that have work waiting. -> [{key, label, last_at, max_min, age_min, state: ok|late|never|idle, heal}] */
export function stageStates(last, routines, now = Date.now(), busy = {}, lim = limits(routines)) {
  const out = [];
  const inactive = new Set((routines || []).filter((r) => r.active === false).map((r) => r.key));
  for (const s of STAGES) {
    if (s.routine && inactive.has(s.routine)) continue;
    const at = (last && last[s.key]) || "", t = Date.parse(at), age = isFinite(t) ? Math.round((now - t) / 6e4) : null, max = lim[s.key];
    if (!(max > 0)) continue;
    let state = age === null ? "never" : age > max ? "late" : "ok";
    if (s.when_work && state !== "ok" && !busy[s.key]) state = "idle";
    out.push({ key: s.key, label: s.label, last_at: isFinite(t) ? at : "", max_min: max, age_min: age, state, heal: s.heal });
  }
  return out;
}

/** Pure: {stageKey: iso} from data/status.json (and the files named in the table, read by the caller into `files`). */
export function lastRuns(status, files = {}) {
  const out = {};
  for (const s of STAGES) out[s.key] = s.status ? String((status && status[s.status]) || "") : String((files[s.file] && files[s.file][s.field]) || "");
  return out;
}
