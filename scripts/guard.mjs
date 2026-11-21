// End-to-end pipeline guard, no AI model. Run: node scripts/guard.mjs [--heal] [--json]
// Looks at the LIVE site and the public GitHub API only, so it works from anywhere, with no access to the repository's
// secrets or to the session that runs the jobs. It answers one question: is fresh, validated data reaching visitors?
//   live data age            the site was rebuilt in the last 90 minutes
//   sweep, collect, feeds    each ran within its limit (150 min, 120 min, 6 h)
//   power grid               the grid collector ran within 120 minutes, its analysis and the news within 60, and no
//                            outage waited over 120 minutes for a cause check (warnings only: context, not cyber data)
//   deploy                   the newest commit on main (code) and on the data branch (data) are live, each within 20 minutes
//                            of being pushed, and the last deploy succeeded; data commits that need no deploy (leases, usage)
//                            are not counted as lag
//   forwarder                while data is still pushed to main during the switch, data-forward.yml brings it to the data
//                            branch within 30 minutes (warning only)
//   data                     the bundle has events, every post in the feed is reviewed, nothing is quarantined
//   every other stage        health.json "stages" against "stage_limits" (scripts/lib/stages.mjs; limits from routines.json):
//                            osint, lead triage, fuse, rules, review desk, follow-up, outage desk, KEV, context, exploit
//                            watch, link check, pipeline check (warnings; --heal starts the stage's workflow)
//   pipeline check           every problem in health.json "quality" (scripts/pipecheck.mjs) that outlasted its threshold
//   live check               monitor.yml ran within 3 hours (GitHub drops scheduled runs under load)
// --heal: where a check fails and `gh` is available, start the overdue workflow or a fresh deploy.
// Exit 0 = healthy, 2 = warnings only, 1 = visitors are (or will soon be) seeing stale or missing data.
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { NO_DEPLOY } from "./lib/repo.mjs";
import { stageStates } from "./lib/stages.mjs";

const SITE = (process.env.SITE_URL || "https://xanderhutch.github.io/CyberView").replace(/\/$/, ""), REPO = "xanderhutch/CyberView";
// brief, analysis and analyst: the routines' own max_age_hours in routines.json (a unit test keeps them equal; until
// 2026-11-21 the guard warned about the twice-daily brief after 7 hours and the daily analysis after 15)
export const LIMITS = { build_min: 90, sweep_min: 45, collect_min: 120, feeds_min: 360, deploy_lag_min: 20, cve_min: 180, brief_min: 840, analysis_min: 1800, analyst_min: 420, grid_min: 120,
  grid_analysis_min: 60, grid_news_min: 60, grid_wait_min: 120, forward_min: 30, monitor_min: 180 };
// stages the checks above already judge (with tighter limits that FAIL); the stage table adds every other one as a warning
const JUDGED = new Set(["collect", "feeds", "cve", "sweep", "grid", "grid-news", "grid-analysis"]);
const mins = (iso, now) => (now - Date.parse(iso)) / 6e4;
/** Where a data file is read from raw.githubusercontent.com: the data branch's root once it exists, else main's data/. */
export const rawDataUrl = (repo, dataBranch, path) => `https://raw.githubusercontent.com/${repo}/${dataBranch ? "data" : "main/data"}/${path}`;
/** --heal: which workflow (dispatched on main) repairs which finding. */
export const HEAL = { deploy: "pages.yml", collect: "collect.yml", grid: "collect.yml", feeds: "feeds.yml", cve: "cve.yml", forward: "data-forward.yml",
  linkcheck: "linkcheck.yml", monitor: "monitor.yml", pipecheck: "pipecheck.yml" };
const HEAL_BY_WF = Object.fromEntries(Object.entries(HEAL).map(([k, v]) => [v, k]).reverse());

/** Pure: what was read -> { fails, warns, heal }.
 *  head: main's newest commit {sha, date}. dataHead: the data branch's newest commit, or null while there is no data branch.
 *  dataLagFiles: files changed between the live data commit and dataHead (only looked up when they differ).
 *  forward: { mark: {sha, date} of the main commit in the data branch's .forwarded, main: [{sha, date}] main commits touching data/ }. */
export function assess({ manifest, health, bundle, head, deploy, leases, dataHead, dataLagFiles, forward, monitor }, now = Date.now()) {
  const fails = [], warns = [], heal = [];
  if (!manifest || !health || !bundle) { fails.push("the live site's data files could not be read"); heal.push("deploy"); return { fails, warns, heal }; }
  const age = mins(manifest.built_at, now);
  if (!(age <= LIMITS.build_min)) { fails.push(`live data was built ${Math.round(age)} minutes ago (limit ${LIMITS.build_min})`); heal.push("collect"); }
  const late = (label, iso, limit, wf) => { const m = mins(iso, now); if (!iso || !(m <= limit)) { (wf ? warns : fails).push(`${label} last ran ${iso ? Math.round(m) + " minutes ago" : "never"} (limit ${limit})`); if (wf) heal.push(wf); return true; } return false; };
  // a live leader lease means the research loop is running, even through a quiet spell with nothing to commit
  const leaderLive = leases && leases["flow:leader"] && Date.parse(leases["flow:leader"].until) > now;
  if (!leaderLive && late("the sweep", health.last_sweep_at, LIMITS.sweep_min, "")) heal.push("sweep");
  late("the lead collector", health.last_collect_at, LIMITS.collect_min, "collect");
  late("the vulnerability feeds", health.last_feeds_at, LIMITS.feeds_min, "feeds");
  if (health.last_cve_at !== undefined && late("the CVE corpus", health.last_cve_at, LIMITS.cve_min, "cve")) heal.push("cve");
  if (health.last_brief_at !== undefined) late("the daily brief", health.last_brief_at, LIMITS.brief_min, "brief");
  if (health.last_analysis_at !== undefined) late("the pattern analysis", health.last_analysis_at, LIMITS.analysis_min, "analysis");
  if (health.last_analyst_at !== undefined) late("the exploit analyst", health.last_analyst_at, LIMITS.analyst_min, "analyst");
  // power grid context layer (grid.mjs collect): a warning only, never FAILING; it is context, not the cyber data
  if (health.last_grid_at !== undefined) late("the power grid collector", health.last_grid_at, LIMITS.grid_min, "grid");
  if (health.grid_analysis_at !== undefined) late("the power grid analysis", health.grid_analysis_at, LIMITS.grid_analysis_min, "grid");
  if (health.last_grid_news_at !== undefined) late("the power outages in the news", health.last_grid_news_at, LIMITS.grid_news_min, "grid");
  const gw = health.grid_waiting;
  if (gw && gw.count > 0 && gw.oldest_min > LIMITS.grid_wait_min) warns.push(`${gw.count} grid outage(s) wait for a cause check, the oldest for ${gw.oldest_min} minutes (limit ${LIMITS.grid_wait_min}): the grid researchers are not running`);
  // the research loop's leader lease is its heartbeat: renewed every cycle, so an expired one means no loop is running
  if (leases) { const l = leases["flow:leader"]; if (!l || !(Date.parse(l.until) > now)) warns.push("no research loop holds the leader lease" + (l ? " (it expired at " + l.until + ")" : "") + ": the standby session should take over within 30 minutes"); }
  if (!Array.isArray(bundle.events) || bundle.events.length < 5) fails.push(`the live bundle has ${Array.isArray(bundle.events) ? bundle.events.length : 0} events`);
  const bl = health.backlog;
  if (bl && bl.waiting > 60) warns.push(`the research queue holds ${bl.waiting} reports waiting for a decision (limit 60): the backlog desk is behind`);
  if (bl && bl.oldest_incident_hours > 2) warns.push(`a report that reads like an incident has waited ${bl.oldest_incident_hours} hours (limit 2)`);
  if (health.quarantined_count > 0) warns.push(`${health.quarantined_count} data record(s) are quarantined (left out of the site): ${(health.quarantined || []).slice(0, 2).join("; ")}`);
  // deploy lag: code (main vs manifest.commit) and data (data branch vs manifest.data_commit), each with the same limit
  const behind = (h, liveSha) => h && h.sha && liveSha && h.sha !== liveSha && mins(h.date, now) > LIMITS.deploy_lag_min;
  if (behind(head, manifest.commit)) { fails.push(`main is at ${head.sha.slice(0, 7)} (${Math.round(mins(head.date, now))} minutes old) but the live site is built from ${manifest.commit.slice(0, 7)}`); heal.push("deploy"); }
  if (dataHead && dataHead.sha) {
    if (!manifest.data_commit) warns.push("the live site does not record which data commit it was built from (deployed before the data branch); the next deploy adds it");
    else if (behind(dataHead, manifest.data_commit) && !(Array.isArray(dataLagFiles) && dataLagFiles.length && dataLagFiles.every(NO_DEPLOY))) {
      fails.push(`the data branch is at ${dataHead.sha.slice(0, 7)} (${Math.round(mins(dataHead.date, now))} minutes old) but the live site has data ${String(manifest.data_commit).slice(0, 7)}`); heal.push("deploy");
    }
  }
  // the switch: a job still on old code pushes data to main; the forwarder must bring it over to the data branch
  if (dataHead && forward && forward.mark && forward.mark.sha && Array.isArray(forward.main)) {
    const markAt = Date.parse(forward.mark.date), waiting = forward.main.filter((c) => c && c.sha && c.sha !== forward.mark.sha && Date.parse(c.date) > markAt);
    const oldest = waiting.reduce((m, c) => Math.max(m, mins(c.date, now)), -Infinity);
    if (oldest > LIMITS.forward_min) { warns.push(`data is still being pushed to main; the forwarder is not keeping up (${waiting.length} data commit(s) on main not on the data branch, the oldest ${Math.round(oldest)} minutes old; limit ${LIMITS.forward_min})`); heal.push("forward"); }
  }
  if (deploy && deploy.conclusion === "failure") { warns.push("the most recent deploy run failed"); heal.push("deploy"); }
  // every other pipeline stage (scripts/lib/stages.mjs), with the limits the build took from routines.json
  if (health.stages && health.stage_limits && typeof health.stages === "object") {
    for (const s of stageStates(health.stages, [], now, {}, health.stage_limits)) {
      if (JUDGED.has(s.key) || (s.state !== "late" && s.state !== "never")) continue;
      warns.push(s.state === "never" ? `${s.label}: no heartbeat recorded` : `${s.label} last ran ${Math.round(s.age_min)} minutes ago (limit ${s.max_min})`);
      if (s.heal && HEAL_BY_WF[s.heal]) heal.push(HEAL_BY_WF[s.heal]);
    }
  }
  // the pipeline check's own findings (scripts/pipecheck.mjs): only those that outlasted their threshold
  const Q = health.quality;
  if (Q && Array.isArray(Q.problems)) for (const p of Q.problems) if (p && p.over === true && p.level !== "info" && typeof p.text === "string") warns.push("pipeline check: " + p.text.slice(0, 240));
  // the live-site monitor runs in Actions with no data heartbeat: its last run is read from the Actions API
  if (monitor && monitor.created_at && !(mins(monitor.created_at, now) <= LIMITS.monitor_min)) { warns.push(`the live site monitor last ran ${Math.round(mins(monitor.created_at, now))} minutes ago (limit ${LIMITS.monitor_min})`); heal.push("monitor"); }
  return { fails, warns, heal: [...new Set(heal)] };
}

async function j(url, headers = {}) {
  for (let i = 0; i < 3; i++) {
    try { const r = await fetch(url, { headers: { "user-agent": "cyberview-guard/1.0", "cache-control": "no-cache", ...headers }, signal: AbortSignal.timeout(20000) }); if (r.ok) return await r.json(); if (r.status === 404 || r.status === 403) return null; }
    catch {} await new Promise((r) => setTimeout(r, 4000));
  }
  return null;
}
const gh = (args) => spawnSync("gh", ["api", ...args], { encoding: "utf8", timeout: 60000 });

async function main() {
  const t = Date.now(), live = (f) => j(`${SITE}/data/${f}?t=${t}`), api = (p) => j(`https://api.github.com/repos/${REPO}/${p}`, { accept: "application/vnd.github+json" });
  const [manifest, health, bundle, commit, runs, mon] = await Promise.all([live("manifest.json"), live("health.json"), live("bundle.json"), api("commits/main"), api("actions/workflows/pages.yml/runs?per_page=1&status=completed"), api("actions/workflows/monitor.yml/runs?per_page=1")]);
  const monitor = mon && mon.workflow_runs && mon.workflow_runs[0] ? { created_at: mon.workflow_runs[0].created_at } : null;
  const head = commit ? { sha: commit.sha, date: commit.commit && commit.commit.committer && commit.commit.committer.date } : null;
  const deploy = runs && runs.workflow_runs && runs.workflow_runs[0] ? { conclusion: runs.workflow_runs[0].conclusion } : null;
  // the data branch (code on main, data on `data`): its newest commit, or null while it does not exist yet
  const dc = await api("commits/data"), dataHead = dc && dc.sha ? { sha: dc.sha, date: dc.commit && dc.commit.committer && dc.commit.committer.date } : null;
  const leases = await j(`${rawDataUrl(REPO, !!dataHead, "leases.json")}?t=${t}`);
  let dataLagFiles, forward;
  if (dataHead && manifest && manifest.data_commit && manifest.data_commit !== dataHead.sha) {
    const cmp = await api(`compare/${manifest.data_commit}...${dataHead.sha}`);
    if (cmp && Array.isArray(cmp.files) && cmp.files.length < 300) dataLagFiles = cmp.files.map((f) => f.filename);   // 300 = the API's cap: a full list may be cut short
  }
  if (dataHead) {
    const mark = await fetch(`${rawDataUrl(REPO, true, ".forwarded")}?t=${t}`, { signal: AbortSignal.timeout(20000) }).then((x) => (x.ok ? x.text() : "")).catch(() => "");
    const sha = (/^[0-9a-f]{40}$/m.exec(mark) || [""])[0], mc = sha ? await api(`commits/${sha}`) : null;
    if (mc && mc.commit) {
      const date = mc.commit.committer && mc.commit.committer.date, list = await api(`commits?sha=main&path=data&since=${encodeURIComponent(date)}&per_page=100`);
      if (Array.isArray(list)) forward = { mark: { sha, date }, main: list.map((c) => ({ sha: c.sha, date: c.commit && c.commit.committer && c.commit.committer.date })) };
    }
  }
  const r = assess({ manifest, health, bundle, head, deploy, leases, dataHead, dataLagFiles, forward, monitor });
  const healed = [];
  if (process.argv.includes("--heal")) for (const h of r.heal) {
    // grid: collect.yml runs grid collect, the analysis and the news when the research loop has not
    const wf = HEAL[h]; if (!wf) continue;
    if (healed.some((x) => x.startsWith(wf + ":"))) continue;
    const x = gh(["-X", "POST", `repos/${REPO}/actions/workflows/${wf}/dispatches`, "-f", "ref=main"]);
    healed.push(`${wf}: ${x.status === 0 ? "started" : "could not be started from here"}`);
  }
  if (process.argv.includes("--json")) { console.log(JSON.stringify({ ...r, healed, built_at: manifest && manifest.built_at })); }
  else {
    console.log(r.fails.length ? "GUARD: FAILING" : r.warns.length ? "GUARD: warnings" : "GUARD: healthy");
    if (manifest) console.log(`live data built ${Math.round(mins(manifest.built_at, Date.now()))} min ago; ${bundle && bundle.events ? bundle.events.length : 0} events; sweep ${health && health.last_sweep_at ? Math.round(mins(health.last_sweep_at, Date.now())) + " min ago" : "unknown"}`);
    r.fails.forEach((x) => console.log("FAIL: " + x)); r.warns.forEach((x) => console.log("warn: " + x)); healed.forEach((x) => console.log("heal: " + x));
    if (r.heal.includes("sweep")) console.log("NEEDS: the sweep is overdue; the session that runs the AI jobs may be stuck");
  }
  process.exit(r.fails.length ? 1 : r.warns.length ? 2 : 0);
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
