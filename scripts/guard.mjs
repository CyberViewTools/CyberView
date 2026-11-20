// End-to-end pipeline guard, no AI model. Run: node scripts/guard.mjs [--heal] [--json]
// Looks at the LIVE site and the public GitHub API only, so it works from anywhere, with no access to the repository's
// secrets or to the session that runs the jobs. It answers one question: is fresh, validated data reaching visitors?
//   live data age            the site was rebuilt in the last 90 minutes
//   sweep, collect, feeds    each ran within its limit (150 min, 120 min, 6 h)
//   power grid               the grid collector ran within 120 minutes, its analysis and the news within 60, and no
//                            outage waited over 120 minutes for a cause check (warnings only: context, not cyber data)
//   deploy                   the newest commit on main is live (or was pushed less than 20 minutes ago), and the last deploy succeeded
//   data                     the bundle has events, every post in the feed is reviewed, nothing is quarantined
// --heal: where a check fails and `gh` is available, start the overdue workflow or a fresh deploy.
// Exit 0 = healthy, 2 = warnings only, 1 = visitors are (or will soon be) seeing stale or missing data.
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

const SITE = (process.env.SITE_URL || "https://xanderhutch.github.io/CyberView").replace(/\/$/, ""), REPO = "xanderhutch/CyberView";
export const LIMITS = { build_min: 90, sweep_min: 45, collect_min: 120, feeds_min: 360, deploy_lag_min: 20, cve_min: 180, brief_min: 420, analysis_min: 900, analyst_min: 300, grid_min: 120,
  grid_analysis_min: 60, grid_news_min: 60, grid_wait_min: 120 };
const mins = (iso, now) => (now - Date.parse(iso)) / 6e4;

/** Pure: what was read -> { fails, warns, heal }. */
export function assess({ manifest, health, bundle, head, deploy, leases }, now = Date.now()) {
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
  if (head && head.sha && manifest.commit && head.sha !== manifest.commit && mins(head.date, now) > LIMITS.deploy_lag_min) { fails.push(`main is at ${head.sha.slice(0, 7)} (${Math.round(mins(head.date, now))} minutes old) but the live site is built from ${manifest.commit.slice(0, 7)}`); heal.push("deploy"); }
  if (deploy && deploy.conclusion === "failure") { warns.push("the most recent deploy run failed"); heal.push("deploy"); }
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
  const [manifest, health, bundle, commit, runs] = await Promise.all([live("manifest.json"), live("health.json"), live("bundle.json"), api("commits/main"), api("actions/workflows/pages.yml/runs?per_page=1&status=completed")]);
  const head = commit ? { sha: commit.sha, date: commit.commit && commit.commit.committer && commit.commit.committer.date } : null;
  const deploy = runs && runs.workflow_runs && runs.workflow_runs[0] ? { conclusion: runs.workflow_runs[0].conclusion } : null;
  const leases = await j(`https://raw.githubusercontent.com/${REPO}/main/data/leases.json?t=${t}`);
  const r = assess({ manifest, health, bundle, head, deploy, leases });
  const healed = [];
  if (process.argv.includes("--heal")) for (const h of r.heal) {
    // grid: collect.yml runs grid collect, the analysis and the news when the research loop has not
    const wf = { deploy: "pages.yml", collect: "collect.yml", grid: "collect.yml", feeds: "feeds.yml", cve: "cve.yml" }[h]; if (!wf) continue;
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
