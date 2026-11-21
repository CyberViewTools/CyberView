// Pipeline check: every stage measured, stalls healed or reported, data quality checked. No AI model.
// Run: node scripts/pipecheck.mjs [check] [--json]     the checks; writes data/quality.json and status.last_pipecheck_at
//      node scripts/pipecheck.mjs heal                  starts the workflow of each late stage that a workflow can restart
//                                                       (at most once an hour per workflow; needs `gh` with actions: write)
//      node scripts/pipecheck.mjs alerts                one GitHub issue per problem, label pipeline-alert (needs `gh` with
//                                                       issues: write): opened once a problem outlasts its threshold, a
//                                                       reminder comment at most once a day, closed when it is healthy
//      node scripts/pipecheck.mjs propose-feeds [--pr]  feeds failing for 7 days -> config/feeds.json `watch`, and 28 days on
//                                                       the watch list -> `retired` (the source scout runs it; its finish step,
//                                                       or --pr here, opens the pull request through scripts/propose.mjs)
// pipecheck.yml runs check, heal and alerts every hour (after a deploy, gated to once an hour) and commits data/quality.json;
// the build copies its problems into site/data/health.json, so the status page lists them under "What needs attention"
// and the guard (scripts/guard.mjs) reports them from the live site. Never emails anyone.
// Why (2026-11-20/21): status.json silently lost 18 keys, a status target failed for hours unseen, a feed answered 403 on
// 158 runs, GDELT answered 429 to every request. The checks, each a problem id with a level and an alert threshold:
//   stage-<key>      a pipeline stage's heartbeat is older than its limit (scripts/lib/stages.mjs; limits from routines.json)
//   status-keys      keys that vanished from data/status.json since earlier checks (a writer that started from {})
//   duplicates       pairs of events the dupes check and the second review let through (same story, two records)
//   unreviewed       events waiting more than 2 hours for their second review
//   leads-growth     today's lead file growing far faster than the last week's median (a collector looping or flooding)
//   data-size        the data branch's files growing much faster than usual in a day
//   collector-<name> an open-source collector failing for a day (backoff in scripts/lib/backoff.mjs)
//   feeds-propose    feeds failing for 7 days or more: proposed for the watch list (never retired silently)
//   broken-links     source links the weekly link check found gone (info only: the verify desk replaces them)
import { spawnSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { ROOT, DATA, readJson, writeJson, nowIso, readStatus, listEventFiles } from "./lib/store.mjs";
import { dataGitDir, dataRel, repoSlug } from "./lib/repo.mjs";
import { STAGES, stageStates, lastRuns } from "./lib/stages.mjs";
import { feedProposals, failingDays, PROPOSE_DAYS } from "./lib/backoff.mjs";
import { needsReview, waitingSince } from "./review.mjs";
import { tokens } from "./triage.mjs";

export const LABEL = "pipeline-alert";
// minutes a problem must last before an issue is opened (the status page lists it at once)
export const THRESHOLD = { stage: 30, stage_never: 24 * 60, "status-keys": 0, duplicates: 24 * 60, unreviewed: 60, "leads-growth": 180, "data-size": 24 * 60, collector: 24 * 60, "feeds-propose": 0, target: 6 * 60 };
export const UNREVIEWED_MIN = 120, KEY_MEMORY_DAYS = 3, KEY_KEEP_DAYS = 14, HEAL_EVERY_MIN = 60, REMIND_HOURS = 24, MAX_OPEN_PER_RUN = 5;
const day = (t) => new Date(t).toISOString().slice(0, 10);
const ago = (m) => (m === null ? "never" : m < 120 ? `${m} minutes ago` : m < 2880 ? `${Math.round(m / 60)} hours ago` : `${Math.round(m / 1440)} days ago`);
const lim = (m) => (m < 120 ? `${m} min` : `${Math.round(m / 60)} h`);

/* ---------------- pure checks (exported for tests) ---------------- */

/** Stage problems from stageStates(): late, or never stamped. */
export function stageProblems(stages) {
  return stages.filter((s) => s.state === "late" || s.state === "never").map((s) => ({
    id: `stage-${s.key}`, level: "warn", threshold_min: s.state === "never" ? THRESHOLD.stage_never : THRESHOLD.stage, heal: s.heal || "",
    text: s.state === "never" ? `${s.label}: no heartbeat recorded (status key missing)` : `${s.label} last ran ${ago(s.age_min)} (limit ${lim(s.max_min)})${s.heal ? "" : ": only the ops session can restart it"}`,
  }));
}

/** status.json keys: remember every key seen (with when), and name those seen in the last KEY_MEMORY_DAYS that are gone now.
 *  known: {key: lastSeenIso} from the previous check (or the committed copy's keys), current: today's status object. */
export function statusKeys(known, current, now = Date.now()) {
  const at = new Date(now).toISOString().replace(/\.\d+Z$/, "Z"), next = {}, cur = Object.keys(current || {});
  for (const [k, t] of Object.entries(known || {})) if (now - Date.parse(t) < KEY_KEEP_DAYS * 864e5) next[k] = t;
  const vanished = Object.keys(next).filter((k) => !cur.includes(k) && now - Date.parse(next[k]) < KEY_MEMORY_DAYS * 864e5).sort();
  for (const k of cur) next[k] = at;
  for (const k of vanished) delete next[k];   // reported once per disappearance; a key that comes back is simply seen again
  const problem = vanished.length ? { id: "status-keys", level: "bad", threshold_min: THRESHOLD["status-keys"],
    text: `${vanished.length} key(s) vanished from data/status.json (now ${cur.length}): ${vanished.slice(0, 12).join(", ")}. A writer started from an empty object; restore them from the previous data commit.` } : null;
  return { known: next, vanished, problem };
}

/** Pairs of live events that look like one story recorded twice and that nothing has settled. -> [{a, b, why}] */
export function missedDuplicates(events, now = Date.now(), days = 14) {
  const since = day(now - days * 864e5);
  const live = (events || []).filter((e) => e && e.id && !e.duplicate_of && String(e.date || "") >= since);
  const tok = new Map(live.map((e) => [e.id, tokens(`${e.title} ${e.org || ""}`)]));
  const urls = (e) => new Set((e.sources || []).map((s) => s && s.url).filter(Boolean));
  const settled = (a, b) => [a, b].some((x) => { const n = String((x.review && x.review.note) || ""); return n.includes(a.id === x.id ? b.id : a.id) || /not (a |the same )?duplicate|distinct (event|incident)|separate (event|incident)/i.test(n); });
  const out = [];
  for (let i = 0; i < live.length; i++) for (let j = i + 1; j < live.length; j++) {
    const a = live[i], b = live[j];
    if (a.category !== b.category || Math.abs(Date.parse(a.date) - Date.parse(b.date)) > 3 * 864e5) continue;
    // two named organisations that differ are two stories (one gang's claims against many victims read alike)
    if (a.org && b.org && a.org.toLowerCase() !== b.org.toLowerCase()) continue;
    const ta = tok.get(a.id), tb = tok.get(b.id); let inter = 0; ta.forEach((w) => tb.has(w) && inter++);
    const words = Math.min(ta.size, tb.size) >= 4 && inter / Math.min(ta.size, tb.size) >= 0.8;
    const cves = (a.cves || []).length && (a.cves || []).length === (b.cves || []).length && a.cves.every((c) => b.cves.includes(c)) && (a.org || "").toLowerCase() === (b.org || "").toLowerCase();
    // one report can describe several findings: a shared page counts only with half the words in common too
    const ua = urls(a), page = a.org && (a.org || "").toLowerCase() === (b.org || "").toLowerCase() && [...urls(b)].some((u) => ua.has(u)) && inter / Math.max(1, Math.min(ta.size, tb.size)) >= 0.5;
    if (!(words || cves || page) || settled(a, b)) continue;
    out.push({ a: a.id, b: b.id, why: words ? "same words" : cves ? "same CVEs and organisation" : "same organisation and source page" });
    if (out.length >= 20) return out;
  }
  return out;
}

/** Events waiting more than UNREVIEWED_MIN minutes for their second review. -> {count, oldest_min, ids} */
export function unreviewed(events, now = Date.now()) {
  const late = (events || []).filter((e) => e && needsReview(e)).map((e) => ({ id: e.id, min: Math.round((now - Date.parse(waitingSince(e))) / 6e4) }))
    .filter((x) => isFinite(x.min) && x.min > UNREVIEWED_MIN).sort((a, b) => b.min - a.min);
  return { count: late.length, oldest_min: late.length ? late[0].min : 0, ids: late.slice(0, 10).map((x) => x.id) };
}

/** Lead files: lines per day. days: [{date, lines}] oldest first, the last one today (partial). Today's pace (lines per
 *  hour so far, projected to a day) against the median of the previous complete days. */
export function leadsGrowth(days, now = Date.now()) {
  const today = day(now), past = (days || []).filter((d) => d.date < today).slice(-7).map((d) => d.lines).sort((a, b) => a - b);
  const t = (days || []).find((d) => d.date === today), hours = Math.max(1, (now - Date.parse(today + "T00:00:00Z")) / 36e5);
  if (!t || past.length < 3) return { today: t ? t.lines : 0, median: null, projected: null, abnormal: false };
  const median = past[Math.floor(past.length / 2)], projected = Math.round((t.lines / hours) * 24);
  // pace is only judged after 3 hours of the day (the first collections after midnight are a burst of the night's items)
  return { today: t.lines, median, projected, abnormal: hours >= 3 && projected > Math.max(1000, median * 3) };
}

/** Data size per day: history [{date, bytes}] (one entry per day, the last one replaced through the day). */
export function sizeGrowth(history, bytes, now = Date.now()) {
  const today = day(now), h = (history || []).filter((x) => x && x.date && x.date !== today).slice(-29).concat([{ date: today, bytes }]);
  const prev = h.length > 1 ? h[h.length - 2] : null, grew = prev ? bytes - prev.bytes : 0;
  return { history: h, grew, abnormal: !!prev && grew > Math.max(25e6, prev.bytes * 0.15) };
}

/** Carry each problem's first-seen time over from the previous check; `over` = it has lasted past its threshold. */
export function carry(problems, prev, now = Date.now()) {
  const was = new Map(((prev && prev.problems) || []).map((p) => [p.id, p]));
  const at = new Date(now).toISOString().replace(/\.\d+Z$/, "Z");
  return problems.map((p) => { const since = (was.get(p.id) && was.get(p.id).since) || at; return { ...p, since, over: p.level !== "info" && (now - Date.parse(since)) / 6e4 >= (p.threshold_min || 0) }; });
}

/** Pure: what to do on GitHub. problems: carried problems; issues: open issues with the label ([{number, body, updated_at}]).
 *  -> {open: [{id, title, body}], comment: [{number, body}], close: [{number, body}]} */
export function planAlerts(problems, issues, now = Date.now()) {
  const marker = (id) => `<!-- ${LABEL}:${id} -->`, idOf = (b) => ((String(b || "").match(new RegExp(`<!-- ${LABEL}:([a-z0-9:_-]+) -->`)) || [])[1] || "");
  const byId = new Map((issues || []).map((i) => [idOf(i.body), i]).filter(([k]) => k));
  const open = [], comment = [], close = [], live = new Set();
  for (const p of problems || []) {
    if (!p.over || p.level === "info") continue;
    live.add(p.id);
    const i = byId.get(p.id);
    if (!i) { if (open.length < MAX_OPEN_PER_RUN) open.push({ id: p.id, title: `Pipeline: ${p.text}`.slice(0, 120), body: `${marker(p.id)}\n**${p.text}**\n\nSeen by the pipeline check (scripts/pipecheck.mjs) since ${p.since}. The Status page lists it under "What needs attention". This issue closes itself when the check finds it healthy.` }); }
    else if ((now - Date.parse(i.updated_at)) / 36e5 >= REMIND_HOURS) comment.push({ number: i.number, body: `Still failing: ${p.text} (since ${p.since}).` });
  }
  for (const [id, i] of byId) if (!live.has(id)) close.push({ number: i.number, body: `Recovered: the pipeline check no longer finds "${id}".` });
  return { open, comment, close };
}

/** Pure: which workflows to start for late stages, at most once per HEAL_EVERY_MIN each. -> {start: [wf], healed: {wf: iso}} */
export function planHeal(problems, healed, now = Date.now()) {
  const at = new Date(now).toISOString().replace(/\.\d+Z$/, "Z"), next = { ...(healed || {}) }, start = [];
  for (const p of problems || []) {
    if (!p.heal || !/^stage-/.test(p.id) || start.includes(p.heal)) continue;
    const last = Date.parse(next[p.heal] || ""); if (isFinite(last) && (now - last) / 6e4 < HEAL_EVERY_MIN) continue;
    start.push(p.heal); next[p.heal] = at;
  }
  return { start, healed: next };
}

/* ---------------- reading the data branch ---------------- */

function walkBytes(dir) {
  let n = 0;
  for (const d of existsSync(dir) ? readdirSync(dir, { withFileTypes: true }) : []) {
    if (d.name === ".git") continue;
    const p = join(dir, d.name);
    if (d.isDirectory()) n += walkBytes(p); else { try { n += statSync(p).size; } catch {} }
  }
  return n;
}
function leadDays() {
  const dir = join(DATA, "leads");
  return (existsSync(dir) ? readdirSync(dir) : []).filter((f) => /^\d{4}-\d{2}-\d{2}\.jsonl$/.test(f)).sort().slice(-9)
    .map((f) => ({ date: f.slice(0, 10), lines: readFileSync(join(dir, f), "utf8").split("\n").filter(Boolean).length }));
}
/** Keys of the last committed data/status.json (the first check has no memory yet). */
function committedKeys() {
  const r = spawnSync("git", ["show", `HEAD:${dataRel("data/status.json")}`], { cwd: dataGitDir(), encoding: "utf8" });
  try { return r.status === 0 ? Object.keys(JSON.parse(r.stdout)) : []; } catch { return []; }
}

/** The owner's targets (scripts/efficiency.mjs) that fail. They are not shown on the status page (the owner took the targets
 *  off it on 2026-11-20: page false), but one that keeps failing opens an issue, so a failing target is never unseen again. */
export function targetProblems(targets) {
  return (Array.isArray(targets) ? targets : []).filter((t) => t && t.state === "fail" && /^[a-z0-9-]{1,30}$/.test(t.key || "")).map((t) => ({
    id: `target-${t.key}`, level: "warn", page: false, threshold_min: THRESHOLD.target, text: `the ${String(t.title || t.key).toLowerCase()} target fails: ${String(t.value || t.figure || "").slice(0, 160)} (goal: ${String(t.goal || "").slice(0, 80)})` }));
}

export async function check(now = Date.now()) {
  const qp = join(DATA, "quality.json"), prev = readJson(qp, {}) || {}, st = readStatus();
  const routines = (readJson(join(ROOT, "routines.json"), { routines: [] }) || { routines: [] }).routines || [];
  const files = {}; for (const s of STAGES) if (s.file) files[s.file] = readJson(join(DATA, s.file), {}) || {};
  const events = listEventFiles().map((f) => f.e).filter(Boolean);
  const rev = unreviewed(events, now);
  const busy = { researchers: (Number(st.stories_open) || 0) - (Number(st.stories_claims) || 0) > 0, reviewers: rev.count > 0 };
  const last = lastRuns(st, files); last.pipecheck = new Date(now).toISOString();   // this run is the pipeline check's own heartbeat
  const stages = stageStates(last, routines, now, busy);
  const problems = stageProblems(stages);
  // status.json keys (first check: remember what the last commit had, so a wipe in this very run is still caught)
  const known = prev.status_keys || Object.fromEntries(committedKeys().map((k) => [k, new Date(now - 60e3).toISOString()]));
  const sk = statusKeys(known, st, now); if (sk.problem) problems.push(sk.problem);
  const dupes = missedDuplicates(events, now);
  if (dupes.length) problems.push({ id: "duplicates", level: "warn", threshold_min: THRESHOLD.duplicates, text: `${dupes.length} pair(s) of events look like one story recorded twice: ${dupes.slice(0, 3).map((d) => `${d.a} / ${d.b}`).join("; ")}` });
  if (rev.count) problems.push({ id: "unreviewed", level: "warn", threshold_min: THRESHOLD.unreviewed, text: `${rev.count} event(s) have waited over ${UNREVIEWED_MIN / 60} hours for their second review, the oldest ${ago(rev.oldest_min).replace(" ago", "")}` });
  const lg = leadsGrowth(leadDays(), now);
  if (lg.abnormal) problems.push({ id: "leads-growth", level: "warn", threshold_min: THRESHOLD["leads-growth"], text: `today's lead file is on course for ${lg.projected} leads (the last week's median is ${lg.median} a day): a collector may be looping` });
  const sg = sizeGrowth(prev.size_history, walkBytes(DATA), now);
  if (sg.abnormal) problems.push({ id: "data-size", level: "warn", threshold_min: THRESHOLD["data-size"], text: `the data branch grew ${Math.round(sg.grew / 1e6)} MB since yesterday (now ${Math.round(sg.history[sg.history.length - 1].bytes / 1e6)} MB)` });
  const osint = readJson(join(DATA, "osint.json"), {}) || {}, cfg = readJson(join(ROOT, "config", "feeds.json"), {}) || {};
  for (const [name, h] of Object.entries(osint.sources || {})) if (h && h.ok === false && h.state === "failing" && failingDays(h, now) >= 1)
    problems.push({ id: `collector-${name.replace(/[^a-z0-9-]/gi, "").toLowerCase()}`, level: "warn", threshold_min: THRESHOLD.collector, text: `the ${name} collector has failed ${h.fails} runs in a row since ${String(h.failing_since).slice(0, 16).replace("T", " ")} UTC: ${h.error}` });
  const failingFeeds = Object.entries(osint.feeds || {}).filter(([, h]) => h && h.state === "failing").map(([name, h]) => ({ name, fails: h.fails, since: h.failing_since || "", error: h.error, days: +failingDays(h, now).toFixed(1), next_try_at: h.next_try_at || "" }));
  const prop = feedProposals(osint.feeds, cfg, now);
  if (prop.watch.length || prop.retire.length) problems.push({ id: "feeds-propose", level: "warn", threshold_min: THRESHOLD["feeds-propose"],
    text: `${prop.watch.length + prop.retire.length} feed(s) failing for ${PROPOSE_DAYS}+ days, proposed for config/feeds.json ${prop.retire.length ? "retired" : "watch"}: ${prop.watch.concat(prop.retire).map((x) => x.name).slice(0, 5).join(", ")} (the source scout runs pipecheck.mjs propose-feeds)` });
  try { problems.push(...targetProblems((await (await import("./efficiency.mjs")).build(7)).targets)); } catch (e) { console.warn("pipecheck: the efficiency report could not be built: " + String((e && e.message) || e).slice(0, 160)); }
  const lc = readJson(join(DATA, "linkcheck.json"), null);
  if (lc && Array.isArray(lc.broken) && lc.broken.length) problems.push({ id: "broken-links", level: "info", threshold_min: 0, text: `${lc.broken.length} source link(s) are gone (404 or 410) in the link check of ${String(lc.checked_at).slice(0, 10)}: the verify desk replaces them` });
  const out = { checked_at: new Date(now).toISOString().replace(/\.\d+Z$/, "Z"), problems: carry(problems, prev, now), stages, status_keys: sk.known,
    status_key_count: Object.keys(st).length, unreviewed: rev, duplicates: dupes, leads: lg, size_history: sg.history, feeds_failing: failingFeeds, propose: prop,
    linkcheck: lc ? { checked_at: lc.checked_at || "", checked: lc.checked || 0, broken: (lc.broken || []).length } : null, healed: prev.healed || {}, alerts: prev.alerts || null };
  writeJson(qp, out);
  const s2 = readStatus(); s2.last_pipecheck_at = out.checked_at; s2.pipecheck_note = out.problems.length ? `${out.problems.filter((p) => p.level !== "info").length} problem(s): ${out.problems.map((p) => p.id).join(", ")}`.slice(0, 200) : "healthy"; writeJson(join(DATA, "status.json"), s2);
  return out;
}

/* ---------------- GitHub (gh, REST only) ---------------- */
const gh = (args, input) => spawnSync("gh", ["api", ...args], { encoding: "utf8", timeout: 60000, input });

function heal() {
  const qp = join(DATA, "quality.json"), q = readJson(qp, null);
  if (!q) { console.log("pipecheck heal: no data/quality.json (run check first)"); return; }
  const p = planHeal(q.problems, q.healed), slug = repoSlug(ROOT);
  for (const wf of p.start) { const x = gh(["-X", "POST", `repos/${slug}/actions/workflows/${wf}/dispatches`, "-f", "ref=main"]); console.log(`heal: ${wf} ${x.status === 0 ? "started" : "could not be started: " + String(x.stderr || "").trim().split("\n").pop()}`); }
  if (!p.start.length) console.log("heal: nothing to restart");
  writeJson(qp, { ...q, healed: p.healed });
}

function alerts() {
  const qp = join(DATA, "quality.json"), q = readJson(qp, null);
  if (!q) { console.log("pipecheck alerts: no data/quality.json (run check first)"); return; }
  const slug = repoSlug(ROOT), list = gh([`repos/${slug}/issues?state=open&labels=${LABEL}&per_page=100`]);
  if (list.status !== 0) { console.log("alerts: could not list issues: " + String(list.stderr || "").trim().split("\n").pop()); return; }
  let issues = []; try { issues = JSON.parse(list.stdout).filter((i) => !i.pull_request); } catch {}
  const plan = planAlerts(q.problems, issues), done = [];
  if (plan.open.length) gh(["-X", "POST", `repos/${slug}/labels`, "-f", `name=${LABEL}`, "-f", "color=B60205", "-f", "description=Opened automatically by the CyberView pipeline check"]);
  for (const o of plan.open) { const x = gh(["-X", "POST", `repos/${slug}/issues`, "--input", "-"], JSON.stringify({ title: o.title, body: o.body, labels: [LABEL] })); done.push(`${x.status === 0 ? "opened" : "could not open"} ${o.id}`); }
  for (const c of plan.comment) { gh(["-X", "POST", `repos/${slug}/issues/${c.number}/comments`, "-f", `body=${c.body}`]); done.push(`reminded #${c.number}`); }
  for (const c of plan.close) { gh(["-X", "POST", `repos/${slug}/issues/${c.number}/comments`, "-f", `body=${c.body}`]); const x = gh(["-X", "PATCH", `repos/${slug}/issues/${c.number}`, "-f", "state=closed"]); done.push(`${x.status === 0 ? "closed" : "could not close"} #${c.number}`); }
  console.log("alerts: " + (done.join("; ") || `nothing to change (${issues.length} open)`));
  writeJson(qp, { ...q, alerts: { at: nowIso(), open: issues.length + plan.open.length - plan.close.length } });
}

function proposeFeeds() {
  const cp = join(ROOT, "config", "feeds.json"), cfg = readJson(cp, null), osint = readJson(join(DATA, "osint.json"), {}) || {};
  if (!cfg) { console.log("propose-feeds: config/feeds.json is missing or not JSON"); process.exit(1); }
  const p = feedProposals(osint.feeds, cfg);
  if (!p.watch.length && !p.retire.length) { console.log(`propose-feeds: no feed has failed for ${PROPOSE_DAYS} days`); return; }
  cfg.watch = (cfg.watch || []).concat(p.watch);
  const gone = new Set(p.retire.map((r) => r.name.toLowerCase()));
  cfg.watch = cfg.watch.filter((w) => !gone.has(String(w.name).toLowerCase()));
  cfg.retired = (cfg.retired || []).concat(p.retire);
  writeFileSync(cp, JSON.stringify(cfg, null, 1) + "\n");
  console.log(`propose-feeds: ${p.watch.length} to the watch list (${p.watch.map((x) => x.name).join(", ") || "none"}), ${p.retire.length} retired (${p.retire.map((x) => x.name).join(", ") || "none"})`);
  if (process.argv.includes("--pr")) import("./propose.mjs").then((m) => console.log(m.propose("pipecheck").msg));
}

async function main() {
  const cmd = process.argv[2] && !process.argv[2].startsWith("--") ? process.argv[2] : "check";
  if (cmd === "heal") return heal();
  if (cmd === "alerts") return alerts();
  if (cmd === "propose-feeds") return proposeFeeds();
  if (cmd !== "check") { console.error("usage: pipecheck.mjs [check|heal|alerts|propose-feeds [--pr]] [--json]"); process.exit(1); }
  const q = await check();
  if (process.argv.includes("--json")) { console.log(JSON.stringify(q)); return; }
  const real = q.problems.filter((p) => p.level !== "info");
  console.log(`PIPECHECK: ${real.length ? real.length + " problem(s)" : "healthy"}; ${q.stages.filter((s) => s.state === "ok").length} of ${q.stages.length} stages on time; status.json ${q.status_key_count} keys`);
  for (const s of q.stages) console.log(`  ${s.state.padEnd(5)} ${s.key.padEnd(14)} ${s.last_at ? ago(s.age_min) : "never"} (limit ${lim(s.max_min)})`);
  for (const p of q.problems) console.log(`${p.level}${p.over ? " ALERT" : ""}: ${p.text}`);
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
