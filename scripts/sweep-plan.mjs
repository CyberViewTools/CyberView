// Sweep plan and scorecard, no AI model. Run: node scripts/sweep-plan.mjs [plan|check]
// The sweep used to decide for itself how much to look at, and looked at very little. Now the work is assigned and counted:
//   plan    picks this run's stories by rule and splits them into researcher batches (data/sweep-plan.json, working file):
//           every story scoring 12 or more, then the strongest by score, up to researchers x stories_per_researcher
//           (config/pipeline.json),
//           always including the 4 strongest from thinly covered regions or non-English sources; stories that need
//           judgment go to deep batches (researcher-deep, Opus), the rest to routine ones (scripts/lib/routing.mjs)
//   check   after the researchers finish: how many of the planned stories became events or were closed with a reason,
//           which were left untouched, and what was added; exit 1 if fewer than 80% were handled
import { leased } from "./lib/lease.mjs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { DATA, ROOT, readJson, writeJson, nowIso, listEventFiles, readStatus } from "./lib/store.mjs";
import { build, isOpen } from "./fuse.mjs";
import { backlog } from "./backlog.mjs";
import { deepReason } from "./lib/routing.mjs";

const cfg = (readJson(join(ROOT, "config", "pipeline.json"), {}).sweep) || {};
// the cap on researchers per run (sweep.researchers) is the owner's dial; the code allows up to 16 (owner, 2026-11-21: "use
// whatever it needs", the usage stop level is the only protection left)
export const PER = Math.max(2, Math.min(12, Number(cfg.stories_per_researcher) || 6)), BATCHES = Math.max(1, Math.min(16, Number(cfg.researchers) || 2)), MAX_STORIES = BATCHES * PER, THIN = ["africa", "latin-america", "middle-east", "south-asia", "southeast-asia"];

/** Pure: open stories (already sorted strongest first) -> the stories to work this run. */
export function pick(stories, max = MAX_STORIES) {
  const open = stories.filter((s) => isOpen(s) && !s.claim_only), chosen = new Map();
  const take = (s, why) => { if (chosen.size < max && !chosen.has(s.id)) chosen.set(s.id, { ...s, picked: why }); };
  open.filter((s) => s.regions.some((r) => THIN.includes(r)) && s.regions.every((r) => THIN.includes(r) || r === "") || s.langs.some((l) => l && l !== "en")).slice(0, 4).forEach((s) => take(s, "thin region or non-English"));
  open.filter((s) => s.score >= 12).forEach((s) => take(s, "score 12 or more"));
  open.forEach((s) => take(s, "next strongest"));
  return [...chosen.values()].sort((a, b) => b.score - a.score);
}
/** Pure: does a story read like an incident or an exploited flaw? When the plan's usage is tight (scripts/lib/usage.mjs)
 *  the research loop plans only these (`plan --urgent`); the rest wait in the queue for the next normal cycle. */
export const urgent = (s) => !!(s && (s.incident || (s.kinds || []).includes("exploited")));
/** Pure: deal stories round-robin so every researcher gets a mix of strong and weak. */
export function split(stories, n = BATCHES) {
  const k = Math.max(1, Math.min(n, Math.ceil(stories.length / 3))), out = Array.from({ length: k }, () => []);
  stories.forEach((s, i) => out[i % k].push(s));
  return out.filter((b) => b.length);
}
/** Pure: the run's batches with each one's model route (scripts/lib/routing.mjs). Stories that need judgment (incidents,
 *  exploited flaws, official reports, two or more publishers) are dealt to deep batches (role researcher-deep, Opus), the
 *  rest to routine batches (role researcher, Sonnet), never mixed, so the expensive model reads only what needs it. At most
 *  n batches in all; each kind gets at least one batch when it has stories. -> [{deep, stories}] (deep batches first). */
export function route(stories, n = BATCHES, per = PER) {
  const deep = stories.filter((s) => deepReason(s)), plain = stories.filter((s) => !deepReason(s));
  let kd = deep.length ? Math.ceil(deep.length / per) : 0, kp = plain.length ? Math.ceil(plain.length / per) : 0;
  while (kd + kp > Math.max(1, n) && (kd > 1 || kp > 1)) { if (kd >= kp && kd > 1) kd--; else kp--; }
  return [...(kd ? split(deep, kd).map((b) => ({ deep: true, stories: b })) : []), ...(kp ? split(plain, kp).map((b) => ({ deep: false, stories: b })) : [])];
}
/** Pure: plan + current stories + events -> scorecard. */
export function score(plan, stories, events) {
  const now = new Map(stories.map((s) => [s.id, s])), urlsUsed = new Set(events.flatMap((e) => (e.sources || []).map((s) => s.url)));
  const rows = plan.stories.map((p) => {
    const s = now.get(p.id);
    // a story is handled when none of its leads is open any more (each is an event source or logged with a reason), or it matched an event
    const handled = !s || !isOpen(s) || (p.urls || []).some((u) => urlsUsed.has(u));
    return { id: p.id, title: p.title, score: p.score, batch: p.batch, handled };
  });
  const added = events.filter((e) => String(e.first_seen || "") >= plan.planned_at && !e.duplicate_of).map((e) => e.id);
  const done = rows.filter((r) => r.handled).length;
  return { planned: rows.length, handled: done, share: rows.length ? done / rows.length : 1, untouched: rows.filter((r) => !r.handled), added };
}

function main() {
  const cmd = process.argv[2] || "plan", pp = join(DATA, "sweep-plan.json");
  const d = build();
  if (cmd === "plan") {
    // the queue is what still needs a decision after the rules (scripts/backlog.mjs); researchers scale with it, up to the cap
    const only = process.argv.includes("--urgent");
    const all = backlog(d.stories), held = leased("story", all.map((s) => s.id), process.env.CYBERVIEW_RUN || ""), queue = all.filter((s) => !held.has(s.id)), chosen = pick(only ? queue.filter(urgent) : queue), routed = chosen.length ? route(chosen, Math.max(1, Math.min(BATCHES, Math.ceil(chosen.length / PER) + 1))) : [], batches = routed.map((r) => r.stories);
    // deep: the batch numbers whose researcher runs as researcher-deep (scripts/run-job.mjs researcherRole)
    const plan = { planned_at: nowIso(), deep: routed.map((r, i) => (r.deep ? i + 1 : 0)).filter(Boolean), stories: batches.flatMap((b, i) => b.map((s) => ({ id: s.id, title: s.title, score: s.score, batch: i + 1, urls: s.urls, ...(routed[i].deep ? { deep: deepReason(s) } : {}) }))) };
    writeJson(pp, plan);
    console.log(`SWEEP PLAN: ${chosen.length} stories for ${batches.length} researcher(s), ${plan.deep.length} on the deep model${only ? " (usage tight: incidents and exploited flaws only)" : ""}; ${queue.length} waiting for a decision${queue.length > chosen.length ? ` (${queue.length - chosen.length} over this run's cap wait for the next run, 15 minutes)` : ""}.`);
    batches.forEach((b, i) => { console.log(`\nRESEARCHER ${i + 1}${routed[i].deep ? " (deep)" : ""} (${b.length} stories):`); b.forEach((s) => console.log(`  ${s.id}  [${s.score}] ${s.title.slice(0, 96)}  (${s.publishers} publisher${s.publishers === 1 ? "" : "s"}${s.langs.filter((l) => l !== "en").length ? ", " + s.langs.join("/") : ""}; ${s.picked}${routed[i].deep ? "; " + deepReason(s) : ""})`)); });
    if (!chosen.length) console.log("Nothing strong is waiting: a quiet hour. Do the gap pass only.");
    return;
  }
  if (cmd === "check") {
    const plan = readJson(pp, null); if (!plan) { console.error("no plan: run `node scripts/sweep-plan.mjs plan` first"); process.exit(1); }
    const r = score(plan, d.stories, listEventFiles().map((f) => f.e).filter(Boolean));
    console.log(`SWEEP SCORECARD: ${r.handled} of ${r.planned} planned stories handled (${Math.round(r.share * 100)}%); ${r.added.length} event(s) added since the plan: ${r.added.slice(0, 20).join(", ") || "none"}`);
    r.untouched.forEach((u) => console.log(`  NOT HANDLED (researcher ${u.batch}): ${u.id}  [${u.score}] ${u.title.slice(0, 90)}`));
    const sp = join(DATA, "status.json"), st = readStatus(); Object.assign(st, { sweep_planned: r.planned, sweep_handled: r.handled }); writeJson(sp, st);
    if (r.planned && r.share < 0.8) { console.log("Below 80%: assign the stories marked NOT HANDLED to researchers again, then run check once more."); process.exit(1); }
    return;
  }
  if (cmd === "retry") {   // mark the stories still open so one more researcher can take them (job-prompt.mjs researcher --batch retry)
    const plan = readJson(pp, null); if (!plan) process.exit(1);
    const r = score(plan, d.stories, listEventFiles().map((f) => f.e).filter(Boolean));
    plan.retry = r.untouched.map((u) => u.id).slice(0, 8); writeJson(pp, plan);
    console.log(`retry: ${plan.retry.length} stories assigned to one more researcher`); return;
  }
  console.error("usage: sweep-plan.mjs plan | check | retry"); process.exit(1);
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
