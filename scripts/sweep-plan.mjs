// Sweep plan and scorecard, no AI model. Run: node scripts/sweep-plan.mjs [plan|check]
// The sweep used to decide for itself how much to look at, and looked at very little. Now the work is assigned and counted:
//   plan    picks this run's stories by rule and splits them into researcher batches (data/sweep-plan.json, working file):
//           every story scoring 12 or more, then the strongest by score, up to researchers x stories_per_researcher
//           (config/pipeline.json),
//           always including the 4 strongest from thinly covered regions or non-English sources
//   check   after the researchers finish: how many of the planned stories became events or were closed with a reason,
//           which were left untouched, and what was added; exit 1 if fewer than 80% were handled
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { DATA, ROOT, readJson, writeJson, nowIso, listEventFiles } from "./lib/store.mjs";
import { build, isOpen } from "./fuse.mjs";

const cfg = (readJson(join(ROOT, "config", "pipeline.json"), {}).sweep) || {};
export const BATCHES = Math.max(1, Math.min(4, Number(cfg.researchers) || 2)), MAX_STORIES = BATCHES * Math.max(2, Math.min(12, Number(cfg.stories_per_researcher) || 6)), THIN = ["africa", "latin-america", "middle-east", "south-asia", "southeast-asia"];

/** Pure: open stories (already sorted strongest first) -> the stories to work this run. */
export function pick(stories, max = MAX_STORIES) {
  const open = stories.filter((s) => isOpen(s) && !s.claim_only), chosen = new Map();
  const take = (s, why) => { if (chosen.size < max && !chosen.has(s.id)) chosen.set(s.id, { ...s, picked: why }); };
  open.filter((s) => s.regions.some((r) => THIN.includes(r)) && s.regions.every((r) => THIN.includes(r) || r === "") || s.langs.some((l) => l && l !== "en")).slice(0, 4).forEach((s) => take(s, "thin region or non-English"));
  open.filter((s) => s.score >= 12).forEach((s) => take(s, "score 12 or more"));
  open.forEach((s) => take(s, "next strongest"));
  return [...chosen.values()].sort((a, b) => b.score - a.score);
}
/** Pure: deal stories round-robin so every researcher gets a mix of strong and weak. */
export function split(stories, n = BATCHES) {
  const k = Math.max(1, Math.min(n, Math.ceil(stories.length / 3))), out = Array.from({ length: k }, () => []);
  stories.forEach((s, i) => out[i % k].push(s));
  return out.filter((b) => b.length);
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
    const chosen = pick(d.stories), batches = split(chosen);
    const plan = { planned_at: nowIso(), stories: batches.flatMap((b, i) => b.map((s) => ({ id: s.id, title: s.title, score: s.score, batch: i + 1, urls: s.urls }))) };
    writeJson(pp, plan);
    console.log(`SWEEP PLAN: ${chosen.length} stories for ${batches.length} researcher(s), out of ${d.stories.filter(isOpen).length} open.`);
    batches.forEach((b, i) => { console.log(`\nRESEARCHER ${i + 1} (${b.length} stories):`); b.forEach((s) => console.log(`  ${s.id}  [${s.score}] ${s.title.slice(0, 96)}  (${s.publishers} publisher${s.publishers === 1 ? "" : "s"}${s.langs.filter((l) => l !== "en").length ? ", " + s.langs.join("/") : ""}; ${s.picked})`)); });
    if (!chosen.length) console.log("Nothing strong is waiting: a quiet hour. Do the gap pass only.");
    return;
  }
  if (cmd === "check") {
    const plan = readJson(pp, null); if (!plan) { console.error("no plan: run `node scripts/sweep-plan.mjs plan` first"); process.exit(1); }
    const r = score(plan, d.stories, listEventFiles().map((f) => f.e).filter(Boolean));
    console.log(`SWEEP SCORECARD: ${r.handled} of ${r.planned} planned stories handled (${Math.round(r.share * 100)}%); ${r.added.length} event(s) added since the plan: ${r.added.slice(0, 20).join(", ") || "none"}`);
    r.untouched.forEach((u) => console.log(`  NOT HANDLED (researcher ${u.batch}): ${u.id}  [${u.score}] ${u.title.slice(0, 90)}`));
    const sp = join(DATA, "status.json"), st = readJson(sp, {}); Object.assign(st, { sweep_planned: r.planned, sweep_handled: r.handled }); writeJson(sp, st);
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
