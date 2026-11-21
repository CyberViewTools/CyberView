// The research backlog, kept at zero by rule and by assignment. No AI model. Run: node scripts/backlog.mjs <command>
// A story the collectors found is "backlog" until it is an event, an update to one, or closed with a reason.
// Left alone, weak stories simply expired unread after 72 hours while the count sat in the hundreds.
//   status [--json]   how many stories are waiting, by kind, and how old the oldest is (the status page and the guard read this)
//   auto              closes what a rule can decide without reading anything: routine bulletins with no sign of exploitation,
//                     commentary, bare database rows, and reports published more than six days ago. Safe to run every collection.
//   plan [--per 40]   splits every remaining story into batches for the backlog triagers (data/backlog-plan.json, working file)
//   apply [--per 8]   after the triagers: closes what they rejected (with their reasons) and writes the researchers' plan
//                     (data/sweep-plan.json, the same file the sweep uses, so job-prompt.mjs researcher --batch N works)
// Nothing here writes or changes an event: it only closes stories with a logged reason, or assigns them.
import { deepReason } from "./lib/routing.mjs";
import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { DATA, readJson, writeJson, writeRunLog, nowIso } from "./lib/store.mjs";
import { build, isOpen } from "./fuse.mjs";

const ROWS = ["cve", "breach-db", "status"];
/** Pure: why a rule can close this story without anyone reading it, or "" when a person or agent has to look. */
export function autoReason(s, now = Date.now()) {
  if (s.claim_only) return "";                                                    // leak-site claims are their own queue
  if (s.kinds.includes("exploited") || s.publishers >= 3) return "";              // never by rule: exploited flaws and well-reported stories
  const ageH = (now - Date.parse(s.published)) / 36e5;
  if (s.dated && ageH > 6 * 24) return "published more than six days ago: older than the map window";
  if (s.explainer) return "commentary, advice or an explainer, not an event";
  if (s.leads.length && s.leads.every((l) => ROWS.includes(l.kind))) return "a bare database row with no report of exploitation";
  if (s.routine && !s.tiers.includes("gov")) return "a routine vendor bulletin with no sign of exploitation";
  if (s.routine && s.publishers <= 1 && !s.incident) return "a routine advisory repeated by one agency, with no sign of exploitation";
  // the owner's rule (2026-11-19): agents read incidents, exploited flaws, official sources and anything two publishers report;
  // a single news item whose headline reports nothing that happened is closed here, at once, with this reason
  // English headlines only: the word lists cannot judge other languages, and those are where coverage is thinnest
  if (s.publishers <= 1 && !s.eventlike && s.langs.every((l) => !l || l === "en") && !s.tiers.some((t) => t === "gov" || t === "vendor")) return "a single-source item whose headline reports no incident, exploitation or official action";
  return "";
}
/** Pure: "already on file: <event id>" for a story fuse.mjs matched to an event while some of its leads are still unlogged, else "". */
export const onFile = (s) => s.event && s.open > 0 && !s.claim_only ? `already on file: ${s.event}` : "";
/** Pure: the stories that still need a decision, strongest and newest first, incidents before everything else. */
export function backlog(stories, now = Date.now()) {
  return stories.filter((s) => isOpen(s) && !s.claim_only && !autoReason(s, now))
    .sort((a, b) => (b.incident - a.incident) || b.score - a.score || (a.published < b.published ? 1 : -1));
}
/** Pure: the numbers the status page and the guard show. */
export function summary(stories, now = Date.now()) {
  const open = stories.filter(isOpen), work = backlog(stories, now), ages = work.map((s) => (now - Date.parse(s.waiting_since || s.first_seen)) / 36e5).filter(isFinite);
  return { at: new Date(now).toISOString().replace(/\.\d+Z$/, "Z"), waiting: work.length, incidents: work.filter((s) => s.incident).length, strong: work.filter((s) => s.score >= 12).length,
    closable_by_rule: open.filter((s) => autoReason(s, now)).length, claims: open.filter((s) => s.claim_only).length, oldest_hours: ages.length ? Math.round(Math.max(...ages)) : 0,
    oldest_incident_hours: Math.round(Math.max(0, ...work.filter((s) => s.incident).map((s) => (now - Date.parse(s.waiting_since || s.first_seen)) / 36e5).filter(isFinite))) };
}
const closeAll = (job, items) => items.length ? writeRunLog(job, { started_at: nowIso(), finished_at: nowIso(), model: null,
  skipped: items.flatMap(({ s, why }) => s.urls.slice(0, 40).map((u) => ({ title: String(s.title).slice(0, 120), url: u, reason: `story ${s.id}: ${why}`.slice(0, 220) }))) }) : null;
const answerFiles = () => existsSync(DATA) ? readdirSync(DATA).filter((f) => /^backlog-triage-\d+\.json$/.test(f)) : [];
/** Every triage answer on disk, by story id: "" = keep, otherwise the reason to close. A keep always wins over a close. */
function answers() {
  const m = new Map();
  for (const f of answerFiles()) { const r = readJson(join(DATA, f), null); if (!r) continue;
    (r.close || []).forEach((c) => { if (c && c.id && !m.has(String(c.id))) m.set(String(c.id), String(c.reason || "").replace(/\s+/g, " ").trim().slice(0, 160)); });
    (r.keep || []).forEach((id) => m.set(String(id && id.id || id), "")); }
  return m;
}
const opt = (name, def) => { const i = process.argv.indexOf("--" + name); return i > 0 ? process.argv[i + 1] : def; };

function main() {
  const cmd = process.argv[2] || "status", d = build();
  if (cmd === "status") {
    const s = summary(d.stories);
    if (process.argv.includes("--json")) { console.log(JSON.stringify(s)); return; }
    console.log(`BACKLOG: ${s.waiting} stories need a decision (${s.incidents} read like incidents, ${s.strong} strong); oldest ${s.oldest_hours} h. ${s.closable_by_rule} more can be closed by rule (run: backlog.mjs auto). ${s.claims} leak-site claims are tracked separately.`);
    return;
  }
  if (cmd === "auto") {
    // a story that matched an event on file (same words, same CVE, or a name only that event has, in any language) is
    // closed with that event's id: its new pages still reach an updater through scripts/updates.mjs, which matches the same way
    const items = d.stories.filter(isOpen).map((s) => ({ s, why: autoReason(s) })).filter((x) => x.why)
      .concat(d.stories.filter((s) => onFile(s)).map((s) => ({ s, why: onFile(s) })));
    closeAll("backlog-auto", items);
    const by = {}; items.forEach((x) => { by[x.why] = (by[x.why] || 0) + 1; });
    console.log(`BACKLOG AUTO: closed ${items.length} stories by rule.` + Object.entries(by).map(([k, n]) => `\n  ${n}  ${k}`).join(""));
    return;
  }
  if (cmd === "plan") {
    // stories an earlier triage already answered or kept are not sorted twice
    const kept = new Set(readJson(join(DATA, "backlog-kept.json"), { ids: [] }).ids || []), answered = new Set(answers().keys());
    const per = Math.max(10, Math.min(60, Number(opt("per", 40)))), max = Number(opt("max", 0)) || Infinity, all = backlog(d.stories);
    const ready = all.filter((s) => kept.has(s.id) || answered.has(s.id)), work = all.filter((s) => !kept.has(s.id) && !answered.has(s.id)).slice(0, max * per), batches = [];
    for (let i = 0; i < work.length; i += per) batches.push(work.slice(i, i + per).map((s) => ({ id: s.id, title: String(s.title).slice(0, 160), score: s.score, publishers: s.publishers,
      sources: [...new Set(s.leads.map((l) => l.source))].slice(0, 4), tiers: s.tiers, kinds: s.kinds, langs: s.langs, published: s.published, dated: s.dated, incident: s.incident })));
    writeJson(join(DATA, "backlog-plan.json"), { planned_at: nowIso(), batches });
    console.log(`BACKLOG PLAN: ${all.length} waiting; ${ready.length} already sorted by an earlier triage; ${work.length} to sort in ${batches.length} triage batch(es) of up to ${per}.`);
    return;
  }
  if (cmd === "apply") {
    // answers are matched by story id from every answers file, so a re-plan or a late triager can never lose or misplace one
    const per = Math.max(3, Math.min(12, Number(opt("per", 8)))), maxB = process.argv.includes("--hold") ? 0 : (Number(opt("max", 0)) || Infinity);
    const ans = answers(), close = [], keep = [], open = backlog(d.stories);
    open.forEach((s) => { if (!ans.has(s.id)) return;                               // nobody has looked at it yet: it stays in the queue
      const why = ans.get(s.id);
      if (why.length >= 8 && !s.kinds.includes("exploited") && s.publishers < 3) close.push({ s, why: "triage: " + why }); else keep.push(s); });
    closeAll("backlog-triage", close);
    const byId = new Map(d.stories.map((s) => [s.id, s]));
    const prev = (readJson(join(DATA, "backlog-kept.json"), { ids: [] }).ids || []).map((id) => byId.get(id)).filter((s) => s && isOpen(s) && !keep.includes(s) && !autoReason(s));
    const queue = prev.concat(keep).sort((a, b) => (b.incident - a.incident) || b.score - a.score), now = queue.slice(0, maxB * per), later = queue.slice(maxB * per);
    const stories = now.map((s, i) => ({ id: s.id, title: s.title, score: s.score, batch: Math.floor(i / per) + 1, urls: s.urls, ...(deepReason(s) ? { deep: deepReason(s) } : {}) })), nb = Math.ceil(now.length / per);
    if (maxB) writeJson(join(DATA, "sweep-plan.json"), { planned_at: nowIso(), backlog: true, stories });
    writeJson(join(DATA, "backlog-kept.json"), { at: nowIso(), ids: later.map((s) => s.id) });
    for (const f of answerFiles()) writeJson(join(DATA, f), { keep: [], close: [], applied_at: nowIso() });   // used: never applied twice
    const untouched = open.length - close.length - keep.length;
    console.log(`BACKLOG APPLY: ${close.length} closed on the triagers' reasons; ${queue.length} worth research, ${now.length} assigned now in ${nb} researcher batch(es) of up to ${per}${later.length ? `, ${later.length} held for the next step` : ""}; ${untouched} not sorted yet.`);
    console.log(`RESEARCHER BATCHES: ${nb ? Array.from({ length: nb }, (_, i) => i + 1).join(" ") : "none"}`);
    return;
  }
  console.error("usage: backlog.mjs status [--json] | auto | plan [--per 40] | apply [--per 8]"); process.exit(1);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
