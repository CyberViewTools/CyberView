// Mechanical lead triage, no AI model. Run: node scripts/triage.mjs [--dry-run]
// Clears leads the AI jobs would only throw away, and logs each one with its reason in a run log
// (data/runs/<date>/<HHMM>-triage.json, "skipped"), which is how q.mjs leads already hides handled leads:
//   1. already on file: the title strongly matches an event from the last 30 days (same words or same CVE)
//   2. not an event: webinars, podcasts, sponsored posts, round-ups, how-to guides, job posts
//   3. expired: published more than 6 days ago, too old for the seven-day map
// Conservative on purpose: anything uncertain stays open for the triage desk and the sweep.
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { DATA, readJson, listEventFiles, dayAgo, writeRunLog, nowIso } from "./lib/store.mjs";

const STOP = new Set("the a an of in on to for and or by with from at as is was are be its it this that new after over into says said us uk how why what".split(" "));
export const tokens = (s) => new Set(String(s || "").toLowerCase().replace(/[^a-z0-9-]+/g, " ").split(" ").filter((w) => w.length > 2 && !STOP.has(w)));
export const NOT_EVENT = /\b(\d+ (steps|ways|tips|things|lessons)|webinar|podcast|episode|sponsored|partner content|week in review|weekly recap|this week in|newsletter|round-?up|how to|tips for|best practices|buyer'?s guide|explained|what is|deal|discount|% off|hiring|job opening|career|interview with|q&a|book review|top \d+|ebook|whitepaper download|register now|save the date)\b/i;

/** Strong match only: most of the lead's words appear in one event, or they share a CVE. */
export function matchEvent(title, evs) {
  const q = tokens(title);
  if (q.size < 3) return null;
  let best = null;
  for (const e of evs) {
    const t = e._tok || (e._tok = tokens(`${e.title} ${e.org || ""} ${(e.cves || []).join(" ")} ${e.actor || ""}`));
    let inter = 0; q.forEach((w) => t.has(w) && inter++);
    const cve = [...q].some((w) => /^cve-\d{4}-\d+$/.test(w) && t.has(w));
    const score = inter / Math.min(q.size, t.size || 1);
    if (cve || score >= 0.75) { if (!best || score > best.score) best = { id: e.id, score: cve ? 2 : score }; }
  }
  return best;
}

/** Reason to clear a lead, or "" to leave it open. */
export function reason(lead, evs, today = new Date().toISOString().slice(0, 10)) {
  const t = String(lead.title || "");
  if (NOT_EVENT.test(t)) return "not an event (webinar, promotion, round-up or guide)";
  const pub = String(lead.published || lead.seen_at || "").slice(0, 10);
  if (/^\d{4}-\d{2}-\d{2}$/.test(pub) && pub < new Date(Date.parse(today) - 6 * 864e5).toISOString().slice(0, 10)) return "expired: published more than 6 days ago";
  const m = matchEvent(t, evs);
  return m ? `already on file as ${m.id}` : "";
}

function openFeedLeads() {
  const used = new Set(), rejected = new Set();
  const evs = listEventFiles().map((f) => f.e).filter((e) => e && !e.duplicate_of);
  evs.forEach((e) => (e.sources || []).forEach((s) => used.add(s.url)));
  const runsDir = join(DATA, "runs");
  if (existsSync(runsDir)) for (const d of readdirSync(runsDir).filter((d) => d >= dayAgo(14)))
    for (const f of readdirSync(join(runsDir, d))) (readJson(join(runsDir, d, f), {}).skipped || []).forEach((l) => l && l.url && rejected.add(l.url));
  const out = [], dir = join(DATA, "leads");
  if (existsSync(dir)) for (const f of readdirSync(dir).filter((f) => f.endsWith(".jsonl") && f.slice(0, 10) >= dayAgo(10)))
    for (const line of readFileSync(join(dir, f), "utf8").split("\n")) {
      try { const l = JSON.parse(line); if (l.url && !used.has(l.url) && !rejected.has(l.url)) out.push(l); } catch {}
    }
  return { leads: [...new Map(out.map((l) => [l.url, l])).values()], evs: evs.filter((e) => e.date >= dayAgo(30)) };
}

async function main() {
  const dry = process.argv.includes("--dry-run");
  const { leads, evs } = openFeedLeads();
  const skipped = [];
  for (const l of leads) { const r = reason(l, evs); if (r) skipped.push({ title: String(l.title).slice(0, 200), url: l.url, reason: r }); }
  const by = (k) => skipped.filter((s) => s.reason.startsWith(k)).length;
  console.log(`triage: ${leads.length} open feed leads; cleared ${skipped.length} (already on file ${by("already")}, not events ${by("not an event")}, expired ${by("expired")}); ${leads.length - skipped.length} left for the desks`);
  if (!dry && skipped.length) writeRunLog("triage", { started_at: nowIso(), finished_at: nowIso(), model: null, skipped, open_left: leads.length - skipped.length });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
