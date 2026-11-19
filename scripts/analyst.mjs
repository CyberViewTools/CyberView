// The exploit analyst's work queue. No AI model. Run: node scripts/analyst.mjs <command>
// Every flaw in the workbench gets an exploitation analysis: how attackers use it (advisory level, never code) and the
// remediation path. This script decides which flaws need one and splits them between analyst workers.
//   queue [--json]              flaws without a current analysis, most urgent first
//   plan [--workers 2 --per 3]  writes data/analyst-plan.json (working file) for job-prompt.mjs exploit-analyst --batch N
//   status                      one line for the status page and the dispatcher
// An analysis is current for 30 days, or until the flaw is added to CISA's catalog after it was written.
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { DATA, readJson, writeJson, listDir, listEventFiles, nowIso, dayAgo } from "./lib/store.mjs";

const isCve = (c) => /^CVE-\d{4}-\d{4,}$/.test(c || "");
/** Pure: the flaws to analyse, most urgent first. kev: catalog entries; vulns: [{cve, ...}] from severe events; done: {cve: analysis}. */
export function queue(kev, vulns, done, today = new Date().toISOString().slice(0, 10)) {
  const stale = (cve, changed) => { const a = done[cve]; if (!a) return true; const at = String(a.analyzed_at || "").slice(0, 10); return at < dayAgo(30) || (changed && at < changed); };
  const left = (k) => k.due ? Math.round((Date.parse(k.due) - Date.parse(today)) / 864e5) : 999;
  const k = kev.filter((x) => isCve(x.cve) && x.added >= dayAgo(45) && stale(x.cve, x.added))
    .map((x) => ({ cve: x.cve, kev: true, vendor: x.vendor || "", product: x.product || "", name: x.name || "", why: [x.ransomware ? "used in ransomware" : "", "known exploited", x.due ? `federal deadline ${x.due}` : ""].filter(Boolean).join("; "),
      // newest additions and approaching deadlines first; flaws used in ransomware above all; long-overdue ones still come, later
      rank: (x.ransomware ? 1000 : 0) + (x.added >= dayAgo(3) ? 600 : x.added >= dayAgo(7) ? 400 : x.added >= dayAgo(14) ? 200 : 0) + (left(x) >= 0 && left(x) <= 14 ? 300 - left(x) * 10 : left(x) < 0 ? 50 : 0) + Math.round((x.epss || 0) * 100), refs: (x.refs || []).slice(0, 4), desc: x.desc || "", required: x.required || "" }));
  const inK = new Set(k.map((x) => x.cve).concat(kev.map((x) => x.cve)));
  const v = vulns.filter((x) => isCve(x.cve) && !inK.has(x.cve) && stale(x.cve)).map((x) => ({ ...x, kev: false, rank: x.rank || 0 }));
  return k.sort((a, b) => b.rank - a.rank).concat(v.sort((a, b) => b.rank - a.rank));
}
function load() {
  const kev = listDir("kev").filter((x) => x.r).map((x) => x.r), done = {};
  listDir("analyses").filter((x) => x.r).forEach((x) => { done[x.id] = x.r; });
  const seen = new Set(), vulns = [];
  for (const e of listEventFiles().map((f) => f.e).filter((e) => e && !e.duplicate_of && e.category === "vuln" && e.status !== "claimed" && e.severity >= 3 && e.date >= dayAgo(30)).sort((a, b) => (a.date < b.date ? 1 : -1)))
    for (const c of (e.cves || []).slice(0, 4)) if (isCve(c) && !seen.has(c)) { seen.add(c);
      vulns.push({ cve: c, vendor: e.org || "", product: (e.products || []).join(", "), name: e.title, why: "severity 3 on the map" + (/exploit/i.test(`${e.title} ${e.summary}`) ? "; exploitation or exploit code reported" : ""), rank: /exploit/i.test(`${e.title} ${e.summary}`) ? 50 : 10, refs: (e.sources || []).map((s) => s.url).slice(0, 3), desc: e.plain || e.summary || "", required: e.action || "", event: e.id }); }
  return { kev, vulns, done };
}
const opt = (n, d) => { const i = process.argv.indexOf("--" + n); return i > 0 ? Number(process.argv[i + 1]) || d : d; };

function main() {
  const cmd = process.argv[2] || "status", d = load(), q = queue(d.kev, d.vulns, d.done);
  if (cmd === "status") { console.log(`ANALYST: ${Object.keys(d.done).length} flaws analysed; ${q.length} waiting (${q.filter((x) => x.kev).length} known exploited).`); return; }
  if (cmd === "queue") { if (process.argv.includes("--json")) console.log(JSON.stringify(q)); else q.slice(0, 40).forEach((x) => console.log(`${x.cve}  ${x.vendor} ${x.product}  (${x.why})`)); return; }
  if (cmd === "plan") {
    const W = Math.max(1, Math.min(6, opt("workers", 2))), per = Math.max(1, Math.min(6, opt("per", 3))), take = q.slice(0, W * per), batches = [];
    for (let i = 0; i < take.length; i += per) batches.push(take.slice(i, i + per));
    writeJson(join(DATA, "analyst-plan.json"), { planned_at: nowIso(), batches });
    console.log(`ANALYST PLAN: ${take.length} flaw(s) for ${batches.length} analyst(s); ${q.length - take.length} more wait for the next run.`);
    return;
  }
  console.error("usage: analyst.mjs status | queue [--json] | plan [--workers N --per K]"); process.exit(1);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
