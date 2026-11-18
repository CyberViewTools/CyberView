// Search the whole CyberView history without reading files into context. One short line per result.
// Jobs use this instead of opening event files: it is cheaper, and it covers every month on file.
//
//   node scripts/q.mjs find [text] [--since YYYY-MM-DD] [--until YYYY-MM-DD] [--cat vuln] [--sev 3] [--status claimed]
//                         [--cve CVE-2026-1] [--org name] [--country name] [--tag ransomware] [--actor name] [--limit 25]
//   node scripts/q.mjs dupes "<title or org and what happened>"   likely duplicates, best first (run before adding an event;
//                         a score of 1 or more is almost certainly the same event, 0.5 to 1 needs a look)
//   node scripts/q.mjs get <id> [--fields title,summary,sources]  one event (all fields, or only those listed)
//   node scripts/q.mjs seen <url>          was this URL already used as a source or read in a past run?
//   node scripts/q.mjs leads [--days 7]    leads past runs found but did not write up (open_leads and skipped items)
//   node scripts/q.mjs runs [--days 2]     what each job run did
//   node scripts/q.mjs kev [text] [--since YYYY-MM-DD]   known-exploited entries
//   node scripts/q.mjs stats               counts by month and category
//   add --json to find/kev/leads for machine-readable output
import { join } from "node:path";
import { existsSync, readdirSync } from "node:fs";
import { DATA, readJson, listEventFiles, listDir, dayAgo } from "./lib/store.mjs";

const argv = process.argv.slice(2), cmd = argv[0] || "help";
const flags = {}, words = [];
for (let i = 1; i < argv.length; i++) {
  if (argv[i].startsWith("--")) { const k = argv[i].slice(2); flags[k] = argv[i + 1] && !argv[i + 1].startsWith("--") ? argv[++i] : true; }
  else words.push(argv[i]);
}
const text = words.join(" ").toLowerCase();
const limit = Number(flags.limit || 25);
const cut = (s, n) => { s = String(s || "").replace(/\s+/g, " "); return s.length > n ? s.slice(0, n - 1) + "…" : s; };
const has = (v, needle) => String(v || "").toLowerCase().includes(String(needle).toLowerCase());
const STOP = new Set("the a an of in on to for and or by with from at as is was are be its it this that new after over into says said us uk".split(" "));
const tokens = (s) => new Set(String(s || "").toLowerCase().replace(/[^a-z0-9-]+/g, " ").split(" ").filter((w) => w.length > 2 && !STOP.has(w)));
const events = () => listEventFiles().filter((x) => x.e).map((x) => x.e);
const line = (e) => `${e.date} ${String(e.category).padEnd(11)} s${e.severity} ${e.status === "claimed" ? "claimed " : ""}${e.id} | ${cut(e.title, 110)}${e.duplicate_of ? " [duplicate of " + e.duplicate_of + "]" : ""}`;
function runs(days) {
  const dir = join(DATA, "runs"); if (!existsSync(dir)) return [];
  return readdirSync(dir).filter((d) => d >= dayAgo(days)).sort().flatMap((d) =>
    readdirSync(join(dir, d)).sort().map((f) => ({ day: d, file: f, r: readJson(join(dir, d, f), {}) })));
}

if (cmd === "find") {
  let list = events().filter((e) =>
    (!text || [e.title, e.summary, e.org, e.actor, e.country, e.place, (e.cves || []).join(" "), (e.products || []).join(" "), (e.tags || []).join(" ")].some((v) => has(v, text))) &&
    (!flags.since || e.date >= flags.since) && (!flags.until || e.date <= flags.until) &&
    (!flags.cat || e.category === flags.cat) && (!flags.sev || e.severity === Number(flags.sev)) &&
    (!flags.status || e.status === flags.status) && (!flags.cve || (e.cves || []).some((c) => has(c, flags.cve))) &&
    (!flags.org || has(e.org, flags.org)) && (!flags.country || has(e.country, flags.country)) &&
    (!flags.tag || (e.tags || []).includes(flags.tag)) && (!flags.actor || has(e.actor, flags.actor)));
  list.sort((a, b) => (a.date < b.date ? 1 : -1));
  if (flags.json) console.log(JSON.stringify(list.slice(0, limit)));
  else { list.slice(0, limit).forEach((e) => console.log(line(e))); console.log(`(${list.length} match${list.length === 1 ? "" : "es"}${list.length > limit ? `, first ${limit} shown` : ""})`); }
} else if (cmd === "dupes") {
  const q = tokens(text); if (!q.size) { console.log("give a title or description"); process.exit(1); }
  const scored = events().map((e) => {
    const t = tokens(`${e.title} ${e.org} ${(e.cves || []).join(" ")} ${e.actor || ""}`);
    let inter = 0; q.forEach((w) => t.has(w) && inter++);
    const cveHit = [...q].some((w) => /^cve-/.test(w) && t.has(w));
    return { e, score: inter / Math.min(q.size, t.size || 1) + (cveHit ? 1 : 0) };
  }).filter((x) => x.score >= 0.5).sort((a, b) => b.score - a.score).slice(0, 8);
  if (!scored.length) console.log("no likely duplicates");
  scored.forEach((x) => console.log(`${x.score.toFixed(2)}  ${line(x.e)}`));
} else if (cmd === "get") {
  const x = listEventFiles().find((f) => f.id === words[0]);
  if (!x || !x.e) { console.log("not found: " + words[0]); process.exit(1); }
  const out = flags.fields ? Object.fromEntries(String(flags.fields).split(",").map((k) => [k, x.e[k]])) : x.e;
  console.log(JSON.stringify({ path: x.path.slice(DATA.length - 4), ...out }, null, 1));
} else if (cmd === "seen") {
  const u = words[0] || ""; const hits = [];
  events().forEach((e) => (e.sources || []).forEach((s) => s.url === u && hits.push(`source of ${e.id}`)));
  runs(60).forEach(({ day, file, r }) => JSON.stringify(r).includes(JSON.stringify(u).slice(1, -1)) && hits.push(`read in run ${day}/${file}`));
  console.log(hits.length ? hits.join("\n") : "not seen");
} else if (cmd === "leads") {
  const days = Number(flags.days || 7), stored = new Set(events().flatMap((e) => (e.sources || []).map((s) => s.url)));
  const leads = [];
  runs(days).forEach(({ day, file, r }) => {
    (r.open_leads || []).forEach((l) => leads.push({ from: `${day}/${file}`, ...l }));
    Object.values(r.lanes || {}).forEach((lane) => (lane && lane.skipped || []).forEach((l) => leads.push({ from: `${day}/${file}`, ...l })));
    (r.skipped || []).forEach((l) => leads.push({ from: `${day}/${file}`, ...l }));
  });
  const open = leads.filter((l) => !l.url || !stored.has(l.url));
  if (flags.json) console.log(JSON.stringify(open));
  else { open.forEach((l) => console.log(`${l.from} | ${cut(l.title, 90)} | ${l.url || ""} | ${cut(l.reason || l.note || "", 80)}`)); console.log(`(${open.length} open lead(s))`); }
} else if (cmd === "runs") {
  runs(Number(flags.days || 2)).forEach(({ day, file, r }) => console.log(`${day}/${file} | ${r.job} | added ${(r.added || r.kev_added || []).length} updated ${(r.updated || r.events_updated || []).length}${(r.failed || r.failed_sites || []).length ? " | failed: " + cut((r.failed || r.failed_sites).join(", "), 80) : ""}`));
} else if (cmd === "kev") {
  const list = listDir("kev").filter((x) => x.r).map((x) => x.r)
    .filter((k) => (!text || [k.cve, k.vendor, k.product, k.name].some((v) => has(v, text))) && (!flags.since || (k.added || "") >= flags.since))
    .sort((a, b) => (a.added < b.added ? 1 : -1));
  if (flags.json) console.log(JSON.stringify(list.slice(0, limit)));
  else { list.slice(0, limit).forEach((k) => console.log(`${k.added} due ${k.due} ${k.cve} | ${cut(k.vendor + " " + k.product, 50)}${k.ransomware ? " | ransomware" : ""} | cvss ${k.cvss ?? "-"} epss ${k.epss ?? "-"}`)); console.log(`(${list.length} entr${list.length === 1 ? "y" : "ies"})`); }
} else if (cmd === "stats") {
  const by = {};
  events().forEach((e) => { const m = String(e.date).slice(0, 7); (by[m] ||= { total: 0 }); by[m].total++; by[m][e.category] = (by[m][e.category] || 0) + 1; });
  Object.entries(by).sort().reverse().forEach(([m, c]) => console.log(`${m}  ${c.total} events  ` + Object.entries(c).filter(([k]) => k !== "total").map(([k, v]) => `${k} ${v}`).join(", ")));
} else {
  console.log(readFileSyncHelp());
}
function readFileSyncHelp() {
  return `CyberView history search. Commands: find, dupes, get, seen, leads, runs, kev, stats. See the top of scripts/q.mjs for options.`;
}
