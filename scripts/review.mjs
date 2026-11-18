// Second-pair-of-eyes review of new events, the mechanical half. No AI model. Run: node scripts/review.mjs <command>
// Every event is written by one agent. Before it is trusted it is reviewed by a different one (the review desk job).
// This script finds what needs review and does the checks a machine can do, so the reviewers spend their time on the
// checks only a reader can do (does the source really say this?).
//   node scripts/review.mjs queue [--limit 30] [--json]   events added or changed in the last 72 hours that have no review
//                                                         of their current version, highest risk first, each with its flags
//   node scripts/review.mjs flags <id>                    the mechanical flags for one event
//   node scripts/review.mjs pass <id> "<what was checked>"            reviewed against its sources; nothing wrong
//   node scripts/review.mjs corrected <id> "<what was wrong and is now fixed>"   reviewed; the reviewer fixed the record first
//   node scripts/review.mjs flagged <id> "<the problem>"             reviewed; a problem remains that the reviewer could not settle
// pass/corrected/flagged write the event's "review" {state, at, note, flags} and qa_checked_at; "flagged" also lowers
// validation to "disputed" so the site shows low confidence until the verify job settles it.
import { pathToFileURL } from "node:url";
import { listEventFiles, saveEvent, findEvent, nowIso, dayAgo } from "./lib/store.mjs";
import { tokens } from "./triage.mjs";

const REDIRECT = /^https?:\/\/(news\.google\.com|(www\.)?bing\.com|(www\.)?msn\.com\/[a-z-]+\/news\/other|t\.co|bit\.ly)\b/i;
const ATTACK = /\b(cyber ?attack|hack(ed|ers?)?|ransomware|breach(ed)?|intrusion|malware)\b/i;
const OFFICIAL = /\b(confirm(ed|s)?|said|stated|according to|official|attribut(ed|es))\b/i;

/** Mechanical flags for one event. evs: the other recent events, for duplicate suspicion. Returns [{code, text}]. */
export function flagsFor(e, evs = [], today = new Date().toISOString().slice(0, 10)) {
  const f = [], add = (code, text) => f.push({ code, text });
  const src = Array.isArray(e.sources) ? e.sources : [], hosts = new Set(src.map((s) => { try { return new URL(s.url).hostname.replace(/^www\./, ""); } catch { return ""; } }).filter(Boolean));
  if (!src.length) add("no-source", "no source at all");
  if (src.some((s) => REDIRECT.test(s.url || ""))) add("redirect-source", "a source is a search-engine or aggregator redirect, not the publisher's own page");
  if (src.some((s) => { try { const u = new URL(s.url); return (u.pathname === "/" || u.pathname === "") && !u.search; } catch { return true; } })) add("front-page-source", "a source is a front page, not a specific article");
  if (hosts.size <= 1 && e.severity >= 3 && e.status !== "official") add("single-source-high", "high severity resting on one publisher");
  if (e.validation && e.validation.state === "corroborated" && hosts.size <= 1 && e.source_tier !== "primary") add("corroborated-one-host", 'marked "corroborated" but every source is the same site');
  if (e.status === "claimed" && e.severity !== 1) add("claim-severity", "an unconfirmed claim must be severity 1");
  if (e.status === "claimed" && e.validation && e.validation.state === "corroborated") add("claim-corroborated", "a claim cannot be corroborated by more attacker posts");
  if (e.category === "outage" && ATTACK.test(`${e.title} ${e.summary || ""}`) && !/cyber cause:|not (a|an) (cyber ?)?attack|no evidence|ruled out|unknown cause/i.test(e.summary || "")) add("outage-as-attack", "an outage described with attack words: confirm an official source says so, or reword");
  if (e.category === "incident" && e.status === "confirmed" && !OFFICIAL.test(e.summary || "") && e.source_tier === "aggregator") add("confirmed-on-aggregator", '"confirmed" but the only sources are aggregators');
  if (e.severity >= 3 && e.category === "vuln" && !(e.cve_meta || []).some((c) => c && c.kev) && !/exploit|patch immediately|actively|critical|zero-day|public (poc|proof)/i.test(`${e.title} ${e.summary || ""} ${e.action || ""}`)) add("severity-3-reason", "severity 3 without exploitation, public exploit code or an official urgent notice in the text");
  if (e.actor && !e.attribution && !/claim|unattributed|unknown/i.test(e.actor) && e.status !== "claimed" && !/attribut|according to|said|linked/i.test(e.summary || "")) add("actor-unsourced", "an actor is named but the summary does not say who attributed it");
  if (e.records_affected && !String(e.summary || "").replace(/[,.\s]/g, "").includes(String(e.records_affected).slice(0, 2))) add("number-check", `records_affected ${e.records_affected} does not appear in the summary: confirm it against the source`);
  const fs = String(e.first_seen || "").slice(0, 10);
  if (/^\d{4}-\d{2}-\d{2}$/.test(fs) && e.date && (Date.parse(fs) - Date.parse(e.date)) / 864e5 > 7 && !e.date_note) add("old-date", "the event date is more than 7 days before it was added and there is no date_note");
  if (e.date > today) add("future-date", "the date is in the future");
  if (e.occurred_at && e.date && Math.abs(Date.parse(e.occurred_at) - Date.parse(e.date + "T12:00:00Z")) > 36 * 36e5) add("time-date-mismatch", "occurred_at is more than a day from date");
  for (const k of ["plain", "exec", "action", "summary"]) if (!String(e[k] || "").trim()) add("missing-" + k, `"${k}" is empty`);
  if (String(e.summary || "").trim().split(/\s+/).length > 75) add("long-summary", "summary over 75 words");
  if ((e.lat == null || e.lng == null) && e.pin_type !== "none" && e.country) add("no-pin", "has a country but no map position");
  if ((e.cves || []).length && !(e.cve_meta || []).length) add("no-cve-meta", "CVEs listed without cve_meta (the feeds job fills it; check the CVE ids are real)");
  if ((e.cves || []).some((c) => !/^CVE-\d{4}-\d{4,}$/.test(c))) add("bad-cve", "a CVE id is malformed");
  const q = tokens(`${e.title} ${e.org || ""}`);
  for (const o of evs) {
    if (o.id === e.id || o.duplicate_of || e.duplicate_of) continue;
    const t = o._tok || (o._tok = tokens(`${o.title} ${o.org || ""}`)); let inter = 0; q.forEach((w) => t.has(w) && inter++);
    const sameCve = (e.cves || []).length && (e.cves || []).every((c) => (o.cves || []).includes(c)) && e.category === o.category && e.org === o.org;
    if ((q.size >= 4 && inter / Math.min(q.size, t.size || 1) >= 0.8) || sameCve) { add("possible-duplicate", `looks like ${o.id}`); break; }
  }
  return f;
}

/** Risk order for the queue: high severity, more flags, serious flags first. */
export function risk(e, flags) {
  const serious = flags.filter((x) => /source|claim|outage-as-attack|actor|number|duplicate|severity-3|future/.test(x.code)).length;
  return e.severity * 10 + serious * 6 + flags.length * 2 + (e.status === "claimed" ? 3 : 0);
}
/** Does this event still need a review of its current version? */
export function needsReview(e) {
  if (e.duplicate_of) return false;
  if (!e.review || !e.review.at) return true;
  return Date.parse(e.updated_at) - Date.parse(e.review.at) > 10 * 6e4;   // changed more than 10 minutes after its review
}

function queue() {
  const all = listEventFiles().map((f) => f.e).filter((e) => e && !e.duplicate_of), recent = all.filter((e) => e.date >= dayAgo(30));
  return all.filter((e) => String(e.first_seen || e.updated_at || "") >= dayAgo(3) && needsReview(e))
    .map((e) => { const flags = flagsFor(e, recent); return { e, flags, risk: risk(e, flags) }; }).sort((a, b) => b.risk - a.risk);
}

function main() {
  const [cmd, id, ...rest] = process.argv.slice(2);
  if (cmd === "queue") {
    const q = queue(), li = process.argv.indexOf("--limit"), lim = li > 0 ? Number(process.argv[li + 1]) : 30;
    if (process.argv.includes("--json")) { console.log(JSON.stringify(q.slice(0, lim).map((x) => ({ id: x.e.id, severity: x.e.severity, status: x.e.status, category: x.e.category, title: x.e.title, flags: x.flags, sources: (x.e.sources || []).map((s) => s.url) })))); return; }
    console.log(`${q.length} event(s) waiting for a second review (added or changed in the last 72 hours). Highest risk first:`);
    q.slice(0, lim).forEach((x) => console.log(`[sev ${x.e.severity}${x.e.status === "claimed" ? " claim" : ""}] ${x.e.id}  ${String(x.e.title).slice(0, 90)}\n       ${x.flags.length ? "FLAGS: " + x.flags.map((f) => f.code).join(", ") : "no mechanical flags"}  |  ${(x.e.sources || []).length} source(s)`));
    return;
  }
  const f = id && findEvent(id);
  if (!f || !f.e) { console.error(cmd ? `no event "${id}"` : "usage: review.mjs queue | flags <id> | pass|corrected|flagged <id> \"<note>\""); process.exit(1); }
  const recent = listEventFiles().map((x) => x.e).filter((e) => e && !e.duplicate_of && e.date >= dayAgo(30));
  if (cmd === "flags") { const fl = flagsFor(f.e, recent); console.log(fl.length ? fl.map((x) => `${x.code}: ${x.text}`).join("\n") : "no mechanical flags"); return; }
  if (!["pass", "corrected", "flagged"].includes(cmd)) { console.error(`unknown command "${cmd}"`); process.exit(1); }
  const note = rest.join(" ").replace(/\s+/g, " ").trim().slice(0, 300);
  if (note.length < 8) { console.error("say what was checked or what is wrong (at least a few words)"); process.exit(1); }
  const left = flagsFor(f.e, recent).map((x) => x.code);
  if (cmd === "pass" && left.some((c) => /^(redirect-source|no-source|claim-severity|claim-corroborated|future-date|bad-cve)$/.test(c))) { console.error(`cannot pass ${id}: fix these first: ${left.join(", ")}`); process.exit(1); }
  const at = nowIso(), e = { ...f.e, review: { state: cmd === "pass" ? "passed" : cmd, at, note, flags: left.slice(0, 12) }, qa_checked_at: at };
  if (cmd === "flagged") e.validation = { state: "disputed", checked_at: at, note: ("Second review: " + note).slice(0, 240) };
  saveEvent(e, f.path);
  console.log(`review: ${id} ${e.review.state}${left.length ? " (remaining flags: " + left.join(", ") + ")" : ""}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
