#!/usr/bin/env node
// X (Twitter) as a LEAD SOURCE only (no AI model). Phase 1 = Route B: Grok Bot files a JSON batch of candidate
// leads on a GitHub issue labelled `x-leads`; this script ingests them the same way every other collector files
// leads, and appends them to data/leads/<YYYY-MM-DD>.jsonl. An X post is NEVER enough to create or corroborate a
// verified event: researchers open `linked_url` (the post's cited .gov/vendor page) or find an independent source,
// and x.com is never an event `sources[]` entry (LEAK_HOST in scripts/claims-desk.mjs; the guard in
// scripts/lib/validate.mjs). Curated accounts live in config/x-accounts.json, keyword queries in config/x-queries.json.
//
// Route A (official X API with X_BEARER_TOKEN) is a dormant switch in run(); it is NOT wired in Phase 1. Nothing is
// posted to X or GitHub by this script; it only reads issues and writes data/ (the data branch).
//
// Usage:
//   node scripts/x-leads.mjs            ingest open `x-leads` issues (needs gh auth), file leads, write heartbeat
//   node scripts/x-leads.mjs --dry      parse and report, write nothing
//   node scripts/x-leads.mjs --file F   ingest one local handoff file F (a JSON array or an issue-body with a ```json block)
//   node scripts/x-leads.mjs status     print the last health file

import { readFileSync, appendFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { DATA, ROOT, readJson, writeJson, nowIso, readStatus } from "./lib/store.mjs";
import { knownLeads } from "./osint.mjs";

export const OUT = join(DATA, "x-leads.json");
const REPO = process.env.GITHUB_REPOSITORY || process.env.GROK_REPO || "xanderhutch/CyberView";

const TIERS = new Set(["gov", "vendor", "grid", "research", "news"]);
const KINDS = new Set(["x-post", "x-news"]);

/* ---------- helpers ---------- */
const txt = (v, max) => (typeof v === "string" && v.trim() ? v.trim().slice(0, max) : "");
const https = (u) => typeof u === "string" && /^https:\/\/[^\s"'<>]+$/.test(u);
const hostOf = (u) => { try { return new URL(u).hostname.toLowerCase().replace(/^www\./, ""); } catch { return ""; } };
// social-media and leak hosts: allowed as a post permalink (lead `url`) but NEVER as a `linked_url` a researcher is sent to
export const SOCIAL_HOST = /(^|\.)(x\.com|twitter\.com|t\.me|telegram\.(me|org)|mastodon\.social|bsky\.app|linkedin\.com|facebook\.com|reddit\.com|onion)$/;
const isSocial = (u) => SOCIAL_HOST.test(hostOf(u));
const postId = (v) => (/^\d{1,25}$/.test(String(v || "").trim()) ? String(v).trim() : "");
const lang2 = (v) => (/^[a-z]{2}$/.test(String(v || "").toLowerCase()) ? String(v).toLowerCase() : "");
const isRetweet = (r) => r.is_retweet === true || /^RT @/i.test(String(r.title || "")) || /^RT @/i.test(String(r.text || ""));

export function config() {
  const c = readJson(join(ROOT, "config", "x-leads.json"), {}) || {};
  return { max_posts_per_batch: 40, max_posts_per_run: 120, lead_days: 7, dedup_days: 14, max_issues: 20, ...c };
}

/** username(lower) -> {username, tier, lang, x_user_id, display} for ACTIVE accounts only. */
export function registry(cfg = readJson(join(ROOT, "config", "x-accounts.json"), {})) {
  const m = new Map();
  for (const a of (cfg && cfg.accounts) || []) {
    if (!a || a.active === false || !a.username) continue;
    m.set(String(a.username).toLowerCase(), { username: a.username, tier: TIERS.has(a.tier) ? a.tier : "news", lang: a.lang || "en", x_user_id: String(a.x_user_id || ""), display: a.display || ("@" + a.username) });
  }
  return m;
}

/** Pull the lead candidates out of a handoff: a bare JSON array, or the first ```json fenced block in an issue body. */
export function parseHandoff(body) {
  if (Array.isArray(body)) return body;
  const s = String(body || "");
  const fence = s.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const raw = fence ? fence[1] : s;
  try { const j = JSON.parse(raw.trim()); return Array.isArray(j) ? j : (Array.isArray(j.leads) ? j.leads : []); } catch { return []; }
}

/** Pure: one raw candidate -> a standard lead object, or null (with a reason) if it must be dropped.
 *  Returns { lead } | { drop: "<reason>" }. */
export function cleanXLead(raw, reg, seenAt = nowIso()) {
  if (!raw || typeof raw !== "object") return { drop: "not an object" };
  if (isRetweet(raw)) return { drop: "retweet" };
  const id = postId(raw.x_post_id || raw.post_id || raw.id);
  if (!id) return { drop: "no x_post_id" };
  const handle = txt(String(raw.handle || raw.username || "").replace(/^@/, ""), 40);
  const kind = KINDS.has(raw.kind) ? raw.kind : "x-post";
  const acc = handle ? reg.get(handle.toLowerCase()) : null;
  // a single post must come from an ACTIVE curated account; a cluster (x-news) may not have a handle but counts as low-weight news
  if (kind === "x-post" && !acc) return { drop: `handle @${handle || "?"} not an active curated account` };
  const title = txt(raw.title || raw.text, 200);
  if (!title) return { drop: "no title" };
  const postUrl = https(raw.url) && isSocial(raw.url) ? raw.url : (handle && id ? `https://x.com/${handle}/status/${id}` : "");
  if (!postUrl) return { drop: "no usable post url" };
  // linked_url: the post's cited page — only a NON-social https url is ever handed to a researcher
  let linked = "";
  for (const u of [raw.linked_url, ...(Array.isArray(raw.urls) ? raw.urls : [])]) { if (https(u) && !isSocial(u)) { linked = u; break; } }
  const tier = acc ? acc.tier : (TIERS.has(raw.tier) ? raw.tier : "news");
  const summary = ("Posted on X, not checked. " + txt(raw.summary, 260)).slice(0, 300).trim();
  const lead = {
    seen_at: seenAt,
    source: acc ? acc.display : (handle ? "@" + handle : "X"),
    tier, via: "x", kind,
    title, url: postUrl,
    published: /^\d{4}-\d{2}-\d{2}/.test(String(raw.published || "")) ? String(raw.published).slice(0, 25) : seenAt,
    summary,
    lang: lang2(raw.lang) || (acc && acc.lang) || "en",
    handle: handle || "",
    x_post_id: id,
    x_user_id: String(raw.x_user_id || (acc && acc.x_user_id) || ""),
  };
  if (linked) lead.linked_url = linked;
  const region = txt(raw.region, 40), country = txt(raw.country, 4);
  if (region) lead.region = region;
  if (country) lead.country = country;
  return { lead };
}

/** Pure: ingest a set of handoff bodies -> { leads, stats }. Dedupes within the batch by x_post_id and against
 *  `known` (recent lead urls + event source urls) by url/linked_url. Enforces per-batch and per-run caps. */
export function ingest(bodies, known, cfg = config(), reg = registry(), seenAt = nowIso()) {
  const seenUrls = new Set(known && known.known ? known.known : []);
  const seenIds = new Set();
  const leads = [], byTier = {}, drops = {};
  let seen = 0, dupes = 0, rejected = 0, retweets = 0, capped = 0;
  for (const body of bodies) {
    const cands = parseHandoff(body).slice(0, cfg.max_posts_per_batch);
    for (const raw of cands) {
      seen++;
      const r = cleanXLead(raw, reg, seenAt);
      if (r.drop) { if (r.drop === "retweet") retweets++; else rejected++; drops[r.drop] = (drops[r.drop] || 0) + 1; continue; }
      const l = r.lead;
      if (seenIds.has(l.x_post_id)) { dupes++; continue; }
      if (seenUrls.has(l.url) || (l.linked_url && seenUrls.has(l.linked_url))) { dupes++; continue; }
      if (leads.length >= cfg.max_posts_per_run) { capped++; continue; }
      seenIds.add(l.x_post_id); seenUrls.add(l.url); if (l.linked_url) seenUrls.add(l.linked_url);
      leads.push(l); byTier[l.tier] = (byTier[l.tier] || 0) + 1;
    }
  }
  return { leads, stats: { seen, kept: leads.length, dupes, rejected, retweets, capped, byTier, drops } };
}

/* ---------- IO ---------- */
/** Read open `x-leads` issue bodies via gh (authenticated in Actions). Returns [] on any failure — never throws. */
function fetchIssueBodies(cfg) {
  try {
    const out = execFileSync("gh", ["api", "--paginate", `repos/${REPO}/issues?labels=x-leads&state=open&per_page=50`, "--jq", ".[] | {number, body}"],
      { encoding: "utf8", timeout: 30000, stdio: ["ignore", "pipe", "ignore"] });
    const items = out.trim().split("\n").filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean).slice(0, cfg.max_issues);
    return items.map((x) => ({ number: x.number, body: x.body || "" }));
  } catch { return []; }
}

export async function run({ dry = false, file = "" } = {}) {
  const cfg = config(), reg = registry(), at = nowIso();
  const route = process.env.X_BEARER_TOKEN ? "api-available" : "handoff";
  if (process.env.X_BEARER_TOKEN) console.log("x-leads: X_BEARER_TOKEN is set, but Route A (official API) is not enabled in Phase 1; using the handoff.");

  let issues = [];
  if (file) issues = [{ number: 0, body: readFileSync(file, "utf8") }];
  else issues = fetchIssueBodies(cfg);

  const known = knownLeads(cfg.dedup_days);
  const { leads, stats } = ingest(issues.map((i) => i.body), known, cfg, reg, at);

  const health = { checked_at: at, route, pending_issues: issues.map((i) => i.number).filter(Boolean),
    seen: stats.seen, kept: stats.kept, dupes: stats.dupes, rejected: stats.rejected, retweets: stats.retweets,
    capped: stats.capped, by_tier: stats.byTier, drops: stats.drops, last_ok: stats.kept || !issues.length ? at : "" };

  console.log(`x-leads: ${issues.length} open issue(s); ${stats.seen} candidate(s) -> ${stats.kept} new lead(s) (${stats.dupes} dup, ${stats.rejected} rejected, ${stats.retweets} retweet).`);
  if (Object.keys(stats.drops).length) console.log("  drops:", JSON.stringify(stats.drops));
  if (dry) { console.log(`DRY: ${stats.kept} lead(s) would be filed; nothing written.`); return { leads, health }; }

  if (leads.length) {
    const dir = join(DATA, "leads"); mkdirSync(dir, { recursive: true });
    appendFileSync(join(dir, `${at.slice(0, 10)}.jsonl`), leads.map((l) => JSON.stringify(l)).join("\n") + "\n");
  }
  writeJson(OUT, health);
  // heartbeat ALWAYS updates (even on a 0-new run) so the stage never goes stale just because Grok has not filed lately
  const st = readStatus(); st.last_x_leads_at = at; writeJson(join(DATA, "status.json"), st);
  return { leads, health };
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const a = process.argv.slice(2);
  if (a[0] === "status") { console.log(JSON.stringify(readJson(OUT, {}), null, 1)); }
  else {
    const fi = a.indexOf("--file");
    run({ dry: a.includes("--dry"), file: fi >= 0 ? a[fi + 1] : "" }).catch((e) => { console.error("x-leads failed:", e && e.message); process.exit(1); });
  }
}
