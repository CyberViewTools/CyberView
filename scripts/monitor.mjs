// Checks the live site over HTTP. No browser, no AI model. Run: node scripts/monitor.mjs [base URL]
// Exit 0 = healthy, 1 = something is broken (the workflow opens or updates a GitHub issue), 2 = only warnings.
// Writes monitor-report.md next to the repo root for the workflow to post.
import { writeFileSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { ROOT } from "./lib/store.mjs";

const BASE = (process.argv[2] || process.env.SITE_URL || "https://xanderhutch.github.io/CyberView").replace(/\/$/, "");
const fails = [], warns = [], notes = [];
const hours = (iso) => (Date.now() - Date.parse(iso)) / 36e5;

async function get(path, { json = false } = {}) {
  for (let i = 0; i < 3; i++) {
    try {
      const r = await fetch(BASE + path, { headers: { "cache-control": "no-cache", "user-agent": "cyberview-monitor/1.0" } });
      const body = json ? await r.json().catch(() => null) : await r.text();
      return { status: r.status, headers: r.headers, body };
    } catch (e) { if (i === 2) return { status: 0, error: (e.cause && e.cause.code) || e.message }; await new Promise((r) => setTimeout(r, 5000)); }
  }
}

// 1. the page and its security headers
const home = await get("/");
if (home.status !== 200) fails.push(`Home page returned ${home.status || home.error}`);
else {
  if (!/<title>CyberView<\/title>/.test(home.body)) fails.push("Home page title is not CyberView (wrong deploy?)");
  // GitHub Pages cannot send custom headers: the policy is a meta tag in the page
  const csp = (home.body.match(/<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]+)"/i) || [])[1] || home.headers.get("content-security-policy") || "";
  if (!csp) fails.push("Content-Security-Policy is missing from the page");
  else if (!/script-src 'self'(;|$)/.test(csp)) fails.push(`CSP script-src is not exactly 'self': ${csp}`);
  if (!/<meta\s+name="referrer"/i.test(home.body)) warns.push("Referrer policy meta tag is missing");
  if (!/^https:/.test(BASE)) fails.push("Site is not served over HTTPS");
}

// 2. the data
const b = await get("/data/bundle.json", { json: true });
if (b.status !== 200 || !b.body) fails.push(`Data bundle returned ${b.status || b.error}`);
else {
  const d = b.body, st = (d.docs && d.docs["meta/status"]) || {};
  const ev = (d.events || []).length;
  notes.push(`${ev} events, ${(d.kev || []).length} known-exploited, built ${d.built_at}`);
  if (ev < 10) fails.push(`Only ${ev} events in the bundle; the map looks empty`);
  const builtH = hours(d.built_at);
  // every data commit redeploys (pages.yml); the sweep commits hourly
  const maxH = Number(process.env.MAX_BUNDLE_HOURS || 12);
  if (builtH > maxH) fails.push(`Bundle was built ${builtH.toFixed(1)} h ago (limit ${maxH} h); the live data is stale`);
  else if (builtH > 6) warns.push(`Bundle was built ${builtH.toFixed(1)} h ago `);
  // lateness comes from routines.json: active routines with a status timestamp, late past max_age_hours, failing past twice that
  const reg = JSON.parse(readFileSync(join(ROOT, "routines.json"), "utf8"));
  for (const r of reg.routines.filter((r) => r.active && r.status_key && r.max_age_hours)) {
    const h = st[r.status_key] ? hours(st[r.status_key]) : Infinity, msg = isFinite(h) ? `${h.toFixed(1)} h ago` : "never";
    if (h > 2 * r.max_age_hours) fails.push(`${r.name} last ran ${msg} (expected every ${r.max_age_hours} h or less); it has stopped`);
    else if (h > r.max_age_hours) warns.push(`${r.name} is late: last ran ${msg}`);
  }
  const future = (d.events || []).filter((e) => e.date > new Date(Date.now() + 864e5).toISOString().slice(0, 10));
  if (future.length) fails.push(`${future.length} event(s) dated in the future: ${future.slice(0, 3).map((e) => e.id).join(", ")}`);
}

// 3. other files the pages need
for (const p of ["/app.js", "/archive.html", "/archive.js", "/data/archive/index.json", "/data/archive/search.json", "/logo.svg", "/vendor/d3.min.js"]) {
  const r = await get(p); if (r.status !== 200) fails.push(`${p} returned ${r.status || r.error}`);
}

const status = fails.length ? "broken" : warns.length ? "degraded" : "healthy";
const md = [`**CyberView live check: ${status}** (${new Date().toISOString().replace(/\.\d+Z$/, "Z")}, ${BASE})`, "",
  ...fails.map((f) => `- ❌ ${f}`), ...warns.map((w) => `- ⚠️ ${w}`), ...notes.map((n) => `- ${n}`)].join("\n");
writeFileSync(join(ROOT, "monitor-report.md"), md + "\n");
console.log(md);
process.exit(fails.length ? 1 : warns.length ? 2 : 0);
