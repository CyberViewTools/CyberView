// Checks the live site over HTTP. No browser, no AI model. Run: node scripts/monitor.mjs [base URL]
// Exit 0 = healthy, 1 = something is broken (the workflow opens or updates a GitHub issue), 2 = only warnings.
// Writes monitor-report.md next to the repo root for the workflow to post.
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { ROOT } from "./lib/store.mjs";

const BASE = (process.argv[2] || process.env.SITE_URL || "https://cyberview.netlify.app").replace(/\/$/, "");
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
  const csp = home.headers.get("content-security-policy") || "";
  if (!csp) fails.push("Content-Security-Policy header is missing");
  else {
    if (!/script-src 'self'(;|$)/.test(csp)) fails.push(`CSP script-src is not exactly 'self': ${csp}`);
    if (!/frame-ancestors 'none'/.test(csp)) fails.push("CSP no longer forbids framing (frame-ancestors 'none')");
  }
  for (const h of ["x-content-type-options", "referrer-policy", "permissions-policy"]) if (!home.headers.get(h)) fails.push(`Security header ${h} is missing`);
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
  if (builtH > 12) fails.push(`Bundle was built ${builtH.toFixed(1)} h ago; nothing has been deployed since (feeds run every 2 h)`);
  else if (builtH > 5) warns.push(`Bundle was built ${builtH.toFixed(1)} h ago`);
  const sweptH = st.last_sweep_at ? hours(st.last_sweep_at) : Infinity;
  if (sweptH > 8) fails.push(`Last sweep was ${isFinite(sweptH) ? sweptH.toFixed(1) + " h" : "never"} ago; the sweep job has stopped`);
  else if (sweptH > 3.5) warns.push(`Last sweep was ${sweptH.toFixed(1)} h ago`);
  const feedsH = st.last_feeds_at ? hours(st.last_feeds_at) : Infinity;
  if (feedsH > 6) warns.push(`Feeds last ran ${isFinite(feedsH) ? feedsH.toFixed(1) + " h" : "never"} ago`);
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
