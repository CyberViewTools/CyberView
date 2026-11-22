// Static security checks for the repository. No network, no AI model. Run: node scripts/security-check.mjs
// Fails (exit 1) on anything that weakens the site's defences or leaks a secret:
//   1. pages: no inline <script> blocks, no inline event handlers (onclick=...), scripts and styles only from this site
//   2. scripts: no HTML string sinks (innerHTML, insertAdjacentHTML, document.write, eval, new Function, setTimeout("..."))
//   3. pages: every page carries a strict Content-Security-Policy meta tag (GitHub Pages cannot send headers)
//   4. vendored libraries match their recorded SHA-256 (catches tampering or an unreviewed upgrade)
//   5. secrets: no tokens or private keys in any tracked file
//   6. data: no markup or script URLs smuggled into event text or source links
import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { execSync } from "node:child_process";
import { join, extname } from "node:path";
import { ROOT, listEventFiles } from "./lib/store.mjs";

const fails = [], passes = [];
const rel = (p) => p.slice(ROOT.length + 1);
const read = (p) => readFileSync(p, "utf8");

// 1. pages
const SITE = join(ROOT, "site");
const pages = readdirSync(SITE).filter((f) => f.endsWith(".html")).map((f) => join(SITE, f));
for (const p of pages) {
  const html = read(p);
  for (const m of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
    if (!/\bsrc\s*=/.test(m[1]) && m[2].trim()) fails.push(`${rel(p)}: inline <script> block (move it to a .js file; the CSP forbids it)`);
    const src = (m[1].match(/\bsrc\s*=\s*"([^"]+)"/) || [])[1];
    if (src && /^(https?:)?\/\//i.test(src)) fails.push(`${rel(p)}: script loaded from another site: ${src}`);
  }
  for (const m of html.matchAll(/<link\b[^>]*href\s*=\s*"((?:https?:)?\/\/[^"]+)"/gi)) fails.push(`${rel(p)}: stylesheet or resource from another site: ${m[1]}`);
  for (const m of html.matchAll(/\s(on[a-z]+)\s*=\s*["']/gi)) fails.push(`${rel(p)}: inline event handler ${m[1]}= (the CSP blocks it; use addEventListener)`);
  if (/vendor\/supabase\.min\.js/.test(html) && !["account.html", "unsubscribe.html"].includes(p.split("/").pop())) fails.push(`${rel(p)}: only the account pages may load the Supabase library`);
}
passes.push(`${pages.length} page(s) checked`);

// 2. scripts we wrote (vendor libraries are checked by hash instead)
const ours = readdirSync(SITE).filter((f) => f.endsWith(".js")).map((f) => join(SITE, f));
const SINKS = [[/\.innerHTML\s*=/, "innerHTML assignment"], [/\.outerHTML\s*=/, "outerHTML assignment"], [/insertAdjacentHTML\s*\(/, "insertAdjacentHTML"],
  [/document\.write\s*\(/, "document.write"], [/\beval\s*\(/, "eval"], [/new\s+Function\s*\(/, "new Function"], [/set(Timeout|Interval)\s*\(\s*["'`]/, "string passed to setTimeout/setInterval"],
  [/\.html\s*\(\s*[^)\s]/, "d3 .html() with content"]];
for (const p of ours) {
  const src = read(p);
  for (const [re, name] of SINKS) if (re.test(src)) fails.push(`${rel(p)}: ${name} (build DOM nodes and set textContent instead)`);
  // an href may come from a quoted literal (internal page or fixed https URL) or a URL-checking helper; anything else could carry javascript:
  for (const m of src.matchAll(/\.href\s*=\s*([^;]{0,80})/g)) {
    const rhs = m[1].trim();
    if (!/^["'`]/.test(rhs) && !/^(safeUrl|eventLink|blobUrl)\(/.test(rhs)) fails.push(`${rel(p)}: href set from "${rhs.slice(0, 40)}" without a URL check (use a literal or safeUrl())`);
  }
}
passes.push(`${ours.length} script(s) checked for HTML sinks`);

// 3. Content-Security-Policy. GitHub Pages cannot send custom headers, so every page carries the policy in a
//    <meta http-equiv> tag (frame-ancestors is not allowed there).
// account pages may also reach the configured Supabase project, and nothing else; every other page stays 'self' only
const ACCOUNT_PAGES = new Set(["account.html", "unsubscribe.html"]);
const SUPABASE = (() => { try { const u = JSON.parse(readFileSync(join(ROOT, "config", "accounts.json"), "utf8")).supabase_url || "";
  if (u && !/^https:\/\/[a-z0-9]{20}\.supabase\.co$/.test(u)) fails.push(`config/accounts.json: supabase_url must look like https://<20-character ref>.supabase.co`);
  return u; } catch { return ""; } })();
function checkCsp(csp, where) {
  const dir = Object.fromEntries(csp.split(";").map((d) => d.trim().split(/\s+/)).filter((d) => d[0]).map((d) => [d[0], d.slice(1).join(" ")]));
  if (dir["script-src"] !== "'self'") fails.push(`${where}: CSP script-src must be exactly 'self' (is "${dir["script-src"]}")`);
  if (dir["default-src"] !== "'self'") fails.push(`${where}: CSP default-src must be 'self' (is "${dir["default-src"]}")`);
  if (dir["base-uri"] !== "'none'") fails.push(`${where}: CSP must keep base-uri 'none'`);
  const extra = ACCOUNT_PAGES.has(where.replace(/^site\//, "")) && SUPABASE ? ` ${SUPABASE}` : "";
  if ((dir["connect-src"] || "") !== `'self'${extra}`) fails.push(`${where}: CSP connect-src must be 'self'${extra ? " plus the configured Supabase project" : " only"}`);
  if (/'unsafe-eval'/.test(csp)) fails.push(`${where}: CSP must not allow 'unsafe-eval'`);
}
for (const p of pages) {
  const html = read(p);
  const m = html.match(/<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]+)"/i);
  if (!m) { fails.push(`${rel(p)}: no Content-Security-Policy meta tag`); continue; }
  checkCsp(m[1], rel(p));
  const headEnd = html.search(/<\/head>/i), firstScript = html.search(/<script\b/i);
  if (firstScript >= 0 && firstScript < headEnd && firstScript < html.indexOf(m[0])) fails.push(`${rel(p)}: the CSP meta tag must come before any script`);
  if (!/<meta\s+name="referrer"/i.test(html)) fails.push(`${rel(p)}: missing referrer meta tag`);
}
passes.push("Content-Security-Policy checked on every page");

// 3b. the deploy workflow must listen for workflows that exist (a rename once stopped feed updates from deploying)
{
  const wfDir = join(ROOT, ".github", "workflows"), names = new Set(readdirSync(wfDir).map((f) => (read(join(wfDir, f)).match(/^name:\s*(.+)$/m) || [])[1]).filter(Boolean).map((n) => n.trim()));
  const listed = (read(join(wfDir, "pages.yml")).match(/workflows:\s*\[([^\]]*)\]/) || [])[1] || "";
  for (const n of [...listed.matchAll(/"([^"]+)"/g)].map((m) => m[1])) if (!names.has(n)) fails.push(`pages.yml waits for workflow "${n}", which does not exist (renamed?)`);
  passes.push("deploy workflow listens for existing workflows");
}

// 4. vendored files
const PINNED = {
  "site/vendor/d3.min.js": "f2094bbf6141b359722c4fe454eb6c4b0f0e42cc10cc7af921fc158fceb86539",
  "site/vendor/topojson.min.js": "25cd02ae486cc5063e0215a4e4cfb15de83700c87ac48bac4d57dc6aaf3ebb89",
  // @supabase/supabase-js 2.118.0, dist/umd/supabase.js (npm integrity sha512-FxI8UXMVC2UG7Ike…), loaded only by account pages
  "site/vendor/supabase.min.js": "ee3be8de192b97cb1d73d1e95d6b82bb1f6b658c0f97c4ef757fc331996ed3d3",
  "site/world-110m.json": "2516c915867c7baf18ddec727aec46c315541a07cfb3d79a6559b05d5e94eee8",
};
for (const [f, want] of Object.entries(PINNED)) {
  const p = join(ROOT, f);
  if (!existsSync(p)) { fails.push(`${f} is missing`); continue; }
  const got = createHash("sha256").update(readFileSync(p)).digest("hex");
  if (got !== want) fails.push(`${f} changed (sha256 ${got.slice(0, 12)}…); review the new file, then update PINNED in scripts/security-check.mjs`);
}
for (const f of readdirSync(join(SITE, "vendor"))) if (!PINNED[`site/vendor/${f}`]) fails.push(`site/vendor/${f} is not pinned; add its sha256 to scripts/security-check.mjs after review`);
passes.push("vendored files match their pinned hashes");

// 5. secrets in tracked files
let tracked = [];
try { tracked = execSync("git ls-files", { cwd: ROOT, encoding: "utf8" }).split("\n").filter(Boolean); } catch { tracked = []; }
const SECRET = [[/gh[pousr]_[A-Za-z0-9]{36,}/, "GitHub token"], [/github_pat_[A-Za-z0-9_]{40,}/, "GitHub token"], [/AKIA[0-9A-Z]{16}/, "AWS access key"],
  [/-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----/, "private key"], [/sk-ant-[A-Za-z0-9_-]{20,}/, "Anthropic API key"], [/sk-[A-Za-z0-9]{40,}/, "API secret key"],
  [/xox[abpr]-[A-Za-z0-9-]{10,}/, "Slack token"], [/nf[pc]_[A-Za-z0-9]{30,}/, "Netlify token"], [/AIza[0-9A-Za-z_-]{35}/, "Google API key"]];
let scanned = 0;
for (const f of tracked) {
  if (/\.(png|jpg|gif|woff2?|ico)$/.test(f) || f.startsWith("legacy/") || f.startsWith("site/vendor/")) continue;
  const p = join(ROOT, f); if (!existsSync(p) || statSync(p).size > 2e6) continue;
  const t = read(p); scanned++;
  for (const [re, name] of SECRET) if (re.test(t)) fails.push(`${f}: looks like a ${name}; remove it and rotate the secret`);
}
for (const f of [".env", ".env.local", "credentials.json"]) if (tracked.includes(f)) fails.push(`${f} is committed`);
passes.push(`${scanned} tracked file(s) scanned for secrets`);

// 6. data
const TEXT = ["title", "summary", "plain", "exec", "action", "impact", "org", "place", "actor", "date_note"];
let n = 0;
for (const { e, path } of listEventFiles()) {
  if (!e) continue; n++;
  for (const k of TEXT) if (/<\s*\/?\s*(script|iframe|img|svg|a|object|embed)\b|javascript:/i.test(String(e[k] || ""))) fails.push(`${rel(path)}: field "${k}" contains markup or a script URL`);
  for (const s of e.sources || []) if (s && !/^https?:\/\//i.test(String(s.url || ""))) fails.push(`${rel(path)}: source url is not http(s)`);
  if (e.report && e.report.url && !/^https?:\/\//i.test(e.report.url)) fails.push(`${rel(path)}: report.url is not http(s)`);
}
passes.push(`${n} event(s) checked for injected markup`);

// 7. the downloadable scanner (scanner/) stays a detection tool (docs/scanner.md): no process spawning, no raw or UDP sockets
//    (no spoofing, flooding or amplification), no request that uploads (only GET), connections to targets only from
//    scanner/lib/probe.mjs, and limits that can be lowered, never raised or switched off
const SCAN = join(ROOT, "scanner");
if (existsSync(SCAN)) {
  const files = [];
  const walk = (d) => { for (const f of readdirSync(d)) { const p = join(d, f); if (statSync(p).isDirectory()) walk(p); else if (/\.(mjs|js)$/.test(f)) files.push(p); } };
  walk(SCAN);
  const NOT = [[/node:child_process|require\(["']child_process|\bexecSync\b|\bspawn\(/, "starts other programs"], [/node:dgram|["']dgram["']/, "opens UDP sockets"], [/\braw[-_ ]?socket|SOCK_RAW|\bsetTTL\b/i, "raw sockets"],
    [/method:\s*["'](POST|PUT|PATCH|DELETE)["']/i, "sends an upload request (the scanner only reads with GET)"], [/\beval\s*\(|new\s+Function\s*\(/, "runs code from text"],
    [/\b(aggressive|insane|no-?rate-?limit|unlimited)\b/i, "an aggressive or unlimited mode"]];
  for (const p of files) {
    const src = read(p);
    for (const [re, what] of NOT) if (re.test(src)) fails.push(`${rel(p)}: ${what}; the scanner must stay detection only (docs/scanner.md)`);
    if (!p.endsWith(join("lib", "probe.mjs")) && /\b(net|tls)\.connect\s*\(|\bhttps?\.request\s*\(/.test(src)) fails.push(`${rel(p)}: connects to a target outside scanner/lib/probe.mjs`);
  }
  const lim = existsSync(join(SCAN, "lib", "limits.mjs")) ? read(join(SCAN, "lib", "limits.mjs")) : "";
  const cap = (k) => Number((new RegExp(`CAPS = Object\\.freeze\\(\\{[\\s\\S]*?\\b${k}:\\s*(\\d+)`).exec(lim) || [])[1]);
  if (!(cap("rate") > 0 && cap("rate") <= 20 && cap("concurrency") > 0 && cap("concurrency") <= 8 && cap("hostConcurrency") <= 2)) fails.push("scanner/lib/limits.mjs: the ceilings (rate 20/s, 8 open, 2 per host) must not be raised");
  passes.push(`${files.length} scanner file(s) checked: detection only`);
}

passes.forEach((p) => console.log("ok: " + p));
fails.forEach((f) => console.error("FAIL: " + f));
console.log(fails.length ? `\nSecurity check failed: ${fails.length} problem(s).` : "\nSecurity check passed.");
process.exit(fails.length ? 1 : 0);
