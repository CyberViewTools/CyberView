// Builds the static pages that share one template: legal/*.html -> site/<name>.html, and site/.well-known/security.txt.
// Placeholders {{key}} come from config/site.json; text is HTML-escaped. Elements marked data-contact are dropped
// when no contact email is configured, so a page never shows an empty address.
// Called by scripts/build.mjs; run alone with: node scripts/pages.mjs
import { readFileSync, writeFileSync, readdirSync, mkdirSync, existsSync } from "node:fs";
import { join, basename } from "node:path";
import { pathToFileURL } from "node:url";
import { ROOT } from "./lib/store.mjs";

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
export const CSP = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; object-src 'none'";
export const LEGAL_PAGES = ["about", "privacy", "terms"];

export function siteConfig() {
  const c = JSON.parse(readFileSync(join(ROOT, "config", "site.json"), "utf8"));
  const email = String(c.contact_email || "").trim();
  if (email && !/^[^\s@<>"]+@[^\s@<>"]+\.[a-z]{2,}$/i.test(email)) throw new Error("config/site.json: contact_email is not a valid address");
  return { ...c, contact_email: email };
}

export function footer() {
  return `<footer class="foot"><a href="about.html">About</a><a href="privacy.html">Privacy</a><a href="terms.html">Terms</a><a href="about.html#corrections">Corrections</a><a href="about.html#security">Report a security issue</a><a href="account.html">Account</a></footer>`;
}

export function accountsConfig() {
  let a = {};
  try { a = JSON.parse(readFileSync(join(ROOT, "config", "accounts.json"), "utf8")); } catch { a = {}; }
  const url = String(a.supabase_url || "").trim(), key = String(a.supabase_anon_key || "").trim();
  if (url && !/^https:\/\/[a-z0-9]{20}\.supabase\.co$/.test(url)) throw new Error("config/accounts.json: supabase_url must be https://<20-character ref>.supabase.co");
  if (url && !/^(eyJ[\w-]+\.[\w-]+\.[\w-]+|sb_publishable_[\w-]{20,})$/.test(key)) throw new Error("config/accounts.json: supabase_anon_key must be the public anon (or publishable) key");
  // refuse a secret key outright: it would bypass row-level security for everyone
  if (/^sb_secret_/.test(key) || (key.startsWith("eyJ") && /"role"\s*:\s*"service_role"/.test(Buffer.from(key.split(".")[1] || "", "base64url").toString()))) throw new Error("config/accounts.json: that is a SECRET service key; use the public anon key");
  return { on: !!(url && key), url, key, region: String(a.region || "").slice(0, 40), github: a.github_login === true };
}

export function render(name, body, cfg, page = {}) {
  const title = (body.match(/<!--\s*title:\s*(.+?)\s*-->/) || [])[1] || name;
  const desc = (body.match(/<!--\s*description:\s*(.+?)\s*-->/) || [])[1] || "";
  let html = body.replace(/<!--[\s\S]*?-->\n?/g, "").replace(/\{\{(\w+)\}\}/g, (m, k) => (k in cfg ? esc(cfg[k]) : m));
  if (/\{\{\w+\}\}/.test(html)) throw new Error(`legal/${name}.html: unknown placeholder ${html.match(/\{\{\w+\}\}/)[0]}`);
  html = cfg.contact_email
    ? html.replace(/<a data-contact-link href="mailto:">/g, `<a href="mailto:${esc(cfg.contact_email)}">`).replace(/ data-contact>/g, ">")
    : html.replace(/<p data-contact>[\s\S]*?<\/p>\n?/g, "");
  return `<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="${page.connect ? CSP.replace("connect-src 'self'", `connect-src 'self' ${page.connect}`) : CSP}">${(page.meta || []).map(([n, v]) => `\n<meta name="${n}" content="${esc(v)}">`).join("")}
<meta name="referrer" content="strict-origin-when-cross-origin">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>${esc(title)} · CyberView</title>
<meta name="description" content="${esc(desc)}">
<link rel="icon" href="favicon.svg" type="image/svg+xml">
<link rel="icon" href="icon-32.png" sizes="32x32" type="image/png">
<link rel="apple-touch-icon" href="apple-touch-icon.png">
<link rel="stylesheet" href="archive.css">
</head>
<body>
<header class="bar">
  <a class="brand" href="./"><img src="logo.svg" alt="" width="26" height="26">CyberView</a>
  <span class="crumb">${esc(title)}</span>
  <span class="spacer"></span>
  <a class="btn ghost" href="./">Back to the map</a>
</header>
<main>
${html.trim()}
</main>
${footer()}${(page.scripts || []).map((s) => `\n<script src="${s}"></script>`).join("")}
</body>
</html>
`;
}

export function buildPages() {
  const cfg = siteConfig(), out = [];
  for (const f of readdirSync(join(ROOT, "legal")).filter((f) => f.endsWith(".html"))) {
    const name = basename(f, ".html");
    writeFileSync(join(ROOT, "site", `${name}.html`), render(name, readFileSync(join(ROOT, "legal", f), "utf8"), cfg));
    out.push(`${name}.html`);
  }
  // account pages: the only pages allowed to reach Supabase, and only when it is configured
  const acct = accountsConfig();
  for (const name of ["account", "unsubscribe"]) {
    const page = acct.on
      ? { connect: acct.url, meta: [["cv-supabase-url", acct.url], ["cv-supabase-key", acct.key], ["cv-region", acct.region], ["cv-github", acct.github ? "1" : "0"]],
          scripts: ["vendor/supabase.min.js", `${name}.js`] }
      : { meta: [["cv-supabase-url", ""]], scripts: [`${name}.js`] };
    writeFileSync(join(ROOT, "site", `${name}.html`), render(name, readFileSync(join(ROOT, "pages", `${name}.html`), "utf8"), cfg, page));
    out.push(`${name}.html`);
  }
  // RFC 9116: how to report security problems; expires within a year, refreshed on every build
  const wk = join(ROOT, "site", ".well-known");
  if (!existsSync(wk)) mkdirSync(wk, { recursive: true });
  const exp = new Date(Date.now() + 180 * 864e5).toISOString().replace(/\.\d+Z$/, "Z");
  writeFileSync(join(wk, "security.txt"), [
    `Contact: https://github.com/${cfg.owner_github}/CyberView/security/advisories/new`,
    ...(cfg.contact_email ? [`Contact: mailto:${cfg.contact_email}`] : []),
    `Expires: ${exp}`,
    "Preferred-Languages: en",
    "Canonical: https://xanderhutch.github.io/CyberView/.well-known/security.txt",
    "Policy: https://xanderhutch.github.io/CyberView/about.html#security",
    "",
  ].join("\n"));
  out.push(".well-known/security.txt");
  return out;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) console.log("Pages: " + buildPages().join(", "));
