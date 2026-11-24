// Email alerts for account holders who turned them on. No AI model. Run: node scripts/alerts.mjs [--dry-run]
// Needs (GitHub Actions secrets, never committed): SUPABASE_SERVICE_ROLE_KEY, and BREVO_API_KEY or RESEND_API_KEY,
// plus ALERT_FROM_EMAIL (a sender address verified with the provider). Supabase URL comes from config/accounts.json.
// Compliance (Canada's CASL, and good practice under GDPR and US CAN-SPAM):
//   - only recipients with alerts on, a recorded consent and a confirmed email (the alert_recipients() function);
//   - every email names the sender, gives a mailing address and a contact page, says why it was sent,
//     and has a working unsubscribe link plus List-Unsubscribe headers; the job refuses to run without a mailing address;
//   - the alert log is kept 90 days and then purged.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { ROOT } from "./lib/store.mjs";
import { get } from "./lib/net.mjs";
import { SITE_URL } from "./lib/site-url.mjs";

const SITE = SITE_URL;
const MAX_ITEMS = 20, SEV = ["", "low", "medium", "high"];
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const wordRe = (t) => new RegExp("(^|[^a-z0-9])" + t.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "($|[^a-z0-9])");

/** Is this recipient due an email now? instant: every run; daily: 23 h since the last; weekly: 6.9 days. */
export function due(r, now = Date.now()) {
  if (!r.last_alert_at) return true;
  const h = (now - Date.parse(r.last_alert_at)) / 36e5;
  return r.alert_frequency === "instant" ? true : r.alert_frequency === "daily" ? h >= 23 : h >= 6.9 * 24;
}

/** New items for one recipient: events and known-exploited entries that match a term, are new since the last alert,
 *  meet the minimum severity, are not unverified claims, and were not sent before. */
export function matches(r, bundle, sent = new Set(), now = Date.now()) {
  const res = (r.alert_terms || []).map(wordRe);
  const hit = (hay) => res.findIndex((re) => re.test(hay.toLowerCase()));
  const since = r.last_alert_at ? Date.parse(r.last_alert_at) : now - 7 * 864e5;
  const out = [];
  for (const e of bundle.events || []) {
    if (sent.has(e.id) || e.status === "claimed" || e.duplicate_of || (e.severity || 1) < r.alert_min_severity) continue;
    const seen = Date.parse(e.first_seen || e.updated_at || "") || 0;
    if (seen <= since) continue;
    const i = hit([e.title, e.org, (e.products || []).join(" | "), (e.tags || []).join(" | "), (e.cves || []).join(" "), e.sector].join(" | "));
    if (i >= 0) out.push({ id: e.id, kind: "event", term: r.alert_terms[i], severity: e.severity || 1, title: e.title, date: e.date, action: e.action || "", url: `${SITE}/#e=${encodeURIComponent(e.id)}` });
  }
  for (const k of bundle.kev || []) {
    const id = `kev-${k.cve}`;
    if (sent.has(id) || Date.parse(k.added + "T23:59:59Z") <= since) continue;
    const i = hit([k.cve, k.vendor, k.product, k.name].join(" | "));
    if (i >= 0) out.push({ id, kind: "kev", term: r.alert_terms[i], severity: 3, title: `${k.cve}: ${k.vendor} ${k.product} is being exploited`, date: k.added, action: k.due ? `CISA deadline for US federal agencies: ${k.due}.` : "", url: `${SITE}/#kev` });
  }
  return out.sort((a, b) => b.severity - a.severity || (a.date < b.date ? 1 : -1)).slice(0, MAX_ITEMS);
}

/** The email. Plain text and HTML carry the same content; everything inserted into HTML is escaped. */
export function compose(r, items, cfg) {
  const unsub = `${SITE}/unsubscribe.html?t=${r.unsubscribe_token}`;
  const n = items.length, subject = `CyberView: ${n} new match${n === 1 ? "" : "es"} for your environment`;
  const why = `You get this because you turned on CyberView alerts for your account (${r.alert_frequency}, ${SEV[r.alert_min_severity] || "all"} severity and above).`;
  const sender = `CyberView, run by ${cfg.owner_name}. ${cfg.mailing_address}. Contact: ${SITE}/about.html#corrections`;
  const text = [subject, "",
    ...items.map((it) => `- [${SEV[it.severity]}] ${it.title} (matched "${it.term}")\n  ${it.action ? it.action + "\n  " : ""}${it.url}`), "",
    "A match is by name only: check the source before acting. CyberView is information, not security advice.", "",
    why, `Unsubscribe (one click): ${unsub}`, `Change your alerts: ${SITE}/account.html`, sender].join("\n");
  const html = `<!doctype html><html><body style="font-family:system-ui,sans-serif;line-height:1.5;color:#111;max-width:640px">
<h2 style="font-size:18px">${esc(subject)}</h2><ul>${items.map((it) => `<li style="margin:8px 0"><strong>[${esc(SEV[it.severity])}]</strong> <a href="${esc(it.url)}">${esc(it.title)}</a> <span style="color:#555">(matched &ldquo;${esc(it.term)}&rdquo;)</span>${it.action ? `<br>${esc(it.action)}` : ""}</li>`).join("")}</ul>
<p style="color:#555;font-size:13px">A match is by name only: check the source before acting. CyberView is information, not security advice.</p>
<hr><p style="color:#555;font-size:12px">${esc(why)}<br><a href="${esc(unsub)}">Unsubscribe with one click</a> &middot; <a href="${esc(SITE)}/account.html">Change your alerts</a><br>${esc(sender)}</p></body></html>`;
  const headers = { "List-Unsubscribe": `<${unsub}>${cfg.contact_email ? `, <mailto:${cfg.contact_email}?subject=unsubscribe>` : ""}` };
  return { subject, text, html, headers };
}

async function send(to, mail, from) {
  if (process.env.BREVO_API_KEY) {
    const r = await fetch("https://api.brevo.com/v3/smtp/email", { method: "POST", headers: { "api-key": process.env.BREVO_API_KEY, "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ sender: { name: "CyberView", email: from }, to: [{ email: to }], subject: mail.subject, textContent: mail.text, htmlContent: mail.html, headers: mail.headers }) });
    if (!r.ok) throw new Error(`Brevo HTTP ${r.status}`);
  } else {
    const r = await fetch("https://api.resend.com/emails", { method: "POST", headers: { authorization: `Bearer ${process.env.RESEND_API_KEY}`, "content-type": "application/json" },
      body: JSON.stringify({ from: `CyberView <${from}>`, to: [to], subject: mail.subject, text: mail.text, html: mail.html, headers: mail.headers }) });
    if (!r.ok) throw new Error(`Resend HTTP ${r.status}`);
  }
}

async function main() {
  const dry = process.argv.includes("--dry-run");
  const acct = JSON.parse(readFileSync(join(ROOT, "config", "accounts.json"), "utf8"));
  const cfg = JSON.parse(readFileSync(join(ROOT, "config", "site.json"), "utf8"));
  const svc = process.env.SUPABASE_SERVICE_ROLE_KEY, from = process.env.ALERT_FROM_EMAIL;
  if (!acct.supabase_url) { console.log("alerts: accounts are not configured; nothing to do"); return; }
  if (!svc) { console.log("alerts: SUPABASE_SERVICE_ROLE_KEY is not set; skipping"); return; }
  if (!dry && !(process.env.BREVO_API_KEY || process.env.RESEND_API_KEY) ) { console.log("alerts: no email provider key; skipping"); return; }
  if (!dry && !from) { console.log("alerts: ALERT_FROM_EMAIL is not set; skipping"); return; }
  if (!String(cfg.mailing_address || "").trim()) { console.error("alerts: config/site.json mailing_address is empty; CASL requires one in every email. Not sending."); process.exit(1); }
  const H = { apikey: svc, authorization: `Bearer ${svc}`, "content-type": "application/json" };
  const db = (path, init = {}) => fetch(`${acct.supabase_url}/rest/v1/${path}`, { ...init, headers: { ...H, ...(init.headers || {}) } });

  const bundle = await get(`${SITE}/data/bundle.json`, { timeoutMs: 30000 });
  const rr = await db("rpc/alert_recipients", { method: "POST", body: "{}" });
  if (!rr.ok) throw new Error(`alert_recipients HTTP ${rr.status}`);
  const recipients = await rr.json();
  let sentN = 0, failed = 0;
  for (const r of recipients.filter((x) => due(x))) {
    const lr = await db(`alert_log?select=event_id&user_id=eq.${r.user_id}`);
    const sent = new Set(lr.ok ? (await lr.json()).map((x) => x.event_id) : []);
    const items = matches(r, bundle, sent);
    if (!items.length) continue;
    const mail = compose(r, items, cfg);
    if (dry) { console.log(`dry run: would send ${items.length} item(s) to user ${r.user_id.slice(0, 8)}`); continue; }
    try {
      await send(r.email, mail, from);
      await db("alert_log", { method: "POST", headers: { prefer: "resolution=ignore-duplicates" }, body: JSON.stringify(items.map((it) => ({ user_id: r.user_id, event_id: it.id }))) });
      await db(`accounts?user_id=eq.${r.user_id}`, { method: "PATCH", body: JSON.stringify({ last_alert_at: new Date().toISOString() }) });
      sentN++;
    } catch (e) { failed++; console.error(`alerts: send failed for user ${r.user_id.slice(0, 8)}: ${e.message}`); }
  }
  // retention: 90 days of alert history
  await db(`alert_log?sent_at=lt.${new Date(Date.now() - 90 * 864e5).toISOString()}`, { method: "DELETE" });
  console.log(`alerts: ${recipients.length} subscribed, ${sentN} emailed, ${failed} failed`);
  if (failed) process.exit(1);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
