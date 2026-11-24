// Data CyberView would like to use: the sources it does not have access to, and the request for each. No AI model.
// config/data-access.json is the curated list (one entry per source). This script
//   - checks it (`check`: every field present and in range, no guessed contact, keys unique); a unit test runs the
//     same check on the real file, so a broken entry fails CI
//   - renders the generated part of the page (scripts/pages.mjs calls accessSection() for legal/access.html; entries that
//     fail the check are left out and reported, so one bad entry can never hold back a build)
//   - checks each entry's own request text (`request`: at most 900 characters, signed by CyberView, never by a person),
//     which the owner sends himself (the page only copies it; it never sends anything), and its ask order (`priority`)
// Run: node scripts/access.mjs check | show [key]
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { ROOT } from "./lib/store.mjs";
import { SITE_URL } from "./lib/site-url.mjs";

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
export const load = () => JSON.parse(readFileSync(join(ROOT, "config", "data-access.json"), "utf8"));

export const WHY = {
  terms: "Terms restrict reuse, or none were found",
  robots: "robots.txt disallows the data path",
  blocks_readers: "Blocks automated readers",
  key_or_account: "Needs a key or an account",
  unavailable: "Could not be reached",
};
// in_use: the data is now read through another open route (detail says which); the entry stays for the operator's own feed
export const STATUS = { not_asked: ["Not asked yet", "wait"], asked: ["Asked, waiting", "info"], granted: ["Granted", "ok"], declined: ["Declined", "bad"], in_use: ["In use", "ok"] };
export const COUNTRIES = {
  US: "United States", CA: "Canada", GB: "United Kingdom", IE: "Ireland", NL: "Netherlands", FR: "France", DE: "Germany", ES: "Spain",
  PT: "Portugal", IT: "Italy", GR: "Greece", PL: "Poland", CZ: "Czechia", SE: "Sweden", FI: "Finland", DK: "Denmark", EE: "Estonia",
  LT: "Lithuania", LV: "Latvia", SI: "Slovenia", HU: "Hungary", AT: "Austria", RO: "Romania", HR: "Croatia", RS: "Serbia", BG: "Bulgaria",
  UA: "Ukraine", TR: "Turkey", AU: "Australia", NZ: "New Zealand", JP: "Japan", TW: "Taiwan", KR: "South Korea", PH: "Philippines",
  MY: "Malaysia", SG: "Singapore", IN: "India", PK: "Pakistan", BD: "Bangladesh", ID: "Indonesia", VN: "Vietnam", TH: "Thailand",
  ZA: "South Africa", KE: "Kenya", NG: "Nigeria", ZM: "Zambia", ZW: "Zimbabwe", CL: "Chile", MX: "Mexico", PR: "Puerto Rico",
  CO: "Colombia", PE: "Peru", BR: "Brazil", LK: "Sri Lanka", RU: "Russia", IL: "Israel", LB: "Lebanon", IQ: "Iraq", AE: "United Arab Emirates", SA: "Saudi Arabia", KW: "Kuwait",
};
export const SITE = SITE_URL + "/";
export const KINDS = { grid: "Power grid and outage data", cyber: "Cyber security sources" };
// Every request ends with this line and names no person and no personal address.
export const SIGN = `\u2014 CyberView (${SITE_URL})`;

// The shape every request follows. Each entry carries its own text (`request`), written for that operator and that feed.
export const REQUEST = `Subject: Permission to show [feed] on CyberView

Hello [operator] team,

CyberView (${SITE_URL}) is a free, public, read-only, non-commercial map of verified cyber incidents and infrastructure outages for security defenders.

We would like to read [feed] automatically every few minutes and show it on the map as context, credited to [operator] with a link back to your page. We would never resell it, collect personal data or call an outage an attack.

May we have permission for this automated reading and display with attribution? We will follow any conditions you set, and stop if you ask.

Thank you,
${SIGN}`;

/** The request for one source: its own text, or the shape above filled in when it has none. */
export const requestText = (s) => (typeof s.request === "string" && s.request.trim()) ? s.request
  : REQUEST.split("[operator]").join(String(s.operator)).split("[feed]").join(String(s.feed));

const KEY = /^[a-z0-9][a-z0-9-]{1,60}$/, DAY = /^\d{4}-\d{2}-\d{2}$/;
const EMAIL = /^[^\s@<>"()]+@[a-z0-9.-]+\.[a-z]{2,}$/i, HTTPS = /^https:\/\/[a-z0-9.-]+\.[a-z]{2,}(\/[^\s<>"]*)?$/i;
const TEXT = { operator: 120, feed: 160, region: 120, what: 60, detail: 200 };
const ADDRESS = /[^\s@<>"()]+@[a-z0-9.-]+\.[a-z]{2,}/i;
export const REQUEST_MAX = 900;

/** Pure: problems with one entry ([] when it is fine). */
export function entryProblems(s) {
  const out = [], k = s && typeof s.key === "string" ? s.key : "?";
  if (!s || typeof s !== "object") return ["entry is not an object"];
  if (!KEY.test(k)) out.push(`${k}: key must be lowercase letters, digits and hyphens`);
  for (const [f, max] of Object.entries(TEXT)) {
    if (typeof s[f] !== "string" || !s[f].trim()) { if (f !== "region") out.push(`${k}: ${f} is required`); continue; }
    if (s[f].length > max) out.push(`${k}: ${f} is longer than ${max} characters`);
    if (/[<>]/.test(s[f])) out.push(`${k}: ${f} must be plain text (no < or >)`);
  }
  if (!COUNTRIES[s.country]) out.push(`${k}: country "${s.country}" is not a known two-letter code (add it to COUNTRIES in scripts/access.mjs)`);
  if (!(s.customers_served === null || (Number.isInteger(s.customers_served) && s.customers_served > 0 && s.customers_served < 1e9))) out.push(`${k}: customers_served must be a positive whole number or null`);
  if (!WHY[s.why_not]) out.push(`${k}: why_not must be one of ${Object.keys(WHY).join(", ")}`);
  if (!STATUS[s.status]) out.push(`${k}: status must be one of ${Object.keys(STATUS).join(", ")}`);
  if (typeof s.contact !== "string") out.push(`${k}: contact must be a string (empty when the operator publishes none)`);
  else if (s.contact && !EMAIL.test(s.contact) && !HTTPS.test(s.contact)) out.push(`${k}: contact must be an email address or an https page the operator publishes`);
  else if (!s.contact && !(typeof s.contact_note === "string" && s.contact_note.trim())) out.push(`${k}: contact_note is required when no contact is published (say what was looked for)`);
  if (s.contact_note !== undefined) {
    if (typeof s.contact_note !== "string" || s.contact_note.length > 200) out.push(`${k}: contact_note must be text of at most 200 characters`);
    else if (/[<>]/.test(s.contact_note)) out.push(`${k}: contact_note must be plain text (no < or >)`);
  }
  if (!KINDS[s.kind]) out.push(`${k}: kind must be one of ${Object.keys(KINDS).join(", ")}`);
  if (!(Number.isInteger(s.priority) && s.priority >= 1 && s.priority <= 9999)) out.push(`${k}: priority must be a whole number from 1 (ask first)`);
  const r = s.request;
  if (typeof r !== "string" || !r.trim()) out.push(`${k}: request is required (the text the owner sends)`);
  else {
    if (r.length > REQUEST_MAX) out.push(`${k}: request is longer than ${REQUEST_MAX} characters (${r.length})`);
    if (/[<>]/.test(r)) out.push(`${k}: request must be plain text (no < or >)`);
    if (!r.trimEnd().endsWith(SIGN)) out.push(`${k}: request must end with "${SIGN}"`);
    if (!r.includes("non-commercial")) out.push(`${k}: request must say CyberView is non-commercial`);
    if (ADDRESS.test(r)) out.push(`${k}: request must not contain an email address (it is signed by CyberView, not a person)`);
    if (/\[(operator|feed)\]/.test(r)) out.push(`${k}: request still has a [placeholder]`);
  }
  if (!DAY.test(String(s.updated || "")) || !isFinite(Date.parse(s.updated))) out.push(`${k}: updated must be a date (YYYY-MM-DD)`);
  return out;
}

/** Pure: problems with the whole document. */
export function problems(doc) {
  if (!doc || !Array.isArray(doc.sources)) return ["config/data-access.json: needs a sources list"];
  const out = [], seen = new Set(), ranks = new Map();
  for (const s of doc.sources) {
    out.push(...entryProblems(s));
    if (s && seen.has(s.key)) out.push(`${s.key}: duplicate key`);
    if (s) seen.add(s.key);
    if (s && Number.isInteger(s.priority)) {
      if (ranks.has(s.priority)) out.push(`${s.key}: priority ${s.priority} is also ${ranks.get(s.priority)}'s (each rank once)`);
      else ranks.set(s.priority, s.key);
    }
  }
  return out;
}

/** Pure: countries with the most sources first; inside each, the source to ask first first (priority), then biggest customer count. */
export function groups(sources) {
  const by = new Map();
  for (const s of sources) { if (!by.has(s.country)) by.set(s.country, []); by.get(s.country).push(s); }
  const rank = (s) => (Number.isInteger(s.priority) ? s.priority : 1e9);
  const cmp = (a, b) => rank(a) - rank(b) || (b.customers_served || 0) - (a.customers_served || 0) || a.operator.localeCompare(b.operator) || a.feed.localeCompare(b.feed);
  return [...by.entries()].map(([country, list]) => ({ country, name: COUNTRIES[country] || country, sources: list.sort(cmp) }))
    .sort((a, b) => b.sources.length - a.sources.length || a.name.localeCompare(b.name));
}

/** Pure: one block per kind (grid first), each grouped by country. */
export const kindGroups = (sources) => Object.keys(KINDS).map((kind) => ({ kind, name: KINDS[kind], groups: groups(sources.filter((s) => s.kind === kind)) })).filter((k) => k.groups.length);

/** Pure: the sources to ask first. */
export const askFirst = (sources, n = 15) => [...sources].filter((s) => s.status !== "in_use").sort((a, b) => a.priority - b.priority).slice(0, n);

const n = (x) => Number(x).toLocaleString("en-US");
const contactLink = (c) => (EMAIL.test(c) ? `mailto:${c}` : c);

/** The page's generated part (HTML, every value escaped). Entries that fail the check are left out. */
export function accessSection(doc) {
  const all = Array.isArray(doc && doc.sources) ? doc.sources : [];
  const ok = all.filter((s) => !entryProblems(s).length);
  const ks = kindGroups(ok), countries = groups(ok);
  const count = (f) => ok.filter(f).length;
  const reasons = Object.keys(WHY).map((w) => [w, count((s) => s.why_not === w)]).filter((x) => x[1]);
  const granted = count((s) => s.status === "granted"), asked = count((s) => s.status === "asked"), inUse = count((s) => s.status === "in_use");
  const withEmail = count((s) => EMAIL.test(s.contact)), withPage = count((s) => s.contact && !EMAIL.test(s.contact));
  const contactOf = (s) => s.contact
    ? `<a href="${esc(contactLink(s.contact))}" rel="noopener">${esc(s.contact)}</a>`
    : `<span class="muted">no contact published${s.contact_note ? " (" + esc(s.contact_note) + ")" : ""}</span>`;
  const rows = (g) => g.sources.map((s) => {
    const [st, cls] = STATUS[s.status];
    return `      <tr data-why="${esc(s.why_not)}" data-country="${esc(s.country)}" data-kind="${esc(s.kind)}" data-operator="${esc(s.operator)}" data-feed="${esc(s.feed)}" data-request="${esc(requestText(s))}" id="src-${esc(s.key)}">
        <td><strong>${esc(s.operator)}</strong><span class="sub">${esc(s.feed)}${s.region ? " · " + esc(s.region) : ""}</span></td>
        <td>${esc(s.what)}</td>
        <td class="num">${s.customers_served ? n(s.customers_served) : '<span class="muted">not stated</span>'}</td>
        <td>${esc(WHY[s.why_not])}<span class="sub">${esc(s.detail)}</span></td>
        <td><span class="badge ${cls}">${esc(st)}</span><span class="sub">Ask order ${esc(s.priority)} · ${esc(s.updated)}</span></td>
        <td><button type="button" class="btn copyreq" hidden>Copy request</button><span class="sub">Send to: ${contactOf(s)}</span>${s.contact && s.contact_note ? `<span class="sub">${esc(s.contact_note)}</span>` : ""}</td>
      </tr>`;
  }).join("\n");
  const first = askFirst(ok);
  return `<section class="panel" id="request">
  <h2>Ask these first</h2>
  <p class="note">Every source has its own short request, written for that operator and naming the exact feed. <strong>Copy request</strong> on a source's row shows it here and copies it, ready to paste into an email or the operator's contact form. The CyberView maintainer sends each request himself; this page never sends anything and keeps nothing you do here. The order puts public bodies and open-data teams, the largest gaps in coverage and the sources that were most productive first.</p>
  <ol class="askfirst" id="askFirst">
${first.map((s) => `    <li><a href="#src-${esc(s.key)}"><strong>${esc(s.operator)}</strong></a> <span class="muted">${esc(s.feed)}</span><span class="sub">Send to: ${contactOf(s)}</span></li>`).join("\n")}
  </ol>
  <pre class="req" id="reqText" tabindex="0">${esc(REQUEST)}</pre>
  <p class="note" id="reqMsg" aria-live="polite">Above: the shape every request follows. Choose Copy request on a source to see and copy its own text.</p>
</section>
<section class="panel" id="sources">
  <h2>${ok.length - inUse} sources CyberView does not use yet</h2>
  <ul class="plain" id="reasons">
${reasons.map(([w, c]) => `    <li><strong>${c}</strong> ${esc(WHY[w].toLowerCase())}</li>`).join("\n")}
  </ul>
  <p class="note">${inUse ? `${inUse} now read through another open route (marked In use). ` : ""}${granted ? `${granted} granted and being connected. ` : ""}${asked ? `${asked} asked and waiting for an answer. ` : ""}${withEmail} publish an email address for the request and ${withPage} a contact page or form; for the rest none could be found. Contacts are the ones each operator publishes on its own site. Inside each country, the source to ask first comes first.</p>
  <div class="acfilters" id="acFilters" hidden>
    <label class="field">Kind<select id="fKind"><option value="">Every kind</option>${ks.map((k) => `<option value="${esc(k.kind)}">${esc(k.name)} (${k.groups.reduce((a, g) => a + g.sources.length, 0)})</option>`).join("")}</select></label>
    <label class="field">Reason<select id="fWhy"><option value="">Every reason</option>${reasons.map(([w, c]) => `<option value="${esc(w)}">${esc(WHY[w])} (${c})</option>`).join("")}</select></label>
    <label class="field">Country<select id="fCountry"><option value="">Every country</option>${countries.map((g) => `<option value="${esc(g.country)}">${esc(g.name)} (${g.sources.length})</option>`).join("")}</select></label>
  </div>
  <p class="note" id="fCount" aria-live="polite"></p>
${ks.map((k) => `  <div class="ackind" data-kind="${esc(k.kind)}">
  <h3>${esc(k.name)}</h3>
${k.groups.map((g) => `  <div class="acgroup" data-country="${esc(g.country)}">
    <h4>${esc(g.name)} <span class="muted">(${g.sources.length})</span></h4>
    <div class="tablewrap"><table class="stack">
      <thead><tr><th scope="col">Operator and feed</th><th scope="col">What</th><th scope="col">Customers</th><th scope="col">Why not yet</th><th scope="col">Status</th><th scope="col">Request</th></tr></thead>
      <tbody>
${rows(g)}
      </tbody>
    </table></div>
  </div>`).join("\n")}
  </div>`).join("\n")}
</section>`;
}

async function main() {
  const cmd = process.argv[2] || "check", doc = load();
  const p = problems(doc);
  if (cmd === "show") { const k = process.argv[3], s = k && (doc.sources || []).find((x) => x.key === k); console.log(s ? requestText(s) : REQUEST); return; }
  if (p.length) { console.log(`access: ${p.length} problem(s)`); p.forEach((x) => console.log("  " + x)); process.exit(1); }
  const by = (f) => Object.entries(doc.sources.reduce((a, s) => ((a[s[f]] = (a[s[f]] || 0) + 1), a), {})).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k} ${v}`).join(", ");
  const email = doc.sources.filter((s) => EMAIL.test(s.contact)).length, page = doc.sources.filter((s) => s.contact && !EMAIL.test(s.contact)).length;
  console.log(`access: ${doc.sources.length} sources check out\n  by kind: ${by("kind")}\n  by reason: ${by("why_not")}\n  by country: ${by("country")}\n  by status: ${by("status")}\n  contact: ${email} email, ${page} page or form, ${doc.sources.length - email - page} none published`);
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
