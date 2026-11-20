// Data CyberView would like to use: the sources it does not have access to, and the request for each. No AI model.
// config/data-access.json is the curated list (one entry per source). This script
//   - checks it (`check`: every field present and in range, no guessed contact, keys unique); a unit test runs the
//     same check on the real file, so a broken entry fails CI
//   - renders the generated part of the page (scripts/pages.mjs calls accessSection() for legal/access.html; entries that
//     fail the check are left out and reported, so one bad entry can never hold back a build)
//   - holds the one request text the owner sends himself (the page only copies it; it never sends anything)
// Run: node scripts/access.mjs check | show
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { ROOT } from "./lib/store.mjs";

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
export const load = () => JSON.parse(readFileSync(join(ROOT, "config", "data-access.json"), "utf8"));

export const WHY = {
  terms: "Terms restrict reuse, or none were found",
  robots: "robots.txt disallows the data path",
  blocks_readers: "Blocks automated readers",
  key_or_account: "Needs a key or an account",
  unavailable: "Could not be reached",
};
export const STATUS = { not_asked: ["Not asked yet", "wait"], asked: ["Asked, waiting", "info"], granted: ["Granted", "ok"], declined: ["Declined", "bad"] };
export const COUNTRIES = {
  US: "United States", CA: "Canada", GB: "United Kingdom", IE: "Ireland", NL: "Netherlands", FR: "France", DE: "Germany", ES: "Spain",
  PT: "Portugal", IT: "Italy", GR: "Greece", PL: "Poland", CZ: "Czechia", SE: "Sweden", FI: "Finland", DK: "Denmark", EE: "Estonia",
  LT: "Lithuania", LV: "Latvia", SI: "Slovenia", HU: "Hungary", AT: "Austria", RO: "Romania", HR: "Croatia", RS: "Serbia", BG: "Bulgaria",
  UA: "Ukraine", TR: "Turkey", AU: "Australia", NZ: "New Zealand", JP: "Japan", TW: "Taiwan", KR: "South Korea", PH: "Philippines",
  MY: "Malaysia", SG: "Singapore", IN: "India", PK: "Pakistan", BD: "Bangladesh", ID: "Indonesia", VN: "Vietnam", TH: "Thailand",
  ZA: "South Africa", KE: "Kenya", NG: "Nigeria", ZM: "Zambia", ZW: "Zimbabwe", CL: "Chile", MX: "Mexico", PR: "Puerto Rico",
  CO: "Colombia", PE: "Peru", IL: "Israel", LB: "Lebanon", IQ: "Iraq", AE: "United Arab Emirates", SA: "Saudi Arabia", KW: "Kuwait",
};
export const SITE = "https://xanderhutch.github.io/CyberView/";

// The one request. [operator] and [feed] are filled in by the page's "Copy request" button.
export const REQUEST = `Subject: Request to show [operator] outage information on CyberView

Hello,

I run CyberView (${SITE}), a free, non-commercial website that gives cyber security defenders a live picture of threats worldwide, with power outages shown as context.

I would like to use your [feed]. CyberView only uses sources whose terms and robots.txt allow it, and it never works around a block, so I am asking first.

What CyberView would do with it:
- show your current outages or grid alerts as context, never as a claim about their cause
- credit [operator] and link to your own outage map or page
- check for updates every few minutes, no more often
- collect no personal data and make no commercial use of the data

Would you allow this? If you would rather I use a particular feed, API or licence, please point me to it. I will follow any conditions you set, and stop if you ask.

Thank you,
The CyberView maintainer
${SITE}access.html`;

/** The request for one source (the same substitution the page does). */
export const requestText = (s) => REQUEST.split("[operator]").join(String(s.operator)).split("[feed]").join(String(s.feed));

const KEY = /^[a-z0-9][a-z0-9-]{1,60}$/, DAY = /^\d{4}-\d{2}-\d{2}$/;
const EMAIL = /^[^\s@<>"()]+@[a-z0-9.-]+\.[a-z]{2,}$/i, HTTPS = /^https:\/\/[a-z0-9.-]+\.[a-z]{2,}(\/[^\s<>"]*)?$/i;
const TEXT = { operator: 120, feed: 160, region: 120, what: 60, detail: 200 };

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
  if (!DAY.test(String(s.updated || "")) || !isFinite(Date.parse(s.updated))) out.push(`${k}: updated must be a date (YYYY-MM-DD)`);
  return out;
}

/** Pure: problems with the whole document. */
export function problems(doc) {
  if (!doc || !Array.isArray(doc.sources)) return ["config/data-access.json: needs a sources list"];
  const out = [], seen = new Set();
  for (const s of doc.sources) {
    out.push(...entryProblems(s));
    if (s && seen.has(s.key)) out.push(`${s.key}: duplicate key`);
    if (s) seen.add(s.key);
  }
  return out;
}

/** Pure: countries with the most sources first; inside each, biggest customer count first (unknown last), then by name. */
export function groups(sources) {
  const by = new Map();
  for (const s of sources) { if (!by.has(s.country)) by.set(s.country, []); by.get(s.country).push(s); }
  const cmp = (a, b) => (b.customers_served || 0) - (a.customers_served || 0) || a.operator.localeCompare(b.operator) || a.feed.localeCompare(b.feed);
  return [...by.entries()].map(([country, list]) => ({ country, name: COUNTRIES[country] || country, sources: list.sort(cmp) }))
    .sort((a, b) => b.sources.length - a.sources.length || a.name.localeCompare(b.name));
}

const n = (x) => Number(x).toLocaleString("en-US");
const contactLink = (c) => (EMAIL.test(c) ? `mailto:${c}` : c);

/** The page's generated part (HTML, every value escaped). Entries that fail the check are left out. */
export function accessSection(doc) {
  const all = Array.isArray(doc && doc.sources) ? doc.sources : [];
  const ok = all.filter((s) => !entryProblems(s).length);
  const gs = groups(ok);
  const count = (f) => ok.filter(f).length;
  const reasons = Object.keys(WHY).map((w) => [w, count((s) => s.why_not === w)]).filter((x) => x[1]);
  const granted = count((s) => s.status === "granted"), asked = count((s) => s.status === "asked");
  const rows = (g) => g.sources.map((s) => {
    const [st, cls] = STATUS[s.status];
    const contact = s.contact ? `<span class="sub">Operator's contact: <a href="${esc(contactLink(s.contact))}" rel="noopener">${esc(s.contact)}</a></span>` : "";
    return `      <tr data-why="${esc(s.why_not)}" data-country="${esc(s.country)}" data-operator="${esc(s.operator)}" data-feed="${esc(s.feed)}" id="src-${esc(s.key)}">
        <td><strong>${esc(s.operator)}</strong><span class="sub">${esc(s.feed)}${s.region ? " · " + esc(s.region) : ""}</span></td>
        <td>${esc(s.what)}</td>
        <td class="num">${s.customers_served ? n(s.customers_served) : '<span class="muted">not stated</span>'}</td>
        <td>${esc(WHY[s.why_not])}<span class="sub">${esc(s.detail)}</span></td>
        <td><span class="badge ${cls}">${esc(st)}</span><span class="sub">${esc(s.updated)}</span></td>
        <td><button type="button" class="btn copyreq" hidden>Copy request</button>${contact}</td>
      </tr>`;
  }).join("\n");
  return `<section class="panel" id="request">
  <h2>The request</h2>
  <p class="note">One short text for every source. <strong>Copy request</strong> on a source's row puts that operator's name and the specific feed into it and copies it. The CyberView maintainer sends each request himself; this page never sends anything and keeps nothing you do here.</p>
  <pre class="req" id="reqText" tabindex="0">${esc(REQUEST)}</pre>
  <p class="note" id="reqMsg" aria-live="polite"></p>
</section>
<section class="panel" id="sources">
  <h2>${ok.length} sources CyberView does not use yet</h2>
  <ul class="plain" id="reasons">
${reasons.map(([w, c]) => `    <li><strong>${c}</strong> ${esc(WHY[w].toLowerCase())}</li>`).join("\n")}
  </ul>
  <p class="note">${granted ? `${granted} granted and being connected. ` : ""}${asked ? `${asked} asked and waiting for an answer. ` : ""}Countries with the most sources come first; inside each country, the operators serving the most customers come first (customer counts as the operator's own feed or page states them).</p>
  <div class="acfilters" id="acFilters" hidden>
    <label class="field">Reason<select id="fWhy"><option value="">Every reason</option>${reasons.map(([w, c]) => `<option value="${esc(w)}">${esc(WHY[w])} (${c})</option>`).join("")}</select></label>
    <label class="field">Country<select id="fCountry"><option value="">Every country</option>${gs.map((g) => `<option value="${esc(g.country)}">${esc(g.name)} (${g.sources.length})</option>`).join("")}</select></label>
  </div>
  <p class="note" id="fCount" aria-live="polite"></p>
${gs.map((g) => `  <div class="acgroup" data-country="${esc(g.country)}">
    <h3>${esc(g.name)} <span class="muted">(${g.sources.length})</span></h3>
    <div class="tablewrap"><table class="stack">
      <thead><tr><th scope="col">Operator and feed</th><th scope="col">What</th><th scope="col">Customers</th><th scope="col">Why not yet</th><th scope="col">Status</th><th scope="col">Request</th></tr></thead>
      <tbody>
${rows(g)}
      </tbody>
    </table></div>
  </div>`).join("\n")}
</section>`;
}

async function main() {
  const cmd = process.argv[2] || "check", doc = load();
  const p = problems(doc);
  if (cmd === "show") { console.log(requestText({ operator: "Example Power", feed: "Example Power outage map" })); return; }
  if (p.length) { console.log(`access: ${p.length} problem(s)`); p.forEach((x) => console.log("  " + x)); process.exit(1); }
  const by = (f) => Object.entries(doc.sources.reduce((a, s) => ((a[s[f]] = (a[s[f]] || 0) + 1), a), {})).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k} ${v}`).join(", ");
  console.log(`access: ${doc.sources.length} sources check out\n  by reason: ${by("why_not")}\n  by country: ${by("country")}\n  by status: ${by("status")}`);
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
