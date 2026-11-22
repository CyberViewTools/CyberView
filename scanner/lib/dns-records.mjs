// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// Mail and certificate DNS records (scan-dns-records), OFF by default: only with --dns-records DOMAIN[,DOMAIN]. Each domain
// must be a host name listed in the scope file's targets (anything else is refused before any query). For each domain the
// system resolver (node:dns Resolver; nothing is sent to the targets themselves) is asked, once each:
//   SPF     TXT  <domain>                     DMARC  TXT  _dmarc.<domain>
//   CAA     CAA  <domain>                     BIMI   TXT  default._bimi.<domain>
//   MTA-STS TXT  _mta-sts.<domain> (the HTTPS policy file is NOT fetched: that GET is not built)
//   DKIM    TXT  <selector>._domainkey.<domain>, ONLY for selectors the operator names with --dkim-selectors (never guessed)
// DNSSEC presence (DS/DNSKEY) is NOT checked: node:dns has no DS or DNSKEY query. No zone transfer, no ANY, no brute force,
// no other record type, no look-alike or typo names. scripts/lib/scanner-hello-check.mjs (security-check section 7) enforces
// the record types and the name table.
import { Resolver } from "node:dns/promises";
import { createPublicKey } from "node:crypto";

const clip = (s, n) => String(s == null ? "" : s).replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, n);
export const MAX_DOMAINS = 16, MAX_SELECTORS = 8;
/** The frozen query table: check -> { prefix, type }. The queried name is prefix + domain (DKIM: selector + prefix + domain). */
export const QUERIES = Object.freeze([
  Object.freeze({ check: "spf", prefix: "", type: "TXT" }),
  Object.freeze({ check: "dmarc", prefix: "_dmarc.", type: "TXT" }),
  Object.freeze({ check: "caa", prefix: "", type: "CAA" }),
  Object.freeze({ check: "bimi", prefix: "default._bimi.", type: "TXT" }),
  Object.freeze({ check: "mta-sts", prefix: "_mta-sts.", type: "TXT" }),
]);
export const DKIM_PREFIX = "._domainkey.";
export const DNS_SENDS = Object.freeze({
  "dns-records": "only with --dns-records DOMAIN[,DOMAIN] (off by default): for each domain listed in the scope file's targets, one query each to the system resolver: TXT (SPF), TXT _dmarc, CAA, TXT default._bimi, TXT _mta-sts, and TXT <selector>._domainkey only for selectors named with --dkim-selectors; no zone transfer, no ANY, no other record type, nothing sent to the targets",
});

const LABEL = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/;
const SELECTOR = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;

/** --dns-records and --dkim-selectors against the scope -> { ok, domains, selectors, problems } (nothing is queried). */
export function dnsPlanArgs(scope, domainsArg, selectorsArg) {
  const problems = [], listed = new Set(((scope && scope.hosts) || []).map((h) => String(h).toLowerCase()));
  const domains = [...new Set(String(domainsArg || "").split(",").map((d) => d.trim().toLowerCase().replace(/\.$/, "")).filter(Boolean))];
  const selectors = [...new Set(String(selectorsArg || "").split(",").map((s) => s.trim()).filter(Boolean))];
  if (!domains.length) problems.push("--dns-records needs at least one domain");
  if (domains.length > MAX_DOMAINS) problems.push(`--dns-records: at most ${MAX_DOMAINS} domains`);
  for (const d of domains) {
    if (!LABEL.test(d)) problems.push(`--dns-records: "${clip(d, 80)}" is not a domain name`);
    else if (!listed.has(d)) problems.push(`--dns-records: "${d}" is not a host name listed in the scope file's targets; only attested names are queried`);
  }
  if (selectors.length > MAX_SELECTORS) problems.push(`--dkim-selectors: at most ${MAX_SELECTORS} selectors`);
  for (const s of selectors) if (!SELECTOR.test(s)) problems.push(`--dkim-selectors: "${clip(s, 80)}" is not a DKIM selector label`);
  return { ok: !problems.length, domains, selectors, problems };
}

/** The exact (name, type) list for one domain. */
export function dnsQueries(domain, selectors = []) {
  return [...QUERIES.map((q) => ({ check: q.check, name: q.prefix + domain, type: q.type })),
    ...selectors.map((s) => ({ check: "dkim", selector: s, name: s + DKIM_PREFIX + domain, type: "TXT" }))];
}

const joinTxt = (rows) => (rows || []).map((r) => (Array.isArray(r) ? r.join("") : String(r)));

/** One query's answer -> rows of { domain, check, name, status, value, observation } and observations (pure). */
export function interpret(q, answer, domain) {
  const row = (status, value = "", observation = "") => ({ domain, check: q.check, ...(q.selector ? { selector: q.selector } : {}), name: q.name, type: q.type, status, value: clip(value, 300), observation });
  const obs = [], O = (severity, kind, text) => { obs.push({ domain, kind, severity, text }); return text; };
  if (answer.error && !/ENODATA|ENOTFOUND/.test(answer.error)) return { rows: [row("error", answer.error)], obs };
  const txt = answer.error ? [] : q.type === "TXT" ? joinTxt(answer.records) : [];
  if (q.check === "spf") {
    const spf = txt.filter((t) => /^v=spf1(\s|$)/i.test(t));
    if (!spf.length) return { rows: [row("absent", "", O("medium", "spf-missing", `${domain} has no SPF record: receivers cannot tell which servers may send its mail`))], obs };
    if (spf.length > 1) return { rows: [row("present", spf.join(" | "), O("medium", "spf-multiple", `${domain} publishes ${spf.length} SPF records: receivers treat that as a permanent error (RFC 7208 section 4.5)`))], obs };
    const all = /(?:^|\s)([+?~-]?)all(?:\s|$)/i.exec(spf[0]);
    const note = !all ? (/\bredirect=/i.test(spf[0]) ? "" : O("low", "spf-no-all", `${domain}'s SPF record ends with no "all" mechanism: mail from other servers gets a neutral result`))
      : all[1] === "+" || all[1] === "" ? O("high", "spf-pass-all", `${domain}'s SPF record ends in "${all[1]}all": it authorizes every server on the internet to send as ${domain}`)
      : all[1] === "?" ? O("low", "spf-neutral-all", `${domain}'s SPF record ends in "?all" (neutral): it does not tell receivers to distrust other senders`) : "";
    return { rows: [row("present", spf[0], note)], obs };
  }
  if (q.check === "dmarc") {
    const d = txt.filter((t) => /^v=DMARC1\s*(;|$)/i.test(t));
    if (!d.length) return { rows: [row("absent", "", O("medium", "dmarc-missing", `${domain} has no DMARC record (_dmarc.${domain}): receivers get no policy for mail that fails SPF and DKIM`))], obs };
    if (d.length > 1) return { rows: [row("present", d.join(" | "), O("medium", "dmarc-multiple", `${domain} publishes ${d.length} DMARC records: receivers ignore DMARC when there is more than one`))], obs };
    const p = (/(?:^|;)\s*p\s*=\s*([a-z]+)/i.exec(d[0]) || [])[1] || "";
    const note = !p ? O("medium", "dmarc-no-policy", `${domain}'s DMARC record has no p= policy tag`) : p.toLowerCase() === "none" ? O("low", "dmarc-p-none", `${domain}'s DMARC policy is p=none (monitoring only): failing mail is still delivered`) : "";
    return { rows: [row("present", d[0], note)], obs };
  }
  if (q.check === "caa") {
    const recs = answer.error ? [] : (answer.records || []).map((r) => Object.entries(r).filter(([k]) => k !== "critical").map(([k, v]) => `${k} ${v}`).join(" ")).filter(Boolean);
    if (!recs.length) return { rows: [row("absent", "", O("low", "caa-missing", `${domain} has no CAA record: any certificate authority may issue certificates for it`))], obs };
    return { rows: [row("present", recs.join(" | "))], obs };
  }
  if (q.check === "bimi") {
    const b = txt.filter((t) => /^v=BIMI1\s*(;|$)/i.test(t));
    return { rows: [b.length ? row("present", b[0]) : row("absent")], obs };
  }
  if (q.check === "mta-sts") {
    const m = txt.filter((t) => /^v=STSv1\s*(;|$)/i.test(t));
    return { rows: [m.length ? row("present", m[0], "TXT record only; the policy file (https://mta-sts.<domain>/.well-known/mta-sts.txt) is not fetched by this scanner") : row("absent")], obs };
  }
  if (q.check === "dkim") {
    const k = txt.filter((t) => /(^|;)\s*p\s*=/i.test(t))[0];
    if (!k) return { rows: [row("absent", "", `no DKIM key at selector "${q.selector}"`)], obs };
    const tags = Object.fromEntries(k.split(";").map((x) => x.trim().split(/=(.*)/s)).filter((x) => x[0]).map(([a, b]) => [a.trim().toLowerCase(), (b || "").replace(/\s+/g, "")]));
    const kt = (tags.k || "rsa").toLowerCase();
    if (!tags.p) return { rows: [row("present", `k=${kt}; key revoked (empty p=)`)], obs };
    let bits = 0;
    if (kt === "rsa") { try { bits = createPublicKey({ key: Buffer.from(tags.p, "base64"), format: "der", type: "spki" }).asymmetricKeyDetails.modulusLength || 0; } catch { bits = 0; } }
    const note = kt === "rsa" && bits && bits < 1024 ? O("medium", "dkim-weak-key", `${domain}'s DKIM key at selector "${q.selector}" is RSA ${bits} bits: below 1024 bits it can be factored and mail forged`) : "";
    return { rows: [row("present", `k=${kt}${bits ? `; ${bits} bits` : ""}`, note)], obs };   // the key itself is not stored
  }
  return { rows: [], obs };
}

/**
 * Query every planned record for every attested domain, one at a time. resolver: an object with resolveTxt and resolveCaa
 * (default: a node:dns Resolver with the system's servers). Refuses unattested names again here. Stops on signal.
 * -> { domains, selectors, resolver, records: [row], observations: [], not_checked: [] }
 */
export async function dnsRecords(scope, domains, selectors = [], { resolver = null, signal = null } = {}) {
  const plan = dnsPlanArgs(scope, domains.join(","), selectors.join(","));
  if (!plan.ok) return { error: plan.problems.join("; "), records: [], observations: [] };
  const r = resolver || new Resolver({ timeout: 3000, tries: 1 });
  const out = { domains: plan.domains, selectors: plan.selectors, resolver: resolver ? "given" : "system", records: [], observations: [],
    not_checked: ["DNSSEC (DS/DNSKEY) presence: node:dns has no DS or DNSKEY query", "MTA-STS policy file: the HTTPS GET of /.well-known/mta-sts.txt is not built"] };
  const ask = { TXT: (n) => r.resolveTxt(n), CAA: (n) => r.resolveCaa(n) };
  for (const d of plan.domains) for (const q of dnsQueries(d, plan.selectors)) {
    if (signal && signal.aborted) { out.records.push({ domain: d, check: q.check, name: q.name, type: q.type, status: "not-checked", value: "stopped", observation: "" }); continue; }
    let answer;
    try { answer = { records: await ask[q.type](q.name) }; } catch (e) { answer = { error: String((e && (e.code || e.message)) || e).slice(0, 60) }; }
    const { rows, obs } = interpret(q, answer, d);
    out.records.push(...rows); out.observations.push(...obs);
  }
  return out;
}

const cell = (v) => { let s = v == null ? "" : String(v); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
export const DNS_HEAD = ["domain", "check", "name", "type", "status", "value", "observation"];
export function toDnsCsv(res) {
  return [DNS_HEAD, ...((res && res.records) || []).map((x) => [x.domain, x.check, x.name, x.type, x.status, x.value, x.observation])].map((r) => r.map(cell).join(",")).join("\r\n") + "\r\n";
}
export function dnsText(res) {
  if (!res || !res.records) return "";
  const L = [`DNS records (--dns-records, system resolver): ${res.domains.join(", ")}`];
  for (const x of res.records) L.push(`   ${x.name} ${x.type}: ${x.status}${x.value ? ` (${x.value.slice(0, 100)})` : ""}${x.observation ? ` - ${x.observation}` : ""}`);
  res.not_checked.forEach((n) => L.push(`   not checked: ${n}`));
  return L.join("\n");
}
