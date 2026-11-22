// Pure helpers for the CVE corpus: one compact row per CVE from the official CVE List (CVE JSON 5, including CISA's
// "vulnrichment" ADP container: CVSS, CWE, SSVC exploitation, KEV), plus FIRST EPSS scores. No network here.
import { parseAffected } from "./affected.mjs";

export const ID = /^CVE-\d{4}-\d{4,}$/;
const txt = (s, n) => String(s == null ? "" : s).replace(/\s+/g, " ").trim().slice(0, n);
const day = (s) => (/^\d{4}-\d{2}-\d{2}/.test(String(s || "")) ? String(s).slice(0, 10) : "");
const SEV = { CRITICAL: "C", HIGH: "H", MEDIUM: "M", LOW: "L", NONE: "N" };

/** Best CVSS from a metrics array: v4.0, then v3.1, v3.0, v2. -> {score, sev, ver} or null */
export function bestCvss(metrics) {
  for (const k of ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"])
    for (const m of metrics || []) {
      const c = m && m[k];
      if (c && typeof c.baseScore === "number") return { score: c.baseScore, sev: SEV[String(c.baseSeverity || "").toUpperCase()] || sevOf(c.baseScore), ver: k.replace("cvssV", "").replace("_", "."), vec: /^[A-Za-z0-9.:\/]{8,200}$/.test(c.vectorString || "") ? c.vectorString : "" };
    }
  return null;
}
const sevOf = (s) => (s >= 9 ? "C" : s >= 7 ? "H" : s >= 4 ? "M" : s > 0 ? "L" : "N");

/** CVE JSON 5 record -> compact row, or null if it is not a CVE record. */
export function compact(r) {
  const md = (r && r.cveMetadata) || {}, id = md.cveId;
  if (!ID.test(id || "")) return null;
  const cna = (r.containers && r.containers.cna) || {}, adp = (r.containers && r.containers.adp) || [];
  const rejected = md.state === "REJECTED";
  const desc = ((cna.descriptions || []).find((d) => /^en/i.test(d.lang || "")) || (cna.descriptions || [])[0] || (cna.rejectedReasons || [])[0] || {}).value || "";
  let cvss = bestCvss(cna.metrics);
  let exploitation = "", kev = "", cwe = "", automatable = "", impact = "";
  for (const a of adp) {
    if (!cvss) cvss = bestCvss(a.metrics);
    for (const m of a.metrics || []) {
      const o = m && m.other;
      if (o && o.type === "ssvc") for (const opt of (o.content && o.content.options) || []) {
        if (opt && opt.Exploitation) exploitation = String(opt.Exploitation).toLowerCase();
        if (opt && opt.Automatable) automatable = String(opt.Automatable).toLowerCase();
        if (opt && opt["Technical Impact"]) impact = String(opt["Technical Impact"]).toLowerCase();
      }
      if (o && o.type === "kev") kev = day(o.content && o.content.dateAdded) || "yes";
    }
  }
  for (const p of [cna, ...adp]) for (const pt of p.problemTypes || []) for (const d of pt.descriptions || []) if (!cwe && /^CWE-\d+$/.test(d.cweId || "")) cwe = d.cweId;
  const aff = (cna.affected || []).find((a) => a && (a.vendor || a.product)) || {};
  return {
    id, state: rejected ? "R" : "P",
    pub: day(md.datePublished), upd: day(md.dateUpdated) || day(md.datePublished),
    cvss: cvss ? cvss.score : null, sev: cvss ? cvss.sev : "", ver: cvss ? cvss.ver : "",
    cwe, vendor: txt(aff.vendor && aff.vendor !== "n/a" ? aff.vendor : "", 60), product: txt(aff.product && aff.product !== "n/a" ? aff.product : "", 80),
    title: txt(cna.title || "", 160), desc: txt(desc, 600), cna: txt(md.assignerShortName, 40),
    expl: ["none", "poc", "active"].includes(exploitation) ? exploitation : "", kev,
    auto: ["yes", "no"].includes(automatable) ? automatable : "", ti: ["total", "partial"].includes(impact) ? impact : "", vec: cvss ? cvss.vec : "",
  };
}

/** EPSS CSV (#comment line, header cve,epss,percentile) -> Map(id -> [epss, percentile]) */
export function parseEpss(csv) {
  const m = new Map();
  for (const line of String(csv).split("\n")) {
    const [id, e, p] = line.trim().split(",");
    if (ID.test(id || "") && e !== undefined) m.set(id, [Math.round(Number(e) * 1e5) / 1e5, Math.round(Number(p) * 1e4) / 1e4]);
  }
  return m;
}

/** Bucket a CVE id for the site's lookup files: CVE-2024-3400 -> "2024/3" (thousands). */
export function bucket(id) { const [, y, n] = String(id).split("-"); return `${y}/${Math.floor(Number(n) / 1000)}`; }

/** deltaLog.json -> [{id, url, at}] changed after `since` (ISO), newest kept per id. */
export function deltaSince(log, since) {
  const out = new Map();
  for (const run of Array.isArray(log) ? log : []) {
    if (!run || String(run.fetchTime || "") <= String(since || "")) continue;
    for (const k of ["new", "updated"]) for (const c of run[k] || [])
      if (c && ID.test(c.cveId || "") && /^https:\/\/raw\.githubusercontent\.com\/CVEProject\/cvelistV5\//.test(c.githubLink || "")) {
        const at = String(c.dateUpdated || run.fetchTime), prev = out.get(c.cveId);
        if (!prev || prev.at < at) out.set(c.cveId, { id: c.cveId, url: c.githubLink, at, isNew: k === "new" || (prev && prev.isNew) });
      }
  }
  return [...out.values()];
}

/** Is this row worth a research lead? Exploited (SSVC active or KEV) or critical, published recently. */
export function notable(row, sinceDay) {
  return !!row && row.state === "P" && row.pub >= sinceDay && (row.expl === "active" || !!row.kev || (row.cvss != null && row.cvss >= 9));
}

/** Row -> lead in the collectors' shape (data/leads/<date>.jsonl). */
export function toLead(row, seenAt) {
  const what = row.title || row.desc;
  return {
    seen_at: seenAt, source: "CVE List (CVE.org)", tier: "gov", via: "cvelist",
    title: txt(`${row.id}${row.cvss != null ? ` (CVSS ${row.cvss})` : ""}${row.vendor ? ` ${row.vendor} ${row.product}`.replace(/\s+$/, "") : ""}: ${what}`, 200),
    url: `https://www.cve.org/CVERecord?id=${row.id}`, published: row.pub ? row.pub + "T00:00:00Z" : seenAt,
    summary: txt(row.desc, 300), kind: row.expl === "active" || row.kev ? "exploited" : "cve",
  };
}

// Affected-version ranges from NVD's CPE match data (its "configurations"), in the SAME shape the browser matcher expects
// (CVWorkbench.match / the site's cleanRange: {vendor, product, from, from_incl, to, to_incl, exact}); the KEV/workbench path
// in site/data/workbench.json already carries this shape, so one matcher serves every CVE. `part` and `update` are dropped
// (the matcher does not use them), booleans are stored only when true, and the list is capped per CVE to keep the lookup files
// (served to browsers) small. parseAffected is pure, so this stays network-free.
export const RANGE_CAP = 16;
export function affectedFromNvd(nvdCve) {
  const out = [];
  for (const r of parseAffected(nvdCve)) {            // [{vendor, product, part, from, from_incl, to, to_incl, exact}]
    if (!r.product) continue;
    const o = { vendor: r.vendor || "", product: r.product };
    if (r.from) { o.from = r.from; if (r.from_incl) o.from_incl = true; }
    if (r.to) { o.to = r.to; if (r.to_incl) o.to_incl = true; }
    if (r.exact) o.exact = r.exact;
    out.push(o);
    if (out.length >= RANGE_CAP) break;
  }
  return out;
}

// fields of the site's lookup files, in order (rows are arrays to keep the files small). `aff` is the affected-version
// ranges (affectedFromNvd), null when NVD has published none for the CVE yet.
export const FIELDS = ["id", "state", "pub", "upd", "cvss", "sev", "ver", "cwe", "vendor", "product", "title", "desc", "cna", "expl", "kev", "epss", "pct",
  "auto", "ti", "vec", "due", "ransom", "ncvss", "nsev", "nvec", "n3", "n3c", "aff"];

/** CISA KEV catalog JSON -> Map(id -> {added, due, ransom}) */
export function parseKevCatalog(j) {
  const m = new Map();
  for (const v of (j && j.vulnerabilities) || []) if (ID.test(v.cveID || "")) m.set(v.cveID, { added: day(v.dateAdded), due: day(v.dueDate), ransom: /^known$/i.test(v.knownRansomwareCampaignUse || "") });
  return m;
}
/** NVD API 2.0 vulnerability item -> {ncvss, nsev, nvec} from NVD's own (Primary) score, v4.0 then v3.1, v3.0, v2. */
export function nvdScore(item) {
  const m = (item && item.cve && item.cve.metrics) || {};
  // NVD's CVSS v3 ratings kept apart: NVD counts "critical" from v3 (n3: NVD's own Primary v3 rating; n3c: any v3 rating
  // NVD lists, its own or the assigner's, is Critical)
  const v3 = [...(m.cvssMetricV31 || []), ...(m.cvssMetricV30 || [])], p3 = v3.find((y) => y && y.type === "Primary");
  const sev3 = (x) => SEV[String((x && ((x.cvssData && x.cvssData.baseSeverity) || x.baseSeverity)) || "").toUpperCase()] || "";
  const extra = { n3: p3 ? sev3(p3) : "", n3c: v3.some((y) => sev3(y) === "C") };
  for (const k of ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]) {
    const list = m[k] || [], x = list.find((y) => y && y.type === "Primary") || list[0];
    const d = x && x.cvssData;
    if (d && typeof d.baseScore === "number") return { ...extra, ncvss: d.baseScore, nsev: SEV[String(d.baseSeverity || x.baseSeverity || "").toUpperCase()] || sevOf(d.baseScore), nvec: /^[A-Za-z0-9.:\/()]{8,200}$/.test(d.vectorString || "") ? d.vectorString : "" };
  }
  return v3.length ? { ...extra, ncvss: null, nsev: "", nvec: "" } : null;
}
export const toArr = (r) => FIELDS.map((k) => (r[k] === undefined ? null : r[k]));
