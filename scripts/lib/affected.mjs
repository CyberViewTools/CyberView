// Affected-version ranges for a CVE, from NVD's CPE match data (the "configurations" of a CVE record).
// Used by scripts/feeds.mjs; the workbench compares a visitor's software versions against these, in the browser.
// Each range: { vendor, product, part (a application, o operating system, h hardware), from, from_incl, to, to_incl, exact }
//   exact  = one specific vulnerable version
//   from/to = a range; to with to_incl false means "fixed in <to>"
//   none of them = every version of the product is listed as vulnerable
const clean = (s) => String(s || "").replace(/\\(.)/g, "$1").replace(/_/g, " ").replace(/[^\w .+\-]/g, "").trim().slice(0, 60);
const ver = (s) => { s = String(s || "").replace(/\\(.)/g, "$1").trim(); return s && s !== "*" && s !== "-" && /^[\w.+\-~:]{1,40}$/.test(s) ? s : ""; };

/** NVD "cve" object (vulnerabilities[0].cve) -> list of ranges, at most 60, duplicates removed. */
export function parseAffected(cve) {
  const out = [], seen = new Set();
  const walk = (nodes) => {
    for (const n of Array.isArray(nodes) ? nodes : []) {
      for (const m of Array.isArray(n.cpeMatch) ? n.cpeMatch : []) {
        if (!m || m.vulnerable !== true || typeof m.criteria !== "string") continue;
        const f = m.criteria.split(/(?<!\\):/);            // cpe:2.3:part:vendor:product:version:update:...
        if (f.length < 6 || f[0] !== "cpe") continue;
        const r = { vendor: clean(f[3]), product: clean(f[4]), part: /^[aoh]$/.test(f[2]) ? f[2] : "a" };
        if (!r.product) continue;
        const from = ver(m.versionStartIncluding) || ver(m.versionStartExcluding), to = ver(m.versionEndExcluding) || ver(m.versionEndIncluding);
        if (from) { r.from = from; r.from_incl = !!ver(m.versionStartIncluding); }
        if (to) { r.to = to; r.to_incl = !ver(m.versionEndExcluding); }
        if (!from && !to) { const v = ver(f[5]); if (v) { r.exact = v; const u = ver(f[6]); if (u) r.update = u; } }
        const key = JSON.stringify(r); if (seen.has(key)) continue; seen.add(key); out.push(r);
      }
      walk(n.nodes); walk(n.children);
    }
  };
  for (const c of Array.isArray(cve && cve.configurations) ? cve.configurations : []) walk(c.nodes);
  // hardware rows only say which device a firmware runs on; keep them out when software rows exist
  const soft = out.filter((r) => r.part !== "h");
  return (soft.length ? soft : out).slice(0, 60);
}

/** CVSS base score and attack vector (N network, A adjacent, L local, P physical) from the same record. */
export function parseCvss(cve) {
  const m = cve && cve.metrics; if (!m) return { score: null, av: "" };
  for (const k of ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]) {
    const x = (m[k] || []).find((y) => y.type === "Primary") || (m[k] || [])[0];
    if (x && x.cvssData && typeof x.cvssData.baseScore === "number") {
      const av = String(x.cvssData.attackVector || x.cvssData.accessVector || "")[0] || "";
      return { score: x.cvssData.baseScore, av: /^[NALP]$/.test(av) ? av : "" };
    }
  }
  return { score: null, av: "" };
}
