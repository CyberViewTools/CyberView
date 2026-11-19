// CyberView CVE helpers for the Vulnerabilities page: the pure rules (bucket file for an id, row cleaning, filtering, sorting,
// paging) kept apart from the page so unit tests can run them in Node. The data is the static lookup files written by
// scripts/cve.mjs `site` into data/cve/: <year>/<thousand>.json = { fields, rows: [[...]] }, index.json, recent.json.
// Nothing a visitor types is sent anywhere.
(function (root) {
  "use strict";
  var L = {};
  var ID_RE = /^CVE-\d{4}-\d{4,}$/;
  var SEV = { C: "Critical", H: "High", M: "Medium", L: "Low", N: "None" };
  var EXPL = { active: "Exploited (CISA)", poc: "Proof of concept public (CISA)", none: "No exploitation seen (CISA)" };
  function str(v, n) { return typeof v === "string" ? v.slice(0, n) : ""; }
  function num(v, lo, hi) { return typeof v === "number" && isFinite(v) && v >= lo && v <= hi ? v : null; }
  function day(s) { return typeof s === "string" && /^\d{4}-\d{2}-\d{2}$/.test(s) ? s : ""; }
  L.SEV = SEV; L.EXPL = EXPL;
  L.isId = function (s) { return typeof s === "string" && s.length <= 24 && ID_RE.test(s); };
  L.normId = function (s) { var t = String(s || "").trim().toUpperCase().replace(/[‐-―−]/g, "-").replace(/\s+/g, ""); return L.isId(t) ? t : ""; };
  L.parseId = function (id) { return L.isId(id) ? { year: +id.slice(4, 8), seq: +id.slice(9) } : null; };
  /* the lookup file that holds an id: CVE-2024-3400 -> "2024/3.json" (thousands, as scripts/lib/cve.mjs bucket()) */
  L.bucketFile = function (id) { var p = L.parseId(id); return p ? p.year + "/" + Math.floor(p.seq / 1000) + ".json" : ""; };

  /* index.json: { built_at, total, rejected, exploited, critical, by_year: {"2024": n}, buckets, sources: { cvelist, epss } } */
  L.cleanIndex = function (x) {
    if (!x || typeof x !== "object") return null;
    var by = x.by_year && typeof x.by_year === "object" ? x.by_year : {}, years = [];
    Object.keys(by).slice(0, 120).forEach(function (k) { var n = num(by[k], 0, 1e7); if (/^\d{4}$/.test(k) && +k >= 1988 && +k <= 2100 && n !== null) years.push({ year: +k, count: n }); });
    years.sort(function (a, b) { return b.year - a.year; });
    var s = x.sources && typeof x.sources === "object" ? x.sources : {};
    var o = { builtAt: str(x.built_at, 30), total: num(x.total, 0, 1e8), rejected: num(x.rejected, 0, 1e8), exploited: num(x.exploited, 0, 1e8), critical: num(x.critical, 0, 1e8), years: years, cvelist: str(s.cvelist, 30), epss: str(s.epss, 30) };
    return o.total === null && !years.length ? null : o;
  };

  /* one lookup-file row (an array in the file's field order) -> a checked record, or null */
  L.cleanRow = function (fields, a) {
    if (!Array.isArray(a) || !Array.isArray(fields)) return null;
    var o = {}; fields.slice(0, 30).forEach(function (k, i) { o[k] = a[i]; });
    if (!L.isId(o.id)) return null;
    var c = {
      id: o.id, rejected: o.state === "R", pub: day(o.pub), upd: day(o.upd), cvss: num(o.cvss, 0, 10), sev: SEV[o.sev] ? o.sev : "", ver: /^[0-9.]{1,4}$/.test(o.ver || "") ? o.ver : "",
      cwe: /^CWE-\d{1,5}$/.test(o.cwe || "") ? o.cwe : "", vendor: str(o.vendor, 60), product: str(o.product, 80), title: str(o.title, 160), desc: str(o.desc, 600), cna: str(o.cna, 40),
      expl: EXPL[o.expl] ? o.expl : "", kev: /^\d{4}-\d{2}-\d{2}$|^yes$/.test(o.kev || "") ? o.kev : "", epss: num(o.epss, 0, 1), pct: num(o.pct, 0, 1)
    };
    c.hay = (c.id + " " + c.vendor + " " + c.product + " " + c.title + " " + c.desc + " " + c.cwe).toLowerCase();
    return c;
  };
  L.parseFile = function (d) {
    var f = Array.isArray(d && d.fields) ? d.fields : [];
    return (Array.isArray(d && d.rows) ? d.rows : []).slice(0, 6000).map(function (a) { return L.cleanRow(f, a); }).filter(Boolean);
  };

  /* filter: { q, sev, minEpss (0..1), cwe, vendor, status: "live" (default: not rejected) | "all" | "R", exploited } ; kev: object keyed by CVE id (CISA catalog as CyberView holds it) */
  L.isExploited = function (r, kev) { return !!(r.kev || r.expl === "active" || (kev && Object.prototype.hasOwnProperty.call(kev, r.id))); };
  L.matches = function (r, f, kev) {
    f = f || {};
    var q = String(f.q || "").trim().toLowerCase();
    if (q && r.hay.indexOf(q) < 0) return false;
    if (f.sev && r.sev !== f.sev) return false;
    if (f.minEpss && !(r.epss >= f.minEpss)) return false;
    if (f.cwe) { var c = String(f.cwe).trim().toUpperCase(); if (/^\d+$/.test(c)) c = "CWE-" + c; if (r.cwe !== c) return false; }
    if (f.vendor) { var v = String(f.vendor).trim().toLowerCase(); if ((r.vendor + " " + r.product).toLowerCase().indexOf(v) < 0) return false; }
    var st = f.status || "live";
    if (st === "live" ? r.rejected : st === "R" ? !r.rejected : false) return false;
    if (f.exploited && !L.isExploited(r, kev)) return false;
    return true;
  };
  function seqOf(id) { var p = L.parseId(id); return p ? p.year * 1e9 + p.seq : 0; }
  var SORTS = {
    pub: function (a, b) { return a.pub < b.pub ? 1 : a.pub > b.pub ? -1 : seqOf(b.id) - seqOf(a.id); },
    old: function (a, b) { return a.pub < b.pub ? -1 : a.pub > b.pub ? 1 : seqOf(a.id) - seqOf(b.id); },
    upd: function (a, b) { return a.upd < b.upd ? 1 : a.upd > b.upd ? -1 : seqOf(b.id) - seqOf(a.id); },
    cvss: function (a, b) { return (b.cvss === null ? -1 : b.cvss) - (a.cvss === null ? -1 : a.cvss) || seqOf(b.id) - seqOf(a.id); },
    epss: function (a, b) { return (b.epss === null ? -1 : b.epss) - (a.epss === null ? -1 : a.epss) || seqOf(b.id) - seqOf(a.id); },
    id: function (a, b) { return seqOf(a.id) - seqOf(b.id); }
  };
  L.SORT_KEYS = Object.keys(SORTS);
  L.filter = function (list, f, kev, sort) { return (list || []).filter(function (r) { return L.matches(r, f, kev); }).sort(SORTS[sort] || SORTS.pub); };
  L.page = function (list, page, size) { var pages = Math.max(1, Math.ceil(list.length / size)), p = Math.min(Math.max(0, page | 0), pages - 1); return { page: p, pages: pages, items: list.slice(p * size, (p + 1) * size) }; };
  /* the n most common vendor names in a list, for the vendor suggestions */
  L.topVendors = function (list, n) {
    var m = {}; list.forEach(function (r) { if (r.vendor) m[r.vendor] = (m[r.vendor] || 0) + 1; });
    return Object.keys(m).sort(function (a, b) { return m[b] - m[a] || (a < b ? -1 : 1); }).slice(0, n).map(function (k) { return [k, m[k]]; });
  };

  if (typeof module !== "undefined" && module.exports) module.exports = L; else root.CVDB = L;
})(typeof window !== "undefined" ? window : this);
