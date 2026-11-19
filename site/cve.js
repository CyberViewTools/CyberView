// CyberView CVE lookup. Reads data/cve/index.json, data/cve/recent.json and, for one CVE, the lookup file of its
// thousand (data/cve/<year>/<n>.json). Every field goes through cleanCve() with length limits; all text is set as text.
(function () {
  "use strict";
  var PAGE = 50, ID = /^CVE-\d{4}-\d{4,}$/;
  var rows = [], shown = PAGE, events = null, $ = function (id) { return document.getElementById(id); };
  var SEV = { C: "Critical", H: "High", M: "Medium", L: "Low", N: "None" };
  var EXPL = { active: "Exploited (CISA)", poc: "Proof of concept public (CISA)", none: "No exploitation seen (CISA)" };

  function el(tag, cls, text) { var n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = String(text); return n; }
  function safeUrl(u) { u = String(u || ""); return /^https:\/\/[a-z0-9.-]+\//i.test(u) || /^archive\.html#q=[^"<>\s]*$/.test(u) ? u : ""; }
  function link(u, text) { var a = el("a", null, text), ok = safeUrl(u); if (ok) a.href = safeUrl(u); a.rel = "noopener"; return a; }
  function str(v, n) { return typeof v === "string" ? v.slice(0, n) : ""; }
  function numOr(v, lo, hi) { return typeof v === "number" && isFinite(v) && v >= lo && v <= hi ? v : null; }
  function day(v) { return /^\d{4}-\d{2}-\d{2}$/.test(v || "") ? v : ""; }
  function fmt(d) { if (!d) return ""; try { return new Date(d + "T12:00:00Z").toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }); } catch (e) { return d; } }

  /** One lookup-file row (array, in the file's field order) -> a checked object, or null. */
  function cleanCve(fields, a) {
    if (!Array.isArray(a)) return null;
    var o = {}; fields.forEach(function (k, i) { o[k] = a[i]; });
    if (!ID.test(o.id || "")) return null;
    return {
      id: o.id, rejected: o.state === "R", pub: day(o.pub), upd: day(o.upd),
      cvss: numOr(o.cvss, 0, 10), sev: SEV[o.sev] ? o.sev : "", ver: /^[0-9.]{1,4}$/.test(o.ver || "") ? o.ver : "",
      cwe: /^CWE-\d{1,5}$/.test(o.cwe || "") ? o.cwe : "", vendor: str(o.vendor, 60), product: str(o.product, 80),
      title: str(o.title, 160), desc: str(o.desc, 600), cna: str(o.cna, 40),
      expl: EXPL[o.expl] ? o.expl : "", kev: /^\d{4}-\d{2}-\d{2}$|^yes$/.test(o.kev || "") ? o.kev : "",
      epss: numOr(o.epss, 0, 1), pct: numOr(o.pct, 0, 1)
    };
  }
  function parse(d) { var f = Array.isArray(d && d.fields) ? d.fields.slice(0, 30) : []; return (Array.isArray(d && d.rows) ? d.rows : []).map(function (a) { return cleanCve(f, a); }).filter(Boolean); }
  function getJson(u) { return fetch(u, { cache: "no-cache" }).then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); }); }

  function pills(c, box) {
    if (c.rejected) box.appendChild(el("span", "pill claimed", "Rejected"));
    if (c.cvss != null) box.appendChild(el("span", "pill", "CVSS " + c.cvss.toFixed(1) + (c.sev ? " " + SEV[c.sev] : "") + (c.ver ? " (v" + c.ver + ")" : "")));
    if (c.kev) box.appendChild(el("span", "pill hot", "Known exploited" + (c.kev !== "yes" ? " since " + fmt(c.kev) : "")));
    else if (c.expl === "active") box.appendChild(el("span", "pill hot", EXPL.active));
    if (c.epss != null) box.appendChild(el("span", "pill", "EPSS " + (c.epss * 100).toFixed(c.epss < 0.01 ? 2 : 1) + "%" + (c.pct != null ? " (top " + Math.max(0.1, (1 - c.pct) * 100).toFixed(1) + "%)" : "")));
    if (c.cwe) box.appendChild(el("span", "pill", c.cwe));
  }

  function detail(c) {
    var d = el("div", "more-info");
    if (c.desc) d.appendChild(el("p", null, c.desc));
    var dl = el("dl", "facts");
    var add = function (k, v) { if (!v) return; dl.appendChild(el("dt", null, k)); dl.appendChild(el("dd", null, v)); };
    add("Affects", [c.vendor, c.product].filter(Boolean).join(" "));
    add("Published", fmt(c.pub)); add("Last changed", c.upd && c.upd !== c.pub ? fmt(c.upd) : "");
    add("Assigned by", c.cna); add("CISA exploitation", c.expl ? EXPL[c.expl] : "");
    add("Exploit likelihood (EPSS)", c.epss != null ? (c.epss * 100).toFixed(2) + "% chance of exploitation in the next 30 days" + (c.pct != null ? "; higher than " + (c.pct * 100).toFixed(1) + "% of CVEs" : "") : "");
    d.appendChild(dl);
    var ls = el("p", "links");
    ls.appendChild(link("https://www.cve.org/CVERecord?id=" + c.id, "CVE record")); ls.appendChild(document.createTextNode(" · "));
    ls.appendChild(link("https://nvd.nist.gov/vuln/detail/" + c.id, "NVD"));
    if (c.kev) { ls.appendChild(document.createTextNode(" · ")); ls.appendChild(link("https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=" + c.id, "CISA catalog entry")); }
    d.appendChild(ls);
    var ev = el("p", "onmap", "Checking the map and archive"); d.appendChild(ev);
    loadEvents().then(function (list) {
      var hit = list.filter(function (e) { return (e.cves || []).indexOf(c.id) >= 0; });
      ev.textContent = "";
      if (!hit.length) { ev.textContent = "Not on the map or in the archive: no checked report of this flaw yet."; return; }
      ev.appendChild(document.createTextNode("In the archive: "));
      hit.slice(0, 5).forEach(function (e, i) { if (i) ev.appendChild(document.createTextNode("; ")); ev.appendChild(link("archive.html#q=" + encodeURIComponent(e.id), str(e.title, 120))); });
    }, function () { ev.textContent = ""; });
    return d;
  }
  function loadEvents() {
    if (!events) events = getJson("data/archive/search.json").then(function (d) {
      var f = d.fields || [], ci = f.indexOf("cves"), ii = f.indexOf("id"), ti = f.indexOf("title");
      return (d.rows || []).map(function (r) { return { id: str(r[ii], 80), title: str(r[ti], 200), cves: Array.isArray(r[ci]) ? r[ci].filter(function (x) { return ID.test(x); }) : [] }; });
    });
    return events;
  }

  function card(c, open) {
    var li = el("li", "row cve"), b = el("button"); b.type = "button"; b.setAttribute("aria-expanded", open ? "true" : "false");
    b.appendChild(el("span", "date", fmt(c.pub)));
    b.appendChild(el("span", "ttl", c.id + (c.title || c.desc ? ": " + (c.title || c.desc).slice(0, 140) : "")));
    var meta = el("span", "meta"); if (c.vendor || c.product) meta.appendChild(el("span", null, [c.vendor, c.product].filter(Boolean).join(" "))); pills(c, meta); b.appendChild(meta);
    if (c.kev || c.expl === "active") li.classList.add("hotrow");
    b.addEventListener("click", function () { var o = li.querySelector(".more-info"); if (o) { o.remove(); b.setAttribute("aria-expanded", "false"); } else { li.appendChild(detail(c)); b.setAttribute("aria-expanded", "true"); } });
    li.appendChild(b); if (open) li.appendChild(detail(c));
    return li;
  }

  function lookup(id) {
    var box = $("one"); box.textContent = "";
    id = String(id || "").trim().toUpperCase();
    if (!ID.test(id)) { box.appendChild(el("p", "note", "Type a CVE ID such as CVE-2024-3400.")); return; }
    var p = id.split("-"), file = "data/cve/" + p[1] + "/" + Math.floor(Number(p[2]) / 1000) + ".json";
    box.appendChild(el("p", "note", "Looking up " + id));
    getJson(file).then(parse).then(function (list) {
      box.textContent = "";
      var c = list.filter(function (x) { return x.id === id; })[0];
      if (!c) { box.appendChild(el("p", "note", id + " is not in the CVE List. It may be reserved but not yet published.")); return; }
      var ol = el("ol", "list"); ol.appendChild(card(c, true)); box.appendChild(ol);
    }, function () { box.textContent = ""; box.appendChild(el("p", "note", id + " is not in the CVE List, or the lookup files are not available right now.")); });
    try { history.replaceState(null, "", "#" + id); } catch (e) {}
  }

  function render() {
    var q = $("q").value.trim().toLowerCase(), show = $("show").value, sort = $("sort").value;
    var list = rows.filter(function (c) {
      if (c.rejected) return false;
      if (show === "expl" && !(c.kev || c.expl === "active")) return false;
      if (show === "crit" && !(c.cvss >= 9)) return false;
      if (show === "high" && !(c.cvss >= 7)) return false;
      if (show === "epss" && !(c.epss >= 0.1)) return false;
      return !q || (c.id + " " + c.vendor + " " + c.product + " " + c.title + " " + c.desc + " " + c.cwe).toLowerCase().indexOf(q) >= 0;
    });
    if (sort === "cvss") list.sort(function (a, b) { return (b.cvss || 0) - (a.cvss || 0); });
    if (sort === "epss") list.sort(function (a, b) { return (b.epss || 0) - (a.epss || 0); });
    var box = $("list"); box.textContent = "";
    $("count").textContent = list.length + " CVE" + (list.length === 1 ? "" : "s") + (list.length > shown ? ", showing " + shown : "");
    if (!list.length) box.appendChild(el("li", "empty", "Nothing matches. Clear a filter or try another word."));
    list.slice(0, shown).forEach(function (c) { box.appendChild(card(c, false)); });
    $("more").hidden = list.length <= shown;
  }

  getJson("data/cve/index.json").then(function (ix) {
    var n = function (v) { return typeof v === "number" && isFinite(v) ? v.toLocaleString() : "?"; };
    var up = str(ix.sources && ix.sources.cvelist, 30), age = up ? Math.round((Date.now() - Date.parse(up)) / 6e4) : null;
    $("summary").textContent = n(ix.total) + " CVEs on file, every one published since 1999 (" + n(ix.rejected) + " of them rejected). " + n(ix.exploited) + " are known or seen exploited, " + n(ix.critical) + " rated CVSS 9 or higher." +
      (age != null && isFinite(age) ? " Updated " + (age < 90 ? age + " minutes" : Math.round(age / 60) + " hours") + " ago." : "") + (age != null && age > 360 ? " This is older than it should be; the hourly update may be failing." : "");
  }, function () { $("summary").textContent = "The CVE list is not available right now. The rest of CyberView works as usual; try again later."; });
  getJson("data/cve/recent.json").then(function (d) { rows = parse(d); render(); }, function () { $("count").textContent = "The recent list is not available right now."; });

  $("look").addEventListener("submit", function (e) { e.preventDefault(); lookup($("id").value); });
  $("filters").addEventListener("submit", function (e) { e.preventDefault(); });
  ["q", "show", "sort"].forEach(function (k) { $(k).addEventListener(k === "q" ? "input" : "change", function () { shown = PAGE; render(); }); });
  $("more").addEventListener("click", function () { shown += PAGE; render(); });
  var h = decodeURIComponent(location.hash.slice(1)); if (ID.test(h.toUpperCase())) { $("id").value = h.toUpperCase(); lookup(h); }
})();
