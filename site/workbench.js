// CyberView workbench page: one tool for "am I affected, what do I patch first, how do I check and fix, what do I hunt for".
// Reads data/workbench.json (written by scripts/build.mjs). The visitor's software list is parsed, matched and stored
// only in this browser (localStorage "cwm.inv"); nothing is sent. Every record passes a clean function with length
// limits, and all text is inserted as text.
(function () {
  "use strict";
  var W = window.CVWorkbench;
  var $ = function (id) { return document.getElementById(id); };
  function el(tag, cls, text) { var n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = String(text); return n; }
  function str(v, n) { return typeof v === "string" ? v.slice(0, n) : ""; }
  function strs(a, k, n) { return (Array.isArray(a) ? a : []).map(function (x) { return str(x, n).trim(); }).filter(Boolean).slice(0, k); }
  function num(v, lo, hi) { return typeof v === "number" && isFinite(v) && v >= lo && v <= hi ? v : null; }
  function isDay(s) { return /^\d{4}-\d{2}-\d{2}$/.test(s || ""); }
  function isCve(s) { return /^CVE-\d{4}-\d{4,}$/.test(s || ""); }
  // every link target from data passes through here: https only, or the map's own permalinks
  function safeUrl(u) { u = String(u || ""); return /^https:\/\/[^\s"'<>]+$/.test(u) || /^\.\/#e=[a-z0-9-]+$/.test(u) ? u : "about:blank"; }
  function blobUrl(b) { return b instanceof Blob ? URL.createObjectURL(b) : "about:blank"; }
  function link(href, text) { var a = el("a", null, text); a.href = safeUrl(href); if (/^https:/.test(href)) { a.target = "_blank"; a.rel = "noopener noreferrer"; } return a; }
  function fmtDay(d) { try { return new Date(d + "T12:00:00Z").toLocaleDateString(undefined, { month: "short", day: "numeric" }); } catch (e) { return d; } }
  function lsGet(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
  function lsSet(k, v) { try { localStorage.setItem(k, v); return true; } catch (e) { return false; } }
  var TODAY = new Date().toISOString().slice(0, 10);
  var FORMATS = { stix: "STIX", sigma: "Sigma rule", yara: "YARA rule", snort: "Snort rule", suricata: "Suricata rule", kql: "KQL query", spl: "Splunk query", csv: "CSV indicators", json: "JSON indicators", misp: "MISP event", openioc: "OpenIOC", text: "Indicator list", pdf: "PDF with indicators" };

  function cleanRange(r) {
    if (!r || typeof r !== "object" || !str(r.product, 60)) return null;
    var v = function (x) { x = str(x, 40); return /^[\w.+\-~:]+$/.test(x) ? x : ""; };
    return { vendor: str(r.vendor, 60), product: str(r.product, 60), from: v(r.from), from_incl: r.from_incl === true, to: v(r.to), to_incl: r.to_incl === true, exact: v(r.exact) };
  }
  function cleanHunt(h) {
    if (!h || typeof h !== "object" || !FORMATS[h.format]) return null;
    var u = str(h.url, 600); if (!/^https:\/\//.test(u)) return null;
    var ev = str(h.event_id, 120);
    return { name: str(h.name, 100) || FORMATS[h.format], format: h.format, url: u, publisher: str(h.publisher, 80), about: str(h.about, 140), cve: isCve(h.cve) ? h.cve : "", event: /^[a-z0-9][a-z0-9-]{2,119}$/.test(ev) ? ev : "", date: isDay(h.date) ? h.date : "" };
  }
  function cleanGuide(g) {
    if (!g || typeof g !== "object") return null;
    var a = g.advisory && typeof g.advisory === "object" ? { name: str(g.advisory.name, 100), url: str(g.advisory.url, 600) } : null;
    if (!a || !/^https:\/\//.test(a.url)) return null;
    return { advisory: a, depth: g.read_depth === "full" ? "full" : "summary", readAt: str(g.read_at, 10), check: strs(g.check, 6, 320), fixed: strs(g.fixed, 8, 160), workaround: strs(g.workaround, 5, 320), signs: strs(g.compromise_signs, 6, 320),
      exposure: { internet: 1, internal: 1, local: 1 }[g.exposure] ? g.exposure : "", exploit: g.exploit_public === true, hunt: (Array.isArray(g.hunt) ? g.hunt : []).map(cleanHunt).filter(Boolean).slice(0, 12) };
  }
  // exploitation analysis (the exploit analyst job, an AI model reading public sources): how the flaw is used and the
  // remediation path. Rendered as text only; links must be https pages. The build already refuses records that look like code.
  var SRC_KIND = { vendor: "Vendor", government: "Government", research: "Research", news: "News", database: "Database" };
  function cleanAnalysis(a) {
    if (!a || typeof a !== "object") return null;
    var r = a.remediation && typeof a.remediation === "object" ? a.remediation : {};
    var src = (Array.isArray(a.sources) ? a.sources : []).slice(0, 10).map(function (x) { var u = str(x && x.url, 600); return x && /^https:\/\//.test(u) && SRC_KIND[x.kind] ? { name: str(x.name, 100), url: u, kind: x.kind, full: x.read_depth === "full" } : null; }).filter(Boolean);
    var o = { at: str(a.analyzed_at, 30), status: str(a.exploitation_status, 240), how: str(a.how_exploited, 900), pre: strs(a.preconditions, 6, 260), path: strs(a.attack_path, 6, 280),
      exposure: { internet: "Internet-facing", internal: "Internal network", local: "Local access" }[a.exposure] || "", who: strs(a.who_is_exposed, 5, 260), detect: strs(a.detect, 6, 300),
      priority: { immediate: 1, urgent: 1, planned: 1 }[r.priority] ? r.priority : "", steps: strs(r.steps, 8, 320), fixed: strs(r.fixed_versions, 8, 160), work: strs(r.workarounds, 5, 320), verify: strs(r.verify, 5, 300), ir: strs(r.if_compromised, 6, 300),
      conf: { high: "High", medium: "Medium", low: "Low" }[a.confidence] || "", caveats: str(a.caveats, 500), sources: src };
    return o.how && o.steps.length && src.length >= 2 ? o : null;
  }
  // exploit watch: public GitHub repositories that name the CVE (a signal that exploit code may exist, not proof)
  function cleanRepo(r) {
    if (!r || typeof r !== "object") return { n: 0, top: [] };
    return { n: num(r.repos, 0, 1e5) || 0, top: (Array.isArray(r.top) ? r.top : []).slice(0, 3).map(function (x) { var u = str(x && x.url, 300); return /^https:\/\/github\.com\/[\w.-]+\/[\w.-]+$/.test(u) ? { name: str(x.name, 100), url: u, stars: num(x.stars, 0, 1e7) || 0 } : null; }).filter(Boolean) };
  }
  function cleanKev(k, guides, eventOf, an) {
    if (!k || typeof k !== "object" || !isCve(k.cve)) return null;
    var g = guides[k.cve] || null, ev = str(eventOf[k.cve], 120);
    return { cve: k.cve, kev: true, vendor: str(k.vendor, 80), product: str(k.product, 120), name: str(k.name, 200), added: isDay(k.added) ? k.added : "", due: isDay(k.due) ? k.due : "", ransomware: k.ransomware === true,
      desc: str(k.desc, 300), cvss: num(k.cvss, 0, 10), epss: num(k.epss, 0, 1), av: /^[NALP]$/.test(k.av || "") ? k.av : "", required: str(k.required, 700),
      refs: strs(k.refs, 4, 600).filter(function (u) { return /^https:\/\//.test(u); }), affected: (Array.isArray(k.affected) ? k.affected : []).slice(0, 60).map(cleanRange).filter(Boolean),
      guide: g, analysis: (an && an[k.cve]) || null, exposure: g ? g.exposure : "", exploit_public: !!(g && g.exploit), event: /^[a-z0-9][a-z0-9-]{2,119}$/.test(ev) ? ev : "", severity: 3, repos: cleanRepo(k.repo).n, repoTop: cleanRepo(k.repo).top };
  }
  function cleanVuln(v, guides, an) {
    if (!v || typeof v !== "object" || !isCve(v.cve)) return null;
    var g = guides[v.cve] || null, prods = strs(v.products, 6, 60), ev = str(v.event_id, 120);
    return { cve: v.cve, kev: false, vendor: str(v.vendor, 80), product: prods.join(", "), name: str(v.title, 160), added: isDay(v.date) ? v.date : "", due: "", ransomware: false, desc: str(v.desc, 300),
      cvss: num(v.cvss, 0, 10), epss: num(v.epss, 0, 1), av: "", required: str(v.action, 300), refs: [], affected: prods.map(function (p) { return { vendor: str(v.vendor, 60), product: p, from: "", to: "", exact: "", nameOnly: true }; }),
      guide: g, analysis: (an && an[v.cve]) || null, exposure: g ? g.exposure : "", exploit_public: !!(g && g.exploit), event: /^[a-z0-9][a-z0-9-]{2,119}$/.test(ev) ? ev : "", severity: v.severity === 3 ? 3 : 2, repos: cleanRepo(v.repo).n, repoTop: cleanRepo(v.repo).top };
  }

  var flaws = [], hunt = [], inv = [], rows = [], openCve = "", builtAt = "";
  function loadInv() {
    try { var a = JSON.parse(lsGet("cwm.inv") || "[]"); inv = (Array.isArray(a) ? a : []).slice(0, W.MAX_ITEMS).map(function (x) {
      return x && typeof x === "object" && str(x.name, 120) ? { name: str(x.name, 120).replace(/[<>]/g, ""), vendor: str(x.vendor, 80).replace(/[<>]/g, ""), version: /^[\w.+\-~:]{1,40}$/.test(x.version || "") ? x.version : "", count: Math.max(1, Math.round(+x.count) || 1) } : null; }).filter(Boolean); } catch (e) { inv = []; }
  }
  function saveInv() { return lsSet("cwm.inv", JSON.stringify(inv)); }

  /* a name-only range (flaws not yet in NVD's range data) can only say "you run this product" */
  function matchFlaw(f) {
    if (!inv.length) return null;
    var real = f.affected.filter(function (r) { return !r.nameOnly; });
    var m = W.match({ vendor: f.vendor, product: f.product, affected: real }, inv);
    if (m.state === "none" && real.length < f.affected.length) {
      var hits = inv.filter(function (it) { return f.affected.some(function (r) { return W.nameHit((it.vendor ? it.vendor + " " : "") + it.name, r.vendor, r.product); }); });
      if (hits.length) m = { state: "check", items: hits.slice(0, 20).map(function (it) { return { name: it.name, version: it.version, count: it.count, state: "check" }; }), fixed: [] };
    }
    return m;
  }
  function compute() {
    rows = flaws.map(function (f) { var m = matchFlaw(f), s = W.score(f, m, TODAY); return { f: f, m: m, score: s.total, points: s.points }; });
    // "clear" (you run it, but a fixed version) drops to the end: it needs no action
    rows.sort(function (a, b) { var ca = a.m && a.m.state === "clear" ? 1 : 0, cb = b.m && b.m.state === "clear" ? 1 : 0; return ca - cb || b.score - a.score || (a.f.added < b.f.added ? 1 : -1); });
  }
  function dueLeft(f) { return f.due ? Math.round((Date.parse(f.due + "T12:00:00Z") - Date.parse(TODAY + "T12:00:00Z")) / 864e5) : null; }
  function dueText(f) { var n = dueLeft(f); return n === null ? "" : n < 0 ? "Federal deadline passed " + (-n) + (n === -1 ? " day" : " days") + " ago" : n === 0 ? "Federal deadline today" : "Federal deadline in " + n + (n === 1 ? " day" : " days") + " (" + fmtDay(f.due) + ")"; }
  function visibleRows() {
    var q = W.norm($("wbQ").value), show = $("wbShow").value;
    return rows.filter(function (r) {
      if (q && W.norm(r.f.cve + " " + r.f.vendor + " " + r.f.product + " " + r.f.name).indexOf(q) < 0) return false;
      if (show === "mine") return r.m && (r.m.state === "affected" || r.m.state === "check");
      if (show === "due") { var n = dueLeft(r.f); return n !== null && n <= 7; }
      if (show === "guide") return !!r.f.guide;
      return true;
    });
  }
  var STATE = { affected: ["Affected", "bad"], check: ["Check version", "warn"], clear: ["Fixed version", "ok"] };
  function mineText(m) {
    if (!m || m.state === "none") return "";
    var parts = m.items.slice(0, 4).map(function (h) { return h.name + (h.version ? " " + h.version : " (no version)") + (h.count > 1 ? " ×" + h.count : ""); });
    return parts.join("; ") + (m.items.length > 4 ? "; and " + (m.items.length - 4) + " more" : "");
  }
  function list(parent, title, items, ordered) {
    if (!items.length) return; parent.appendChild(el("h4", null, title));
    var l = el(ordered ? "ol" : "ul"); items.forEach(function (x) { l.appendChild(el("li", null, x)); }); parent.appendChild(l);
  }
  var PRIO = { immediate: ["Fix immediately", "bad"], urgent: ["Fix urgently", "warn"], planned: ["Fix in the next planned cycle", "info"] };
  function analysisBox(a) {
    var box = el("section", "wbanal"); box.setAttribute("aria-label", "How it is exploited and how to fix it");
    var h = el("div", "wbanh"); h.appendChild(el("h4", null, "How it is exploited and how to fix it"));
    if (a.priority) h.appendChild(el("span", "badge " + PRIO[a.priority][1], PRIO[a.priority][0]));
    if (a.exposure) h.appendChild(el("span", "badge info", a.exposure));
    box.appendChild(h);
    if (a.status) box.appendChild(el("p", "wbanst", a.status));
    var cols = el("div", "wbancols"), left = el("div", "wbancol"), right = el("div", "wbancol fix");
    left.appendChild(el("h5", null, "The attack"));
    left.appendChild(el("p", null, a.how));
    list(left, "What an attacker needs", a.pre);
    list(left, "How an attack unfolds", a.path, true);
    list(left, "Who is exposed", a.who);
    list(left, "How to detect it", a.detect);
    right.appendChild(el("h5", null, "The remediation path"));
    list(right, "Do this, in order", a.steps, true);
    list(right, "Fixed in", a.fixed);
    list(right, "If you cannot patch yet", a.work);
    list(right, "Confirm the fix took", a.verify);
    list(right, "If you find signs of compromise", a.ir, true);
    cols.appendChild(left); cols.appendChild(right); box.appendChild(cols);
    var sl = el("p", "note"); sl.appendChild(document.createTextNode("Sources read: "));
    a.sources.forEach(function (s, i) { if (i) sl.appendChild(document.createTextNode(" · ")); sl.appendChild(link(s.url, s.name)); sl.appendChild(document.createTextNode(" (" + SRC_KIND[s.kind].toLowerCase() + (s.full ? "" : ", summary") + ")")); });
    box.appendChild(sl);
    box.appendChild(el("p", "note", "Written by an AI model (Claude Opus) from the sources listed" + (a.at ? ", " + a.at.slice(0, 10) : "") + (a.conf ? "; confidence " + a.conf.toLowerCase() : "") + ". It explains how the flaw is used so you can defend against it and contains no exploit code. Confirm versions and steps against the vendor advisory before you act." + (a.caveats ? " Caveats: " + a.caveats : "")));
    return box;
  }
  function detail(r) {
    var f = r.f, g = f.guide, d = el("div", "wbdetail");
    if (f.desc) d.appendChild(el("p", null, f.desc));
    if (r.m && r.m.state !== "none") {
      var me = el("div", "wbme " + STATE[r.m.state][1]);
      me.appendChild(el("b", null, r.m.state === "affected" ? "You run an affected version" : r.m.state === "check" ? "You run this product: confirm the version" : "Your listed versions are outside the affected ranges"));
      me.appendChild(el("p", null, mineText(r.m)));
      if (r.m.fixed.length && r.m.state !== "clear") me.appendChild(el("p", null, "NVD lists it as fixed in: " + r.m.fixed.join(", ") + ". Confirm the right fixed release for your branch in the vendor advisory."));
      d.appendChild(me);
    }
    if (f.analysis) d.appendChild(analysisBox(f.analysis));
    var pts = el("div", "wbpts"); pts.appendChild(el("h4", null, "Why it ranks here: " + r.score + " of 100"));
    var pl = el("ul"); r.points.forEach(function (p) { var li = el("li"); li.appendChild(el("b", null, "+" + p[0])); li.appendChild(document.createTextNode(" " + p[1])); pl.appendChild(li); }); pts.appendChild(pl); d.appendChild(pts);
    if (g) {
      var gb = el("div", "wbguide");
      list(gb, "How to check if you are affected", g.check, true);
      list(gb, "Fixed in", g.fixed);
      list(gb, "If you cannot patch yet", g.workaround);
      list(gb, "Signs of compromise to look for", g.signs);
      if (g.hunt.length) { gb.appendChild(el("h4", null, "Detection resources")); var hl = el("ul"); g.hunt.forEach(function (h) { var li = el("li"); li.appendChild(link(h.url, h.name)); li.appendChild(el("span", "note", " " + FORMATS[h.format] + (h.publisher ? " · " + h.publisher : ""))); hl.appendChild(li); }); gb.appendChild(hl); }
      var src = el("p", "note", "From the advisory, " + (g.depth === "full" ? "read in full" : "from its summary page") + (g.readAt ? " on " + g.readAt : "") + ": "); src.appendChild(link(g.advisory.url, g.advisory.name)); gb.appendChild(src);
      d.appendChild(gb);
    } else {
      var fx = W.fixedIn(f);
      if (fx.length) list(d, "Fixed in (from NVD's version ranges)", fx);
      d.appendChild(el("p", "note", "Check and fix steps from the vendor advisory have not been written for this one yet. The advisory desk adds them for new exploited flaws within a day."));
    }
    if (f.repoTop.length) {
      d.appendChild(el("h4", null, "Public repositories naming this CVE (" + f.repos + ")"));
      var rl = el("ul"); f.repoTop.forEach(function (x) { var li = el("li"); li.appendChild(link(x.url, x.name)); li.appendChild(el("span", "note", " " + x.stars + " stars")); rl.appendChild(li); }); d.appendChild(rl);
      d.appendChild(el("p", "note", "Found by an automatic search of GitHub. A repository naming a CVE may hold a working exploit, a detector, notes or nothing useful, and some are traps: review before running anything."));
    }
    if (f.required) { d.appendChild(el("h4", null, f.kev ? "What CISA requires" : "What to do")); d.appendChild(el("p", null, f.required)); }
    var ln = el("p", "wblinks");
    f.refs.forEach(function (u) { var host = ""; try { host = new URL(u).host.replace(/^www\./, ""); } catch (e) {} ln.appendChild(link(u, "Advisory (" + (host || "link") + ")")); });
    ln.appendChild(link("https://nvd.nist.gov/vuln/detail/" + encodeURIComponent(f.cve), "NVD record"));
    if (f.event) ln.appendChild(link("./#e=" + f.event, "On the map"));
    d.appendChild(ln);
    return d;
  }
  function renderQueue() {
    var vis = visibleRows(), box = $("wbList"); box.textContent = "";
    $("wbNoInv").hidden = inv.length > 0;
    var mine = rows.filter(function (r) { return r.m && r.m.state === "affected"; }).length, chk = rows.filter(function (r) { return r.m && r.m.state === "check"; }).length;
    var over = rows.filter(function (r) { var n = dueLeft(r.f); return n !== null && n < 0; }).length;
    $("wbSummary").textContent = rows.length + " exploited or high-risk flaws ranked" + (inv.length ? " · " + mine + " affect versions you run" + (chk ? " · " + chk + " to check" : "") : "") + " · " + over + " past the federal deadline" + (builtAt ? " · data built " + builtAt.slice(0, 16).replace("T", " ") + " UTC" : "");
    $("wbnQueue").textContent = String(rows.length);
    $("wbCount").textContent = vis.length === rows.length ? "Highest priority first." : vis.length + " of " + rows.length + " shown.";
    if (!vis.length) { box.appendChild(el("li", "empty", "Nothing matches. Clear the search or the filter.")); return; }
    vis.slice(0, 150).forEach(function (r, i) {
      var f = r.f, li = el("li", "wbrow" + (r.m && r.m.state === "clear" ? " clear" : "")), open = openCve === f.cve;
      var b = el("button", "wbhead"); b.type = "button"; b.setAttribute("aria-expanded", open ? "true" : "false");
      var sc = el("span", "wbscore", String(r.score)); sc.title = "Priority score out of 100"; b.appendChild(sc);
      var mid = el("span", "wbmid");
      var top = el("span", "wbtop"); top.appendChild(el("b", null, f.cve)); top.appendChild(document.createTextNode(" " + [f.vendor, f.product].filter(Boolean).join(" ")));
      mid.appendChild(top); mid.appendChild(el("span", "wbname", f.name));
      var chips = el("span", "wbchips");
      if (r.m && STATE[r.m.state]) chips.appendChild(el("span", "badge " + STATE[r.m.state][1], STATE[r.m.state][0] + (r.m.state !== "clear" ? ": " + mineText(r.m) : "")));
      if (f.kev) chips.appendChild(el("span", "badge bad", "Known exploited")); else chips.appendChild(el("span", "badge info", "Not on CISA's list"));
      if (f.ransomware) chips.appendChild(el("span", "badge bad", "Ransomware"));
      var dt = dueText(f); if (dt) chips.appendChild(el("span", "badge " + (dueLeft(f) < 0 ? "warn" : "info"), dt));
      if (f.epss !== null) chips.appendChild(el("span", "badge info", "EPSS " + Math.round(f.epss * 100) + "%"));
      if (f.guide) chips.appendChild(el("span", "badge ok", "Check and fix steps"));
      if (f.analysis) chips.appendChild(el("span", "badge ok", "Exploit and fix analysis"));
      mid.appendChild(chips); b.appendChild(mid);
      b.appendChild(el("span", "wbrank", "#" + (i + 1)));
      b.addEventListener("click", function () { openCve = open ? "" : f.cve; renderQueue(); if (!open) { var n = document.getElementById("row-" + f.cve); if (n) n.querySelector("button").focus(); } });
      li.id = "row-" + f.cve; li.appendChild(b);
      if (open) li.appendChild(detail(r));
      box.appendChild(li);
    });
  }

  /* ---- my software ---- */
  function renderInv() {
    $("wbnInv").textContent = inv.length ? String(inv.length) : "";
    var t = $("wbInvTable"); t.textContent = "";
    if (!inv.length) { $("wbInvHead").textContent = "Nothing loaded yet"; return; }
    var hit = {}; rows.forEach(function (r) { if (r.m) r.m.items.forEach(function (h) { var k = h.name + "|" + h.version; (hit[k] = hit[k] || []).push({ cve: r.f.cve, state: h.state }); }); });
    var order = { affected: 0, check: 1, clear: 2, none: 3 }, list = inv.map(function (it) { var h = hit[it.name + "|" + it.version] || []; var worst = h.reduce(function (w, x) { return order[x.state] < order[w] ? x.state : w; }, "none"); return { it: it, h: h, worst: worst }; })
      .sort(function (a, b) { return order[a.worst] - order[b.worst] || a.it.name.localeCompare(b.it.name); });
    var nAff = list.filter(function (x) { return x.worst === "affected"; }).length, noVer = inv.filter(function (x) { return !x.version; }).length;
    $("wbInvHead").textContent = inv.length + " products on your list · " + nAff + " with an affected version" + (noVer ? " · " + noVer + " without a version (matched by name only)" : "");
    var hr = el("tr"); ["Product", "Version", "Devices", "Exploited flaws"].forEach(function (h) { hr.appendChild(el("th", null, h)); }); var th = el("thead"); th.appendChild(hr); t.appendChild(th);
    var tb = el("tbody");
    list.slice(0, 400).forEach(function (x) {
      var tr = el("tr"); tr.appendChild(el("td", null, (x.it.vendor ? x.it.vendor + " " : "") + x.it.name)); tr.appendChild(el("td", "nowrap", x.it.version || "none given")); tr.appendChild(el("td", null, x.it.count));
      var td = el("td");
      if (!x.h.length) td.appendChild(el("span", "note", "none on file"));
      x.h.slice(0, 6).forEach(function (h) { var b = el("button", "badge " + STATE[h.state][1], h.cve + " · " + STATE[h.state][0]); b.type = "button"; b.addEventListener("click", function () { $("wbQ").value = h.cve; $("wbShow").value = "all"; openCve = h.cve; tab("queue"); renderQueue(); showOpen(); }); td.appendChild(b); });
      tr.appendChild(td); tb.appendChild(tr);
    });
    t.appendChild(tb);
    if (list.length > 400) $("wbInvHead").textContent += " · first 400 shown";
  }
  function addItems(name, text) {
    var r = W.parseInventory(name, text), before = inv.length;
    if (!r.items.length) { $("wbInvMsg").textContent = r.kind === "unreadable JSON" ? "That JSON file could not be read." : "No products found. Use one product per line with its version, or a table with a product column."; return; }
    var seen = {}; inv.forEach(function (x) { seen[W.norm(x.vendor + " " + x.name) + "|" + x.version] = x; });
    r.items.forEach(function (x) { var k = W.norm(x.vendor + " " + x.name) + "|" + x.version; if (seen[k]) seen[k].count = Math.max(seen[k].count, x.count); else if (inv.length < W.MAX_ITEMS) { inv.push(x); seen[k] = x; } });
    var saved = saveInv();
    $("wbInvMsg").textContent = "Read as " + r.kind + ": " + r.items.length + " products, " + (inv.length - before) + " new." + (saved ? "" : " This browser would not save the list, so it lasts until you close the page.") + (inv.length >= W.MAX_ITEMS ? " The list is full at " + W.MAX_ITEMS + "." : "");
    $("wbText").value = ""; compute(); renderInv(); renderQueue();
  }
  function readFile(f) {
    if (!f) return; if (f.size > 8e6) { $("wbInvMsg").textContent = "That file is over 8 MB. Export just the product, version and count columns."; return; }
    var fr = new FileReader(); fr.onload = function () { addItems(f.name, String(fr.result || "")); }; fr.onerror = function () { $("wbInvMsg").textContent = "The file could not be read."; }; fr.readAsText(f);
  }

  /* ---- hunt pack ---- */
  function renderHunt() {
    var fmt = $("wbFmt").value, box = $("wbHunt"); box.textContent = ""; $("wbnHunt").textContent = hunt.length ? String(hunt.length) : "";
    var list = hunt.filter(function (h) { return !fmt || h.format === fmt; });
    if (!list.length) { box.appendChild(el("li", "empty", hunt.length ? "No files in that format." : "No detection resources on file yet. The report-review and advisory jobs add them as advisories publish indicator files and rules.")); return; }
    list.forEach(function (h) {
      var li = el("li", "wbh"); li.appendChild(el("span", "badge info", FORMATS[h.format]));
      var mid = el("div"); mid.appendChild(link(h.url, h.name));
      var sub = el("p", "note", [h.publisher, h.date ? fmtDay(h.date) : ""].filter(Boolean).join(" · ") + (h.about ? " · for " : ""));
      if (h.cve) { var b = el("button", "linkbtn", h.cve); b.type = "button"; b.addEventListener("click", function () { $("wbQ").value = h.cve; openCve = h.cve; tab("queue"); renderQueue(); showOpen(); }); sub.appendChild(b); }
      else if (h.event) sub.appendChild(link("./#e=" + h.event, h.about)); else if (h.about) sub.appendChild(document.createTextNode(h.about));
      mid.appendChild(sub); li.appendChild(mid); box.appendChild(li);
    });
  }

  /* ---- exports ---- */
  function csvCell(v) { v = String(v == null ? "" : v); if (/^[=+\-@\t\r]/.test(v)) v = "'" + v; return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; }   // no spreadsheet formulas
  function toCsv() {
    var L = [["Rank", "Score", "CVE", "Vendor", "Product", "Flaw", "Known exploited", "Ransomware", "EPSS %", "CVSS", "CISA deadline", "Your status", "Your versions", "Fixed in", "Why", "Advisory", "NVD"]];
    visibleRows().forEach(function (r, i) { var f = r.f, g = f.guide;
      L.push([i + 1, r.score, f.cve, f.vendor, f.product, f.name, f.kev ? "yes" : "no", f.ransomware ? "yes" : "no", f.epss === null ? "" : Math.round(f.epss * 100), f.cvss === null ? "" : f.cvss, f.due,
        r.m && STATE[r.m.state] ? STATE[r.m.state][0] : inv.length ? "Not on your list" : "", mineText(r.m), (g && g.fixed.length ? g.fixed : (r.m && r.m.fixed.length ? r.m.fixed : W.fixedIn(f))).join("; "),
        r.points.map(function (p) { return "+" + p[0] + " " + p[1]; }).join("; "), (g && g.advisory.url) || f.refs[0] || "", "https://nvd.nist.gov/vuln/detail/" + f.cve]); });
    return L.map(function (row) { return row.map(csvCell).join(","); }).join("\r\n") + "\r\n";
  }
  function toChange() {
    var top = visibleRows().filter(function (r) { return !r.m || r.m.state !== "clear"; }).slice(0, 10), L = ["PATCH PRIORITIES  " + TODAY, "From CyberView's workbench" + (inv.length ? ", matched against our software list (" + inv.length + " products)" : " (general ranking; no software list loaded)"), ""];
    top.forEach(function (r, i) { var f = r.f, g = f.guide;
      L.push((i + 1) + ". " + f.cve + "  " + [f.vendor, f.product].filter(Boolean).join(" ") + "  [score " + r.score + "]");
      if (r.m && r.m.state !== "none") L.push("   We run: " + mineText(r.m) + " -> " + STATE[r.m.state][0]);
      L.push("   Why: " + r.points.map(function (p) { return p[1]; }).join("; "));
      var fx = g && g.fixed.length ? g.fixed : (r.m && r.m.fixed.length ? r.m.fixed : W.fixedIn(f)); if (fx.length) L.push("   Fixed in: " + fx.join("; "));
      if (dueText(f)) L.push("   " + dueText(f));
      L.push("   " + ((g && g.advisory.url) || f.refs[0] || "https://nvd.nist.gov/vuln/detail/" + f.cve)); L.push("");
    });
    L.push("Version ranges are from NIST NVD and can lag: confirm against the vendor advisory before closing an item.");
    return L.join("\n");
  }
  function flash(btn, t) { var old = btn.textContent; btn.textContent = t; setTimeout(function () { btn.textContent = old; }, 2200); }

  /* bring the opened flaw into view (on a phone it is otherwise below the fold) */
  function showOpen() { var n = openCve && document.getElementById("row-" + openCve); if (n) { try { n.scrollIntoView({ block: "start" }); } catch (e) { n.scrollIntoView(); } var b = n.querySelector("button"); if (b) b.focus({ preventScroll: true }); } }

  /* ---- tabs and wiring ---- */
  function tab(t) {
    ["queue", "inv", "hunt"].forEach(function (k) { $("wbt-" + k).setAttribute("aria-selected", k === t ? "true" : "false"); $("wbp-" + k).hidden = k !== t; });
    try { history.replaceState(null, "", t === "queue" ? location.pathname : "#" + t); } catch (e) {}
    if (t === "inv") renderInv(); if (t === "hunt") renderHunt();
  }
  ["queue", "inv", "hunt"].forEach(function (k) { $("wbt-" + k).addEventListener("click", function () { tab(k); }); });
  $("wbGoInv").addEventListener("click", function () { tab("inv"); $("wbText").focus(); });
  var qt = 0; $("wbQ").addEventListener("input", function () { clearTimeout(qt); qt = setTimeout(renderQueue, 140); });
  $("wbShow").addEventListener("change", renderQueue);
  $("wbFmt").addEventListener("change", renderHunt);
  $("wbCsv").addEventListener("click", function () { var a = el("a"); a.href = blobUrl(new Blob([toCsv()], { type: "text/csv" })); var u = a.href; a.download = "cyberview-patch-queue-" + TODAY + ".csv"; document.body.appendChild(a); a.click(); a.remove(); setTimeout(function () { URL.revokeObjectURL(u); }, 4000); });
  $("wbCopy").addEventListener("click", function () { var b = $("wbCopy"); try { navigator.clipboard.writeText(toChange()).then(function () { flash(b, "Copied"); }, function () { flash(b, "Copy blocked"); }); } catch (e) { flash(b, "Copy blocked"); } });
  var drop = $("wbDrop"), file = $("wbFile");
  drop.addEventListener("click", function () { file.click(); });
  drop.addEventListener("keydown", function (ev) { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); file.click(); } });
  file.addEventListener("change", function () { readFile(file.files && file.files[0]); file.value = ""; });
  ["dragenter", "dragover"].forEach(function (n) { drop.addEventListener(n, function (ev) { ev.preventDefault(); drop.classList.add("over"); }); });
  ["dragleave", "drop"].forEach(function (n) { drop.addEventListener(n, function (ev) { ev.preventDefault(); drop.classList.remove("over"); }); });
  drop.addEventListener("drop", function (ev) { readFile(ev.dataTransfer && ev.dataTransfer.files && ev.dataTransfer.files[0]); });
  $("wbAdd").addEventListener("click", function () { var t = $("wbText").value; if (!t.trim()) { $("wbInvMsg").textContent = "Type or paste at least one product first."; return; } addItems("pasted", t); });
  $("wbClear").addEventListener("click", function () { inv = []; saveInv(); try { localStorage.removeItem("cwm.inv"); } catch (e) {} $("wbInvMsg").textContent = "Your list is cleared from this browser."; compute(); renderInv(); renderQueue(); });

  loadInv();
  fetch("data/workbench.json", { cache: "no-cache" }).then(function (r) { if (!r.ok) throw new Error(); return r.json(); }).then(function (d) {
    builtAt = str(d && d.built_at, 30);
    var guides = {}, raw = d && d.guides && typeof d.guides === "object" ? d.guides : {};
    Object.keys(raw).slice(0, 2000).forEach(function (k) { if (isCve(k)) { var g = cleanGuide(raw[k]); if (g) guides[k] = g; } });
    var eventOf = d && d.event_of && typeof d.event_of === "object" ? d.event_of : {};
    var an = {}, ra = d && d.analyses && typeof d.analyses === "object" ? d.analyses : {};
    Object.keys(ra).slice(0, 2000).forEach(function (k) { if (isCve(k)) { var a = cleanAnalysis(ra[k]); if (a) an[k] = a; } });
    flaws = (Array.isArray(d && d.kev) ? d.kev : []).slice(0, 3000).map(function (k) { return cleanKev(k, guides, eventOf, an); }).filter(Boolean)
      .concat((Array.isArray(d && d.vulns) ? d.vulns : []).slice(0, 80).map(function (v) { return cleanVuln(v, guides, an); }).filter(Boolean));
    hunt = (Array.isArray(d && d.hunt) ? d.hunt : []).slice(0, 200).map(cleanHunt).filter(Boolean);
    var fm = {}; hunt.forEach(function (h) { fm[h.format] = 1; });
    Object.keys(fm).sort().forEach(function (k) { var o = el("option", null, FORMATS[k]); o.value = k; $("wbFmt").appendChild(o); });
    compute();
    var h = location.hash.slice(1); if (isCve(h)) { openCve = h; $("wbQ").value = h; }
    renderQueue(); renderInv(); renderHunt();
    if (h === "inv" || h === "hunt") tab(h);
  }).catch(function () { $("wbSummary").textContent = "The workbench data can't be loaded right now. Try again in a minute."; });
})();
