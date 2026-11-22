// CyberView Scanner page. Reads data/scanner.json (written by scripts/build.mjs through scripts/scanner-stats.mjs, no AI
// model): live counts read from the scanner's code, its opt-in flags and the hand-written list of recent features
// (config/scanner-page.json). Every record goes through clean*() first; all text is inserted as text. A missing number
// shows a dash.
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  function el(tag, cls, text) { var n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = String(text); return n; }
  // one failing panel must not blank the page: each renders inside safe() and says so if it breaks
  function safe(name, fn, box) { try { fn(); } catch (e) { if (box) { box.textContent = ""; box.appendChild(el("li", "note bad", "The " + name + " could not be shown.")); } } }
  function str(v, n) { return typeof v === "string" ? v.replace(/\s+/g, " ").trim().slice(0, n) : ""; }
  function num(v) { return typeof v === "number" && isFinite(v) && v >= 0 && v < 1e7 ? Math.round(v) : null; }
  function date(v) { return typeof v === "string" && /^\d{4}-\d{2}-\d{2}$/.test(v) ? v : ""; }
  function fmtN(n) { return n == null ? "—" : n.toLocaleString("en-US"); }
  function fmtD(d) { try { return new Date(d + "T12:00:00Z").toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }); } catch (e) { return d; } }
  var AREAS = ["services", "edge", "cms", "apps", "rail"];
  var FLAG = /^--[a-z][a-z-]{1,40}$/;

  // ---------- clean: known fields only, with length limits ----------
  function cleanStats(s) {
    var o = { ok: false, version: "", products: null, rules: null, kevTotal: null, kevCovered: null, kevGap: null, railPaths: null, railEntries: null, perHost: null, areas: {}, optIns: [], recent: [], built: "" };
    if (!s || typeof s !== "object" || s.error) return o;
    o.ok = true;
    o.version = /^[\w.+-]{1,20}$/.test(s.version || "") ? s.version : "";
    o.products = num(s.products); o.rules = num(s.rules);
    o.kevTotal = num(s.kev_products); o.kevCovered = num(s.kev_covered); o.kevGap = num(s.kev_gap);
    if (o.kevTotal == null || o.kevCovered == null || o.kevCovered > o.kevTotal) { o.kevTotal = o.kevCovered = o.kevGap = null; }
    o.railPaths = num(s.rail_paths); o.railEntries = num(s.rail_entries); o.perHost = num(s.paths_per_host);
    var a = s.areas && typeof s.areas === "object" ? s.areas : {};
    AREAS.forEach(function (k) { o.areas[k] = num(a[k]); });
    o.optIns = (Array.isArray(s.opt_ins) ? s.opt_ins.slice(0, 12) : []).map(function (x) {
      return x && FLAG.test(x.flag || "") && str(x.what, 200) ? { flag: x.flag, what: str(x.what, 200) } : null;
    }).filter(Boolean);
    o.recent = (Array.isArray(s.recent) ? s.recent.slice(0, 20) : []).map(function (r) {
      if (!r || typeof r !== "object" || !str(r.title, 100) || !date(r.date)) return null;
      var pr = typeof r.pr === "number" && r.pr > 0 && r.pr < 100000 && Math.round(r.pr) === r.pr ? r.pr : null;
      return { title: str(r.title, 100), line: str(r.line, 300), date: r.date, pr: pr };
    }).filter(Boolean);
    o.built = typeof s.built_at === "string" && /^\d{4}-\d{2}-\d{2}T[\d:.]+Z$/.test(s.built_at) ? s.built_at : "";
    return o;
  }

  // ---------- render ----------
  function tiles(d) {
    $("nProducts").textContent = fmtN(d.products);
    $("nRules").textContent = fmtN(d.rules);
    if (d.kevTotal != null) {
      $("nKev").textContent = fmtN(d.kevCovered) + " of " + fmtN(d.kevTotal);
      $("nKevL").textContent = "known-exploited products it can name (" + fmtN(d.kevGap) + " not yet)";
    } else $("nKev").textContent = "—";
    $("nRail").textContent = fmtN(d.railPaths);
    $("nVersion").textContent = d.version || "—";
    var note = $("glanceNote");
    if (!d.ok) note.textContent = "The scanner's numbers could not be loaded; dashes stand for them.";
    else note.textContent = d.built ? "Counted at the site build of " + d.built.slice(0, 10) + " " + d.built.slice(11, 16) + " UTC." : "";
  }
  function areas(d) {
    Array.prototype.forEach.call(document.querySelectorAll("#areas .acount[data-n]"), function (b) {
      var k = b.getAttribute("data-n"), n = d.areas[k];
      var card = b.closest(".area");
      if (n != null) {
        b.textContent = k === "rail" ? fmtN(n) + " entries" + (d.railPaths != null ? ", " + fmtN(d.railPaths) + " paths" : "") + (d.perHost != null ? ", at most " + d.perHost + " per host" : "") + " · opt-in: --paths"
          : fmtN(n) + (k === "services" ? " built-in entries" : " detection rows");
        if (card) card.classList.remove("absent");
      } else if (d.ok) {
        b.textContent = "Not in this release yet";
        if (card) card.classList.add("absent");
      } else b.textContent = "—";
    });
  }
  function optIns(d) {
    var box = $("optins"); box.textContent = "";
    if (!d.optIns.length) { box.appendChild(el("li", "note", d.ok ? "None listed." : "Could not be loaded; see the guide.")); return; }
    d.optIns.forEach(function (x) { var li = el("li"); li.appendChild(el("code", null, x.flag)); li.appendChild(document.createTextNode(" " + x.what)); box.appendChild(li); });
  }
  function recent(d) {
    var box = $("recent"); box.textContent = "";
    if (!d.recent.length) { box.appendChild(el("li", "note", d.ok ? "Nothing listed yet." : "Could not be loaded.")); return; }
    d.recent.forEach(function (r) {
      var li = el("li", "rc");
      var t = el("time", "date", fmtD(r.date)); t.setAttribute("datetime", r.date); li.appendChild(t);
      var body = el("div", "rcb");
      var h = el("span", "rct", r.title); body.appendChild(h);
      if (r.pr) { var a = el("a", "rcpr", "#" + r.pr); a.href = "https://github.com/xanderhutch/CyberView/pull/" + r.pr; a.target = "_blank"; a.rel = "noopener noreferrer"; a.setAttribute("aria-label", "Pull request " + r.pr); body.appendChild(a); }
      if (r.line) body.appendChild(el("p", null, r.line));
      li.appendChild(body); box.appendChild(li);
    });
  }
  function render(d) {
    safe("numbers", function () { tiles(d); });
    safe("areas", function () { areas(d); });
    safe("opt-ins", function () { optIns(d); }, $("optins"));
    safe("recent list", function () { recent(d); }, $("recent"));
  }

  fetch("data/scanner.json", { cache: "no-cache" }).then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); })
    .then(function (s) { render(cleanStats(s)); })
    .catch(function () { render(cleanStats(null)); });
})();
