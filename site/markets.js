// CyberView markets page. Reads data/markets.json (built by scripts/build.mjs from data/markets and the events).
// Every record goes through a clean function; nodes are built with textContent and d3 .text(), never HTML strings.
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var reduced = window.matchMedia && matchMedia("(prefers-reduced-motion:reduce)").matches;
  function str(s, n) { return String(s == null ? "" : s).replace(/[\u0000-\u001f]/g, " ").slice(0, n); }
  function num(v, lo, hi) { return typeof v === "number" && isFinite(v) && v >= lo && v <= hi ? v : null; }
  function day(s) { s = str(s, 10); return /^\d{4}-\d{2}-\d{2}$/.test(s) ? s : ""; }
  function el(tag, cls, text) { var n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = String(text); return n; }
  function eventLink(id) { return "./#e=" + encodeURIComponent(id); }
  function safeUrl(u) { u = String(u || ""); return /^https:\/\/www\.sec\.gov\/[^\s"'<>]*$/.test(u) ? u : "about:blank"; }
  function pct(x, signed) { if (x == null) return "n/a"; var v = (x * 100).toFixed(Math.abs(x) < 0.1 ? 1 : 0); return (signed && x > 0 ? "+" : "") + v + "%"; }
  function fmtDay(d) { var t = Date.parse(d + "T12:00:00Z"); return isFinite(t) ? new Date(t).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" }) : d; }
  var CAT = { incident: "Incident", report: "Threat report", vuln: "Patch / advisory", policy: "Law / policy", enforcement: "Law enforcement", investment: "Investment", outage: "Outage" };

  // ---------- cleaning ----------
  function cleanEv(x) {
    if (!x || typeof x !== "object") return null;
    var id = str(x.id, 120); if (!/^[a-z0-9][a-z0-9-]*$/.test(id)) return null;
    return { id: id, title: str(x.title, 200), date: day(x.date), category: CAT[x.category] ? x.category : "incident", severity: num(x.severity, 1, 3) || 1, org: str(x.org, 120) };
  }
  function cleanSeries(a, cols) {
    return (Array.isArray(a) ? a : []).slice(0, 400).map(function (r) {
      if (!Array.isArray(r) || !day(r[0])) return null;
      var o = [day(r[0])]; for (var i = 1; i < cols; i++) o.push(typeof r[i] === "number" && isFinite(r[i]) ? r[i] : null); return o;
    }).filter(Boolean);
  }
  function cleanImpact(x) {
    var e = cleanEv(x); if (!e) return null;
    e.ticker = str(x.ticker, 10); e.status = ["ok", "split", "no_window", "no_prices"].indexOf(x.status) >= 0 ? x.status : "no_prices";
    ["ret0", "ret5", "mkt0", "mkt5", "abn0", "abn5"].forEach(function (k) { e[k] = num(x[k], -5, 50); });
    e.day0 = day(x.day0); e.series = cleanSeries(x.series, 4);
    return e;
  }
  function cleanTracked(x) {
    if (!x || typeof x !== "object") return null;
    var t = { symbol: str(x.symbol, 10), name: str(x.name, 80), kind: x.kind === "etf" ? "etf" : "vendor",
      chg1: num(x.chg1, -5, 50), chg5: num(x.chg5, -5, 50), chg30: num(x.chg30, -5, 50),
      last: Array.isArray(x.last) && day(x.last[0]) && num(x.last[1], 0, 1e7) != null ? { d: x.last[0], c: x.last[1] } : null,
      series: cleanSeries(x.series, 2),
      events: (Array.isArray(x.events) ? x.events : []).map(cleanEv).filter(Boolean).slice(0, 40),
      kev: (Array.isArray(x.kev) ? x.kev : []).map(function (k) { return k && /^CVE-\d{4}-\d+$/.test(k.cve) && day(k.added) ? { cve: k.cve, added: k.added, product: str(k.product, 80) } : null; }).filter(Boolean).slice(0, 40) };
    return /^[A-Z][A-Z0-9.\-]{0,9}$/.test(t.symbol) ? t : null;
  }
  function cleanFiling(x) {
    var e = cleanEv(x); if (!e || !x.filing || typeof x.filing !== "object") return null;
    e.ticker = str(x.ticker, 10);
    e.filing = { form: str(x.filing.form, 8), item: str(x.filing.item, 8), filed: day(x.filing.filed), url: safeUrl(x.filing.url), company: str(x.filing.company, 120) };
    return e.filing.filed ? e : null;
  }

  // ---------- tooltip ----------
  var tipEl = $("mtip");
  function tip(ev, a, b) {
    tipEl.textContent = ""; tipEl.appendChild(document.createTextNode(a)); if (b) tipEl.appendChild(el("small", null, b));
    tipEl.hidden = false;
    var x = Math.min(innerWidth - 320, ev.clientX + 14), y = Math.min(innerHeight - 80, ev.clientY + 14);
    tipEl.style.left = Math.max(8, x) + "px"; tipEl.style.top = y + "px";
  }
  function untip() { tipEl.hidden = true; }

  fetch("data/markets.json", { cache: "no-cache" }).then(function (r) { if (!r.ok) throw new Error(); return r.json(); }).then(render)
    .catch(function () { $("asof").textContent = "Market data can't be loaded right now. Try again in a minute."; });

  var data = null, win = 0;
  function render(raw) {
    data = {
      asOf: day(raw.as_of), source: str(raw.source, 80),
      bench: cleanSeries(raw.benchmark && raw.benchmark.series, 2), benchSym: str(raw.benchmark && raw.benchmark.symbol, 10) || "SPY",
      impacts: (Array.isArray(raw.impacts) ? raw.impacts : []).map(cleanImpact).filter(Boolean),
      tracked: (Array.isArray(raw.tracked) ? raw.tracked : []).map(cleanTracked).filter(Boolean),
      filings: (Array.isArray(raw.filings) ? raw.filings : []).map(cleanFiling).filter(Boolean),
    };
    $("asof").textContent = data.asOf ? "Prices to the close of " + fmtDay(data.asOf) + ". " + data.impacts.length + (data.impacts.length === 1 ? " incident" : " incidents") + " at listed companies, " + data.filings.length + (data.filings.length === 1 ? " SEC filing, " : " SEC filings, ") + data.tracked.length + " stocks tracked." : "No price data yet: the first prices arrive with the next markets run.";
    tiles(); impactChart(); impactCards(); filings(); tracker();
  }

  function tiles() {
    var box = $("tiles"); box.textContent = "";
    var ok = data.impacts.filter(function (x) { return x.status === "ok" && x.abn0 != null; });
    var avg = ok.length ? ok.reduce(function (s, x) { return s + x.abn0; }, 0) / ok.length : null;
    var etf = data.tracked.filter(function (t) { return t.kind === "etf" && t.chg30 != null; })[0];
    [[ok.length ? String(ok.length) : "0", "incidents at listed companies with a measured move"],
     [avg == null ? "n/a" : pct(avg, true), "average move against the market on disclosure day"],
     [String(data.filings.length), "SEC cyber incident filings on file"],
     [etf ? pct(etf.chg30, true) : "n/a", etf ? etf.symbol + " (cyber security ETF), last 30 trading days" : "cyber security ETF, last 30 trading days"]].forEach(function (t) {
      var d = el("div", "tile"); d.appendChild(el("b", null, t[0])); d.appendChild(el("span", null, t[1])); box.appendChild(d);
    });
  }

  // ---------- abnormal-move bar chart (single colour, sign from the zero line) ----------
  function impactChart() {
    var box = $("impactChart"); box.textContent = "";
    var k = win === 0 ? "abn0" : "abn5";
    var rows = data.impacts.filter(function (x) { return x.status === "ok" && x[k] != null; }).slice(0, 25);
    if (!rows.length) { box.appendChild(el("p", "empty", win === 0 ? "No measured moves yet. They appear once a listed company's incident is on file and its prices have been fetched." : "Five-day moves appear five trading days after each disclosure.")); return; }
    var W = Math.max(320, box.clientWidth || 800), rowH = 28, L = Math.min(260, W * 0.38), R = 64, H = rows.length * rowH + 30;
    var ext = d3.max(rows, function (r) { return Math.abs(r[k]); }) || 0.01;
    var x = d3.scaleLinear().domain([-ext * 1.1, ext * 1.1]).range([L, W - R]).nice();
    var svg = d3.select(box).append("svg").attr("viewBox", "0 0 " + W + " " + H).attr("role", "img")
      .attr("aria-label", "Abnormal share moves after disclosure, one bar per company");
    svg.append("g").attr("class", "axis").attr("transform", "translate(0," + (H - 22) + ")")
      .call(d3.axisBottom(x).ticks(5).tickFormat(function (v) { return (v > 0 ? "+" : "") + Math.round(v * 100) + "%"; }));
    svg.append("line").attr("class", "zero").attr("x1", x(0)).attr("x2", x(0)).attr("y1", 0).attr("y2", H - 22);
    rows.forEach(function (r, i) {
      var y = i * rowH + 4, v = r[k], x0 = x(Math.min(0, v)), w = Math.max(2, Math.abs(x(v) - x(0)));
      var g = svg.append("g").attr("tabindex", 0).attr("role", "link").attr("aria-label", r.org + " " + r.ticker + ", " + pct(v, true) + " against the market");
      g.append("text").attr("class", "bl").attr("x", L - 10).attr("y", y + 15).attr("text-anchor", "end").text((r.org || r.ticker).slice(0, 28) + " (" + r.ticker + ")");
      g.append("rect").attr("class", "hit").attr("x", 0).attr("y", y - 2).attr("width", W).attr("height", rowH);
      g.append("rect").attr("class", "bar").attr("x", x0).attr("y", y + 4).attr("width", w).attr("height", 16).attr("rx", 3);
      g.append("text").attr("class", "bv").attr("x", v < 0 ? x0 - 6 : x0 + w + 6).attr("y", y + 16).attr("text-anchor", v < 0 ? "end" : "start").text(pct(v, true));
      var open = function () { location.href = eventLink(r.id); };
      g.on("click", open).on("keydown", function (ev) { if (ev.key === "Enter") open(); })
        .on("pointermove", function (ev) {
          tip(ev, r.title, fmtDay(r.date) + " · " + r.ticker + ": shares " + pct(win === 0 ? r.ret0 : r.ret5, true) + ", S&P 500 " + pct(win === 0 ? r.mkt0 : r.mkt5, true) + " → " + pct(v, true) + " against the market. Click to open the event.");
        }).on("pointerleave", untip);
    });
  }
  document.querySelectorAll("#winSeg button").forEach(function (b) {
    b.addEventListener("click", function () {
      win = +b.dataset.win; document.querySelectorAll("#winSeg button").forEach(function (x) { x.setAttribute("aria-pressed", x === b ? "true" : "false"); });
      impactChart();
    });
  });

  // ---------- per-event cards: stock vs market, indexed to 100 the day before disclosure ----------
  function miniLine(box, series, label) {
    var W = 300, H = 120, m = { l: 34, r: 40, t: 10, b: 20 };
    var pts = series.filter(function (r) { return r[2] != null; });
    if (pts.length < 3) { box.appendChild(el("p", "empty", "Not enough trading days yet.")); return; }
    var all = pts.map(function (r) { return r[2]; }).concat(pts.map(function (r) { return r[3]; }).filter(function (v) { return v != null; }));
    var x = d3.scaleLinear().domain(d3.extent(pts, function (r) { return r[1]; })).range([m.l, W - m.r]);
    var y = d3.scaleLinear().domain(d3.extent(all)).nice().range([H - m.b, m.t]);
    var svg = d3.select(box).append("svg").attr("viewBox", "0 0 " + W + " " + H).attr("role", "img").attr("aria-label", label);
    svg.append("g").attr("class", "axis").attr("transform", "translate(" + m.l + ",0)").call(d3.axisLeft(y).ticks(3).tickSize(-(W - m.l - m.r)))
      .call(function (g) { g.select(".domain").remove(); g.selectAll("line").attr("stroke", "rgba(255,255,255,.07)"); });
    svg.append("line").attr("class", "d0").attr("x1", x(0)).attr("x2", x(0)).attr("y1", m.t).attr("y2", H - m.b);
    svg.append("text").attr("class", "dl").attr("x", x(0) + 3).attr("y", H - 6).text("disclosure");
    var ln = d3.line().defined(function (d) { return d[1] != null; }).x(function (d) { return x(d[0]); }).y(function (d) { return y(d[1]); });
    svg.append("path").attr("class", "bench").attr("d", ln(pts.map(function (r) { return [r[1], r[3]]; })));
    svg.append("path").attr("class", "line").attr("d", ln(pts.map(function (r) { return [r[1], r[2]]; })));
    var last = pts[pts.length - 1];
    svg.append("text").attr("class", "dl s").attr("x", x(last[1]) + 4).attr("y", y(last[2]) + 4).text("stock");
    if (last[3] != null) svg.append("text").attr("class", "dl").attr("x", x(last[1]) + 4).attr("y", y(last[3]) + (Math.abs(y(last[3]) - y(last[2])) < 12 ? 14 : 4)).text("S&P");
    var hit = svg.append("rect").attr("x", m.l).attr("y", m.t).attr("width", W - m.l - m.r).attr("height", H - m.t - m.b).attr("fill", "transparent");
    hit.on("pointermove", function (ev) {
      var px = d3.pointer(ev)[0], dx = Math.round(x.invert(px)), r = pts.reduce(function (a, b) { return Math.abs(b[1] - dx) < Math.abs(a[1] - dx) ? b : a; });
      tip(ev, fmtDay(r[0]) + " (day " + (r[1] > 0 ? "+" : "") + r[1] + ")", "Stock " + r[2].toFixed(1) + (r[3] != null ? " · S&P 500 " + r[3].toFixed(1) : "") + " (100 = close before disclosure)");
    }).on("pointerleave", untip);
  }
  function impactCards() {
    var box = $("impactCards"); box.textContent = "";
    data.impacts.slice(0, 12).forEach(function (r) {
      var c = el("article", "card"), h = el("h3"), a = el("a", null, r.title); a.href = eventLink(r.id); h.appendChild(a); c.appendChild(h);
      c.appendChild(el("p", "meta", fmtDay(r.date) + " · " + (r.org || "") + " · " + r.ticker));
      if (r.status === "ok") {
        miniLine(c, r.series, r.ticker + " against the S&P 500 around the disclosure");
        var n = el("div", "nums");
        [["Disclosure day", r.abn0], ["Five days", r.abn5]].forEach(function (p) {
          var s = el("span"); s.appendChild(document.createTextNode(p[0] + " vs market: "));
          s.appendChild(el("b", p[1] == null ? null : p[1] < 0 ? "dn" : "up", p[1] == null ? "pending" : pct(p[1], true))); n.appendChild(s);
        });
        c.appendChild(n);
      } else c.appendChild(el("p", "empty", r.status === "split" ? "Share split inside the window: move not computed." : r.status === "no_window" ? "Prices do not cover the disclosure date yet." : "Prices for " + r.ticker + " arrive with the next markets run."));
      box.appendChild(c);
    });
  }

  function filings() {
    var body = $("filings").querySelector("tbody"); body.textContent = "";
    $("filingNote").textContent = data.filings.length ? "" : "No filings on file yet. The markets research job looks for new Item 1.05 filings every day.";
    data.filings.forEach(function (f) {
      var tr = el("tr");
      tr.appendChild(el("td", null, fmtDay(f.filing.filed)));
      var co = el("td"); co.appendChild(el("strong", null, f.filing.company || f.org)); if (f.ticker) co.appendChild(document.createTextNode(" (" + f.ticker + ")")); tr.appendChild(co);
      var fm = el("td"), a = el("a", null, f.filing.form + (f.filing.item ? " Item " + f.filing.item : "")); a.href = safeUrl(f.filing.url); a.target = "_blank"; a.rel = "noopener noreferrer"; fm.appendChild(a); tr.appendChild(fm);
      var ev = el("td"), b = el("a", null, f.title); b.href = eventLink(f.id); ev.appendChild(b); tr.appendChild(ev);
      body.appendChild(tr);
    });
  }

  // ---------- small multiples: one stock each, own incidents and KEV additions marked ----------
  function tracker() {
    var box = $("tracker"); box.textContent = "";
    var list = data.tracked.slice().sort(function (a, b) { return (a.kind === "etf" ? 0 : 1) - (b.kind === "etf" ? 0 : 1); });
    list.forEach(function (t) {
      var c = el("article", "stock"), h = el("h3", null, t.name); c.appendChild(h);
      var px = el("div", "px"); px.appendChild(el("span", "kind", t.symbol + (t.kind === "etf" ? " · ETF" : "")));
      if (t.last) { px.appendChild(el("b", null, "$" + t.last.c.toFixed(2))); }
      c.appendChild(px);
      if (t.series.length < 5) { c.appendChild(el("p", "empty", "Prices arrive with the next markets runs.")); box.appendChild(c); return; }
      var n = el("div", "nums");
      [["1 day", t.chg1], ["5 days", t.chg5], ["30 days", t.chg30]].forEach(function (p) { var s = el("span"); s.appendChild(document.createTextNode(p[0] + " ")); s.appendChild(el("b", p[1] == null ? null : p[1] < 0 ? "dn" : "up", pct(p[1], true))); n.appendChild(s); });
      c.appendChild(n);
      stockChart(c, t);
      box.appendChild(c);
    });
  }
  function stockChart(box, t) {
    var W = 300, H = 130, m = { l: 40, r: 8, t: 12, b: 20 };
    var s = t.series.map(function (r) { return [new Date(r[0] + "T12:00:00Z"), r[1], r[0]]; });
    var x = d3.scaleTime().domain(d3.extent(s, function (r) { return r[0]; })).range([m.l, W - m.r]);
    var y = d3.scaleLinear().domain(d3.extent(s, function (r) { return r[1]; })).nice().range([H - m.b, m.t]);
    var svg = d3.select(box).append("svg").attr("viewBox", "0 0 " + W + " " + H).attr("role", "img").attr("aria-label", t.name + " share price, last 90 trading days");
    svg.append("g").attr("class", "axis").attr("transform", "translate(" + m.l + ",0)").call(d3.axisLeft(y).ticks(3).tickSize(-(W - m.l - m.r)).tickFormat(function (v) { return "$" + v; }))
      .call(function (g) { g.select(".domain").remove(); g.selectAll("line").attr("stroke", "rgba(255,255,255,.07)"); });
    svg.append("g").attr("class", "axis").attr("transform", "translate(0," + (H - m.b) + ")").call(d3.axisBottom(x).ticks(3).tickFormat(d3.timeFormat("%b")))
      .call(function (g) { g.select(".domain").remove(); });
    svg.append("path").attr("class", "line").attr("d", d3.line().x(function (r) { return x(r[0]); }).y(function (r) { return y(r[1]); })(s));
    var at = function (d) { var r = s.find(function (p) { return p[2] >= d; }) || s[s.length - 1]; return r; };
    var cross = svg.append("line").attr("class", "d0").attr("y1", m.t).attr("y2", H - m.b).style("display", "none");
    svg.append("rect").attr("x", m.l).attr("y", m.t).attr("width", W - m.l - m.r).attr("height", H - m.t - m.b).attr("fill", "transparent")
      .on("pointermove", function (ev) {
        var d = x.invert(d3.pointer(ev)[0]), r = s.reduce(function (a, b) { return Math.abs(b[0] - d) < Math.abs(a[0] - d) ? b : a; });
        cross.style("display", null).attr("x1", x(r[0])).attr("x2", x(r[0]));
        tip(ev, t.symbol + " $" + r[1].toFixed(2), fmtDay(r[2]));
      }).on("pointerleave", function () { cross.style("display", "none"); untip(); });
    t.events.forEach(function (e) {
      var r = at(e.date);
      svg.append("circle").attr("class", "mk").attr("r", 4.5).attr("cx", x(r[0])).attr("cy", y(r[1])).attr("tabindex", 0).attr("role", "link").attr("aria-label", e.title)
        .on("pointermove", function (ev) { tip(ev, e.title, fmtDay(e.date) + " · " + CAT[e.category] + " · click to open"); }).on("pointerleave", untip)
        .on("click", function () { location.href = eventLink(e.id); }).on("keydown", function (ev) { if (ev.key === "Enter") location.href = eventLink(e.id); });
    });
    t.kev.forEach(function (k) {
      var r = at(k.added), cx = x(r[0]), cy = y(r[1]) - 9;
      svg.append("path").attr("class", "mk kev").attr("d", d3.symbol().type(d3.symbolTriangle).size(42)()).attr("transform", "translate(" + cx + "," + cy + ")")
        .on("pointermove", function (ev) { tip(ev, k.cve + " added to CISA's known-exploited list", fmtDay(k.added) + (k.product ? " · " + k.product : "")); }).on("pointerleave", untip);
    });
  }

  var rt = 0; window.addEventListener("resize", function () { clearTimeout(rt); rt = setTimeout(function () { if (data) impactChart(); }, 150); });
  void reduced;
})();
