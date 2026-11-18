// CyberView trends page. Reads data/trends.json (written by scripts/build.mjs). All text is inserted as text.
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var TITLES = { category: "Event types", sector: "Sectors", country: "Countries", actor: "Threat actors", product: "Products", tag: "Themes" };
  var CAT = { incident: "Incidents", vuln: "Patches and advisories", report: "Threat reports", policy: "Law and policy", enforcement: "Law enforcement", investment: "Investment and vendors", outage: "Outages" };
  function el(tag, cls, text) { var n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = String(text); return n; }
  function fmt(d, o) { try { return new Date(d + "T12:00:00Z").toLocaleDateString(undefined, o || { month: "short", day: "numeric" }); } catch (e) { return d; } }

  fetch("data/trends.json", { cache: "no-cache" }).then(function (r) { if (!r.ok) throw new Error(); return r.json(); }).then(render)
    .catch(function () { $("summary").textContent = "Trends can't be loaded right now. Try again in a minute."; });

  function render(t) {
    var complete = !!(t.prev && t.prev.complete);
    $("summary").textContent = t.cur.total + " events from " + fmt(t.cur.from) + " to " + fmt(t.cur.to) + "; " + t.prev.total + " in the week before.";
    if (!complete) {
      var c = $("caveat"); c.hidden = false;
      var ready = new Date(Date.parse(t.collection_started + "T12:00:00Z") + 14 * 864e5).toISOString().slice(0, 10);
      c.textContent = "CyberView began collecting on " + fmt(t.collection_started, { month: "long", day: "numeric" }) + ". Events before that were filled in afterwards and are incomplete, so the week before is undercounted. Until about " + fmt(ready, { month: "long", day: "numeric" }) + ", read this week's counts as a ranking, not the changes as real trends.";
    }
    days(t.daily || []);
    var box = $("dims");
    ["category", "sector", "country", "actor", "product", "tag"].forEach(function (k) { var rows = (t.dims && t.dims[k]) || []; if (rows.filter(function (r) { return r.cur > 0; }).length >= 2) box.appendChild(dim(k, rows, complete)); });
  }

  function days(list) {
    var box = $("days"), max = Math.max(1, Math.max.apply(null, list.map(function (d) { return d.total; })));
    list.forEach(function (d, i) {
      var col = el("div", "day"); col.title = fmt(d.date, { weekday: "short", month: "short", day: "numeric" }) + ": " + d.total + " event" + (d.total === 1 ? "" : "s");
      var bar = el("div", "bar"); bar.style.height = Math.round((d.total / max) * 128) + "px"; if (!d.total) bar.hidden = true; col.appendChild(bar);
      col.appendChild(el("span", "lab", i % 7 === 6 || i === list.length - 1 ? fmt(d.date) : ""));
      box.appendChild(col);
    });
  }

  function dim(k, rows, complete) {
    var sec = el("section", "panel");
    sec.appendChild(el("h2", null, TITLES[k]));
    var top = rows.slice().sort(function (a, b) { return b.cur - a.cur || (b.cur - b.prev) - (a.cur - a.prev); }).slice(0, 8);
    var max = Math.max(1, top[0] ? top[0].cur : 1);
    var tb = el("table"), th = el("thead"), tr = el("tr");
    [["Name", ""], ["This week", "num"], [complete ? "Week before" : "Week before (partial)", "num"], ["Change", "num"]].forEach(function (h) { var c = el("th", h[1], h[0]); c.scope = "col"; tr.appendChild(c); });
    th.appendChild(tr); tb.appendChild(th);
    var body = el("tbody");
    top.forEach(function (r) {
      var row = el("tr"), name = el("td"), a = el("a", null, k === "category" ? (CAT[r.k] || r.k) : r.k);
      a.href = "archive.html#q=" + encodeURIComponent(k === "category" ? "" : r.k) + (k === "category" ? "&cat=" + encodeURIComponent(r.k) : "");
      name.appendChild(a); row.appendChild(name);
      var cur = el("td", "num"), bw = el("span", "mini"), b = el("span", "fill"); b.style.width = Math.round((r.cur / max) * 100) + "%"; bw.appendChild(b);
      cur.appendChild(bw); cur.appendChild(el("span", null, String(r.cur))); row.appendChild(cur);
      row.appendChild(el("td", "num", String(r.prev)));
      var d = r.cur - r.prev, ch = el("td", "num " + (complete ? (d > 0 ? "up" : d < 0 ? "down" : "") : "muted"));
      ch.textContent = r.prev === 0 && r.cur > 0 ? "new" : (d > 0 ? "+" : "") + d;
      row.appendChild(ch); body.appendChild(row);
    });
    tb.appendChild(body); sec.appendChild(tb);
    return sec;
  }
})();
