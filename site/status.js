// CyberView status page. Reads data/ops.json (written by scripts/build.mjs from routines.json and the run logs).
// Lateness is worked out here against the visitor's clock, so the page stays truthful between deploys.
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var REPO = "https://github.com/xanderhutch/CyberView";
  var MODEL = { "claude-sonnet-5-5": "Sonnet 5.5", "claude-opus-5-5": "Opus 5.5", "claude-haiku-5-5": "Haiku 5.5" };
  var DOW = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  function safeUrl(u) { u = String(u || ""); return /^https:\/\/github\.com\//.test(u) ? u : "about:blank"; }
  function el(tag, cls, text) { var n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = String(text); return n; }
  function pad(n) { return String(n).padStart(2, "0"); }
  function ago(iso) {
    var m = Math.round((Date.now() - Date.parse(iso)) / 6e4);
    if (!isFinite(m)) return "";
    if (m < 2) return "just now"; if (m < 60) return m + " min ago";
    var h = m / 60; if (h < 48) return (h < 10 ? h.toFixed(1) : Math.round(h)) + " h ago";
    return Math.round(h / 24) + " days ago";
  }
  // plain-language schedule for the cron shapes the routines use
  function when(cron) {
    var p = String(cron || "").split(/\s+/); if (p.length !== 5) return cron || "";
    var min = p[0], hr = p[1], dow = p[4];
    var days = dow === "*" ? "" : dow.split(",").map(function (d) { return DOW[+d] || d; }).join(" and ") + " ";
    if (hr === "*") return "hourly at :" + pad(min);
    var every = hr.match(/^\*\/(\d+)$/); if (every) return "every " + every[1] + " h at :" + pad(min);
    return days + hr.split(",").map(function (h) { return pad(h) + ":" + pad(min); }).join(" and ");
  }
  function state(r) {
    if (!r.active) return { cls: "wait", text: r.tier === "ai" ? "Not running yet: needs the Claude token" : "Paused" };
    if (!r.status_key) return { cls: "info", text: "See GitHub runs", link: /^[a-z0-9-]+\.yml$/.test(String(r.workflow)) ? REPO + "/actions/workflows/" + r.workflow : "" };
    if (!r.last_at) return { cls: "bad", text: "No run recorded" };
    var h = (Date.now() - Date.parse(r.last_at)) / 36e5;
    if (h <= r.max_age_hours) return { cls: "ok", text: "On time" };
    if (h <= 2 * r.max_age_hours) return { cls: "warn", text: "Late" };
    return { cls: "bad", text: "Stopped" };
  }

  fetch("data/ops.json", { cache: "no-cache" }).then(function (r) { if (!r.ok) throw new Error(); return r.json(); }).then(render)
    .catch(function () { $("summary").textContent = "Status can't be loaded right now. Try again in a minute."; });

  function render(o) {
    var body = $("routines").querySelector("tbody"), counts = { ok: 0, active: 0 };
    (o.routines || []).forEach(function (r) {
      var s = state(r), tr = el("tr");
      if (r.active) { counts.active++; if (s.cls === "ok" || s.cls === "info") counts.ok++; }
      var name = el("td"); name.appendChild(el("strong", null, r.name)); name.appendChild(el("span", "sub", r.does)); tr.appendChild(name);
      tr.appendChild(el("td", "nowrap", when(r.cron)));
      tr.appendChild(el("td", "nowrap", r.model ? (MODEL[r.model] || r.model) : "none (script)"));
      tr.appendChild(el("td", "nowrap", r.last_at ? ago(r.last_at) : "—"));
      var st = el("td"), b = el("span", "badge " + s.cls, s.text);
      if (s.link) { var a = el("a", "badge " + s.cls, s.text); a.href = safeUrl(s.link); a.target = "_blank"; a.rel = "noopener noreferrer"; st.appendChild(a); } else st.appendChild(b);
      tr.appendChild(st); body.appendChild(tr);
    });
    $("summary").textContent = counts.ok + " of " + counts.active + " active routines are on time. Data built " + ago(o.built_at) + ".";
    var L = o.leads || {};
    $("leads").textContent = (L.last_24h || 0) + " new leads";
    var ul = $("leadTiers");
    [["gov", "from government agencies and CERTs"], ["vendor", "from security vendors' research"], ["news", "from security news"]].forEach(function (t) {
      ul.appendChild(el("li", null, ((L.by_tier || {})[t[0]] || 0) + " " + t[1]));
    });
    (L.failed_feeds || []).forEach(function (f) { ul.appendChild(el("li", "warnline", "Not loading: " + f)); });
    var runs = $("runs");
    if (!(o.runs || []).length) runs.appendChild(el("li", "muted", "No runs logged in the last 7 days."));
    (o.runs || []).slice(0, 14).forEach(function (r) {
      var li = el("li");
      li.appendChild(el("span", "when", ago(r.at)));
      li.appendChild(el("strong", null, " " + r.job));
      li.appendChild(document.createTextNode(": " + r.added + " added, " + r.updated + " updated" + (r.failed ? ", " + r.failed + " source(s) failed" : "")));
      runs.appendChild(li);
    });
  }
})();
