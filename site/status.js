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
  function L0(o) { return (o.leads && Array.isArray(o.leads.failed_feeds) ? o.leads.failed_feeds : []); }
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
    if (hr === "*") return min.indexOf(",") > 0 ? "every 30 min" : "hourly at :" + pad(min);
    var every = hr.match(/^\*\/(\d+)$/); if (every) return "every " + every[1] + " h at :" + pad(min);
    return days + hr.split(",").map(function (h) { return pad(h) + ":" + pad(min); }).join(" and ");
  }
  function state(r) {
    if (!r.active) return { cls: "wait", text: "Paused" };
    if (!r.status_key) return { cls: "info", text: "See GitHub runs", link: /^[a-z0-9-]+\.yml$/.test(String(r.workflow)) ? REPO + "/actions/workflows/" + r.workflow : "" };
    if (!r.last_at) {
      var since = r.active_since ? (Date.now() - Date.parse(r.active_since)) / 36e5 : Infinity;
      return since <= r.max_age_hours ? { cls: "info", text: "Waiting for first run" } : { cls: "bad", text: "No run recorded" };
    }
    var h = (Date.now() - Date.parse(r.last_at)) / 36e5;
    if (h <= r.max_age_hours) return { cls: "ok", text: "On time" };
    if (h <= 2 * r.max_age_hours) return { cls: "warn", text: "Late" };
    return { cls: "bad", text: "Stopped" };
  }

  fetch("data/ops.json", { cache: "no-cache" }).then(function (r) { if (!r.ok) throw new Error(); return r.json(); }).then(render)
    .catch(function () { $("summary").textContent = "Status can't be loaded right now. Try again in a minute."; });

  // pipeline health: data age, last runs, and anything the build left out (site/data/health.json and manifest.json)
  Promise.all(["health.json", "manifest.json"].map(function (f) { return fetch("data/" + f + "?t=" + Date.now(), { cache: "no-store" }).then(function (r) { return r.ok ? r.json() : null; }).catch(function () { return null; }); })).then(function (a) {
    var h = a[0], m = a[1], ul = $("health"); ul.textContent = "";
    function row(ok, text) { var li = el("li"); li.appendChild(el("span", "badge " + (ok ? "ok" : "warn"), ok ? "OK" : "Check")); li.appendChild(document.createTextNode(" " + text)); ul.appendChild(li); }
    if (!h) { row(false, "The health record can't be loaded right now."); return; }
    var mins = function (iso) { return (Date.now() - Date.parse(iso)) / 6e4; }, lim = function (iso, max, label) { var v = mins(iso); row(isFinite(v) && v <= max, label + " " + (iso ? ago(iso) : "has not run yet") + (isFinite(v) && v > max ? " (expected within " + (max >= 120 ? Math.round(max / 60) + " h" : max + " min") + ")" : "")); };
    lim(h.built_at, 90, "Site data rebuilt");
    lim(h.last_sweep_at, 150, "Research sweep ran");
    lim(h.last_collect_at, 120, "Feeds collected");
    lim(h.last_feeds_at, 360, "Vulnerability feeds synced");
    var bl = h.backlog;
    if (bl && typeof bl.waiting === "number") row(bl.waiting <= 150 && !(bl.oldest_incident_hours > 12), "Research queue: " + bl.waiting + " report" + (bl.waiting === 1 ? "" : "s") + " waiting for a decision" + (bl.incidents ? ", " + bl.incidents + " that read like incidents" : "") + (bl.waiting ? "; oldest " + bl.oldest_hours + " h" : "") + (bl.waiting > 150 ? " (expected under 150)" : ""));
    var q = typeof h.quarantined_count === "number" ? h.quarantined_count : 0;
    row(q === 0, q === 0 ? "Every record passed validation" : q + " record" + (q === 1 ? "" : "s") + " failed validation and " + (q === 1 ? "is" : "are") + " left out until fixed");
    if (m && m.counts) row(true, "Published: " + m.counts.events_total + " events on file, " + m.counts.events_bundle + " in the seven-day map, " + m.counts.kev_total + " known-exploited flaws" + (typeof m.commit === "string" && m.commit ? " (build " + m.commit.slice(0, 7) + ")" : ""));
  });

  function render(o) {
    var body = $("routines").querySelector("tbody"), counts = { ok: 0, active: 0 };
    (o.routines || []).forEach(function (r) {
      var s = state(r), tr = el("tr");
      if (r.active) { counts.active++; if (s.cls === "ok" || s.cls === "info") counts.ok++; }
      var name = el("td"); name.appendChild(el("strong", null, String(r.name))); name.appendChild(el("span", "sub", r.does)); tr.appendChild(name);
      tr.appendChild(el("td", "nowrap", when(r.cron)));
      tr.appendChild(el("td", "nowrap", r.model ? (MODEL[r.model] || r.model) : "none (script)"));
      tr.appendChild(el("td", "nowrap", r.last_at ? ago(r.last_at) : "—"));
      var st = el("td"), b = el("span", "badge " + s.cls, s.text);
      if (s.link) { var a = el("a", "badge " + s.cls, s.text); a.href = safeUrl(s.link); a.target = "_blank"; a.rel = "noopener noreferrer"; st.appendChild(a); } else st.appendChild(b);
      tr.appendChild(st); body.appendChild(tr);
    });
    $("summary").textContent = counts.ok + " of " + counts.active + " active routines are on time. Data built " + ago(o.built_at) + ".";
    var P = o.pipeline || {}, S = P.stories || {}, WHAT = { rss: "RSS and Atom feeds of agencies, vendors and news", "google-news": "Google News, standing searches in 12 languages", "bing-news": "Bing News, standing searches", gdelt: "GDELT global news index", hibp: "Have I Been Pwned breach database",
      euvd: "ENISA EU Vulnerability Database (exploited)", nvd: "NIST NVD, new critical CVEs", "ransomware-live": "Leak-site listings (attacker claims)", "hacker-news": "Hacker News discussion", "cloud-status": "Cloud providers' status pages" };
    if (P.leads_7d != null) $("pipe").textContent = (P.feeds ? P.feeds + " feeds and " : "") + ((o.sources || []).length) + " other collectors. Last 7 days: " + P.leads_7d + " leads, " + P.events_7d + " events" + (P.median_hours != null ? ", median " + P.median_hours + " h from first lead to the map" : "") + ". " +
      (S.open != null ? S.open + " stories waiting, " + S.corroborated + " of them reported by two or more publishers." : "");
    var stb = $("sources").querySelector("tbody"), col = {}; (P.collectors || []).forEach(function (c) { if (c && typeof c.name === "string") col[c.name] = c; });
    var rows = [{ name: "rss", ok: !(L0(o).length), error: L0(o).length ? L0(o).length + " feed(s) not loading" : "", at: "" }].concat(o.sources || []);
    rows.slice(0, 20).forEach(function (x) {
      var name = String(x.name || "").slice(0, 30), c = col[name] || {}, tr = el("tr");
      tr.appendChild(el("td", null, name)); tr.appendChild(el("td", null, WHAT[name] || ""));
      tr.appendChild(el("td", "nowrap", x.at ? ago(x.at) : name === "rss" ? "every 30 min" : ""));
      var td = el("td"); td.appendChild(el("span", "badge " + (x.ok ? "ok" : "warn"), x.ok ? "Working" : "Not loading")); if (!x.ok && x.error) td.appendChild(el("span", "note", " " + String(x.error).slice(0, 90))); tr.appendChild(td);
      tr.appendChild(el("td", null, c.leads != null ? c.leads : "")); tr.appendChild(el("td", null, c.used != null ? c.used : ""));
      stb.appendChild(tr);
    });
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
