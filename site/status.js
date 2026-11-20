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
    lim(h.last_sweep_at, 45, "Research run (every 15 minutes)");
    lim(h.last_collect_at, 120, "Feeds collected");
    lim(h.last_feeds_at, 360, "Vulnerability feeds synced");
    // power grid context layer: collection age, open incidents on the map, last cause research (context, not cyber events)
    if (h.last_grid_at !== undefined) {
      var gv = mins(h.last_grid_at), gOk = isFinite(gv) && gv <= 120, gn = typeof h.grid_open === "number" && isFinite(h.grid_open) ? Math.max(0, Math.round(h.grid_open)) : null;
      row(gOk, "Power grid outages collected " + (h.last_grid_at ? ago(h.last_grid_at) : "not yet") + (h.last_grid_at && !gOk ? " (expected within 2 h)" : "") +
        (gn !== null ? "; " + gn + " open incident" + (gn === 1 ? "" : "s") + " on the map" : "") +
        "; causes last checked " + (h.last_grid_research_at && isFinite(mins(h.last_grid_research_at)) ? ago(h.last_grid_research_at) : "not yet") + " (context, not cyber events)");
      // the later grid stages, each with its own limit (ops-6): the analysis and the news run every cycle
      if (h.grid_analysis_at !== undefined) lim(h.grid_analysis_at, 60, "Power grid analysis (no AI model) ran");
      if (h.last_grid_news_at !== undefined) lim(h.last_grid_news_at, 60, "Power outages in the news collected");
      var gw = h.grid_waiting && typeof h.grid_waiting === "object" ? h.grid_waiting : null;
      if (gw && typeof gw.count === "number" && isFinite(gw.count)) {
        var gc = Math.max(0, Math.round(gw.count)), go = typeof gw.oldest_min === "number" && isFinite(gw.oldest_min) ? Math.max(0, Math.round(gw.oldest_min)) : 0;
        row(!(gc && go > 120), "Grid outages waiting for a cause check: " + gc + (gc ? "; oldest " + (go >= 120 ? Math.round(go / 60) + " h" : go + " min") : "") + (gc && go > 120 ? " (expected within 2 h)" : ""));
      }
      var gf = Array.isArray(h.grid_audit_flags) ? h.grid_audit_flags.filter(function (f) { return typeof f === "string" && /^[a-z0-9_]{1,40}$/.test(f); }).slice(0, 10) : null;
      if (gf) row(!gf.length, gf.length ? "Grid data audit (no AI model) flags: " + gf.map(function (f) { return f.replace(/_/g, " "); }).join(", ") : "Grid data audit (no AI model): no pipeline flags");
    }
    try { gridSources(h.grid_sources); } catch (e) {}
    var bl = h.backlog;
    if (bl && typeof bl.waiting === "number") row(bl.waiting <= 60 && !(bl.oldest_incident_hours > 2), "Research queue: " + bl.waiting + " report" + (bl.waiting === 1 ? "" : "s") + " waiting for a decision" + (bl.incidents ? ", " + bl.incidents + " that read like incidents" : "") + (bl.waiting ? "; oldest " + bl.oldest_hours + " h" : "") + (bl.waiting > 60 ? " (expected under 60)" : ""));
    var q = typeof h.quarantined_count === "number" ? h.quarantined_count : 0;
    row(q === 0, q === 0 ? "Every record passed validation" : q + " record" + (q === 1 ? "" : "s") + " failed validation and " + (q === 1 ? "is" : "are") + " left out until fixed");
    if (m && m.counts) row(true, "Published: " + m.counts.events_total + " events on file, " + m.counts.events_bundle + " in the seven-day map, " + m.counts.kev_total + " known-exploited flaws" + (typeof m.commit === "string" && m.commit ? " (build " + m.commit.slice(0, 7) + ")" : ""));
  });

  // one row per grid source, every source health.json lists (grid_sources, from data/grid/live.json and analysis.json;
  // ops-7): failing ones first, then by country. Names come from the data; GRID_SRC only adds a description for the
  // first sources. A keyed source with no key saved reads "not connected" and is shown neutral, not as a fault.
  var GRID_SRC = { hydroquebec: ["Hydro-Québec", "outages in Quebec"], bchydro: ["BC Hydro", "outages in British Columbia"], ukpn: ["UK Power Networks", "faults in London, the South East and East of England"],
    eskom: ["Eskom", "load shedding in South Africa"], ercot: ["ERCOT", "grid conditions in Texas"], aemo: ["AEMO", "market notices in Australia"],
    eia: ["EIA", "US electricity demand (needs a key)"], cfradar: ["Cloudflare Radar", "internet outages with a power cause (needs a key)"], entsoe: ["ENTSO-E", "generation and transmission outages in Europe (needs a key)"] };
  var FLAG_WORDS = { failing_over_24h: "failing for over a day", stale_data: "the operator's data is old", dormant: "the feed has published nothing for weeks",
    suddenly_empty: "suddenly empty", surge: "ten times more items than usual", customers_missing: "items without customer counts", zero_customers: "no customers in any item",
    customers_fell: "customer total fell sharply", locations_suspect: "locations far from the country", future_times: "start times in the future", duplicate_ids: "duplicate ids", links_off_host: "links off the operator's site" };
  function gridSources(gs) {
    if (!gs || typeof gs !== "object") return;
    var ul = $("gridSources"); ul.textContent = "";
    var rows = Object.keys(gs).filter(function (k) { return /^[a-z0-9_-]{1,40}$/.test(k) && gs[k] && typeof gs[k] === "object"; }).slice(0, 200).map(function (k) {
      var x = gs[k], err = String(x.error || "").slice(0, 120), nc = !x.ok && /^not connected/i.test(err);
      var flags = Array.isArray(x.flags) ? x.flags.filter(function (f) { return typeof f === "string" && Object.prototype.hasOwnProperty.call(FLAG_WORDS, f); }).slice(0, 4) : [];
      var st = x.paused === true ? ["neutral", "Paused", 3] : nc ? ["neutral", "Not connected", 4] : x.ok !== true ? ["warn", "Not loading", 0]
        : x.dormant === true ? ["warn", "Dormant", 1] : x.stale === true ? ["warn", "Stale data", 1] : flags.length ? ["warn", "Check", 2] : ["ok", "Working", 5];
      return { k: k, x: x, err: err, nc: nc, flags: flags, st: st, cc: /^[A-Z]{2}$/.test(String(x.country || "")) ? x.country : "" };
    });
    rows.sort(function (a, b) { return a.st[2] - b.st[2] || (a.cc < b.cc ? -1 : a.cc > b.cc ? 1 : 0) || (a.k < b.k ? -1 : 1); });
    rows.forEach(function (r) {
      var d = Object.prototype.hasOwnProperty.call(GRID_SRC, r.k) ? GRID_SRC[r.k] : null, name = String(r.x.name || "").slice(0, 60).trim() || (d ? d[0] : r.k);
      var at = typeof r.x.at === "string" ? r.x.at.slice(0, 30) : "", li = el("li");
      li.appendChild(el("span", "badge " + r.st[0], r.st[1]));
      li.appendChild(document.createTextNode(" " + name + (d ? ": " + d[1] : r.cc ? " (" + r.cc + ")" : "") + (r.nc ? " · no key saved" : r.x.ok !== true && r.err ? " · " + r.err : (r.x.stale || r.x.dormant) && r.err ? " · " + r.err : "") +
        (r.flags.length ? " · " + r.flags.map(function (f) { return FLAG_WORDS[f]; }).join(", ") : "") + (at && isFinite(Date.parse(at)) ? " · checked " + ago(at) : "")));
      li.dataset.src = r.k; ul.appendChild(li);
    });
    $("gridSrcBox").hidden = false;
  }
  function renderSpeed(s) {
    if (!s || typeof s !== "object" || !s.publish) return;
    var v = function (x) { return typeof x === "number" && isFinite(x) ? Math.round(x) + " min" : "not measured"; }, p = s.publish || {}, r = s.review || {};
    $("speedSum").textContent = "Speed, last " + (typeof s.hours === "number" ? s.hours : 24) + " hours (" + (typeof s.n === "number" ? s.n : 0) + " events): from the first report collected to the event on the map, half took under " + v(p.p50) + " and nine in ten under " + v(p.p90) +
      "; to the second review, half under " + v(r.p50) + " and nine in ten under " + v(r.p90) + ". The target is under 15 minutes for both.";
  }
  function renderImprove(m) {
    if (!m || typeof m !== "object") return;
    var num = function (v, d) { return typeof v === "number" && isFinite(v) ? v : d; };
    if (m.at) {
      var rv = m.review || {}, g = m.guard || {};
      $("impSum").textContent = "Last " + num(m.days, 7) + " days: " + num(m.events_added, 0) + " events added" + (typeof m.cost_usd === "number" ? "; worker cost $" + m.cost_usd.toFixed(2) : "") + (typeof m.cost_per_event === "number" ? " ($" + m.cost_per_event.toFixed(2) + " per event)" : "") +
        (typeof rv.rate === "number" ? "; the second review corrected or flagged " + Math.round(rv.rate * 100) + "% of " + num(rv.reviewed, 0) + " checked" : "") + "." + (g.blocked ? " Quality guard on: " + String(g.why || "").slice(0, 200) + "." : "");
    }
    var tb = $("impRoles").querySelector("tbody"); tb.textContent = "";
    Object.keys(m.roles || {}).slice(0, 30).forEach(function (k) { var r = m.roles[k] || {}, tr = el("tr");
      [String(k).slice(0, 40), String(r.model || "").slice(0, 12), String(num(r.runs, 0)), Math.round(num(r.ok_rate, 0) * 100) + "%" + (r.timeouts ? " (" + r.timeouts + " timed out)" : ""), "$" + num(r.cost_per_run, 0).toFixed(3), String(num(r.turns_per_run, 0))].forEach(function (v) { tr.appendChild(el("td", null, v)); });
      tb.appendChild(tr); });
    var ul = $("impChanges"); ul.textContent = "";
    (Array.isArray(m.changes) ? m.changes : []).slice(0, 10).forEach(function (c) { var li = el("li");
      li.appendChild(el("strong", null, String(c.key || "").slice(0, 80) + ": " + String(c.from).slice(0, 20) + " to " + String(c.to).slice(0, 20)));
      li.appendChild(document.createTextNode(" · " + (c.at ? ago(c.at) : "") + " · " + String(c.reason || "").slice(0, 300))); ul.appendChild(li); });
    if (!ul.children.length) ul.appendChild(el("li", null, "None yet."));
  }
  function render(o) {
    try { renderImprove(o.improve); } catch (e) {}
    try { renderSpeed(o.speed); } catch (e) {}
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
