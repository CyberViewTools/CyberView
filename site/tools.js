// CyberView Tools: My software. The visitor's software list is read, matched and kept in this browser only
// (localStorage "cwm.inv", the same key the Vulnerabilities page reads to rank its queue); nothing is sent anywhere.
// Matching uses workbench-lib.js unchanged, so this page, the Vulnerabilities page and the downloadable scanner judge a
// software list the same way. Every record from data/workbench.json passes a clean function with length limits, and
// everything is drawn with textContent (no HTML sinks).
(function () {
  "use strict";
  var W = window.CVWorkbench;
  function $(id) { return document.getElementById(id); }
  function el(tag, cls, text) { var n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = String(text); return n; }
  function str(v, n) { return typeof v === "string" ? v.slice(0, n) : ""; }
  function strs(a, k, n) { return (Array.isArray(a) ? a : []).map(function (x) { return str(x, n).trim(); }).filter(Boolean).slice(0, k); }
  function isCve(s) { return /^CVE-\d{4}-\d{4,}$/.test(s || ""); }
  function lsGet(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
  function lsSet(k, v) { try { localStorage.setItem(k, v); return true; } catch (e) { return false; } }
  function safe(fn) {
    try { fn(); var old = document.querySelector("#tlInv > .fault"); if (old) old.remove(); }
    catch (e) {
      var p = $("tlInv"); if (!p) return;
      var n = p.querySelector(":scope > .fault"); if (!n) { n = el("p", "caveat fault", "This part of the page could not be drawn. Reload the page; if it keeps happening, report it from the About page."); p.insertBefore(n, p.firstChild); }
    }
  }

  /* the flaws a list is matched against: CISA's known-exploited entries with their version ranges, then recent high-risk
     flaws named by product only (the same two lists, cleaned the same way, as the Vulnerabilities page) */
  function cleanKev(k) {
    if (!k || typeof k !== "object" || !isCve(k.cve)) return null;
    return { cve: k.cve, kev: true, vendor: str(k.vendor, 80), product: str(k.product, 120), name: str(k.name, 200),
      affected: (Array.isArray(k.affected) ? k.affected : []).slice(0, 60).map(W.cleanRange).filter(Boolean) };
  }
  function cleanVuln(v) {
    if (!v || typeof v !== "object" || !isCve(v.cve)) return null;
    var prods = strs(v.products, 6, 60);
    return { cve: v.cve, kev: false, vendor: str(v.vendor, 80), product: prods.join(", "), name: str(v.title, 160),
      affected: prods.map(function (p) { return { vendor: str(v.vendor, 60), product: p, from: "", to: "", exact: "", nameOnly: true }; }) };
  }

  var flaws = [], inv = [], loaded = false;
  function loadInv() {
    try { var a = JSON.parse(lsGet("cwm.inv") || "[]"); inv = (Array.isArray(a) ? a : []).slice(0, W.MAX_ITEMS).map(function (x) {
      return x && typeof x === "object" && str(x.name, 120) ? { name: str(x.name, 120).replace(/[<>]/g, ""), vendor: str(x.vendor, 80).replace(/[<>]/g, ""), version: /^[\w.+\-~:]{1,40}$/.test(x.version || "") ? x.version : "", count: Math.max(1, Math.round(+x.count) || 1) } : null; }).filter(Boolean); } catch (e) { inv = []; }
  }
  function saveInv() { return lsSet("cwm.inv", JSON.stringify(inv)); }

  var STATE = { affected: ["Affected", "bad"], check: ["Check version", "warn"], clear: ["Fixed version", "ok"] };
  function render() { safe(draw); }
  function draw() {
    $("tlCount").textContent = inv.length ? String(inv.length) : "";
    var t = $("wbInvTable"); t.textContent = "";
    if (!inv.length) { $("wbInvHead").textContent = "Nothing loaded yet"; return; }
    var hit = {};
    flaws.forEach(function (f) { var m = W.matchFlaw(f, inv); if (m) m.items.forEach(function (h) { var k = h.name + "|" + h.version; (hit[k] = hit[k] || []).push({ cve: f.cve, state: h.state }); }); });
    var order = { affected: 0, check: 1, clear: 2, none: 3 }, list = inv.map(function (it) { var h = hit[it.name + "|" + it.version] || []; var worst = h.reduce(function (w, x) { return order[x.state] < order[w] ? x.state : w; }, "none"); return { it: it, h: h, worst: worst }; })
      .sort(function (a, b) { return order[a.worst] - order[b.worst] || a.it.name.localeCompare(b.it.name); });
    var nAff = list.filter(function (x) { return x.worst === "affected"; }).length, noVer = inv.filter(function (x) { return !x.version; }).length;
    $("wbInvHead").textContent = inv.length + " products on your list · " + (loaded ? nAff + " with an affected version" : "exploited flaws still loading") + (noVer ? " · " + noVer + " without a version (matched by name only)" : "");
    var hr = el("tr"); ["Product", "Version", "Devices", "Exploited flaws"].forEach(function (h) { hr.appendChild(el("th", null, h)); }); var th = el("thead"); th.appendChild(hr); t.appendChild(th);
    var tb = el("tbody");
    list.slice(0, 400).forEach(function (x) {
      var tr = el("tr"); tr.appendChild(el("td", null, (x.it.vendor ? x.it.vendor + " " : "") + x.it.name)); tr.appendChild(el("td", "nowrap", x.it.version || "none given")); tr.appendChild(el("td", null, x.it.count));
      var td = el("td");
      if (!x.h.length) td.appendChild(el("span", "note", loaded ? "none on file" : "loading"));
      // each flaw opens on the Vulnerabilities page, which reads the same list from this browser
      x.h.slice(0, 6).forEach(function (h) { var a = el("a", "badge " + STATE[h.state][1], h.cve + " · " + STATE[h.state][0]); a.href = "vulnerabilities.html#" + h.cve; td.appendChild(a); td.appendChild(document.createTextNode(" ")); });
      if (x.h.length > 6) td.appendChild(el("span", "note", "and " + (x.h.length - 6) + " more"));
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
    $("wbText").value = ""; render();
  }
  function readFile(f) {
    if (!f) return; if (f.size > 8e6) { $("wbInvMsg").textContent = "That file is over 8 MB. Export just the product, version and count columns."; return; }
    var fr = new FileReader(); fr.onload = function () { addItems(f.name, String(fr.result || "")); }; fr.onerror = function () { $("wbInvMsg").textContent = "The file could not be read."; }; fr.readAsText(f);
  }

  var drop = $("wbDrop"), file = $("wbFile");
  drop.addEventListener("click", function () { file.click(); });
  drop.addEventListener("keydown", function (ev) { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); file.click(); } });
  file.addEventListener("change", function () { readFile(file.files && file.files[0]); file.value = ""; });
  ["dragenter", "dragover"].forEach(function (n) { drop.addEventListener(n, function (ev) { ev.preventDefault(); drop.classList.add("over"); }); });
  ["dragleave", "drop"].forEach(function (n) { drop.addEventListener(n, function (ev) { ev.preventDefault(); drop.classList.remove("over"); }); });
  drop.addEventListener("drop", function (ev) { readFile(ev.dataTransfer && ev.dataTransfer.files && ev.dataTransfer.files[0]); });
  $("wbAdd").addEventListener("click", function () { var t = $("wbText").value; if (!t.trim()) { $("wbInvMsg").textContent = "Type or paste at least one product first."; return; } addItems("pasted", t); });
  $("wbClear").addEventListener("click", function () { inv = []; saveInv(); try { localStorage.removeItem("cwm.inv"); } catch (e) {} $("wbInvMsg").textContent = "Your list is cleared from this browser."; render(); });
  /* the list changed in another tab (for example on the Vulnerabilities page's calendar): show the current one */
  window.addEventListener("storage", function (ev) { if (ev.key === "cwm.inv" || ev.key === null) { loadInv(); render(); } });

  loadInv(); render();
  fetch("data/workbench.json", { cache: "no-cache" }).then(function (r) { if (!r.ok) throw new Error(); return r.json(); }).then(function (d) {
    flaws = (Array.isArray(d && d.kev) ? d.kev : []).slice(0, 3000).map(cleanKev).filter(Boolean)
      .concat((Array.isArray(d && d.vulns) ? d.vulns : []).slice(0, 80).map(cleanVuln).filter(Boolean));
    loaded = true; render();
  }).catch(function () {
    $("wbInvMsg").textContent = "The exploited-flaw data can't be loaded right now, so your list is shown without matches. Try again in a minute.";
  });
})();
