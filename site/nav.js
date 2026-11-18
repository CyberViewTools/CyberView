// Site navigation for every page: inline links on wide screens; on narrow screens a menu button opens a sheet.
// Esc, a click outside or choosing a link closes it; focus moves into the sheet and back to the button.
(function () {
  "use strict";
  // offline copy (sw.js): if the site cannot be reached, the last good pages and data are shown instead of an error
  try { if ("serviceWorker" in navigator && /^https:$|^http:$/.test(location.protocol)) navigator.serviceWorker.register("sw.js").catch(function () {}); } catch (e) {}
  var btn = document.getElementById("navBtn"), sheet = document.getElementById("navSheet");
  if (!btn || !sheet) return;
  function set(open) {
    sheet.hidden = !open;
    btn.setAttribute("aria-expanded", open ? "true" : "false");
    btn.setAttribute("aria-label", open ? "Close menu" : "Open menu");
    document.body.classList.toggle("nav-open", open);
    if (open) { var f = sheet.querySelector(".sheetnav a"); if (f) f.focus(); }
  }
  btn.addEventListener("click", function (ev) { ev.stopPropagation(); set(sheet.hidden); });
  var close = document.getElementById("navClose");
  if (close) close.addEventListener("click", function () { set(false); btn.focus(); });
  document.addEventListener("keydown", function (ev) { if (ev.key === "Escape" && !sheet.hidden) { set(false); btn.focus(); } });
  document.addEventListener("click", function (ev) { if (!sheet.hidden && !sheet.contains(ev.target) && !btn.contains(ev.target)) set(false); });
  Array.prototype.forEach.call(sheet.querySelectorAll("a"), function (a) { a.addEventListener("click", function () { set(false); }); });
  window.addEventListener("resize", function () { if (!sheet.hidden && window.innerWidth > 760) set(false); });
})();
