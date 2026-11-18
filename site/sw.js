// CyberView offline copy. The network always comes first, so visitors get the newest data whenever the site answers.
// If the site cannot be reached (an outage at the host, a dropped connection), the last good copy of each page and
// data file is served instead, and the page says how old the data is. Same-origin GET requests only; nothing else is touched.
"use strict";
var CACHE = "cyberview-v1";
self.addEventListener("install", function () { self.skipWaiting(); });
self.addEventListener("activate", function (ev) {
  ev.waitUntil(caches.keys().then(function (keys) { return Promise.all(keys.filter(function (k) { return k !== CACHE; }).map(function (k) { return caches.delete(k); })); }).then(function () { return self.clients.claim(); }));
});
// one stored copy per file: the cache-busting "t" parameter is left out of the key
function keyOf(req) { var u = new URL(req.url); u.searchParams.delete("t"); u.hash = ""; return u.toString(); }
function timeout(ms) { return new Promise(function (_, no) { setTimeout(function () { no(new Error("timeout")); }, ms); }); }
self.addEventListener("fetch", function (ev) {
  var req = ev.request, url = new URL(req.url);
  if (req.method !== "GET" || url.origin !== self.location.origin) return;
  var key = keyOf(req);
  ev.respondWith(
    Promise.race([fetch(req), timeout(12000)]).then(function (res) {
      // keep only complete, successful answers from this site
      if (res && res.status === 200 && res.type === "basic") { var copy = res.clone(); caches.open(CACHE).then(function (c) { return c.put(key, copy); }).catch(function () {}); }
      return res;
    }).catch(function () {
      return caches.open(CACHE).then(function (c) { return c.match(key); }).then(function (hit) { if (hit) return hit; throw new Error("offline and no stored copy"); });
    })
  );
});
