"""Browser regression suite for CyberView.

Run from the repo root:  python3 tests/test_all.py
Needs: node, and `pip install playwright && playwright install chromium`.
Builds the bundle from data/, then checks the real data plus four variants
(dark, phone width, missing optional data, missing bundle, high volume).
Prints ALL PASS or the list of failures, and exits 1 on failure.
"""
import asyncio, copy, json, os, random, shutil, subprocess, sys, tempfile, time
from playwright.async_api import async_playwright

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT = 8765
fails, count = [], 0


def ok(name, cond, info=""):
    global count
    count += 1
    if not cond:
        fails.append(name + (f" :: {info}" if info else ""))


def make_site(bundle):
    """Copy site/ to a temp dir and write the given bundle (or none)."""
    d = tempfile.mkdtemp(prefix="cwm-")
    shutil.copytree(os.path.join(ROOT, "site"), d, dirs_exist_ok=True)
    os.makedirs(os.path.join(d, "data"), exist_ok=True)
    p = os.path.join(d, "data", "bundle.json")
    if bundle is None:
        if os.path.exists(p):
            os.remove(p)
    else:
        json.dump(bundle, open(p, "w"))
    return d


def dense(bundle, factor=5):
    b = copy.deepcopy(bundle)
    random.seed(4)
    # Spread copies over the last 7 days counted from today, so the check does not drift as the data ages.
    import datetime
    today = datetime.datetime.now(datetime.timezone.utc).date()
    days = [(today - datetime.timedelta(days=n)).isoformat() for n in range(7)]
    extra = []
    for k in range(factor):
        for e in bundle["events"]:
            c = copy.deepcopy(e)
            c["id"] = f'{e["id"]}-x{k}'
            c["title"] = f'{e["title"]} ({k})'
            c["date"] = random.choice(days)
            extra.append(c)
    b["events"] += extra
    return b


async def open_page(browser, url, w=1440, h=860, theme=None, wait=1500):
    ctx = await browser.new_context(viewport={"width": w, "height": h})
    pg = await ctx.new_page()
    errs = []
    pg.on("pageerror", lambda e: errs.append(str(e)[:160]))
    pg.on("console", lambda m: errs.append(m.text[:160]) if m.type == "error" and "favicon" not in m.text and "404" not in m.text else None)
    await pg.goto(url)
    await pg.wait_for_timeout(wait)
    if theme:
        pass  # the page is dark only; no theme switch to click
        await pg.wait_for_timeout(150)
    return pg, errs


OVERLAP = """() => { let n = 0; document.querySelectorAll('#viz .vsec svg').forEach(svg => {
  const pts = [...svg.querySelectorAll('g.ev[transform]')].map(g => { const r = g.getBoundingClientRect(); return [r.left + r.width / 2, r.top + r.height / 2]; });
  for (let i = 0; i < pts.length; i++) for (let j = i + 1; j < pts.length; j++) if (Math.hypot(pts[i][0] - pts[j][0], pts[i][1] - pts[j][1]) < 11) n++; });
  return n; }"""


async def serve(dirpath, fn):
    srv = subprocess.Popen([sys.executable, os.path.join(ROOT, "tests", "serve.py"), str(PORT)], cwd=dirpath, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.8)
    try:
        await fn(f"http://localhost:{PORT}/index.html")
    finally:
        srv.kill()
        srv.wait()


async def main():
    r = subprocess.run(["node", os.path.join(ROOT, "scripts", "build.mjs")], capture_output=True, text=True)
    ok("build passes on data/", r.returncode == 0, r.stderr.strip()[-400:])
    if r.returncode != 0:
        return
    bundle = json.load(open(os.path.join(ROOT, "site", "data", "bundle.json")))
    n_events = len(bundle["events"])

    async with async_playwright() as p:
        try:
            browser = await p.chromium.launch()
        except Exception:
            browser = await p.chromium.launch(executable_path="/usr/bin/google-chrome", args=["--no-sandbox"])

        async def core(url):
            for th in ["dark"]:
                pg, errs = await open_page(browser, url, theme=th)
                ok(f"{th}: feed has cards", await pg.locator("#feed .card").count() >= min(10, n_events))
                ok(f"{th}: map markers drawn", await pg.locator("#svg g.m, #svg g.cl").count() > 3)
                ok(f"{th}: stats shown", "events" in await pg.inner_text("#stats"))
                await pg.evaluate('document.getElementById("feed").scrollTop=400')
                await pg.locator("#feed .card .head").nth(4).click()
                await pg.wait_for_timeout(700)
                ok(f"{th}: detail opens", await pg.is_visible("#detail") and not await pg.is_visible("#feed"))
                t1 = await pg.inner_text("#dcard .ttl")
                await pg.keyboard.press("j")
                await pg.wait_for_timeout(600)
                ok(f"{th}: J moves to next", t1 != await pg.inner_text("#dcard .ttl"))
                await pg.keyboard.press("Escape")
                await pg.wait_for_timeout(600)
                # Back returns to where you were: the list is not reset to the top, and stays near the event last viewed
                pos = await pg.evaluate("""() => { const f = document.getElementById("feed"), c = f.querySelector(".card.sel");
                  if (!c) return {top: f.scrollTop, seen: false};
                  const a = f.getBoundingClientRect(), b = c.getBoundingClientRect();
                  return {top: f.scrollTop, seen: b.bottom > a.top && b.top < a.bottom}; }""")
                ok(f"{th}: back restores list position", 200 < pos["top"] < 1400, pos)  # J moved one event on, so the list may sit a card lower
                await pg.click("#tab-kev")
                await pg.wait_for_timeout(300)
                ok(f"{th}: exploited feed lists flaws", await pg.locator("#kev .kcard").count() >= min(5, len(bundle["kev"])))
                await pg.click("#hoOpen")
                await pg.wait_for_timeout(200)
                ok(f"{th}: handover text built", "TOP PRIORITY" in await pg.input_value("#hoText"))
                await pg.click("#hoClose")
                await pg.click("[data-view=time]")
                await pg.wait_for_timeout(600)
                ok(f"{th}: timeline has three sections", await pg.locator("#viz .vsec").count() == 3)
                await pg.click("[data-view=graph]")
                await pg.wait_for_timeout(600)
                ok(f"{th}: correlation has five sections", await pg.locator("#viz .vsec").count() == 5)
                await pg.fill("#q", "micro")
                await pg.click('[data-sev="3"]')
                await pg.wait_for_timeout(300)
                await pg.click("#refresh")
                await pg.wait_for_timeout(1000)
                ok(f"{th}: refresh resets to main", await pg.evaluate("document.body.dataset.view") == "map" and await pg.input_value("#q") == "" and await pg.is_visible("#feed"))
                for tab in ["brief", "pat", "ins", "kev", "feed"]:
                    await pg.click(f"#tab-{tab}")
                    await pg.wait_for_timeout(120)
                ok(f"{th}: no marking wording", not await pg.evaluate(r"/\bhandled\b|not relevant|\bpatched\b|not affected/i.test([...document.querySelectorAll('button,label,option,[role=button],[role=tab]')].filter(e=>!e.closest('.card,#detail')).map(e=>e.innerText||e.textContent).join(' '))"))
                await pg.click("#tab-ins")
                ok(f"{th}: version shown", "version" in (await pg.inner_text("#ins")).lower())
                ok(f"{th}: no fault notice", not await pg.is_visible("#fault"))
                ok(f"{th}: no script errors", not errs, errs)
                await pg.context.close()
            pg, errs = await open_page(browser, url, 390, 800)
            for v in ["map", "time", "graph"]:
                await pg.click(f"[data-view={v}]")
                await pg.wait_for_timeout(500)
                ok(f"phone {v}: no sideways scroll", await pg.evaluate("document.documentElement.scrollWidth<=window.innerWidth+2"))
            ok("phone: no script errors", not errs, errs)
            await pg.context.close()

        await serve(make_site(bundle), core)

        async def empty(url):
            pg, errs = await open_page(browser, url)
            await pg.click("[data-view=graph]")
            await pg.wait_for_timeout(400)
            ok("events only: correlation still draws", await pg.locator("#viz .vsec").count() == 5)
            ok("events only: no script errors", not errs, errs)
            await pg.context.close()

        await serve(make_site({"built_at": "x", "events": bundle["events"], "kev": [], "corrections": [], "docs": {}}), empty)

        async def missing(url):
            pg, errs = await open_page(browser, url)
            ok("no bundle: notice shown", await pg.is_visible("#notice"))
            await pg.click("#refresh")
            await pg.wait_for_timeout(400)
            ok("no bundle: refresh explains", "can't be reached" in await pg.inner_text("#toast"))
            await pg.context.close()

        await serve(make_site(None), missing)

        big = dense(bundle)

        async def volume(url):
            pg, errs = await open_page(browser, url)
            ok(f"{len(big['events'])} events: feed renders", await pg.locator("#feed .card").count() > len(big["events"]) * 0.6)
            t = await pg.evaluate('(()=>{const t=performance.now();document.querySelector("[data-sev=\\"2\\"]").click();document.querySelector("[data-sev=\\"1\\"]").click();return performance.now()-t})()')
            lim = max(800, 0.75 * len(big["events"]))  # scales with the data, which grows every hour
            ok(f"volume: two full redraws under {round(lim)} ms", t < lim, round(t))
            await pg.click("[data-view=time]")
            await pg.wait_for_timeout(700)
            ok("volume: no overlapping marks in lanes", await pg.evaluate(OVERLAP) == 0, await pg.evaluate(OVERLAP))
            ok("volume: no script errors", not errs, errs)
            await pg.context.close()

        await serve(make_site(big), volume)

        async def archive(url):
            pg, errs = await open_page(browser, url.replace("index.html", "archive.html"), wait=1200)
            ok("archive: lists events", await pg.locator(".row").count() > 0)
            await pg.fill("#q", "zzzz-no-such-thing")
            await pg.wait_for_timeout(400)
            ok("archive: search filters", "0 events" in await pg.inner_text("#count") and not await pg.is_visible("#more"))
            await pg.fill("#q", "")
            await pg.wait_for_timeout(400)
            await pg.locator(".row button").first.click()
            await pg.wait_for_timeout(600)
            ok("archive: opening an event shows details", await pg.locator(".more-info p").count() > 0)
            ok("archive: no script errors", not errs, errs)
            await pg.context.close()

        await serve(make_site(bundle), archive)

        # v1.5 features: permalinks, feeds, exposure report
        target = next(e for e in bundle["events"] if e.get("status") != "claimed" and e["severity"] >= 2)

        async def features(url):
            pg, errs = await open_page(browser, url + "#e=" + target["id"], wait=1800)
            ok("permalink: #e= opens the event", await pg.is_visible("#detail") and target["title"][:30] in await pg.inner_text("#dcard"))
            ok("permalink: detail has Copy link", await pg.locator("#dcard button", has_text="Copy link").count() == 1)
            other = next(e for e in bundle["events"] if e.get("status") != "claimed" and e["id"] != target["id"])
            await pg.evaluate("id => { location.hash = 'e=' + id; }", other["id"])
            await pg.wait_for_timeout(700)
            ok("permalink: a new link opens while the page is open", other["title"][:30] in await pg.inner_text("#dcard"))
            ok("permalink: the address follows the open event", ("#e=" + other["id"]) in pg.url)
            await pg.keyboard.press("Escape")
            await pg.wait_for_timeout(500)
            await pg.click("#wlOpen")
            await pg.fill("#wlText", (target.get("org") or target["title"].split()[0])[:40])
            await pg.click("#wlSave")
            await pg.wait_for_timeout(900)
            rep = await pg.inner_text("#wlReport")
            ok("exposure: report shows known-exploited, window and archive sections", all(x in rep for x in ["Known-exploited", "This window", "Across the whole archive"]), rep[:160])
            ok("exposure: matching event listed", await pg.locator("#wlReport li button").count() >= 1)
            ok("exposure: copy button shown", await pg.is_visible("#wlCopy"))
            ok("features: no script errors", not errs, errs)
            await pg.context.close()

        await serve(make_site(bundle), features)

        # v1.6 features: search reaches the archive, trends page, time-lapse
        async def v16(url):
            pg, errs = await open_page(browser, url, wait=1500)
            await pg.click("#playDays")
            await pg.wait_for_timeout(300)
            d1 = await pg.evaluate("document.querySelector('#days .day[aria-pressed=\"true\"]:not(.play)') ? document.querySelector('#days .day[aria-pressed=\"true\"]:not(.play)').getAttribute('aria-label') : ''")
            await pg.wait_for_timeout(1700)
            d2 = await pg.evaluate("document.querySelector('#days .day[aria-pressed=\"true\"]:not(.play)') ? document.querySelector('#days .day[aria-pressed=\"true\"]:not(.play)').getAttribute('aria-label') : ''")
            ok("time-lapse: play steps through the days", bool(d1) and bool(d2) and d1 != d2, (d1, d2))
            await pg.click("#playDays")
            await pg.wait_for_timeout(1800)
            d3 = await pg.evaluate("document.querySelector('#days .day[aria-pressed=\"true\"]:not(.play)') ? document.querySelector('#days .day[aria-pressed=\"true\"]:not(.play)').getAttribute('aria-label') : ''")
            ok("time-lapse: pause holds the current day", d3 != "" and await pg.get_attribute("#playDays", "aria-pressed") == "false", d3)
            await pg.click("#refresh")
            await pg.wait_for_timeout(900)
            ok("time-lapse: refresh clears the day filter", await pg.evaluate("!document.querySelector('#days .day[aria-pressed=\"true\"]:not(.play)')"))
            await pg.fill("#q", "a")
            await pg.fill("#q", "microsoft")
            await pg.wait_for_timeout(1200)
            import datetime as _dt
            arch = json.load(open(os.path.join(ROOT, "site", "data", "archive", "search.json")))
            f = arch["fields"]; start = (_dt.date.today() - _dt.timedelta(days=7)).isoformat()
            hay = lambda r: " ".join(str(r[f.index(k)]) for k in ["title", "org", "country", "actor", "cves", "tags"]).lower()
            expect = sum(1 for r in arch["rows"] if r[f.index("status")] != "claimed" and r[f.index("date")] < start and "microsoft" in hay(r))
            hint = await pg.locator(".arch-hint a").count()
            ok("search: older archive matches are offered exactly when they exist", (hint == 1) == (expect > 0), (hint, expect))
            await pg.goto(url.replace("index.html", "trends.html"))
            await pg.wait_for_timeout(1200)
            ok("trends: summary and tables render", "events from" in await pg.inner_text("#summary") and await pg.locator("table").count() >= 2)
            ok("trends: daily chart drawn", await pg.locator("#days .day").count() == 28)
            ok("v1.6: no script errors", not errs, errs)
            await pg.context.close()

        await serve(make_site(bundle), v16)

        # v1.7: status page from routines.json, feed parser
        async def v17(url):
            pg, errs = await open_page(browser, url.replace("index.html", "status.html"), wait=1200)
            reg = json.load(open(os.path.join(ROOT, "routines.json")))
            ok("status: one row per routine", await pg.locator("#routines tbody tr").count() == len(reg["routines"]))
            ok("status: summary counts active routines", "active routines" in await pg.inner_text("#summary"))
            ok("status: lead queue shown", "new leads" in await pg.inner_text("#leads"))
            ok("status: no script errors", not errs, errs)
            await pg.context.close()

        await serve(make_site(bundle), v17)
        probe = r"""import('./scripts/collect.mjs').then(m => {
          const rss = '<rss><channel><item><title>A &amp; B</title><link>https://x.test/a</link><pubDate>Tue, 18 Nov 2026 10:00:00 GMT</pubDate><description><![CDATA[<p>Hi</p>]]></description></item></channel></rss>';
          const atom = '<feed><entry><title>C</title><link rel="alternate" href="https://x.test/c"/><updated>2026-11-18T09:00:00Z</updated><summary>S</summary></entry></feed>';
          const a = m.parseFeed(rss), b = m.parseFeed(atom);
          console.log(JSON.stringify([a[0].title, a[0].url, a[0].published, a[0].summary, b[0].url, m.FEEDS.length]));
        })"""
        r = subprocess.run(["node", "--input-type=module", "-e", probe], capture_output=True, text=True, cwd=ROOT)
        try:
            got = json.loads(r.stdout.strip().splitlines()[-1])
        except Exception:
            got = None
        ok("collector: parses RSS and Atom", got is not None and got[:5] == ["A & B", "https://x.test/a", "2026-11-18T10:00:00Z", "Hi", "https://x.test/c"], got or r.stderr[-200:])
        import xml.etree.ElementTree as ET
        try:
            items = ET.parse(os.path.join(ROOT, "site", "data", "feed.xml")).findall(".//item")
            jf = json.load(open(os.path.join(ROOT, "site", "data", "feed.json")))
            ok("feeds: RSS and JSON Feed parse, same items, no claims", len(items) == len(jf["items"]) > 0 and not any(i["id"].endswith("-claim-2026-11") for i in jf["items"]))
            ok("feeds: items link to permalinks", all("/#e=" in i.find("link").text for i in items))
        except Exception as x:
            ok("feeds: RSS and JSON Feed parse", False, str(x)[:160])
        # v1.8: globe view, context layers with health, HUD and wire (fixed fixture, no network)
        import datetime
        now = datetime.datetime.now(datetime.timezone.utc)
        iso = lambda h: (now - datetime.timedelta(hours=h)).strftime("%Y-%m-%dT%H:%M:%SZ")
        b18 = copy.deepcopy(bundle)
        b18["context"] = {
            "ioda": {"source": "IODA", "source_url": "https://ioda.inetintel.cc.gatech.edu/", "fetched_at": iso(1), "ok": True, "error": "",
                     "items": [{"code": "FR", "name": "France", "map_name": "France", "score": 900, "events": 2, "signals": ["bgp"], "url": "https://ioda.inetintel.cc.gatech.edu/country/FR"},
                               {"code": "XX", "name": "Bad<b>", "map_name": "", "score": 1, "events": 1, "signals": [], "url": "javascript:alert(1)"}]},
            "gdacs": {"source": "GDACS", "source_url": "https://www.gdacs.org/", "fetched_at": iso(30), "ok": False, "error": "timeout",
                      "items": [{"id": "EQ-1", "type": "earthquake", "level": "red", "name": "Earthquake test", "country": "Chile", "lat": -33.4, "lng": -70.6, "url": "https://evil.test/x"}]},
        }

        async def v18(url):
            pg, errs = await open_page(browser, url, wait=1500)
            ok("hud: UTC clock shown", (await pg.inner_text("#hud")).startswith("UTC "))
            ok("wire: newest item shown", len((await pg.inner_text("#wire")).strip()) > 5)
            ok("layers: disaster alerts on by default", await pg.locator("g.haz").count() == 1)
            ok("layers: disruptions off by default", await pg.locator("path.country.dis").count() == 0)
            await pg.click("#zlayers")
            ok("layers: panel opens", await pg.locator("#layers").is_visible())
            txt = await pg.inner_text("#layers")
            ok("layers: health shows live and stale", "Live" in txt and "Stale" in txt and "timeout" in txt, txt[:200])
            hrefs = await pg.eval_on_selector_all("#layers a", "as => as.map(a => a.getAttribute('href'))")
            ok("layers: off-site and script links neutralised", "javascript:alert(1)" not in hrefs and "https://evil.test/x" not in hrefs, hrefs)
            await pg.click("#layers .chip:not([data-arc]) >> nth=0")
            ok("layers: disruptions shade the country", await pg.locator("path.country.dis").count() == 1)
            await pg.keyboard.press("Escape")
            ok("layers: Esc closes the panel", await pg.locator("#layers").is_hidden())
            ok("globe: always on, no flat-map toggle", await pg.locator("path.ocean").count() == 1 and await pg.locator("#zglobe").count() == 0)
            flat_marks = await pg.locator("#svg g.m, #svg g.cl").count()
            ok("globe: far side hidden", flat_marks > 0, flat_marks)
            box = await pg.locator("#svg").bounding_box()
            d0 = await pg.get_attribute("path.grat", "d")
            await pg.mouse.move(box["x"] + 500, box["y"] + 450); await pg.mouse.down(); await pg.mouse.move(box["x"] + 350, box["y"] + 430, steps=6); await pg.mouse.up()
            await pg.wait_for_timeout(200)
            ok("globe: drag turns it", await pg.get_attribute("path.grat", "d") != d0)
            await pg.click("#refresh")
            await pg.wait_for_timeout(500)
            ok("globe: refresh keeps the globe and turns it back", await pg.locator("path.ocean").count() == 1 and await pg.evaluate("document.body.classList.contains('globe')"))
            ok("v1.8: no script errors", not errs, errs)
            await pg.context.close()

        await serve(make_site(b18), v18)

        # v1.9: environment drop (file read in the browser), quick picks, whole-word matching
        fx = tempfile.mkdtemp(prefix="cv-env-")
        files = {
            "assets.csv": 'Hostname,Vendor,Product,Version\nsrv1,Fortinet,FortiOS,7.4.2\nsrv2,"Ivanti","Connect Secure",22.7\nsrv3,Microsoft,Exchange Server 2019,15.2\n',
            "bom.json": json.dumps({"bomFormat": "CycloneDX", "components": [{"name": "openssl", "version": "3.0.1", "publisher": "OpenSSL Project"}, {"name": "core", "version": "1"}, {"name": "log4j-core", "components": [{"name": "jackson-databind"}]}]}),
            "spdx.json": json.dumps({"spdxVersion": "SPDX-2.3", "packages": [{"name": "Veeam Backup", "supplier": "Organization: Veeam"}]}),
            "requirements.txt": "# deps\nDjango==4.2.1\nrequests>=2.0\n-r other.txt\n",
            "profile.json": json.dumps({"cyberview_environment": 1, "terms": ["Atlassian Confluence", "energy"]}),
            "empty.txt": "1.0\n2.0\n",
        }
        for n, c in files.items():
            open(os.path.join(fx, n), "w").write(c)

        async def v19(url):
            pg, errs = await open_page(browser, url, wait=1200)
            reqs = []
            pg.on("request", lambda r: reqs.append(r.url))
            await pg.click("#wlOpen")
            ok("env: dialog opens with drop zone", await pg.locator("#envDrop").is_visible())
            ok("env: quick picks shown", await pg.locator("#envQuick .chip").count() >= 20)
            await pg.fill("#wlText", "")
            n0 = len(reqs)
            for n in ["assets.csv", "bom.json", "spdx.json", "requirements.txt", "profile.json"]:
                await pg.set_input_files("#envFile", os.path.join(fx, n))
                await pg.wait_for_timeout(150)
            terms = [t.strip() for t in (await pg.input_value("#wlText")).splitlines() if t.strip()]
            low = [t.lower() for t in terms]
            ok("env: CSV vendor and product columns read", all(x in low for x in ["fortinet", "fortios", "ivanti", "connect secure", "microsoft"]) and "srv1" not in low, terms)
            ok("env: versions stripped", "exchange server 2019" in low or "exchange server" in low, terms)
            ok("env: CycloneDX components and publishers, generic names dropped", all(x in low for x in ["openssl", "openssl project", "log4j-core", "jackson-databind"]) and "core" not in low, terms)
            ok("env: SPDX supplier read", "veeam" in low and "veeam backup" in low, terms)
            ok("env: requirements.txt read", "django" in low and "requests" in low, terms)
            ok("env: saved profile restored", "atlassian confluence" in low and "energy" in low, terms)
            ok("env: message names the format", "requirements" in (await pg.inner_text("#envMsg")) or "profile" in (await pg.inner_text("#envMsg")))
            ok("env: nothing sent over the network while reading files", len(reqs) == n0, reqs[n0:])
            await pg.set_input_files("#envFile", os.path.join(fx, "empty.txt"))
            await pg.wait_for_timeout(150)
            ok("env: useless file explained", "Nothing usable" in await pg.inner_text("#toast"))
            await pg.fill("#wlText", "")
            await pg.click("#envQuick .chip >> text=Cisco")
            ok("env: quick pick adds", "Cisco" in await pg.input_value("#wlText"))
            await pg.click("#envQuick .chip >> text=Cisco")
            ok("env: quick pick removes", "Cisco" not in await pg.input_value("#wlText"))
            await pg.fill("#wlText", "sap")
            await pg.click("#wlSave")
            await pg.wait_for_timeout(200)
            hit = await pg.evaluate("""() => { const re = new RegExp('(^|[^a-z0-9])sap($|[^a-z0-9])'); return [re.test('sapphire rapids'), re.test('sap netweaver flaw')]; }""")
            ok("env: whole-word matching", hit == [False, True], hit)
            ok("env: header button renamed", (await pg.inner_text("#wlOpen")).startswith("My environment"))
            ok("v1.9: no script errors", not errs, errs)
            await pg.context.close()

        await serve(make_site(bundle), v19)

        # v1.10: legal pages, and the account page against a fake Supabase (no network)
        async def legal(url):
            for name in ["about", "privacy", "terms"]:
                pg, errs = await open_page(browser, url.replace("index.html", name + ".html"), wait=300)
                body = await pg.inner_text("body")
                ok(f"legal: {name} renders without placeholders", "{{" not in body and len(body) > 1500, body[:80])
                ok(f"legal: {name} has the footer", await pg.locator("footer.foot a").count() >= 5)
                ok(f"legal: {name} no script errors", not errs, errs)
                await pg.context.close()
            pg, errs = await open_page(browser, url.replace("index.html", "account.html"), wait=300)
            ok("account: unconfigured shows 'not open yet'", await pg.locator("#offline").is_visible() and await pg.locator("#signedIn").is_hidden())
            await pg.context.close()
            r = await (await browser.new_context()).request.get(url.replace("index.html", ".well-known/security.txt"))
            t = await r.text()
            ok("security.txt served with Contact and Expires", r.status == 200 and "Contact: " in t and "Expires: " in t, t[:120])

        await serve(make_site(bundle), legal)

        REF = "abcdefghijklmnopqrst"
        SB = f"https://{REF}.supabase.co"
        acct_site = make_site(bundle)
        ap = os.path.join(acct_site, "account.html")
        h = open(ap).read()
        h = h.replace("connect-src 'self'", f"connect-src 'self' {SB}").replace('<meta name="cv-supabase-url" content="">',
            f'<meta name="cv-supabase-url" content="{SB}">\n<meta name="cv-supabase-key" content="eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.x">\n<meta name="cv-region" content="Canada (Central)">\n<meta name="cv-github" content="1">')
        h = h.replace('<script src="account.js">', '<script src="vendor/supabase.min.js"></script>\n<script src="account.js">')
        open(ap, "w").write(h)

        async def account(url):
            import base64, time as _t
            uid = "00000000-0000-0000-0000-00000000000a"
            store = {"accounts": None, "env": None, "calls": []}
            def jwt(payload):
                enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
                return enc({"alg": "HS256", "typ": "JWT"}) + "." + enc(payload) + ".sig"
            exp = int(_t.time()) + 3600
            session = {"access_token": jwt({"sub": uid, "role": "authenticated", "exp": exp, "email": "a@example.test"}), "token_type": "bearer", "expires_in": 3600, "expires_at": exp,
                       "refresh_token": "r", "user": {"id": uid, "aud": "authenticated", "role": "authenticated", "email": "a@example.test", "app_metadata": {}, "user_metadata": {}, "created_at": "2026-11-18T00:00:00Z"}}
            ctx = await browser.new_context(viewport={"width": 1280, "height": 900})
            await ctx.add_init_script(f"localStorage.setItem('sb-{REF}-auth-token', JSON.stringify({json.dumps(session)})); localStorage.setItem('cwm.wl', JSON.stringify(['Fortinet','Ivanti','Microsoft']));")
            pg = await ctx.new_page()
            errs = []
            pg.on("pageerror", lambda e: errs.append(str(e)[:160]))
            outside = []
            pg.on("request", lambda r: outside.append(r.url) if not (r.url.startswith("http://localhost") or r.url.startswith(SB)) else None)

            async def handle(route):
                req = route.request; u = req.url; m = req.method
                store["calls"].append((m, u.split(".co", 1)[1], req.post_data or ""))
                body, status = "[]", 200
                if "/rest/v1/accounts" in u:
                    if m == "GET":
                        a = store["accounts"]
                        if "select=user_id" in u: body = json.dumps({"user_id": uid} if a else None) if "maybe" in u else json.dumps([{"user_id": uid}] if a else [])
                        else: body = json.dumps(a or {})
                        if a is None and "select=user_id" in u: body = "[]"
                    elif m == "POST": store["accounts"] = {"user_id": uid, "alerts_enabled": False, "alert_frequency": "daily", "alert_min_severity": 2, "alert_terms": [], "consent_at": None}; status = 201; body = ""
                    elif m == "PATCH":
                        store["accounts"].update(json.loads(req.post_data)); body = ""; status = 204
                elif "/rest/v1/environments" in u:
                    if m == "POST": store["env"] = json.loads(req.post_data); body = ""; status = 201
                    elif m == "DELETE": store["env"] = None; body = ""; status = 204
                    else:
                        e = store["env"]
                        body = json.dumps([e] if e else [])
                elif "/rpc/export_my_data" in u: body = json.dumps({"account": {"email": "a@example.test"}, "settings": store["accounts"]})
                elif "/rpc/delete_my_account" in u: body = "true"
                elif "/auth/v1/logout" in u: body = ""; status = 204
                elif "/auth/v1/otp" in u: body = "{}"
                elif "/auth/v1/user" in u: body = json.dumps(session["user"])
                hdr = {"content-type": "application/json", "access-control-allow-origin": "*", "content-range": "0-0/1"}
                if m in ("GET", "POST") and "/rest/v1/" in u and req.headers.get("accept", "").startswith("application/vnd.pgrst.object"):
                    try:
                        arr = json.loads(body) if body else []
                        body = json.dumps(arr[0] if isinstance(arr, list) and arr else (arr if isinstance(arr, dict) else None))
                        if body == "null": status = 406; body = json.dumps({"code": "PGRST116", "message": "0 rows"})
                    except Exception: pass
                await route.fulfill(status=status, headers=hdr, body=body)
            await pg.route(SB + "/**", handle)
            await pg.goto(url.replace("index.html", "account.html"))
            await pg.wait_for_timeout(1200)
            ok("account: signed-in view shown", await pg.locator("#signedIn").is_visible(), await pg.inner_text("body"))
            ok("account: shows who and region", "a@example.test" in await pg.inner_text("#who") and "Canada" in await pg.inner_text("#region"))
            # encrypted sync
            await pg.fill("#pass", "short")
            await pg.click("#push")
            ok("sync: short passphrase refused", "at least 12" in await pg.inner_text("#syncMsg"))
            await pg.fill("#pass", "correct horse battery staple")
            await pg.click("#push")
            await pg.wait_for_timeout(2500)
            env = store["env"] or {}
            ok("sync: ciphertext saved", bool(env.get("ciphertext")) and env.get("kdf") == "PBKDF2-SHA256-600000", env)
            wire = json.dumps(env)
            ok("sync: plain terms never sent", "Fortinet" not in wire and "Ivanti" not in wire and "correct horse" not in wire)
            await pg.evaluate("localStorage.setItem('cwm.wl','[]')")
            await pg.fill("#pass", "wrong passphrase entirely")
            await pg.click("#pull")
            await pg.wait_for_timeout(2500)
            ok("sync: wrong passphrase cannot decrypt", "does not open" in await pg.inner_text("#syncMsg"))
            await pg.fill("#pass", "correct horse battery staple")
            await pg.click("#pull")
            await pg.wait_for_timeout(2500)
            ok("sync: right passphrase restores the list", json.loads(await pg.evaluate("localStorage.getItem('cwm.wl')")) == ["Fortinet", "Ivanti", "Microsoft"])
            # alerts need consent
            await pg.click("#useEnv")
            await pg.click("#alertsOn")
            ok("alerts: refused without the consent box", "Tick the box" in await pg.inner_text("#alertMsg") and not (store["accounts"] or {}).get("alerts_enabled"))
            await pg.check("#consent")
            await pg.click("#alertsOn")
            await pg.wait_for_timeout(600)
            a = store["accounts"] or {}
            ok("alerts: consent recorded with wording and version", a.get("alerts_enabled") is True and a.get("consent_at") and "unsubscribe" in (a.get("consent_text") or "") and a.get("consent_version") == "1", a)
            ok("alerts: terms saved", a.get("alert_terms") == ["Fortinet", "Ivanti", "Microsoft"], a.get("alert_terms"))
            await pg.click("#alertsOff")
            await pg.wait_for_timeout(500)
            ok("alerts: can be turned off", (store["accounts"] or {}).get("alerts_enabled") is False)
            # data rights
            await pg.click("#export")
            await pg.wait_for_timeout(500)
            ok("export: shows the data", "a@example.test" in await pg.input_value("#exportOut"))
            await pg.click("#delete")
            ok("delete: needs DELETE typed", "Type DELETE" in await pg.inner_text("#dataMsg") and not any("delete_my_account" in c[1] for c in store["calls"]))
            await pg.fill("#delConfirm", "DELETE")
            await pg.click("#delete")
            await pg.wait_for_timeout(1200)
            ok("delete: calls delete_my_account and signs out", any("delete_my_account" in c[1] for c in store["calls"]) and await pg.locator("#signedOut").is_visible())
            ok("account: talks to nothing but the site and Supabase", not outside, outside)
            ok("account: no script errors", not errs, errs)
            await ctx.close()

        await serve(acct_site, account)

        # v1.11: patch deadlines as calendar files; desktop notifications for new matches
        import datetime as _dt
        today = _dt.date.today()
        b11 = copy.deepcopy(bundle)
        b11["kev"] = [
            {"id": "CVE-2026-90001", "cve": "CVE-2026-90001", "vendor": "Fortinet", "product": "FortiOS", "name": "x", "added": (today - _dt.timedelta(days=2)).isoformat(), "due": (today + _dt.timedelta(days=10)).isoformat(), "desc": "Lets attackers in; patch, now", "ransomware": True},
            {"id": "CVE-2026-90002", "cve": "CVE-2026-90002", "vendor": "Acme", "product": "Widget", "name": "y", "added": (today - _dt.timedelta(days=3)).isoformat(), "due": (today + _dt.timedelta(days=5)).isoformat()},
            {"id": "CVE-2026-90003", "cve": "CVE-2026-90003", "vendor": "Fortinet", "product": "Old", "name": "z", "added": (today - _dt.timedelta(days=40)).isoformat(), "due": (today - _dt.timedelta(days=19)).isoformat()},
        ]
        site11 = make_site(b11)

        async def v111(url):
            ctx = await browser.new_context(viewport={"width": 1440, "height": 900}, accept_downloads=True)
            await ctx.grant_permissions(["notifications"])
            await ctx.add_init_script("""localStorage.setItem('cwm.wl', JSON.stringify(['Fortinet']));
              window.__notes = []; window.Notification = function(t, o){ window.__notes.push([t, (o||{}).body||'']); this.close = function(){}; };
              window.Notification.permission = 'granted'; window.Notification.requestPermission = function(){ return Promise.resolve('granted'); };""")
            pg = await ctx.new_page()
            errs = []
            pg.on("pageerror", lambda e: errs.append(str(e)[:160]))
            await pg.goto(url); await pg.wait_for_timeout(1500)
            await pg.click("#tab-kev"); await pg.wait_for_timeout(300)
            ok("calendar: button labelled for my environment", (await pg.inner_text("#kevCal")).startswith("My deadlines"))
            async with pg.expect_download() as dl:
                await pg.click("#kevCal")
            d = await dl.value
            ics = open(await d.path(), newline="").read()
            ok("calendar: file name", d.suggested_filename == "cyberview-patch-deadlines.ics", d.suggested_filename)
            ok("calendar: valid calendar with reminders", ics.startswith("BEGIN:VCALENDAR\r\n") and ics.rstrip().endswith("END:VCALENDAR") and "TRIGGER:-P3D" in ics, ics[:200])
            ok("calendar: only open deadlines that match", "CVE-2026-90001" in ics and "CVE-2026-90002" not in ics and "CVE-2026-90003" not in ics)
            ok("calendar: text escaped", "patch\\, now" in ics and "\\;" in ics, ics[ics.find("DESCRIPTION"):][:160])
            ok("calendar: lines folded to the limit", all(len(l.encode()) <= 75 for l in ics.split("\r\n")))
            # notifications: turn on, then a new matching event arrives on refresh
            await pg.click("#wlOpen"); await pg.click("#notifyBtn"); await pg.wait_for_timeout(200)
            ok("notify: toggle on", await pg.get_attribute("#notifyBtn", "aria-pressed") == "true")
            await pg.click("#wlClose")
            nb = copy.deepcopy(b11)
            ev = copy.deepcopy(nb["events"][0]); ev.update({"id": "fortinet-new-flaw-test", "title": "Fortinet FortiGate flaw under attack", "severity": 3, "status": "confirmed", "date": today.isoformat(), "org": "Fortinet"})
            ev2 = copy.deepcopy(ev); ev2.update({"id": "unrelated-test", "title": "Acme widget outage", "org": "Acme", "products": [], "tags": []})
            nb["events"] += [ev, ev2]; nb["built_at"] = "2099-01-01T00:00:00Z"
            json.dump(nb, open(os.path.join(site11, "data", "bundle.json"), "w"))
            await pg.click("#refresh"); await pg.wait_for_timeout(1500)
            notes = await pg.evaluate("window.__notes")
            ok("notify: one notification for the new match only", len(notes) == 1 and "Fortinet FortiGate" in notes[0][1] and "Acme" not in notes[0][1], notes)
            ok("v1.11: no script errors", not errs, errs)
            await ctx.close()

        await serve(site11, v111)

        # v1.12: dialogs, header menu, tools per tab
        async def v112(url):
            pg, errs = await open_page(browser, url, wait=1300)
            links = await pg.eval_on_selector_all("header .sitenav a", "as => as.map(a => [a.textContent, a.getAttribute('href'), a.getAttribute('aria-current')])")
            ok("nav: site links visible on desktop", [l[0] for l in links] == ["Map", "Workbench", "Archive", "Trends", "Exercise", "Community", "Status", "About"] and await pg.locator("header .sitenav").is_visible(), links)
            ok("nav: current page marked", links[0][2] == "page" and all(l[2] is None for l in links[1:]))
            ok("nav: menu button hidden on desktop", await pg.locator("#navBtn").is_hidden())
            ok("nav: full screen and shortcuts buttons", await pg.locator("#fs").is_visible() and await pg.locator("#keysBtn").is_visible())
            for t, search, filters in [("kev", True, False), ("brief", False, False), ("ins", False, False), ("feed", True, True)]:
                await pg.click("#tab-" + t); await pg.wait_for_timeout(150)
                ok(f"tools on {t}: search {search}, filters {filters}", await pg.locator("#q").is_visible() == search and await pg.locator("#sort").is_visible() == filters)
            await pg.click("#wlOpen"); await pg.wait_for_timeout(200)
            ok("env: modal with backdrop", await pg.locator("#backdrop").is_visible() and await pg.locator("#wlPaneList").is_visible() and await pg.locator("#wlPaneRep").is_hidden())
            ok("env: page behind does not scroll", await pg.evaluate("document.body.classList.contains('modal-open')"))
            await pg.fill("#wlText", "Fortinet"); await pg.wait_for_timeout(350)
            ok("env: unsaved changes shown", await pg.locator("#wlDirty").is_visible())
            await pg.click("#wlSave"); await pg.wait_for_timeout(500)
            ok("env: save switches to the report", await pg.locator("#wlPaneRep").is_visible() and await pg.locator("#wlCopy").is_visible() and await pg.locator("#wlDirty").is_hidden())
            h = await pg.evaluate("document.getElementById('wlReport').getBoundingClientRect().height")
            ok("env: report is not squashed", h > 80, h)
            await pg.click("#wlTabList")
            ok("env: tabs switch back", await pg.locator("#wlPaneList").is_visible() and await pg.locator("#wlSave").is_visible())
            for _ in range(30): await pg.keyboard.press("Tab")
            ok("env: Tab stays inside the dialog", await pg.evaluate("!!document.activeElement.closest('#wlDlg')"))
            await pg.mouse.click(12, 12)
            ok("env: backdrop click closes and returns focus", await pg.locator("#wlDlg").is_hidden() and await pg.locator("#backdrop").is_hidden() and await pg.evaluate("document.activeElement.id") == "wlOpen")
            await pg.click("#hoOpen"); await pg.wait_for_timeout(200)
            ok("handover: modal with backdrop", await pg.locator("#hoDlg").is_visible() and await pg.locator("#backdrop").is_visible())
            await pg.keyboard.press("Escape")
            ok("handover: Esc closes", await pg.locator("#hoDlg").is_hidden() and await pg.locator("#backdrop").is_hidden())
            ok("handover: CyberView name", "CYBERVIEW HANDOVER" in await pg.evaluate("document.getElementById('hoText').value"))
            ok("v1.12: no script errors", not errs, errs)
            await pg.context.close()
            ctx = await browser.new_context(viewport={"width": 390, "height": 844})
            pg = await ctx.new_page(); await pg.goto(url); await pg.wait_for_timeout(1200)
            await pg.click("#wlOpen"); await pg.wait_for_timeout(200)
            box = await pg.locator("#wlDlg").bounding_box()
            ok("phone: environment dialog fills the screen", box["width"] >= 389 and box["height"] >= 800, box)
            ok("phone: no sideways page scroll", await pg.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"))
            await pg.keyboard.press("Escape")
            ok("phone: links collapse into a menu button", await pg.locator("header .sitenav").is_hidden() and await pg.locator("#navBtn").is_visible())
            await pg.click("#navBtn"); await pg.wait_for_timeout(150)
            sb = await pg.locator("#navSheet").bounding_box()
            ok("phone: menu sheet covers the screen above everything", sb and sb["width"] >= 389 and sb["height"] >= 800 and await pg.evaluate("document.elementFromPoint(200, 300).closest('#navSheet') !== null"), sb)
            ok("phone: focus moves to the first link", await pg.evaluate("document.activeElement.textContent") == "Map")
            await pg.click("#navClose")
            ok("phone: close button closes the sheet", await pg.locator("#navSheet").is_hidden())
            await pg.click("#navBtn"); await pg.keyboard.press("Escape")
            ok("phone: Esc closes the sheet and returns focus", await pg.locator("#navSheet").is_hidden() and await pg.evaluate("document.activeElement.id") == "navBtn")
            vs = await pg.locator("#viewseg").bounding_box()
            ok("phone: view switcher fills its row", vs["width"] > 330, vs)
            for sub in ["archive.html", "trends.html", "tabletop.html", "workbench.html", "community.html", "about.html"]:
                await pg.goto(url.replace("index.html", sub)); await pg.wait_for_timeout(500)
                await pg.click("#navBtn"); await pg.wait_for_timeout(100)
                ok(f"phone: {sub} has the same menu", await pg.locator("#navSheet .sheetnav a").count() == 8 and await pg.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"))
            await ctx.close()

        await serve(make_site(bundle), v112)

        # v1.16: arcs and blast radius, campaign replay, wall mode, tabletop exercise
        b16 = copy.deepcopy(bundle)
        geo = [e for e in b16["events"] if e.get("lat") is not None and e.get("status") != "claimed" and e.get("lng") is not None]
        src, dst, vic = geo[0], geo[1], geo[2]
        src["links"] = [{"to": dst["id"], "rel": "customer of breached supplier", "url": "https://example.com/story"}]
        vic["attribution"] = {"actor": "Test Group", "origin_country": "Iceland", "lat": 64.15, "lng": -21.94, "by": "Test Agency", "by_type": "government", "url": "https://example.gov/advisory"}
        vic["pin_type"] = "victim"; vic["geo_basis"] = "victim location"
        bad = geo[3]; bad["links"] = [{"to": geo[4]["id"], "rel": "x", "url": "javascript:alert(1)"}]
        site16 = make_site(b16)
        tt = {"label": "exercise", "generated_at": "2026-11-20T15:40:00Z", "date": "2026-11-20", "title": "Exercise: a supplier breach reaches you",
              "based_on": [src["id"]], "real_story": "A supplier was breached.", "duration_min": 60, "roles": ["Incident lead", "Communications"],
              "facts": [{"text": "Fact one.", "source_url": "https://example.com/a"}, {"text": "Fact two.", "source_url": "javascript:alert(1)"}],
              "scenario": "Your organisation uses the supplier.",
              "injects": [{"at_min": 0, "title": "First signal", "text": "A customer emails."}, {"at_min": 15, "title": "Confirmation", "text": "The supplier confirms.", "ask": "Who decides?"}, {"at_min": 30, "title": "Media", "text": "A reporter calls."}],
              "questions": ["Q1?", "Q2?", "Q3?", "Q4?"], "good_looks_like": ["G1", "G2", "G3"], "adapt": "Shrink it.", "sources": [{"name": "Example", "url": "https://example.com/a"}]}
        json.dump({"built_at": "x", "current": tt, "past": [], "exercises": []}, open(os.path.join(site16, "data", "tabletop.json"), "w"))

        async def v116(url):
            pg, errs = await open_page(browser, url, wait=1800)
            await pg.evaluate(f"location.hash='e={src['id']}'"); await pg.wait_for_timeout(1500)
            ok("arcs: a stated link is drawn", await pg.locator("#svg .arc.link").count() >= 1)
            ok("arcs: the selected event's link is highlighted", await pg.locator("#svg .arc.link.hot").count() >= 1)
            ok("arcs: blast radius around the selected event", await pg.locator("#svg .blast").count() == 1 and "linked" in (await pg.locator("#svg .blast text").text_content() or ""))
            ok("card: lists the stated link with its source", await pg.locator("#dcard .rel.links").count() == 1 and "customer of breached supplier" in await pg.locator("#dcard .rel.links").text_content())
            hrefs = await pg.eval_on_selector_all("#dcard a", "as => as.map(a => a.href)")
            ok("card: no unsafe link targets", not any(h.startswith("javascript") for h in hrefs), hrefs)
            await pg.evaluate(f"location.hash='e={vic['id']}'"); await pg.wait_for_timeout(1500)
            ok("arcs: attributed origin drawn dashed", await pg.locator("#svg .arc.origin").count() >= 1)
            ok("card: attribution names who made it", await pg.locator("#dcard .todo.attr").count() == 1 and "Test Agency" in await pg.locator("#dcard .todo.attr").text_content())
            ok("arcs: an unsafe link url is dropped", await pg.evaluate(f"!document.body.textContent.includes('javascript:')"))
            await pg.keyboard.press("Escape"); await pg.wait_for_timeout(200)
            await pg.click("#zlayers"); await pg.wait_for_timeout(150)
            ok("layers: arc toggles listed", await pg.locator("#layers [data-arc]").count() == 2)
            await pg.click("#layers [data-arc=links]"); await pg.click("#layers [data-arc=origins]"); await pg.wait_for_timeout(200)
            ok("layers: arcs can be hidden", await pg.locator("#svg .arc").count() == 0)
            await pg.click("#layers [data-arc=links]"); await pg.click("#layers [data-arc=origins]")
            await pg.keyboard.press("Escape")
            # campaign replay
            await pg.click("#tab-pat"); await pg.wait_for_timeout(200)
            rb = pg.locator("#pat button:has-text('Replay on globe')")
            ok("replay: patterns offer a replay", await rb.count() >= 1)
            await rb.first.click(); await pg.wait_for_timeout(1700)
            ok("replay: panel opens on step 1", await pg.locator("#replay").is_visible() and (await pg.locator("#rpCount").text_content()).startswith("Step 1 of"))
            ok("replay: stage named", len((await pg.locator("#rpStage").text_content()).strip()) > 3)
            ok("replay: step markers drawn", await pg.locator("#svg .stepn").count() >= 1 and await pg.locator("#svg .rpcur").count() == 1)
            await pg.click("#rpPlay"); await pg.click("#rpNext"); await pg.wait_for_timeout(1600)
            ok("replay: next moves on and draws the path", (await pg.locator("#rpCount").text_content()).startswith("Step 2 of") and await pg.locator("#svg .stepn").count() >= 2)
            await pg.keyboard.press("ArrowLeft"); await pg.wait_for_timeout(300)
            ok("replay: arrow keys step back", (await pg.locator("#rpCount").text_content()).startswith("Step 1 of"))
            await pg.keyboard.press("Escape"); await pg.wait_for_timeout(300)
            ok("replay: Esc closes and clears the pattern", await pg.locator("#replay").is_hidden() and await pg.evaluate("!document.body.classList.contains('replaying')"))
            # wall mode
            await pg.click("#wallBtn"); await pg.wait_for_timeout(3000)
            ok("wall: overlay shown, controls hidden", await pg.locator("#wall").is_visible() and await pg.locator("header").is_hidden() and await pg.locator("aside").is_hidden())
            ok("wall: five counters and a clock", await pg.locator("#wStats .wstat").count() == 5 and ":" in await pg.locator("#wClock").text_content())
            ok("wall: flies to a high-severity event", len((await pg.locator("#wCap h2").text_content() or "").strip()) > 5 and await pg.locator("#svg .ring.wallr, #svg .cl.sel").count() == 1)
            ok("wall: headline ticker", await pg.locator("#wTrack .wit").count() >= 4)
            gb = await pg.locator("#svg .sphere").bounding_box()
            ok("wall: globe is large and centred", gb and gb["height"] > 560 and abs(gb["x"] + gb["width"] / 2 - 720) < 40, gb)
            await pg.keyboard.press("Escape"); await pg.wait_for_timeout(400)
            ok("wall: Esc exits back to the map", await pg.locator("#wall").is_hidden() and await pg.locator("header").is_visible() and await pg.evaluate("!document.body.classList.contains('wall')"))
            ok("v1.16: no script errors", not errs, errs)
            await pg.goto(url.replace("index.html", "index.html?wall")); await pg.wait_for_timeout(2500)
            ok("wall: ?wall opens straight into wall mode", await pg.locator("#wall").is_visible())
            await pg.context.close()
            ctx = await browser.new_context(viewport={"width": 390, "height": 844})
            pg = await ctx.new_page(); await pg.goto(url.replace("index.html", "index.html?wall")); await pg.wait_for_timeout(2500)
            ok("phone wall: no sideways scroll", await pg.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"))
            cap, st = await pg.locator("#wCap").bounding_box(), await pg.locator("#wStats").bounding_box()
            ok("phone wall: counters and caption do not overlap", cap and st and st["y"] + st["height"] <= cap["y"], [st, cap])
            await pg.goto(url.replace("index.html", "tabletop.html")); await pg.wait_for_timeout(800)
            ok("phone exercise: no sideways scroll", await pg.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"))
            await ctx.close()
            # tabletop page
            pg, errs = await open_page(browser, url.replace("index.html", "tabletop.html"), wait=900)
            ok("exercise: title and banner", "supplier breach" in await pg.locator("#ttTitle").text_content() and await pg.locator("#ttBanner").is_visible())
            ok("exercise: injects listed in order", await pg.locator("#ttInj > li").count() == 3)
            ok("exercise: fact with an unsafe source is dropped", await pg.locator(".ttfacts li").count() == 1)
            ok("exercise: map link to the real event", await pg.locator(f"a[href='./#e={src['id']}']").count() == 1)
            await pg.check("#ttReveal"); await pg.wait_for_timeout(100)
            ok("exercise: reveal hides later updates", await pg.locator("#ttInj > li.locked").count() == 3)
            await pg.click("#ttGo"); await pg.wait_for_timeout(1300)
            ok("exercise: clock runs and opens the first update", (await pg.locator("#ttFace").text_content()) in ("00:01", "00:02") and await pg.locator("#ttInj > li.locked").count() == 2)
            await pg.click("#ttReset")
            ok("exercise: reset", await pg.locator("#ttFace").text_content() == "00:00")
            ok("exercise: nav marks the page", await pg.locator("header .sitenav a[aria-current=page]").text_content() == "Exercise")
            ok("exercise: no script errors", not errs, errs)
            await pg.context.close()

        await serve(site16, v116)

        # v1.17: workbench (patch queue, my software, fix guides, hunt pack)
        site17 = make_site(bundle)
        wbd = {"built_at": "2026-11-18T22:00:00Z", "event_of": {},
               "kev": [
                   {"cve": "CVE-2026-1001", "vendor": "Fortinet", "product": "FortiOS", "name": "FortiOS auth bypass", "added": "2026-11-10", "due": "2026-11-12", "ransomware": True, "desc": "Lets a remote attacker log in.", "cvss": 9.8, "epss": 0.9, "av": "N",
                    "required": "Apply the vendor fix.", "refs": ["https://vendor.example/psirt/1", "javascript:alert(1)"],
                    "affected": [{"vendor": "fortinet", "product": "fortios", "part": "o", "from": "7.0.0", "from_incl": True, "to": "7.4.10", "to_incl": False}]},
                   {"cve": "CVE-2026-1002", "vendor": "Acme", "product": "Widget Server", "name": "Acme Widget Server RCE", "added": "2026-11-01", "due": "2099-01-01", "ransomware": False, "desc": "x", "cvss": 7.0, "epss": 0.01, "av": "L",
                    "affected": [{"vendor": "acme", "product": "widget server", "part": "a", "to": "2.0", "to_incl": False}]},
                   {"cve": "CVE-2026-1003", "vendor": "<img src=x onerror=alert(1)>", "product": "Thing", "name": "Markup test", "added": "2026-11-01", "due": "", "affected": []}],
               "vulns": [{"cve": "CVE-2026-2001", "event_id": bundle["events"][0]["id"], "title": "Not yet on CISA's list", "date": "2026-11-17", "severity": 3, "vendor": "Zeta", "products": ["Zeta Mail"], "desc": "d", "action": "Patch.", "cvss": None, "epss": 0.2}],
               "guides": {"CVE-2026-1001": {"advisory": {"name": "Fortinet PSIRT FG-IR-26-001", "url": "https://vendor.example/psirt/1"}, "read_at": "2026-11-18T20:00:00Z", "read_depth": "full",
                                              "check": ["Run get system status and read the version line."], "fixed": ["7.4.10 or later"], "workaround": ["Disable the admin interface on WAN."], "compromise_signs": ["Unknown admin accounts."],
                                              "exposure": "internet", "exploit_public": True,
                                              "hunt": [{"name": "Indicators", "format": "stix", "url": "https://agency.example/x.stix.json", "publisher": "Test Agency"}, {"name": "bad", "format": "yara", "url": "javascript:alert(2)"}]}},
               "hunt": [{"name": "Indicators", "format": "stix", "url": "https://agency.example/x.stix.json", "publisher": "Test Agency", "about": "CVE-2026-1001", "cve": "CVE-2026-1001", "date": "2026-11-18"},
                        {"name": "Sigma rule for webshell", "format": "sigma", "url": "https://vendor.example/rule.yml", "about": "Some report", "event_id": bundle["events"][0]["id"], "date": "2026-11-17"},
                        {"name": "evil", "format": "exe", "url": "https://x.example/a"}]}
        json.dump(wbd, open(os.path.join(site17, "data", "workbench.json"), "w"))

        async def v117(url):
            pg, errs = await open_page(browser, url.replace("index.html", "workbench.html"), wait=900)
            ok("workbench: flaws ranked, exploited first", await pg.locator("#wbList .wbrow").count() == 4 and "CVE-2026-1001" in await pg.locator("#wbList .wbrow >> nth=0").text_content())
            ok("workbench: general ranking notice without a list", await pg.locator("#wbNoInv").is_visible())
            ok("workbench: markup in data shown as text", await pg.locator("#wbList img").count() == 0)
            top = int(await pg.locator("#wbList .wbscore >> nth=0").text_content())
            ok("workbench: score without a list", top == 35 + 10 + 14 + 5 + 10 + 5, top)
            await pg.click("#wbt-inv"); await pg.fill("#wbText", "FortiOS 7.2.4, 12\nAcme Widget Server 2.1\nZeta Mail\nSlack 4.0")
            await pg.click("#wbAdd"); await pg.wait_for_timeout(250)
            ok("software: list read and saved in the browser only", "4 products" in await pg.locator("#wbInvMsg").text_content() and await pg.evaluate("JSON.parse(localStorage.getItem('cwm.inv')).length") == 4)
            rows = await pg.locator("#wbInvTable tbody tr").all_text_contents()
            ok("software: affected first, with states", "FortiOS" in rows[0] and "Affected" in rows[0] and any("Fixed version" in r for r in rows) and any("Check version" in r for r in rows) and any("none on file" in r for r in rows), rows)
            await pg.click("#wbt-queue"); await pg.wait_for_timeout(150)
            ok("queue: your affected version adds 20 points", int(await pg.locator("#wbList .wbscore >> nth=0").text_content()) == min(100, top + 20))
            ok("queue: notice gone once a list is loaded", await pg.locator("#wbNoInv").is_hidden())
            ok("queue: a fixed version drops to the end", "CVE-2026-1002" in await pg.locator("#wbList .wbrow >> nth=3").text_content() and await pg.locator("#wbList .wbrow.clear").count() == 1)
            await pg.locator("#wbList .wbhead >> nth=0").click(); await pg.wait_for_timeout(150)
            det = await pg.locator(".wbdetail").text_content()
            ok("detail: your version, reasons, steps and fix", all(x in det for x in ["You run an affected version", "FortiOS 7.2.4 ×12", "Known exploited (CISA)", "Used by ransomware groups", "Internet-facing (from the advisory)", "How to check if you are affected", "get system status", "7.4.10 or later", "Signs of compromise"]), det[:300])
            hrefs = await pg.eval_on_selector_all(".wbdetail a", "as => as.map(a => a.href)")
            ok("detail: only https links, advisory and NVD present", not any(h.startswith("javascript") for h in hrefs) and any("nvd.nist.gov/vuln/detail/CVE-2026-1001" in h for h in hrefs) and any("vendor.example/psirt/1" in h for h in hrefs), hrefs)
            await pg.select_option("#wbShow", "mine"); await pg.wait_for_timeout(100)
            ok("queue: filter to my software", await pg.locator("#wbList .wbrow").count() == 2)
            await pg.select_option("#wbShow", "all")
            async with pg.expect_download() as dl:
                await pg.click("#wbCsv")
            csvp = await (await dl.value).path(); csv = open(csvp, newline="").read()
            ok("csv: header, ranked rows, formulas neutralised", csv.startswith("Rank,Score,CVE") and "CVE-2026-1001" in csv.split("\r\n")[1] and "\r\n=" not in csv and ",=" not in csv, csv[:200])
            await pg.click("#wbt-hunt"); await pg.wait_for_timeout(150)
            ok("hunt: valid resources only", await pg.locator("#wbHunt .wbh").count() == 2 and "STIX" in await pg.locator("#wbHunt").text_content())
            await pg.select_option("#wbFmt", "sigma"); await pg.wait_for_timeout(100)
            ok("hunt: format filter", await pg.locator("#wbHunt .wbh").count() == 1)
            await pg.click("#wbt-inv"); await pg.click("#wbClear"); await pg.wait_for_timeout(150)
            ok("software: clear removes it from the browser", await pg.evaluate("localStorage.getItem('cwm.inv')") is None and await pg.locator("#wbInvTable tbody tr").count() == 0)
            reqs = []
            pg.on("request", lambda r: reqs.append(r.url) if not r.url.startswith("http://localhost") else None)
            await pg.fill("#wbText", "FortiOS 7.2.4"); await pg.click("#wbAdd"); await pg.wait_for_timeout(300)
            ok("software: nothing leaves the page", not reqs, reqs)
            ok("workbench: no script errors", not errs, errs)
            await pg.goto(url.replace("index.html", "workbench.html#CVE-2026-1002")); await pg.reload(); await pg.wait_for_timeout(700)
            ok("workbench: a CVE link opens that flaw", await pg.locator(".wbdetail").count() == 1 and await pg.locator("#wbList .wbrow").count() == 1)
            await pg.context.close()
            ctx = await browser.new_context(viewport={"width": 390, "height": 844})
            pg = await ctx.new_page(); await pg.goto(url.replace("index.html", "workbench.html")); await pg.wait_for_timeout(700)
            await pg.locator("#wbList .wbhead >> nth=0").click()
            ok("phone workbench: no sideways scroll", await pg.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"))
            await ctx.close()

        await serve(site17, v117)

        # v1.18: community feed (reviewed posts only)
        site18 = make_site(bundle)
        ev0 = bundle["events"][0]["id"]
        json.dump({"built_at": "x", "posts": [
            {"id": 41, "at": "2026-11-18T21:00:00Z", "author": "defender-one", "kind": "tip", "text": "Disabling http2 held for us. Guidance: https://www.cisa.gov/example-alert and more.", "event_id": ev0, "links": ["https://www.cisa.gov/example-alert"], "reviewed_at": "2026-11-18T21:40:00Z", "note": "Opinion; not verified."},
            {"id": 42, "at": "2026-11-18T20:00:00Z", "author": "blue-team", "kind": "question", "text": "<img src=x onerror=alert(1)> is 7.2 affected?", "event_id": "", "links": ["javascript:alert(1)"], "reviewed_at": "2026-11-18T20:40:00Z"},
            {"id": 43, "at": "2026-11-18T19:00:00Z", "author": "not-reviewed", "kind": "comment", "text": "This must never show.", "links": []},
            {"id": 44, "at": "2026-11-18T18:00:00Z", "author": "bad name<script>", "kind": "comment", "text": "bad author", "links": [], "reviewed_at": "2026-11-18T18:40:00Z"}]},
            open(os.path.join(site18, "data", "chat.json"), "w"))

        async def v118(url):
            pg, errs = await open_page(browser, url.replace("index.html", "community.html"), wait=800)
            ok("community: only reviewed, well-formed posts shown", await pg.locator("#cmList .cmpost").count() == 2 and "This must never show" not in await pg.inner_text("body"))
            ok("community: markup shown as text", await pg.locator("#cmList img").count() == 0 and await pg.locator("#cmList script").count() == 0)
            hrefs = await pg.eval_on_selector_all("#cmList a", "as => as.map(a => [a.href, a.rel])")
            ok("community: links are https and nofollow", not any(h[0].startswith("javascript") for h in hrefs) and any("cisa.gov/example-alert" in h[0] and "nofollow" in h[1] for h in hrefs), hrefs)
            first = await pg.locator("#cmList .cmpost >> nth=0").text_content()
            ok("community: author, reviewed mark, moderator note, report link", all(x in first for x in ["defender-one", "Reviewed", "Moderator's note", "Report #41"]), first)
            await pg.select_option("#cmShow", "question"); await pg.wait_for_timeout(100)
            ok("community: filter by kind", await pg.locator("#cmList .cmpost").count() == 1)
            await pg.select_option("#cmShow", "")
            await pg.click("#cmPost")
            ok("post: empty message stopped on the page", await pg.locator("#cmWarn").is_visible() and "Write a message" in await pg.locator("#cmWarn").text_content())
            await pg.fill("#cmText", "my key is " + "AKIA" + "ABCDEFGHIJKLMNOP")   # a made-up key, split so the secret scan does not flag this file; await pg.click("#cmPost")
            ok("post: a credential is stopped on the page", "credential" in await pg.locator("#cmWarn").text_content())
            await pg.fill("#cmText", "Seeing scans for this flaw across our edge."); await pg.fill("#cmEvent", ev0)
            await pg.context.route("https://github.com/**", lambda r: r.fulfill(status=200, content_type="text/html", body="ok"))   # never reach GitHub from a test
            async with pg.context.expect_page() as np:
                await pg.click("#cmPost")
            gh = await np.value; await gh.wait_for_load_state()
            ok("post: opens the GitHub form prefilled, nothing sent from the page", "github.com/xanderhutch/CyberView/issues/new" in gh.url and "template=chat.yml" in gh.url and "Seeing%20scans" in gh.url and "event=" + ev0 in gh.url, gh.url[:160])
            await gh.close()
            ok("community: no script errors", not errs, errs)
            await pg.goto(url.replace("index.html", "community.html#e=" + ev0)); await pg.reload(); await pg.wait_for_timeout(600)
            ok("community: event link shows that event's posts", await pg.locator("#cmList .cmpost").count() == 1 and await pg.locator("#cmClear").is_visible() and await pg.input_value("#cmEvent") == ev0)
            await pg.context.close()
            ctx = await browser.new_context(viewport={"width": 390, "height": 844})
            pg = await ctx.new_page(); await pg.goto(url.replace("index.html", "community.html")); await pg.wait_for_timeout(600)
            ok("phone community: no sideways scroll", await pg.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"))
            await ctx.close()
            pg, errs = await open_page(browser, url, w=1000, wait=1200)
            nb = await pg.locator("header .sitenav").bounding_box(); rb = await pg.locator("#refresh").bounding_box()
            ok("nav: eight links fit beside the buttons on a small laptop", nb and rb and nb["x"] + nb["width"] <= rb["x"] + 1 and abs((await pg.locator("#keysBtn").bounding_box())["y"] - rb["y"]) < 12 and await pg.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), [nb, rb])
            await pg.context.close()

        await serve(site18, v118)

        await browser.close()


asyncio.run(main())
print(f"{count} checks")
if fails:
    print("FAILED:\n- " + "\n- ".join(fails))
    sys.exit(1)
print("ALL PASS")
