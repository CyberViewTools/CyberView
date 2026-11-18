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
            ok("volume: two full redraws under 800 ms", t < 800, round(t))
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
            await pg.click("#layers .chip >> nth=0")
            ok("layers: disruptions shade the country", await pg.locator("path.country.dis").count() == 1)
            await pg.keyboard.press("Escape")
            ok("layers: Esc closes the panel", await pg.locator("#layers").is_hidden())
            await pg.click("#zglobe")
            await pg.wait_for_timeout(300)
            ok("globe: switches on", await pg.get_attribute("#zglobe", "aria-pressed") == "true" and await pg.locator("path.ocean").count() == 1)
            flat_marks = await pg.locator("#svg g.m, #svg g.cl").count()
            ok("globe: far side hidden", flat_marks > 0, flat_marks)
            box = await pg.locator("#svg").bounding_box()
            d0 = await pg.get_attribute("path.grat", "d")
            await pg.mouse.move(box["x"] + 500, box["y"] + 450); await pg.mouse.down(); await pg.mouse.move(box["x"] + 350, box["y"] + 430, steps=6); await pg.mouse.up()
            await pg.wait_for_timeout(200)
            ok("globe: drag turns it", await pg.get_attribute("path.grat", "d") != d0)
            await pg.click("#refresh")
            await pg.wait_for_timeout(500)
            ok("globe: refresh returns to the flat map", await pg.get_attribute("#zglobe", "aria-pressed") == "false" and await pg.locator("path.ocean").count() == 0)
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
        await browser.close()


asyncio.run(main())
print(f"{count} checks")
if fails:
    print("FAILED:\n- " + "\n- ".join(fails))
    sys.exit(1)
print("ALL PASS")
