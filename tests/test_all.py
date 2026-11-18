"""Browser regression suite for Cyber Watch Map.

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
        await pg.click(f"[data-theme-set={theme}]")
        await pg.wait_for_timeout(150)
    return pg, errs


OVERLAP = """() => { let n = 0; document.querySelectorAll('#viz .vsec svg').forEach(svg => {
  const pts = [...svg.querySelectorAll('g.ev[transform]')].map(g => { const r = g.getBoundingClientRect(); return [r.left + r.width / 2, r.top + r.height / 2]; });
  for (let i = 0; i < pts.length; i++) for (let j = i + 1; j < pts.length; j++) if (Math.hypot(pts[i][0] - pts[j][0], pts[i][1] - pts[j][1]) < 11) n++; });
  return n; }"""


async def serve(dirpath, fn):
    srv = subprocess.Popen([sys.executable, "-m", "http.server", str(PORT)], cwd=dirpath, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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
            for th in ["light", "dark"]:
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
                st = await pg.evaluate('document.getElementById("feed").scrollTop')
                ok(f"{th}: back restores list position", abs(st - 400) < 80, st)
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
        await browser.close()


asyncio.run(main())
print(f"{count} checks")
if fails:
    print("FAILED:\n- " + "\n- ".join(fails))
    sys.exit(1)
print("ALL PASS")
