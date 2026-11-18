"""Loads the live site in a real browser and checks that it renders: map, feed, archive, and no script
errors or Content Security Policy violations. Run: python3 tests/smoke_live.py [base URL]
Exit 1 on failure. Appends its result to monitor-report.md when that file exists."""
import asyncio, os, sys
from playwright.async_api import async_playwright

BASE = (sys.argv[1] if len(sys.argv) > 1 else os.environ.get("SITE_URL", "https://cyberview.netlify.app")).rstrip("/")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


async def main():
    fails = []
    async with async_playwright() as p:
        b = None
        for opts in ({}, {"executable_path": "/opt/pw-browsers/chromium"}, {"executable_path": "/usr/bin/google-chrome", "args": ["--no-sandbox"]}):
            try:
                b = await p.chromium.launch(**opts)
                break
            except Exception:
                continue
        if b is None:
            print("Browser check: could not start a browser"); sys.exit(1)
        for name, w, h in [("desktop", 1440, 860), ("phone", 390, 844)]:
            ctx = await b.new_context(viewport={"width": w, "height": h})
            pg = await ctx.new_page()
            errs = []
            pg.on("pageerror", lambda e: errs.append(str(e)[:200]))
            # CSP violations are classified by the script that caused them: Netlify injects its own badge script
            # (/.netlify/scripts/...), which our policy blocks on purpose; anything else is a real problem.
            await pg.add_init_script("""window.__csp = []; document.addEventListener('securitypolicyviolation',
              e => window.__csp.push({src: e.sourceFile || '', blocked: e.blockedURI || '', dir: e.violatedDirective}));""")
            pg.on("console", lambda m: errs.append(m.text[:200]) if m.type == "error" and "Content Security Policy" not in m.text else None)
            await pg.goto(BASE + "/", wait_until="networkidle")
            await pg.wait_for_timeout(2500)
            if name == "desktop":
                if await pg.locator("#feed .card").count() < 5:
                    fails.append("desktop: the feed shows fewer than 5 events")
                if await pg.locator("#svg g.m, #svg g.cl").count() < 3:
                    fails.append("desktop: the map shows fewer than 3 markers")
            if "events" not in (await pg.inner_text("#stats")):
                fails.append(f"{name}: the header stats did not load")
            csp_home = [v for v in await pg.evaluate("window.__csp || []") if "/.netlify/" not in v["src"]]
            if csp_home:
                fails.append(f"{name}: Content Security Policy blocked our own code on the map: {csp_home[:2]}")
            await pg.goto(BASE + "/archive.html", wait_until="networkidle")
            await pg.wait_for_timeout(1500)
            if await pg.locator(".row").count() < 1:
                fails.append(f"{name}: the archive lists no events")
            csp = [v for v in await pg.evaluate("window.__csp || []") if "/.netlify/" not in v["src"]]
            if csp:
                fails.append(f"{name}: Content Security Policy blocked our own code: {csp[:2]}")
            if errs:
                fails.append(f"{name}: browser errors: " + " | ".join(errs[:3]))
            await ctx.close()
        await b.close()
    msg = "Browser check: " + ("passed" if not fails else "FAILED\n" + "\n".join("- ❌ " + f for f in fails))
    print(msg)
    rep = os.path.join(ROOT, "monitor-report.md")
    with open(rep, "a") as f:
        f.write("\n" + msg + "\n")
    sys.exit(1 if fails else 0)


asyncio.run(main())
