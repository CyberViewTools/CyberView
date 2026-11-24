# Moving CyberView to its own domain (Cloudflare in front of GitHub Pages)

Why (pen test, 2026-11-23): on `xanderhutch.github.io` the site shares one browser origin with every other GitHub Pages
site of the account, so their scripts could read CyberView's browser storage and offline cache. GitHub Pages also cannot
send security headers, so `frame-ancestors`, `X-Content-Type-Options` and the like are impossible there. Its own domain
behind Cloudflare fixes both.

The repository is ready: the address lives in one place (`config/site.json` `site_url`, overridden by the repository
variable `SITE_URL`, read by `scripts/lib/site-url.mjs` and every workflow). Replace `cyberview.example` below with the
real domain.

## 1. Domain and DNS (Cloudflare dashboard)
1. Buy or transfer the domain on Cloudflare (Domain Registration), or add an existing domain to Cloudflare and switch
   its nameservers.
2. DNS: for the apex `cyberview.example`, add four `A` records to GitHub Pages: `185.199.108.153`, `185.199.109.153`,
   `185.199.110.153`, `185.199.111.153`, and four `AAAA` records: `2606:50c0:8000::153`, `2606:50c0:8001::153`,
   `2606:50c0:8002::153`, `2606:50c0:8003::153`. For `www`, a `CNAME` to `xanderhutch.github.io`.
   Leave them **DNS only (grey cloud)** for now, so GitHub can issue its certificate.

## 2. GitHub
1. Settings → Pages → Custom domain: `cyberview.example`. Wait for the DNS check and the certificate, then tick
   **Enforce HTTPS**.
2. Settings → Pages: verify the domain for the account (Settings → Pages → Verified domains) so nobody else can claim it.
3. Settings → Secrets and variables → Actions → Variables: `SITE_URL` = `https://cyberview.example`.
4. In the repository: set `"site_url": "https://cyberview.example"` in `config/site.json` (a pull request), and add the
   host to `V.BASE_HOSTS` in `site/scanner-lib.js` (the scanner report's own-site link allowlist).
   GitHub redirects `xanderhutch.github.io/CyberView/...` to the new domain by itself.

## 3. Cloudflare proxy and headers
1. Once Enforce HTTPS is on, switch the DNS records to **Proxied (orange cloud)** and set SSL/TLS mode to **Full (strict)**.
2. Rules → Transform Rules → Modify Response Header, for all requests to the domain, **set**:
   - `Content-Security-Policy`: `frame-ancestors 'none'` (a second policy; browsers enforce both it and the page's own
     meta policy, so nothing else changes)
   - `X-Frame-Options`: `DENY`
   - `X-Content-Type-Options`: `nosniff`
   - `Referrer-Policy`: `strict-origin-when-cross-origin`
   - `Permissions-Policy`: `camera=(), microphone=(), geolocation=(), payment=(), usb=()`
   - `Cross-Origin-Opener-Policy`: `same-origin`
3. SSL/TLS → Edge Certificates: Always Use HTTPS on; HSTS on (max-age 6 months, include subdomains only if every
   subdomain is HTTPS); minimum TLS 1.2.
4. Caching: leave the default (Cloudflare respects GitHub's `max-age=600`). Do not cache `data/*.json` longer than
   that, or the site's freshness check will show old data.

## 4. Check
- `curl -sI https://cyberview.example/ | grep -i -E "frame|nosniff|referrer|strict-transport"` shows the headers.
- `node scripts/guard.mjs` and the monitor (`SITE_URL` set) report healthy against the new address.
- The `.well-known/security.txt` is now at the origin root, where scanners look for it.
- If accounts are turned on later, add the new domain to the Supabase project's allowed redirect URLs.
