# Handoff: scan-http-paths — bounded HTTP path rail

Run scanner-build-2026-11-22, wave 2 (plan_id w2-7c1e). Catalog rows are referenced by id only.

## Discovery → Design
- **Need:** KEV-heavy products (edge devices, CMS plugins, self-hosted dev/AI tools, BMCs) state a version only on a
  documented version/status file, not on the root page. One shared rail keeps edge, CMS and app items from each inventing
  a crawler.
- **Constraints:** product-limit change. Detection only, GET only, redirects recorded not followed, no wordlists, no
  operator-supplied URLs, no login/management/exploit-class paths, CAPS untouched, every request through `probe.mjs`
  and the Limiter, declared in SENDS, the run header, the docs and section 7.
- **Design review (done before this slice):** a frozen table of 50 catalog rows / 39 distinct literal paths
  (`rail-table.json`, reviewed). Nothing outside it may ever be requested.
- **Recommendation:** built; OFF by default, on only with `--paths`.

## Design → Implementation
- **Interfaces / CLI:** `scan ... --paths [--paths-per-host N] [--paths-bmc]`.
  - `--paths` turns the rail on. Without it the scanner sends exactly what it sent before (one GET of the root page per
    web port).
  - `--paths-per-host N` lowers the per-host cap (1–8); a higher value is refused ("limits can only be lowered").
  - `--paths-bmc` adds the two BMC rows (`ami-megarac-spx`, `redfish-service-root`), which stay opt-in even with `--paths`.
  - `--paths-bmc` / `--paths-per-host` without `--paths` are refused.
- **Modules:**
  - `scanner/lib/paths.mjs` (new, pure): `RAIL` (the frozen table as data: id, literal `paths`, `hint(ev)`,
    `parse(path, ctx)`, optional `group: "bmc"`), `RAIL_PATHS` (frozen list of the 39 literals), `PATHS_PER_HOST = 8`,
    `railEvidence(port, probeResult)`, `railPlan(evs, {perHost, bmc})`, `railResult(item, res)`, `outcomeOf`,
    `railCoverage`, `railHeaderText`, `railSummaryLine`, `pathsPerHost`, `mmh3`/`faviconHash`.
  - `scanner/lib/probe.mjs`: `getPath(ip, port, path, opts)` — refuses any path not in `RAIL_PATHS` before connecting,
    then one connection, one GET (same User-Agent, `Connection: close`), redirect recorded not followed, body capped at
    `TIMEOUTS.maxBytes`. `httpGet` takes an optional rail path (used only by `getPath`; the request path is `"/"` or a
    `RAIL_PATHS` literal). `SENDS.paths` added.
  - `scanner/lib/scan.mjs`: `probeAll({ paths, getPath })` — evidence kept in memory per web port, rail run per host after
    the TCP pass (and throttle retry), before UDP; each request takes a Limiter slot (rate, open-at-once, per-host and total
    budgets all apply). Report: `run.paths`, `coverage.paths`, `hosts[].paths`.
  - `scanner/lib/report.mjs`: run-header line "Path rail:" and a summary.txt line.
  - `scanner/cyberview-scan.mjs`: the three flags, usage text.
  - `scripts/lib/scanner-rail-check.mjs` (new) + `scripts/security-check.mjs` section 7 hook.
- **Hint evidence (already collected, per port):** root status, title, `Location` (recorded redirect), `Server`, other
  header names/values, cookie NAMES only (values are never read), `WWW-Authenticate` realm, meta generator, the root body in
  memory (never stored), TLS subject/issuer/SAN, the port number. An unhinted host gets nothing beyond the root GET.
- **Planning:** table order, one request per port+path (rows sharing a path, e.g. `/version`, `/status.php`,
  `/currentsetting.htm`, `/redfish/v1/`, are requested once and parsed for every hinted row), at most `PATHS_PER_HOST`
  across all ports of a host; hinted paths over the cap are recorded as `not-sent: per-host cap`; a request the Limiter
  refuses (budget/time) is recorded as `not-sent: budget or time`.
- **Parsing:** only a 200 is parsed. A parser returns at most `{vendor, product, version}`; the service record carries
  `source: "HTTP GET <path> (path rail, <catalog id>)"` and a short evidence token. Presence-only rows and rows whose token
  is a build number rather than NVD's release naming (Pulse/Ivanti build, Magento major.minor, Qlik server build) are
  `guessed` with no comparable version, so they stay out of the headline counts.
- **Design decisions taken here (where the reviewed table said "fix in Design"):**
  - `apache-tomcat-version-path`: parse the documentation index title `Apache Tomcat N (x.y.z)` or `Version x.y.z,`.
    Note: Tomcat usually answers `/docs` with a redirect to `/docs/`, which is recorded, not followed (see limits).
  - `chroma`: hint = the root body or Server header names Chroma; parse = a JSON key containing "heartbeat" with a number
    (presence only).
  - `ollama`: hint = root body starts "Ollama is running", or port 11434.
  - `weaviate`: hint = root body names Weaviate; parse = JSON `version` with `modules` or `hostname`.
  - `prometheus-ui-or-api`: hint = title contains Prometheus, or port 9090 with a recorded redirect to `/graph`/`/query`.
  - `kubernetes-api-version`: hint = certificate CN `kube-apiserver` or SAN `kubernetes.default`, or port 6443.
  - `kubernetes-insecure-api-port`: hint = port 8080 and a root JSON `"paths": [... "/api" ...]`.
  - `openshift-console-or-api`: hint = certificate text containing "openshift"; the `/version` document gives the
    Kubernetes version, so OpenShift is reported presence-only (guessed) with that token as evidence.
  - `plex-media-server`: `version` attribute of `<MediaContainer>` in `/identity`.
  - `sonatype-nexus-repository`: version only from the status response's own `Server: Nexus/x.y.z` header; else presence.
  - `samsung-magicinfo-9-server`: reviewed status/content pair = 200 + `image/*` content type + ICO magic bytes
    (00 00 01 00), so a generic 404 page never matches.
  - `netgear-jgs516pe-devices`: 200 + `image/gif` + GIF magic.
  - `sonicwall-sonicwall-email-security`: murmur3 (x86 32, seed 0) of the base64 (76-column lines) icon = 2063459123, as
    the published hash convention; a truncated icon never matches.
  - `ami-megarac-spx` / `redfish-service-root`: BMC group, `--paths-bmc` only; hint = the AMI default certificate subject.
  - `perforce-puppet-enterprise`: reports PuppetDB with its own version (the `/pdb/meta/v1/version` document is PuppetDB's,
    not the PE release).
- **Safety-model check:** detection only; GET only; one connection per rail request; no redirect followed; no body,
  cookie value or header dump stored (status, outcome, Location and the parsed token only); CAPS untouched; every request
  counts against the host and total budgets; nothing sent without `--paths`. `node scripts/security-check.mjs` green.
- **Test plan (done):** `tests/unit/scanner-paths.test.mjs`, 17 tests, loopback only.

## Implementation → Review
- **Branch/commit:** see the worker report.
- **Section 7 additions (CI fails when):** (a) a `paths:` entry in `paths.mjs` is not a literal array of plain strings, a
  path-like string literal is not plain (query, traversal, encoding), the loaded `RAIL_PATHS` holds anything not written as
  a literal, the table is not frozen, `getPath` does not first refuse paths outside `RAIL_PATHS`, the request path is not
  `"/"` or a `RAIL_PATHS` literal, `scan.mjs` calls `getPath` with anything but a planned item's path, or another scanner
  file calls `getPath`; (b) `paths.mjs` names an HTTP method, or any `method:` in `probe.mjs` is not `"GET"`; (c)
  `PATHS_PER_HOST` is not a literal 1–16; (d) any rail path matches
  `login|signin|logon|.cgi|actuator|heapdump|phpinfo|console|server-status|_cat|_search|_all_dbs|graphql|xmlrpc|soap|.env`.
- **Open questions / follow-ups:**
  - `/docs` (Tomcat) normally redirects to `/docs/`; the reviewed table has only `/docs`, so a Tomcat version is read only
    where `/docs` answers directly. Adding `/docs/` needs a new Design review.
  - Drupal 8+ keeps its changelog at a different path that is not in the table; `/CHANGELOG.txt` covers Drupal 7.
  - Hints that rely on a port (Docker 2375/2376, etcd 2379, LiteLLM 4000, Collabora 9980, Langflow 7860, Ollama 11434,
    kube 6443) only fire when that port is scanned as a web port (`--http-ports` / `--https-ports`).
  - Rows whose catalog owner is another slice (`scan-cms-paths`, `scan-edge-paths`, `scan-app-versions`,
    `scan-mgmt-identify`, `scan-voip-identify`) now have their parse here; those slices can extend or move the parsers
    without adding paths.

---

## Exact doc text for the orchestrator

### `SENDS` (already in `scanner/lib/probe.mjs`)

```
paths: only with --paths (off by default): at most 8 extra HTTP GET requests per host, each for a frozen literal path in scanner/lib/paths.mjs and only when that host's own root page, headers, certificate or port already hint at the product; same User-Agent, redirects recorded, not followed, only a product/version token kept
```

### Run header (already in `scanner/lib/report.mjs`, SCOPE block)

```
  Path rail:   off (--paths not given): web ports get one GET / and nothing else
  Path rail:   on (--paths): at most 8 extra GET request(s) per host (hard cap 8), only frozen literal paths from scanner/lib/paths.mjs (39 reviewed), and only when the host's own root page, headers, certificate or port already hint at that product; redirects recorded, not followed; BMC identify off
```

### `docs/scanner.md`

Replace the first bullet of "Design limits":

> - No exploitation, payloads, injection strings or crafted input beyond reading a greeting, one request for a web
>   server's root page and a TLS handshake — and, only with `--paths`, the bounded path rail below. No check that works by
>   triggering a flaw.

Add to the Files table:

> | `scanner/lib/paths.mjs` | the bounded HTTP path rail: the frozen, reviewed table of literal version/status paths (data), the hints over already-collected evidence, the parsers, the per-host cap `PATHS_PER_HOST` (8) |

Append to the section 7 paragraph:

> It also fails if the path rail (`scanner/lib/paths.mjs`) holds a path that is not a plain string literal, holds a login,
> management or exploit-class path, names an HTTP method, or sets `PATHS_PER_HOST` above 16; if `getPath` in `probe.mjs`
> does not refuse every path outside the frozen table before connecting; or if anything but a planned rail item's path
> reaches it (`scripts/lib/scanner-rail-check.mjs`).

New section after "Depth: more ports and read-only UDP checks":

> ## The bounded path rail (`--paths`, off by default)
>
> Some products state their version only in a documented version or status file, not on the root page. With `--paths`
> the scanner may make a few extra GET requests for those files, and nothing else:
>
> - **A frozen table, not a wordlist.** `scanner/lib/paths.mjs` holds 39 literal paths for 50 reviewed catalog rows. A
>   path is added only after a Design review; operator-supplied URLs are not accepted. No login, management, debug or
>   exploit-class path is allowed (section 7 enforces it).
> - **Hint-gated.** A host gets a path only when its own already-collected evidence on that port — the root page's
>   title, headers, cookie names, body markers, a recorded redirect, the TLS certificate or the port — points at that
>   product. A host with no hint gets the root request and nothing more.
> - **Bounded.** At most 8 extra requests per host (`PATHS_PER_HOST`; `--paths-per-host N` can lower it, never raise
>   it). Each request takes a Limiter slot like a connection, so the rate, open-at-once and budget limits all apply.
>   Baseboard management controllers stay opt-in even with `--paths` (`--paths-bmc`).
> - **Read, not followed.** GET only, the scanner's User-Agent, one connection per request. Redirects are recorded, not
>   followed. The body is read up to 16 KB and only a product and version token is kept; bodies, cookie values and
>   headers are never written to the report.
> - **Every outcome recorded.** Each rail request's status (ok, redirect with its Location, unauthorized, forbidden,
>   not-found, other code, timeout, error) and every hinted path left unsent (per-host cap, budget) is in
>   `coverage.paths` and `hosts[].paths` in report.json, with a line in summary.txt.
> - Products identified only by presence, or whose file states a build number rather than the release name NVD uses,
>   are reported as inferred (low confidence) and stay out of the headline counts.

In "Deliberately left out", keep "following redirects; crawling" and add "requesting any path outside the reviewed
frozen table".

In "Tests", add:

> `tests/unit/scanner-paths.test.mjs`: the path rail on loopback — an unhinted host sees only the root request, a
> hinted host only its frozen paths (GET, the scanner's User-Agent), the per-host cap across many hints, budgets, a
> redirect recorded and not followed, 401/404 in coverage, the flag off sends nothing extra, the parsers on canned
> responses, and the section 7 rules (each failure case).

### `scanner/README.md`

In the scan options list (next to `--udp`):

> - `--paths` (off by default) adds at most 8 GET requests per host for frozen, reviewed version/status files, only
>   where the host's own root page, headers, certificate or port already point at that product (see "what goes over the
>   network"). `--paths-per-host N` lowers the cap; `--paths-bmc` adds BMC identification (Redfish service root).

In "Exactly what goes over the network", after the UDP table:

> With `--paths` (off by default), at most 8 extra HTTP requests per host, method GET, the same User-Agent, one
> connection each, each for a literal path from the reviewed table in `scanner/lib/paths.mjs`, and only when that host's
> own root page, headers, certificate or port already hint at the product. Redirects are recorded, not followed; only a
> product and version token is kept. Every request's status is in the report's coverage.

In "What it deliberately does not do", add:

> - No crawling, no wordlists and no paths you supply: the optional path rail requests only the reviewed literal paths in
>   `scanner/lib/paths.mjs`, never a login or management page, and is off unless you pass `--paths`.
