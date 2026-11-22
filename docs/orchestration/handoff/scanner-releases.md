# Handoff: scanner-releases — the scanner as one downloadable file (GitHub Releases)

Source: issue #89 (a Grok brief, treated as a proposal). The owner's lead approved a narrower build: one `.mjs` file that
runs with Node.js 22+, built and released by CI from a `scanner-v*` tag. No compiled executables (see "Not done").

## Implementation → Review

- **Branch:** `scanner/releases` (one commit, `[scanner-releases]`).
- **What landed:**
  - `scripts/scanner-release.mjs` — a stdlib-only bundler. It copies `scanner/cyberview-scan.mjs` and every
    `scanner/lib/*.mjs` it imports verbatim, each into its own function scope, in Node's evaluation order; only import
    lines, `export` keywords and `export { … }` lists are rewritten. `scanner/lib/shared.mjs` keeps its `vm.runInNewContext`
    call; the two site files it runs (`site/workbench-lib.js`, `site/cvedb-lib.js`) are embedded as strings instead of read
    from disk. Anything it does not understand (dynamic `import()`, default export, a multi-line import, a cycle, a name a
    module does not export, a change to `shared.mjs`'s two swapped lines) stops the build. Output is deterministic: the
    same commit gives the same bytes and checksum. Header: version, source commit, Node requirement, `scanner/LICENSE` in full.
    `node scripts/scanner-release.mjs [--out DIR] [--commit SHA]` (default `dist/scanner/`, git-ignored).
  - `.github/workflows/scanner-release.yml` — tag `scanner-v*`: checks the tag equals `VERSION`, runs the security check and
    `tests/unit/scanner*.test.mjs`, builds, smoke-tests the bundle outside the repo (help, refusal without a scope file),
    writes `SHA256SUMS`, then a separate `release` job (the only one with `contents: write`) verifies the sums and runs
    `gh release create` with the bundle, `SHA256SUMS` and `LICENSE`. `workflow_dispatch` is a dry run: artifact only.
    Actions pinned by commit SHA (checkout v4.2.2, setup-node v4.4.0, upload-artifact v4.6.2, download-artifact v4.3.0).
  - `tests/unit/scanner-release.test.mjs` — walks the bundle line by line against the sources (no line of code the source
    lacks; same `node:` built-ins, none added); runs the bundle and the source CLI side by side: help, refusals (no scope,
    unattested scope, public address without the flag), `check` output including WHAT IS SENT, and a loopback scan against
    `tests/fixtures/scanner/servers.mjs` (identical bytes received by the stand-in services, identical findings and output).
  - `scripts/security-check.mjs` section 7 refuses a committed bundle (`cyberview-scan-X.Y.Z.mjs` in `scanner/` or the
    repository root); `.gitignore` ignores `dist/` and `cyberview-scan-*.mjs`.
  - `VERSION` in `scanner/lib/probe.mjs` is now `1.1.0` (it is the scanner's only version: USAGE, User-Agent, SSH ident,
    report and SARIF). The release workflow requires the tag to match it.

## Text for scanner/README.md and docs/scanner.md (for the docs consolidation)

The docs agent owns those two files; the text below is ready to paste.

**scanner/README.md, replace the "What you need" section with:**

~~~markdown
## What you need

- Node.js 22 or later (`node --version`). Nothing else to install: the scanner uses Node's standard library only.
- The scanner itself, in one of two ways:
  - **One file (recommended).** From the repository's [Releases](https://github.com/xanderhutch/CyberView/releases),
    take the latest `scanner-v…` release and download `cyberview-scan-<version>.mjs` and `SHA256SUMS` into one folder.
    Check the file before you run it:

    ```
    sha256sum -c --ignore-missing SHA256SUMS            # Linux
    shasum -a 256 -c --ignore-missing SHA256SUMS        # macOS
    (Get-FileHash .\cyberview-scan-<version>.mjs -Algorithm SHA256).Hash   # Windows PowerShell: compare with SHA256SUMS
    ```

    It must print `cyberview-scan-<version>.mjs: OK` (on Windows, the same hash as in `SHA256SUMS`). Then run it with
    `node cyberview-scan-<version>.mjs` wherever the commands below say `node scanner/cyberview-scan.mjs`. The file is
    the scanner and the site's matching and rating code in one, built by CI from the tagged commit (named in its first
    lines); it contains nothing the repository's scanner does not.
  - **From the repository** (developers): [download the ZIP](https://github.com/xanderhutch/CyberView/archive/refs/heads/main.zip)
    or clone it, then run the commands below from the repository's folder.
~~~

**scanner/README.md, under "Quick start", add after the first code block:**

~~~markdown
With the one-file release, the same steps are:

    node cyberview-scan-<version>.mjs init --out scope.json
    node cyberview-scan-<version>.mjs check --scope scope.json
    node cyberview-scan-<version>.mjs scan --scope scope.json --online
    node cyberview-scan-<version>.mjs data --out cyberview-data          # air-gapped: on a connected machine
    node cyberview-scan-<version>.mjs scan --scope scope.json --data cyberview-data

The help text still shows `node scanner/cyberview-scan.mjs`; the commands and flags are the same.
~~~

**scanner/README.md, "Exactly what goes over the network":** the version in the two strings is now 1.1.0:
`SSH-2.0-CyberViewScanner_1.1.0 authorized-vulnerability-scan` and `CyberView-Scanner/1.1.0 (authorized vulnerability scan, …)`.
(Better: write `<version>` there, since it changes with every release.)

**docs/scanner.md, add a section "Releases":**

~~~markdown
## Releases

The scanner is also published as one file, `cyberview-scan-<version>.mjs`, on GitHub Releases (tag `scanner-v<version>`),
with `SHA256SUMS` and `LICENSE`. `scripts/scanner-release.mjs` builds it with no dependencies: the entry and every
`scanner/lib` module it imports, copied verbatim into their own function scopes, and `site/workbench-lib.js` and
`site/cvedb-lib.js` embedded and run with `node:vm` exactly as `scanner/lib/shared.mjs` runs them from disk. The build
is deterministic (same commit, same checksum). `tests/unit/scanner-release.test.mjs` proves the bundle holds no code the
source lacks and behaves like the source CLI (same refusals, same WHAT IS SENT, same bytes on a loopback scan). The
bundle is never committed; the security check refuses one in the repository.

Cutting a release (owner):

1. Set `VERSION` in `scanner/lib/probe.mjs` to the new version in a pull request and merge it.
2. Tag that commit on main and push the tag:

       git checkout main && git pull
       git tag scanner-v1.1.0
       git push origin scanner-v1.1.0

3. `.github/workflows/scanner-release.yml` checks the tag matches `VERSION` (it stops otherwise), runs the security check
   and the scanner tests, builds the file, writes `SHA256SUMS` and publishes the release. To try the build without
   releasing, run the workflow by hand (Actions → Scanner release → Run workflow): it uploads the files as an artifact only.
~~~

## Not done, and why

- **Compiled executables (Node SEA / bun).** Node 22's Single Executable Applications need `postject`, an npm package, to
  inject the blob into the node binary, and Node 22 SEA only takes a CommonJS entry; bun is a third-party toolchain. Both
  are outside "stdlib only, no new dependencies", so the release is the single `.mjs` (Node 22+ still required).
- **`--version` flag, macOS/Windows signing, Homebrew/winget/Docker** (issue #89 Phase 1 items 3 and 2b, Phase 2): not in
  the approved scope.
- **README/docs edits:** left to the docs consolidation; the exact text is above.
