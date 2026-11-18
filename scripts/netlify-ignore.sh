#!/usr/bin/env bash
# Netlify runs this before each build: exit 0 skips the build, exit 1 builds.
# The site moved to GitHub Pages; Netlify only serves redirects (netlify.toml). Build only when
# netlify.toml itself changes, so the redirect rules can be updated and nothing else uses credits.
set -u
prev="${CACHED_COMMIT_REF:-}"; cur="${COMMIT_REF:-HEAD}"
[ -z "$prev" ] && exit 1
git cat-file -e "$prev^{commit}" 2>/dev/null || exit 1
if git diff --name-only "$prev" "$cur" | grep -qx 'netlify.toml'; then echo "netlify.toml changed: building the redirect site."; exit 1; fi
echo "Site is on GitHub Pages; Netlify only redirects. Skipping."
exit 0
