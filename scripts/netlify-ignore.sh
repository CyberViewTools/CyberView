#!/usr/bin/env bash
# Netlify runs this before each build: exit 0 skips the build, exit 1 builds.
# Code changes always build. Data-only commits (the scheduled jobs) build at most once per
# DEPLOY_MIN_MINUTES (default 50) to stay inside the plan's build allowance; skipped data goes out
# with the next build. The live monitor flags data that is more than a few hours old.
set -u
prev="${CACHED_COMMIT_REF:-}"; cur="${COMMIT_REF:-HEAD}"
[ -z "$prev" ] && exit 1
git cat-file -e "$prev^{commit}" 2>/dev/null || exit 1
if git diff --name-only "$prev" "$cur" | grep -qv '^data/'; then exit 1; fi
age=$(( $(date +%s) - $(git show -s --format=%ct "$prev") ))
if [ "$age" -ge $(( ${DEPLOY_MIN_MINUTES:-50} * 60 )) ]; then exit 1; fi
echo "Data-only change and the last deploy is $((age / 60)) min old: skipping this build."
exit 0
