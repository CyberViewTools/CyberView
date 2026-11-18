#!/usr/bin/env bash
# Netlify runs this before each build: exit 0 skips the build, exit 1 builds.
# Netlify's Free plan allows about 20 production deploys a month (300 credits, 15 per deploy), and a
# paused site is worse than a stale one. So: code changes always build; data-only commits from the jobs
# build only when DATA_DEPLOY_MINUTES is set (in netlify.toml) and the last deploy is at least that old.
# With it unset, data waits for the next code deploy or a manual "Trigger deploy".
set -u
prev="${CACHED_COMMIT_REF:-}"; cur="${COMMIT_REF:-HEAD}"
[ -z "$prev" ] && exit 1
git cat-file -e "$prev^{commit}" 2>/dev/null || exit 1
if git diff --name-only "$prev" "$cur" | grep -qv '^data/'; then exit 1; fi
# "[deploy]" in a commit message publishes data on demand (one deploy) even when automatic data deploys are off
if git log --format=%B "$prev..$cur" 2>/dev/null | grep -q '\[deploy\]'; then echo "A commit asks for [deploy]: building."; exit 1; fi
if [ -z "${DATA_DEPLOY_MINUTES:-}" ]; then echo "Data-only change and automatic data deploys are off (Free plan deploy budget): skipping."; exit 0; fi
age=$(( $(date +%s) - $(git show -s --format=%ct "$prev") ))
if [ "$age" -ge $(( DATA_DEPLOY_MINUTES * 60 )) ]; then exit 1; fi
echo "Data-only change and the last deploy is $((age / 60)) min old (minimum ${DATA_DEPLOY_MINUTES}): skipping this build."
exit 0
