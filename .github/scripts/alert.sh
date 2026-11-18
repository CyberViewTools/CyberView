#!/usr/bin/env bash
# Opens, updates or closes one GitHub issue per alert type, so a long outage is one issue, not hundreds.
# Usage: alert.sh <label> <title> <report.md> <failing|healthy>
# Needs GH_TOKEN with issues: write (the workflow passes github.token).
set -euo pipefail
label="$1"; title="$2"; report="$3"; state="$4"
gh label create "$label" --color B60205 --description "Opened automatically by a CyberView check" --force >/dev/null 2>&1 || true
open=$(gh issue list --label "$label" --state open --json number --jq '.[0].number // empty')
run="${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-}/actions/runs/${GITHUB_RUN_ID:-}"
if [ "$state" = "failing" ]; then
  body="$(cat "$report")

Run: $run"
  if [ -n "$open" ]; then
    # comment at most once an hour so a long outage does not flood the issue
    last=$(gh issue view "$open" --json comments --jq '.comments[-1].createdAt // empty')
    if [ -z "$last" ] || [ $(( $(date +%s) - $(date -d "$last" +%s) )) -gt 3300 ]; then gh issue comment "$open" --body "$body"; fi
  else
    gh issue create --title "$title" --label "$label" --body "$body"
  fi
elif [ -n "$open" ]; then
  gh issue comment "$open" --body "Recovered: $(head -1 "$report")

Run: $run"
  gh issue close "$open"
fi
