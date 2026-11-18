#!/usr/bin/env bash
# Starts the mechanical workflows when GitHub's scheduler has not run them recently.
# GitHub has never fired this repository's cron schedules, so the hourly sweep calls this first.
# If the schedules do start working, every workflow will have a recent run and this does nothing.
# Usage: bash scripts/kick.sh        (needs gh; uses the REST API only)
set -u
REPO=xanderhutch/CyberView
now=$(date -u +%s)
# workflow, start it when its newest run (any trigger) is older than this many minutes
specs="collect.yml 40|feeds.yml 110|monitor.yml 70|markets.yml 290|linkcheck.yml 10080"
# email alerts only once accounts are configured
if node -e 'process.exit(require("./config/accounts.json").supabase_url ? 0 : 1)' 2>/dev/null; then specs="$specs|alerts.yml 70"; fi
IFS='|'; for spec in $specs; do unset IFS
  set -- $spec; wf=$1; max=$2
  last=$(gh api "repos/$REPO/actions/workflows/$wf/runs?per_page=1" -q '.workflow_runs[0].created_at // ""' 2>/dev/null)
  age=999999
  if [ -n "$last" ]; then age=$(( (now - $(date -u -d "$last" +%s)) / 60 )); fi
  if [ "$age" -ge "$max" ]; then
    if gh api -X POST "repos/$REPO/actions/workflows/$wf/dispatches" -f ref=main >/dev/null 2>&1; then
      echo "kick: started $wf (last run ${age} min ago)"
    else
      echo "kick: could not start $wf"
    fi
  else
    echo "kick: $wf ran ${age} min ago, fine"
  fi
done
