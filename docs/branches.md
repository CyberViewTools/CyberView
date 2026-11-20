# Code and data branches

CyberView keeps its code and its data on two branches of the same repository. The owner decided this on 2026-11-20.
This page explains the reasons, how the two branches fit together, and how to work with them. The operator's
step-by-step runbook for the switch-over is `swarm/handoff/data-branch.md`.

## Why

- **Code needs protection.** Until now every job pushed straight to `main`, so `main` could not be protected: a rule
  that blocked direct pushes would have stopped the data. With the data on its own branch, `main` can require a pull
  request and a passing CI run for every code change, with no exceptions.
- **Data must stay fast.** Jobs commit data hundreds of times a day. Those commits must not wait for a pull request or
  a review. They go straight to the `data` branch, and each push starts the deploy at once, so new events reach the site
  as fast as before.
- **Readable history.** `main`'s history shows code changes only. Data history is kept in full on `data`.

## The two branches

| Branch | Holds | Changed by | Protection (stage B) |
|---|---|---|---|
| `main` | the code: `site/`, `scripts/`, `tests/`, `config/`, `docs/`, `legal/`, `pages/`, `supabase/`, `.github/`, `routines.json` | pull requests only, merged when CI passes (auto-merge) | pull request required, CI status checks required, no force push, no deletion, no bypass |
| `data` | what used to be the `data/` folder; the branch root is that folder, so `data/events/...` on main is `events/...` here | every automated job, directly | no force push, no deletion |

The `data` branch was made from `main` with `git subtree split`, so every data file keeps its full history. Its file
`.forwarded` records the last `main` commit whose `data/` changes were brought over (see stage A below).

Two other branches are unaffected: `cve-data` (superseded, rebuilt by hand by `cve-db.yml`) and the `bot/<job>-<time>`
branches that jobs open pull requests from.

## How a checkout is laid out

Every checkout (the Claude sessions, a developer's clone, every GitHub Actions run) has the code of `main` at the root
and the `data` branch mounted at `./data`:

- **Locally** `./data` is a git worktree of the `data` branch. `main`'s own copy of `data/` is left out with a sparse
  checkout (`/*` and `!/data/`), its index entries are marked skip-worktree, and `/data/` is in `.git/info/exclude`, so
  `git status` at the root never shows data files. `node scripts/data-branch.mjs ensure` sets all of this up.
- **In GitHub Actions** the workflow checks out `main` without `data/` (sparse checkout) and then the step
  `./.github/actions/data` checks out the `data` branch at `./data`. Until the `data` branch exists, that step puts
  `main`'s own `data/` back instead.

Scripts read and write `data/...` exactly as before. Only committing and pushing differ, and `scripts/lib/repo.mjs` is
the one place that knows how: `dataMode()` says `branch` when `./data` is the `data` branch and `main` for the old layout,
which still works for a checkout that has not switched yet.

## How a data commit reaches the site

1. A job writes files under `data/` (events, run logs, leads, `status.json`).
2. It commits with `node scripts/finish.mjs <job>` (the Claude jobs) or `node scripts/data-commit.mjs "<message>" [paths]`
   (the data workflows and single jobs). The commit is made inside `./data`, on the `data` branch.
3. `scripts/git-sync.mjs` pushes it to `origin/data`. If another job pushed in the meantime it rebases, merging
   `status.json` and other JSON objects by key and lead files by union of lines; any other conflict stops it without
   merging anything blindly. Up to 5 tries.
4. After a push that changed anything besides `leases.json` and `usage/`, `dispatchDeploy()` starts
   `.github/workflows/pages.yml` on `main` through the GitHub API (`workflow_dispatch`). This is needed because a push to
   `data` does not trigger the deploy's push trigger, and pushes made with a workflow's own token start no workflows at
   all. Workflows that commit data therefore need `actions: write`.
5. `pages.yml` checks out `main`, mounts the `data` branch, builds with `--quarantine` (a broken record is left out and
   reported, never blocks the rest), verifies the build, publishes to GitHub Pages and checks the live copy.

A deploy that does not happen is noticed by `scripts/guard.mjs` and the guardian, which start `pages.yml` again.

## How code changes reach main

People and interactive Claude sessions:

```bash
git fetch origin main
git switch -c fix/short-name origin/main
# edit, then: npm run ci  (or at least node scripts/build.mjs and node scripts/security-check.mjs)
git commit -am "what changed and why"
git push -u origin fix/short-name
gh pr create --fill --base main
gh pr merge --auto --squash        # merges by itself once CI passes
```

Never put data files in a code branch, and never push to `main` directly.

Scheduled jobs: a job that changes `config/` or `docs/` (the improver tuning `config/pipeline.json` and
`config/models.json`, the scout adding a feed to `config/feeds.json`) does not push it. `scripts/finish.mjs` calls
`node scripts/propose.mjs <job>`, which copies the changed files onto a new branch `bot/<job>-<time>` made from
`origin/main`, pushes it, opens a pull request and switches on auto-merge (squash). The checkout's own copy is then put
back to `main`'s version; the change arrives with the next pull once the pull request has merged. A job never changes
other code; it opens a GitHub issue instead.

Auto-merge only works when it is allowed in the repository (Settings, General, Pull Requests, "Allow auto-merge").
Without it a job's pull request waits for the owner. Pull requests opened with a workflow's own `GITHUB_TOKEN` start no
CI run, so `propose.mjs` runs in the Claude sessions with their own GitHub credentials, never from a workflow.

## Running things on your own computer

```bash
git clone https://github.com/xanderhutch/CyberView && cd CyberView
node scripts/data-branch.mjs ensure     # mounts the data branch at ./data (does nothing until the branch exists)
node scripts/data-branch.mjs status     # which layout this checkout uses, and whether origin/data exists
npm run build                           # or: npm run preview, npm run ci
```

Staying up to date:

```bash
git pull --ff-only origin main                        # code
git -C data pull --rebase --autostash origin data     # data (only when status says the data branch is at ./data)
```

Committing a data fix by hand (for example a correction to an event):

```bash
node scripts/build.mjs                                # never commit if it fails
node scripts/data-commit.mjs "data: correct <event id>" data/events/2026-11/<id>.json data/corrections/<file>.json
```

`git status` at the root shows code changes only; `git -C data status` shows data changes.

## Recovering a checkout

`node scripts/data-branch.mjs ensure` is safe to run again at any time, and is the first thing to try.

- **`./data` is missing, empty, or a plain folder of `main`'s files** (a switch was interrupted): run `ensure`. It keeps
  a copy of the folder as `data.pre-<time>/`, mounts the `data` branch, and carries over every file that differed from
  `main`'s committed copy (line files by union, JSON by key). The copy is git-ignored; delete it after a day.
- **`git status` at the root lists thousands of `data/` files**: run `ensure` again; it re-applies the sparse checkout and
  the skip-worktree flags.
- **Data commits do not get pushed** (`PUSH FAILED`): look at `git -C data status` and
  `git -C data log --oneline origin/data..HEAD`. If a rebase is stuck, `git -C data rebase --abort`, then run
  `node scripts/git-sync.mjs` from the root. Files with conflict markers are left out of commits and named by
  `finish.mjs`; fix them in `./data` and commit again.
- **Start the data mount over**: commit or copy anything uncommitted first, then
  `mv data data.pre-manual && git worktree prune && node scripts/data-branch.mjs ensure`, and copy back any file from
  `data.pre-manual/` that the `data` branch does not have yet.
- **Back to the old layout** (only for a full rollback): `swarm/handoff/data-branch.md`, Rollback.

## The switch-over

**Stage A (done 2026-11-20).** The `data` branch exists and takes the data. Each checkout switches the first time a job starts
there (`scripts/dispatch.mjs` runs `data-branch.mjs ensure`; it waits while a research loop is running in that
checkout). Anything still pushing data to `main` (a checkout not yet switched, an old workflow) is forwarded by
`.github/workflows/data-forward.yml`, which runs `data-branch.mjs forward` and brings those changes onto `data` with the
same merge rules, so nothing is lost. `main` still contained its old copy of `data/`, unused.

**Stage B (done 2026-11-20).** `data/` was removed from `main` by a pull request once every checkout ran the safe
pull (`pullAll` moves `./data` aside for the one pull that drops it; without that, git deletes those paths on disk even
under the sparse checkout). `data-forward.yml` stays as a safety net with nothing to do, and the owner turns on two
rulesets. The exact commands and checks are in
`swarm/handoff/data-branch.md`.

### The rulesets (Settings → Rules → Rulesets → New ruleset → New branch ruleset)

Ruleset 1, for `main`:

| Setting | Value |
|---|---|
| Ruleset Name | `main: pull requests and CI` |
| Enforcement status | Active |
| Bypass list | empty (no bypass, not even for admins) |
| Target branches | Add target → Include default branch (`main`) |
| Restrict creations | off |
| Restrict updates | off |
| Restrict deletions | **on** |
| Require linear history | off |
| Require deployments to succeed | off |
| Require signed commits | off (the bots' commits are not signed) |
| Require a pull request before merging | **on**; Required approvals **0** (GitHub does not let an author approve their own pull request, and job pull requests must merge by themselves); Dismiss stale pull request approvals, Require review from Code Owners, Require approval of the most recent reviewable push, Require conversation resolution: all off; Allowed merge methods: keep Squash allowed (`propose.mjs` uses it) |
| Require status checks to pass | **on**; Add checks: `validate`, `browser-tests`, `sql-security-tests` (the jobs of `build.yml`, source GitHub Actions); Require branches to be up to date before merging: off (otherwise every job pull request needs a rebase before it can merge) |
| Block force pushes | **on** |
| Require code scanning results | off |

A check can only be added once it has run in the last week; if one is missing from the search, open any pull request
first so CI runs.

Ruleset 2, for `data`:

| Setting | Value |
|---|---|
| Ruleset Name | `data: no force push or deletion` |
| Enforcement status | Active |
| Bypass list | empty |
| Target branches | Add target → Include by pattern → `data` |
| Restrict deletions | **on** |
| Block force pushes | **on** |
| everything else | off: jobs push directly, with no pull request and no status checks; do not turn on Restrict updates |

The pattern `data` matches only the branch named `data`, not `cve-data`, which `cve-db.yml` still force-pushes.
