# Handoff: code and data branches (operator runbook)

Owner's decision, 2026-11-20: code on `main` (pull requests only), data on `data` (mounted at `./data`, every job commits
there, each push starts the deploy). Why and how it works: `docs/branches.md`. Tools: `scripts/lib/repo.mjs`,
`scripts/data-branch.mjs`, `scripts/data-commit.mjs`, `scripts/propose.mjs`, `.github/actions/data`,
`.github/workflows/data-forward.yml`.

Repository: `xanderhutch/CyberView`. Run the commands from a checkout of it. Behind the session proxy add
`NODE_USE_ENV_PROXY=1` to node commands that reach the network.

## Stage A: the data branch takes the data

### 1. The data branch exists

```bash
git ls-remote --heads origin data                 # one line = it exists
git fetch origin data && git show origin/data:.forwarded   # the main commit it was made from (or last forwarded)
```

If it does not exist, create it ONCE, from a checkout with full history of `main` (not a shallow clone; subtree split
walks the whole history):

```bash
node scripts/data-branch.mjs create
```

### 2. Workflows commit to the data branch and the deploy follows

```bash
git log --oneline -10 origin/data                 # collect, feeds, cve, linkcheck and job commits appear here
gh run list --workflow collect.yml -L 3           # green; its log shows "Mount the data branch at ./data" checking out data
gh run list --workflow pages.yml -L 10 --json event,status,conclusion,createdAt
                                                  # workflow_dispatch runs within a minute or two of each data push
node scripts/guard.mjs                            # GUARD: healthy (data age, deploy lag)
```

### 3. Every checkout has switched

Each checkout switches at its next job start (`scripts/dispatch.mjs` runs `data-branch.mjs ensure`). In each Claude
session (ops, standby) and any other long-lived checkout:

```bash
node scripts/data-branch.mjs status               # "layout data branch at ./data; origin/data exists"
git -C data rev-parse --abbrev-ref HEAD           # data
git status --short | head                         # no data/ lines at the root
```

`ensure` waits while a research loop is running in that checkout. If a checkout is still on the old layout after two
hours because its loop never stops, check with `node scripts/swarm.mjs board` that the loop is between cycles, end the
loop process (`kill $(node -p 'require("/tmp/cyberview-flow.json").pid')`), and run `node scripts/data-branch.mjs ensure`
there. Uncommitted data is carried over, leases expire by themselves, and the next research schedule (or the standby)
restarts the loop.

### 4. Nothing pushes data to main any more (the condition for stage B)

All three must hold for 24 hours in a row:

```bash
git fetch origin main
git log --oneline --since="24 hours ago" origin/main -- data/      # empty
gh run list --workflow data-forward.yml -L 50 --json conclusion,createdAt,databaseId
                                                  # no runs in 24 h, or each run's log says "up to date" / "forwarded 0 file(s)"
node scripts/guard.mjs                            # no warning about data on main or a checkout on the old layout
```

A commit that does touch `data/` on `main` names its author and job: find that checkout or workflow, run `ensure` there
(or fix the workflow to use `.github/actions/data` and `scripts/data-commit.mjs`), and restart the 24 hours.

Also confirm every workflow that reads `data/` mounts the data branch, so nothing breaks when `main` has no `data/`:

```bash
grep -l "node scripts/" .github/workflows/*.yml | xargs grep -L "actions/data"
```

Each file listed must either not read `data/` at all (check it) or be fixed first, through a pull request. `pages.yml`
and `build.yml` must be among the ones that mount it.

## Stage B: data/ leaves main, rulesets on

**Done 2026-11-20 (B2) by pull request**, after a rehearsal showed the B2 pull below deletes `./data`'s files in a
switched checkout (git removes the paths on disk even under the sparse checkout). Fixed first: `pullAll` moves
`./data` aside for that one pull, commits that would delete never-deleted records are undone (`protectDeletes`), and
the research loop records its code commit and hands over when main moves on, so B2 was merged only once the loop's
leader commit showed code with the safe pull. B4 changed: `data-forward.yml` stays as a safety net. B1 and B3 are the
owner's (repository settings).

### B1. Allow auto-merge

Settings → General → Pull Requests → tick "Allow auto-merge". (`gh api -X PATCH repos/xanderhutch/CyberView -F allow_auto_merge=true`)

### B2. Remove data/ from main by pull request

Back up first: every checkout's data is committed and pushed (`git -C data status --short` empty and
`git -C data log --oneline origin/data..HEAD` empty in each).

```bash
cd "$(mktemp -d)"
git clone --depth 1 https://github.com/xanderhutch/CyberView cv && cd cv
git switch -c stage-b/remove-data
git rm -r -q data
printf '\n# the data branch is mounted here (docs/branches.md)\n/data/\n/data.pre-*/\n' >> .gitignore
git commit -q -m "stage B: data/ lives only on the data branch (docs/branches.md)"
git push -u origin stage-b/remove-data
gh pr create --fill --base main
gh pr checks --watch                              # CI must pass with the data branch mounted
gh pr merge --squash
```

Then, in one switched checkout first (the ops session's, between jobs):

```bash
git pull --ff-only origin main
git -C data status --short                        # empty: ./data untouched
ls data/events | head -3                          # still there
```

If files under `./data` went missing, `git -C data checkout -- .` restores them (they are all committed on `data`).
Then the other checkouts follow at their next job.

A checkout that was still on the old layout would delete its `data/` on this pull; that is why step 4 of stage A must
hold before B2. If one turns up, its uncommitted files are in its `data/` until the pull: copy them aside, run
`node scripts/data-branch.mjs ensure`, and copy back what the data branch lacks.

### B3. Turn on the rulesets

Settings → Rules → Rulesets → New ruleset → New branch ruleset. The exact settings are in `docs/branches.md`
("The rulesets"). In short:

- `main: pull requests and CI`: Active, no bypass, target the default branch; Restrict deletions, Require a pull request
  before merging (0 approvals), Require status checks to pass (`validate`, `browser-tests`, `sql-security-tests`; not
  "up to date"), Block force pushes.
- `data: no force push or deletion`: Active, no bypass, target pattern `data`; Restrict deletions, Block force pushes.

The same with the API (the owner's token needs admin rights on the repository):

```bash
gh api -X POST repos/xanderhutch/CyberView/rulesets --input - <<'JSON'
{"name":"main: pull requests and CI","target":"branch","enforcement":"active","bypass_actors":[],
 "conditions":{"ref_name":{"include":["~DEFAULT_BRANCH"],"exclude":[]}},
 "rules":[{"type":"deletion"},{"type":"non_fast_forward"},
  {"type":"pull_request","parameters":{"required_approving_review_count":0,"dismiss_stale_reviews_on_push":false,
   "require_code_owner_review":false,"require_last_push_approval":false,"required_review_thread_resolution":false}},
  {"type":"required_status_checks","parameters":{"strict_required_status_checks_policy":false,
   "required_status_checks":[{"context":"validate"},{"context":"browser-tests"},{"context":"sql-security-tests"}]}}]}
JSON
gh api -X POST repos/xanderhutch/CyberView/rulesets --input - <<'JSON'
{"name":"data: no force push or deletion","target":"branch","enforcement":"active","bypass_actors":[],
 "conditions":{"ref_name":{"include":["refs/heads/data"],"exclude":[]}},
 "rules":[{"type":"deletion"},{"type":"non_fast_forward"}]}
JSON
```

Check:

```bash
gh api repos/xanderhutch/CyberView/rules/branches/main --jq '.[].type'   # deletion non_fast_forward pull_request required_status_checks
gh api repos/xanderhutch/CyberView/rules/branches/data --jq '.[].type'   # deletion non_fast_forward
git push origin HEAD:main                         # from any checkout: refused ("Changes must be made through a pull request")
```

and that data keeps flowing: a new commit on `origin/data` within the hour and a deploy after it.

### B4. Remove the forwarder, update the docs

One pull request (it is also the first test of the `main` ruleset): delete `.github/workflows/data-forward.yml`; in
`CLAUDE.md` drop "until stage B removes it" from the `data/` line and the data-forward.yml entry; in `docs/branches.md`
mark stage B done; in `swarm/LANES.md` set the migration lane to done. `scripts/data-branch.mjs forward` can stay: with
no `data/` on main it has nothing to do.

## Rollback

### Stage B only (rulesets causing trouble)

Set the ruleset's Enforcement status to Disabled (Settings → Rules → Rulesets → the ruleset), or:

```bash
gh api repos/xanderhutch/CyberView/rulesets --jq '.[] | "\(.id) \(.name)"'
gh api -X PUT repos/xanderhutch/CyberView/rulesets/<id> -f enforcement=disabled
```

The data branch keeps working; nothing else changes.

### Back to data inside main (full rollback)

1. Stop the writers: switch off the "CyberView 4: ..." and "CyberView standby: ..." scheduled tasks (switch off, never
   delete), and `gh workflow disable` each of `collect.yml`, `feeds.yml`, `cve.yml`, `linkcheck.yml`, `data-forward.yml`.
   Disable both rulesets (above): the `main` one would refuse step 3's push, the `data` one step 4's rename.
2. In every checkout, push what is left: `node scripts/data-commit.mjs "data: before rollback"`.
3. Put the data branch's files back into `main` (the data branch has everything `main` had, plus everything since):

   ```bash
   cd "$(mktemp -d)" && git clone https://github.com/xanderhutch/CyberView cv && cd cv
   git fetch origin data
   git rm -r -q --ignore-unmatch data
   git read-tree --prefix=data/ -u origin/data
   git rm -q --cached --ignore-unmatch data/.forwarded && rm -f data/.forwarded
   sed -i '\#^/data/$#d;\#^/data\.pre-\*/$#d' .gitignore    # stage B added these
   git commit -q -m "data: back on main from the data branch (rollback)"
   git push origin HEAD:main
   ```

4. Rename the data branch so nothing switches to it again (its history is kept):
   `gh api -X POST repos/xanderhutch/CyberView/branches/data/rename -f new_name=data-retired`.
   With no `data` branch, `ensure` keeps the old layout and `.github/actions/data` uses `main`'s `data/`.
5. In every switched checkout, back to the old layout:

   ```bash
   git -C data status --short                     # must be empty (step 2)
   git worktree remove --force data
   git worktree prune
   git sparse-checkout disable
   git ls-files -z -- data/ | git update-index --no-skip-worktree -z --stdin
   sed -i '\#^/data/$#d;\#^/data\.pre-\*/$#d' "$(git rev-parse --git-path info/exclude)"
   git pull --rebase origin main
   git checkout -- data/
   node scripts/data-branch.mjs status            # "data/ inside main (old)"
   ```

6. Switch the workflows (`gh workflow enable ...`, not `data-forward.yml`) and the scheduled tasks back on. Check with
   `node scripts/guard.mjs` and `git log --oneline -5 origin/main -- data/`.
