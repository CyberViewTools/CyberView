# Library reports: read every record, write stories people want to read (2026-11-25)

Status: approved by the owner, 2026-11-25.

## Intent

The Library today is a catalogue: 29,585 report records and 2,010 threat actors mirrored from ORKL, each a title and a set of links. A visitor has to leave CyberView and read a vendor PDF to learn anything.

The owner wants the Library to be something people read on CyberView: Haiku goes through every single record, and Sonnet turns that into write-ups that are "consumable and fun reads for end users". The owner's second instruction sets the bar: "Make sure everything is reviewed and validated and correct as this is a library of fact."

So a story is only worth publishing if a reader can trust every line of it and trace it to the report it came from.

## Goals

- Every report record with readable text gets a short plain-language summary and a set of facts (who, what, when, who was targeted, how, which CVEs and tools).
- Every threat actor gets a profile and a story (owner, 2026-11-25), built from all the reports that name it and its catalogue record. Where little is documented the story is short and says so; it is never padded.
- Reports that name no actor also get a story where the report holds enough detail to tell one (owner, 2026-11-25). Where it does not, the summary is enough.
- Every stated fact in a story traces to a specific report, and the reader can see which.
- Nothing is published until it has passed the script checks and a second review by a run that did not write it.
- The original report stays one click away, on ORKL, as it is today.

## Non-goals

- ORKL reports still never become research leads or event sources. The map and the event pipeline are untouched.
- No translation or republication of reports. Non-English reports (909) are summarised in English; the original stays where it is.
- No viewer workflow state (rule 6).

## Anti-goals (a failure even if it works)

- A story that states something no report says: an invented date, victim, figure, CVE or attribution.
- Attribution written as fact ("X is Russian intelligence") where the report says a vendor assesses it.
- Report text, exploit code, commands or working indicators copied onto CyberView.
- A lively tone that costs accuracy: jokes about victims, dramatised detail, dropped hedges.
- Unreviewed text shown to a visitor.

## What changes about the old rule

`scripts/orkl.mjs` never reads `plain_text` "so the licence and the no-exploit-code rules are never in question". This design reverses "never read" and keeps "never store":

- The report text is fetched, held in memory for one run, checked against, and discarded. It is never written to the repo, the data branch, a log or the site.
- What is stored is CyberView's own words (the summary, the facts, the story) plus short evidence quotes (below).
- The reader is told not to carry over code, commands, payloads, hashes used as instructions, or step-by-step technique detail. A script check refuses fact cards and stories containing code-like blocks.
- Report text is untrusted data. The reader and the writer run with **no tools at all**, so text inside a report that tries to instruct the model cannot make it do anything; the worst it can do is produce a bad card, which the checks and the audit are there to catch.

## Approaches

1. **Fact cards per report, stories per actor, review before publishing (chosen).** Haiku reads every record into a small checked fact card. Sonnet writes one story per actor from the cards only. A second Sonnet run reviews each story against the cards and re-reads original reports. Chosen by the owner: fewer, richer reads (TraderTraitor's 34 reports become one story), every record is still read, and the writer can only work from facts that have already been checked against the source.
2. **One Sonnet article per report.** About 29,600 Sonnet articles. Many records are short, duplicated or purely technical, so many articles would be thin, and the review load would be about fifteen times larger for a weaker result.
3. **Both: actor stories, then articles for the most significant reports.** A sensible later step once approach 1 is measured. Not now: "most significant" needs data the fact cards will provide.

Ruled out early: letting Sonnet write straight from the report text (no checked intermediate, so nothing to validate a sentence against cheaply), and writing from titles and metadata alone (nothing factual to write from).

## How it works

Three stages. Each has a script that plans the work, a model that does one thing, and a script that checks the result before anything is saved. All three run through `scripts/run-job.mjs` like the other desks.

### Stage 1: the reader (Haiku), every record

New role `library-reader`: Haiku, no tools, one turn. New script `scripts/library-read.mjs` (`plan`, `apply`, `status`).

- The script fetches one report's text from ORKL (API `plain_text`, falling back to the archive text file), cleans control characters, and caps it (builder's call on the cap; a capped read is marked `partial`). It passes the text and the record's metadata to the model in a single prompt, one report per call. One report per call because every extra turn re-reads the conversation, and because one report's text must not colour another's card.
- The model returns one JSON fact card:
  - `summary`: 2 to 3 plain sentences on what the report says.
  - `kind`: actor campaign, malware analysis, vulnerability, incident, overview, or not a threat report.
  - `facts`: who (actors as the report names them, and who made the attribution), targets (sectors, countries), when (dates the report states), tools and malware, techniques in plain words, CVEs.
  - `evidence`: for every fact, a short verbatim quote from the report that states it.
  - `confidence` notes: anything the report itself hedges.
- **Script checks before a card is saved** (pure functions in a new `scripts/lib/library-check.mjs`, reusing `NOCODE` from `validate.mjs`; unit-tested):
  - every evidence quote appears verbatim in the fetched text (whitespace-normalised);
  - every CVE id is well-formed and appears in the text;
  - every actor name, tool or malware name, CVE and figure in `facts` appears in its own evidence quote, and a date's year appears in its quote. Sectors, countries and techniques are stated in plain words, so for those the quote must be in the text and the audit and reviewer judge the wording;
  - no code-like blocks; length limits on every field (rule 1).
  - A card that fails is rejected and the record is queued once more. A second failure marks the record `unread` with the reason; it stays link-only on the site.
- Records with no text, or too little to say anything, are marked `no-text` and stay link-only. This is said honestly on the record ("CyberView has not summarised this report").
- Stored additively in `data/orkl/cards/<xx>.json`, sharded by sha1 like the reports. Evidence quotes are capped short (builder's call, about 160 characters) and are kept in the data branch for the reviewer and the audit; they are not rendered on the site.

### Stage 2: the writer (Sonnet), one story per actor

New role `library-writer`: Sonnet, no tools. New script `scripts/library-write.mjs`.

- Input: the actor's ORKL catalogue record (aliases, tools, source) and the fact cards of every report that names it. **Not the report text, and no web.** The writer cannot state what the cards do not hold.
- Every actor gets a profile and a story (owner). The length follows the material:
  - several read reports: the full shape below;
  - one read report: a short story from that card and the catalogue record;
  - no read reports: a profile from the catalogue record alone (name, aliases, tools, who tracks it, and ORKL's description, fetched in passing under the same quote rule), ending with a plain line that no public report in the library describes its operations. Sections with nothing behind them are left out, not filled.
- **Stories without an actor (owner).** A report that names no actor gets a story when its card holds enough to tell one: a subject that can be named (a malware family, a campaign name, a vulnerability, an incident) and at least what it does, who it hit or when. Cards that share the same named subject are combined into one story, like an actor's. A card without a nameable subject or with too few facts keeps its summary only. The script decides eligibility from the card's fields, not the model. These stories pass the same checks and second review, and are stored in `data/orkl/stories/` under a subject key.
- Output shape (required):
  - headline and a one-line "in short";
  - who they are, and who says so;
  - who they go after;
  - how they work, in plain words;
  - notable operations, in date order;
  - what a defender should take from it;
  - every sentence that states a fact ends with the reports it rests on (`[1]`, `[2]`), which map to report sha1s.
- Voice: a good magazine explainer. Short sentences, concrete detail, plain words for techniques, a story with a beginning. No dramatisation, no jokes about victims, hedges kept exactly as the report hedges them.
- Stored in `data/orkl/stories/<actor-id>.json` with status `draft`.

### Stage 3: review and validation

Nothing is shown to a visitor until both parts pass.

**Script checks on every story** (`storyProblems` in `library-check.mjs`; errors block publishing):

- every factual sentence carries at least one citation, and every citation is a card that exists and names this actor;
- every CVE, date, figure, country, sector, tool and malware name in a sentence appears in a card that sentence cites (the same idea as the events' `figure-no-evidence` rule);
- attribution sentences name who attributes ("according to", "assesses", "attributes"), never a bare statement;
- no code-like blocks; length bounds; the required sections are present;
- the AI label is set (rule 15).

**Second review (Sonnet, new role `library-reviewer`, `min_tier` sonnet, a separate run from the writer):**

- Reads the story and its cited cards.
- Re-reads the original text of the reports the story leans on most (builder's call on how many; at least three, or all when the actor has fewer), fetched fresh by the script, to catch a card that is wrong at the root.
- Corrects, or rejects with reasons. Corrections go to the same corrections ledger the event reviewers use, so `node scripts/review.mjs errors` reports the Library's correction rate by role and model next to the events'.
- A passed story gets `reviewed_at` and becomes `published`. A rejected one returns to the writer once, then is parked for the pipeline check to raise.

**Audit of the reader (the cards are the foundation, so they are measured):**

- A fixed share of new cards (builder's call, about 10%) is re-checked by Sonnet against the original text.
- If the audited error rate goes above a threshold (about 5%), the reader pauses, the pipeline check raises "Library reader accuracy below target", and nothing new is published until the owner or the improver job acts.
- The audit result is in `efficiency.json` and on the Status page.

**Keeping stories true over time:**

- A new report that names an actor marks that actor's story `stale`; it is rewritten and reviewed again. The old version stays up until the new one passes.
- A correction to a card marks every story citing it `stale`.
- Each story page links to the existing way of reporting a mistake.

### Pilot gate, then the backfill

- **Pilot:** the 200 most recent reports, the 10 actors with the most reports, 5 actors with one or no reports, and 5 stories without an actor. Every pilot card is audited (100%, not 10%), and the owner reads the twenty stories before anything else runs. The pilot also measures real cost and time per card and per story.
- **Backfill:** only after the owner approves the pilot. Order: actors by report count (so the best-documented stories arrive first), then the remaining reports newest first. It runs on spare capacity: it checks `node scripts/budget.mjs can-build` before each wave and waits while the pipeline needs the window, so the map never publishes less because of the Library.
- **Steady state:** the existing 2-hourly ORKL mirror stays as it is (no model). New records go to the reader; touched actors go to the writer and reviewer.

Cost is not estimated here on purpose: 29,585 reads is a large job and the honest number comes from the pilot.

## What the visitor sees

Library tabs stay as they are (Reports, Actor catalogue, Actors in events, Event archive).

```
Actor catalogue > TraderTraitor   (stories without an actor open the same way from Reports and Featured reads)
┌────────────────────────────────────────────────────────────┐
│ <headline>                                                 │
│ <in short, one line>                                       │
│ CyberView Tools AI · from 34 reports ·          │
│ reviewed 2 Dec 2026                                        │
│                                                            │
│ Who they are ...................................... [1][4] │
│ Who they go after ................................. [2][7] │
│ How they work ..................................... [3]    │
│ Notable operations (timeline) ..................... [5][9] │
│ What defenders should take from it                         │
│                                                            │
│ Sources: 1. <report title> (vendor, date) → on ORKL · PDF  │
│          2. ...                                            │
│ Aliases · Tools · ORKL profile · CyberView profile         │
└────────────────────────────────────────────────────────────┘

Reports > a report
  What this report says: <2–3 sentence summary>
  Who · Targets · Tools · CVEs (linked as elsewhere)
  The report on ORKL · The report (PDF)
```

- A "Featured reads" band at the top of the Library shows the newest reviewed stories.
- An actor without a story, and a report without a card, look as they do today, with one honest line saying it has not been summarised.
- The Library's intro line changes from "CyberView keeps the titles and links; each report is read on ORKL" to say what is now true.
- All text is rendered with `textContent` through `clean*()` functions (rules 1 and 2). Citations are links to the report record.

## Constraints

- Rules 1, 2, 3, 6 and 15 in `CLAUDE.md`. "Facts only from pages actually read."
- Workers are denied git, deletion, curl and wget as today; the two writing roles and the reader get no tools at all.
- Storage is additive (`protectDeletes`).
- Docs that state the old rule must change in the same PR: the header of `scripts/orkl.mjs`, the `orkl` entry in `routines.json`, `docs/jobs.md`, `docs/schema.md`, `docs/legal.md`, `legal/about.html`.
- `config/models.json` gains `library-reader` (haiku), `library-writer` (sonnet), `library-reviewer` (sonnet, in `min_tier`). No Opus.
- Unit tests for every pure check; browser tests for the story and summary views; the security check and docs check pass.

## Calls made here, not by the owner

- How much detail an unattributed report needs before it gets a story, and that cards sharing a named subject are combined.
- An actor with no read reports gets a catalogue-only profile that says so.
- Evidence quotes are stored short in the data branch and not shown on the site.
- The reader audit is about 10% with a pause at about 5% errors; the pilot is 200 reports and 10 actors.
- The backfill yields to the pipeline's usage window.

## Evidence quotes (owner approved, 2026-11-25)

Short evidence quotes from the reports (about a sentence each) would sit in the public data branch so the checks and reviewers can verify facts. The reports belong to their publishers. The alternative is to store no quotes and re-fetch the report every time something is checked, which is slower and makes later audits depend on ORKL being reachable. The owner approved storing the short quotes.

## Left to the builder

The text cap, the exact quote cap, batch sizes and parallelism, the card and story JSON field names, how many reports the reviewer re-reads, the Featured reads layout, and the audit share and threshold within the figures above.
