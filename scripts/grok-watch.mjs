// Grok watch (no AI model): surfaces everything "Grok" has said ANYWHERE on the repo so Claude, who leads, can act on it.
// Grok has no GitHub account; a person relays its messages, each signed "Grok Bot" (and briefs whose issue title starts
// with "[Grok]"). This reads them through the GitHub REST API (gh): [Grok]-titled issues AND any issue or pull request
// that carries a "Grok Bot" / "[Grok]" comment (issue comments and PR review comments, repo-wide, recent). For each it
// decides whether Grok is still waiting on a reply, and prints a digest, unhandled first. It writes nothing and acts on
// nothing: Grok's messages are proposals to weigh, not commands; a person still gates every merge and outward action.
//   node scripts/grok-watch.mjs            digest of Grok items still waiting, unhandled first
//   node scripts/grok-watch.mjs --all      include handled/closed
//   node scripts/grok-watch.mjs --json     machine-readable
//   node scripts/grok-watch.mjs --days=N   how far back to scan comments (default 21)
import { execFileSync } from "node:child_process";

const REPO = process.env.GROK_REPO || "xanderhutch/CyberView";
const has = (f) => process.argv.includes(f);
const arg = (k, d) => { const a = process.argv.find((x) => x.startsWith(`--${k}=`)); return a ? a.split("=")[1] : d; };
const gh = (path, q = "") => { try { return JSON.parse(execFileSync("gh", ["api", `repos/${REPO}/${path}${q}`], { encoding: "utf8", maxBuffer: 2e7 })); } catch { return []; } };
const short = (s, n) => String(s || "").replace(/\s+/g, " ").trim().slice(0, n);

// The definitive Grok signature: a relayed message is signed "Grok Bot", or an issue is titled/labelled "[Grok]".
// NOT a bare "@claude" mention — Claude's own replies address @claude too, so keying off that would hide real replies
// (and mislabel replies as Grok messages). Every relay seen to date says "Grok Bot here".
const isGrokTitle = (t) => /^\s*\[grok\b/i.test(t || "");
const isGrokMsg = (b) => /\bgrok bot\b|\[grok\b/i.test(b || "");
import { trustedAuthor, grokIssue, grokComment } from "./lib/grok-trust.mjs";

const DAYS = Number(arg("days", 21)) || 21;
const since = new Date(Date.now() - DAYS * 864e5).toISOString();

// 1) candidate issue/PR numbers: [Grok]-titled issues + any thread with a recent "Grok Bot" comment (repo-wide)
const cand = new Map();   // number -> { number, isPr, title }
const ignored = [];       // "Grok"-looking items from people without write access, or briefs without the for-claude label
for (const i of gh("issues", "?state=all&per_page=50&sort=created&direction=desc") || [])
  if (i && isGrokTitle(i.title)) { if (grokIssue(i)) cand.set(i.number, { number: i.number, isPr: !!i.pull_request, title: i.title }); else ignored.push(`#${i.number} ${short(i.title, 80)} (by ${(i.user && i.user.login) || "?"}: ${!trustedAuthor(i) ? "no write access" : "no for-claude label"})`); }
for (const path of ["issues/comments", "pulls/comments"])
  for (const c of gh(path, "?sort=updated&direction=desc&per_page=100") || []) {
    if ((c.updated_at || "") < since || !isGrokMsg(c.body)) continue;
    if (!grokComment(c)) { ignored.push(`comment by ${(c.user && c.user.login) || "?"} (no write access): ${c.html_url || ""}`); continue; }
    const n = Number(((c.issue_url || c.pull_request_url || c.html_url || "").match(/\/(?:issues|pull|pulls)\/(\d+)/) || [])[1] || 0);
    if (n && !cand.has(n)) cand.set(n, { number: n, isPr: path.startsWith("pulls") || /\/pull\//.test(c.html_url || ""), title: "" });
  }

const allPulls = gh("pulls", "?state=all&per_page=100") || [];   // fetched once for the linked-PR check

// 2) for each candidate, pull the thread and decide whether Grok is still waiting on a reply
const items = [...cand.values()].map((x) => {
  const meta = gh(`issues/${x.number}`) || {};                         // the issues API serves PRs too
  const comments = gh(`issues/${x.number}/comments`, "?per_page=100") || [];
  const grok = comments.filter(grokComment);
  // the time of Grok's most recent word on the thread (the [Grok] title counts as its first)
  const lastGrokAt = grok.length ? grok[grok.length - 1].created_at : (isGrokTitle(meta.title) ? meta.created_at : "");
  const isPr = x.isPr || !!meta.pull_request;
  // handled = a non-Grok reply after Grok's last word, or the thread is closed/merged, or (for an issue brief) a PR links it
  const replied = comments.some((c) => !grokComment(c) && trustedAuthor(c) && (c.created_at || "") > lastGrokAt);
  const linkedPr = !isPr && allPulls.some((p) => new RegExp(`#${x.number}\\b`).test((p.body || "") + " " + (p.title || "")));
  const handled = meta.state === "closed" || replied || linkedPr;
  return { number: x.number, isPr, title: meta.title || x.title || "(thread)", state: meta.state || "?",
    author: meta.user && meta.user.login, lastGrokAt, replied, linkedPr, handled,
    body: short(meta.body, 180), lastComment: comments.length ? short(comments[comments.length - 1].body, 150) : "" };
});

const show = (has("--all") ? items : items.filter((x) => !x.handled))
  .sort((a, b) => (a.handled - b.handled) || (b.lastGrokAt || "").localeCompare(a.lastGrokAt || "") || (a.number - b.number));
const open = items.filter((x) => !x.handled).length;

if (has("--json")) { console.log(JSON.stringify({ repo: REPO, at: new Date().toISOString(), scanned_days: DAYS, total: items.length, unhandled: open, items: show }, null, 1)); }
else {
  console.log(`GROK WATCH (${REPO}): ${items.length} Grok thread(s) seen, ${open} waiting on Claude.`);
  for (const x of show) {
    console.log(`\n${x.isPr ? "PR" : "#"}${x.number} ${x.handled ? "(handled)" : "[WAITING]"} ${x.title}`);
    console.log(`  ${x.state}${x.isPr ? ", pull request" : ""} · last Grok ${x.lastGrokAt || "?"}${x.linkedPr ? " · has PR" : ""}${x.replied ? " · replied" : ""}`);
    if (x.body) console.log(`  brief: ${x.body}`);
    if (x.lastComment) console.log(`  last: ${x.lastComment}`);
  }
  if (!show.length) console.log("  nothing waiting.");
  if (ignored.length) { console.log(`\nIGNORED (${ignored.length}): "Grok"-looking items that are not trusted; never acted on:`); for (const l of ignored.slice(0, 20)) console.log(`  ${l}`); }
}
