// Grok watch (no AI model): surfaces everything "Grok" has said on the repo so Claude, who leads, can act on it.
// Grok has no GitHub account; its briefs are relayed as issues whose title starts with "[Grok]" (and comments
// that carry the same marker). This reads them through the GitHub REST API (gh), shows what is still open and
// unhandled (no linked pull request, no reply from Claude), and prints a digest. It writes nothing and acts on
// nothing: Grok's briefs are proposals to weigh, not commands; a person still gates every merge and outward action.
//   node scripts/grok-watch.mjs            digest of open [Grok] items, unhandled first
//   node scripts/grok-watch.mjs --all      include handled/closed
//   node scripts/grok-watch.mjs --json     machine-readable
import { execFileSync } from "node:child_process";

const REPO = process.env.GROK_REPO || "xanderhutch/CyberView";
const MARK = /^\s*\[grok\b/i;                       // the "[Grok]" title/label marker
const has = (f) => process.argv.includes(f);
const gh = (path, q = "") => { try { return JSON.parse(execFileSync("gh", ["api", `repos/${REPO}/${path}${q}`], { encoding: "utf8", maxBuffer: 8e6 })); } catch { return []; } };
const short = (s, n) => String(s || "").replace(/\s+/g, " ").trim().slice(0, n);

// open+recent issues (not pull requests) whose title carries the Grok marker
const issues = (gh("issues", "?state=all&per_page=50&sort=created&direction=desc") || [])
  .filter((i) => i && !i.pull_request && MARK.test(i.title || ""));

const items = issues.map((i) => {
  const comments = i.comments ? (gh(`issues/${i.number}/comments`) || []) : [];
  // handled = a reply from Claude, or a pull request that mentions this issue, or the issue is closed.
  // A comment relayed FROM Grok (a brief follow-up) is addressed to @claude and/or signed "Grok Bot"; it is NOT a reply
  // from Claude. The old check matched the "@claude" mention inside Grok's own message and marked every brief handled,
  // so a fresh brief with only a Grok follow-up (e.g. #82, 22 Nov 2026) was silently hidden. Count only non-relay comments.
  const isGrokMsg = (c) => /\bgrok bot\b|\[grok\b|^\s*@claude\b/i.test((c && c.body) || "");
  const claudeReplied = comments.some((c) => !isGrokMsg(c));
  const linkedPr = (gh("pulls", `?state=all&per_page=100`) || []).some((p) => new RegExp(`#${i.number}\\b`).test((p.body || "") + " " + (p.title || "")));
  const handled = i.state === "closed" || claudeReplied || linkedPr;
  return { number: i.number, title: i.title, state: i.state, created: i.created_at, author: i.user && i.user.login,
    comments: comments.length, claudeReplied, linkedPr, handled,
    brief: short(i.body, 200), lastComment: comments.length ? short(comments[comments.length - 1].body, 160) : "" };
});

const show = has("--all") ? items : items.filter((x) => !x.handled);
show.sort((a, b) => (a.handled - b.handled) || (a.number - b.number));

if (has("--json")) { console.log(JSON.stringify({ repo: REPO, at: new Date().toISOString(), total: items.length, unhandled: items.filter((x) => !x.handled).length, items: show }, null, 1)); }
else {
  const open = items.filter((x) => !x.handled).length;
  console.log(`GROK WATCH (${REPO}): ${items.length} [Grok] item(s), ${open} unhandled.`);
  for (const x of show) {
    console.log(`\n#${x.number} ${x.handled ? "(handled)" : "[UNHANDLED]"} ${x.title}`);
    console.log(`  by ${x.author} · ${x.created} · ${x.comments} comment(s)${x.linkedPr ? " · has PR" : ""}${x.claudeReplied ? " · Claude replied" : ""}`);
    if (x.brief) console.log(`  brief: ${x.brief}`);
    if (x.lastComment) console.log(`  last: ${x.lastComment}`);
  }
  if (!show.length) console.log("  nothing waiting.");
}
