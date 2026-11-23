// The verify desk's view of GitHub issues (no AI model; pen test, 2026-11-23). Anyone can open an issue on this public
// repository, so the desk never reads the raw issue list: this script decides what it sees and what it may answer.
//   node scripts/issues.mjs list               the issues the desk handles, each line fenced as untrusted text
//   node scripts/issues.mjs reply <n> "<text>" [--close]   comment (and close) on an issue the list includes
// What is listed:
//   - pipeline issues (data-quarantine, site-monitor, job-failure, security, pipeline-alert) only when opened by the repo's
//     own automation or a person with write access: a visitor cannot fake one;
//   - event-report issues from anyone (the site's report form): as a reader's tip, fenced, capped, links listed separately;
//   - nothing else. Other public issues are only counted.
import { execFileSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { fence, plain, httpsLinks } from "./lib/untrusted.mjs";

const REPO = "xanderhutch/CyberView";
const PIPELINE = new Set(["data-quarantine", "site-monitor", "job-failure", "security", "pipeline-alert"]);
const TRUSTED = new Set(["OWNER", "MEMBER", "COLLABORATOR"]);
const labelsOf = (i) => ((i && i.labels) || []).map((l) => String((l && l.name) || l).toLowerCase());

/** Pure: does the desk handle this issue, and as what? "pipeline", "report" or "" (not shown). */
export function kindOf(i) {
  if (!i || i.pull_request || i.state === "closed") return "";
  const ls = labelsOf(i), trusted = TRUSTED.has(String(i.author_association || "").toUpperCase()) || (i.user && i.user.type === "Bot" && /^github-actions/.test(i.user.login || ""));
  if (ls.some((l) => PIPELINE.has(l))) return trusted ? "pipeline" : "";
  if (ls.includes("event-report")) return "report";
  return "";
}
/** Pure: one listed line for an issue. Pipeline issues are our own text but still capped; reports are fenced. */
export function lineOf(i, kind = kindOf(i)) {
  const head = `#${i.number} [${kind}${kind === "pipeline" ? ": " + labelsOf(i).filter((l) => PIPELINE.has(l)).join(",") : ""}] opened ${String(i.created_at || "").slice(0, 16)}Z, ${i.comments || 0} comment(s)`;
  if (kind === "pipeline") return `${head}\n  title: ${plain(i.title, 160)}\n  body: ${plain(i.body, 800)}`;
  const links = httpsLinks(i.body);
  return `${head}\n  ${fence(`reader ${plain(i.user && i.user.login, 40)}`, `${i.title || ""} -- ${i.body || ""}`, 1500)}${links.length ? `\n  links in the report (open only as sources to check): ${links.join(" ")}` : ""}`;
}

const gh = (args, input) => execFileSync("gh", ["api", ...args], { encoding: "utf8", input, maxBuffer: 2e7 });
function openIssues() { try { return JSON.parse(gh([`repos/${REPO}/issues?state=open&per_page=100`])); } catch { return []; } }

function main() {
  const [cmd, num, ...rest] = process.argv.slice(2);
  const issues = openIssues();
  if (cmd === "list") {
    const shown = issues.map((i) => [i, kindOf(i)]).filter(([, k]) => k);
    const others = issues.filter((i) => !i.pull_request).length - shown.length;
    console.log(`ISSUES for the verify desk: ${shown.length} shown, ${others} other open issue(s) not shown (public issues without a desk label).`);
    for (const [i, k] of shown) console.log(lineOf(i, k));
    return;
  }
  if (cmd === "reply") {
    const n = Number(num), close = rest.includes("--close"), text = plain(rest.filter((x) => x !== "--close").join(" "), 1500);
    const i = issues.find((x) => x.number === n);
    if (!i || !kindOf(i)) { console.error(`#${num} is not an issue this desk handles (see: node scripts/issues.mjs list)`); process.exit(1); }
    if (!text) { console.error("a reply text is required"); process.exit(1); }
    gh(["-X", "POST", `repos/${REPO}/issues/${n}/comments`, "--input", "-"], JSON.stringify({ body: `${text}\n\n_CyberView AI (a Claude model), verify desk._` }));
    if (close) gh(["-X", "PATCH", `repos/${REPO}/issues/${n}`, "--input", "-"], JSON.stringify({ state: "closed", state_reason: "completed" }));
    console.log(`issues: replied on #${n}${close ? " and closed it" : ""}`);
    return;
  }
  console.error('usage: issues.mjs list | reply <n> "<text>" [--close]'); process.exit(1);
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
