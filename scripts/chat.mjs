// Community feed: intake and publishing, no AI model. Posts arrive as GitHub issues made with the "Community post"
// form (label "chat"). Nothing reaches the site until it has passed BOTH the fixed rules here and the moderator job.
//   node scripts/chat.mjs intake                      fetch open posts, refuse the ones that break a fixed rule (comment + close),
//                                                    write the rest to data/chat/pending.json for the moderator
//   node scripts/chat.mjs approve <issue> [note]      publish a pending post (data/chat/<YYYY-MM>/<issue>.json), comment, close
//   node scripts/chat.mjs reject <issue> "<reason>"   refuse a pending post: comment with the reason, close; nothing is published
//   node scripts/chat.mjs remove <issue> "<reason>"   take a published post down (kept on file with removed:true; the build leaves it out)
// Issue text is untrusted input from anyone on the internet: it is only ever parsed as data, never executed or interpolated
// into a shell (gh is called with an argument list).
import { spawnSync } from "node:child_process";
import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { DATA, readJson, writeJson, nowIso } from "./lib/store.mjs";

const REPO = "xanderhutch/CyberView";
export const MAX_TEXT = 600, MAX_LINKS = 2, MAX_PER_DAY = 5, MIN_ACCOUNT_DAYS = 3;
export const KINDS = { comment: "comment", tip: "tip", question: "question" };

/** Plain text only: control characters, markup brackets and zero-width tricks out; whitespace collapsed. */
export function cleanText(s) {
  return String(s == null ? "" : s).replace(/<!--[\s\S]*?-->/g, " ").replace(/[\u0000-\u001f\u007f​-‏‪-‮⁠-⁩﻿]/g, " ")
    .replace(/[<>]/g, " ").replace(/\s+/g, " ").trim();
}

/** The body of an issue made with the form -> { text, kind, event_id }. Unknown sections are ignored. */
export function parseForm(body) {
  const sec = {};
  String(body || "").replace(/\r/g, "").split(/^### +/m).slice(1).forEach((part) => {
    const nl = part.indexOf("\n"); if (nl < 0) return;
    const v = part.slice(nl + 1).trim();
    sec[part.slice(0, nl).trim().toLowerCase()] = v === "_No response_" ? "" : v;
  });
  const ev = cleanText(sec["about an event (optional)"] || "").toLowerCase().replace(/^.*#e=/, "");
  return { text: cleanText(sec.message || ""), kind: KINDS[cleanText(sec.kind || "").toLowerCase()] || "comment", event_id: /^[a-z0-9][a-z0-9-]{2,119}$/.test(ev) ? ev : "" };
}

const URL_RE = /\bhttps?:\/\/[^\s"'<>)\]]+/gi;
const SHORTENERS = /^(bit\.ly|t\.co|tinyurl\.com|goo\.gl|is\.gd|ow\.ly|buff\.ly|cutt\.ly|rb\.gy|shorturl\.at|t\.me|discord\.gg|rebrand\.ly|lnkd\.in)$/i;
const BAD_FILE = /\.(exe|scr|msi|bat|cmd|ps1|vbs|js|jar|apk|dmg|iso|zip|rar|7z|lnk|hta|dll)(\?|#|$)/i;
const SECRETS = [/AKIA[0-9A-Z]{16}/, /gh[pousr]_[A-Za-z0-9]{30,}/, /-----BEGIN [A-Z ]*PRIVATE KEY/, /xox[baprs]-[A-Za-z0-9-]{10,}/, /sk-[A-Za-z0-9_-]{20,}/, /eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\./, /\b[A-Fa-f0-9]{40,}\b/, /\b[A-Za-z0-9+/]{60,}={0,2}/, /password\s*[:=]\s*\S{4,}/i];
const INJECT = /ignore (all |any )?(previous|prior|above) (instructions|prompts)|system prompt|you are (now )?(an?|the) (ai|assistant|moderator)|as the moderator|approve this (post|message)|disregard (the|your) rules/i;
const ABUSE = /\b(kys|kill yourself|n[i1]gg(er|a)|f[a4]gg?ot|retard(ed)?|k[i1]ke|tr[a4]nny|wh[o0]re|c[u\*]nt)\b/i;

/**
 * The fixed rules. post: { text, links? }, ctx: { recentByAuthor, accountAgeDays, knownEvent(id) }.
 * Returns { ok: true, links } or { ok: false, reason } where reason is shown to the author.
 */
export function screen(post, ctx = {}) {
  const t = post.text || "";
  const no = (reason) => ({ ok: false, reason });
  if (t.length < 3) return no("The message is empty.");
  if (t.length > MAX_TEXT) return no(`The message is ${t.length} characters; the limit is ${MAX_TEXT}.`);
  if (ctx.accountAgeDays != null && ctx.accountAgeDays < MIN_ACCOUNT_DAYS) return no(`GitHub accounts must be at least ${MIN_ACCOUNT_DAYS} days old to post.`);
  if ((ctx.recentByAuthor || 0) >= MAX_PER_DAY) return no(`The limit is ${MAX_PER_DAY} posts a day.`);
  if (/\b(javascript|data|vbscript|file):/i.test(t)) return no("Only ordinary https links are allowed.");
  const links = [...new Set(t.match(URL_RE) || [])].map((u) => u.replace(/[.,;:!?]+$/, ""));
  if (links.length > MAX_LINKS) return no(`At most ${MAX_LINKS} links per post.`);
  for (const u of links) {
    let x; try { x = new URL(u); } catch { return no("A link is not a valid address."); }
    if (x.protocol !== "https:") return no("Links must be https.");
    if (x.username || x.password || x.port) return no("Links with logins or ports are not allowed.");
    if (/^[\d.]+$/.test(x.hostname) || x.hostname.includes(":") || !x.hostname.includes(".")) return no("Links to raw IP addresses or local names are not allowed.");
    if (/xn--/.test(x.hostname)) return no("Links to look-alike (punycode) domains are not allowed.");
    if (SHORTENERS.test(x.hostname.replace(/^www\./, ""))) return no("Link shorteners and invite links are not allowed; link to the page itself.");
    if (BAD_FILE.test(x.pathname)) return no("Links to downloadable files are not allowed.");
  }
  if (/[\w.+-]+@[\w-]+\.[\w.-]{2,}/.test(t)) return no("Email addresses are not allowed in posts.");
  if (/(\+?\d[\s().-]?){10,}/.test(t.replace(URL_RE, ""))) return no("Phone numbers and long number strings are not allowed in posts.");
  if (SECRETS.some((re) => re.test(t.replace(URL_RE, "")))) return no("The post looks like it contains a credential, key, hash or encoded data. Those do not belong in a public feed.");
  if (INJECT.test(t)) return no("The post reads as instructions to an automated system, not a message to people.");
  if (ABUSE.test(t)) return no("Abusive language is not allowed.");
  const letters = t.replace(/[^A-Za-z]/g, "");
  if (letters.length > 40 && letters.replace(/[^A-Z]/g, "").length / letters.length > 0.7) return no("Please do not write in capitals.");
  if (/(.)\1{9,}/.test(t) || /(\b\w+\b)(\s+\1\b){5,}/i.test(t)) return no("The post is repetitive.");
  if (post.event_id && ctx.knownEvent && !ctx.knownEvent(post.event_id)) return { ok: true, links, event_id: "" };
  return { ok: true, links, event_id: post.event_id || "" };
}

/* ---- GitHub (REST only) ---- */
function gh(args, input) {
  const r = spawnSync("gh", ["api", ...args], { encoding: "utf8", input, timeout: 60000 });
  if (r.status !== 0) throw new Error((r.stderr || "gh failed").trim().split("\n")[0].slice(0, 200));
  return r.stdout ? JSON.parse(r.stdout) : null;
}
const comment = (n, body) => gh(["-X", "POST", `repos/${REPO}/issues/${n}/comments`, "--input", "-"], JSON.stringify({ body }));
const close = (n, reason) => gh(["-X", "PATCH", `repos/${REPO}/issues/${n}`, "--input", "-"], JSON.stringify({ state: "closed", state_reason: reason }));

const chatDir = join(DATA, "chat"), pendingPath = join(chatDir, "pending.json");
export function published() {
  const out = [];
  if (existsSync(chatDir)) for (const m of readdirSync(chatDir).filter((d) => /^\d{4}-\d{2}$/.test(d)))
    for (const f of readdirSync(join(chatDir, m)).filter((f) => f.endsWith(".json"))) { const r = readJson(join(chatDir, m, f)); if (r) out.push(r); }
  return out;
}

function intake() {
  const issues = gh([`repos/${REPO}/issues?labels=chat&state=open&per_page=50&sort=created&direction=asc`]).filter((i) => !i.pull_request);
  const have = published(), pend = [], refused = [];
  const events = new Set(); for (const m of existsSync(join(DATA, "events")) ? readdirSync(join(DATA, "events")) : []) for (const f of readdirSync(join(DATA, "events", m))) events.add(f.replace(/\.json$/, ""));
  for (const i of issues) {
    const author = String(i.user && i.user.login || "").slice(0, 40), post = parseForm(i.body);
    let age = null; try { age = (Date.now() - Date.parse(gh([`users/${encodeURIComponent(author)}`]).created_at)) / 864e5; } catch {}
    const day = Date.now() - 864e5, recent = have.filter((p) => p.author === author && Date.parse(p.at) > day).length + pend.filter((p) => p.author === author).length;
    const isBot = i.user && i.user.type !== "User";
    const res = isBot ? { ok: false, reason: "Automated accounts cannot post." } : screen(post, { recentByAuthor: recent, accountAgeDays: age, knownEvent: (id) => events.has(id) });
    if (!res.ok) {
      comment(i.number, `Thanks for posting. This one was not published: ${res.reason}\n\nThe community rules are on https://xanderhutch.github.io/CyberView/community.html. You are welcome to post again within them.`);
      close(i.number, "not_planned"); refused.push({ issue: i.number, reason: res.reason });
    } else pend.push({ issue: i.number, at: i.created_at, author, kind: post.kind, text: post.text, event_id: res.event_id, links: res.links });
  }
  writeJson(pendingPath, { fetched_at: nowIso(), posts: pend });
  console.log(`chat intake: ${issues.length} open, ${refused.length} refused by the fixed rules, ${pend.length} waiting for the moderator`);
  for (const p of pend) console.log(`PENDING #${p.issue} by ${p.author} (${p.kind}${p.event_id ? ", about " + p.event_id : ""}): ${JSON.stringify(p.text)}`);
  // open reports of published posts, for the moderator
  const reports = gh([`repos/${REPO}/issues?labels=chat-report&state=open&per_page=20`]).filter((i) => !i.pull_request);
  for (const r of reports) console.log(`REPORT #${r.number}: ${JSON.stringify(cleanText(r.body).slice(0, 400))}`);
}

function takePending(n) {
  const d = readJson(pendingPath, { posts: [] }), p = (d.posts || []).find((x) => x.issue === n);
  if (!p) { console.error(`#${n} is not in data/chat/pending.json; run intake first`); process.exit(1); }
  d.posts = d.posts.filter((x) => x.issue !== n); writeJson(pendingPath, d);
  return p;
}

function main() {
  const [cmd, num, ...rest] = process.argv.slice(2), n = Number(num), note = cleanText(rest.join(" ")).slice(0, 200);
  if (cmd === "intake") return intake();
  if (!Number.isInteger(n) || n < 1) { console.error("usage: chat.mjs intake | approve <issue> [note] | reject <issue> <reason> | remove <issue> <reason>"); process.exit(1); }
  if (cmd === "approve") {
    const p = takePending(n);
    const again = screen(p, {}); if (!again.ok) { console.error(`#${n} fails the fixed rules (${again.reason}); it cannot be approved`); process.exit(1); }
    writeJson(join(chatDir, p.at.slice(0, 7), `${n}.json`), { id: n, at: p.at, author: p.author, kind: p.kind, text: p.text, event_id: p.event_id || "", links: again.links, reviewed_at: nowIso(), ...(note ? { note } : {}) });
    comment(n, "Reviewed and published on https://xanderhutch.github.io/CyberView/community.html (it appears after the next site build, a few minutes)."); close(n, "completed");
    console.log(`chat: #${n} published`);
  } else if (cmd === "reject") {
    if (!note) { console.error("a reason is required"); process.exit(1); }
    takePending(n);
    comment(n, `Thanks for posting. After review this one was not published: ${note}\n\nThe community rules are on https://xanderhutch.github.io/CyberView/community.html.`); close(n, "not_planned");
    console.log(`chat: #${n} refused`);
  } else if (cmd === "remove") {
    if (!note) { console.error("a reason is required"); process.exit(1); }
    const f = published().find((p) => p.id === n); if (!f) { console.error(`#${n} is not a published post`); process.exit(1); }
    writeJson(join(chatDir, f.at.slice(0, 7), `${n}.json`), { ...f, removed: true, removed_at: nowIso(), removed_reason: note });
    console.log(`chat: #${n} taken down`);
  } else { console.error(`unknown command "${cmd}"`); process.exit(1); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
