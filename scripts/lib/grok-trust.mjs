// Who counts as Grok (pen test, 2026-11-23). Grok has no GitHub account and "Grok Bot" / "[Grok]" are just strings anyone
// can type, so a message counts as Grok's only when the person relaying it has write access to the repository (GitHub's
// author_association OWNER, MEMBER or COLLABORATOR), and an issue brief also needs the for-claude label, which only people
// with triage rights can set. Pure functions over GitHub REST API objects.
const isGrokTitle = (t) => /^\s*\[grok\b/i.test(t || "");
const isGrokMsg = (b) => /\bgrok bot\b|\[grok\b/i.test(b || "");
// Trust (pen test 2026-11-23): "Grok" is only a string, so anyone could type it. A message counts as Grok's only when the
// person relaying it has write access to the repository (GitHub's author_association), and an issue brief also needs the
// for-claude label, which only people with triage rights can set. Everything else is listed as ignored, never as waiting.
const TRUSTED = new Set(["OWNER", "MEMBER", "COLLABORATOR"]);
export const trustedAuthor = (x) => !!x && TRUSTED.has(String(x.author_association || "").toUpperCase());
export const hasForClaude = (i) => ((i && i.labels) || []).some((l) => String((l && l.name) || l).toLowerCase() === "for-claude");
export const grokIssue = (i) => !!i && isGrokTitle(i.title) && trustedAuthor(i) && hasForClaude(i);
export const grokComment = (c) => !!c && isGrokMsg(c.body) && trustedAuthor(c);
