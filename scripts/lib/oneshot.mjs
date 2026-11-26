// The no-tools, single-turn model caller for the Library's reader, writer, reviewer and auditor desks (scripts/library-*.mjs).
// One `claude -p` call: one turn, no tools, no MCP server, so a document that says "run this" has nothing to run. It goes through
// the same environment, API-key fallback decision and usage ledger as every other worker (scripts/run-job.mjs); the prompt is
// never logged and the fallback key is never read here (envFor hands it straight to the spawned process).
import { spawn } from "node:child_process";
import { join } from "node:path";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { ROOT, readJson } from "./store.mjs";
import { LIMIT_RE } from "./usage.mjs";
import { ledgerLine, record, servedNow, fallbackNote, noteOutcome, envFor } from "../run-job.mjs";

const MODELS = readJson(join(ROOT, "config", "models.json"), { roles: {} });

const roleOf = (role, models) => { const r = (models.roles || {})[role]; if (!r || !r.model) throw new Error(`oneshot: unknown role ${role}`); return r; };

/** Pure: the claude command line for one no-tools role. The prompt is not in it: it goes in on stdin (a long report would
 *  overrun the one-argument limit of 131072 bytes, and argv is readable by other processes). */
export function oneShotArgs(role, models = MODELS) {
  const r = roleOf(role, models);
  return ["-p", "--model", r.model, "--max-turns", "1", "--output-format", "json", "--tools", "", "--strict-mcp-config"];
}

/** The first balanced {...} in the text that parses as an object (string-aware), else null. */
function firstJsonObject(s) {
  for (let i = s.indexOf("{"); i >= 0; i = s.indexOf("{", i + 1)) {
    let depth = 0, inStr = false, esc = false;
    for (let j = i; j < s.length; j++) {
      const c = s[j];
      if (inStr) { if (esc) esc = false; else if (c === "\\") esc = true; else if (c === '"') inStr = false; continue; }
      if (c === '"') inStr = true; else if (c === "{") depth++;
      else if (c === "}" && --depth === 0) { try { const o = JSON.parse(s.slice(i, j + 1)); if (o && typeof o === "object" && !Array.isArray(o)) return o; } catch {} break; }
    }
  }
  return null;
}

/** Pure: read claude's JSON envelope. ok = a JSON object was found in the reply; limit = the plan's usage limit said no;
 *  error = the call failed for a reason that is not a reply (no readable envelope, is_error, an API-error terminal_reason). */
export function parseReply(stdout) {
  let env = null; try { env = JSON.parse(String(stdout || "")); } catch {}
  if (!env || typeof env !== "object") return { ok: false, json: null, limit: false, error: true, usage: {} };
  const result = String(env.result == null ? "" : env.result);
  const limit = LIMIT_RE.test(result) && (env.is_error === true || !firstJsonObject(result));
  const json = env.is_error ? null : firstJsonObject(result);
  // error = the call itself failed (an API or envelope error), not "the model replied with something unusable"
  const error = !limit && (env.is_error === true || /error/i.test(String(env.terminal_reason || "")) || env.subtype === "error_during_execution");
  return { ok: !!json, json, limit, error, usage: env.usage && typeof env.usage === "object" ? env.usage : {} };
}

/** Pure: `call` with a per-call timeout (ms) added to its options; 0 leaves the role's own timeout. */
export const withTimeout = (call, ms) => (ms > 0 ? (role, prompt, o = {}) => call(role, prompt, { ...o, timeoutMs: ms }) : call);

/** Pure: the usage-ledger line for one call, as ledgerLine builds it for every worker, then stripped of anything the model wrote: `last`
 *  is "" and `error` is a short code (limit, timeout, exit-<n>, spawn-failed, turn-cap, api-error, no-json), so no reply text, and so no
 *  report text a reply might echo, reaches the committed ledger. ledgerLine itself is unchanged for the other workers.
 *  meta: { timedOut, code (the exit code), spawnFailed }. */
export function ledgerFor(job, role, batch, model, ms, out, err, served, meta = {}) {
  const l = ledgerLine(job, role, batch, model, ms, out, err, served);
  let j = null; try { j = JSON.parse(String(out || "")); } catch {}
  const code = l.limit ? "limit"
    : meta.timedOut ? "timeout"
    : meta.spawnFailed ? "spawn-failed"
    : Number.isInteger(meta.code) && meta.code !== 0 ? `exit-${meta.code}`
    : l.capped ? "turn-cap"
    : !j || typeof j !== "object" ? "no-json"
    : j.is_error ? "api-error"
    : l.error ? "error" : null;
  return { ...l, last: "", error: code };
}

/** One call. Writes one usage-ledger line (role, model, tokens; never the prompt). A parked plan limit returns limit: true without a call. */
export async function oneShot(role, prompt, { job = "library", batch = "", timeoutMs = 0 } = {}) {
  const cfg = roleOf(role, MODELS);
  const served = servedNow();
  if (served === "park") return { ok: false, json: null, limit: true, error: false, note: fallbackNote() };
  const model = cfg.model, roleMs = (Number(cfg.timeout_min) || 6) * 60000, ms = timeoutMs > 0 ? Math.min(roleMs, timeoutMs) : roleMs, t0 = Date.now();   // timeoutMs: the desk's time left, never more than the role's own
  // run from an empty directory so the repository's CLAUDE.md, settings and hooks are not loaded into a no-tools call
  const cwd = mkdtempSync(join(tmpdir(), "cyberview-oneshot-"));
  const { out, err, meta } = await new Promise((resolve) => {
    let out = "", err = "", timedOut = false, spawnFailed = false;
    let ch; try { ch = spawn("claude", oneShotArgs(role), { cwd, env: envFor(served), stdio: ["pipe", "pipe", "pipe"] }); } catch (e) { return resolve({ out: "", err: String(e.message), meta: { spawnFailed: true } }); }
    ch.stdin.on("error", () => {}); ch.stdin.end(String(prompt));
    const kill = setTimeout(() => { timedOut = true; ch.kill("SIGTERM"); setTimeout(() => ch.kill("SIGKILL"), 5000); }, ms);
    ch.stdout.on("data", (d) => { out += d; }); ch.stderr.on("data", (d) => { err += d; });
    ch.on("error", (e) => { spawnFailed = true; err += String(e.message); });
    ch.on("close", (code) => { clearTimeout(kill); resolve({ out, err: timedOut ? "timeout" : code !== 0 && !out ? (err.trim().split("\n").pop() || `exit ${code}`).slice(0, 160) : null, meta: { timedOut, spawnFailed, code } }); });
  });
  try { rmSync(cwd, { recursive: true, force: true }); } catch {}
  const l = ledgerFor(job, role, batch, model, Date.now() - t0, out, err, served, meta);
  record(l); noteOutcome(l, served);
  const r = parseReply(out);
  // error: the call itself failed (spawn failure, timeout, non-zero exit with no result, envelope error); the caller must not count it as a bad reply
  return { ok: r.ok && l.ok, json: r.json, limit: r.limit || !!l.limit, error: !(r.limit || l.limit) && (r.error || !!err) };
}
