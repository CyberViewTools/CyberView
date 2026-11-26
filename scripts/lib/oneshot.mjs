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

/** Pure: read claude's JSON envelope. ok = a JSON object was found in the reply; limit = the plan's usage limit said no. */
export function parseReply(stdout) {
  let env = null; try { env = JSON.parse(String(stdout || "")); } catch {}
  if (!env || typeof env !== "object") return { ok: false, json: null, limit: false, usage: {} };
  const result = String(env.result == null ? "" : env.result);
  const limit = LIMIT_RE.test(result) && (env.is_error === true || !firstJsonObject(result));
  const json = env.is_error ? null : firstJsonObject(result);
  return { ok: !!json, json, limit, usage: env.usage && typeof env.usage === "object" ? env.usage : {} };
}

/** One call. Writes one usage-ledger line (role, model, tokens; never the prompt). A parked plan limit returns limit: true without a call. */
export async function oneShot(role, prompt, { job = "library", batch = "" } = {}) {
  const cfg = roleOf(role, MODELS);
  const served = servedNow();
  if (served === "park") return { ok: false, json: null, limit: true, note: fallbackNote() };
  const model = cfg.model, ms = (Number(cfg.timeout_min) || 6) * 60000, t0 = Date.now();
  // run from an empty directory so the repository's CLAUDE.md, settings and hooks are not loaded into a no-tools call
  const cwd = mkdtempSync(join(tmpdir(), "cyberview-oneshot-"));
  const { out, err } = await new Promise((resolve) => {
    let out = "", err = "";
    let ch; try { ch = spawn("claude", oneShotArgs(role), { cwd, env: envFor(served), stdio: ["pipe", "pipe", "pipe"] }); } catch (e) { return resolve({ out: "", err: String(e.message) }); }
    ch.stdin.on("error", () => {}); ch.stdin.end(String(prompt));
    const kill = setTimeout(() => { ch.kill("SIGTERM"); setTimeout(() => ch.kill("SIGKILL"), 5000); err += "timeout"; }, ms);
    ch.stdout.on("data", (d) => { out += d; }); ch.stderr.on("data", (d) => { err += d; });
    ch.on("error", (e) => { err += String(e.message); });
    ch.on("close", (code) => { clearTimeout(kill); resolve({ out, err: err.includes("timeout") ? "timeout" : code !== 0 && !out ? (err.trim().split("\n").pop() || `exit ${code}`).slice(0, 160) : null }); });
  });
  try { rmSync(cwd, { recursive: true, force: true }); } catch {}
  const l = ledgerLine(job, role, batch, model, Date.now() - t0, out, err, served);
  record(l); noteOutcome(l, served);
  const r = parseReply(out);
  return { ok: r.ok && l.ok, json: r.json, limit: r.limit || !!l.limit };
}
