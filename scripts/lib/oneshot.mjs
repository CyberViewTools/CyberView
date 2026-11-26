// The no-tools, single-turn model caller for the Library's reader, writer, reviewer and auditor desks (scripts/library-*.mjs).
// One `claude -p` call: one turn, no tools, no MCP server, so a document that says "run this" has nothing to run. It goes through
// the same environment, API-key fallback decision and usage ledger as every other worker (scripts/run-job.mjs); the prompt is
// never logged and the fallback key is never read here (envFor hands it straight to the spawned process).
import { spawn } from "node:child_process";
import { join } from "node:path";
import { ROOT, readJson } from "./store.mjs";
import { LIMIT_RE } from "./usage.mjs";
import { ledgerLine, record, servedNow, fallbackNote, noteOutcome, envFor } from "../run-job.mjs";

const MODELS = readJson(join(ROOT, "config", "models.json"), { roles: {} });

/** Pure: the claude command line for one no-tools role. */
export function oneShotArgs(role, prompt, models = MODELS) {
  const r = { model: "sonnet", ...((models.roles || {})[role] || {}) };
  return ["-p", prompt, "--model", r.model, "--max-turns", "1", "--output-format", "json", "--tools", "", "--strict-mcp-config"];
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
  const served = servedNow();
  if (served === "park") return { ok: false, json: null, limit: true, note: fallbackNote() };
  const model = ((MODELS.roles || {})[role] || {}).model || "sonnet";
  const ms = (Number((MODELS.roles[role] || {}).timeout_min) || 6) * 60000, t0 = Date.now();
  const { out, err } = await new Promise((resolve) => {
    let out = "", err = "";
    let ch; try { ch = spawn("claude", oneShotArgs(role, prompt), { cwd: ROOT, env: envFor(served), stdio: ["ignore", "pipe", "pipe"] }); } catch (e) { return resolve({ out: "", err: String(e.message) }); }
    const kill = setTimeout(() => { ch.kill("SIGTERM"); setTimeout(() => ch.kill("SIGKILL"), 5000); err += "timeout"; }, ms);
    ch.stdout.on("data", (d) => { out += d; }); ch.stderr.on("data", (d) => { err += d; });
    ch.on("error", (e) => { err += String(e.message); });
    ch.on("close", (code) => { clearTimeout(kill); resolve({ out, err: err.includes("timeout") ? "timeout" : code !== 0 && !out ? (err.trim().split("\n").pop() || `exit ${code}`).slice(0, 160) : null }); });
  });
  const l = ledgerLine(job, role, batch, model, Date.now() - t0, out, err, served);
  record(l); noteOutcome(l, served);
  const r = parseReply(out);
  return { ok: r.ok && l.ok, json: r.json, limit: r.limit || !!l.limit };
}
