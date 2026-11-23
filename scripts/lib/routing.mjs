// Which model does the work: routing rules, no AI model. Owner, 2026-11-21: "accuracy first; Opus where it counts".
// The second review corrected 34% of events (target under 10%), and the corrections cluster where judgment matters:
// incidents (what the organisation really confirmed), exploited flaws, official reports and stories several publishers
// carry (which publisher says what). Those go to the deep roles (config/models.json: researcher-deep, updater-deep,
// followup-deep); routine bulletins, single-source headlines and the rest stay on the base roles.
// Owner, 2026-11-23 (cost-conscious; the #127 evals showed the Opus deep roles were not corrected less often than
// Sonnet): the deep roles now run on Sonnet with detailed-harness prompts, not Opus. This routing is unchanged -- the
// deep role still gets the hardest work, just at a lower tier with a fuller prompt and more turns than the base role.
// A rule, not a global switch: the owner can move either role's model in config/models.json, and an empty or missing
// deep role falls back to the base role (roleFor); the deep role's prompt is the base role's section (baseRole).

const DB_KINDS = new Set(["cve", "breach-db", "status", "claim"]);

/** Pure: does a story (scripts/fuse.mjs story()) need the deep researcher? Why, as a short reason, or "" when it does not.
 *  - listed as exploited (KEV, a CERT's exploited flag, an exploited lead): always
 *  - reads like an incident (breach, ransomware, outage, intrusion ...) and is not commentary
 *  - reported by a government or CERT (a report, not a bare database row), unless it is a routine bulletin
 *  - two or more independent publishers, unless it is a routine bulletin */
export function deepReason(s) {
  if (!s || s.claim_only || s.explainer) return "";
  const kinds = s.kinds || [], leads = s.leads || [];
  if (kinds.includes("exploited")) return "exploited flaw";
  if (s.incident) return "incident";
  if (s.routine) return "";
  if (leads.some((l) => l && l.tier === "gov" && !DB_KINDS.has(l.kind))) return "official report";
  if (Number(s.publishers) >= 2) return `${s.publishers} publishers`;
  return "";
}
export const deepStory = (s) => !!deepReason(s);

/** Pure: does an event on file need the deep updater or follow-up desk? Severity 3, or an exploited flaw (on the
 *  known-exploited list, tagged zero-day, or "exploited" in its title). */
export function deepEvent(e) {
  if (!e || typeof e !== "object") return false;
  if (Number(e.severity) >= 3) return true;
  if ((e.cve_meta || []).some((c) => c && c.kev)) return true;
  if ((e.tags || []).includes("zero-day")) return true;
  return /\bexploited\b|\bin the wild\b/i.test(String(e.title || ""));
}

/** Pure: the follow-up desk's candidates (docs/jobs.md, Follow-up desk INPUTS and step 1): events of the last 10 days that
 *  are developing, claimed, single-source, carry a date_note, or are severity 3, not updated in the last 24 hours. */
export function followupCandidates(events, now = Date.now()) {
  const since = new Date(now - 10 * 864e5).toISOString().slice(0, 10), fresh = new Date(now - 864e5).toISOString();
  return (events || []).filter((e) => e && !e.duplicate_of && String(e.date || "") >= since && String(e.updated_at || "") < fresh
    && (["developing", "claimed"].includes(e.status) || (e.validation && e.validation.state === "single_source") || e.date_note || Number(e.severity) >= 3));
}
/** Pure: the follow-up desk's role this time. Its first pick is the highest severity, so when any candidate is a deep
 *  event the desk works on one: followup-deep. */
export const followupDeep = (events, now = Date.now()) => followupCandidates(events, now).some(deepEvent);

/** Pure: the role a worker runs as: the deep role when asked for and configured in config/models.json, else the base role. */
export function roleFor(base, deep, models) {
  const d = `${base}-deep`;
  return deep && models && models.roles && models.roles[d] ? d : base;
}
/** Pure: the base role of a deep role (its prompt is the base role's section of docs/jobs.md). */
export const baseRole = (role) => String(role || "").replace(/-deep$/, "");
