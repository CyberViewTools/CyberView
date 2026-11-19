// Validation for the newer record shapes, kept here so unit tests can reach them without running the build.
// Each function returns a list of problems (strings); an empty list means the record is fine.

const https = (u) => typeof u === "string" && /^https:\/\/[^\s"'<>]+$/.test(u) && (() => { try { const x = new URL(u); return x.pathname !== "/" || !!x.search; } catch { return false; } })();
const text = (v, max) => typeof v === "string" && v.trim().length > 0 && v.length <= max;
const ID = /^[a-z0-9][a-z0-9-]{2,119}$/;

/**
 * Event "attribution": who a government or the investigating firm says did it, and where the actor is said to be based.
 * Drawn on the globe as a dashed arc from the attributed origin to the victim, labelled with who attributed it.
 * { actor, origin_country, lat, lng, by, by_type: government | investigator, url, stated_at? }
 */
export function checkAttribution(a) {
  if (a == null) return [];
  if (typeof a !== "object" || Array.isArray(a)) return ["attribution must be an object"];
  const p = [];
  if (!text(a.actor, 120)) p.push("attribution.actor is required (as named in the attribution)");
  if (!text(a.origin_country, 60)) p.push("attribution.origin_country is required");
  if (typeof a.lat !== "number" || a.lat < -90 || a.lat > 90 || typeof a.lng !== "number" || a.lng < -180 || a.lng > 180) p.push("attribution.lat and lng must be numbers in range (the origin country's capital or centre)");
  if (!["government", "investigator"].includes(a.by_type)) p.push('attribution.by_type must be "government" or "investigator" (attacker boasts and press speculation do not count)');
  if (!text(a.by, 120)) p.push("attribution.by must name the government body or investigating firm");
  if (!https(a.url)) p.push("attribution.url must be the https page where the attribution is made (not a front page)");
  return p;
}

/**
 * Event "links": stated relationships to other events, e.g. a breached supplier and a customer hit through it.
 * [{ to: <event id>, rel: "customer of breached supplier", url: <page that states the link> }]
 * `known` is a Set of event ids on file, so a link to a missing event is caught.
 */
export function checkLinks(links, selfId, known) {
  if (links == null) return [];
  if (!Array.isArray(links)) return ["links must be a list"];
  const p = [];
  if (links.length > 40) p.push("links: at most 40");
  links.forEach((l, i) => {
    if (!l || typeof l !== "object") { p.push(`links[${i}] must be an object`); return; }
    if (!ID.test(l.to || "")) p.push(`links[${i}].to must be an event id`);
    else if (l.to === selfId) p.push(`links[${i}] points at the event itself`);
    else if (known && !known.has(l.to)) p.push(`links[${i}].to "${l.to}" is not an event on file`);
    if (!text(l.rel, 60)) p.push(`links[${i}].rel must say how they are linked (at most 60 characters)`);
    if (!https(l.url)) p.push(`links[${i}].url must be the https page that states the link`);
  });
  return p;
}

/**
 * The weekly tabletop exercise (data/tabletop.json and data/snapshots/tabletop/<date>.json). See docs/schema.md.
 * `known` is a Set of event ids on file.
 */
export function checkTabletop(t, known) {
  if (!t || typeof t !== "object" || Array.isArray(t)) return ["not an object"];
  const p = [];
  if (t.label !== "exercise") p.push('label must be "exercise"');
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(t.generated_at || "")) p.push("generated_at must be an ISO time");
  if (!/^\d{4}-\d{2}-\d{2}$/.test(t.date || "")) p.push("date must be YYYY-MM-DD");
  if (!text(t.title, 120)) p.push("title is required (at most 120 characters)");
  if (!Array.isArray(t.based_on) || !t.based_on.length) p.push("based_on must list the real event id(s) the exercise is built from");
  else t.based_on.forEach((id) => { if (!ID.test(id || "")) p.push(`based_on: "${id}" is not an event id`); else if (known && !known.has(id)) p.push(`based_on: "${id}" is not an event on file`); });
  if (!text(t.real_story, 900)) p.push("real_story is required: what really happened, from the event record (at most 900 characters)");
  if (!Array.isArray(t.facts) || t.facts.length < 2) p.push("facts: list at least 2 verified facts, each with the source it came from");
  else t.facts.forEach((f, i) => { if (!f || !text(f.text, 300)) p.push(`facts[${i}].text is required (at most 300 characters)`); if (!f || !https(f.source_url)) p.push(`facts[${i}].source_url must be the https page the fact is from`); });
  if (!text(t.scenario, 1200)) p.push("scenario is required (at most 1200 characters)");
  if (!Number.isInteger(t.duration_min) || t.duration_min < 20 || t.duration_min > 180) p.push("duration_min must be a whole number from 20 to 180");
  if (!Array.isArray(t.roles) || !t.roles.length || t.roles.some((r) => !text(r, 60))) p.push("roles: list who should be in the room (each at most 60 characters)");
  if (!Array.isArray(t.injects) || t.injects.length < 3 || t.injects.length > 10) p.push("injects: 3 to 10 timed updates");
  else {
    let last = -1;
    t.injects.forEach((x, i) => {
      if (!x || typeof x !== "object") { p.push(`injects[${i}] must be an object`); return; }
      if (!Number.isInteger(x.at_min) || x.at_min < 0 || x.at_min > (t.duration_min || 180)) p.push(`injects[${i}].at_min must be a minute within the exercise`);
      else if (x.at_min < last) p.push(`injects[${i}] is out of time order`); else last = x.at_min;
      if (!text(x.title, 90)) p.push(`injects[${i}].title is required (at most 90 characters)`);
      if (!text(x.text, 600)) p.push(`injects[${i}].text is required (at most 600 characters)`);
      if (x.ask != null && !text(x.ask, 300)) p.push(`injects[${i}].ask must be text (at most 300 characters)`);
    });
  }
  for (const [k, min, max, len] of [["questions", 4, 12, 300], ["good_looks_like", 3, 10, 300]]) {
    if (!Array.isArray(t[k]) || t[k].length < min || t[k].length > max || t[k].some((q) => !text(q, len))) p.push(`${k}: ${min} to ${max} items, each at most ${len} characters`);
  }
  if (t.adapt != null && !text(t.adapt, 600)) p.push("adapt must be text (at most 600 characters)");
  if (!Array.isArray(t.sources) || !t.sources.length) p.push("sources: list the pages read");
  else t.sources.forEach((s, i) => { if (!s || !text(s.name, 80) || !https(s.url)) p.push(`sources[${i}] needs a name and the https url of the page read`); });
  return p;
}

export const HUNT_FORMATS = ["stix", "sigma", "yara", "snort", "suricata", "kql", "spl", "csv", "json", "misp", "openioc", "text", "pdf"];
/**
 * Detection resources published by the original advisory or report: indicator files and detection rules.
 * [{ name, format, url, publisher }]. Links only: CyberView never copies indicators themselves.
 */
export function checkHunt(list) {
  if (list == null) return [];
  if (!Array.isArray(list)) return ["hunt must be a list"];
  const p = [];
  if (list.length > 12) p.push("hunt: at most 12");
  list.forEach((h, i) => {
    if (!h || typeof h !== "object") { p.push(`hunt[${i}] must be an object`); return; }
    if (!text(h.name, 100)) p.push(`hunt[${i}].name is required (what the file is, at most 100 characters)`);
    if (!HUNT_FORMATS.includes(h.format)) p.push(`hunt[${i}].format must be one of ${HUNT_FORMATS.join(", ")}`);
    if (!https(h.url)) p.push(`hunt[${i}].url must be the https address of the file or the page that publishes it`);
    if (h.publisher != null && !text(h.publisher, 80)) p.push(`hunt[${i}].publisher must be text (at most 80 characters)`);
  });
  return p;
}

/**
 * A fix guide for one CVE (data/guides/<CVE>.json), written by the advisory desk from the vendor's own advisory.
 * { cve, advisory: {name, url}, read_at, read_depth: full | summary, check[], fixed[], workaround[], compromise_signs[],
 *   exposure: internet | internal | local, exploit_public: bool, hunt[] }
 */
export function checkGuide(g, id) {
  if (!g || typeof g !== "object" || Array.isArray(g)) return ["not an object"];
  const p = [];
  if (!/^CVE-\d{4}-\d{4,}$/.test(g.cve || "")) p.push("cve must be a CVE id");
  else if (id && g.cve !== id) p.push(`cve "${g.cve}" does not match the file name`);
  if (!g.advisory || !text(g.advisory.name, 100) || !https(g.advisory.url)) p.push("advisory needs a name and the https url of the vendor or agency advisory that was read");
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(g.read_at || "")) p.push("read_at must be an ISO time");
  if (!["full", "summary"].includes(g.read_depth)) p.push('read_depth must be "full" or "summary" (a guide is never written from secondary coverage)');
  for (const [k, max, len] of [["check", 6, 320], ["fixed", 8, 160], ["workaround", 5, 320], ["compromise_signs", 6, 320]]) {
    if (g[k] == null) continue;
    if (!Array.isArray(g[k]) || g[k].length > max || g[k].some((x) => !text(x, len))) p.push(`${k}: at most ${max} items, each at most ${len} characters`);
  }
  if (!(g.check || []).length && !(g.fixed || []).length && !(g.workaround || []).length) p.push("a guide needs at least one of check, fixed or workaround");
  if (g.exposure != null && !["internet", "internal", "local"].includes(g.exposure)) p.push("exposure must be internet, internal or local");
  if (g.exploit_public != null && typeof g.exploit_public !== "boolean") p.push("exploit_public must be true or false");
  return p.concat(checkHunt(g.hunt));
}

/**
 * An exploitation analysis (data/analyses/<CVE>.json), written by the exploit analyst job (an Opus agent) from public sources.
 * It explains how attackers use a flaw at the level of an advisory, so defenders can find exposure, detect use and fix it.
 * It never contains exploit code, payloads, request strings, commands that attack a system, or reproduction steps:
 * NOCODE rejects text that looks like any of those, so a record carrying them is refused by the build.
 * { cve, analyzed_at, model, exploitation_status, how_exploited, preconditions[], attack_path[], exposure, who_is_exposed[],
 *   detect[], remediation: { priority, steps[], fixed_versions[], workarounds[], verify[], if_compromised[] },
 *   confidence, caveats, sources: [{ name, url, kind, read_depth }] }
 */
export const NOCODE = /`|<\/?(script|iframe|svg|img|object|embed)\b|\$\{|\$\(|\b(curl|wget|nc|ncat|netcat|powershell|bash|sh|python3?|perl|ruby|php|msfconsole|sqlmap|nmap)\s+-|\b(curl|wget)\s+https?:|\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\/\S|\.\.\/\.\.|%2e%2e|%00|\\x[0-9a-f]{2}|\b0x[0-9a-f]{8,}|[A-Za-z0-9+\/]{60,}={0,2}|\b(payload|shellcode|proof[- ]of[- ]concept code|exploit code)\s*:|\bUNION\s+SELECT\b|\bOR\s+1\s*=\s*1\b|\/bin\/(ba)?sh\b|\bcmd\.exe\s*\/c\b|\bjndi:|\{\{.*\}\}|\bchmod\s+\+x\b/i;
const SRC_KINDS = ["vendor", "government", "research", "news", "database"];
export function checkAnalysis(a, id) {
  if (!a || typeof a !== "object" || Array.isArray(a)) return ["not an object"];
  const p = [], strs = [];
  const one = (k, max, req = true) => { const v = a[k]; if ((v == null || v === "") && !req) return; if (!text(v, max)) p.push(`${k}: required text, at most ${max} characters`); else strs.push([k, v]); };
  const many = (o, k, min, max, len, label = k) => { const v = o[k]; if (v == null && !min) return;
    if (!Array.isArray(v) || v.length < min || v.length > max || v.some((x) => !text(x, len))) p.push(`${label}: ${min ? min + " to " : "at most "}${max} items, each at most ${len} characters`); else v.forEach((x) => strs.push([label, x])); };
  if (!/^CVE-\d{4}-\d{4,}$/.test(a.cve || "")) p.push("cve must be a CVE id"); else if (id && a.cve !== id) p.push(`cve "${a.cve}" does not match the file name`);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(a.analyzed_at || "")) p.push("analyzed_at must be an ISO time");
  if (!text(a.model, 60)) p.push("model must name the model that wrote it");
  one("exploitation_status", 240); one("how_exploited", 900);
  many(a, "preconditions", 1, 6, 260); many(a, "attack_path", 1, 6, 280); many(a, "who_is_exposed", 0, 5, 260); many(a, "detect", 1, 6, 300);
  if (!["internet", "internal", "local"].includes(a.exposure)) p.push("exposure must be internet, internal or local");
  const r = a.remediation;
  if (!r || typeof r !== "object" || Array.isArray(r)) p.push("remediation is required");
  else {
    if (!["immediate", "urgent", "planned"].includes(r.priority)) p.push("remediation.priority must be immediate, urgent or planned");
    many(r, "steps", 1, 8, 320, "remediation.steps"); many(r, "fixed_versions", 0, 8, 160, "remediation.fixed_versions"); many(r, "workarounds", 0, 5, 320, "remediation.workarounds");
    many(r, "verify", 1, 5, 300, "remediation.verify"); many(r, "if_compromised", 0, 6, 300, "remediation.if_compromised");
  }
  if (!["high", "medium", "low"].includes(a.confidence)) p.push("confidence must be high, medium or low");
  one("caveats", 500, false);
  const src = a.sources;
  if (!Array.isArray(src) || src.length < 2 || src.length > 10) p.push("sources: 2 to 10 pages that were read");
  else {
    src.forEach((x, i) => { if (!x || !text(x.name, 100) || !https(x.url) || !SRC_KINDS.includes(x.kind) || !["full", "summary"].includes(x.read_depth)) p.push(`sources[${i}] needs name, https url (a specific page), kind (${SRC_KINDS.join(", ")}) and read_depth (full or summary)`); });
    if (!src.some((x) => x && (x.kind === "vendor" || x.kind === "government"))) p.push("sources must include the vendor's advisory or a government source");
  }
  for (const [k, v] of strs) if (NOCODE.test(v)) { p.push(`${k}: looks like code, a payload, a request or an attack command; describe the technique in words instead`); break; }
  return p;
}

/**
 * A published community post (data/chat/<YYYY-MM>/<issue>.json), written only by scripts/chat.mjs approve after review.
 * { id, at, author, kind: comment | tip | question, text, event_id, links[], reviewed_at, note?, removed?, removed_reason? }
 */
export function checkChat(c, known) {
  if (!c || typeof c !== "object" || Array.isArray(c)) return ["not an object"];
  const p = [];
  if (!Number.isInteger(c.id) || c.id < 1) p.push("id must be the issue number");
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(c.at || "")) p.push("at must be an ISO time");
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/.test(c.author || "")) p.push("author must be a GitHub login");
  if (!["comment", "tip", "question"].includes(c.kind)) p.push("kind must be comment, tip or question");
  if (!text(c.text, 600) || /[<>\u0000-\u001f]/.test(c.text)) p.push("text is required: plain text, at most 600 characters, no markup");
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(c.reviewed_at || "")) p.push("reviewed_at is required: a post is never published unreviewed");
  if (!Array.isArray(c.links) || c.links.length > 2 || c.links.some((u) => typeof u !== "string" || !/^https:\/\/[^\s"'<>]+$/.test(u))) p.push("links: at most 2, https only");
  if (c.event_id && (!ID.test(c.event_id) || (known && !known.has(c.event_id)))) p.push(`event_id "${c.event_id}" is not an event on file`);
  if (c.note != null && !text(c.note, 200)) p.push("note must be text (at most 200 characters)");
  if (c.removed != null && typeof c.removed !== "boolean") p.push("removed must be true or false");
  return p;
}
