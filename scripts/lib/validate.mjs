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
