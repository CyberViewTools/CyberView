// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// The ONLY file in the scanner that opens a UDP socket (node:dgram); scripts/security-check.mjs enforces that and that this
// file sends EXACTLY ONE datagram per call and contains no loop (the flood guard: one benign query per service per host,
// no retransmit, no amplification, no community or credential iteration). The query bytes and the parsing are built in the
// pure udp-codec.mjs; this file only sends one datagram and reads at most one reply.
//
// What goes out, per (host, service), in ONE datagram and nothing more:
//   DNS  -> the "version.bind" CHAOS TXT query        NTP -> a mode-6 read-variables request       SNMP -> one GET of sysDescr with community "public"
// Read-only: none of them changes the target, carries a payload beyond the standard query, or tries a second community.
import dgram from "node:dgram";
import { isIP } from "node:net";
import { UDP_SERVICES, SNMP_COMMUNITY } from "./udp-codec.mjs";
import { TIMEOUTS } from "./limits.mjs";

export { UDP_SERVICES, SNMP_COMMUNITY };
/** Lines for the run header / report: exactly what each UDP check sends. */
export const UDP_SENDS = Object.fromEntries(Object.values(UDP_SERVICES).map((s) => [s.proto, s.sends]));

/**
 * One UDP service on one host: send the single benign query, wait for at most one reply (or time out), close.
 * Never throws. -> { service, port, proto, state: open|filtered, parsed, bytes, error }
 * state is "open" only when the service answered; UDP gives no closed/filtered certainty, so silence is "filtered".
 */
// services: the --udp table by default; scanner/lib/ics.mjs passes its frozen BACnet entry (only with --ics), still one datagram
export async function udpProbe(ip, serviceKey, { signal = null, timeouts = TIMEOUTS, port = 0, services = UDP_SERVICES } = {}) {
  const svc = services[serviceKey], dest = port || svc.port;   // port override: a service on a non-standard port (and the tests)
  const out = { service: serviceKey, port: dest, proto: svc.proto, state: "filtered", parsed: null, bytes: 0, error: "" };
  const datagram = svc.build(serviceKey === "snmp" ? SNMP_COMMUNITY : undefined);
  const family = isIP(ip) === 6 ? "udp6" : "udp4";
  const sock = dgram.createSocket(family);
  const cleanup = () => { try { sock.close(); } catch { /* already closed */ } };
  const result = await new Promise((resolve) => {
    let settled = false;
    const finish = (v) => { if (settled) return; settled = true; clearTimeout(timer); if (signal) signal.removeEventListener("abort", onAbort); cleanup(); resolve(v); };
    const onAbort = () => finish(out);
    const timer = setTimeout(() => finish(out), timeouts.connectMs + timeouts.readMs);
    if (signal) { if (signal.aborted) return finish(out); signal.addEventListener("abort", onAbort, { once: true }); }
    sock.once("error", (e) => { out.error = String((e && (e.code || e.message)) || e).slice(0, 80); finish(out); });
    sock.once("message", (msg) => { out.state = "open"; out.bytes = msg.length; try { out.parsed = svc.parse(msg.subarray(0, timeouts.maxBytes)); } catch { out.parsed = null; } finish(out); });
    // the single datagram: the one and only send in the whole scanner's UDP path
    sock.send(datagram, dest, ip, (err) => { if (err) { out.error = String(err.code || err.message).slice(0, 80); finish(out); } });
  });
  return result;
}
