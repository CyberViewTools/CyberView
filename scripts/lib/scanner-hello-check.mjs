// Section 7 of scripts/security-check.mjs, the scanner's opt-in identify hellos (scanner/lib/hello.mjs, --identify) and DNS
// records (scanner/lib/dns-records.mjs, --dns-records): the rules that keep each one a frozen, standard, unauthenticated
// message, one exchange per service per host, off unless asked, never a login, a mail command, an enumeration, a call or
// stream setup, a zone transfer, or a broadcast. Pure: the caller hands in the source texts and the loaded modules.

/** A verb that may never start any line of a hello request (authentication, mail, user enumeration, call/stream setup, zone transfer). */
export const FORBIDDEN_VERB = /(?:^|\r\n|\n)(AUTH|USER|PASS|APOP|VRFY|EXPN|MAIL|RCPT|DATA|STARTTLS|STLS|TURN|ETRN|REGISTER|INVITE|SUBSCRIBE|MESSAGE|REFER|DESCRIBE|SETUP|PLAY|RECORD|ANNOUNCE|TEARDOWN|SET_PARAMETER|GET_PARAMETER|AXFR|IXFR|BIND)(?=[ \r\n]|$)/i;
/** The same verbs as a quoted string literal's first word anywhere in hello.mjs (a request cannot be smuggled outside the table). */
export const FORBIDDEN_LITERAL = /["'`](?:AUTH|USER|PASS|APOP|VRFY|EXPN|MAIL FROM|RCPT TO|STARTTLS|STLS|REGISTER|INVITE|DESCRIBE|SETUP|PLAY|AXFR|IXFR)(?:\s|\\r|\\n|["'`])/;
/** Text requests start with one of these verbs (and QUIT only as the polite close). */
export const ALLOWED_VERB = /^(EHLO|CAPA|OPTIONS)[ \r]/;
/** The reviewed binary requests, byte for byte (each sourced in scanner/lib/hello.mjs and the handoff doc). */
export const REVIEWED_HEX = Object.freeze({
  mdns: "000000000001000000000000095f7365727669636573075f646e732d7364045f756470056c6f63616c00000c0001",   // RFC 6763 s.9 PTR _services._dns-sd._udp.local
  ipmi: "0600ff06000011be80000000",   // DMTF ASF 2.0 presence ping (RMCP class 6, IANA 4542, type 0x80)
  rdp: "030000130ee000000000000100080003000000",   // [MS-RDPBCGR] 2.2.1.1 X.224 CR + RDP_NEG_REQ (SSL|HYBRID)
  smb: "0000006cfe534d424000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002400040001000000000000004379626572566965772d5363616e6e7200000000000000000202100200030203",   // [MS-SMB2] 2.2.3 NEGOTIATE
  ldap: "3063020101635e04000a01000a010002010102010a010100870b6f626a656374436c617373303e0414737570706f727465644c44415056657273696f6e040a76656e646f724e616d65040d76656e646f7256657273696f6e040b6f626a656374436c617373",   // RFC 4511 root DSE base search
  "ldap-close": "30050201024200",   // RFC 4511 4.3 UnbindRequest
});
export const DNS_TYPES = Object.freeze(["TXT", "CAA"]);
export const DNS_PREFIXES = Object.freeze(["", "_dmarc.", "default._bimi.", "_mta-sts."]);
const START = "/* ---- transport (no loop)", END = "/* ---- end transport ---- */";

/**
 * { helloSrc, mod, scanSrc, dnsSrc, dnsMod, otherSrcs: [{ file, src }] } -> [problem strings]
 */
export function helloProblems({ helloSrc = "", mod = null, scanSrc = "", dnsSrc = "", dnsMod = null, otherSrcs = [] } = {}) {
  const P = [], F = "scanner/lib/hello.mjs", G = "scanner/lib/dns-records.mjs";
  if (helloSrc) {
    // (a) every request, quit and hex value in the source is one plain double-quoted literal
    const uses = (helloSrc.match(/\b(request|quit|hex|closeHex)\s*:/g) || []).length;
    const lits = [...helloSrc.matchAll(/\b(request|quit|hex|closeHex)\s*:\s*"((?:[^"\\$`]|\\[rn])*)"\s*[,}]/g)];
    if (uses !== lits.length) P.push(`${F}: every request/quit/hex must be one plain string literal (${uses} found, ${lits.length} literal)`);
    if (FORBIDDEN_LITERAL.test(helloSrc)) P.push(`${F}: a string literal starts with a forbidden verb (AUTH, USER, PASS, APOP, VRFY, EXPN, MAIL, RCPT, STARTTLS, STLS, REGISTER, INVITE, DESCRIBE, SETUP, PLAY, AXFR, IXFR)`);
    // (b) no broadcast or multicast, ever
    if (/setBroadcast|addMembership|setMulticast|224\.0\.0\.251|ff02::fb|255\.255\.255\.255/i.test(helloSrc)) P.push(`${F}: broadcasts or multicasts; hellos go to the attested host's own address only`);
    // (c) the transport: one .write( and one .send( in the whole file, both inside the transport block, which has no loop
    const a = helloSrc.indexOf(START), b = helloSrc.indexOf(END);
    if (a < 0 || b < a) P.push(`${F}: the transport block markers are missing`);
    else {
      const inside = helloSrc.slice(a, b), outside = helloSrc.slice(0, a) + helloSrc.slice(b);
      const n = (re, s) => (s.match(re) || []).length;
      if (n(/\.write\s*\(/g, helloSrc) !== 1 || n(/\.write\s*\(/g, inside) !== 1) P.push(`${F}: exactly one .write( call, inside the transport block (found ${n(/\.write\s*\(/g, helloSrc)})`);
      if (n(/\.send\s*\(/g, helloSrc) !== 1 || n(/\.send\s*\(/g, inside) !== 1) P.push(`${F}: exactly one .send( call (one datagram), inside the transport block (found ${n(/\.send\s*\(/g, helloSrc)})`);
      if (/\.end\s*\(\s*[^)\s]/.test(helloSrc)) P.push(`${F}: .end( may not carry data (everything sent goes through the one .write()`);
      if (/\b(for|while|do)\s*[({]|\bsetInterval\b|\.forEach\s*\(|\bPromise\.all\b/.test(inside)) P.push(`${F}: the transport block must contain no loop or timer (one exchange per call)`);
      if (n(/\bnet\.connect\s*\(/g, inside) !== 1 || n(/\bnet\.connect\s*\(|\btls\.connect\s*\(|\bhttps?\.request\s*\(/g, outside)) P.push(`${F}: one net.connect( only, inside the transport block, and no TLS or HTTP request`);
      if (n(/createSocket\s*\(/g, inside) !== 1 || n(/createSocket\s*\(/g, outside)) P.push(`${F}: one dgram createSocket( only, inside the transport block`);
    }
    // (d) off unless enabled
    if (!/export async function identifyHost\(h, opts = \{\}\) \{\s*if \(!opts \|\| opts\.enabled !== true\) return \[\];/.test(helloSrc)) P.push(`${F}: identifyHost must first refuse to run unless opts.enabled === true`);
    if (!/if \(identify && identify\.enabled === true\) \{\s*h\.identify = await identifyHost\(/.test(scanSrc) || (scanSrc.match(/\bidentifyHost\(/g) || []).length !== 1) P.push("scanner/lib/scan.mjs: identifyHost may be called once, only inside `if (identify && identify.enabled === true)`");
    for (const { file, src } of otherSrcs) if (/\b(identifyHost|tcpHello|udpHello)\s*\(/.test(src)) P.push(`${file}: only scanner/lib/scan.mjs may run the identify hellos`);
    // (e) the loaded table: frozen; each request an allowed verb with only {target}/{ua}; each binary one byte-for-byte reviewed
    if (mod) {
      const H = mod.HELLO || {};
      if (!Object.isFrozen(H) || Object.values(H).some((e) => !Object.isFrozen(e))) P.push(`${F}: HELLO and its entries must be frozen`);
      for (const [k, e] of Object.entries(H)) {
        if (!e || (typeof e.request === "string") === (typeof e.hex === "string")) { P.push(`${F}: ${k} must have exactly one of request or hex`); continue; }
        if (e.flag !== "--identify" && e.flag !== "--identify-bmc") P.push(`${F}: ${k} must be behind --identify or --identify-bmc`);
        if (!/^only with --identify/.test(String(e.sends || ""))) P.push(`${F}: ${k}.sends must start "only with --identify" (declared in SENDS, off by default)`);
        if (e.closeHex !== undefined && REVIEWED_HEX[`${k}-close`] !== e.closeHex) P.push(`${F}: ${k} closeHex is not the reviewed byte sequence`);
        if (typeof e.hex === "string") { if (REVIEWED_HEX[k] !== e.hex) P.push(`${F}: ${k} binary request is not the reviewed byte sequence`); continue; }
        const req = e.request;
        if (!ALLOWED_VERB.test(req)) P.push(`${F}: ${k} request must start with EHLO, CAPA or OPTIONS`);
        if (FORBIDDEN_VERB.test(req) || (e.quit !== undefined && FORBIDDEN_VERB.test(e.quit))) P.push(`${F}: ${k} request contains a forbidden verb`);
        if (e.quit !== undefined && e.quit !== "QUIT\r\n") P.push(`${F}: ${k} quit must be exactly "QUIT\\r\\n"`);
        if ((req.match(/\{[^}]*\}/g) || []).some((t) => t !== "{target}" && t !== "{ua}") || /\$\{/.test(req)) P.push(`${F}: ${k} request may substitute only {target} and {ua}`);
        if (/^OPTIONS sip:/.test(req) && !/\r\nMax-Forwards: 0\r\n/.test(req)) P.push(`${F}: ${k} SIP OPTIONS must carry Max-Forwards: 0 (never forwarded)`);
        if ((req.match(/^[A-Z]+ /gm) || []).length > 1) P.push(`${F}: ${k} must be one message`);
      }
    }
  }
  if (dnsSrc) {
    if (/\bresolve(Any|Ns|Soa|Mx|Srv|Ptr|Naptr|Cname|Tlsa|4|6)\b|\.reverse\s*\(|\.resolve\s*\(|["'](AXFR|IXFR|ANY)["']|\bdgram\b|\bnet\.connect\b/.test(dnsSrc)) P.push(`${G}: may query only TXT and CAA (no ANY, AXFR, IXFR or other record type, no own sockets)`);
    if (dnsMod) {
      const Q = dnsMod.QUERIES || [];
      if (!Object.isFrozen(Q) || Q.some((q) => !Object.isFrozen(q))) P.push(`${G}: QUERIES must be frozen`);
      for (const q of Q) {
        if (!DNS_TYPES.includes(q.type)) P.push(`${G}: record type ${String(q.type).slice(0, 20)} is not allowed (TXT and CAA only)`);
        if (!DNS_PREFIXES.includes(q.prefix)) P.push(`${G}: name prefix "${String(q.prefix).slice(0, 40)}" is not a reviewed record name`);
      }
      if (dnsMod.DKIM_PREFIX !== "._domainkey.") P.push(`${G}: DKIM names must be <selector>._domainkey.<domain>`);
      if (!(dnsMod.MAX_SELECTORS <= 8 && dnsMod.MAX_DOMAINS <= 16)) P.push(`${G}: at most 8 DKIM selectors and 16 domains`);
    }
    if (!/if \(!plan\.ok\) return \{ error:/.test(dnsSrc)) P.push(`${G}: dnsRecords must refuse names that are not attested before any query`);
    for (const { file, src } of otherSrcs) if (/\bResolver\b|resolveTxt|resolveCaa/.test(src)) P.push(`${file}: only scanner/lib/dns-records.mjs may query DNS records`);
  }
  return P;
}
