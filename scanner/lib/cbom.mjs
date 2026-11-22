// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// [scan-cbom] a CycloneDX inventory of cryptography this scan already saw.
// It records the negotiated TLS parameters and the SSH algorithms the server advertised.
// It is not a list of every algorithm the server supports, and it does not open another connection.
// https://cyclonedx.org/capabilities/cbom/

const clip = (s, n) => String(s == null ? "" : s).slice(0, n);

export function toCbom(report) {
  const components = [];
  for (const h of (report && report.hosts) || []) {
    for (const t of h.tls || []) {
      components.push({
        type: "cryptographic-asset",
        name: clip(`${h.address}:${t.port} tls`, 120),
        cryptoProperties: {
          assetType: "protocol",
          protocolProperties: { type: "tls", version: clip(t.protocol, 20), cipherSuites: [{ name: clip(t.cipher_std || t.cipher || "", 80) }] },
        },
      });
      if (t.cert) components.push({
        type: "cryptographic-asset",
        name: clip(`${h.address}:${t.port} certificate`, 120),
        cryptoProperties: {
          assetType: "certificate",
          certificateProperties: {
            subjectName: clip(t.cert.subject, 200), issuerName: clip(t.cert.issuer, 200),
            signatureAlgorithmRef: clip(t.cert.sig_alg, 60),
          },
        },
      });
    }
    for (const s of h.ssh || []) {
      components.push({
        type: "cryptographic-asset",
        name: clip(`${h.address}:${s.port} ssh algorithms advertised`, 140),
        cryptoProperties: { assetType: "algorithm", algorithmProperties: { primitive: "other", names: (s.kex || []).slice(0, 20).map((n) => clip(n, 80)) } },
      });
    }
  }
  return {
    bomFormat: "CycloneDX", specVersion: "1.6", version: 1,
    metadata: { component: { type: "application", name: "CyberView Scanner run" } },
    components,
    note: "Negotiated TLS and advertised SSH only. A missing algorithm was not offered or was not read; it is not proof the peer lacks it.",
  };
}
