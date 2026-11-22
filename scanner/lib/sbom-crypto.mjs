// CyberView Scanner — proprietary; see scanner/LICENSE (not the repository's MIT licence).
// [scan-sbom-crypto] crypto libraries in an imported SBOM or service list. No probe.
// "Past end of support" is only applied where the project itself published the date.
// OpenSSL 1.1.1 ended 11 September 2023: https://openssl-library.org/post/2023-09-11-eol/
// A 3.x version is listed, not called past support, because this file does not carry a 3.x end date.

const clip = (s, n) => String(s == null ? "" : s).slice(0, n);

function olderThan3(version) {
  const m = /^(\d+)/.exec(String(version || ""));
  return !!m && Number(m[1]) < 3;
}

/** services -> notes. Only OpenSSL / libssl below 3.0 is marked past the published end of support. */
export function cryptoNotes(services) {
  const out = [];
  for (const s of services || []) {
    const name = `${s.vendor || ""} ${s.product || ""} ${s.label || ""}`;
    if (!/openssl|libssl/i.test(name)) continue;
    const version = s.version || s.shown_version || "";
    if (olderThan3(version)) out.push({ product: clip(s.product || "OpenSSL", 80), version: clip(version, 40), past_support: true, why: "OpenSSL 1.1.1 and earlier are past the project's published end of support (11 September 2023)" });
    else if (version) out.push({ product: clip(s.product || "OpenSSL", 80), version: clip(version, 40), past_support: false, why: "version stated; not compared with a 3.x end-of-support date" });
  }
  return out.slice(0, 40);
}
