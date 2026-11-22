# Handoff: scan-tls-extra-hello

`--tls-legacy` is off by default. When set, one extra handshake offers only TLS 1.0, counted by the limiter. If this runtime cannot build that context, it does not connect. A hello that fails is not reported as proof the server refuses TLS 1.0. No cipher sweep and no fallback signaling.
