# hns-browser-loopback-proxy

Authenticated loopback browser-proxy adapters with explicit mobile and
Chromium feature contracts, bounded HTTP parsing, and local certificate
management.

The optional mobile `WholeBrowserIcannBootstrap` mode lets a browser shell
render eligible ICANN pages while its Handshake headers synchronize. The
caller supplies a bounded resolver that enforces its ICANN-root allowlist and
a public-address dialer. HTTPS CONNECT
remains opaque so the browser engine validates origin certificates; Handshake
single-label names are rejected until a new dual-root proxy generation starts.

This crate is part of [hns-dane-engine](https://github.com/handshake-rs/hns-dane-engine).
It is licensed under the PolyForm Noncommercial License 1.0.0.
