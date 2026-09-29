# HNS DANE Engine

`hns-dane-engine` is the reusable Handshake resolution, validation, transport,
and browser-security layer used by the native ShakeScape applications. The
workspace separates consensus and DNS/DANE authority from platform-owned
networking, storage, browser UI, and wallet UI.

The important rule is simple: a remote resolver, relay, website, or platform
adapter can transport evidence, but it cannot declare that evidence valid.
Handshake proofs, DNSSEC, TLSA, namespace selection, and provider admission are
validated locally against the selected Handshake chain.

## What is implemented

- Handshake header validation anchored to each network's genesis block,
  including proof of work, difficulty, chainwork, median time, and fork
  selection.
- Strict Urkel proof and `NameState` validation for Handshake names.
- Bounded Handshake peer framing, discovery, header synchronization, and
  standard `GETADDR`, `GETHEADERS`, and `GETBLOCKS` request events.
- DNS wire encoding and decoding with compression-loop and allocation bounds.
- DNSSEC validation, authenticated denial, CNAME processing, and TLSA/DANE
  certificate validation.
- Independent HNS and ICANN resolution plans with explicit namespace selection
  and no silent cross-root record merging.
- Direct delegated-authoritative UDP/TCP, authenticated authoritative DoH,
  HIP-76 DNS Relay, HIP-77 ODoH, and explicitly configured recursive HNS DoH
  transport contracts.
- Bounded cache, policy, provenance, runtime-generation, and revocation state.
- Browser provider-authority and loopback-proxy admission contracts.
- HNSR requester and opaque-relay state machines, including the ShakeScape
  Experimental V1 service profiles defined by the pinned `hns-rs` cohort.
- Rust and C-facing adapter contracts used by Android, Apple, and other native
  hosts.

## Trust boundary

The engine is not a remote trust service. Successful HNS navigation requires a
locally verified chain of evidence:

```text
Handshake genesis and validated headers
                  │
                  ▼
        committed Urkel name proof
                  │
                  ▼
     HNS resource and DNSSEC authority
                  │
                  ▼
         TLSA and certificate chain
                  │
                  ▼
       exact origin provider authority
```

Transport authentication and content authentication are separate. Brontide,
HTTPS, DNS Relay, ODoH, and HNSR protect or route transport; none replaces the
local proof, DNSSEC, and DANE checks.

For dual-root names, HNS and ICANN are resolved independently. The resulting
plans are classified as HNS-only, ICANN-only, convergent, divergent, or
unavailable. Records from the two roots are never combined into a synthetic
answer.

## Workspace map

| Area | Crates | Purpose |
| --- | --- | --- |
| Core DNS and DANE | `hns-dns-wire`, `hns-dnssec`, `hns-dane`, `hns-cache` | Wire parsing, DNSSEC, TLSA/DANE, and bounded caching |
| Handshake light client | `hns-light-chain`, `hns-light-p2p`, `hns-light-sync`, `hns-light-wallet` | Headers, peer protocol, synchronization, and wallet primitives |
| Resolution | `hns-resolver`, `hns-transport`, `hns-namespace-resolution`, `hns-resolution-policy` | HNS/ICANN planning, transport policy, and provenance |
| Browser adapters | `hns-browser-*` | Mobile/browser-safe chain, P2P, resolver, transport, gateway, proxy, and status contracts |
| Integrated facade | `hns-dane-engine`, `hns-dane-engine-ffi` | Rust facade and C ABI |
| Experimental networking | `hns-gateway`, `hns-p2p-transport` | Negotiated DNS Relay, ODoH, HNSA, and HNSR integration |

The complete public package order is maintained in
[`release/public-crates.txt`](release/public-crates.txt). The private
`hns-browser-testkit` crate contains repository fixtures and is never
published.

## Current mobile-wallet cohort

The current targeted compatible patch cohort is `0.2.6`:

- `hns-light-chain`
- `hns-light-wallet`
- `hns-light-p2p`
- `hns-light-sync`
- `hns-browser-chain`
- `hns-browser-p2p`
- `hns-browser-resolver`

This cohort moves the complete light-client type graph to `hns-rs 0.5.0`,
retains the typed inbound Handshake request events needed by a native
peer-serving adapter, and keeps the SQLite-backed browser chain, peer, and
resolver graph on one compatible release line. It supersedes the prepared but
unpublished `0.2.4` mobile-network cohort and does not republish unrelated
immutable crates. The machine-readable release set is
[`release/mobile-wallet-0.2.6-crates.txt`](release/mobile-wallet-0.2.6-crates.txt).

The workspace intentionally contains compatible mixed versions. Previously
published archives and their checksums are recorded under [`release/`](release/)
instead of being rebuilt from newer source. See
[`docs/releasing.md`](docs/releasing.md) for the exact release contract.

## Upstream Handshake protocol cohort

The current mobile-wallet cohort consumes the coherent `hns-rs 0.5.0` protocol
cohort. Direct
protocol dependencies use exact crates.io requirements, and all nineteen
upstream archive checksums are pinned in
[`release/hns-rs-0.5.0-crates.sha256`](release/hns-rs-0.5.0-crates.sha256).
The reviewed upstream source revision is
`60eb912d615243a6bfb9741b17f16833c5a9181a`.

Repository policy rejects Git dependencies, unreviewed registry sources,
escaping path dependencies, dependency aliases that hide protocol identities,
and lockfile drift. Details are in
[`docs/supply-chain.md`](docs/supply-chain.md).

## Build and test

The minimum supported Rust compiler is 1.89.0.

```sh
cargo +1.89.0 fetch --locked
cargo +1.89.0 install cargo-deny --version 0.19.9 --locked
./scripts/check.sh
```

For the targeted mobile-network packages:

```sh
cargo +1.89.0 test --locked \
  -p hns-light-p2p \
  -p hns-browser-chain \
  -p hns-browser-p2p \
  -p hns-browser-resolver

python3 scripts/verify-release.py --toolchain 1.89.0
./scripts/publish.sh --dry-run hns-light-p2p
./scripts/publish.sh --dry-run hns-browser-chain
./scripts/publish.sh --dry-run hns-browser-p2p
./scripts/publish.sh --dry-run hns-browser-resolver
```

## Platform responsibilities

The Rust state machines are runtime independent, but a complete installed
browser is not. A platform integration still owns:

- sockets and authenticated Brontide exchanges;
- durable, rollback-resistant platform storage and trusted-time floors;
- browser process, tab, lifecycle, and background execution policy;
- secure key storage and UI authorization;
- target-specific OpenSSL or equivalent native linkage where required;
- operating-system proxy, certificate, notification, and accessibility APIs.

The adapter crates provide contracts and reusable implementations for those
hosts. Publishing a crate does not by itself qualify an Android, iOS, macOS,
or Chromium product.

## Experimental protocol notice

ShakeScape, P2P DNS Relay, P2P ODoH, HNSA, and HNSR are described as
**ShakeScape Experimental V1**. They are not official Handshake protocol
assignments. Peers must negotiate the exact registry/network/genesis profile;
unknown or incompatible profiles fail closed.

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — component and authority architecture
- [`docs/security-policy.md`](docs/security-policy.md) — required security properties
- [`docs/p2p-dns-transports.md`](docs/p2p-dns-transports.md) — experimental P2P DNS transports
- [`docs/provenance.md`](docs/provenance.md) — resolution evidence and provenance
- [`docs/abi.md`](docs/abi.md) — native ABI contract
- [`docs/qualification.md`](docs/qualification.md) — test and qualification boundaries
- [`docs/releasing.md`](docs/releasing.md) — immutable crate release procedure

## License

The core crates retain their package-declared Apache-2.0/MIT licensing. The
published `hns-browser-*` adapter crates retain their package-declared
PolyForm Noncommercial license. Always consult the individual crate manifest
and bundled license files for the authoritative terms.
