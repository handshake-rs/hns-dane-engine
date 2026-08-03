# hns-dane-engine

Runtime-independent facade for fail-closed Handshake browser resolution and
DANE validation.

The engine coordinates session and policy generations, transport admission,
query correlation, locally verified evidence, certificate matching, and
structured provenance. Native adapters own platform I/O and persistence; they
cannot substitute transport assertions for local validation.

Rust facade version 3 also exposes the minimal browser-authority boundary for
wallet-provider injection. It permits HTTPS only and stamps the exact logical
origin and URL port, selected service port and namespace, complete
namespace-decision fingerprint, network, authentication path, runtime and
policy generations, authority event, and validity interval into a private
context, then returns a typed allow-or-deny result. Exact success can mint a
separate non-cloneable, non-serializable `ProviderAuthorityContext`; native
browser code reads its typed origin/namespace/service/network and generation
bindings and consumes/replaces it through engine revalidation instead of
reproducing trust policy. A borrowed check lets a trusted native publication
retain the opaque context. Its private admission stamp survives unrelated work
but not degradation, revocation, stop, policy/runtime invalidation, or expiry.
HNS requires a matching strict engine completion.
ICANN uses an exact-request opaque token minted by a trusted embedding-browser adapter; that
adapter is a security principal and must never accept page-controlled TLS
assertions. The engine does not contain wallet, permissions, signing, or
marketplace code. A separate consumer ABI can take ownership of an already
authorized Rust context for typed inspection, currentness checks, and
destruction, but exposes no C mint/import path. Pure-C authority construction
and platform wiring remain unavailable. Navigation and same-origin decision
replacement remain platform revoke-or-replace responsibilities; the engine
keeps no unbounded per-origin navigation map.

Published releases can be added with:

```bash
cargo add hns-dane-engine
```

See the repository's
[architecture](https://github.com/handshake-rs/hns-dane-engine/blob/main/docs/architecture.md)
and
[security policy](https://github.com/handshake-rs/hns-dane-engine/blob/main/docs/security-policy.md)
for integration boundaries. The minimum supported Rust version is 1.89. API
documentation for published releases is hosted on
[docs.rs](https://docs.rs/hns-dane-engine).

Licensed under either Apache-2.0 or MIT.
