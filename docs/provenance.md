# Provenance and compatibility pins

This repository is independently implemented and dual-licensed `MIT OR Apache-2.0`.

Compatibility was inspected against these immutable inputs:

| Input | Commit | License | Relevant paths |
| --- | --- | --- | --- |
| handshake-rs/hns-rs | `dde2da81f29df935f043978a6d517c1d60ceff31` | MIT OR Apache-2.0 | Nine direct workspace dependencies and the locked eleven-package closure |
| handshake-org/hsd | `698e252ebc7b5c1dd0a9587e342fdd153d020ae4` | MIT | `test/dns-test.js`, `test/resource-test.js` |
| Denuo-Web/hns-dane-browser | `a71f9ea8dd2e697df6059e8840907f96e6eea2c9` | PolyForm Noncommercial 1.0.0 | `rust/crates/hns-core/src/dns.rs`, `fixtures/experimental-dns-relay/manifest.json` |

The `hns-rs` input is executable source, not only a compatibility reference.
The root manifest and `Cargo.lock` pin its exact canonical Git revision.
`scripts/verify_cargo_source_policy.py` independently verifies that the direct
and transitive package sets, URL, revision, consumer locations, and lock
sources match the reviewed graph. MeshMine is not a dependency.

The browser source has a license incompatible with copying it into this dual-licensed workspace.
No source was copied. The local DNS vectors are independently generated protocol fixtures. The
manifest pins inspected paths and hashes so compatibility can be reproduced without claiming code
provenance.

The DANE certificate/SPKI fixtures were generated locally with OpenSSL 3.5.6. Their decoded sizes
and SHA-256 hashes are pinned in `fixtures/dane/manifest.toml`; no private key is tracked.
`hns-browser-testkit` generates a temporary test-only DNSSEC RSA key in memory for each strict
regtest fixture, uses it to authenticate and sign the synthetic HNS authority/TLSA path, and drops
the private key before returning the public verification fixture.

HSD source SHA-256 values:

- `test/dns-test.js`: `dc86df3f7e56b638a99b9243936560ca252ead18bbfcf10e751419957b651ed4`
- `test/resource-test.js`: `a46392345a7b607d20d613267fe6e17ea0b9459ead52be3bdc812db771c9a245`

Browser source SHA-256 values:

- `rust/crates/hns-core/src/dns.rs`: `e3338986a75a43fd4a483b89c86a5f1691e4816226f9ac6e9f3093eddc3f24bb`
- `fixtures/experimental-dns-relay/manifest.json`:
  `b72f84ca688460115995383e7be26482f03cf456f7a82044a5abcf5e1a71f75f`
