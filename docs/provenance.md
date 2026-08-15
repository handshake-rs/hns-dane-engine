# Provenance and compatibility pins

This repository is independently implemented and dual-licensed `MIT OR Apache-2.0`.

Compatibility was inspected against these immutable inputs:

| Input | Commit | License | Relevant paths |
| --- | --- | --- | --- |
| handshake-rs/hns-rs | `d0cde9ded6f8f93f96f16daafc094849c6d484bf` | MIT OR Apache-2.0 | Thirteen exact crates.io `=0.3.0` workspace dependencies and their sixteen-package locked closure; all nineteen published archive hashes retained in `release/hns-rs-0.3.0-crates.sha256`, including HRM, durable HNSA/HNSR, and external rollback-journal contracts |
| handshake-org/hsd | `698e252ebc7b5c1dd0a9587e342fdd153d020ae4` | MIT | `test/dns-test.js`, `test/resource-test.js` |
| Denuo-Web/hns-dane-browser | `a71f9ea8dd2e697df6059e8840907f96e6eea2c9` | PolyForm Noncommercial 1.0.0 | `rust/crates/hns-core/src/dns.rs`, `fixtures/experimental-dns-relay/manifest.json` |

The `hns-rs` input is executable source, not only a compatibility reference.
The root manifest requires exact crates.io `=0.3.0`; `Cargo.lock` pins the
registry checksums of the exact sixteen-package engine closure.
`scripts/verify_cargo_source_policy.py` independently verifies the direct and
transitive package sets, consumer locations, versions, registry sources,
archive checksums, and absence of Cargo Git dependencies. Execute-mode release
verification downloads all nineteen upstream packages, rejects a yanked API
record, and checks the downloaded hashes, clean VCS source revision, and exact
`crates/<package>` source path. MeshMine is not a dependency.

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
