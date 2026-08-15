# Cargo source and supply-chain policy

The engine is designed to build from an independent clone. It does not depend
on the surrounding ecosystem workspace layout.

## Canonical `hns-rs` source

Thirteen packages are declared once in the root `[workspace.dependencies]`
table:

- `hns-covenants`
- `hns-dns-relay-protocol`
- `hns-encoding`
- `hns-header-consensus`
- `hns-hrm`
- `hns-hnsr-protocol`
- `hns-odoh-protocol`
- `hns-p2p-experimental`
- `hns-p2p-wire`
- `hns-primitives`
- `hns-rollback-journal`
- `hns-service-authority`
- `hns-urkel-proof`

Every declaration requires the exact crates.io version `=0.3.0`. The lockfile
resolves those packages plus transitive `hns-chat-protocol`, `hns-mining`, and
`hns-transaction` from the crates.io registry, for a fixed sixteen-package
closure. No Git package is permitted in a tracked manifest or the lockfile.

[`../release/hns-rs-0.3.0-crates.sha256`](../release/hns-rs-0.3.0-crates.sha256)
records the crates.io archive checksum for all nineteen public `hns-rs` 0.3.0
packages. Each archive identifies clean source revision
`d0cde9ded6f8f93f96f16daafc094849c6d484bf` and its expected `crates/<name>`
source path. `hns-script`, `hns-swap`, and `hns-marketplace-protocol` are
verified release-cohort members but are outside this engine's dependency
closure. The newly declared `hns-hrm` and `hns-rollback-journal` dependencies
are dormant facade dependencies reserved for later broker work; this migration
does not alter the legacy `hnsa_route` v2 runtime path.

Engine crates inherit these declarations with `workspace = true`. Other local
crate dependencies remain repository-local paths.

## Enforced invariants

`scripts/verify_cargo_source_policy.py` fails if:

- any direct `hns-rs` package is not an exact `=0.3.0` crates.io dependency or
  uses a Git, path, branch, tag, revision, or alias override;
- a consumer bypasses the root declaration or appears outside the reviewed
  manifest and dependency section;
- any Git package enters a tracked manifest or the lockfile;
- the direct thirteen-package, locked sixteen-package, or public
  nineteen-package set changes;
- a locked package checksum differs from the reviewed archive manifest; or
- any path dependency escapes the engine repository.

The verifier has mutation-derived unit tests in
`tests/test_cargo_source_policy.py`. `cargo-deny` separately enforces reviewed
licenses, advisories, registry sources, and the prohibition on Git sources.

## Qualification

Install the pinned tools and fetch the locked graph once:

```sh
cargo +1.89.0 install cargo-deny --version 0.19.9 --locked
cargo +1.89.0 fetch --locked
```

Then run the complete gate:

```sh
./scripts/check.sh
```

All Cargo compilation, test, lint, and release-build steps in that gate use
`--locked --offline`. The source-policy tests and metadata check run before
compilation. After the workspace build, the gate creates and inspects all 19
normalized source archives without compiling them again. Cargo's real publish
dry-runs remain isolated in the exact-commit manual workflow documented in
[`releasing.md`](releasing.md). Qualification also repeats in an independent
clone with no sibling `hns-rs` directory.

Before an upload, release execute mode independently reads back all nineteen
crates.io API records and archives. It requires exact version 0.3.0, non-yanked
status, the reviewed archive checksums, and clean per-package VCS provenance at
the reviewed source revision and paths.
