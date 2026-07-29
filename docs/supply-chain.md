# Cargo source and supply-chain policy

The engine is designed to build from an independent clone. It does not depend
on the surrounding ecosystem workspace layout.

## Canonical `hns-rs` source

Nine packages are declared once in the root `[workspace.dependencies]` table:

- `hns-covenants`
- `hns-dns-relay-protocol`
- `hns-encoding`
- `hns-header-consensus`
- `hns-odoh-protocol`
- `hns-p2p-experimental`
- `hns-p2p-wire`
- `hns-primitives`
- `hns-urkel-proof`

Every declaration uses
`https://github.com/handshake-rs/hns-rs.git` at exact revision
`dde2da81f29df935f043978a6d517c1d60ceff31` and also requires crates.io
version `0.1.0`. Development and qualification therefore retain the reviewed
Git source, while Cargo preserves the version and removes the Git selector
when normalizing a package for crates.io. The lockfile resolves those packages
plus transitive `hns-mining` and `hns-transaction` from that same source and
revision. MeshMine is not in the dependency graph.

Engine crates inherit these declarations with `workspace = true`. Other local
crate dependencies remain repository-local paths.

## Enforced invariants

`scripts/verify_cargo_source_policy.py` fails if:

- any `hns-rs` package uses another URL, revision, crates.io version, branch,
  tag, or alias;
- a consumer bypasses the root declaration or appears outside the reviewed
  manifest and dependency section;
- another Git package enters a tracked manifest or the lockfile;
- the direct nine-package or locked eleven-package set changes; or
- any path dependency escapes the engine repository.

The verifier has mutation-derived unit tests in
`tests/test_cargo_source_policy.py`. `cargo-deny` separately enforces reviewed
licenses, advisories, registry sources, and the sole allowed Git repository.
The exact revision remains the verifier's responsibility because
`cargo-deny` source allowlists operate at repository granularity.

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
compilation. Qualification also repeats in an independent clone with no
sibling `hns-rs` directory.

The dual Git-and-version dependency model supports deterministic Git checkout
builds and crates.io normalization. The compatible `hns-rs` version must
already be published before dependent engine crates are released.
