# Releasing

The public `hns-dane-engine` crates use one shared version and are published to
crates.io as a dependency-ordered cohort. Crates.io uploads are permanent: a
published version cannot be overwritten or deleted.

The initial twenty `0.2.2` packages were published from immutable source tag
`v0.2.2` at `b7fdf8826c81b77650a0f740d1f05314b74969f9`. The eleven browser
adapter names are new crates on that same version line, with their own
immutable source tag `browser-adapters-v0.2.2`. A release runner must not
recreate an already published package from the successor adapter commit: it
verifies the initial artifacts directly by checksum and provenance, then
packages and publishes only the new names.

The retained stateless-DANE plan correction is a targeted `0.2.3` patch release
of only `hns-namespace-resolution` and `hns-browser-gateway`. It does not
reissue the other twenty-nine crates solely to preserve a workspace-wide version
number. [`release/stateless-dane-0.2.3-crates.txt`](../release/stateless-dane-0.2.3-crates.txt)
is the exact release set. The runner verifies both immutable `0.2.2`
inventories before packaging either patch crate.

## Public package allowlist

The release script processes only these packages, in dependency order:

1. `hns-dns-wire`
2. `hns-browser-runtime`
3. `hns-icann-dane`
4. `hns-namespace-resolution`
5. `hns-resolution-policy`
6. `hns-light-chain`
7. `hns-light-wallet`
8. `hns-dane`
9. `hns-dnssec`
10. `hns-gateway`
11. `hns-cache`
12. `hns-light-p2p`
13. `hns-light-sync`
14. `hns-transport`
15. `hns-resolver`
16. `hns-browser-observability`
17. `hns-p2p-transport`
18. `hns-dane-engine`
19. `hns-dane-engine-ffi`
20. `hns-loopback-proxy`
21. `hns-browser-primitives`
22. `hns-browser-urkel`
23. `hns-browser-dnssec`
24. `hns-browser-dane`
25. `hns-browser-chain`
26. `hns-browser-p2p`
27. `hns-browser-resolver`
28. `hns-browser-transport`
29. `hns-browser-gateway`
30. `hns-browser-loopback-proxy`
31. `hns-browser-sync`

[`release/public-crates.txt`](../release/public-crates.txt) is the
machine-readable authority for this list. The release validator rejects any
divergence among that file, this document, the workspace publish settings, or
the internal dependency order. It also rejects any workspace package or lock
entry that resolves another workspace package through a registry identity
instead of the canonical repository path. The browser adapters in this list
are published under their existing PolyForm Noncommercial license; the
`hns-browser-testkit` fixture crate remains private.

[`release/prepublished-0.2.2-crates.txt`](../release/prepublished-0.2.2-crates.txt)
records the initial twenty packages in dependency order. Their crates.io
checksums are pinned in
[`release/hns-dane-engine-0.2.2-crates.sha256`](../release/hns-dane-engine-0.2.2-crates.sha256).
Execute mode requires each archive to remain non-yanked, match both the API
and downloaded checksums, and carry clean `b7fdf8826c81b77650a0f740d1f05314b74969f9`
provenance at `crates/<name>` before it can upload an adapter.

[`release/prepublished-browser-adapters-0.2.2-crates.txt`](../release/prepublished-browser-adapters-0.2.2-crates.txt)
and
[`release/hns-dane-engine-browser-adapters-0.2.2-crates.sha256`](../release/hns-dane-engine-browser-adapters-0.2.2-crates.sha256)
provide the equivalent immutable registry checksum and
`3907e2a93eb7b10ee7deb1f179ce67824277c82a` provenance record for the eleven
browser adapters. No release operation may reconstruct either `0.2.2` archive
from a later source commit.

Every dependency between public packages carries both a repository path and
the shared crates.io version. The private repository-only test dependency
remains path-only. Cargo removes repository-local source selectors
when it normalizes a source package. Every public package carries a README,
exact workspace license copies, and a package changelog linked to the immutable
shared release notes. Tests that embed the canonical DNS or DANE corpus use
package-local, byte-identical fixture copies so the normalized source never
references a path outside its crate root. `scripts/verify-release.py` checks
these files and fixture copies, crates.io metadata, version requirements,
dependency order, private packages, the exact protocol source, the release
workflow, and execute-mode guards without compiling Rust.

`hns-dane-engine`'s repository-only full-path tests also use the intentionally
private `hns-browser-testkit` development crate. That dependency is not a
published consumer API and Cargo removes it from the normalized manifest. The
release contract therefore qualifies the normalized engine library, examples,
and embedded package data; it does not claim that `cargo test` against the
downloaded engine archive recreates the private repository test harness.

Routine qualification verifies all thirty-one immutable `0.2.2` registry
archives and creates normalized `0.2.3` archives only for the two crates in
`release/stateless-dane-0.2.3-crates.txt`. The separate manual release
preflight performs Cargo's real normalized `cargo publish --dry-run` only for
those two updates while revalidating every recorded immutable artifact.

## Upstream protocol gate

This source consumes twelve direct `hns-rs` packages with exact crates.io
requirement `=0.3.1` and `hns-p2p-experimental` with exact requirement
`=0.4.0`; the lockfile contains the reviewed sixteen-package closure.
Before any engine upload, execute mode reads back the nineteen-package 0.3.1
baseline and the selected 0.4.0 successor archive from the crates.io API and
archive endpoint. It requires non-yanked status, the baseline checksums in
[`../release/hns-rs-0.3.1-crates.sha256`](../release/hns-rs-0.3.1-crates.sha256),
the selected successor checksum in
[`../release/hns-rs-0.4.0-successor-crates.sha256`](../release/hns-rs-0.4.0-successor-crates.sha256),
and clean `.cargo_vcs_info.json` provenance at source revisions
`0e99addca59778b7b7c6fc56291333a97c4c8815` and
`c8feb6f90f3e03efbb982a5e33192dda6fd2f37a`, respectively, with each package's
expected `crates/<name>` path. Any mismatch stops the release before an engine
upload.

The protocol source passed exact CI run
[`32637180489`](https://github.com/handshake-rs/hns-rs/actions/runs/32637180489),
CodeQL run
[`32637186016`](https://github.com/handshake-rs/hns-rs/actions/runs/32637186016),
and the nineteen-package credential-free release preflight in
[`32637182502`](https://github.com/handshake-rs/hns-rs/actions/runs/32637182502).
All nineteen 0.3.1 packages are published and non-yanked, exact archive
readback passed, and source tag `v0.3.1` exists. This is upstream dependency
evidence and does not satisfy any engine gate.

The exact dated engine source at
`2b23bd55d14d36fe60073606869d75b4796c54f7` passed the complete locked CI gate
in run
[`31400455158`](https://github.com/handshake-rs/hns-dane-engine/actions/runs/31400455158),
every configured CodeQL language in run
[`31400453827`](https://github.com/handshake-rs/hns-dane-engine/actions/runs/31400453827),
and the separately dispatched credential-free 19-crate preflight in run
[`31401229842`](https://github.com/handshake-rs/hns-dane-engine/actions/runs/31401229842).
Those workflows performed no upload or tag operation. The results qualify only
that exact commit; a later documentation, metadata, dependency, or source
commit must repeat the exact-commit gates before execute mode is authorized.

Intermediate engine commit `97cbeb2b4e83d603af757f903391c719b29bf429`,
which still pinned protocol preparation source
`abf11ff3b16920c08f3c0b6d32d2e1af7cbe37b2`, passed exact-source CI run
[`31397210853`](https://github.com/handshake-rs/hns-dane-engine/actions/runs/31397210853)
and CodeQL run
[`31397207768`](https://github.com/handshake-rs/hns-dane-engine/actions/runs/31397207768).
Those runs are retained historical evidence and did not replace the manual
19-crate publish preflight.

## Release procedure

1. Update the shared version in the root `Cargo.toml`, every internal dependency
   version, `CHANGELOG.md`, and `release/CRATE-CHANGELOG.md`. Before an upload,
   replace `Unreleased` with the release date in both changelog authorities,
   then repin `scripts/verify_cargo_source_policy.py` together with the root
   manifest, lockfile, `release/hns-rs-<version>-crates.sha256`, release script,
   release validator, and protocol documentation if the final `hns-rs` release
   changed. Synchronize the package copies:

   ```bash
   ./scripts/sync-release-files.sh
   ```

   Execute mode rejects a mismatched version, unsynchronized release file, or
   undated changelog.

2. Run the cheap release checks while preparing source. Archive-only mode does
   not compile package code:

   ```bash
   python3 scripts/verify-release.py --toolchain 1.89.0
   ./scripts/check-publish-arguments.sh
   ./scripts/publish.sh --archive-only
   ```

3. Inspect and commit the exact release source. Execute mode requires a clean
   worktree whose HEAD resolves to one exact 40-character Git commit.

4. Qualify that exact commit with both the complete locked CI gate and the
   repository's CodeQL workflow after an authorized push:

   ```bash
   ./scripts/check.sh
   ```

   Routine qualification reads back the twenty immutable baseline archives and
   performs one archive-only packaging pass for the eleven new adapter crates
   after the normal workspace checks. Confirm
   that CI and every configured CodeQL language completed successfully for the
   same exact commit before continuing.

5. After routine CI succeeds for the exact candidate, manually dispatch
   [`.github/workflows/release-preflight.yml`](../.github/workflows/release-preflight.yml)
   with that lowercase 40-character SHA as the required `expected_commit`:

   ```bash
   gh workflow run release-preflight.yml \
     --ref main \
     -f expected_commit="$(git rev-parse HEAD)"
   ```

   The workflow checks out and reads back the exact immutable commit, uses a
   SHA-keyed concurrency group, receives no publication credential, and runs
   only `./scripts/publish.sh --dry-run`. The equivalent local command is:

   ```bash
   ./scripts/publish.sh --dry-run
   ```

   Both modes inspect each resulting `.crate` for the normalized manifests,
   README, exact licenses and changelog, and exact VCS source commit. They
   reject a dependency path, Git selector, branch, tag, or revision that
   survives normalization. The FFI archive additionally carries the exact
   public C header. A single package may be inspected during preparation, but
   partial selection is unavailable in execute mode:

   While browser adapter crate names are not yet available in the registry, the
   dry-run runner temporarily patches their local dependency graph. Any shared
   engine type that crosses that boundary is patched to the same local source,
   so the preflight rejects a split registry/path Rust type identity rather
   than mistaking it for a package failure. Those temporary Cargo patches are
   command arguments only; normalized package manifests remain registry-only.

   ```bash
   ./scripts/publish.sh --dry-run hns-dane-engine-ffi
   ```

6. Confirm the complete upstream `hns-rs` release, then stop and obtain explicit
   human authorization for the irreversible crates.io upload. Authentication,
   publication, and tagging are never CI steps and are not implied by a
   successful archive check or publish dry-run. Authenticate without storing a
   token in the repository:

   ```bash
   cargo login
   ```

7. Recheck the intended patch version and run the explicitly confirmed upload.
   The confirmation must equal the exact patch-release version:

   ```bash
   ./scripts/publish.sh --execute --confirm-publish 0.2.3
   ```

Execute mode validates the clean, dated adapter source, all upstream protocol
archives, and the twenty initial engine archives before it can reach the first
upload. It reads those prepublished archives directly from crates.io, requiring
their pinned API/download checksums and clean `v0.2.2` provenance rather than
incorrectly recreating them from the successor source. For every new adapter,
the runner creates and inspects the exact local normalized archive before
checking the registry. An HTTP 200 is never sufficient to skip an adapter:
the script downloads the published archive, requires byte-for-byte SHA-256
identity with the local archive, and requires both archives to identify the
current clean adapter release commit. This makes a partially completed adapter
release safely resumable without accepting another artifact under the same
package and version.

Before an upload, the script checks whether the crate name already exists and
selects crates.io's independent action bucket. A new name uses a 605-second
new-name propagation/cooldown interval; a new version of an existing name uses
a 65-second existing-crate update interval. Those defaults add five seconds to
the current [crates.io default refill periods](https://github.com/rust-lang/crates.io/blob/main/src/rate_limiter.rs).
Verified resume skips and the final new upload do not sleep. Override either
interval only when crates.io communicates a different non-negative limit:

```bash
PUBLISH_NEW_INTERVAL_SECONDS=605 \
PUBLISH_UPDATE_INTERVAL_SECONDS=65 \
  ./scripts/publish.sh --execute --confirm-publish 0.2.3
```

After each applicable cooldown, the script downloads the new archive and
applies the same checksum and VCS checks before continuing. On resume, it
reconstructs an already-published package through Cargo's registry-backed
publish dry-run so normalized `Cargo.lock` source/checksum fields reproduce the
uploaded archive exactly. If the registry has not exposed the archive yet, the
command exits safely; rerun the identical execute command after propagation so
resume verification can continue without republishing.

After publication, create and push the annotated
`browser-adapters-v0.2.2` tag from the exact qualified adapter release commit,
then confirm every new package page and docs.rs build. The historical `v0.2.2`
tag remains the source record for the initial twenty packages.
Yanking can discourage new resolution but cannot delete or replace an upload.
