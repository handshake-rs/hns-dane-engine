# Releasing

The public `hns-dane-engine` crates are published to crates.io in dependency
order. Targeted compatible patches may advance only the affected packages;
crates.io uploads are permanent and a published version cannot be overwritten
or deleted.

The initial twenty `0.2.2` packages were published from immutable source tag
`v0.2.2` at `b7fdf8826c81b77650a0f740d1f05314b74969f9`. The eleven browser
adapter names are new crates on that same version line, with their own
immutable source tag `browser-adapters-v0.2.2`. A release runner must not
recreate an already published package from the successor adapter commit: it
verifies the initial artifacts directly by checksum and provenance, then
packages and publishes only the new names.

The retained stateless-DANE plan correction was a targeted `0.2.3` patch
release of `hns-namespace-resolution` and `hns-browser-gateway`, recorded in
[`release/stateless-dane-0.2.3-crates.txt`](../release/stateless-dane-0.2.3-crates.txt).
Those immutable archives are now pinned by checksum and source provenance. The
four light-client `0.2.3` crates are likewise immutable inputs recorded in
[`release/prepublished-light-client-0.2.3-crates.txt`](../release/prepublished-light-client-0.2.3-crates.txt)
and
[`release/hns-dane-engine-light-client-0.2.3-crates.sha256`](../release/hns-dane-engine-light-client-0.2.3-crates.sha256)
at source `87d2346c13ade4987801e0f1367bd604fd77c9f0`.

The loopback-proxy `0.2.3` patch is now an immutable input recorded in
[`release/prepublished-loopback-proxy-0.2.3-crates.txt`](../release/prepublished-loopback-proxy-0.2.3-crates.txt)
and its checksum manifest. The current targeted `0.2.4` mobile-network cohort
advances only `hns-light-p2p`, `hns-browser-chain`, `hns-browser-p2p`, and
`hns-browser-resolver`, as recorded in
[`release/mobile-network-0.2.4-crates.txt`](../release/mobile-network-0.2.4-crates.txt).
It publishes the typed inbound Handshake request events and one coherent
SQLite native-link graph without reissuing any other archive.

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

[`release/prepublished-stateless-dane-0.2.3-crates.txt`](../release/prepublished-stateless-dane-0.2.3-crates.txt)
and
[`release/hns-dane-engine-stateless-dane-0.2.3-crates.sha256`](../release/hns-dane-engine-stateless-dane-0.2.3-crates.sha256)
pin the two earlier `0.2.3` stateless-DANE archives to clean source revision
`142117058690220b066782d8ff0655cf0a2670b3`. They are verified directly and are
never reconstructed from the current release source.

The already-published Shakescape policy and successor engine crates are also
immutable inputs to this patch release. The policy archive is recorded in
[`release/prepublished-policy-0.3.0-crates.txt`](../release/prepublished-policy-0.3.0-crates.txt)
and
[`release/hns-dane-engine-policy-0.3.0-crates.sha256`](../release/hns-dane-engine-policy-0.3.0-crates.sha256)
at source `2e06af3489bd40e0ef90b847101e4f6a7aeebe71`. The remaining four
successor archives are recorded in
[`release/prepublished-shakescape-successor-crates.txt`](../release/prepublished-shakescape-successor-crates.txt)
and
[`release/hns-dane-engine-shakescape-successor-crates.sha256`](../release/hns-dane-engine-shakescape-successor-crates.sha256)
at source `ee222208a7750dcb061c5c3cc16b8cf82d75033e`. Execute mode verifies
those archives directly and never attempts to rebuild them from the current
light-client patch source.

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

Routine qualification verifies every recorded immutable registry archive and
performs Cargo's normalized `cargo publish --dry-run` for the four current
mobile-network `0.2.4` packages from
`release/mobile-network-0.2.4-crates.txt`. This compilation
uses the normalized dependency declarations that crates.io consumers receive,
so registry-only version skew cannot be hidden by workspace path dependencies.
The separate manual release preflight repeats that release boundary for the
exact candidate commit.

## Upstream protocol gate

This source consumes thirteen direct `hns-rs` packages with one exact
crates.io requirement, `=0.4.1`; the lockfile contains the reviewed protocol
closure. Before any engine upload, execute mode reads back all nineteen
packages in the coherent `0.4.1` cohort from the crates.io API and archive
endpoint. It requires non-yanked status, the checksums in
[`../release/hns-rs-0.4.1-crates.sha256`](../release/hns-rs-0.4.1-crates.sha256),
and clean `.cargo_vcs_info.json` provenance at source revision
`73611a0d83778e157b35f28ca2197d068e83fc61`, with each package's expected
`crates/<name>` path. Any mismatch stops the release before an engine upload.

The protocol source passed exact CI run
[`33492052293`](https://github.com/handshake-rs/hns-rs/actions/runs/33492052293),
CodeQL run
[`33492052309`](https://github.com/handshake-rs/hns-rs/actions/runs/33492052309),
and the nineteen-package credential-free release preflight in
[`33492499333`](https://github.com/handshake-rs/hns-rs/actions/runs/33492499333).
All nineteen `0.4.1` packages must be published, non-yanked, and pass exact
archive readback before engine publication. This upstream evidence does not
satisfy any engine gate.

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

2. Run the cheap release checks while preparing source, followed by the real
   normalized package compilation:

   ```bash
   python3 scripts/verify-release.py --toolchain 1.89.0
   ./scripts/check-publish-arguments.sh
   ./scripts/publish.sh --archive-only
   ./scripts/publish.sh --dry-run
   ```

3. Inspect and commit the exact release source. Execute mode requires a clean
   worktree whose HEAD resolves to one exact 40-character Git commit.

4. Qualify that exact commit with both the complete locked CI gate and the
   repository's CodeQL workflow after an authorized push:

   ```bash
   ./scripts/check.sh
   ```

   Routine qualification reads back every immutable baseline archive and
   performs normalized publish dry-runs for the current mobile-network patch
   cohort after the normal workspace checks. Confirm
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
   ./scripts/publish.sh --execute --confirm-publish 0.2.4
   ```

Execute mode validates the clean, dated targeted source, all upstream protocol
archives, and every recorded immutable engine archive before it can reach the
upload. It reads those prepublished archives directly from crates.io, requiring
their pinned API/download checksums and clean source provenance rather than
incorrectly recreating them from successor source. For each new cohort version,
the runner creates and inspects the exact local normalized archive before
checking the registry. An HTTP 200 is never sufficient to skip the package:
the script downloads the published archive, requires byte-for-byte SHA-256
identity with the local archive, and requires both archives to identify the
current clean targeted release commit. This makes a partially completed
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
  ./scripts/publish.sh --execute --confirm-publish 0.2.4
```

After each applicable cooldown, the script downloads the new archive and
applies the same checksum and VCS checks before continuing. On resume, it
reconstructs an already-published package through Cargo's registry-backed
publish dry-run so normalized `Cargo.lock` source/checksum fields reproduce the
uploaded archive exactly. If the registry has not exposed the archive yet, the
command exits safely; rerun the identical execute command after propagation so
resume verification can continue without republishing.

After publication, create and push the annotated
`mobile-network-v0.2.4` tag from the exact qualified release commit, then
confirm all four package pages and docs.rs builds. Historical tags remain the
source records for their immutable packages.
Yanking can discourage new resolution but cannot delete or replace an upload.
