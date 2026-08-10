# Releasing

The public `hns-dane-engine` crates use one shared version and are published to
crates.io as a dependency-ordered cohort. Crates.io uploads are permanent: a
published version cannot be overwritten or deleted.

## Public package allowlist

The release script processes only these packages, in dependency order:

1. `hns-dns-wire`
2. `hns-browser-runtime`
3. `hns-icann-dane`
4. `hns-namespace-resolution`
5. `hns-resolution-policy`
6. `hns-light-chain`
7. `hns-dane`
8. `hns-dnssec`
9. `hns-gateway`
10. `hns-cache`
11. `hns-light-p2p`
12. `hns-light-sync`
13. `hns-transport`
14. `hns-resolver`
15. `hns-browser-observability`
16. `hns-p2p-transport`
17. `hns-dane-engine`
18. `hns-dane-engine-ffi`
19. `hns-loopback-proxy`

[`release/public-crates.txt`](../release/public-crates.txt) is the
machine-readable authority for this list. The release validator rejects any
divergence among that file, this document, the workspace publish settings, or
the internal dependency order. It also rejects any workspace package or lock
entry that resolves another workspace package through a registry identity
instead of the canonical repository path. The twelve browser adapter and
fixture crates outside the list must remain private.

Every dependency between public packages carries both a repository path and
the shared crates.io version. Private repository-only adapter and test
dependencies remain path-only. Cargo removes repository-local source selectors
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

Routine qualification creates all 19 normalized archives with `cargo package
--no-verify` and applies the custom archive inventory checks. The separate
manual release preflight performs Cargo's real normalized `cargo publish
--dry-run` for every package, keeping that repeated compilation out of the
routine gate.

## Upstream protocol gate

This source consumes `hns-rs` `0.2.0` at final dated release-source revision
`b24b66c382de53330ec21dd3137e056a2bea3e2d`. Before any engine upload,
execute mode downloads all 17 protocol packages and requires every
`.cargo_vcs_info.json` to identify that exact clean source revision. If the
protocol release is published from a later commit, stop and repin
the engine manifest, lockfile, release script, validator, and documentation to
the actual published commit before qualifying the engine release.

The pinned protocol source passed exact CI run
[`31398600728`](https://github.com/handshake-rs/hns-rs/actions/runs/31398600728),
CodeQL run
[`31398598588`](https://github.com/handshake-rs/hns-rs/actions/runs/31398598588),
and the 17-package credential-free release preflight in
[`31399004538`](https://github.com/handshake-rs/hns-rs/actions/runs/31399004538).
This is upstream dependency evidence and does not satisfy any engine gate.

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
   manifest, lockfile, release script, release validator, and protocol
   documentation if the final `hns-rs` source changed. Synchronize the package
   copies:

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

   Routine qualification runs one archive-only packaging pass after the normal
   workspace checks; it does not repeat 19 normalized package builds. Confirm
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

7. Recheck the intended version and run the explicitly confirmed upload. The
   confirmation must equal the workspace version:

   ```bash
   ./scripts/publish.sh --execute --confirm-publish 0.2.0
   ```

Execute mode validates the clean, dated source and all upstream protocol
archives before it can reach the first upload. For every engine package it
creates and inspects the exact local normalized archive before checking the
registry. An HTTP 200 is never sufficient to skip: the script downloads the
published archive, requires byte-for-byte SHA-256 identity with the local
archive, and requires both archives to identify the current clean release
commit. This makes a partially completed release safely resumable without
accepting another artifact under the same package and version.

New uploads use a 605-second propagation and cooldown interval before the next
allowlisted crate by default. Verified resume skips and the final new upload do
not sleep. Override the interval only when crates.io communicates a different
non-negative limit:

```bash
PUBLISH_INTERVAL_SECONDS=605 \
  ./scripts/publish.sh --execute --confirm-publish 0.2.0
```

After each cooldown, the script downloads the new archive and applies the same
checksum and VCS checks before continuing. If the registry has not exposed the
archive yet, the command exits safely; rerun the identical execute command
after propagation so resume verification can continue without republishing.

After publication, create and push the annotated `vX.Y.Z` tag from the exact
qualified release commit, then confirm every package page and docs.rs build.
Yanking can discourage new resolution but cannot delete or replace an upload.
