# Releasing

Select only packages whose source or published dependency requirements change.
Keep compatible unaffected packages on their selected versions. An upload is
permanent and cannot replace an existing package/version archive.

## Package selection

The dependency-order authority is
[`release/public-crates.txt`](../release/public-crates.txt):

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

The current targeted set is the seven `0.2.6` light-client and SQLite browser
packages in
[`release/mobile-wallet-0.2.6-crates.txt`](../release/mobile-wallet-0.2.6-crates.txt).
Other public packages retain the versions in their manifests. The private
`hns-browser-testkit` is never published. Browser adapters retain their
PolyForm Noncommercial license; foundation crates retain their manifest license.

## Source and dependency gates

Direct protocol dependencies require exact crates.io `=0.5.0`. The complete
nineteen-package upstream checksum manifest is
[`release/hns-rs-0.5.0-crates.sha256`](../release/hns-rs-0.5.0-crates.sha256),
with clean reviewed source revision
`60eb912d615243a6bfb9741b17f16833c5a9181a`.
Execute mode checks non-yanked API records, downloaded archive checksums, clean
VCS provenance, and the expected `crates/<name>` source paths. The immutable
engine dependency manifests in `release/` receive the same verification. Do
not reconstruct an immutable dependency archive from a different commit.

Every public crate carries its README, license copies, current changelog, and
package-local fixture data. Normalized archives must contain no escaping path
or Git selector. The FFI archive must contain the exact public C header.
Repository-only tests may use the private testkit; normalized package consumers
receive the library and embedded package data without that private harness.

## Candidate procedure

Update only affected package versions and their current changelogs, compatible
internal dependency requirements, the selected release set, and version guards.
Keep shared changelog templates synchronized only for packages using those
templates. `scripts/sync-release-files.sh` synchronizes licenses and common
fixture data while preserving the individually versioned patch changelogs.

Run the source, archive, and normalized compilation checks:

```sh
python3 scripts/verify-release.py --toolchain 1.89.0
./scripts/check-publish-arguments.sh
./scripts/publish.sh --archive-only
./scripts/publish.sh --dry-run
./scripts/check.sh
```

A focused preparation check is available as:

```sh
./scripts/publish.sh --dry-run hns-dane-engine-ffi
```

Execute mode uses the complete selected release set; partial execute selection
is unavailable. Temporary command-scoped local patches used for preparation
must not enter tracked manifests or normalized packages.

Commit the exact candidate on `main`. Execute mode requires a clean worktree
and a lowercase 40-character HEAD. Once the candidate has been pushed with
explicit authorization, require successful CI and CodeQL for that exact SHA.
The credential-free
[release preflight workflow](../.github/workflows/release-preflight.yml) takes
that SHA as its required `expected_commit` and runs normalized dry-runs:

```sh
gh workflow run release-preflight.yml --ref main \
  -f expected_commit="$(git rev-parse HEAD)"
```

Inspect normalized manifests, archive inventory, checksum, and source
provenance. A successful build, authenticated registry session, or preflight
never authorizes upload, tagging, or deployment.

## Authorized upload and readback

After explicit publication authorization, the current confirmation command is:

```sh
./scripts/publish.sh --execute --confirm-publish 0.2.6
```

The runner checks the clean dated candidate, all protocol inputs, and immutable
engine dependencies before upload. It creates and inspects the exact local
archive before considering a registry resume skip. A skip requires matching
API/download SHA-256, byte-identical local archive, and clean VCS provenance
at the exact candidate commit. A version collision stops execution.

The runner uses a 605-second new-name interval and a 65-second existing-crate update
interval. Verified resume skips and the final upload require no cooldown.
Override only with a registry-approved non-negative interval:

```sh
PUBLISH_NEW_INTERVAL_SECONDS=605 \
PUBLISH_UPDATE_INTERVAL_SECONDS=65 \
  ./scripts/publish.sh --execute --confirm-publish 0.2.6
```

After propagation, the downloaded archive receives the same checksum and VCS
checks. If propagation is incomplete, rerun the identical execute command
against the same clean commit. Tagging and GitHub release publication require
separate authorization. Confirm every selected package page and docs.rs build.
