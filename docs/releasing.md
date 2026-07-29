# Releasing

The `hns-dane-engine` libraries use a shared version and are published to
crates.io. Published versions are permanent and cannot be overwritten.

## Public package allowlist

The release script publishes only these packages, in dependency order:

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

Repository-local public dependencies carry both a workspace path and the
shared crates.io version. The nine direct `hns-rs` dependencies carry their
crates.io version together with the reviewed Git URL and exact revision. Cargo
removes path and Git selectors while creating a crates.io package and preserves
the compatible version requirements.

## Private packages

`hns-browser-testkit` is a development-only fixture package and must retain
`publish = false`. Path-only development dependencies on it are omitted from
published packages. The release preflight fails if Cargo permits the testkit to
be published.

## Release procedure

1. Update the shared version, every internal dependency version, the compatible
   `hns-rs` version requirements, and `CHANGELOG.md`.
2. Run the complete locked qualification gate:

   ```bash
   ./scripts/check.sh
   ```

3. Inspect and commit the exact release source. Execution mode refuses a dirty
   worktree, including untracked files.
4. Authenticate without placing a token in the repository:

   ```bash
   cargo login
   ```

5. Re-run the package-only preflight if desired:

   ```bash
   ./scripts/publish.sh --dry-run
   ```

   The preflight temporarily patches unpublished engine dependencies to their
   repository-local sources. Where that would mix normalized crates.io
   dependencies with the pinned development source, it also patches the
   affected crates.io dependencies back to the exact reviewed `hns-rs` Git
   revision. This gives one coherent package identity while Cargo verifies
   every archive before its engine dependencies exist on crates.io. None of
   these temporary patches are used for real uploads.

6. Publish the allowlist:

   ```bash
   ./scripts/publish.sh --execute
   ```

The execution mode is restartable: it checks the crates.io API and skips
versions already present. It waits 605 seconds after each new upload by default
to respect the current new-crate cooldown. Override that delay only if
crates.io communicates a different limit:

```bash
PUBLISH_INTERVAL_SECONDS=605 ./scripts/publish.sh --execute
```

After publication, create an annotated `vX.Y.Z` tag, push the commit and tag
from an authorized checkout, and confirm every package page and docs.rs build.
This repository's operating rules prohibit pushing from the preparation
checkout.
