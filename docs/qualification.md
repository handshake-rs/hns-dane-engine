# Foundation qualification

The command transcript below is retained evidence from published tag `v0.1.0`
(commit `02c063ac3e94a91b222201fb51d95ff3ac19f026`). It does not qualify the
current unreleased 0.2 provider-authority continuation or the August 9 shared
platform-adapter consolidation. The current line has not received the
benchmark, C-header, or complete release qualification gate. The narrow
provider-authority ABI regression recorded below is the only compiled test
evidence retained from the earlier continuation. The focused HNSA batch
selection and direct-open tests recorded below add current-head Rust evidence,
but the adapter consolidation and current `hns-rs` repin add no
installed-product or live-network evidence. `cargo-deny` may separately
refresh its advisory database:

The current `scripts/check.sh` qualifies the default Chromium workspace and
then separately qualifies the mobile-only configurations of
`hns-browser-gateway`, `hns-browser-loopback-proxy`, and
`hns-browser-transport`. Those crates deliberately require exactly one platform
feature, so a workspace-wide `--all-features` invocation is invalid rather than
stronger coverage. The historical v0.1 transcript below predates those
exclusive platform crates.

```text
python3 -m unittest -v tests/test_cargo_source_policy.py
  12 tests passed

python3 scripts/verify_cargo_source_policy.py
  exact canonical hns-rs source and repository-local paths passed

cargo +1.89.0 metadata --locked --offline --format-version 1
  passed from a standalone checkout with no sibling hns-rs tree

cargo +1.89.0 deny --locked check --config deny.toml
  advisories, licenses, bans, and sources passed

cargo test --workspace --all-targets --all-features --locked --offline
  177 unit tests passed

cargo test --workspace --doc --all-features --locked --offline
  20 doc-test targets passed (0 doctests)

cargo test --workspace --all-features --locked --offline
  177 unit tests passed

cargo test --workspace --locked --offline
  177 unit tests passed

cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings
  passed

cargo build --workspace --all-features --release --locked --offline
  passed

cc -std=c11 -Wall -Wextra -Werror -fsyntax-only tests/abi_header_smoke.c
  passed
```

Current unreleased focused evidence (2026-08-03):

```text
CARGO_TARGET_DIR=/home/den/.codex/targets/hns-dane-engine-authority-abi-aug3 \
TMPDIR=/home/den/.codex/tmp/hns-dane-engine-authority-abi-aug3 \
cargo test --offline -p hns-dane-engine-ffi provider_authority_ffi -- --test-threads=1
  2 passed; 0 failed; 5 filtered out
```

Current non-compiling dependency-policy evidence (2026-08-09):

```text
python3 -m unittest -v tests/test_cargo_source_policy.py
  13 tests passed

python3 scripts/verify_cargo_source_policy.py
  exact canonical hns-rs source at b33b346780c8f6a9bb18a54390019486cdab0221
  and repository-local paths passed

cargo +1.89.0 metadata --locked --offline --format-version 1
  passed
```

These checks qualify only the locked dependency-source policy; they compiled
and executed no Rust or platform implementation.

Current focused HNSA engine evidence (2026-08-09):

```text
cargo +1.89.0 fmt --all -- --check
  passed

cargo +1.89.0 test --locked --offline -p hns-dane-engine --lib hnsa_route::tests
  10 passed; 0 failed; 33 filtered out

cargo +1.89.0 check --locked --offline -p hns-dane-engine --lib
  passed

cargo +1.89.0 clippy --locked --offline -p hns-dane-engine --lib --tests -- -D warnings
  passed

cargo +1.89.0 test --locked --offline --workspace
  passed

cargo +1.89.0 clippy --locked --offline --workspace --all-targets -- -D warnings
  passed

cargo +1.89.0 build --locked --offline --release --workspace
  passed
```

These commands compiled and exercised full signed regtest batch selection,
multilevel conflict and rollback rejection, bounded state round trips and
capacity exhaustion, state advancement without a usable route, direct
named-route open, node-only raw-open enforcement, and external/engine
invalidation boundaries. They do not qualify directory discovery,
response-completeness or quorum policy, live network execution, authenticated
platform persistence, mobile/Chromium products, or the complete 0.2 release.

The requester-only ODoH lifecycle, status, revocation, and signed-target cache
continuation was added after the August 3 ABI command. Its source tests are
covered by the current full workspace pass, but the complete release gate and
live adapter qualification have not run.

The first locked invocation stopped before compilation because the workspace
lockfile still carried a stale `hns-loopback-proxy` dependency list. The same
focused command regenerated that local-package stanza offline; the corrected
lockfile is committed with this continuation.

Recorded foundation coverage and current source status:

- independently cloneable Cargo resolution with eleven reviewed direct
  `hns-rs` packages and the exact fourteen-package locked closure at
  `b33b346780c8f6a9bb18a54390019486cdab0221`; rejection of mutable or
  noncanonical Git sources, aliases, unreviewed consumers/packages, lock
  drift, and external path dependencies;
- hard 65,535-byte DNS message bound and configurable tighter limits;
- bounded questions, records, RDATA, labels, expanded names, and compression jumps;
- backward-only compression pointers with self/forward, out-of-bounds, and cycle defenses;
- strict single-question correlation across ID, opcode, name, type, class, and truncation;
- typed A, AAAA, NS, CNAME, SOA, MX, TXT, SRV, DS, DNSKEY, RRSIG, NSEC, NSEC3, TLSA, and OPT;
- DNSSEC bitmap and EDNS framing validation, including strict-query ECS rejection;
- the AD bit retained only as an untrusted claim;
- shared automatic ICANN TLSA owner derivation across nondefault ports and TCP/UDP/SCTP, plus typed
  validating-DoH decisions that enforce secure presence, permit WebPKI only for authenticated
  absence or insecure delegation, ignore unsigned TLSA bytes, and keep unauthenticated,
  bypassed, bogus, indeterminate, incomplete, or contradictory evidence fail-closed;
- syntax-only canonical full-host admission with no IANA authority list; independent HNS/ICANN
  plan, authenticated-absence, and failure types; explicit HNS-only, ICANN-only, convergent,
  divergent, and neither outcomes; complete query binding; whole-plan comparison across origin
  aliases, ServiceMode target, endpoint CNAMEs/final owner, addresses, HTTPS/SVCB mandatory
  parameters, ordered ALPN, bounded hints, scheme/protocol coherence, effective transport, TLS
  policy, and supported TLSA; no
  cross-root record mixing; exact HNS proof-anchor provenance; secure/insecure ICANN chain
  provenance; absolute non-renewing freshness; any-root failure and stale-evidence rejection;
  pin/binding/first-use precedence; joint convergent freshness; and
  query/policy/root/configuration-bound decision and decision-derived cache fingerprints,
  including rejection of a silent switch away from an authentically absent pinned or persistently
  bound root;
- unqualified 0.2 source and test cases for exact HTTPS-only
  logical-origin derivation; private decision/authentication contexts;
  exact-request opaque ICANN adapter tokens; strict HNS completion binding
  across URL/service ports, canonical TLSA, network, proof anchor, and
  provenance; all-outcomes typed permission; a non-cloneable,
  non-serializable authorized-only provider context; engine-owned context
  consuming decision revalidation plus borrowed opaque-context currentness;
  admission-watermark survival across unrelated work; runtime
  session/generation, policy generation, authority event, decision
  fingerprint, freshness, authentication lifetime, and selected TLS policy
  checks; plus negative cases for HTTP, WS, WSS, unauthenticated,
  no-root, other-origin/port/root/decision/TLSA/provenance/network, stale
  decision and exact expiry, other-session, revoked generation,
  degraded/revoked/stopped authority, retained ICANN token replay across
  another exact request or any changed binding, and ICANN DANE/WebPKI mismatch;
  plus source-only, unexecuted loopback publication cases for
  authorized-context-only creation, complete provider/process/listener binding,
  bounded registry and lifetimes, expired/engine-invalid publication reclamation,
  rollback-safe expiring pending records,
  generation-checked atomic publish/replace/revoke, short-grant revalidation,
  and restart isolation;
- canonical shared `hns-rs` network genesis, 236-byte header, proof-of-work, median-time,
  difficulty-transition, and chainwork validation for contiguous light-chain extensions;
- transactional bounded header batches and retention of the exact 147-entry Handshake retarget
  context, plus a recent-first exponential locator ending at network genesis;
- standard HSD version/verack admission with protocol/service, self-connection, clock-skew, and
  handshake-deadline checks; bounded one-at-a-time header/proof/ping requests; exact proof
  root/key and pong correlation; and response deadlines enforced during frame admission;
- bounded multi-peer same-base header rounds; independent transactional consensus validation;
  unique greatest-chainwork selection; configurable peer agreement; equal-work ambiguity
  rejection; invalid-response scoring/banning; duplicate/stale/deadline defenses; and current-state
  gating on a complete-response round whose valid peers report no extension and no non-banned peer
  advertises a higher height;
- explicit minimum-height, minimum-chainwork, maximum-tip-age, and future-tip currency rejection;
- strict HSD Urkel inclusion proofs at the exact validated header tree root;
- strict HSD `NameState` decoding, proof-key/name equality, state-height bounds, canonical compact
  integers, assigned-field enforcement, and the 512-byte resource limit;
- assigned DS, NS, GLUE4, GLUE6, SYNTH4, SYNTH6, and TXT resource parsing with bounded DNS-name
  decompression and unknown-tag, forward-pointer, and loop rejection;
- a private verified-HNS-resource token that is the only HNS Rust path into initial DS/DNSKEY
  authentication;
- RSA, ECDSA, Ed25519, and Ed448 DNSSEC RRset validation with RFC serial-time handling;
- DS-authenticated DNSKEY keysets, child-delegation chaining, SHA-1/SHA-256/SHA-384 DS matching,
  and DNSKEY revocation/protocol checks;
- NSEC and NSEC3 no-data/name-error validation, closest-encloser/wildcard proofs, bounded NSEC3
  iterations, and the RFC 5155 example vector;
- strict DANE-EE and DANE-TA usage validation with no PKIX usages, network, or WebPKI fallback;
- exact DER extraction of certificate SPKI plus full-certificate/SPKI selectors and
  exact/SHA-256/SHA-512 matching;
- private-root DANE-TA certificate signature, explicit-time, strict hostname, chain-completeness,
  and chain-bound validation, including the RFC 7671 full-certificate omitted-anchor case;
- bounded locally signed CNAME chasing across one or multiple correlated responses, loop and
  ambiguous-data rejection, exact terminal TLSA binding, and SNI mismatch rejection;
- positive real-certificate fixtures, negative mismatch/mutation cases, unsupported TLSA fields,
  malformed DER, wrong digest lengths, nonzero response codes, missing/wrong-owner TLSA, and input
  bounds;
- checksummed fixed-length policy persistence with schema-1/schema-2 migration to schema 3,
  optimistic updates, generation revocation, independent requester/relay/output controls,
  persistent opt-out for opaque ODoH and HNSR relaying, explicit opt-in for
  plaintext/output-node roles and configured recursive HNS DoH, older-schema decoding of the new
  consent as false, and conflicting privacy-policy rejection;
- direct-authoritative-first planning with no OS or implicit recursive fallback and configured
  recursive HNS DoH admitted only as an explicitly consented terminal transport, plus append-only
  `LocalHnsProof` status provenance that is never planned or admitted;
- engine-integrated, policy-generation-bound gateway ordering; one process-unique active attempt;
  response/identity/deadline bounds; valid UDP-truncation-to-TCP handling; retry only for
  reachability, timeout, or unsupported paths; fail-closed malformed/authentication/cancellation
  handling; ODoH proxy/target topology; derived relay downgrade; and foreign-token/stale-policy
  rejection;
- authenticated HIP-76/HIP-77 adapter contracts; exact negotiated packet admission; non-cloneable
  independent request-ID sequences; adapter-attested Brontide response identity; request/response
  ID and deadline checks; negotiated outbound and local inbound allocation bounds; signed current
  ODoH target selection and response-time currency;
  distinct proxy/target enforcement; fixed-bucket outer padding; local HPKE seal/open; qname
  non-disclosure to the proxy; exact DNS parsing/correlation; mutated ciphertext rejection; and
  gateway failure classification;
- unqualified 0.2 source for an engine-admitted, requester-only ODoH runtime:
  exact runtime session/generation/invalidation/policy/network binding;
  canonical network/genesis/registry/negotiation proxy admission; exact
  policy-resolved Denuo V1 peer-profile retention; mandatory Denuo-extension
  and ODoH services; rejection of Official, Denuo V2, legacy-draft, and
  unresolved automatic peer profiles; status schema 4 exposure of the resolved
  peer profile and monotonic cache generation; target-cache wire schema 3 with
  a mandatory caller-held restore floor;
  pre/post-adapter invalidation and response start/deadline monotonicity; closed
  readiness/revocation; a 16-locator signed-target cache with sequence and
  trusted-time and generation high-water retention; bounded canonical
  checksummed schema-3 restart encoding, caller-held generation-floor
  enforcement, signature/network/locator/configuration/sequence/lifetime
  revalidation, and permanently unavailable proxy/target provider roles;
- unqualified 0.2 source for canonical GETCONFIG/CONFIG acquisition and the
  HNSR requester/opaque-relay adapter: borrowed consumption of the one
  platform-owned `BrowserRuntime`; exact Denuo V1 outer-peer, connection,
  network/genesis, policy, role, and service-profile binding; signed-ticket
  requester flow control; opaque reservation/circuit routing; exact queued
  write acknowledgement and disconnect cleanup; checked role enablement
  replacement/revocation; nested checksummed snapshots with caller-held
  generation and trusted-time floors; no restored live state; and permanently
  unavailable endpoint, rendezvous, plaintext, and transport-adapter fields;
- unqualified 0.2 source for bounded HNSA batch verification and conflict-safe
  greatest authorization/delegation/per-endpoint route selection from a
  non-forgeable current HNS resource; one bounded checksummed
  `HnsaNamedRouteState` with global authorization and up to 64 endpoint
  delegation/route histories; sticky conflict and capacity-exhaustion states;
  and a direct named-route requester-open sink that rechecks the exact
  external, engine, requester, expiry, and committed-state authorities without
  exposing raw tickets;
- atomic engine admission of a gateway selection's policy generation, actual transport, response,
  identities, and relay-downgrade state, including non-cloneable selection consumption and
  stale-selection rejection before an engine event is consumed;
- engine-derived HNS proof, chain-currency, DNSSEC, TLSA, DANE, and SNI evidence; exact
  Handshake-network and validation-time binding; derived rather than caller-selected provenance
  anchors; and distinct ODoH proxy/target identity enforcement;
- the complete 13-by-13 authority transition matrix, terminal stop behavior, policy-change
  generation revocation, monotonic event stamps, stable discriminants, checked zero-session
  rejection, and rejection of other-session, stale-generation, future, degraded, revoked, and
  stopped work—including an engine-level cross-session response-replay negative; explicit bypass
  edges cover pre-navigation bridge startup and authenticated-absence/proven-insecure ICANN WebPKI
  without entering the DANE state;
- strict completion encapsulation and browser-bridge authorization bound to each admitted fully
  verified exact origin, runtime/policy security epoch, event sequence, and chain validity window;
  interleaved completion retention and unrelated-event survival;
  legacy completion, stale provenance, wrong-origin, not-yet-valid, and expired authorization
  rejection;
- numeric-loopback endpoint/client enforcement; fresh-instance capability and realm binding;
  fixed-width constant-time Basic-token comparison; credential-bearing debug redaction; strict
  bounded `CONNECT`/`Host` parsing; exact HNS TLD/port scope; body, upgrade, duplicate-auth, IP, and
  malformed-authority rejection; bounded one-shot pending tokens; invalidation-watermark rejection;
  non-cloneable validity-window-carrying tunnel grants; and process-instance isolation;
- a shared end-to-end regtest fixture that mines and validates a header, verifies its committed
  Urkel/`NameState` DS resource, authenticates DNSKEY, validates a signed TLSA response, derives
  exact-certificate DANE evidence, mints the engine bridge authorization, and issues only the exact
  current proxy tunnel grant;
- shared status schema v2 with one private-field runtime/authority snapshot, policy generation,
  network/chain anchor, complete policy, actual transport including validating ICANN DoH and
  proof-contained local HNS origin data, bounded identities, experimental-P2P-only registry
  fingerprint/profile/version, HNSR/provider roles and policy-derived readiness, aggregate rate
  limits, sanitized namespace
  outcome/selection/fingerprint and root-failure fields, typed ICANN DNSSEC/TLS action,
  authority-consistent
  degraded/revocation reasons, and bounded unsupported-evidence details;
- exhaustive authority-state/degraded-option/revocation-option status checks; direct transport
  without registry metadata; provider-disabled policy derivation; name-free ICANN DANE,
  authenticated-absence WebPKI, proven-insecure WebPKI, bogus failure, indeterminate failure, and
  divergent-root selection; fail-closed failed/unavailable/unsupported/not-attempted/stale/revoked
  evidence; selected-ICANN and failed-ICANN facade evidence requirements, outcome-free bogus and
  indeterminate lookup failures, HNS/registry metadata clearing, and stale-provenance suppression
  for failed classification and `Neither`; and
  cross-field negatives preventing failure evidence from becoming WebPKI or DANE or exact
  WebPKI/DANE tuples from being relabeled as failure, ICANN root failure from omitting fail-closed,
  or non-P2P transport from carrying experimental registry identity;
- all required evidence states: verified, failed, unavailable, unsupported, not attempted, stale,
  and revoked, with verified-state clearing on engine degradation or policy revocation;
- qname-free secret-derived cache keys bound to network, runtime generation, policy generation,
  chain height/tree root, qtype, and canonical DNS name; bounded positive/negative TTLs; exact
  entry/value/total-byte limits; LRU eviction; and remove-before-use expiry/stale handling;
- proof-derived in-bailiwick authoritative endpoints; mainnet/testnet public-address and port-53
  enforcement; explicit regtest-only loopback fixture ports; exact HNS TLD and request-time anchor
  binding; finite socket/message bounds; connected UDP source filtering; exact TCP length framing;
  lifecycle cancellation; and strict DNS response correlation;
- explicit browser authority states;
- C layout assertions for policy V1 and V2, ownership functions, nonzero runtime-session rejection,
  V2 recursive-HNS-DoH consent exchange, V1 fail-closed downgrade behavior, transport planning,
  query admission, end-to-end local DANE matching, caller-DANE-bit rejection, response correlation,
  and panic containment; and
- positive pinned vectors plus mutation-derived negatives.

Implemented in shared source, but not qualified:

- private mobile/Chromium adapter packages provide request-surface wiring,
  validating ICANN DoH, origin TLS transport, native loopback listener and
  HTTP/TLS handling, local CA and exact-host leaf management, and browser
  platform bridges;
- mobile and Chromium shells consume those shared packages at source level,
  but no installed-product or live-network evidence and no current-head 0.2
  qualification gate establish provider availability.

Still absent or unevidenced:

- socket dialing and peer discovery, competing-fork download/reorganization before the current
  base, durable restart state, and checkpoint bootstrap (current sync selects bounded extensions
  from one shared validated base);
- subdelegation discovery and a complete live authoritative DNSSEC walk beyond the on-chain TLD
  DNSKEY path;
- authenticated authoritative DoH and HIP-76/77 provider roles;
- a native Brontide socket adapter and live Denuo registry negotiation exchange
  for the implemented HIP-76/77 requester boundary, engine-owned ODoH
  lifecycle, and HNSR requester/opaque-relay state machines, plus HSD draft-PR
  cross-language execution (the requester consumes and enforces an already
  authenticated `NegotiatedRegistry`);
- complete HNSA directory discovery and response-completeness/quorum policy,
  authenticated rollback-resistant platform persistence of
  `HnsaNamedRouteState` with resource/profile generation and trusted-time state,
  HNSA live routing and endpoint-authenticated inner sessions, and HNSR
  endpoint/rendezvous roles;
- qualified atomic authenticated rollback-resistant ODoH target-cache and HNSR
  snapshot/floor writes, durable platform preferences, and restart evidence;
- pure-C namespace/context authority minting (the authorized-only consumer ABI
  can only receive a context moved from trusted Rust);
- fuzz targets, HSD-generated live DNSSEC fixture generation, and performance benchmarks.

The strict Rust facade has a non-forgeable
header/Urkel/resource/DS/DNSKEY/CNAME/TLSA path and derives DANE-EE or DANE-TA
evidence locally. Rust facade version 3 also has source for a fail-closed
exact-origin provider-injection authority, opaque authorized-only context, and
bounded loopback publication consumer,
while the legacy C resolution ABI still accepts prerequisite verdicts and
exposes neither the full proof workflow nor opaque namespace/authentication
contexts. The source-only consumer ABI can retain an authorized Rust provider
context, inspect its immutable bindings, copy its bounded host, check engine
currentness, and destroy it, but cannot mint authority from C. Its two focused
Rust ABI regressions passed in this continuation. Full Rust workspace tests,
strict all-target Clippy, and an optimized workspace build passed; the C header
smoke, benchmarks, and complete release gate were not rerun. The new Rust
context/publication, ODoH requester-lifecycle, and HNSA
batch-selection/direct-open source, the shared platform-adapter consolidation
and source consumption, the current `hns-rs` repin, and the unreleased 0.2 line
still require the applicable qualification gate. No installed-product evidence
has been recorded, and
platform provider availability remains disabled. This repository therefore
does not claim that the complete browser engine or ecosystem is qualified.
