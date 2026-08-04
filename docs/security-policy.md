# HNS browser security policy

For an HNS HTTPS origin, success requires all of:

1. locally validated Handshake state and a verified current Urkel proof;
2. a DNS response correlated to the exact local query;
3. local DNSSEC validation;
4. an exact, supported TLSA match;
5. local DANE origin validation, including SNI; and
6. an admission token from the current runtime and policy generations.

Opening a browser tunnel additionally requires an engine-issued
`ProviderAuthorityContext` consumed into the current process/listener publication registry. For HNS,
any strict completion whose private admission stamp remains valid in the current security epoch can
authenticate its exact namespace decision. Unrelated completions do not revoke it. The publication
binds the complete provider, runtime, policy, event, decision, lifetime, registry, process, and
listener tuple. Legacy completions based on
caller-supplied prerequisite verdicts cannot authorize this path.

For an ICANN HTTPS or WSS origin, the shared policy derives
`_<effective-port>._<transport>.<canonical-host>.` without a hostname allowlist. The browser adapter
queries that owner through its TLS-authenticated validating ICANN DoH resolver with DNSSEC records
requested and checking enabled. Secure TLSA presence selects mandatory DANE. Authenticated denial
or a proven insecure delegation retains WebPKI; unsigned TLSA bytes are ignored. An
unauthenticated resolver channel, validation bypass, missing authenticated denial, contradictory
evidence, bogus DNSSEC, an indeterminate result, or any transport/HTTP/DNS parsing failure is
terminal and can never be relabeled as “no TLSA.” This policy must be invoked at the common request
boundary used by navigations, redirects, subresources, Service Workers, downloads, and WebSockets.

Namespace selection is based on independent resolution of the complete hostname through both HNS
and ICANN, not on whether its rightmost label appears in an IANA list. The only authoritative
outcomes are HNS-only, ICANN-only, both convergent, both divergent, and neither. Presence in one
root is usable only after authenticated absence in the other; failure, bogus or indeterminate
DNSSEC, stale HNS state, unauthenticated resolver transport, or stale evidence on either side makes
the classification indeterminate. A selected plan supplies every endpoint, alias, service-binding,
and TLS decision; records from different roots are never mixed. Origin and endpoint alias paths
are retained separately around the normalized HTTPS/SVCB ServiceMode TargetName. Terminal
AliasMode, unsupported/missing mandatory parameters, inconsistent ALPN/transport/port/hints, alias
cycles, unsupported or malformed TLSA, and endpoints unrelated to retained connection hints fail
closed.

Every plan, authenticated absence, and failure binds the full
scheme/host/effective-origin-port/protocol-capability query. HNS evidence carries the exact
network/tree-root/height anchor from the proof used by that lookup; a separately reopened best tip
is not provenance. ICANN evidence carries the authenticated validating-DoH DNSSEC chain state.
Positive and negative evidence uses an absolute expiry capped by applicable TTL or SOA negative
TTL, RRSIG expiry, HNS currency, and lifecycle generation. Loading persisted evidence never
restarts its TTL. Missing exact lineage or expiry is a root failure, not absence.

For a divergent dual-root name, an exact-origin user pin wins, followed by the last successful
persistent exact-origin binding, followed by first-use ICANN precedence. The selected namespace
must be shown in trusted browser status. A namespace change must rotate or invalidate resolver and
proxy generations, origin connection pools, TLS sessions, Alt-Svc state, and any other
authority-derived runtime state. Site data must be cleared or partitioned by namespace before a
write-capable switch; if a platform cannot guarantee that boundary, it may expose status and
selection controls only as read-only. An IANA snapshot may be a lookup-order hint or expiring cache
input, never namespace authority. Authenticated absence of a pinned or persistently bound root
does not authorize an automatic switch to the other root.

Wallet-provider injection is a separate browser-authority decision, not a
property inferred from hostname syntax or page content. The Rust facade first
requires HTTPS and binds the exact scheme, canonical host, URL-origin port,
selected TCP service port, selected namespace, complete namespace-decision
fingerprint (including plan, TLSA, and provenance), network, trusted local
authentication path, runtime session/generation, policy generation, authority
event, and absolute expiry into a private context. It then rechecks those
fields under one engine lock. Cleartext and WSS/other non-HTTPS origins, no
selected root, unauthenticated contexts, another
origin/root/decision/network/session/generation/event, stale evidence,
degraded/revoked/stopped authority, and a TLS path inconsistent with the
selected plan all return an explicit denial.

The all-outcomes decision is a diagnostic report, not a capability. Native
browser code that will install the provider must request a
`ProviderAuthorityOutcome` and proceed only with its `Authorized` variant. The
contained `ProviderAuthorityContext` has private fields, is neither cloneable
nor serializable, and is minted only after the same complete check succeeds.
It exposes typed bindings for the native provider host, which must revalidate
the context with the engine before installation and after navigation,
namespace replacement, or a security-invalidating authority/policy event. A
revalidation consumes the old context and returns either a replacement capped
by the current decision expiry or a denial with no reusable authority. The
context must never cross into page JavaScript, and its readable fields are
bindings rather than independent permission inputs.

The provider-authority consumer ABI preserves that distinction. Its ordinary
Rust handoff consumes an authorized context exactly once into an opaque native
handle; no C constructor, import, clone, or serialization operation exists.
The C projection is output-only and the canonical host is copied as bounded
exact UTF-8 bytes without a terminator contract. Native code must retain the
opaque handle and obtain a successful currentness result from the originating
live engine retained by that handle immediately before publication or use.
The handle keeps the engine alive until destruction. A different engine
session/generation pairing remains non-current rather than creating authority.
Expiry and every engine/session/network/policy/runtime/invalidation mismatch
fail closed as a zero result. The native host supplies time, rejects rollback,
and never accepts a page timestamp. Projection fields are never independent
permission inputs, and the raw handle, its address, and its bindings must not
be exposed to page JavaScript or logs. Destroying/replacing the handle remains
part of the platform's navigation lifecycle.

For ICANN, the trusted embedding adapter receives an exact engine-derived
request and returns an opaque token minted from that request after local DANE
or WebPKI verification. A token retained from another origin, decision,
network, policy, expiry, runtime generation, or invalidated admission epoch is
rejected. Unrelated admitted work during authentication does not invalidate
the token. The
embedding caller is an explicit security principal: Rust cannot isolate
malicious same-process code, so page-controlled code must never implement or
influence this adapter. For HNS, only an engine strict completion admitted in
the current security epoch can be combined with a decision, and the TCP
service port, canonical TLSA
RRset, HNS network, proof height/tree root, provenance, and validity must match.
This result authorizes only injection. Origin permissions, approval UI, key
access, request dispatch, signing, and transaction policy remain
wallet/platform responsibilities. Wallet-session, permission-generation, and
navigation-generation checks must be composed by the platform provider host;
this engine context neither replaces nor gains access to them.

Local matching accepts DANE-EE usage 3 and DANE-TA usage 2. It supports full-certificate selector 0
and SPKI selector 1 with exact, SHA-256, and SHA-512 matching types 0, 1, and 2. Every terminal
record is checked for supported fields and association length before any match is accepted.
Certificate DER, extracted SPKI, chain length, RRset count, association data, CNAME hops, DNSSEC
records, and signed bytes are bounded. Empty, unsupported, malformed, oversized, unsigned, expired,
or nonmatching inputs fail closed.

On the HNS/private-DANE path, PKIX usages 0/1 are rejected because there is no WebPKI trust path.
DANE-TA builds a private X.509
path rooted only in the DNSSEC-selected trust anchor, checks certificate signatures, validity at an
explicit time, strict server-name matching, and chain bounds. It never loads a platform or public
root store. In accordance with RFC 7671, DANE-EE treats the DNSSEC-signed TLSA binding—not leaf
certificate names or dates—as the peer identity and validity period. The engine nevertheless
requires the actual origin SNI to equal the original TLSA base domain, as required by browser
policy.

RSA/SHA-1, RSA/SHA-256, RSA/SHA-512, ECDSA P-256, ECDSA P-384, Ed25519, and Ed448 DNSSEC
signatures are checked locally. DS SHA-1, SHA-256, and SHA-384 are supported. DNSKEY RRsets must be
signed by a DS-matched zone key before their other keys can validate terminal data. CNAME and TLSA
RRsets are verified independently, loops and ambiguous CNAME/data coexistence fail, and NSEC/NSEC3
denial uses bounded closest-encloser and wildcard proofs.

The HNS DS set is not caller data. The light-chain gate validates every contiguous header from the
selected network genesis using shared `hns-rs` consensus code, requires explicit height, chainwork,
and tip-age currency, verifies a canonical Urkel inclusion proof at that header's exact tree root,
and strictly decodes the committed name state and resource. A private resource token is consumed to
authenticate the TLD DNSKEY. The resolver carries that anchor through every CNAME/TLSA response.
The engine rejects a missing lineage, another Handshake network, a different DNSSEC/DANE validation
time, or a caller-provided provenance anchor that conflicts with the derived header.

The standard peer layer admits only bounded HSD version/verack sessions and correlates one
outstanding header, proof, and ping request at finite deadlines. Multi-peer synchronization
validates every response on an independent chain clone, requires configurable agreement on the
unique greatest-work same-base extension, and rejects equal-work ambiguity. A chain is reported
current only after every selected peer responds, every consensus-valid response returns an empty
extension, and no non-banned peer advertises a higher height. Consensus-invalid responders may be
excluded only under the configured agreement and ban policy. Socket dialing, peer discovery,
durable checkpoints, and download/reorganization from a fork before the current base are not yet
implemented; production adapters must not treat the in-memory same-base synchronizer as durable
fork recovery.

The DNS AD bit, Brontide, a relay, an ODoH proxy, and an ODoH target are never validation
authorities. Transport status is reported separately from evidence status.

HIP-76/77 requesters consume only an established peer whose advertised service, Denuo extension,
registry fingerprint, network, and genesis identity were admitted. Each requester owns a
non-cloneable monotonic nonzero request-ID sequence. The runtime adapter receives an exact packet,
deadline, authenticated destination, and response allocation cap; its response must attest the
same Brontide static key. Wrong keys, semantic packets, request IDs, deadlines, lengths, status
framing, or DNS questions fail closed. Reachability, timeout, and explicit unsupported statuses are
the only classes that may advance the gateway.

An ODoH target comes only from a target-signed, locator/network/lifetime-bound configuration
record. The proxy identity must differ from the target's signed Brontide identity. HPKE sealing and
opening occur locally, the client envelope is zero-padded to a bounded bucket, and the proxy never
receives plaintext DNS. A decrypted response is still untrusted DNS and must pass exact local
correlation, HNS proof, DNSSEC, TLSA, and DANE validation.

The engine's requester-only ODoH runtime is admitted under one private runtime
stamp. Unrelated later work does not revoke it, but degradation, revocation,
stop, policy replacement, or another runtime session does. Both sides of the
platform adapter call are checked; a response completed after invalidation is
discarded. Readiness requires one exact authenticated/registry-negotiated proxy
and at least one current signed target. Canonical transport errors are not
flattened, preserving peer, registry, packet, deadline, request-correlation,
DNS-correlation, target-signature, and HPKE failure identity.

The target cache is bounded to 16 locators and retains a greatest signed
sequence high-water per locator. Its restart blob has strict lengths, ordering,
schema, network, private-address-policy, and checksum checks. Restore uses a
fresh request-ID space and engine admission and cryptographically revalidates
each signed record; expired records can retain only their high-water slot. The
checksum is corruption detection, not authentication. Production adapters
must store the blob atomically in authenticated rollback-resistant platform
storage; until that exists and is qualified, restart anti-rollback is not a
product claim. No proxy or target provider API exists in this runtime.

Shared status uses explicit `verified`, `failed`, `unavailable`, `unsupported`, `not attempted`,
`stale`, and `revoked` evidence values. It never contains qnames, URLs, DNS payloads, certificates,
or secrets. Schema v2 consumes one private-field runtime snapshot and checks authority state
against degraded/revocation reasons. Its name-free namespace fields expose only the five-way
outcome, selected root, selection reason, decision fingerprint, and root-failure kinds. A root
failure never fabricates an outcome or selected root. Typed ICANN TLS action and evidence must
agree: DANE requires verified DNSSEC/TLSA/DANE; authenticated-absence and proven-insecure WebPKI
require a validated secure or proven-insecure DNSSEC disposition, unavailable TLSA, and
unattempted/unavailable DANE; bogus and indeterminate evidence remains explicitly fail closed.
Actual transport identities
are bounded and checked against the selected transport. Failed, unavailable, unsupported,
not-attempted, stale, and revoked ICANN trust tuples are reportable as fail closed, while the exact
DANE and permitted-WebPKI tuples cannot be relabeled. ICANN action/evidence is valid for an
ICANN-selected plan or an ICANN root failure. The facade requires that evidence, clears HNS
chain/identity state, reports validating ICANN DoH, and forces experimental registry
fingerprint/protocol to zero. Bogus and indeterminate root failures carry explicit DNSSEC
dispositions and no namespace selection; secondary-root trust details do not enter a successful
selected-plan status. ICANN failure is bound to validating-DoH provenance, while an HNS-only
failure clears transport provenance to unavailable. ODoH proxy and target must be present and distinct.
Registry fingerprint/protocol identity is mandatory for experimental P2P paths and forbidden for
every other transport, preventing stale or fabricated negotiation metadata from surviving a
transport change.
Provider readiness is derived from policy and must agree with explicit provider roles, and
rate-limit counters cannot claim impossible capacity or saturation states.

Cache entries use a per-runtime secret-derived opaque key and are bound to network, runtime and
policy generations, and the exact Handshake chain height/tree root. Positive and authenticated
negative TTLs have separate finite maxima. Entry count, per-value size, total value bytes, and LRU
state are bounded; expired or generation-mismatched entries are removed before any value is
returned. Cache metrics contain no qnames or values.

Direct UDP/TCP destinations are derived only from current proof-authenticated HNS resources. Glue
must be in bailiwick; mainnet/testnet addresses must be globally routable and use port 53.
Nonstandard ports are accepted only for explicit regtest loopback fixtures. Every exchange
rechecks the anchor validity window and exact query TLD before socket I/O, uses finite timeouts and
message bounds, sends a non-recursive DNSSEC query, and parses/correlates the complete response.

The built-in HNS resolution candidates are direct delegated-authoritative
UDP/TCP, explicitly authenticated authoritative DoH, Denuo Experimental V1 P2P
ODoH, and Denuo Experimental V1 P2P DNS Relay. A separate, default-off
requester-consent bit may append explicitly user-configured recursive HNS DoH
after all of them. The policy model contains no operating-system or implicit
recursive fallback. When the locally verified HNS name proof itself contains
the origin data, `LocalHnsProof` records that provenance without inventing a
DNS transport; it is status-only and cannot be planned or admitted.

The gateway—not the caller—selects the next candidate from the exact policy snapshot. Unreachable,
timed-out, and unsupported paths may advance; a valid truncated UDP response advances specifically
to direct TCP. Malformed framing, endpoint/intermediary authentication failure, cancellation,
foreign attempt tokens, stale policy, invalid proxy/target topology, and response-bound violations
terminate the plan. Direct-relay privacy downgrade is true only when an ODoH attempt actually
preceded the relay attempt.

After selection, the engine parses the response and atomically admits the selection's policy
generation, actual transport, identities, and downgrade state under its current runtime lock.
A stale selection consumes no engine event, and completion context is derived from the gateway
rather than supplied independently.

Policy updates increment generations, immediately reject new disabled work, reject stale
completions, clear requester selections, and report provider withdrawal/peer-renegotiation effects.
User-configured recursive HNS DoH is an independent requester permission that defaults off. It
enters the transport plan only as the terminal candidate, and opting out generation-revokes any
admitted attempt. The endpoint value and its bootstrap are platform concerns; this engine persists
only the consent bit and never treats transport TLS or a DNS AD bit as HNS validation authority.
Requester paths, the ODoH proxy, and HNSR requester/opaque-relay roles default on and have
independent persistent opt-outs. Output roles that learn a plaintext request or originate an
external request (the HIP-76 DNS relay, ODoH target, and HNSR endpoint/output node) default off and
require explicit opt-in. The HNSR rendezvous role is also independent and default off. Enabling any
requester, relay, or output role never enables another role implicitly. Policy persistence schema 3
uses settings bit 2 for recursive-HNS-DoH consent while retaining the exact 32-byte encoding.
Schema-1 and schema-2 blobs decode that new permission as false; schema-1 role migration retains its
exact legacy role selection, and every current-schema blob retains its exact requester, relay, and
output bits, so an upgrade cannot override a stored opt-out.

Every admitted operation is stamped with the caller-supplied per-start unique runtime session,
current runtime generation, and monotonic event sequence. The session is a checked nonzero type,
the runtime cannot be cloned, and its snapshot fields are private. Parsing and completion reject
another session, a revoked generation, an event that was never admitted, or any stamp checked while
authority is degraded, revoked, or stopped. Platform adapters must supply a fresh unpredictable
session on every engine start; a constant or reused session violates this replay-isolation
contract. An admitted stamp remains valid across later unrelated events, but the runtime's
invalidation floor prevents any pre-failure stamp from becoming valid again after recovery. Bridge
readiness may bypass per-origin DANE only before navigation or after validated
ICANN authenticated absence/proven-insecure delegation; evidence remains explicit and no DANE
state is claimed.

The shared loopback-proxy gate accepts only a nonzero numeric loopback endpoint and a loopback
client. Native adapters must generate a fresh unpredictable 128-bit realm nonce, 256-bit capability,
and nonzero 128-bit process session for every process start. Process and listener generations must
advance on their respective lifecycle replacement. The derived fixed-width Basic token is compared
in constant time, exactly one authentication header is required, secret-bearing debug output is
redacted, and owned intermediate/retained secret buffers are cleared when practical. The returned
authorization header remains a secret owned by the adapter and must never be logged or persisted.

`CONNECT` admission requires one complete bounded CRLF header, the exact `CONNECT host:port
HTTP/1.1` form, one equal `Host`, one valid capability, a nonzero port, strict ASCII/punycode DNS
labels, and the immutable HNS TLD label boundary. IP literals, legacy numeric IP forms, request
bodies, transfer encodings, upgrades, duplicate credentials, and ambiguous authorities fail closed.
Pending admissions are bounded, carry a hard-capped exclusive expiry, and are scoped to one
non-cloneable process instance. The native host supplies trusted nondecreasing time; rollback is
rejected, and expired entries are pruned before capacity is tested. A pending token is consumed
before provider publication authorization succeeds or fails, including expiry rejection, preventing
retry with changed evidence. Its host and port must then equal the published HTTPS logical origin
exactly; the selected TCP service port is carried separately for the native origin adapter.

The publication registry is private, in-memory, and bounded. Its only authority-bearing input is a
consumed `ProviderAuthorityContext` minted in an `Authorized` outcome. It copies the exact logical
origin, selected namespace, HNS network, selected TCP service, TLS/authentication path, runtime
session/generation/event, policy generation, decision fingerprint, and original validity interval,
retains the opaque context for borrowed engine currentness checks, then binds it to the exact
endpoint, process session/generation, listener generation, publication
identity, and registry generation. Diagnostic decisions are never accepted. Publish, same-origin
replace, and exact-handle revoke require the current registry generation and change no state on a
stale or invalid request. Publications have finite capacity and a capped absolute lifetime. Before
duplicate/capacity checks, a publish attempt validates every retained opaque context and reclaims
expired or engine-invalid records. Their removal does not advance the registry generation because
they already cannot authorize; live records remain unchanged on failure. The registry is not
serialized; process/listener restart creates an empty instance and rejects every old handle.

An opaque, non-cloneable, non-serializable `TunnelGrant` authorizes only one exact CONNECT under a
short exclusive-expiry window. It is not a certificate, a WebPKI verdict, wallet permission, or
permission to resolve another origin. Native hosts must revalidate its complete binding immediately
before listener/origin I/O; any registry mutation, security-invalidating authority event, lifecycle
replacement, or expiry rejects it. Ordinary unrelated admissions do not. Same-origin navigation or
decision replacement must synchronously revoke or replace its publication because the engine keeps
no unbounded per-origin navigation map. Native hosts still own DNS wire I/O, the listener, local CA,
exact-host leaf creation,
upstream TLS, origin dialing, and byte forwarding, and must stop on runtime/policy revocation or
lifecycle cancellation. No provider path is enabled in a platform product by this source.

The persisted policy CRC detects accidental corruption only. Platform adapters must use their normal
integrity-protected settings or secure storage; the CRC is not a MAC or signature.
