# Authenticated P2P DNS requester boundary

Status: **Denuo Experimental V1 — Not an official Handshake protocol
assignment**.

`hns-p2p-transport` executes the runtime-independent requester side of draft
HIP-76 DNS Relay and HIP-77 P2P ODoH. It uses the canonical codecs and
experimental assignment state in `hns-rs`. It deliberately does not own a
socket runtime or claim that Brontide authenticates DNS content.

## Adapter contract

The platform establishes an ordinary Handshake Brontide session and completes
the Denuo registry negotiation. It then binds the authenticated compressed
static key, peer service mask, registry fingerprint/version, network, and
genesis identity into `AuthenticatedPeer`.

For each request, `ExperimentalExchange` receives:

- the exact authenticated destination key;
- the negotiated semantic packet assignment;
- a strictly encoded bounded payload;
- an absolute caller-clock deadline; and
- the maximum response payload it may allocate.

The response reports the static key authenticated by the response-bearing
Brontide session, the semantic packet assignment, bounded payload, and
completion time. Returning caller-selected display text is insufficient. A
wrong key, packet, deadline, or bound fails closed before protocol decoding.
Cancellation is checked before and after the adapter call.
The encoded request must also fit the remote receive bound captured by
`NegotiatedRegistry`; an undersized peer is classified as unsupported before
adapter I/O.

`AuthenticatedPeer`, `DnsRelayRequester`, and `OdohRequester` are intentionally
non-cloneable. Each requester owns its own monotonic nonzero request-ID space,
so cloning cannot replay an outstanding ID onto another adapter or hop. The
first ID is supplied by the platform and should be unpredictable.

Platforms that already own the one canonical `BrowserRuntime` construct a
short-lived `PrivateTransportAuthority` view with that runtime, the current
network, and the current persisted `PolicySnapshot`. The view mints and
validates the same opaque transport bindings as `Engine`; it does not create or
clone another authority clock. Supplying a stale policy snapshot is a trusted
adapter violation.

## HIP-76

The requester emits one strict non-recursive, DNSSEC-enabled query in
`GETDNSRELAY`. It requires `DNSRELAY` from the same authenticated peer, the
exact request ID, a defined status/body combination, a bounded DNS message,
and exact local response correlation. The relay's DNS AD bit and answer are
untrusted.

## HIP-77

`VerifiedOdohTarget::decode` verifies the target signature, compressed
Brontide key, locator, network magic, lifetime, configuration list, and record
identifier before selecting an immutable HPKE configuration. A current target
whose identity equals the proxy is rejected.

`OdohRequesterRuntime::fetch_target_configuration` owns the bounded
GETCONFIG/CONFIG bootstrap exchange. It encodes the locator request, requires
the response from the exact authenticated proxy, rejects proxy/target identity
collision, correlates the request ID and opcode, verifies the target-signed
record against the engine network and exact locator at completion time, then
atomically applies sequence anti-rollback and configuration selection. The
returned record ID and cache generation tell the adapter which `{ generation,
bytes }` export must be committed; adapters never reproduce HIP-77 framing or
signature logic.

The requester seals DNS locally with RFC 9230/9180, wraps the signed locator
and record identifier in `CLIENT_QUERY`, and pads the complete ODNS request to
a configured zero-filled bucket. The authenticated proxy sees routing data
and ciphertext, not the qname. Only `CLIENT_RESPONSE` with the exact outer
request ID is accepted. The response is opened locally, parsed with requester
bounds, and correlated to the original DNS question.

The proxy and target authenticate transport hops, not HNS data. Successful
bytes still traverse the private HNS proof, DNSSEC, TLSA, and DANE gates.

## Requester lifecycle and persistence

`Engine::start_odoh_requester` mints a private transport admission stamp and a
non-cloneable request-ID space. The runtime retains the exact engine session,
runtime generation, policy generation, invalidation watermark, network magic,
policy wire profile, Brontide proxy identity, exact peer wire profile, registry
fingerprint/version, and negotiated request bound. Binding resolves policy
`DenuoV1` or `Auto` to concrete Denuo V1, independently compares that exact
profile and the peer's negotiated network and genesis to canonical engine
parameters, requires the canonical Denuo V1 registry
fingerprint/version/negotiation protocol, and pre-admits `ODOH_PACKET` against
both advertised ODoH and Denuo-extension services before reporting a proxy.
Official, Denuo V2, legacy-draft, and unresolved `Auto` peer profiles fail
closed. Requester status schema 4 reports the retained resolved profile and
monotonic target-cache generation; target-cache wire schema 3 persists that
generation. It checks the engine before and
after adapter I/O, so degradation,
revocation, stop, policy replacement, or another process session cannot return
stale response bytes. Readiness requires both an authenticated proxy and a
current signed target. Status reports those prerequisites and closed
revocation reasons without qnames, DNS bytes, or HPKE state. This local
protocol-ready bit does not claim that a platform adapter or live path is
available.

The target cache has 16 locator slots and retains each locator's greatest
target-signed sequence even after expiry. Its bounded checksummed canonical
schema-3 blob contains only public signed target material, configuration
selection, sequence high-water state, the greatest trusted caller/adapter
time, and a nonzero monotonic cache generation. Durable changes advance the
generation with checked arithmetic. Export returns `{ generation, bytes }`;
restore requires the caller-held minimum generation and rejects an older valid
blob. Install, pruning, status, export, restore, and exchange also reject a
lower clock. A bounded adapter completion advances the clock even if later
protocol parsing fails, and every response must complete no earlier than
request start and no later than its deadline. Restore uses a new engine
admission and request-ID space, never restores a proxy or in-flight HPKE
context, and re-verifies every record against the exact network, locator,
signature, sequence, configuration, and signed expiry. The checksum detects
corruption; the platform must atomically place the blob and generation floor
in its authenticated rollback-resistant store before the cache can be treated
as durable anti-rollback state.

This runtime implements only the ODoH requester. Its proxy-provider and
target-provider availability fields are permanently false; policy defaults do
not create either server role.

## HNSR requester and opaque relay

`HnsrRequesterRuntime` and `HnsrOpaqueRelayRuntime` wrap the canonical bounded
`hns-hnsr-protocol` state machines. Start binds the current browser admission,
policy generation, Handshake network/genesis, concrete Denuo V1 peer registry,
exact HNSR service profile, and a nonzero caller-held role generation. Every
outer peer is admitted from an exact adapter connection label plus its
Brontide-authenticated key and negotiated registry. A reconnect cannot inherit
the old connection's circuit authority.

The requester validates signed tickets against the authenticated relay key and
returns exact routes for OPEN, DATA, WINDOW, and CLOSE. The opaque relay owns a
relay reservation service but no rendezvous service, maps reservations and
circuits to exact authenticated connection IDs, and returns
generation-qualified queued routes. The adapter must acknowledge each write;
failed writes and disconnects revoke the associated work. Ciphertext is never
interpreted. Endpoint/output, rendezvous, and plaintext availability are hard
false on this surface even if a caller presents a policy enabling them.

`export` nests the canonical checksummed core snapshot in a checksummed
engine-binding envelope and returns `{ generation, trusted_time_high_water,
bytes }`. Restore requires both caller-held floors, a fresh process session,
the same network/policy/wire/service/address binding, and nondecreasing trusted
time. It restores settings and counters only: private relay keys are supplied
fresh, while authenticated peers, reservations, circuits, opaque frames, and
queued writes are never serialized. The blob and both floors must be committed
atomically in authenticated rollback-resistant platform storage.

## HNSA named-route selection and open

`Engine::verify_and_select_hnsa_named_routes` performs complete cryptographic
verification and conflict-safe selection over one response containing at most
16 encoded HNSA/HNSR records. The application selects the expected lowercase
HNS name, canonical service name, `HNS_WEB_V1` or `HNS_CHAT_V1`, and exact
capability/constraints policy. A non-forgeable current `VerifiedHnsResource`
supplies the name hash, chain height, tree root, network, and one complete ASCII
`hsa1` authority character-string. Every supplied item consumes batch capacity
before decode; invalid records are ignored, but an equal-sequence conflict at
the service-authorization, endpoint-delegation, or route layer fails closed.
For the two reviewed profiles the exact endpoint key defines the logical
endpoint. Future profile support requires explicit replacement-scope semantics
and code review.

The engine returns one opaque non-cloneable selection per accepted endpoint.
It exposes only typed route/relay metadata, not the signed record or a
detachable `RelayTicket`. The caller instead supplies the sole sequence
persistence object, `HnsaNamedRouteState`. Its bounded checksummed encoding
holds the global authorization and at most 64 exact-endpoint delegation and
route histories in at most 7,519 bytes. The checksum detects accidental
corruption but is not a storage authenticator. A newer valid authorization or
delegation advances the state even when no usable route remains. An
equal-sequence conflict or endpoint-history exhaustion is sticky until a
verified changed `hsa1` authority appears under a greater
`resource_generation`.

The platform must compare the state generation after every selector call,
including errors and empty selections, and atomically commit every change in
authenticated rollback-resistant storage before opening. Selection, commit,
and open must be serialized per authority/service scope. The external
`HnsaNamedRouteContext::trusted_time_high_water` must likewise advance for
every trusted time observation, including a selector failure.

`Engine::begin_hnsa_named_route_open` requires the current committed state and
rechecks the current resource, external generations and policy, caller and
selection time floors, chain/route expiry, engine requester epoch,
and the supplied requester/relay binding. It advances the selection time floor
before later expiry or engine failures, bounds the deadline by the enclosing
route/anchor lifetime, and gives the indexed internal ticket directly to the
HNSR requester sink. Raw `HnsrRequesterRuntime::begin_open` admits only the
node profile; named Web and Chat profiles must use the opaque HNSA path. The
platform still owns complete directory acquisition, response-completeness and
quorum policy, live Brontide/relay I/O, and the profile's
endpoint-authenticated inner session. HNSA signatures and tickets alone grant
no browser permission and prove neither relay liveness nor session completion.

## Engine admission

A successful requester result becomes `AttemptOutcome::Response`; a failure
becomes the crate's fail-closed `TransportFailure` classification. `Gateway`
alone decides whether another policy candidate exists.

`Engine::admit_gateway_selection` then parses/correlates the selected bytes and
atomically checks the selection's policy generation and transport while
admitting one runtime event. It derives the completion identities and
ODoH-to-relay downgrade flag from that selection. A stale selection consumes
no event, the non-cloneable selection is consumed exactly once, and the caller
cannot substitute a separate intermediary context.

## Remaining platform work

Native/mobile/Chromium hosts still need to connect `ExperimentalExchange` to
their established Brontide socket runtime, propagate lifecycle cancellation,
source unpredictable first request IDs, perform live registry-hello exchange,
atomically protect the cache blob, and run platform network qualification.
Provider roles are independent and are not implemented by this requester
runtime. The policy-level opaque ODoH proxy is default-on with a persistent
opt-out, but remains unavailable until a separate provider implementation is
present and qualified. The plaintext HIP-76 DNS relay and ODoH target are
output roles that remain default-off until explicitly enabled. One role never
conveys consent for another.
