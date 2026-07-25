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

## HIP-76

The requester emits one strict non-recursive, DNSSEC-enabled query in
`GETDNSRELAY`. It requires `DNSRELAY` from the same authenticated peer, the
exact request ID, a defined status/body combination, a bounded DNS message,
and exact local response correlation. The relay's DNS AD bit and answer are
untrusted.

`Unsupported`, `Busy`, `ResolverUnavailable`, and `Timeout` map to the narrow
gateway retry classes. Refusal, invalid query, internal error, malformed
framing, identity failure, cancellation, or DNS mismatch terminate the plan.

## HIP-77

`VerifiedOdohTarget::decode` verifies the target signature, compressed
Brontide key, locator, network magic, lifetime, configuration list, and record
identifier before selecting an immutable HPKE configuration. A current target
whose identity equals the proxy is rejected.

The requester seals DNS locally with RFC 9230/9180, wraps the signed locator
and record identifier in `CLIENT_QUERY`, and pads the complete ODNS request to
a configured zero-filled bucket. The authenticated proxy sees routing data
and ciphertext, not the qname. Only `CLIENT_RESPONSE` with the exact outer
request ID is accepted. The response is opened locally, parsed with requester
bounds, and correlated to the original DNS question.

The proxy and target authenticate transport hops, not HNS data. Successful
bytes still traverse the private HNS proof, DNSSEC, TLSA, and DANE gates.

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

Native/mobile/Chromium hosts still need to connect this contract to their
established Brontide socket runtime, propagate lifecycle cancellation, source
unpredictable first request IDs, perform live registry-hello exchange, and run
platform network qualification. HIP-76/77 relay, proxy, and target provider
roles are separate operator opt-ins and are not implemented by this requester
crate.
