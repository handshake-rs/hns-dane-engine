# HNS browser security policy

For an HNS HTTPS origin, success requires all of:

1. locally validated Handshake state and a verified current Urkel proof;
2. a DNS response correlated to the exact local query;
3. local DNSSEC validation;
4. an exact, supported TLSA match;
5. local DANE origin validation, including SNI; and
6. an admission token from the current runtime and policy generations.

The DNS AD bit, Brontide, a relay, an ODoH proxy, and an ODoH target are never validation
authorities. Transport status is reported separately from evidence status.

The only HNS resolution candidates are direct delegated-authoritative UDP/TCP, explicitly
authenticated authoritative DoH, Denuo Experimental V1 P2P ODoH, and Denuo Experimental V1 P2P DNS
Relay. The policy model contains no operating-system or public-recursive fallback variant.

Policy updates increment generations, immediately reject new disabled work, reject stale
completions, clear requester selections, and report provider withdrawal/peer renegotiation effects.
Provider roles default off. HNSR requester and provider roles default off.

The persisted policy CRC detects accidental corruption only. Platform adapters must use their normal
integrity-protected settings or secure storage; the CRC is not a MAC or signature.
