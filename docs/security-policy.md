# HNS browser security policy

For an HNS HTTPS origin, success requires all of:

1. locally validated Handshake state and a verified current Urkel proof;
2. a DNS response correlated to the exact local query;
3. local DNSSEC validation;
4. an exact, supported TLSA match;
5. local DANE origin validation, including SNI; and
6. an admission token from the current runtime and policy generations.

Local matching accepts only TLSA DANE-EE usage 3. It supports full-certificate selector 0 and SPKI
selector 1 with exact, SHA-256, and SHA-512 matching types 0, 1, and 2. Every record in the
exact-owner RRset is checked for supported fields and association length before any match is
accepted. Certificate DER, extracted SPKI, RRset count, and association data are bounded. Empty,
unsupported, malformed, oversized, or nonmatching inputs fail closed.

PKIX usages 0/1 are rejected because there is no WebPKI trust path. DANE-TA usage 2 is rejected
until a local chain-signature validator exists. There is no network, WebPKI, public DNS, or
operating-system fallback. The DER reader extracts the exact SPKI from the presented leaf; it is not
a substitute for certificate-signature, validity-time, or SNI validation, which remain explicit
prerequisites.

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
