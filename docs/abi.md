# C ABI

The C ABI is declared by `include/hns_dane_engine.h` and implemented in the
`hns-dane-engine-ffi` crate. The runtime, attempt, validation, and original
policy entry points retain their `v1` names and layouts. `HnsDanePolicyV2` plus
`hns_dane_engine_v2_get_policy` and `hns_dane_engine_v2_set_policy` add the
explicit recursive-HNS-DoH requester-consent field without reinterpreting
`HnsDanePolicyV1` reserved bytes. All Rust panics are caught before crossing
the boundary.

`hns_dane_engine_v1_create` requires a fresh, unpredictable, nonzero 16-byte
runtime session for every process start. The all-zero sentinel is rejected as
`HNS_DANE_INVALID_ARGUMENT` before an engine handle is allocated.

Ownership rules:

- `hns_dane_engine_v1_create` transfers one engine handle to the caller.
- `hns_dane_engine_v1_destroy` consumes it exactly once after concurrent calls stop.
- `hns_dane_engine_v1_admit` transfers one attempt handle to the caller.
- `hns_dane_engine_v1_attempt_destroy` consumes it exactly once.
- all other input pointers are borrowed only for the duration of the call.

Policy structs include both `struct_size` and `abi_version`; reserved bytes
must be zero. `HnsDanePolicyV1` and `HnsDanePolicyV2` are each exactly 32
bytes, with ABI versions 1 and 2 respectively. ODoH completion requires
distinct proxy and target identities. Direct-relay completion requires a relay
peer identity. Fixed buffers bound identity allocation at the ABI edge.

`HnsDanePolicyV1.hnsr` is an independent role bitset using the
`HNS_DANE_HNSR_*` constants, not a single mode enum. New policy snapshots enable only the opaque
HNSR relay and ODoH proxy provider roles. Both have persistent opt-outs. The HNSR endpoint/output
node, plaintext DNS relay, and ODoH target remain off until separately enabled; no role implies
another.

Only policy V2 can enable or retain
`user_configured_recursive_hns_doh`. Policy V1 has an explicit fail-closed
boundary: V1 get returns `HNS_DANE_ABI_MISMATCH` while that consent is enabled,
and every successful V1 set decodes the absent field as disabled. This prevents
a V1 caller from receiving an incomplete policy projection or silently
continuing consent it cannot inspect. The endpoint URL remains platform-local
and is not part of either ABI struct.

`HnsDaneResultV1.untrusted_ad_claim` reports only what arrived on the wire. It never substitutes for
local evidence. `hns_dane_engine_v1_validate_response` borrows both the correlated DNS response and
the presented leaf-certificate DER. Its prerequisite mask contains only HNS proof, DNSSEC, chain
currency, and origin-SNI bits (`0x33` when all are verified). Bits for TLSA or DANE are invalid:
those results are computed inside Rust and returned as `tlsa_record_index`, `tlsa_usage`,
`tlsa_selector`, and `tlsa_matching_type`.

The function accepts only a class-IN TLSA attempt and uses same-owner TLSA answers from that
correlated response. The caller must keep the response, certificate, context, and output storage
valid for the duration of the call. The default certificate limit is 256 KiB, although DNS wire
limits normally constrain each association to less than 64 KiB.

The policy blob remains a 32-byte versioned representation with a CRC-32
corruption check. Schema 3 stores recursive-HNS-DoH consent in settings bit 2.
Schema 1 and schema 2 blobs remain accepted with that field forced to false;
the decoder rejects bit 2 if a blob is mislabeled as either older schema. CRC
is not an authentication mechanism: platform adapters must store the blob in
their normal integrity-protected settings or secure storage and use optimistic
generation matching on updates.

Existing `ResolutionTransport` values 0 through 5 retain their meanings.
Value 6 names TLS-authenticated validating ICANN DoH for shared status
provenance; it is not admitted by the HNS transport plan. Value 7 names
user-configured recursive HNS DoH. It is admitted only when policy V2 consent
is true and is always the terminal HNS transport candidate. Value 8 is
`LocalHnsProof`, the status-only provenance for origin data supplied directly
by a locally verified HNS name proof. It is never a network transport-plan
candidate and admission returns `HNS_DANE_TRANSPORT_DISABLED`. The Rust
facade/runtime and shared observability schema remain version 2; the policy
persistence schema is independently version 3.
