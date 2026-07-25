# C ABI v1

The C ABI is declared by `include/hns_dane_engine.h` and implemented in the
`hns-dane-engine-ffi` crate. Its exported names include the `v1` version. All Rust panics are caught
before crossing the boundary.

Ownership rules:

- `hns_dane_engine_v1_create` transfers one engine handle to the caller.
- `hns_dane_engine_v1_destroy` consumes it exactly once after concurrent calls stop.
- `hns_dane_engine_v1_admit` transfers one attempt handle to the caller.
- `hns_dane_engine_v1_attempt_destroy` consumes it exactly once.
- all other input pointers are borrowed only for the duration of the call.

Policy structs include both `struct_size` and `abi_version`; reserved bytes must be zero. ODoH
completion requires distinct proxy and target identities. Direct-relay completion requires a relay
peer identity. Fixed buffers bound identity allocation at the ABI edge.

`HnsDaneResultV1.untrusted_ad_claim` reports only what arrived on the wire. It never substitutes for
the six required local evidence bits.

The policy blob is a 32-byte versioned representation with a CRC-32 corruption check. CRC is not an
authentication mechanism: platform adapters must store the blob in their normal integrity-protected
settings or secure storage and use optimistic generation matching on updates.

