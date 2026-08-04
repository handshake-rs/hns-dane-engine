# hns-p2p-transport

Authenticated adapter boundary for experimental Handshake P2P DNS transports.

The crate constructs and validates draft HIP-76 DNS Relay and HIP-77 ODoH
exchanges after explicit Denuo registry negotiation. ODoH engine admission
retains and requires the exact policy-resolved Denuo V1 peer profile plus both
Denuo-extension and ODoH service advertisements. Platform adapters own sockets
and Brontide records; the engine correlates and validates returned DNS bytes
locally.

These transports are Denuo Experimental V1 and are not official Handshake
protocol assignments.

Published releases can be added with:

```bash
cargo add hns-p2p-transport
```

The minimum supported Rust version is 1.89. API documentation for published
releases is hosted on [docs.rs](https://docs.rs/hns-p2p-transport).

Licensed under either Apache-2.0 or MIT.
