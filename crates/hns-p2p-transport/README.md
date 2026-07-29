# hns-p2p-transport

Authenticated adapter boundary for experimental Handshake P2P DNS transports.

The crate constructs and validates draft HIP-76 DNS Relay and HIP-77 ODoH
exchanges after explicit Denuo registry negotiation. Platform adapters own
sockets and Brontide records; the engine correlates and validates returned DNS
bytes locally.

These transports are Denuo Experimental V1 and are not official Handshake
protocol assignments.

```bash
cargo add hns-p2p-transport
```

The minimum supported Rust version is 1.89. API documentation is available on
[docs.rs](https://docs.rs/hns-p2p-transport).

Licensed under either Apache-2.0 or MIT.
