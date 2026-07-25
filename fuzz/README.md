# Fuzzing

The parser API is deterministic and accepts arbitrary byte slices through
`hns_dns_wire::Message::parse_with_limits`. A cargo-fuzz harness should call that function with
strict production limits. Mutation-derived regression cases live in the crate tests and
`fixtures/dns/`.

