# DNS wire fixtures

These vectors are independently constructed from RFC wire formats. The manifest pins the exact HSD
and browser compatibility sources inspected, but no browser source or fixture was copied into this
dual-licensed repository.

The positive corpus covers a strict query, compressed response correlation with an untrusted AD bit,
and TLSA RDATA. Mutation-derived negatives cover self/forward compression pointers, out-of-bounds
pointers, and section-count bombs. Additional in-crate negatives cover truncation, oversized RDATA,
name limits, reserved label bits, response correlation, and malformed DNSSEC bitmaps.

