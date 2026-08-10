# Fixtures

The active fixture set exercises the experimental DNS relay's bounded,
cross-language framing and request-correlation contract.

- `experimental-dns-relay/manifest.json` records the fixture names, expected
  parser result, and protocol meaning.
- `experimental-dns-relay/*.hex` covers valid basic and boundary-sized
  requests/responses, maximum QNAME handling, error status, malformed and
  oversized lengths, trailing bytes, unknown status values, and zero request
  IDs.

These fixtures are protocol test vectors, not live-network captures or
authoritative DNS/header/Urkel test oracles.
