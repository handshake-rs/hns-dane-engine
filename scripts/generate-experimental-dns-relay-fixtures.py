#!/usr/bin/env python3
"""Generate the private DNS-relay wire fixtures without third-party modules."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path


REQUEST_ID = 0x0102030405060708
MAX_QUERY = 4096
MAX_RESPONSE = 65535


def dns_name(labels: list[bytes]) -> bytes:
    encoded = bytearray()
    for label in labels:
        if not 1 <= len(label) <= 63:
            raise ValueError("invalid fixture label")
        encoded.append(len(label))
        encoded.extend(label)
    encoded.append(0)
    if len(encoded) > 255:
        raise ValueError("fixture name exceeds DNS limit")
    return bytes(encoded)


def dns_query(name: bytes, target_size: int | None = None) -> bytes:
    header = struct.pack("!HHHHHH", 0x1234, 0x0110, 1, 0, 0, 1)
    question = name + struct.pack("!HH", 1, 1)
    opt_prefix = b"\x00" + struct.pack("!HHIH", 41, 1232, 0x00008000, 0)
    message = header + question + opt_prefix
    if target_size is None:
        return message
    padding_len = target_size - len(message) - 4
    if not 0 <= padding_len <= 65535:
        raise ValueError("invalid query padding target")
    option = struct.pack("!HH", 12, padding_len) + bytes(padding_len)
    return message[:-2] + struct.pack("!H", len(option)) + option


def dns_response(name: bytes, target_size: int | None = None) -> bytes:
    # AD is deliberately present so clients can prove that transport syntax is
    # retained while local validation remains the only source of secure state.
    header = struct.pack("!HHHHHH", 0x1234, 0x81B0, 1, 1, 0, 1)
    question = name + struct.pack("!HH", 1, 1)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\xc0\x00\x02\x01"
    opt_prefix = b"\x00" + struct.pack("!HHIH", 41, 1232, 0x00008000, 0)
    message = header + question + answer + opt_prefix
    if target_size is None:
        return message
    padding_len = target_size - len(message) - 4
    if not 0 <= padding_len <= 65535:
        raise ValueError("invalid response padding target")
    option = struct.pack("!HH", 12, padding_len) + bytes(padding_len)
    return message[:-2] + struct.pack("!H", len(option)) + option


def request(query: bytes, declared_length: int | None = None) -> bytes:
    length = len(query) if declared_length is None else declared_length
    return struct.pack("<QH", REQUEST_ID, length) + query


def response(status: int, message: bytes = b"", request_id: int = REQUEST_ID) -> bytes:
    return struct.pack("<QBH", request_id, status, len(message)) + message


def write_fixtures(output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    ordinary_name = dns_name([b"www", b"relaytest"])
    maximum_name = dns_name([b"a" * 63, b"b" * 63, b"c" * 63, b"d" * 61])
    basic_query = dns_query(ordinary_name)
    basic_response = dns_response(ordinary_name)
    maximum_query = dns_query(ordinary_name, MAX_QUERY)
    maximum_response = dns_response(ordinary_name, MAX_RESPONSE)

    fixtures: dict[str, tuple[bytes, bool, str]] = {
        "request-basic.hex": (request(basic_query), True, "basic request"),
        "response-ok.hex": (
            response(0, basic_response),
            True,
            "successful response with an untrusted AD bit",
        ),
        "response-error.hex": (response(3), True, "BUSY transport response"),
        "request-max.hex": (request(maximum_query), True, "maximum legal request"),
        "response-max.hex": (
            response(0, maximum_response),
            True,
            "maximum legal response",
        ),
        "request-max-qname.hex": (
            request(dns_query(maximum_name)),
            True,
            "maximum 255-byte DNS name",
        ),
        "malformed-length.hex": (
            request(basic_query, len(basic_query) + 1),
            False,
            "declared request body is longer than packet",
        ),
        "trailing-bytes.hex": (
            request(basic_query) + b"\xff",
            False,
            "packet data after declared request body",
        ),
        "unknown-status.hex": (
            response(255),
            False,
            "unknown response transport status",
        ),
        "oversized-request.hex": (
            request(b"", MAX_QUERY + 1),
            False,
            "declared request exceeds limit before allocation",
        ),
        "oversized-response.hex": (
            response(0, maximum_response) + b"\x00",
            False,
            "response exceeds the maximum packet body",
        ),
        "zero-request-id.hex": (
            response(3, request_id=0),
            False,
            "zero request identifier",
        ),
    }

    entries = []
    for filename, (wire, valid, description) in fixtures.items():
        encoded = wire.hex()
        wrapped = "\n".join(
            encoded[offset : offset + 128]
            for offset in range(0, len(encoded), 128)
        )
        (output / filename).write_text(wrapped + "\n", encoding="ascii")
        entries.append(
            {
                "file": filename,
                "description": description,
                "valid": valid,
                "wire_bytes": len(wire),
                "sha256": hashlib.sha256(wire).hexdigest(),
            }
        )

    manifest = {
        "version": 1,
        "byte_order": "little-endian packet integers; DNS network byte order",
        "temporary_service_bit": "0x40000000",
        "temporary_request_packet": "0xf0",
        "temporary_response_packet": "0xf1",
        "request_id": f"0x{REQUEST_ID:016x}",
        "maximum_query_bytes": MAX_QUERY,
        "maximum_response_bytes": MAX_RESPONSE,
        "statuses": {
            "OK": 0,
            "REFUSED": 1,
            "UNSUPPORTED": 2,
            "BUSY": 3,
            "INVALID_QUERY": 4,
            "RESOLVER_UNAVAILABLE": 5,
            "TIMEOUT": 6,
            "INTERNAL_ERROR": 7,
        },
        "fixtures": entries,
    }
    (output / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", nargs="+", type=Path)
    args = parser.parse_args()
    for output in args.output:
        write_fixtures(output)


if __name__ == "__main__":
    main()
