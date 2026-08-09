use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const BROWSER_SPECIAL_USE_SUFFIXES: &[&str] = &[
    "alt",
    "arpa",
    "example",
    "internal",
    "invalid",
    "local",
    "localhost",
    "onion",
    "test",
];

/// Returns the exact special-use suffix snapshot used by browser namespace
/// classification. Platform adapters may serialize this data, but must not
/// maintain an independent copy of the policy.
pub fn browser_special_use_suffixes() -> &'static [&'static str] {
    BROWSER_SPECIAL_USE_SUFFIXES
}

/// Returns whether an address is suitable for an untrusted Internet endpoint.
///
/// This is intentionally more conservative than merely checking for loopback or private-use
/// space. Native transports bypass browser Private Network Access protections, so reserved,
/// documentation, benchmarking, transition, and other non-global ranges are rejected too.
pub fn is_publicly_routable(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_ipv4(address),
        IpAddr::V6(address) => is_public_ipv6(address),
    }
}

/// Returns whether a canonical DNS host is in a namespace that native browser
/// networking must not forward to the public Internet.
///
/// The exact names and every subdomain are covered. Callers remain responsible
/// for parsing and canonicalizing a URL authority before applying this policy.
pub fn is_browser_special_use_host(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    let Some(suffix) = host.rsplit('.').next() else {
        return false;
    };
    BROWSER_SPECIAL_USE_SUFFIXES
        .iter()
        .any(|candidate| suffix.eq_ignore_ascii_case(candidate))
}

fn is_public_ipv4(address: Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    !matches!(
        (a, b, c),
        (0, _, _)
            | (10, _, _)
            | (100, 64..=127, _)
            | (127, _, _)
            | (169, 254, _)
            | (172, 16..=31, _)
            | (192, 0, 0)
            | (192, 0, 2)
            | (192, 88, 99)
            | (192, 168, _)
            | (198, 18..=19, _)
            | (198, 51, 100)
            | (203, 0, 113)
            | (224..=255, _, _)
    )
}

fn is_public_ipv6(address: Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return is_public_ipv4(mapped);
    }

    let segments = address.segments();

    // RFC 6052's well-known NAT64 prefix embeds the actual IPv4 destination. Allow the
    // translation only when that destination is independently public.
    if segments[..6] == [0x0064, 0xff9b, 0, 0, 0, 0] {
        return is_public_ipv4(Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            segments[6] as u8,
            (segments[7] >> 8) as u8,
            segments[7] as u8,
        ));
    }

    // Global unicast is 2000::/3. A positive allowlist avoids accidentally treating future or
    // reserved special-purpose ranges (for example ::2 or fe00::/9) as Internet-routable.
    if segments[0] & 0xe000 != 0x2000 {
        return false;
    }

    // Exclude non-forwardable and transition/documentation space inside global unicast.
    !(segments[0] == 0x2001 && segments[1] == 0x0000 // Teredo
        || segments[..3] == [0x2001, 0x0002, 0] // benchmarking
        || segments[0] == 0x2001 && segments[1] & 0xfff0 == 0x0010 // ORCHID
        || segments[0] == 0x2001 && segments[1] & 0xfff0 == 0x0020 // ORCHIDv2
        || segments[..2] == [0x2001, 0x0db8] // documentation
        || segments[0] == 0x2002 // deprecated 6to4
        || segments[0] & 0xfff0 == 0x3ff0) // documentation (3fff::/20)
}

/// Returns whether Fetch's browser port-blocking policy rejects a port.
pub fn is_browser_blocked_port(port: u16) -> bool {
    // WHATWG Fetch, section 2.9 (Port blocking). Native fetching must apply this policy itself.
    matches!(
        port,
        0 | 1
            | 7
            | 9
            | 11
            | 13
            | 15
            | 17
            | 19
            | 20
            | 21
            | 22
            | 23
            | 25
            | 37
            | 42
            | 43
            | 53
            | 69
            | 77
            | 79
            | 87
            | 95
            | 101
            | 102
            | 103
            | 104
            | 109
            | 110
            | 111
            | 113
            | 115
            | 117
            | 119
            | 123
            | 135
            | 137
            | 139
            | 143
            | 161
            | 179
            | 389
            | 427
            | 465
            | 512
            | 513
            | 514
            | 515
            | 526
            | 530
            | 531
            | 532
            | 540
            | 548
            | 554
            | 556
            | 563
            | 587
            | 601
            | 636
            | 989
            | 990
            | 993
            | 995
            | 1719
            | 1720
            | 1723
            | 2049
            | 3659
            | 4045
            | 4190
            | 5060
            | 5061
            | 6000
            | 6566
            | 6665..=6669 | 6679 | 6697 | 10080
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_public_ipv4_and_ipv6_addresses() {
        for address in [
            "1.1.1.1",
            "8.8.8.8",
            "2001:4860:4860::8888",
            "2606:4700:4700::1111",
            "64:ff9b::808:808",
        ] {
            assert!(is_publicly_routable(address.parse().unwrap()), "{address}");
        }
    }

    #[test]
    fn rejects_private_metadata_reserved_and_transition_addresses() {
        for address in [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.168.0.1",
            "198.18.0.1",
            "224.0.0.1",
            "::",
            "::1",
            "::2",
            "::ffff:127.0.0.1",
            "64:ff9b::a00:1",
            "64:ff9b::a9fe:a9fe",
            "fc00::1",
            "fe80::1",
            "fe00::1",
            "2001::1",
            "2001:2::1",
            "2001:10::1",
            "2001:20::1",
            "2001:db8::1",
            "2002:0808:0808::1",
            "3fff::1",
            "ff02::1",
        ] {
            assert!(!is_publicly_routable(address.parse().unwrap()), "{address}");
        }
    }

    #[test]
    fn browser_port_policy_covers_sensitive_services() {
        for port in [0, 22, 53, 389, 6000, 6667, 10080] {
            assert!(is_browser_blocked_port(port), "{port}");
        }
        for port in [80, 443, 8080, 8443] {
            assert!(!is_browser_blocked_port(port), "{port}");
        }
    }

    #[test]
    fn browser_special_use_policy_covers_exact_names_and_subdomains() {
        for host in [
            "localhost",
            "WWW.LOCALHOST.",
            "printer.local",
            "name.internal",
            "home.arpa",
            "service.onion",
            "name.test",
            "name.invalid",
            "name.example",
            "name.alt",
        ] {
            assert!(is_browser_special_use_host(host), "{host}");
        }
        for host in ["example.com", "public.org", "notlocalhost"] {
            assert!(!is_browser_special_use_host(host), "{host}");
        }
    }
}
