use crate::hash::Hash;
use std::str::FromStr;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkKind {
    Mainnet,
    Testnet,
    Regtest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Network {
    pub name: &'static str,
    pub magic: u32,
    pub port: u16,
    pub brontide_port: u16,
    pub dns_seeds: &'static [&'static str],
    pub pow_bits: u32,
    pub pow_limit_hex: &'static str,
    pub genesis_hash: Hash,
}

pub const MAINNET_DNS_SEEDS: &[&str] = &["hs-mainnet.bcoin.ninja", "seed.htools.work"];
pub const TESTNET_DNS_SEEDS: &[&str] = &["hs-testnet.bcoin.ninja"];
pub const REGTEST_DNS_SEEDS: &[&str] = &[];

impl NetworkKind {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "main" | "mainnet" => Some(Self::Mainnet),
            "test" | "testnet" => Some(Self::Testnet),
            "reg" | "regtest" => Some(Self::Regtest),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
            Self::Regtest => "regtest",
        }
    }

    pub fn network(self) -> Network {
        match self {
            Self::Mainnet => mainnet(),
            Self::Testnet => testnet(),
            Self::Regtest => regtest(),
        }
    }
}

impl FromStr for NetworkKind {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value).ok_or(())
    }
}

pub fn mainnet() -> Network {
    Network {
        name: "mainnet",
        magic: 1_533_997_779,
        port: 12_038,
        brontide_port: 44_806,
        dns_seeds: MAINNET_DNS_SEEDS,
        pow_bits: 0x1c00ffff,
        pow_limit_hex: "0000000000ffff00000000000000000000000000000000000000000000000000",
        genesis_hash: Hash::from_hex(
            "5b6ef2d3c1f3cdcadfd9a030ba1811efdd17740f14e166489760741d075992e0",
        )
        .expect("valid mainnet genesis hash"),
    }
}

pub fn testnet() -> Network {
    Network {
        name: "testnet",
        magic: 2_974_944_722,
        port: 13_038,
        brontide_port: 45_806,
        dns_seeds: TESTNET_DNS_SEEDS,
        pow_bits: 0x1d00ffff,
        pow_limit_hex: "00000000ffff0000000000000000000000000000000000000000000000000000",
        genesis_hash: Hash::from_hex(
            "b1520dd24372f82ec94ebf8cf9d9b037d419c4aa3575d05dec70aedd1b427901",
        )
        .expect("valid testnet genesis hash"),
    }
}

pub fn regtest() -> Network {
    Network {
        name: "regtest",
        magic: 2_922_943_951,
        port: 14_038,
        brontide_port: 46_806,
        dns_seeds: REGTEST_DNS_SEEDS,
        pow_bits: 0x207fffff,
        pow_limit_hex: "7fffff0000000000000000000000000000000000000000000000000000000000",
        genesis_hash: Hash::from_hex(
            "ae3895cf597eff05b19e02a70ceeeecb9dc72dbfe6504a50e9343a72f06a87c5",
        )
        .expect("valid regtest genesis hash"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BlockHeader;

    #[test]
    fn testnet_network_matches_genesis_header() {
        let network = testnet();

        assert_eq!(network.name, "testnet");
        assert_eq!(network.magic, 2_974_944_722);
        assert_eq!(network.port, 13_038);
        assert_eq!(network.genesis_hash, BlockHeader::testnet_genesis().hash());
    }

    #[test]
    fn regtest_network_matches_genesis_header() {
        let network = regtest();

        assert_eq!(network.name, "regtest");
        assert_eq!(network.magic, 2_922_943_951);
        assert_eq!(network.port, 14_038);
        assert_eq!(network.genesis_hash, BlockHeader::regtest_genesis().hash());
    }

    #[test]
    fn parses_network_kind_aliases() {
        assert_eq!("main".parse(), Ok(NetworkKind::Mainnet));
        assert_eq!(" TESTNET ".parse(), Ok(NetworkKind::Testnet));
        assert_eq!("reg".parse(), Ok(NetworkKind::Regtest));
        assert!("unknown".parse::<NetworkKind>().is_err());
    }
}
