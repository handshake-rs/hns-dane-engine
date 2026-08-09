use crate::bytes::{ParseError, Reader};
use crate::hash::{Hash, blake2b_256, blake2b_512, sha3_256};

pub const HEADER_SIZE: usize = 236;
pub const EXTRA_NONCE_SIZE: usize = 24;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockHeader {
    pub nonce: u32,
    pub time: u64,
    pub prev_block: Hash,
    pub tree_root: Hash,
    pub extra_nonce: [u8; EXTRA_NONCE_SIZE],
    pub reserved_root: Hash,
    pub witness_root: Hash,
    pub merkle_root: Hash,
    pub version: u32,
    pub bits: u32,
    pub mask: Hash,
}

impl BlockHeader {
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() != HEADER_SIZE {
            return Err(ParseError::UnexpectedEof);
        }

        let mut reader = Reader::new(data);
        let header = Self {
            nonce: reader.read_u32_le()?,
            time: reader.read_u64_le()?,
            prev_block: Hash::new(reader.read_array()?),
            tree_root: Hash::new(reader.read_array()?),
            extra_nonce: reader.read_array()?,
            reserved_root: Hash::new(reader.read_array()?),
            witness_root: Hash::new(reader.read_array()?),
            merkle_root: Hash::new(reader.read_array()?),
            version: reader.read_u32_le()?,
            bits: reader.read_u32_le()?,
            mask: Hash::new(reader.read_array()?),
        };
        reader.ensure_finished()?;
        Ok(header)
    }

    pub fn serialize(&self) -> [u8; HEADER_SIZE] {
        let mut out = [0u8; HEADER_SIZE];
        let mut offset = 0;
        write_bytes(&mut out, &mut offset, &self.nonce.to_le_bytes());
        write_bytes(&mut out, &mut offset, &self.time.to_le_bytes());
        write_bytes(&mut out, &mut offset, self.prev_block.as_bytes());
        write_bytes(&mut out, &mut offset, self.tree_root.as_bytes());
        write_bytes(&mut out, &mut offset, &self.extra_nonce);
        write_bytes(&mut out, &mut offset, self.reserved_root.as_bytes());
        write_bytes(&mut out, &mut offset, self.witness_root.as_bytes());
        write_bytes(&mut out, &mut offset, self.merkle_root.as_bytes());
        write_bytes(&mut out, &mut offset, &self.version.to_le_bytes());
        write_bytes(&mut out, &mut offset, &self.bits.to_le_bytes());
        write_bytes(&mut out, &mut offset, self.mask.as_bytes());
        debug_assert_eq!(offset, HEADER_SIZE);
        out
    }

    pub fn mainnet_genesis() -> Self {
        Self {
            nonce: 0,
            time: 1_580_745_078,
            prev_block: Hash::ZERO,
            tree_root: Hash::ZERO,
            extra_nonce: [0u8; EXTRA_NONCE_SIZE],
            reserved_root: Hash::ZERO,
            witness_root: Hash::from_hex(
                "1a2c60b9439206938f8d7823782abdb8b211a57431e9c9b6a6365d8d42893351",
            )
            .expect("valid genesis witness root"),
            merkle_root: Hash::from_hex(
                "8e4c9756fef2ad10375f360e0560fcc7587eb5223ddf8cd7c7e06e60a1140b15",
            )
            .expect("valid genesis merkle root"),
            version: 0,
            bits: 0x1c00ffff,
            mask: Hash::ZERO,
        }
    }

    pub fn testnet_genesis() -> Self {
        Self {
            time: 1_580_745_079,
            bits: 0x1d00ffff,
            ..Self::genesis_template()
        }
    }

    pub fn regtest_genesis() -> Self {
        Self {
            time: 1_580_745_080,
            bits: 0x207fffff,
            ..Self::genesis_template()
        }
    }

    pub fn genesis_for_network(network: crate::network::NetworkKind) -> Self {
        match network {
            crate::network::NetworkKind::Mainnet => Self::mainnet_genesis(),
            crate::network::NetworkKind::Testnet => Self::testnet_genesis(),
            crate::network::NetworkKind::Regtest => Self::regtest_genesis(),
        }
    }

    pub fn hash(&self) -> Hash {
        self.pow_hash()
    }

    pub fn sub_hash(&self) -> Hash {
        blake2b_256(&[&self.to_subhead()])
    }

    pub fn mask_hash(&self) -> Hash {
        blake2b_256(&[self.prev_block.as_bytes(), self.mask.as_bytes()])
    }

    pub fn commit_hash(&self) -> Hash {
        let sub_hash = self.sub_hash();
        let mask_hash = self.mask_hash();
        blake2b_256(&[sub_hash.as_bytes(), mask_hash.as_bytes()])
    }

    pub fn share_hash(&self) -> Hash {
        let prehead = self.to_prehead();
        let left = blake2b_512(&[&prehead]);
        let padding8 = self.padding::<8>();
        let right = sha3_256(&[&prehead, &padding8]);
        let padding32 = self.padding::<32>();
        blake2b_256(&[&left, &padding32, right.as_bytes()])
    }

    pub fn pow_hash(&self) -> Hash {
        let mut hash = self.share_hash().into_bytes();
        for (byte, mask) in hash.iter_mut().zip(self.mask.as_bytes()) {
            *byte ^= mask;
        }
        Hash::new(hash)
    }

    pub fn to_subhead(&self) -> [u8; 128] {
        let mut out = [0u8; 128];
        let mut offset = 0;
        write_bytes(&mut out, &mut offset, &self.extra_nonce);
        write_bytes(&mut out, &mut offset, self.reserved_root.as_bytes());
        write_bytes(&mut out, &mut offset, self.witness_root.as_bytes());
        write_bytes(&mut out, &mut offset, self.merkle_root.as_bytes());
        write_bytes(&mut out, &mut offset, &self.version.to_le_bytes());
        write_bytes(&mut out, &mut offset, &self.bits.to_le_bytes());
        debug_assert_eq!(offset, 128);
        out
    }

    pub fn to_prehead(&self) -> [u8; 128] {
        let commit_hash = self.commit_hash();
        let mut out = [0u8; 128];
        let mut offset = 0;
        write_bytes(&mut out, &mut offset, &self.nonce.to_le_bytes());
        write_bytes(&mut out, &mut offset, &self.time.to_le_bytes());
        write_bytes(&mut out, &mut offset, &self.padding::<20>());
        write_bytes(&mut out, &mut offset, self.prev_block.as_bytes());
        write_bytes(&mut out, &mut offset, self.tree_root.as_bytes());
        write_bytes(&mut out, &mut offset, commit_hash.as_bytes());
        debug_assert_eq!(offset, 128);
        out
    }

    fn padding<const N: usize>(&self) -> [u8; N] {
        let mut out = [0u8; N];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = self.prev_block.as_bytes()[index % 32] ^ self.tree_root.as_bytes()[index % 32];
        }
        out
    }

    fn genesis_template() -> Self {
        Self {
            nonce: 0,
            time: 1_580_745_078,
            prev_block: Hash::ZERO,
            tree_root: Hash::ZERO,
            extra_nonce: [0u8; EXTRA_NONCE_SIZE],
            reserved_root: Hash::ZERO,
            witness_root: Hash::from_hex(
                "1a2c60b9439206938f8d7823782abdb8b211a57431e9c9b6a6365d8d42893351",
            )
            .expect("valid genesis witness root"),
            merkle_root: Hash::from_hex(
                "8e4c9756fef2ad10375f360e0560fcc7587eb5223ddf8cd7c7e06e60a1140b15",
            )
            .expect("valid genesis merkle root"),
            version: 0,
            bits: 0x1c00ffff,
            mask: Hash::ZERO,
        }
    }
}

fn write_bytes<const N: usize>(out: &mut [u8; N], offset: &mut usize, bytes: &[u8]) {
    let end = *offset + bytes.len();
    out[*offset..end].copy_from_slice(bytes);
    *offset = end;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trip_preserves_genesis() {
        let genesis = BlockHeader::mainnet_genesis();
        let encoded = genesis.serialize();
        let decoded = BlockHeader::parse(&encoded).unwrap();

        assert_eq!(decoded, genesis);
    }

    #[test]
    fn mainnet_genesis_hash_matches_hsd() {
        let genesis = BlockHeader::mainnet_genesis();

        assert_eq!(
            genesis.hash().to_string(),
            "5b6ef2d3c1f3cdcadfd9a030ba1811efdd17740f14e166489760741d075992e0",
        );
    }

    #[test]
    fn testnet_genesis_hash_matches_hsd() {
        assert_eq!(
            BlockHeader::testnet_genesis().hash().to_string(),
            "b1520dd24372f82ec94ebf8cf9d9b037d419c4aa3575d05dec70aedd1b427901",
        );
    }

    #[test]
    fn regtest_genesis_hash_matches_hsd() {
        assert_eq!(
            BlockHeader::regtest_genesis().hash().to_string(),
            "ae3895cf597eff05b19e02a70ceeeecb9dc72dbfe6504a50e9343a72f06a87c5",
        );
    }

    #[test]
    fn parser_rejects_short_header() {
        assert_eq!(
            BlockHeader::parse(&[0u8; HEADER_SIZE - 1]).unwrap_err(),
            ParseError::UnexpectedEof,
        );
    }
}
