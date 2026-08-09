use crate::hash::Hash;
use num_bigint::BigUint;
use num_traits::{One, ToPrimitive, Zero};
use std::fmt;
use thiserror::Error;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Target(BigUint);

#[derive(Clone, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct Chainwork(BigUint);

#[derive(Debug, Error, Eq, PartialEq)]
pub enum PowError {
    #[error("compact target is negative")]
    NegativeTarget,
    #[error("compact target is zero")]
    ZeroTarget,
    #[error("compact target exceeds 256 bits")]
    Overflow,
    #[error("chainwork hex is invalid")]
    InvalidChainworkHex,
}

impl Target {
    pub fn from_compact(bits: u32) -> Result<Self, PowError> {
        compact_to_target(bits)
    }

    pub fn as_biguint(&self) -> &BigUint {
        &self.0
    }

    pub fn to_be_bytes_32(&self) -> [u8; 32] {
        let bytes = self.0.to_bytes_be();
        let mut out = [0u8; 32];
        let start = 32usize.saturating_sub(bytes.len());
        out[start..].copy_from_slice(&bytes);
        out
    }

    pub fn to_compact(&self) -> u32 {
        target_to_compact(self)
    }
}

impl Chainwork {
    pub fn zero() -> Self {
        Self(BigUint::zero())
    }

    pub fn from_bits(bits: u32) -> Result<Self, PowError> {
        Ok(Self(work_for_target(&Target::from_compact(bits)?)?))
    }

    pub fn checked_add(&self, other: &Self) -> Self {
        Self(&self.0 + &other.0)
    }

    pub fn checked_sub(&self, other: &Self) -> Option<Self> {
        if self.0 < other.0 {
            return None;
        }

        Some(Self(&self.0 - &other.0))
    }

    pub fn mul_u64(&self, factor: u64) -> Self {
        Self(&self.0 * factor)
    }

    pub fn div_u64(&self, divisor: u64) -> Option<Self> {
        if divisor == 0 {
            return None;
        }

        Some(Self(&self.0 / divisor))
    }

    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    pub fn as_biguint(&self) -> &BigUint {
        &self.0
    }

    pub fn from_hex(value: &str) -> Result<Self, PowError> {
        let parsed =
            BigUint::parse_bytes(value.as_bytes(), 16).ok_or(PowError::InvalidChainworkHex)?;
        Ok(Self(parsed))
    }

    pub fn to_hex(&self) -> String {
        self.0.to_str_radix(16)
    }
}

impl fmt::Debug for Chainwork {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "0x{}", self.0.to_str_radix(16))
    }
}

pub fn compact_to_target(bits: u32) -> Result<Target, PowError> {
    if bits & 0x0080_0000 != 0 {
        return Err(PowError::NegativeTarget);
    }

    let exponent = bits >> 24;
    let mantissa = bits & 0x007f_ffff;
    if mantissa == 0 {
        return Err(PowError::ZeroTarget);
    }

    let mut target = BigUint::from(mantissa);
    if exponent <= 3 {
        target >>= 8 * (3 - exponent);
    } else {
        target <<= 8 * (exponent - 3);
    }

    if target.is_zero() {
        return Err(PowError::ZeroTarget);
    }

    if target.bits() > 256 {
        return Err(PowError::Overflow);
    }

    Ok(Target(target))
}

pub fn work_for_target(target: &Target) -> Result<BigUint, PowError> {
    if target.0.is_zero() {
        return Err(PowError::ZeroTarget);
    }

    let numerator = BigUint::one() << 256u32;
    Ok(numerator / (&target.0 + BigUint::one()))
}

pub fn target_for_work(work: &Chainwork) -> Result<Target, PowError> {
    if work.0.is_zero() {
        return Err(PowError::ZeroTarget);
    }

    let numerator = BigUint::one() << 256u32;
    let target = numerator / &work.0;
    if target.is_zero() {
        return Err(PowError::ZeroTarget);
    }

    Ok(Target(target - BigUint::one()))
}

pub fn target_to_compact(target: &Target) -> u32 {
    if target.0.is_zero() {
        return 0;
    }

    let mut exponent = target.0.to_bytes_be().len() as u32;
    let mut mantissa = if exponent <= 3 {
        target
            .0
            .to_u32()
            .expect("target with at most 3 bytes fits in u32")
            << (8 * (3 - exponent))
    } else {
        (&target.0 >> (8 * (exponent - 3)))
            .to_u32()
            .expect("target compact mantissa fits in u32")
    };

    if mantissa & 0x0080_0000 != 0 {
        mantissa >>= 8;
        exponent += 1;
    }

    (exponent << 24) | mantissa
}

pub fn verify_pow(hash: Hash, bits: u32) -> Result<bool, PowError> {
    Ok(hash.as_bytes() <= &target_bytes_from_compact(bits)?)
}

fn target_bytes_from_compact(bits: u32) -> Result<[u8; 32], PowError> {
    if bits & 0x0080_0000 != 0 {
        return Err(PowError::NegativeTarget);
    }

    let exponent = bits >> 24;
    let mantissa = bits & 0x007f_ffff;
    if mantissa == 0 {
        return Err(PowError::ZeroTarget);
    }

    if exponent > 32 {
        return Ok(Target::from_compact(bits)?.to_be_bytes_32());
    }

    let mut out = [0u8; 32];
    if exponent <= 3 {
        let target = mantissa >> (8 * (3 - exponent));
        out[28..].copy_from_slice(&target.to_be_bytes());
    } else {
        let offset = 32usize
            .checked_sub(exponent as usize)
            .ok_or(PowError::Overflow)?;
        out[offset] = (mantissa >> 16) as u8;
        out[offset + 1] = (mantissa >> 8) as u8;
        out[offset + 2] = mantissa as u8;
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_mainnet_limit_matches_hsd() {
        let target = Target::from_compact(0x1c00ffff).unwrap();

        assert_eq!(
            hex::encode(target.to_be_bytes_32()),
            "0000000000ffff00000000000000000000000000000000000000000000000000",
        );
        assert_eq!(target.to_compact(), 0x1c00ffff);
    }

    #[test]
    fn compact_rejects_negative() {
        assert_eq!(
            Target::from_compact(0x1c80ffff).unwrap_err(),
            PowError::NegativeTarget,
        );
    }

    #[test]
    fn target_for_work_matches_hsd_retarget_fixture() {
        let target = Target::from_compact(0x1c00ffff).unwrap();
        let proof = Chainwork(work_for_target(&target).unwrap());
        let adjusted_work = proof.mul_u64(144 * 600).div_u64(36 * 600).unwrap();
        let adjusted_target = target_for_work(&adjusted_work).unwrap();

        assert_eq!(adjusted_target.to_compact(), 0x1b3fffc0);
    }
}
