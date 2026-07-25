//! Bounded positive and negative cache for HNS browser resolution.
//!
//! Keys are session-secret-derived SHA-256 values rather than qnames. Entries
//! are bound to runtime generation, policy generation, and exact Handshake
//! chain anchor. Expired or mismatched entries are removed before use.

#![forbid(unsafe_code)]
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    reason = "HNS and DNS protocol names are intentional"
)]

use std::collections::HashMap;
use std::fmt;
use std::hash::Hash;

use hns_dns_wire::{Name, RecordType};
use sha2::{Digest, Sha256};
use thiserror::Error;

const CACHE_KEY_DOMAIN: &[u8] = b"hns-browser-cache-key-v1";

/// Bounds for one cache instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheLimits {
    /// Maximum resident entries.
    pub max_entries: usize,
    /// Maximum caller-reported bytes across resident values.
    pub max_total_value_bytes: usize,
    /// Maximum caller-reported bytes for one value.
    pub max_value_bytes: usize,
    /// Maximum positive TTL in seconds.
    pub max_positive_ttl: u32,
    /// Maximum negative TTL in seconds.
    pub max_negative_ttl: u32,
}

impl Default for CacheLimits {
    fn default() -> Self {
        Self {
            max_entries: 4_096,
            max_total_value_bytes: 16 * 1024 * 1024,
            max_value_bytes: 256 * 1024,
            max_positive_ttl: 86_400,
            max_negative_ttl: 3_600,
        }
    }
}

impl CacheLimits {
    fn validate(self) -> Result<Self, CacheError> {
        if self.max_entries == 0
            || self.max_total_value_bytes == 0
            || self.max_value_bytes == 0
            || self.max_value_bytes > self.max_total_value_bytes
            || self.max_positive_ttl == 0
            || self.max_negative_ttl == 0
        {
            return Err(CacheError::InvalidLimits);
        }
        Ok(self)
    }
}

/// Exact authority state under which an entry was produced.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CacheGeneration {
    /// Runtime generation.
    pub runtime_generation: u64,
    /// Policy generation.
    pub policy_generation: u64,
    /// Validated Handshake height.
    pub chain_height: u32,
    /// Exact committed Handshake name-tree root.
    pub tree_root: [u8; 32],
}

impl CacheGeneration {
    fn validate(self) -> Result<Self, CacheError> {
        if self.runtime_generation == 0 || self.policy_generation == 0 {
            return Err(CacheError::InvalidGeneration);
        }
        Ok(self)
    }
}

/// Negative cache result.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NegativeKind {
    /// DNSSEC-authenticated name error.
    NameError = 0,
    /// DNSSEC-authenticated no-data result.
    NoData = 1,
    /// Current HNS Urkel non-inclusion.
    HnsNameAbsent = 2,
}

/// Positive or authenticated-negative cache disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheDisposition {
    /// Positive validated data.
    Positive,
    /// Cryptographically authenticated absence.
    Negative(NegativeKind),
}

/// Metadata checked when admitting one cache value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheAdmission {
    /// Conservative encoded/in-memory value byte estimate.
    pub value_bytes: usize,
    /// Positive or authenticated-negative result.
    pub disposition: CacheDisposition,
    /// Exact runtime, policy, and chain authority.
    pub generation: CacheGeneration,
    /// Current monotonic or Unix time in seconds.
    pub now: u64,
    /// Requested TTL in seconds.
    pub ttl_seconds: u32,
}

/// Opaque per-session query key.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct CacheKey([u8; 32]);

impl CacheKey {
    /// Derive a key from a secret runtime salt and canonical query identity.
    pub fn derive(
        session_secret: &[u8; 32],
        network_id: u8,
        generation: CacheGeneration,
        name: &Name,
        record_type: RecordType,
    ) -> Result<Self, CacheError> {
        if session_secret == &[0; 32] {
            return Err(CacheError::WeakSessionSecret);
        }
        let generation = generation.validate()?;
        let mut wire_name = Vec::with_capacity(name.wire_len());
        name.encode(&mut wire_name)?;
        let mut hasher = Sha256::new();
        hasher.update(CACHE_KEY_DOMAIN);
        hasher.update(session_secret);
        hasher.update([network_id]);
        hasher.update(generation.runtime_generation.to_be_bytes());
        hasher.update(generation.policy_generation.to_be_bytes());
        hasher.update(generation.chain_height.to_be_bytes());
        hasher.update(generation.tree_root);
        hasher.update(record_type.code().to_be_bytes());
        hasher.update(
            u16::try_from(wire_name.len())
                .map_err(|_| CacheError::InvalidQuery)?
                .to_be_bytes(),
        );
        hasher.update(&wire_name);
        Ok(Self(hasher.finalize().into()))
    }
}

impl fmt::Debug for CacheKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CacheKey([redacted])")
    }
}

/// Name-free cache counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CacheStats {
    /// Resident entries.
    pub entries: usize,
    /// Caller-reported resident value bytes.
    pub value_bytes: usize,
    /// Successful current-generation reads.
    pub hits: u64,
    /// Absent, expired, or generation-mismatched reads.
    pub misses: u64,
    /// Capacity-driven removals.
    pub evictions: u64,
    /// TTL-driven removals.
    pub expirations: u64,
    /// Generation-mismatch removals.
    pub stale_removals: u64,
}

#[derive(Clone, Debug)]
struct Entry<Value> {
    value: Value,
    value_bytes: usize,
    disposition: CacheDisposition,
    generation: CacheGeneration,
    expires_at: u64,
    last_access: u64,
}

/// Bounded LRU cache with explicit TTL and authority-generation binding.
#[derive(Clone, Debug)]
pub struct SecureCache<Value> {
    limits: CacheLimits,
    entries: HashMap<CacheKey, Entry<Value>>,
    sequence: u64,
    stats: CacheStats,
}

impl<Value> SecureCache<Value> {
    /// Create an empty cache after validating all bounds.
    pub fn new(limits: CacheLimits) -> Result<Self, CacheError> {
        let limits = limits.validate()?;
        Ok(Self {
            limits,
            entries: HashMap::with_capacity(limits.max_entries),
            sequence: 0,
            stats: CacheStats::default(),
        })
    }

    /// Insert one positive or authenticated-negative result.
    ///
    /// `value_bytes` is the caller's conservative encoded/in-memory estimate.
    pub fn insert(
        &mut self,
        key: CacheKey,
        value: Value,
        admission: CacheAdmission,
    ) -> Result<(), CacheError> {
        let generation = admission.generation.validate()?;
        let value_bytes = admission.value_bytes;
        if value_bytes == 0
            || value_bytes > self.limits.max_value_bytes
            || value_bytes > self.limits.max_total_value_bytes
        {
            return Err(CacheError::ValueLimit);
        }
        let maximum_ttl = match admission.disposition {
            CacheDisposition::Positive => self.limits.max_positive_ttl,
            CacheDisposition::Negative(_) => self.limits.max_negative_ttl,
        };
        if admission.ttl_seconds == 0 || admission.ttl_seconds > maximum_ttl {
            return Err(CacheError::TtlLimit);
        }
        let expires_at = admission
            .now
            .checked_add(u64::from(admission.ttl_seconds))
            .ok_or(CacheError::TimeOverflow)?;
        let sequence = self.next_sequence()?;
        self.remove_expired(admission.now);
        self.remove_internal(&key);
        while self.entries.len() >= self.limits.max_entries
            || self
                .stats
                .value_bytes
                .checked_add(value_bytes)
                .is_none_or(|bytes| bytes > self.limits.max_total_value_bytes)
        {
            self.evict_lru().ok_or(CacheError::ValueLimit)?;
        }
        self.stats.value_bytes = self
            .stats
            .value_bytes
            .checked_add(value_bytes)
            .ok_or(CacheError::ValueLimit)?;
        self.entries.insert(
            key,
            Entry {
                value,
                value_bytes,
                disposition: admission.disposition,
                generation,
                expires_at,
                last_access: sequence,
            },
        );
        self.stats.entries = self.entries.len();
        Ok(())
    }

    /// Read one current entry and update its LRU position.
    pub fn get(
        &mut self,
        key: &CacheKey,
        generation: CacheGeneration,
        now: u64,
    ) -> Result<Option<(&Value, CacheDisposition)>, CacheError> {
        let generation = generation.validate()?;
        let Some(metadata) = self
            .entries
            .get(key)
            .map(|entry| (entry.generation, entry.expires_at, entry.disposition))
        else {
            self.stats.misses = self.stats.misses.saturating_add(1);
            return Ok(None);
        };
        if metadata.0 != generation {
            self.remove_internal(key);
            self.stats.stale_removals = self.stats.stale_removals.saturating_add(1);
            self.stats.misses = self.stats.misses.saturating_add(1);
            return Ok(None);
        }
        if now >= metadata.1 {
            self.remove_internal(key);
            self.stats.expirations = self.stats.expirations.saturating_add(1);
            self.stats.misses = self.stats.misses.saturating_add(1);
            return Ok(None);
        }
        let sequence = self.next_sequence()?;
        let entry = self
            .entries
            .get_mut(key)
            .ok_or(CacheError::InternalInvariant)?;
        entry.last_access = sequence;
        self.stats.hits = self.stats.hits.saturating_add(1);
        Ok(Some((&entry.value, metadata.2)))
    }

    /// Remove every entry on a generation, policy, or chain-anchor transition.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.stats.entries = 0;
        self.stats.value_bytes = 0;
    }

    /// Remove one opaque key.
    pub fn remove(&mut self, key: &CacheKey) -> bool {
        self.remove_internal(key).is_some()
    }

    /// Name-free counters.
    #[must_use]
    pub const fn stats(&self) -> CacheStats {
        self.stats
    }

    /// Configured hard bounds.
    #[must_use]
    pub const fn limits(&self) -> CacheLimits {
        self.limits
    }

    fn next_sequence(&mut self) -> Result<u64, CacheError> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(CacheError::SequenceExhausted)?;
        Ok(self.sequence)
    }

    fn remove_expired(&mut self, now: u64) {
        let expired = self
            .entries
            .iter()
            .filter_map(|(key, entry)| (now >= entry.expires_at).then_some(*key))
            .collect::<Vec<_>>();
        for key in expired {
            if self.remove_internal(&key).is_some() {
                self.stats.expirations = self.stats.expirations.saturating_add(1);
            }
        }
    }

    fn evict_lru(&mut self) -> Option<()> {
        let key = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.last_access)
            .map(|(key, _)| *key)?;
        self.remove_internal(&key)?;
        self.stats.evictions = self.stats.evictions.saturating_add(1);
        Some(())
    }

    fn remove_internal(&mut self, key: &CacheKey) -> Option<Entry<Value>> {
        let entry = self.entries.remove(key)?;
        self.stats.value_bytes = self.stats.value_bytes.saturating_sub(entry.value_bytes);
        self.stats.entries = self.entries.len();
        Some(entry)
    }
}

/// Cache configuration, key, bound, or invariant failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CacheError {
    /// DNS name encoding failed.
    #[error("DNS query encoding failed: {0}")]
    Wire(#[from] hns_dns_wire::Error),
    /// A configured cache bound is zero or inconsistent.
    #[error("invalid cache limits")]
    InvalidLimits,
    /// Runtime or policy generation is zero.
    #[error("invalid cache generation")]
    InvalidGeneration,
    /// Runtime cache-key secret is all zero.
    #[error("cache session secret must be randomly generated")]
    WeakSessionSecret,
    /// Canonical query identity cannot be represented.
    #[error("invalid cache query identity")]
    InvalidQuery,
    /// Caller-reported value size exceeds a bound.
    #[error("cache value exceeds its bound")]
    ValueLimit,
    /// TTL is zero or exceeds its positive/negative bound.
    #[error("cache TTL exceeds its bound")]
    TtlLimit,
    /// Expiration time overflowed.
    #[error("cache expiration time overflow")]
    TimeOverflow,
    /// LRU sequence cannot advance.
    #[error("cache LRU sequence exhausted")]
    SequenceExhausted,
    /// Internal entry disappeared during one exclusive operation.
    #[error("cache internal invariant failed")]
    InternalInvariant,
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "tests fail immediately on invalid local cache fixtures"
)]
mod tests {
    use super::*;

    fn cache_generation(value: u8) -> CacheGeneration {
        CacheGeneration {
            runtime_generation: u64::from(value),
            policy_generation: 1,
            chain_height: 100,
            tree_root: [value; 32],
        }
    }

    fn key(secret: u8, name: &str, generation: CacheGeneration) -> CacheKey {
        CacheKey::derive(
            &[secret; 32],
            0,
            generation,
            &Name::from_ascii(name).unwrap(),
            RecordType::Tlsa,
        )
        .unwrap()
    }

    #[test]
    fn keys_are_qname_free_session_and_generation_specific() {
        let generation = cache_generation(1);
        let first = key(7, "_443._tcp.alpha.", generation);
        let same = key(7, "_443._tcp.alpha.", generation);
        let other_secret = key(8, "_443._tcp.alpha.", generation);
        let other_generation = key(7, "_443._tcp.alpha.", cache_generation(2));
        assert_eq!(first, same);
        assert_ne!(first, other_secret);
        assert_ne!(first, other_generation);
        assert_eq!(format!("{first:?}"), "CacheKey([redacted])");
        assert!(matches!(
            CacheKey::derive(
                &[0; 32],
                0,
                generation,
                &Name::from_ascii("alpha.").unwrap(),
                RecordType::A,
            ),
            Err(CacheError::WeakSessionSecret)
        ));
    }

    #[test]
    fn expiration_and_generation_mismatch_remove_before_use() {
        let generation = cache_generation(1);
        let cache_key = key(7, "alpha.", generation);
        let mut cache = SecureCache::new(CacheLimits::default()).unwrap();
        cache
            .insert(
                cache_key,
                "secure",
                CacheAdmission {
                    value_bytes: 6,
                    disposition: CacheDisposition::Positive,
                    generation,
                    now: 100,
                    ttl_seconds: 10,
                },
            )
            .unwrap();
        assert_eq!(
            cache.get(&cache_key, generation, 109).unwrap(),
            Some((&"secure", CacheDisposition::Positive))
        );
        assert_eq!(cache.get(&cache_key, generation, 110).unwrap(), None);
        assert_eq!(cache.stats().expirations, 1);

        cache
            .insert(
                cache_key,
                "negative",
                CacheAdmission {
                    value_bytes: 8,
                    disposition: CacheDisposition::Negative(NegativeKind::NoData),
                    generation,
                    now: 200,
                    ttl_seconds: 10,
                },
            )
            .unwrap();
        assert_eq!(
            cache.get(&cache_key, cache_generation(2), 201).unwrap(),
            None
        );
        assert_eq!(cache.stats().stale_removals, 1);
    }

    #[test]
    fn entry_and_byte_bounds_evict_least_recently_used() {
        let limits = CacheLimits {
            max_entries: 2,
            max_total_value_bytes: 8,
            max_value_bytes: 8,
            max_positive_ttl: 100,
            max_negative_ttl: 10,
        };
        let generation = cache_generation(1);
        let first = key(7, "one.", generation);
        let second = key(7, "two.", generation);
        let third = key(7, "three.", generation);
        let mut cache = SecureCache::new(limits).unwrap();
        for (key, value) in [(first, "1111"), (second, "2222")] {
            cache
                .insert(
                    key,
                    value,
                    CacheAdmission {
                        value_bytes: 4,
                        disposition: CacheDisposition::Positive,
                        generation,
                        now: 0,
                        ttl_seconds: 100,
                    },
                )
                .unwrap();
        }
        assert!(cache.get(&first, generation, 1).unwrap().is_some());
        cache
            .insert(
                third,
                "3333",
                CacheAdmission {
                    value_bytes: 4,
                    disposition: CacheDisposition::Positive,
                    generation,
                    now: 2,
                    ttl_seconds: 100,
                },
            )
            .unwrap();
        assert!(cache.get(&second, generation, 3).unwrap().is_none());
        assert!(cache.get(&first, generation, 3).unwrap().is_some());
        assert!(cache.get(&third, generation, 3).unwrap().is_some());
        assert_eq!(cache.stats().evictions, 1);
        assert_eq!(cache.stats().entries, 2);
        assert_eq!(cache.stats().value_bytes, 8);
    }

    #[test]
    fn invalid_limits_sizes_and_ttls_fail_without_insertion() {
        assert!(matches!(
            SecureCache::<()>::new(CacheLimits {
                max_entries: 0,
                ..CacheLimits::default()
            }),
            Err(CacheError::InvalidLimits)
        ));
        let mut cache = SecureCache::new(CacheLimits {
            max_entries: 1,
            max_total_value_bytes: 8,
            max_value_bytes: 4,
            max_positive_ttl: 10,
            max_negative_ttl: 2,
        })
        .unwrap();
        let generation = cache_generation(1);
        let cache_key = key(7, "alpha.", generation);
        assert!(matches!(
            cache.insert(
                cache_key,
                (),
                CacheAdmission {
                    value_bytes: 5,
                    disposition: CacheDisposition::Positive,
                    generation,
                    now: 0,
                    ttl_seconds: 1,
                },
            ),
            Err(CacheError::ValueLimit)
        ));
        assert!(matches!(
            cache.insert(
                cache_key,
                (),
                CacheAdmission {
                    value_bytes: 1,
                    disposition: CacheDisposition::Negative(NegativeKind::NameError),
                    generation,
                    now: 0,
                    ttl_seconds: 3,
                },
            ),
            Err(CacheError::TtlLimit)
        ));
        assert_eq!(cache.stats().entries, 0);
    }
}
