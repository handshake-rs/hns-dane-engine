//! Bounded concurrency and request-rate admission for the loopback listener.

use std::collections::{HashMap, VecDeque, hash_map::RandomState};
use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use thiserror::Error;

pub const DEFAULT_MAX_ACTIVE_CLIENTS: usize = 64;
pub const DEFAULT_GLOBAL_REQUESTS_PER_WINDOW: usize = 240;
pub const DEFAULT_HOST_REQUESTS_PER_WINDOW: usize = 80;
pub const DEFAULT_MAX_TRACKED_HOSTS: usize = 256;
pub const DEFAULT_RATE_WINDOW: Duration = Duration::from_secs(10);

/// Independently configurable request limits for a proxy generation.
///
/// Keeping this type in the admission module lets platform configuration map
/// into it without making the limiter depend on the server or configuration
/// modules.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RateLimitConfig {
    pub global_requests: usize,
    pub per_host_requests: usize,
    pub window: Duration,
    pub max_tracked_hosts: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            global_requests: DEFAULT_GLOBAL_REQUESTS_PER_WINDOW,
            per_host_requests: DEFAULT_HOST_REQUESTS_PER_WINDOW,
            window: DEFAULT_RATE_WINDOW,
            max_tracked_hosts: DEFAULT_MAX_TRACKED_HOSTS,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RateLimitConfigError {
    #[error("the global request limit must be non-zero")]
    ZeroGlobalLimit,
    #[error("the per-host request limit must be non-zero")]
    ZeroHostLimit,
    #[error("the rate-limit window must be non-zero")]
    ZeroWindow,
    #[error("the tracked-host limit must be non-zero")]
    ZeroTrackedHosts,
    #[error("the per-host request limit cannot exceed the global request limit")]
    HostLimitExceedsGlobal,
    #[error("a rate-limit value exceeds the hard proxy maximum")]
    ExceedsMaximum,
}

impl RateLimitConfig {
    pub fn validate(self) -> Result<Self, RateLimitConfigError> {
        if self.global_requests == 0 {
            return Err(RateLimitConfigError::ZeroGlobalLimit);
        }
        if self.per_host_requests == 0 {
            return Err(RateLimitConfigError::ZeroHostLimit);
        }
        if self.window.is_zero() {
            return Err(RateLimitConfigError::ZeroWindow);
        }
        if self.max_tracked_hosts == 0 {
            return Err(RateLimitConfigError::ZeroTrackedHosts);
        }
        if self.per_host_requests > self.global_requests {
            return Err(RateLimitConfigError::HostLimitExceedsGlobal);
        }
        if self.global_requests > DEFAULT_GLOBAL_REQUESTS_PER_WINDOW
            || self.per_host_requests > DEFAULT_HOST_REQUESTS_PER_WINDOW
            || self.window > DEFAULT_RATE_WINDOW
            || self.max_tracked_hosts > DEFAULT_MAX_TRACKED_HOSTS
        {
            return Err(RateLimitConfigError::ExceedsMaximum);
        }
        Ok(self)
    }
}

/// Shared active-client admission counter.
#[derive(Clone, Debug)]
pub struct ActiveClientLimiter {
    inner: Arc<ActiveClientLimiterInner>,
}

#[derive(Debug)]
struct ActiveClientLimiterInner {
    max_active: usize,
    active: AtomicUsize,
}

impl ActiveClientLimiter {
    pub fn new(max_active: usize) -> Self {
        Self {
            inner: Arc::new(ActiveClientLimiterInner {
                max_active,
                active: AtomicUsize::new(0),
            }),
        }
    }

    /// Acquires one client slot. Dropping the returned permit releases it.
    pub fn try_acquire(&self) -> Option<ActiveClientPermit> {
        let mut active = self.inner.active.load(Ordering::Acquire);
        loop {
            if active >= self.inner.max_active {
                return None;
            }
            match self.inner.active.compare_exchange_weak(
                active,
                active + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(ActiveClientPermit {
                        inner: Arc::clone(&self.inner),
                    });
                }
                Err(observed) => active = observed,
            }
        }
    }

    pub fn active(&self) -> usize {
        self.inner.active.load(Ordering::Acquire)
    }

    pub fn max_active(&self) -> usize {
        self.inner.max_active
    }
}

/// A single non-cloneable active-client slot.
#[derive(Debug)]
pub struct ActiveClientPermit {
    inner: Arc<ActiveClientLimiterInner>,
}

impl Drop for ActiveClientPermit {
    fn drop(&mut self) {
        self.inner.active.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RateLimitScope {
    Global,
    Host,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RateLimitDecision {
    Allowed,
    Limited {
        scope: RateLimitScope,
        retry_after: Duration,
    },
}

/// An exact sliding-window limiter with bounded per-host state.
///
/// Host names are hashed with a per-instance random key and never retained.
/// Hash collisions can only make admission stricter. Callers should pass the
/// canonical host so aliases do not receive separate windows.
#[derive(Clone, Debug)]
pub struct RequestRateLimiter {
    inner: Arc<RequestRateLimiterInner>,
}

#[derive(Debug)]
struct RequestRateLimiterInner {
    config: RateLimitConfig,
    host_hasher: RandomState,
    state: Mutex<RateLimitState>,
}

#[derive(Debug, Default)]
struct RateLimitState {
    global: VecDeque<Instant>,
    hosts: HashMap<u64, HostWindow>,
}

#[derive(Debug)]
struct HostWindow {
    requests: VecDeque<Instant>,
}

impl RequestRateLimiter {
    pub fn new(config: RateLimitConfig) -> Result<Self, RateLimitConfigError> {
        let config = config.validate()?;
        Ok(Self {
            inner: Arc::new(RequestRateLimiterInner {
                config,
                host_hasher: RandomState::new(),
                state: Mutex::new(RateLimitState::default()),
            }),
        })
    }

    pub fn config(&self) -> RateLimitConfig {
        self.inner.config
    }

    /// Atomically admits and records one request, or reports the limiting
    /// window and the earliest useful retry time.
    pub fn check(&self, canonical_host: &str, now: Instant) -> RateLimitDecision {
        let config = self.inner.config;
        let host_key = self.host_key(canonical_host);
        let mut state = lock_recover(&self.inner.state);

        expire(&mut state.global, now, config.window);
        for window in state.hosts.values_mut() {
            expire(&mut window.requests, now, config.window);
        }
        state.hosts.retain(|_, window| !window.requests.is_empty());

        if state.global.len() >= config.global_requests {
            return RateLimitDecision::Limited {
                scope: RateLimitScope::Global,
                retry_after: retry_after(&state.global, now, config.window),
            };
        }

        if let Some(host) = state.hosts.get_mut(&host_key) {
            if host.requests.len() >= config.per_host_requests {
                return RateLimitDecision::Limited {
                    scope: RateLimitScope::Host,
                    retry_after: retry_after(&host.requests, now, config.window),
                };
            }
        } else {
            if state.hosts.len() >= config.max_tracked_hosts {
                let retry_after = state
                    .hosts
                    .values()
                    .filter_map(|window| window.requests.front())
                    .filter_map(|request| request.checked_add(config.window))
                    .map(|expires| expires.saturating_duration_since(now))
                    .min()
                    .unwrap_or(config.window);
                return RateLimitDecision::Limited {
                    scope: RateLimitScope::Host,
                    retry_after,
                };
            }
            state.hosts.insert(
                host_key,
                HostWindow {
                    requests: VecDeque::new(),
                },
            );
        }

        state.global.push_back(now);
        if let Some(host) = state.hosts.get_mut(&host_key) {
            host.requests.push_back(now);
        }
        RateLimitDecision::Allowed
    }

    pub fn tracked_hosts(&self) -> usize {
        lock_recover(&self.inner.state).hosts.len()
    }

    fn host_key(&self, canonical_host: &str) -> u64 {
        let mut hasher = self.inner.host_hasher.build_hasher();
        for byte in canonical_host.bytes() {
            hasher.write_u8(byte.to_ascii_lowercase());
        }
        hasher.finish()
    }
}

fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn expire(requests: &mut VecDeque<Instant>, now: Instant, window: Duration) {
    while requests.front().is_some_and(|request| {
        request
            .checked_add(window)
            .is_some_and(|expires| expires <= now)
    }) {
        requests.pop_front();
    }
}

fn retry_after(requests: &VecDeque<Instant>, now: Instant, window: Duration) -> Duration {
    requests
        .front()
        .and_then(|request| request.checked_add(window))
        .map_or(window, |expires| expires.saturating_duration_since(now))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::mpsc;
    use std::thread;

    fn test_config() -> RateLimitConfig {
        RateLimitConfig {
            global_requests: 4,
            per_host_requests: 2,
            window: Duration::from_secs(10),
            max_tracked_hosts: 2,
        }
    }

    #[test]
    fn defaults_match_the_proxy_budget() {
        assert_eq!(
            RateLimitConfig::default(),
            RateLimitConfig {
                global_requests: 240,
                per_host_requests: 80,
                window: Duration::from_secs(10),
                max_tracked_hosts: 256,
            }
        );
        assert_eq!(DEFAULT_MAX_ACTIVE_CLIENTS, 64);
    }

    #[test]
    fn permit_releases_exactly_one_slot_on_drop() {
        let limiter = ActiveClientLimiter::new(1);
        let permit = limiter.try_acquire().expect("first slot");
        assert_eq!(limiter.active(), 1);
        assert!(limiter.try_acquire().is_none());
        drop(permit);
        assert_eq!(limiter.active(), 0);
        assert!(limiter.try_acquire().is_some());
    }

    #[test]
    fn concurrent_permits_never_exceed_the_limit() {
        let limiter = Arc::new(ActiveClientLimiter::new(8));
        let (sender, receiver) = mpsc::channel();
        let mut threads = Vec::new();
        for _ in 0..32 {
            let limiter = Arc::clone(&limiter);
            let sender = sender.clone();
            threads.push(thread::spawn(move || {
                sender
                    .send(limiter.try_acquire())
                    .expect("receiver remains alive");
            }));
        }
        drop(sender);
        for handle in threads {
            handle.join().expect("thread joins");
        }
        let permits = receiver.into_iter().flatten().collect::<Vec<_>>();
        assert_eq!(permits.len(), 8);
        assert_eq!(limiter.active(), 8);
        drop(permits);
        assert_eq!(limiter.active(), 0);
    }

    #[test]
    fn host_window_is_exact_and_case_insensitive() {
        let limiter = RequestRateLimiter::new(test_config()).expect("valid config");
        let now = Instant::now();
        assert_eq!(limiter.check("Example", now), RateLimitDecision::Allowed);
        assert_eq!(
            limiter.check("example", now + Duration::from_secs(1)),
            RateLimitDecision::Allowed
        );
        assert_eq!(
            limiter.check("EXAMPLE", now + Duration::from_secs(2)),
            RateLimitDecision::Limited {
                scope: RateLimitScope::Host,
                retry_after: Duration::from_secs(8),
            }
        );
        assert_eq!(
            limiter.check("example", now + Duration::from_secs(10)),
            RateLimitDecision::Allowed
        );
    }

    #[test]
    fn global_window_applies_across_hosts() {
        let limiter = RequestRateLimiter::new(RateLimitConfig {
            max_tracked_hosts: 8,
            ..test_config()
        })
        .expect("valid config");
        let now = Instant::now();
        for host in ["one", "two", "three", "four"] {
            assert_eq!(limiter.check(host, now), RateLimitDecision::Allowed);
        }
        assert_eq!(
            limiter.check("five", now),
            RateLimitDecision::Limited {
                scope: RateLimitScope::Global,
                retry_after: Duration::from_secs(10),
            }
        );
    }

    #[test]
    fn host_state_stays_capped_under_rotation() {
        let limiter = RequestRateLimiter::new(test_config()).expect("valid config");
        let now = Instant::now();
        assert_eq!(limiter.check("one", now), RateLimitDecision::Allowed);
        assert_eq!(limiter.check("two", now), RateLimitDecision::Allowed);
        assert_eq!(
            limiter.check("three", now),
            RateLimitDecision::Limited {
                scope: RateLimitScope::Host,
                retry_after: Duration::from_secs(10),
            }
        );
        assert_eq!(limiter.tracked_hosts(), 2);
    }

    #[test]
    fn invalid_config_is_rejected() {
        let mut config = test_config();
        config.max_tracked_hosts = 0;
        assert!(matches!(
            RequestRateLimiter::new(config),
            Err(RateLimitConfigError::ZeroTrackedHosts)
        ));
    }
}
