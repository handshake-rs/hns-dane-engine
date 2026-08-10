//! Per-generation local TLS identities for scoped CONNECT termination.

use crate::{NormalizedHost, ProxyInstanceId};
use ring::digest::{SHA256, digest};
use rustls::ServerConfig;
use rustls::crypto::ring::sign::any_ecdsa_type;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroizing;

const MAX_CACHED_IDENTITIES: usize = 128;
const MAX_PRESENTED_CERTIFICATE_DER_BYTES: usize = 64 * 1024;

/// Opaque SHA-256 equality token for one generated local certificate.
///
/// Raw digest bytes and DER authorization are deliberately not exposed.
/// Diagnostics redact the token so it never enters ordinary logging.
#[derive(Clone, Copy)]
pub struct CertificateSha256([u8; 32]);

impl CertificateSha256 {
    /// Compares a bounded DER certificate to this pin in constant time after
    /// hashing. Oversized, attacker-controlled challenge data fails closed.
    pub(crate) fn matches_der(&self, certificate_der: &[u8]) -> bool {
        if certificate_der.len() > MAX_PRESENTED_CERTIFICATE_DER_BYTES {
            return false;
        }
        let candidate = digest(&SHA256, certificate_der);
        self.0.ct_eq(candidate.as_ref()).into()
    }

    fn from_der(certificate_der: &[u8]) -> Self {
        let fingerprint = digest(&SHA256, certificate_der);
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(fingerprint.as_ref());
        Self(bytes)
    }
}

impl PartialEq for CertificateSha256 {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for CertificateSha256 {}

impl fmt::Debug for CertificateSha256 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CertificateSha256([REDACTED])")
    }
}

/// Generation- and exact-host-bound certificate pin for browser trust hooks.
#[derive(Clone, Eq, PartialEq)]
pub struct LocalCertificatePin {
    instance: ProxyInstanceId,
    host: NormalizedHost,
    certificate_sha256: CertificateSha256,
}

impl LocalCertificatePin {
    /// Exposes the proxy instance (session and generation) that created this pin.
    pub fn instance(&self) -> &ProxyInstanceId {
        &self.instance
    }

    /// Explicitly exposes the canonical exact host covered by this pin.
    pub fn host(&self) -> &NormalizedHost {
        &self.host
    }

    /// Exposes the certificate's opaque SHA-256 equality token.
    pub fn certificate_sha256(&self) -> &CertificateSha256 {
        &self.certificate_sha256
    }

    /// Verifies DER only inside the active store. Keeping this non-public
    /// prevents a copied pin from becoming stale authorization after stop.
    pub(crate) fn matches_der(&self, certificate_der: &[u8]) -> bool {
        self.certificate_sha256.matches_der(certificate_der)
    }
}

impl fmt::Debug for LocalCertificatePin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalCertificatePin")
            .field("instance", &"[REDACTED]")
            .field("host", &"[REDACTED]")
            .field("certificate_sha256", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum CertificateError {
    #[error("the local TLS identity store is inactive")]
    Inactive,
    #[error("the local TLS identity cache is full of active leases")]
    CapacityExhausted,
    #[error("the local TLS identity store is unavailable")]
    StoreUnavailable,
    #[error("unable to generate a local TLS certificate")]
    CertificateGeneration,
    #[error("unable to load the generated local TLS signing key")]
    SigningKey,
    #[error("unable to configure the local TLS server")]
    ServerConfiguration,
}

/// A lease keeps its cache entry alive until the CONNECT connection finishes.
pub(crate) struct IdentityLease {
    identity: Arc<LocalTlsIdentity>,
}

impl IdentityLease {
    pub(crate) fn server_config(&self) -> Arc<ServerConfig> {
        Arc::clone(&self.identity.server_config)
    }

    pub(crate) fn pin(&self) -> &LocalCertificatePin {
        &self.identity.pin
    }
}

impl fmt::Debug for IdentityLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IdentityLease([REDACTED])")
    }
}

struct LocalTlsIdentity {
    server_config: Arc<ServerConfig>,
    pin: LocalCertificatePin,
    // Retaining public certificate bytes is harmless and lets the store avoid
    // recovering them through rustls internals when validating local pins.
    #[cfg(test)]
    certificate_der: Vec<u8>,
}

struct CacheEntry {
    identity: Arc<LocalTlsIdentity>,
    last_access: u128,
}

#[derive(Default)]
struct StoreState {
    entries: HashMap<NormalizedHost, CacheEntry>,
    access_counter: u128,
}

impl StoreState {
    fn next_access(&mut self) -> u128 {
        if self.access_counter == u128::MAX {
            let mut oldest_first: Vec<_> = self
                .entries
                .iter()
                .map(|(host, entry)| (host.clone(), entry.last_access))
                .collect();
            oldest_first.sort_by_key(|(_, last_access)| *last_access);
            for (rank, (host, _)) in oldest_first.into_iter().enumerate() {
                if let Some(entry) = self.entries.get_mut(&host) {
                    entry.last_access = rank as u128;
                }
            }
            self.access_counter = self.entries.len() as u128;
        }
        self.access_counter += 1;
        self.access_counter
    }
}

/// Exact-host identity cache owned by one proxy generation.
pub(crate) struct LocalTlsIdentityStore {
    instance: ProxyInstanceId,
    active: Arc<AtomicBool>,
    state: Mutex<StoreState>,
}

impl LocalTlsIdentityStore {
    pub(crate) fn new(instance: ProxyInstanceId) -> Self {
        Self {
            instance,
            active: Arc::new(AtomicBool::new(true)),
            state: Mutex::new(StoreState::default()),
        }
    }

    pub(crate) fn prepare(&self, host: &NormalizedHost) -> Result<IdentityLease, CertificateError> {
        if !self.active.load(Ordering::Acquire) {
            return Err(CertificateError::Inactive);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| CertificateError::StoreUnavailable)?;
        if !self.active.load(Ordering::Acquire) {
            return Err(CertificateError::Inactive);
        }

        let access = state.next_access();
        if let Some(entry) = state.entries.get_mut(host) {
            entry.last_access = access;
            if !self.active.load(Ordering::Acquire) {
                return Err(CertificateError::Inactive);
            }
            return Ok(IdentityLease {
                identity: Arc::clone(&entry.identity),
            });
        }

        let eviction = if state.entries.len() < MAX_CACHED_IDENTITIES {
            None
        } else {
            Some(
                state
                    .entries
                    .iter()
                    .filter(|(_, entry)| Arc::strong_count(&entry.identity) == 1)
                    .min_by_key(|(_, entry)| entry.last_access)
                    .map(|(candidate, _)| candidate.clone())
                    .ok_or(CertificateError::CapacityExhausted)?,
            )
        };

        // Generation happens while holding the state lock. This deliberately
        // serializes same-host generation and makes prepare/deactivate linear.
        // The eviction is committed only after generation succeeds.
        let identity = Arc::new(generate_identity(
            self.instance.clone(),
            host.clone(),
            Arc::clone(&self.active),
        )?);
        if !self.active.load(Ordering::Acquire) {
            return Err(CertificateError::Inactive);
        }
        if let Some(eviction) = eviction {
            state.entries.remove(&eviction);
        }
        state.entries.insert(
            host.clone(),
            CacheEntry {
                identity: Arc::clone(&identity),
                last_access: access,
            },
        );
        if !self.active.load(Ordering::Acquire) {
            state.entries.remove(host);
            return Err(CertificateError::Inactive);
        }
        Ok(IdentityLease { identity })
    }

    pub(crate) fn pin(&self, host: &NormalizedHost) -> Option<LocalCertificatePin> {
        if !self.active.load(Ordering::Acquire) {
            return None;
        }
        let mut state = self.state.lock().ok()?;
        if !self.active.load(Ordering::Acquire) {
            return None;
        }
        let access = state.next_access();
        let entry = state.entries.get_mut(host)?;
        entry.last_access = access;
        Some(entry.identity.pin.clone())
    }

    pub(crate) fn matches_der(&self, host: &NormalizedHost, certificate_der: &[u8]) -> bool {
        if certificate_der.len() > MAX_PRESENTED_CERTIFICATE_DER_BYTES {
            return false;
        }
        self.pin(host)
            .is_some_and(|pin| pin.matches_der(certificate_der))
    }

    pub(crate) fn deactivate(&self) {
        // Resolver revocation is immediate and never waits behind certificate
        // generation. The mutex is needed only to release cached identities.
        self.active.store(false, Ordering::Release);
        let mut state = lock_recover(&self.state);
        state.entries.clear();
    }
}

impl fmt::Debug for LocalTlsIdentityStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let entry_count = self
            .state
            .lock()
            .map(|state| state.entries.len())
            .unwrap_or_default();
        formatter
            .debug_struct("LocalTlsIdentityStore")
            .field("instance", &"[REDACTED]")
            .field("active", &self.active.load(Ordering::Acquire))
            .field("entry_count", &entry_count)
            .finish()
    }
}

impl Drop for LocalTlsIdentityStore {
    fn drop(&mut self) {
        self.deactivate();
    }
}

#[derive(Clone)]
struct ExactSniResolver {
    expected_host: NormalizedHost,
    certified_key: Arc<CertifiedKey>,
    active: Arc<AtomicBool>,
}

impl ExactSniResolver {
    fn allows(&self, presented_sni: Option<&str>) -> bool {
        self.active.load(Ordering::Acquire)
            && presented_sni
                .and_then(|name| NormalizedHost::parse(name).ok())
                .is_some_and(|name| name == self.expected_host)
    }
}

impl fmt::Debug for ExactSniResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExactSniResolver")
            .field("expected_host", &"[REDACTED]")
            .field("active", &self.active.load(Ordering::Acquire))
            .finish()
    }
}

impl ResolvesServerCert for ExactSniResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.allows(client_hello.server_name())
            .then(|| Arc::clone(&self.certified_key))
    }
}

fn generate_identity(
    instance: ProxyInstanceId,
    host: NormalizedHost,
    active: Arc<AtomicBool>,
) -> Result<LocalTlsIdentity, CertificateError> {
    let mut params = rcgen::CertificateParams::new(vec![host.as_str().to_owned()])
        .map_err(|_| CertificateError::CertificateGeneration)?;
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];

    // rcgen retains its PKCS#8 serialization alongside the ring key. Its
    // zeroize feature makes this guard erase that serialized state on every
    // success, error, and unwind path after key generation.
    let key_pair = Zeroizing::new(
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|_| CertificateError::CertificateGeneration)?,
    );
    let certificate = params
        .self_signed(&*key_pair)
        .map_err(|_| CertificateError::CertificateGeneration)?;
    let certificate_der = certificate.der().as_ref().to_vec();
    if certificate_der.len() > MAX_PRESENTED_CERTIFICATE_DER_BYTES {
        return Err(CertificateError::CertificateGeneration);
    }

    // rustls/ring parses the borrowed PKCS#8 bytes into its signing-key
    // representation. The temporary serialization is erased at scope exit.
    let private_key_der = Zeroizing::new(key_pair.serialize_der());
    let borrowed_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(private_key_der.as_slice()));
    let signing_key = any_ecdsa_type(&borrowed_key).map_err(|_| CertificateError::SigningKey)?;
    let certified_key = Arc::new(CertifiedKey::new(
        vec![CertificateDer::from(certificate_der.clone())],
        signing_key,
    ));
    certified_key
        .keys_match()
        .map_err(|_| CertificateError::SigningKey)?;

    let resolver = Arc::new(ExactSniResolver {
        expected_host: host.clone(),
        certified_key,
        active,
    });
    let mut server_config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|_| CertificateError::ServerConfiguration)?
            .with_no_client_auth()
            .with_cert_resolver(resolver);
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    // Every CONNECT is deliberately a fresh, single-request TLS connection.
    // Disabling resumption prevents per-host session-cache amplification and
    // ensures the exact current-generation certificate participates in every
    // handshake seen by a native browser trust hook.
    server_config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    server_config.send_tls13_tickets = 0;

    let pin = LocalCertificatePin {
        instance,
        host,
        certificate_sha256: CertificateSha256::from_der(&certificate_der),
    };
    Ok(LocalTlsIdentity {
        server_config: Arc::new(server_config),
        pin,
        #[cfg(test)]
        certificate_der,
    })
}

fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProxySessionId;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{ServerName, UnixTime};
    use rustls::{
        ClientConfig, ClientConnection, DigitallySignedStruct, Error as RustlsError,
        ServerConnection, SignatureScheme, SupportedProtocolVersion,
    };
    use std::sync::Barrier;
    use std::thread;

    fn instance(generation: u64) -> ProxyInstanceId {
        ProxyInstanceId::new(ProxySessionId::generate().unwrap(), generation)
    }

    fn host(name: &str) -> NormalizedHost {
        NormalizedHost::parse(name).unwrap()
    }

    fn entry_count(store: &LocalTlsIdentityStore) -> usize {
        lock_recover(&store.state).entries.len()
    }

    #[test]
    fn identities_are_fresh_across_stores_and_reused_within_one_store() {
        let shared_instance = instance(7);
        let first = LocalTlsIdentityStore::new(shared_instance.clone());
        let second = LocalTlsIdentityStore::new(shared_instance);
        let canonical = host("WELCOME.");
        let equivalent = host("welcome");

        let first_lease = first.prepare(&canonical).unwrap();
        let reused_lease = first.prepare(&equivalent).unwrap();
        let second_lease = second.prepare(&equivalent).unwrap();

        assert!(Arc::ptr_eq(&first_lease.identity, &reused_lease.identity));
        assert_eq!(first_lease.pin(), reused_lease.pin());
        assert_ne!(
            first_lease.pin().certificate_sha256(),
            second_lease.pin().certificate_sha256()
        );
        assert_eq!(first_lease.pin().host(), &equivalent);
        assert_eq!(entry_count(&first), 1);
    }

    #[test]
    fn pins_match_only_the_exact_host_certificate_and_active_generation() {
        let store = LocalTlsIdentityStore::new(instance(11));
        let welcome = host("welcome");
        let subdomain = host("www.welcome");
        let lease = store.prepare(&welcome).unwrap();
        let certificate_der = lease.identity.certificate_der.clone();

        assert!(lease.pin().matches_der(&certificate_der));
        assert!(store.matches_der(&welcome, &certificate_der));
        assert!(!store.matches_der(&subdomain, &certificate_der));
        assert!(!store.matches_der(&welcome, b"not the certificate"));
        assert!(!store.matches_der(
            &welcome,
            &vec![0_u8; MAX_PRESENTED_CERTIFICATE_DER_BYTES + 1]
        ));

        store.deactivate();
        assert_eq!(entry_count(&store), 0);
        assert!(store.pin(&welcome).is_none());
        assert!(!store.matches_der(&welcome, &certificate_der));
        assert!(matches!(
            store.prepare(&welcome),
            Err(CertificateError::Inactive)
        ));
    }

    #[test]
    fn diagnostics_redact_hosts_generation_tokens_and_fingerprints() {
        let store = LocalTlsIdentityStore::new(instance(23));
        let private_host = host("private-history.welcome");
        let lease = store.prepare(&private_host).unwrap();
        let pin_debug = format!("{:?}", lease.pin());
        let digest_debug = format!("{:?}", lease.pin().certificate_sha256());
        let lease_debug = format!("{lease:?}");
        let store_debug = format!("{store:?}");

        for diagnostic in [pin_debug, digest_debug, lease_debug, store_debug] {
            assert!(!diagnostic.contains(private_host.as_str()));
            assert!(!diagnostic.contains(store.instance.session().as_str()));
            assert!(diagnostic.contains("REDACTED") || diagnostic.contains("entry_count"));
        }
    }

    #[test]
    fn cache_evicts_the_least_recent_idle_identity_only() {
        let store = LocalTlsIdentityStore::new(instance(31));
        let hosts: Vec<_> = (0..MAX_CACHED_IDENTITIES)
            .map(|index| host(&format!("host-{index}.welcome")))
            .collect();
        for candidate in &hosts {
            drop(store.prepare(candidate).unwrap());
        }
        assert_eq!(entry_count(&store), MAX_CACHED_IDENTITIES);

        // Refresh the oldest entry so the second-created entry becomes LRU.
        drop(store.prepare(&hosts[0]).unwrap());
        let replacement = host("replacement.welcome");
        drop(store.prepare(&replacement).unwrap());

        assert_eq!(entry_count(&store), MAX_CACHED_IDENTITIES);
        assert!(store.pin(&hosts[0]).is_some());
        assert!(store.pin(&hosts[1]).is_none());
        assert!(store.pin(&replacement).is_some());
    }

    #[test]
    fn cache_fails_closed_when_every_identity_is_leased() {
        let store = LocalTlsIdentityStore::new(instance(37));
        let hosts: Vec<_> = (0..MAX_CACHED_IDENTITIES)
            .map(|index| host(&format!("leased-{index}.welcome")))
            .collect();
        let mut leases: Vec<_> = hosts
            .iter()
            .map(|candidate| store.prepare(candidate).unwrap())
            .collect();
        let extra = host("extra.welcome");

        assert!(matches!(
            store.prepare(&extra),
            Err(CertificateError::CapacityExhausted)
        ));
        assert_eq!(entry_count(&store), MAX_CACHED_IDENTITIES);

        drop(leases.remove(0));
        assert!(store.prepare(&extra).is_ok());
        assert_eq!(entry_count(&store), MAX_CACHED_IDENTITIES);
    }

    #[test]
    fn deactivate_fails_closed_for_prepare_and_pin_racing_the_state_lock() {
        let store = Arc::new(LocalTlsIdentityStore::new(instance(38)));
        let cached_host = host("cached.welcome");
        let pending_host = host("pending.welcome");
        let retained_lease = store.prepare(&cached_host).unwrap();
        let cached_certificate_der = retained_lease.identity.certificate_der.clone();

        // Keep both lookups behind the state mutex until deactivate has made
        // resolver revocation visible. Depending on scheduling, each lookup
        // observes inactivity either before locking or immediately after it;
        // neither path may publish a lease or pin after that transition.
        let state = lock_recover(&store.state);
        let lookup_gate = Arc::new(Barrier::new(3));
        let prepare_thread = {
            let store = Arc::clone(&store);
            let lookup_gate = Arc::clone(&lookup_gate);
            thread::spawn(move || {
                lookup_gate.wait();
                store
                    .prepare(&pending_host)
                    .map(|lease| lease.pin().clone())
            })
        };
        let pin_thread = {
            let store = Arc::clone(&store);
            let lookup_gate = Arc::clone(&lookup_gate);
            thread::spawn(move || {
                lookup_gate.wait();
                store.pin(&cached_host)
            })
        };
        lookup_gate.wait();

        let deactivate_thread = {
            let store = Arc::clone(&store);
            thread::spawn(move || store.deactivate())
        };
        while store.active.load(Ordering::Acquire) {
            thread::yield_now();
        }
        drop(state);

        assert!(matches!(
            prepare_thread.join().unwrap(),
            Err(CertificateError::Inactive)
        ));
        assert!(pin_thread.join().unwrap().is_none());
        deactivate_thread.join().unwrap();

        assert_eq!(entry_count(&store), 0);
        assert!(store.pin(&host("cached.welcome")).is_none());
        assert!(!store.matches_der(&host("cached.welcome"), &cached_certificate_der));
        assert!(
            handshake(
                retained_lease.server_config(),
                "cached.welcome",
                &rustls::version::TLS13,
                true,
            )
            .is_err()
        );
    }

    #[test]
    fn eviction_skips_a_retained_lru_lease_then_deactivation_revokes_it() {
        let store = LocalTlsIdentityStore::new(instance(39));
        let hosts: Vec<_> = (0..MAX_CACHED_IDENTITIES)
            .map(|index| host(&format!("lease-aware-{index}.welcome")))
            .collect();
        let retained_lru = store.prepare(&hosts[0]).unwrap();
        let retained_certificate_der = retained_lru.identity.certificate_der.clone();
        for candidate in &hosts[1..] {
            drop(store.prepare(candidate).unwrap());
        }

        let replacement = host("lease-aware-replacement.welcome");
        drop(store.prepare(&replacement).unwrap());

        assert_eq!(entry_count(&store), MAX_CACHED_IDENTITIES);
        assert_eq!(store.pin(&hosts[0]).as_ref(), Some(retained_lru.pin()));
        assert!(store.pin(&hosts[1]).is_none());
        assert!(store.pin(&replacement).is_some());
        assert!(store.matches_der(&hosts[0], &retained_certificate_der));

        store.deactivate();

        assert_eq!(entry_count(&store), 0);
        assert!(retained_lru.pin().matches_der(&retained_certificate_der));
        assert!(!store.matches_der(&hosts[0], &retained_certificate_der));
        assert!(
            handshake(
                retained_lru.server_config(),
                hosts[0].as_str(),
                &rustls::version::TLS13,
                true,
            )
            .is_err()
        );
    }

    #[derive(Debug)]
    struct AcceptCertificate;

    impl ServerCertVerifier for AcceptCertificate {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, RustlsError> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            signature: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, RustlsError> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                signature,
                &rustls::crypto::ring::default_provider().signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            signature: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, RustlsError> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                signature,
                &rustls::crypto::ring::default_provider().signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    fn handshake(
        server_config: Arc<ServerConfig>,
        sni: &str,
        version: &'static SupportedProtocolVersion,
        send_sni: bool,
    ) -> Result<Option<Vec<u8>>, RustlsError> {
        let mut client_config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[version])
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptCertificate))
                .with_no_client_auth();
        client_config.enable_sni = send_sni;
        client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let server_name = ServerName::try_from(sni.to_owned()).unwrap();
        let mut client = ClientConnection::new(Arc::new(client_config), server_name)?;
        let mut server = ServerConnection::new(server_config)?;

        for _ in 0..32 {
            let mut client_wire = Vec::new();
            while client.wants_write() {
                client
                    .write_tls(&mut client_wire)
                    .map_err(|_| in_memory_io_error())?;
            }
            if !client_wire.is_empty() {
                server
                    .read_tls(&mut client_wire.as_slice())
                    .map_err(|_| in_memory_io_error())?;
                server.process_new_packets()?;
            }

            let mut server_wire = Vec::new();
            while server.wants_write() {
                server
                    .write_tls(&mut server_wire)
                    .map_err(|_| in_memory_io_error())?;
            }
            if !server_wire.is_empty() {
                client
                    .read_tls(&mut server_wire.as_slice())
                    .map_err(|_| in_memory_io_error())?;
                client.process_new_packets()?;
            }

            if !client.is_handshaking() && !server.is_handshaking() {
                return Ok(client.alpn_protocol().map(<[u8]>::to_vec));
            }
        }
        Err(RustlsError::General(
            "in-memory TLS handshake did not finish".to_owned(),
        ))
    }

    fn in_memory_io_error() -> RustlsError {
        RustlsError::General("in-memory TLS handshake I/O failed".to_owned())
    }

    #[test]
    fn resolver_requires_exact_canonical_sni_and_supports_tls12_tls13_http11() {
        let store = LocalTlsIdentityStore::new(instance(41));
        let welcome = host("welcome");
        let lease = store.prepare(&welcome).unwrap();
        assert!(!lease.server_config().session_storage.can_cache());
        assert_eq!(lease.server_config().send_tls13_tickets, 0);

        for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
            assert_eq!(
                handshake(lease.server_config(), "welcome", version, true).unwrap(),
                Some(b"http/1.1".to_vec())
            );
        }
        assert_eq!(
            handshake(
                lease.server_config(),
                "WELCOME.",
                &rustls::version::TLS13,
                true,
            )
            .unwrap(),
            Some(b"http/1.1".to_vec())
        );
        assert!(
            handshake(
                lease.server_config(),
                "other.welcome",
                &rustls::version::TLS13,
                true
            )
            .is_err()
        );
        assert!(
            handshake(
                lease.server_config(),
                "welcome",
                &rustls::version::TLS13,
                false
            )
            .is_err()
        );

        store.deactivate();
        assert!(
            handshake(
                lease.server_config(),
                "welcome",
                &rustls::version::TLS13,
                true
            )
            .is_err()
        );
    }
}
