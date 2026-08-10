//! Bounded local TLS termination after an authenticated `CONNECT` request.

use crate::backend::CancellationToken;
use crate::certificate::IdentityLease;
use crate::host::NormalizedHost;
use rustls::{ServerConnection, StreamOwned};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;

const HTTP_1_1_ALPN: &[u8] = b"http/1.1";
const CANCELLATION_POLL_INTERVAL: Duration = Duration::from_millis(25);

pub(crate) type TlsStream = StreamOwned<ServerConnection, DeadlineTcpStream>;

/// Payload-free local TLS failure suitable for privacy-bounded diagnostics.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum TlsTerminationError {
    #[error("local TLS handshake was cancelled")]
    Cancelled,
    #[error("local TLS handshake timed out")]
    TimedOut,
    #[error("local TLS handshake failed")]
    HandshakeFailed,
    #[error("local TLS server name was rejected")]
    ServerNameRejected,
    #[error("local TLS application protocol was rejected")]
    ApplicationProtocolRejected,
    #[error("local TLS socket configuration failed")]
    Socket,
}

/// Completes one server-side TLS handshake without ever writing a plaintext
/// response to the post-`CONNECT` stream.
pub(crate) fn accept_local_tls(
    stream: TcpStream,
    identity: &IdentityLease,
    expected_host: &NormalizedHost,
    timeout: Duration,
    cancellation: &CancellationToken,
) -> Result<TlsStream, TlsTerminationError> {
    accept_local_tls_with_config(
        stream,
        identity.server_config(),
        expected_host,
        timeout,
        cancellation,
    )
}

fn accept_local_tls_with_config(
    mut stream: TcpStream,
    server_config: Arc<rustls::ServerConfig>,
    expected_host: &NormalizedHost,
    timeout: Duration,
    cancellation: &CancellationToken,
) -> Result<TlsStream, TlsTerminationError> {
    if cancellation.is_cancelled() {
        return Err(TlsTerminationError::Cancelled);
    }
    let started = Instant::now();
    let deadline = started
        .checked_add(timeout)
        .ok_or(TlsTerminationError::TimedOut)?;
    let previous_read_timeout = stream
        .read_timeout()
        .map_err(|_error| TlsTerminationError::Socket)?;
    let previous_write_timeout = stream
        .write_timeout()
        .map_err(|_error| TlsTerminationError::Socket)?;
    let mut connection = ServerConnection::new(server_config)
        .map_err(|_error| TlsTerminationError::HandshakeFailed)?;

    while connection.is_handshaking() {
        let result = {
            let mut io = HandshakeIo {
                stream: &mut stream,
                deadline,
                cancellation,
            };
            connection.complete_io(&mut io)
        };
        match result {
            Ok((0, 0)) if connection.is_handshaking() => {
                return Err(TlsTerminationError::HandshakeFailed);
            }
            Ok(_) => {}
            Err(_error) if cancellation.is_cancelled() => {
                return Err(TlsTerminationError::Cancelled);
            }
            Err(_error) if Instant::now() >= deadline => {
                return Err(TlsTerminationError::TimedOut);
            }
            Err(_error) => return Err(TlsTerminationError::HandshakeFailed),
        }
    }

    if cancellation.is_cancelled() {
        return Err(TlsTerminationError::Cancelled);
    }
    if Instant::now() >= deadline {
        return Err(TlsTerminationError::TimedOut);
    }
    let server_name = connection
        .server_name()
        .ok_or(TlsTerminationError::ServerNameRejected)?;
    let normalized_server_name = NormalizedHost::parse(server_name)
        .map_err(|_error| TlsTerminationError::ServerNameRejected)?;
    if normalized_server_name != *expected_host {
        return Err(TlsTerminationError::ServerNameRejected);
    }
    if connection
        .alpn_protocol()
        .is_some_and(|protocol| protocol != HTTP_1_1_ALPN)
    {
        return Err(TlsTerminationError::ApplicationProtocolRejected);
    }

    stream
        .set_read_timeout(previous_read_timeout)
        .map_err(|_error| TlsTerminationError::Socket)?;
    stream
        .set_write_timeout(previous_write_timeout)
        .map_err(|_error| TlsTerminationError::Socket)?;
    Ok(StreamOwned::new(
        connection,
        DeadlineTcpStream::new(
            stream,
            previous_read_timeout,
            previous_write_timeout,
            cancellation.clone(),
        ),
    ))
}

/// Underlying rustls transport that applies one absolute request deadline to
/// every raw read and write rustls performs, including control records that a
/// single outer `StreamOwned` operation may process internally.
pub(crate) struct DeadlineTcpStream {
    stream: TcpStream,
    base_read_timeout: Option<Duration>,
    base_write_timeout: Option<Duration>,
    read_deadline: Option<Instant>,
    write_deadline: Option<Instant>,
    cancellation: CancellationToken,
}

impl DeadlineTcpStream {
    fn new(
        stream: TcpStream,
        base_read_timeout: Option<Duration>,
        base_write_timeout: Option<Duration>,
        cancellation: CancellationToken,
    ) -> Self {
        Self {
            stream,
            base_read_timeout,
            base_write_timeout,
            read_deadline: None,
            write_deadline: None,
            cancellation,
        }
    }

    pub(crate) fn set_request_deadline(&mut self, deadline: Instant) {
        self.read_deadline = Some(deadline);
        self.write_deadline = Some(deadline);
    }

    pub(crate) fn clear_request_deadline(&mut self) -> io::Result<()> {
        self.read_deadline = None;
        self.write_deadline = None;
        self.stream.set_read_timeout(self.base_read_timeout)?;
        self.stream.set_write_timeout(self.base_write_timeout)
    }

    fn wait_budget(&self, deadline: Instant) -> io::Result<Duration> {
        if self.cancellation.is_cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "local TLS request cancelled",
            ));
        }
        deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .map(|remaining| remaining.min(CANCELLATION_POLL_INTERVAL))
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "TLS request deadline elapsed"))
    }

    fn retryable(error: &io::Error) -> bool {
        matches!(
            error.kind(),
            io::ErrorKind::Interrupted | io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        )
    }
}

impl Read for DeadlineTcpStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let Some(deadline) = self.read_deadline else {
            if self.cancellation.is_cancelled() {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "local TLS request cancelled",
                ));
            }
            return self.stream.read(buffer);
        };
        loop {
            self.stream
                .set_read_timeout(Some(self.wait_budget(deadline)?))?;
            match self.stream.read(buffer) {
                Err(error) if Self::retryable(&error) => {}
                result => return result,
            }
        }
    }
}

impl Write for DeadlineTcpStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let Some(deadline) = self.write_deadline else {
            if self.cancellation.is_cancelled() {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "local TLS request cancelled",
                ));
            }
            return self.stream.write(buffer);
        };
        loop {
            self.stream
                .set_write_timeout(Some(self.wait_budget(deadline)?))?;
            match self.stream.write(buffer) {
                Err(error) if Self::retryable(&error) => {}
                result => return result,
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        let Some(deadline) = self.write_deadline else {
            if self.cancellation.is_cancelled() {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "local TLS request cancelled",
                ));
            }
            return self.stream.flush();
        };
        loop {
            self.stream
                .set_write_timeout(Some(self.wait_budget(deadline)?))?;
            match self.stream.flush() {
                Err(error) if Self::retryable(&error) => {}
                result => return result,
            }
        }
    }
}

/// Blocking adapter that converts every rustls socket operation into a slice
/// of one absolute handshake deadline. Short polling slices make cancellation
/// prompt even when cancellation is not accompanied by listener shutdown;
/// listener shutdown still interrupts the active socket operation directly.
struct HandshakeIo<'a> {
    stream: &'a mut TcpStream,
    deadline: Instant,
    cancellation: &'a CancellationToken,
}

impl HandshakeIo<'_> {
    fn wait_budget(&self) -> io::Result<Duration> {
        if self.cancellation.is_cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "local TLS handshake cancelled",
            ));
        }
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .map(|remaining| remaining.min(CANCELLATION_POLL_INTERVAL))
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "local TLS handshake timed out"))
    }

    fn interrupted(&self, error: &io::Error) -> bool {
        matches!(
            error.kind(),
            io::ErrorKind::Interrupted | io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        )
    }
}

impl Read for HandshakeIo<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            let wait = self.wait_budget()?;
            self.stream.set_read_timeout(Some(wait))?;
            match self.stream.read(buffer) {
                Err(error) if self.interrupted(&error) => {}
                result => return result,
            }
        }
    }
}

impl Write for HandshakeIo<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            let wait = self.wait_budget()?;
            self.stream.set_write_timeout(Some(wait))?;
            match self.stream.write(buffer) {
                Err(error) if self.interrupted(&error) => {}
                result => return result,
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        loop {
            let wait = self.wait_budget()?;
            self.stream.set_write_timeout(Some(wait))?;
            match self.stream.flush() {
                Err(error) if self.interrupted(&error) => {}
                result => return result,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig};
    use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener};
    use std::thread;

    const EXPECTED_HOST: &str = "tls.welcome";
    const OTHER_HOST: &str = "other.welcome";
    const TEST_TIMEOUT: Duration = Duration::from_secs(2);

    struct TestConfigs {
        server: Arc<ServerConfig>,
        certificate: CertificateDer<'static>,
    }

    type HandshakeResult = (
        Result<Option<Vec<u8>>, TlsTerminationError>,
        Result<Option<Vec<u8>>, ()>,
    );

    fn test_configs() -> TestConfigs {
        let rcgen::CertifiedKey { cert, signing_key } = rcgen::generate_simple_self_signed(vec![
            EXPECTED_HOST.to_owned(),
            OTHER_HOST.to_owned(),
        ])
        .unwrap();
        let certificate = CertificateDer::from(cert.der().to_vec());
        let private_key =
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
        let mut server =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![certificate.clone()], private_key)
                .unwrap();
        // The production identity config has the same preference: clients that
        // offer both h2 and HTTP/1.1 must negotiate HTTP/1.1, while h2-only
        // clients receive a TLS no_application_protocol alert.
        server.alpn_protocols = vec![HTTP_1_1_ALPN.to_vec()];
        TestConfigs {
            server: Arc::new(server),
            certificate,
        }
    }

    fn client_config(
        certificate: CertificateDer<'static>,
        alpn_protocols: &[&[u8]],
        enable_sni: bool,
    ) -> Arc<ClientConfig> {
        let mut roots = RootCertStore::empty();
        roots.add(certificate).unwrap();
        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
        config.alpn_protocols = alpn_protocols.iter().map(|value| value.to_vec()).collect();
        config.enable_sni = enable_sni;
        Arc::new(config)
    }

    fn socket_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        client.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
        client.set_write_timeout(Some(TEST_TIMEOUT)).unwrap();
        (server, client)
    }

    fn complete_client_handshake(
        mut stream: TcpStream,
        config: Arc<ClientConfig>,
        server_name: &str,
    ) -> Result<Option<Vec<u8>>, ()> {
        let server_name = ServerName::try_from(server_name.to_owned()).map_err(|_error| ())?;
        let mut connection = ClientConnection::new(config, server_name).map_err(|_error| ())?;
        while connection.is_handshaking() {
            connection.complete_io(&mut stream).map_err(|_error| ())?;
        }
        Ok(connection.alpn_protocol().map(<[u8]>::to_vec))
    }

    fn run_handshake(
        configs: &TestConfigs,
        client: Arc<ClientConfig>,
        client_name: &str,
    ) -> HandshakeResult {
        let (server_stream, client_stream) = socket_pair();
        let server_config = Arc::clone(&configs.server);
        let expected_host = NormalizedHost::parse(EXPECTED_HOST).unwrap();
        let cancellation = CancellationToken::new();
        let server = thread::spawn(move || {
            accept_local_tls_with_config(
                server_stream,
                server_config,
                &expected_host,
                TEST_TIMEOUT,
                &cancellation,
            )
            .map(|stream| stream.conn.alpn_protocol().map(<[u8]>::to_vec))
        });
        let client = complete_client_handshake(client_stream, client, client_name);
        (server.join().unwrap(), client)
    }

    #[test]
    fn accepts_exact_normalized_sni_without_alpn() {
        let configs = test_configs();
        let client = client_config(configs.certificate.clone(), &[], true);

        let (server, client) = run_handshake(&configs, client, EXPECTED_HOST);

        assert_eq!(server, Ok(None));
        assert_eq!(client, Ok(None));
    }

    #[test]
    fn rejects_wrong_and_missing_sni_after_the_tls_handshake() {
        let configs = test_configs();
        let wrong_client = client_config(configs.certificate.clone(), &[], true);
        let (wrong_server, wrong_client) = run_handshake(&configs, wrong_client, OTHER_HOST);
        assert_eq!(wrong_client, Ok(None));
        assert_eq!(wrong_server, Err(TlsTerminationError::ServerNameRejected));

        let missing_client = client_config(configs.certificate.clone(), &[], false);
        let (missing_server, missing_client) =
            run_handshake(&configs, missing_client, EXPECTED_HOST);
        assert_eq!(missing_client, Ok(None));
        assert_eq!(missing_server, Err(TlsTerminationError::ServerNameRejected));
    }

    #[test]
    fn prefers_http1_when_the_client_also_offers_h2() {
        let configs = test_configs();
        let client = client_config(configs.certificate.clone(), &[b"h2", HTTP_1_1_ALPN], true);

        let (server, client) = run_handshake(&configs, client, EXPECTED_HOST);

        assert_eq!(server, Ok(Some(HTTP_1_1_ALPN.to_vec())));
        assert_eq!(client, Ok(Some(HTTP_1_1_ALPN.to_vec())));
    }

    #[test]
    fn rejects_h2_only_during_tls_negotiation() {
        let configs = test_configs();
        let client = client_config(configs.certificate.clone(), &[b"h2"], true);

        let (server, client) = run_handshake(&configs, client, EXPECTED_HOST);

        assert_eq!(server, Err(TlsTerminationError::HandshakeFailed));
        assert!(client.is_err());
    }

    #[test]
    fn cancellation_interrupts_a_stalled_handshake_promptly() {
        let configs = test_configs();
        let (server_stream, client_stream) = socket_pair();
        let control = server_stream.try_clone().unwrap();
        let expected_host = NormalizedHost::parse(EXPECTED_HOST).unwrap();
        let server_config = Arc::clone(&configs.server);
        let cancellation = CancellationToken::new();
        let task_cancellation = cancellation.clone();
        let started = Instant::now();
        let server = thread::spawn(move || {
            accept_local_tls_with_config(
                server_stream,
                server_config,
                &expected_host,
                TEST_TIMEOUT,
                &task_cancellation,
            )
        });
        thread::sleep(Duration::from_millis(30));
        cancellation.cancel();
        control.shutdown(Shutdown::Both).unwrap();

        assert!(matches!(
            server.join().unwrap(),
            Err(TlsTerminationError::Cancelled)
        ));
        assert!(started.elapsed() < Duration::from_millis(500));
        drop(client_stream);
    }

    #[test]
    fn partial_client_hello_obeys_one_absolute_deadline() {
        let configs = test_configs();
        let (server_stream, mut client_stream) = socket_pair();
        let expected_host = NormalizedHost::parse(EXPECTED_HOST).unwrap();
        let server_config = Arc::clone(&configs.server);
        let cancellation = CancellationToken::new();
        let timeout = Duration::from_millis(90);
        let started = Instant::now();
        let server = thread::spawn(move || {
            accept_local_tls_with_config(
                server_stream,
                server_config,
                &expected_host,
                timeout,
                &cancellation,
            )
        });
        client_stream
            .write_all(b"\x16\x03\x03\x00\x40\x01\x00\x00")
            .unwrap();

        assert!(matches!(
            server.join().unwrap(),
            Err(TlsTerminationError::TimedOut)
        ));
        let elapsed = started.elapsed();
        assert!(elapsed >= timeout);
        assert!(elapsed < Duration::from_millis(500));
    }

    #[test]
    fn post_handshake_control_records_cannot_extend_the_request_deadline() {
        let configs = test_configs();
        let client_config = client_config(configs.certificate.clone(), &[HTTP_1_1_ALPN], true);
        let (server_stream, client_stream) = socket_pair();
        let expected_host = NormalizedHost::parse(EXPECTED_HOST).unwrap();
        let server_config = Arc::clone(&configs.server);
        let cancellation = CancellationToken::new();
        let server = thread::spawn(move || {
            accept_local_tls_with_config(
                server_stream,
                server_config,
                &expected_host,
                TEST_TIMEOUT,
                &cancellation,
            )
        });

        let server_name = ServerName::try_from(EXPECTED_HOST.to_owned()).unwrap();
        let connection = ClientConnection::new(client_config, server_name).unwrap();
        let mut client = StreamOwned::new(connection, client_stream);
        while client.conn.is_handshaking() {
            client.conn.complete_io(&mut client.sock).unwrap();
        }
        assert_eq!(
            client.conn.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        let mut server = server.join().unwrap().unwrap();
        let timeout = Duration::from_millis(100);
        server.sock.set_request_deadline(Instant::now() + timeout);

        let control_sender = thread::spawn(move || {
            for _ in 0..4 {
                thread::sleep(Duration::from_millis(20));
                client.conn.refresh_traffic_keys().unwrap();
                while client.conn.wants_write() {
                    client.conn.write_tls(&mut client.sock).unwrap();
                }
            }
            thread::sleep(Duration::from_millis(150));
        });
        let started = Instant::now();
        let error = server.read(&mut [0_u8; 1]).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() >= timeout);
        assert!(started.elapsed() < Duration::from_millis(200));
        control_sender.join().unwrap();
    }
}
