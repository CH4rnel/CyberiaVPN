//! Transport lifecycle contracts for the Cyberia VPN network core.

#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt::{Display, Formatter};
use std::num::NonZeroU16;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// A protocol implemented by a transport adapter.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TransportKind {
    WireGuard,
    Vless,
    Hysteria2,
    Tuic,
    Trojan,
    Shadowsocks,
    Ikev2,
    OpenVpn,
    SoftEther,
    Socks5,
    HttpProxy,
}

/// Public connection parameters. Credentials are deliberately supplied by a
/// separate secret provider owned by each adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportConfig {
    pub kind: TransportKind,
    pub endpoint: Endpoint,
    pub connect_timeout: Duration,
}

impl TransportConfig {
    /// Validates bounded work and endpoint constraints at the trust boundary.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::InvalidConfig`] when the endpoint is blank or
    /// the timeout would allow no connection work.
    pub fn validate(&self) -> Result<(), TransportError> {
        if self.endpoint.host.trim().is_empty() {
            return Err(TransportError::InvalidConfig("endpoint host is empty"));
        }
        if self.connect_timeout.is_zero() {
            return Err(TransportError::InvalidConfig("connect timeout is zero"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Endpoint {
    pub host: String,
    pub port: NonZeroU16,
}

/// Cooperative cancellation shared with a transport adapter.
#[derive(Clone, Debug, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Bounds a connection attempt by both cancellation and a deadline.
#[derive(Clone, Debug)]
pub struct ConnectContext {
    pub deadline: Instant,
    pub cancellation: CancellationToken,
}

impl ConnectContext {
    /// Checks whether a connection attempt may continue.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Cancelled`] or [`TransportError::TimedOut`]
    /// when the corresponding bound has been reached.
    pub fn check(&self) -> Result<(), TransportError> {
        if self.cancellation.is_cancelled() {
            return Err(TransportError::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(TransportError::TimedOut);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Session {
    pub id: String,
    pub transport: TransportKind,
    pub established_at: Instant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportHealth {
    pub status: HealthStatus,
    pub round_trip_time: Option<Duration>,
    pub consecutive_failures: u32,
}

/// Common lifecycle implemented by every protocol adapter.
pub trait Transport: Send {
    fn kind(&self) -> TransportKind;

    /// Establishes one session within the supplied execution bounds.
    ///
    /// # Errors
    ///
    /// Returns a typed lifecycle, configuration, authentication or network
    /// error. Implementations must not retry beyond the context deadline.
    fn connect(
        &mut self,
        config: &TransportConfig,
        context: &ConnectContext,
    ) -> Result<Session, TransportError>;

    /// Tears down the active session.
    ///
    /// # Errors
    ///
    /// Returns a typed lifecycle or network error when teardown is incomplete.
    fn disconnect(&mut self) -> Result<(), TransportError>;

    fn health(&self) -> TransportHealth;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportError {
    InvalidConfig(&'static str),
    Cancelled,
    TimedOut,
    AlreadyConnected,
    NotConnected,
    AuthenticationFailed,
    Network(String),
}

impl Display for TransportError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(reason) => write!(formatter, "invalid configuration: {reason}"),
            Self::Cancelled => formatter.write_str("connection attempt cancelled"),
            Self::TimedOut => formatter.write_str("connection attempt timed out"),
            Self::AlreadyConnected => formatter.write_str("transport is already connected"),
            Self::NotConnected => formatter.write_str("transport is not connected"),
            Self::AuthenticationFailed => formatter.write_str("transport authentication failed"),
            Self::Network(reason) => write!(formatter, "transport network error: {reason}"),
        }
    }
}

impl Error for TransportError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(host: &str) -> Endpoint {
        Endpoint {
            host: host.to_owned(),
            port: NonZeroU16::new(51820).expect("test port is non-zero"),
        }
    }

    #[test]
    fn rejects_an_empty_endpoint() {
        let config = TransportConfig {
            kind: TransportKind::WireGuard,
            endpoint: endpoint("  "),
            connect_timeout: Duration::from_secs(5),
        };

        assert_eq!(
            config.validate(),
            Err(TransportError::InvalidConfig("endpoint host is empty"))
        );
    }

    #[test]
    fn cancellation_is_visible_to_connection_attempt() {
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let context = ConnectContext {
            deadline: Instant::now() + Duration::from_secs(5),
            cancellation,
        };

        assert_eq!(context.check(), Err(TransportError::Cancelled));
    }

    #[test]
    fn expired_deadline_is_rejected() {
        let context = ConnectContext {
            deadline: Instant::now(),
            cancellation: CancellationToken::default(),
        };

        assert_eq!(context.check(), Err(TransportError::TimedOut));
    }
}
