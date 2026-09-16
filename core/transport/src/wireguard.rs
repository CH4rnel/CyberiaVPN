use std::collections::HashSet;
use std::net::IpAddr;

use crate::{
    ConnectContext, Endpoint, HealthStatus, Session, Transport, TransportConfig, TransportError,
    TransportHealth, TransportKind,
};

const MINIMUM_MTU: u16 = 1_280;
const MAXIMUM_MTU: u16 = 9_000;
const MAXIMUM_KEEPALIVE_SECONDS: u16 = 300;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TunnelAddress {
    pub address: IpAddr,
    pub prefix_length: u8,
}

/// One network prefix accepted from the configured `WireGuard` peer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AllowedIp {
    pub network: IpAddr,
    pub prefix_length: u8,
}

/// Public parameters for a `WireGuard` peer. The device private key is
/// intentionally absent and must be obtained by the adapter from its local
/// platform key store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireGuardConfig {
    pub peer_public_key: [u8; 32],
    pub endpoint: Endpoint,
    pub tunnel_addresses: Vec<TunnelAddress>,
    pub allowed_ips: Vec<AllowedIp>,
    pub persistent_keepalive_seconds: Option<u16>,
    pub mtu: u16,
}

impl WireGuardConfig {
    /// Validates public peer and interface parameters before adapter use.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::InvalidConfig`] for an unusable key,
    /// endpoint, address, keepalive interval or MTU.
    pub fn validate(&self) -> Result<(), TransportError> {
        if self.peer_public_key.iter().all(|byte| *byte == 0) {
            return Err(TransportError::InvalidConfig(
                "WireGuard peer public key is zero",
            ));
        }
        if self.endpoint.host.trim().is_empty() {
            return Err(TransportError::InvalidConfig("endpoint host is empty"));
        }
        if self.tunnel_addresses.is_empty() {
            return Err(TransportError::InvalidConfig(
                "WireGuard tunnel address list is empty",
            ));
        }
        let mut unique_addresses = HashSet::with_capacity(self.tunnel_addresses.len());
        for tunnel_address in &self.tunnel_addresses {
            let maximum_prefix = if tunnel_address.address.is_ipv4() {
                32
            } else {
                128
            };
            if tunnel_address.prefix_length > maximum_prefix
                || tunnel_address.address.is_unspecified()
                || tunnel_address.address.is_multicast()
            {
                return Err(TransportError::InvalidConfig(
                    "invalid tunnel address prefix",
                ));
            }
            if !unique_addresses.insert(tunnel_address.address) {
                return Err(TransportError::InvalidConfig(
                    "duplicate WireGuard tunnel address",
                ));
            }
        }
        if self.allowed_ips.is_empty() || self.allowed_ips.len() > 64 {
            return Err(TransportError::InvalidConfig(
                "WireGuard allowed IP list must contain between 1 and 64 prefixes",
            ));
        }
        let mut allowed_ips = HashSet::with_capacity(self.allowed_ips.len());
        for allowed_ip in &self.allowed_ips {
            if !valid_network(*allowed_ip) || !allowed_ips.insert(*allowed_ip) {
                return Err(TransportError::InvalidConfig(
                    "invalid or duplicate WireGuard allowed IP prefix",
                ));
            }
        }
        if self
            .persistent_keepalive_seconds
            .is_some_and(|seconds| seconds == 0 || seconds > MAXIMUM_KEEPALIVE_SECONDS)
        {
            return Err(TransportError::InvalidConfig(
                "WireGuard keepalive is outside safe bounds",
            ));
        }
        if !(MINIMUM_MTU..=MAXIMUM_MTU).contains(&self.mtu) {
            return Err(TransportError::InvalidConfig(
                "WireGuard MTU is outside safe bounds",
            ));
        }
        Ok(())
    }
}

fn valid_network(allowed_ip: AllowedIp) -> bool {
    match allowed_ip.network {
        IpAddr::V4(address) => {
            if allowed_ip.prefix_length > 32 || address.is_multicast() {
                return false;
            }
            let bits = u32::from(address);
            let mask = if allowed_ip.prefix_length == 0 {
                0
            } else {
                u32::MAX << (32 - allowed_ip.prefix_length)
            };
            bits & mask == bits
        }
        IpAddr::V6(address) => {
            if allowed_ip.prefix_length > 128 || address.is_multicast() {
                return false;
            }
            let bits = u128::from(address);
            let mask = if allowed_ip.prefix_length == 0 {
                0
            } else {
                u128::MAX << (128 - allowed_ip.prefix_length)
            };
            bits & mask == bits
        }
    }
}

/// Narrow platform boundary for creating and removing one `WireGuard` interface.
/// Implementations must check `context` before starting work and must leave no
/// interface behind when `bring_up` returns an error.
pub trait WireGuardBackend: Send {
    ///
    /// # Errors
    ///
    /// Returns a bounded transport error when the platform cannot create the
    /// interface or apply its profile.
    fn bring_up(
        &mut self,
        interface: &str,
        profile: &WireGuardConfig,
        context: &ConnectContext,
    ) -> Result<(), TransportError>;

    ///
    /// # Errors
    ///
    /// Returns a transport error when the platform cannot remove the interface.
    fn bring_down(&mut self, interface: &str) -> Result<(), TransportError>;

    fn health(&mut self) -> TransportHealth;
}

/// A lifecycle adapter over a platform-specific `WireGuard` backend. It does not
/// hold private keys; the backend obtains them from its platform key store.
pub struct WireGuardAdapter<B> {
    interface: String,
    profile: WireGuardConfig,
    backend: B,
    connected: bool,
}

impl<B: WireGuardBackend> WireGuardAdapter<B> {
    /// Creates an adapter with a validated interface name and public profile.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::InvalidConfig`] for unsafe interface names or
    /// invalid public peer parameters.
    pub fn new(
        interface: String,
        profile: WireGuardConfig,
        backend: B,
    ) -> Result<Self, TransportError> {
        if !valid_interface(&interface) {
            return Err(TransportError::InvalidConfig(
                "invalid WireGuard interface name",
            ));
        }
        profile.validate()?;
        Ok(Self {
            interface,
            profile,
            backend,
            connected: false,
        })
    }
}

impl<B: WireGuardBackend> Transport for WireGuardAdapter<B> {
    fn kind(&self) -> TransportKind {
        TransportKind::WireGuard
    }

    fn connect(
        &mut self,
        config: &TransportConfig,
        context: &ConnectContext,
    ) -> Result<Session, TransportError> {
        if self.connected {
            return Err(TransportError::AlreadyConnected);
        }
        if config.kind != TransportKind::WireGuard || config.endpoint != self.profile.endpoint {
            return Err(TransportError::InvalidConfig(
                "WireGuard transport parameters do not match profile",
            ));
        }
        config.validate()?;
        context.check()?;
        self.backend
            .bring_up(&self.interface, &self.profile, context)?;
        self.connected = true;
        Ok(Session {
            id: self.interface.clone(),
            transport: TransportKind::WireGuard,
            established_at: std::time::Instant::now(),
        })
    }

    fn disconnect(&mut self) -> Result<(), TransportError> {
        if !self.connected {
            return Err(TransportError::NotConnected);
        }
        self.backend.bring_down(&self.interface)?;
        self.connected = false;
        Ok(())
    }

    fn health(&mut self) -> TransportHealth {
        if !self.connected {
            return TransportHealth {
                status: HealthStatus::Unavailable,
                round_trip_time: None,
                consecutive_failures: 0,
            };
        }
        self.backend.health()
    }
}

fn valid_interface(interface: &str) -> bool {
    !interface.is_empty()
        && interface.len() <= 15
        && interface
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}
