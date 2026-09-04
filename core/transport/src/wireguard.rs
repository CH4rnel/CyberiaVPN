use std::collections::HashSet;
use std::net::IpAddr;

use crate::{Endpoint, TransportError};

const MINIMUM_MTU: u16 = 1_280;
const MAXIMUM_MTU: u16 = 9_000;
const MAXIMUM_KEEPALIVE_SECONDS: u16 = 300;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TunnelAddress {
    pub address: IpAddr,
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
            if !unique_addresses.insert(*tunnel_address) {
                return Err(TransportError::InvalidConfig(
                    "duplicate WireGuard tunnel address",
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
