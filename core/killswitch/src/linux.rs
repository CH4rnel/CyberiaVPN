//! Linux nftables policy rendering for the kill switch.

use std::net::IpAddr;
use std::num::NonZeroU16;
use std::{error::Error, fmt};

use crate::TrafficPolicy;

const TABLE_NAME: &str = "cyberia_vpn";

/// Network values that must remain reachable while non-tunnel traffic is
/// blocked. The endpoint is restricted to an IP address so nftables never
/// performs name resolution while applying the policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NftablesConfig {
    pub endpoint_address: IpAddr,
    pub endpoint_port: NonZeroU16,
}

impl NftablesConfig {
    /// Renders a complete ruleset for the private Cyberia VPN table.
    ///
    /// Applying the returned input through `nft --file -` updates the table in
    /// one nftables transaction. The rules never flush tables owned by other
    /// applications.
    ///
    /// # Errors
    ///
    /// Returns [`NftablesError::InvalidInterface`] when a caller supplies a
    /// tunnel policy that was not produced by the validated state machine.
    pub fn render(&self, policy: &TrafficPolicy) -> Result<String, NftablesError> {
        let mut rules = format!("add table inet {TABLE_NAME}\nflush table inet {TABLE_NAME}\n");
        if policy == &TrafficPolicy::Disabled {
            return Ok(rules);
        }

        rules.push_str(&format!(
            "add chain inet {TABLE_NAME} output {{ type filter hook output priority -100; policy drop; }}\n"
        ));
        rules.push_str(&format!(
            "add rule inet {TABLE_NAME} output oifname \"lo\" accept\n"
        ));
        rules.push_str(&format!(
            "add rule inet {TABLE_NAME} output ct state established,related accept\n"
        ));
        let address_family = if self.endpoint_address.is_ipv4() {
            "ip"
        } else {
            "ip6"
        };
        rules.push_str(&format!(
            "add rule inet {TABLE_NAME} output {address_family} daddr {} udp dport {} accept\n",
            self.endpoint_address, self.endpoint_port
        ));
        if let TrafficPolicy::TunnelOnly { interface } = policy {
            if !valid_interface(interface) {
                return Err(NftablesError::InvalidInterface);
            }
            rules.push_str(&format!(
                "add rule inet {TABLE_NAME} output oifname \"{interface}\" accept\n"
            ));
        }
        Ok(rules)
    }
}

fn valid_interface(interface: &str) -> bool {
    !interface.is_empty()
        && interface.len() <= 63
        && interface.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'.'
        })
}

/// A policy cannot be represented safely as nftables input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NftablesError {
    InvalidInterface,
}

impl fmt::Display for NftablesError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid nftables tunnel interface")
    }
}

impl Error for NftablesError {}
