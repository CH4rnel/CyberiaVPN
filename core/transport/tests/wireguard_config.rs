use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU16;

use cyberia_transport::{AllowedIp, Endpoint, TransportError, TunnelAddress, WireGuardConfig};

fn valid_config() -> WireGuardConfig {
    WireGuardConfig {
        peer_public_key: [7; 32],
        endpoint: Endpoint {
            host: "192.0.2.10".to_owned(),
            port: NonZeroU16::new(51820).unwrap(),
        },
        tunnel_addresses: vec![TunnelAddress {
            address: IpAddr::V4(Ipv4Addr::new(10, 42, 0, 2)),
            prefix_length: 32,
        }],
        allowed_ips: vec![AllowedIp {
            network: "0.0.0.0".parse().unwrap(),
            prefix_length: 0,
        }],
        persistent_keepalive_seconds: Some(25),
        mtu: 1_420,
    }
}

#[test]
fn accepts_public_wireguard_profile() {
    assert_eq!(valid_config().validate(), Ok(()));
}

#[test]
fn rejects_zero_peer_public_key() {
    let mut config = valid_config();
    config.peer_public_key = [0; 32];

    assert_eq!(
        config.validate(),
        Err(TransportError::InvalidConfig(
            "WireGuard peer public key is zero"
        ))
    );
}

#[test]
fn rejects_prefix_that_does_not_match_address_family() {
    let mut config = valid_config();
    config.tunnel_addresses = vec![TunnelAddress {
        address: IpAddr::V6(Ipv6Addr::LOCALHOST),
        prefix_length: 129,
    }];

    assert_eq!(
        config.validate(),
        Err(TransportError::InvalidConfig(
            "invalid tunnel address prefix"
        ))
    );
}

#[test]
fn rejects_unsafe_tunnel_mtu() {
    let mut config = valid_config();
    config.mtu = 9_001;

    assert_eq!(
        config.validate(),
        Err(TransportError::InvalidConfig(
            "WireGuard MTU is outside safe bounds"
        ))
    );
}

#[test]
fn rejects_same_tunnel_ip_with_different_prefixes() {
    let mut config = valid_config();
    let mut duplicate = config.tunnel_addresses[0];
    duplicate.prefix_length = 24;
    config.tunnel_addresses.push(duplicate);
    assert_eq!(
        config.validate(),
        Err(TransportError::InvalidConfig(
            "duplicate WireGuard tunnel address"
        ))
    );
}

#[test]
fn accepts_distinct_dual_stack_tunnel_addresses() {
    let mut config = valid_config();
    config.tunnel_addresses.push(TunnelAddress {
        address: "fd00::2".parse().unwrap(),
        prefix_length: 128,
    });
    assert_eq!(config.validate(), Ok(()));
}

#[test]
fn rejects_missing_non_network_and_duplicate_allowed_ips() {
    let mut missing = valid_config();
    missing.allowed_ips.clear();
    assert!(missing.validate().is_err());

    let mut host_bits = valid_config();
    host_bits.allowed_ips[0] = AllowedIp {
        network: "10.0.0.1".parse().unwrap(),
        prefix_length: 24,
    };
    assert!(host_bits.validate().is_err());

    let mut duplicate = valid_config();
    duplicate.allowed_ips.push(duplicate.allowed_ips[0]);
    assert!(duplicate.validate().is_err());
}

#[test]
fn accepts_dual_stack_default_allowed_ips() {
    let mut config = valid_config();
    config.allowed_ips.push(AllowedIp {
        network: "::".parse().unwrap(),
        prefix_length: 0,
    });
    assert_eq!(config.validate(), Ok(()));
}
