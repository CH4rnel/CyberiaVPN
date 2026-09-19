use std::num::NonZeroU16;

use cyberia_transport::{
    AllowedIp, TransportError, TunnelAddress, WireGuardNodeConfig, WireGuardNodePeer,
};

fn node() -> WireGuardNodeConfig {
    WireGuardNodeConfig {
        listen_port: NonZeroU16::new(51820).unwrap(),
        interface_addresses: vec![TunnelAddress {
            address: "10.0.0.1".parse().unwrap(),
            prefix_length: 24,
        }],
        mtu: 1420,
    }
}

fn peer() -> WireGuardNodePeer {
    WireGuardNodePeer {
        public_key: [7; 32],
        allowed_ips: vec![AllowedIp {
            network: "10.0.0.2".parse().unwrap(),
            prefix_length: 32,
        }],
        persistent_keepalive_seconds: None,
    }
}

#[test]
fn accepts_bounded_node_and_client_peer_profiles() {
    assert_eq!(node().validate(), Ok(()));
    assert_eq!(peer().validate(), Ok(()));
}

#[test]
fn rejects_node_without_interface_addresses_or_safe_mtu() {
    let mut missing = node();
    missing.interface_addresses.clear();
    assert!(missing.validate().is_err());

    let mut mtu = node();
    mtu.mtu = 9001;
    assert!(mtu.validate().is_err());
}

#[test]
fn rejects_zero_peer_key_and_non_host_routes() {
    let mut zero = peer();
    zero.public_key = [0; 32];
    assert_eq!(
        zero.validate(),
        Err(TransportError::InvalidConfig(
            "WireGuard node peer public key is zero"
        ))
    );

    for route in [
        AllowedIp {
            network: "0.0.0.0".parse().unwrap(),
            prefix_length: 0,
        },
        AllowedIp {
            network: "10.0.0.0".parse().unwrap(),
            prefix_length: 24,
        },
    ] {
        let mut broad = peer();
        broad.allowed_ips = vec![route];
        assert!(broad.validate().is_err());
    }
}

#[test]
fn rejects_duplicate_peer_host_routes_and_unsafe_keepalive() {
    let mut duplicate = peer();
    duplicate.allowed_ips.push(duplicate.allowed_ips[0]);
    assert!(duplicate.validate().is_err());

    let mut keepalive = peer();
    keepalive.persistent_keepalive_seconds = Some(301);
    assert!(keepalive.validate().is_err());
}
