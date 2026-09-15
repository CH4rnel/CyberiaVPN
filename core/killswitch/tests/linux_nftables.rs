#![cfg(target_os = "linux")]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU16;

use cyberia_killswitch::TrafficPolicy;
use cyberia_killswitch::linux::NftablesConfig;

fn config(address: IpAddr) -> NftablesConfig {
    NftablesConfig {
        endpoint_address: address,
        endpoint_port: NonZeroU16::new(51820).unwrap(),
    }
}

#[test]
fn blocking_policy_allows_only_loopback_existing_flows_and_peer() {
    let rules = config(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)))
        .render(&TrafficPolicy::BlockNonTunnel)
        .unwrap();

    assert!(rules.contains("policy drop"));
    assert!(rules.contains("oifname \"lo\" accept"));
    assert!(rules.contains("ct state established,related accept"));
    assert!(rules.contains("ip daddr 198.51.100.7 udp dport 51820 accept"));
    assert!(!rules.contains("oifname \"wg0\""));
}

#[test]
fn tunnel_policy_allows_the_validated_tunnel_interface() {
    let rules = config(IpAddr::V6(Ipv6Addr::LOCALHOST))
        .render(&TrafficPolicy::TunnelOnly {
            interface: "wg0".into(),
        })
        .unwrap();

    assert!(rules.contains("ip6 daddr ::1 udp dport 51820 accept"));
    assert!(rules.contains("oifname \"wg0\" accept"));
}

#[test]
fn disabled_policy_leaves_the_owned_table_empty() {
    assert_eq!(
        config(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .render(&TrafficPolicy::Disabled)
            .unwrap(),
        "add table inet cyberia_vpn\nflush table inet cyberia_vpn\n"
    );
}

#[test]
fn rejects_an_unvalidated_interface_before_rendering() {
    assert!(
        config(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .render(&TrafficPolicy::TunnelOnly {
                interface: "wg0\"; flush ruleset".into(),
            })
            .is_err()
    );
}
