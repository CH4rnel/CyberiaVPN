use cyberia_transport::{AllowedIp, WireGuardNodeGatewayPolicy};

fn network(address: &str, prefix_length: u8) -> AllowedIp {
    AllowedIp {
        network: address.parse().unwrap(),
        prefix_length,
    }
}

#[test]
fn accepts_bounded_dual_stack_client_networks() {
    let policy = WireGuardNodeGatewayPolicy {
        client_networks: vec![network("10.20.0.0", 24), network("fd00:20::", 64)],
    };

    assert_eq!(policy.validate(), Ok(()));
}

#[test]
fn rejects_default_host_and_non_canonical_networks() {
    for client_network in [
        network("0.0.0.0", 0),
        network("10.20.0.2", 32),
        network("10.20.0.1", 24),
        network("::", 0),
        network("fd00:20::1", 64),
        network("fd00:20::1", 128),
    ] {
        let policy = WireGuardNodeGatewayPolicy {
            client_networks: vec![client_network],
        };
        assert!(policy.validate().is_err());
    }
}

#[test]
fn rejects_duplicate_and_overlapping_networks() {
    for networks in [
        vec![network("10.20.0.0", 24), network("10.20.0.0", 24)],
        vec![network("10.20.0.0", 24), network("10.20.0.0", 25)],
        vec![network("fd00:20::", 64), network("fd00:20::", 80)],
    ] {
        let policy = WireGuardNodeGatewayPolicy {
            client_networks: networks,
        };
        assert!(policy.validate().is_err());
    }
}
