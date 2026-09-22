#![cfg(target_os = "linux")]

use std::net::IpAddr;
use std::path::PathBuf;

use cyberia_linux_client::{ClientConfig, ClientTools, ConfigError};

fn config() -> ClientConfig {
    ClientConfig {
        interface: "wg0".into(),
        runtime_directory: PathBuf::from("/run/cyberia"),
        endpoint_address: "198.51.100.7".parse().unwrap(),
        endpoint_port: 51820,
        peer_public_key_hex: "01".repeat(32),
        tunnel_addresses: vec!["10.20.0.2/24".into(), "fd00:20::2/64".into()],
        allowed_ips: vec!["0.0.0.0/0".into(), "::/0".into()],
        dns_resolvers: vec!["192.0.2.53".parse().unwrap()],
        mtu: 1420,
        persistent_keepalive_seconds: Some(25),
        routing_mark: 51820,
        connect_timeout_seconds: 10,
        always_on: true,
        tools: ClientTools {
            ip: PathBuf::from("/usr/sbin/ip"),
            wg: PathBuf::from("/usr/bin/wg"),
            nft: PathBuf::from("/usr/sbin/nft"),
            resolvectl: PathBuf::from("/usr/bin/resolvectl"),
            private_key: PathBuf::from("/run/cyberia/key"),
        },
    }
}

#[test]
fn maps_runtime_configuration_to_managed_connection_settings() {
    let settings = config().into_connection_settings().unwrap();
    assert_eq!(settings.interface, "wg0");
    assert_eq!(settings.profile.peer_public_key, [1; 32]);
    assert_eq!(settings.profile.endpoint.host, "198.51.100.7");
    assert_eq!(
        settings.profile.tunnel_addresses[1].address,
        "fd00:20::2".parse::<IpAddr>().unwrap()
    );
    assert_eq!(settings.profile.allowed_ips[0].prefix_length, 0);
    assert_eq!(
        settings.dns.resolvers,
        ["192.0.2.53".parse::<IpAddr>().unwrap()]
    );
    assert!(settings.always_on);
}

#[test]
fn rejects_malformed_keys_cidrs_and_zero_kernel_values() {
    let mut malformed_key = config();
    malformed_key.peer_public_key_hex = "not-a-key".into();
    assert!(matches!(
        malformed_key.into_connection_settings(),
        Err(ConfigError::InvalidField(_))
    ));

    let mut malformed_cidr = config();
    malformed_cidr.allowed_ips = vec!["10.0.0.0/33".into()];
    assert!(matches!(
        malformed_cidr.into_connection_settings(),
        Err(ConfigError::InvalidField(_))
    ));

    let mut zero_mark = config();
    zero_mark.routing_mark = 0;
    assert!(matches!(
        zero_mark.into_connection_settings(),
        Err(ConfigError::InvalidField(_))
    ));
}
