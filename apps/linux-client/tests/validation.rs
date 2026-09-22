#![cfg(target_os = "linux")]

use std::fs;
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use cyberia_linux_client::{
    ClientConfig, ClientTools, ClientValidationError, validate_client_configuration,
};

fn executable(directory: &Path, name: &str) -> PathBuf {
    let path = directory.join(name);
    fs::write(&path, "").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

fn config(name: &str) -> (ClientConfig, PathBuf) {
    let directory = std::env::temp_dir().join(format!(
        "cyberia-client-validation-{name}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let key = directory.join("key");
    fs::write(&key, "private").unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    (
        ClientConfig {
            interface: "wg0".into(),
            runtime_directory: directory.clone(),
            endpoint_address: "198.51.100.7".parse().unwrap(),
            endpoint_port: 51820,
            peer_public_key_hex: "01".repeat(32),
            tunnel_addresses: vec!["10.20.0.2/24".into()],
            allowed_ips: vec!["0.0.0.0/0".into()],
            dns_resolvers: vec!["192.0.2.53".parse::<IpAddr>().unwrap()],
            mtu: 1420,
            persistent_keepalive_seconds: Some(25),
            routing_mark: 51820,
            connect_timeout_seconds: 10,
            always_on: false,
            tools: ClientTools {
                ip: executable(&directory, "ip"),
                wg: executable(&directory, "wg"),
                nft: executable(&directory, "nft"),
                resolvectl: executable(&directory, "resolvectl"),
                private_key: key,
            },
        },
        directory,
    )
}

#[test]
fn validates_client_inputs_without_network_mutation() {
    let (config, directory) = config("valid");
    assert!(validate_client_configuration(&config).is_ok());
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn rejects_untrusted_platform_executables() {
    let (mut config, directory) = config("nft");
    fs::set_permissions(&config.tools.nft, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        validate_client_configuration(&config),
        Err(ClientValidationError::Nftables(_))
    ));
    config.tools.nft = PathBuf::from("relative-nft");
    assert!(matches!(
        validate_client_configuration(&config),
        Err(ClientValidationError::Nftables(_))
    ));
    fs::remove_dir_all(directory).unwrap();
}
