#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};

use cyberia_linux_client::{ConfigError, load_config};

fn config_json(extra: &str) -> String {
    format!(
        r#"{{
        "interface":"wg0","endpoint_address":"198.51.100.7","endpoint_port":51820,
        "peer_public_key_hex":"0101010101010101010101010101010101010101010101010101010101010101",
        "tunnel_addresses":["10.20.0.2/24"],"allowed_ips":["0.0.0.0/0"],
        "dns_resolvers":["192.0.2.53"],"mtu":1420,"persistent_keepalive_seconds":25,
        "routing_mark":51820,"connect_timeout_seconds":10,"always_on":false,
        "tools":{{"ip":"/usr/sbin/ip","wg":"/usr/bin/wg","nft":"/usr/sbin/nft","resolvectl":"/usr/bin/resolvectl","private_key":"/run/cyberia/key"}}
        {extra}
    }}"#
    )
}

fn private_file(name: &str, contents: &str) -> std::path::PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "cyberia-client-config-{name}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir(&directory).unwrap();
    let path = directory.join("client.json");
    fs::write(&path, contents).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    path
}

#[test]
fn loads_a_private_bounded_configuration() {
    let path = private_file("valid", &config_json(""));
    let config = load_config(&path).unwrap();
    assert_eq!(config.interface, "wg0");
    assert_eq!(config.endpoint_port, 51820);
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn rejects_broad_permissions_and_symbolic_links() {
    let path = private_file("metadata", &config_json(""));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    assert!(matches!(load_config(&path), Err(ConfigError::UnsafeFile)));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let link = path.parent().unwrap().join("link.json");
    symlink(&path, &link).unwrap();
    assert!(matches!(load_config(&link), Err(ConfigError::UnsafeFile)));
    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn rejects_unknown_fields_and_trailing_documents() {
    for (name, contents) in [
        ("unknown", config_json(",\"unexpected\":true")),
        ("trailing", format!("{} {{}}", config_json(""))),
    ] {
        let path = private_file(name, &contents);
        assert!(matches!(load_config(&path), Err(ConfigError::Json(_))));
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}
