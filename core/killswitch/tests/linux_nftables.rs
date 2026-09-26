#![cfg(target_os = "linux")]

use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU16;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use cyberia_killswitch::TrafficPolicy;
use cyberia_killswitch::linux::{
    NftablesBackend, NftablesConfig, NftablesError, NftablesRunner, SystemNftablesRunner,
};

struct Recorder {
    inputs: Arc<Mutex<Vec<String>>>,
    failure: Option<NftablesError>,
}

impl NftablesRunner for Recorder {
    fn apply(&mut self, rules: &str) -> Result<(), NftablesError> {
        self.inputs.lock().unwrap().push(rules.into());
        match &self.failure {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }
}

fn config(address: IpAddr) -> NftablesConfig {
    NftablesConfig {
        endpoint_address: address,
        endpoint_port: NonZeroU16::new(51820).unwrap(),
    }
}

#[test]
fn blocking_policy_allows_only_loopback_and_peer() {
    let rules = config(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)))
        .render(&TrafficPolicy::BlockNonTunnel)
        .unwrap();

    assert!(rules.contains("policy drop"));
    assert!(rules.contains("oifname \"lo\" accept"));
    assert!(!rules.contains("ct state established,related accept"));
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
fn disabled_policy_removes_the_owned_table() {
    assert_eq!(
        config(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .render(&TrafficPolicy::Disabled)
            .unwrap(),
        "add table inet cyberia_vpn\nflush table inet cyberia_vpn\ndelete table inet cyberia_vpn\n"
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

#[test]
fn backend_applies_one_complete_policy_transaction() {
    let inputs = Arc::new(Mutex::new(Vec::new()));
    let mut backend = NftablesBackend::new(
        config(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))),
        Recorder {
            inputs: Arc::clone(&inputs),
            failure: None,
        },
    );

    backend.apply(&TrafficPolicy::BlockNonTunnel).unwrap();

    let inputs = inputs.lock().unwrap();
    assert_eq!(inputs.len(), 1);
    assert!(inputs[0].contains("policy drop"));
}

#[test]
fn backend_propagates_a_failed_transaction() {
    let mut backend = NftablesBackend::new(
        config(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        Recorder {
            inputs: Arc::new(Mutex::new(Vec::new())),
            failure: Some(NftablesError::Command("denied".into())),
        },
    );

    assert_eq!(
        backend.apply(&TrafficPolicy::BlockNonTunnel),
        Err(NftablesError::Command("denied".into()))
    );
}

#[test]
fn system_runner_requires_an_absolute_regular_executable() {
    assert!(matches!(
        SystemNftablesRunner::new(PathBuf::from("nft")),
        Err(NftablesError::InvalidExecutable)
    ));

    let directory = std::env::temp_dir().join(format!("cyberia-nft-{}", std::process::id()));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir(&directory).unwrap();
    let executable = directory.join("nft");
    fs::write(&executable, "").unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(SystemNftablesRunner::new(executable).is_ok());
    fs::remove_dir_all(directory).unwrap();
}
