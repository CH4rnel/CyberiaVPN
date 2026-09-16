#![cfg(target_os = "linux")]

use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroU16;
use std::num::NonZeroU32;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cyberia_transport::linux::{CommandRunner, CommandSpec, LinuxTools, LinuxWireGuardBackend};
use cyberia_transport::{
    AllowedIp, CancellationToken, ConnectContext, Endpoint, TransportError, TunnelAddress,
    WireGuardBackend, WireGuardConfig,
};

struct Recorder {
    commands: Arc<Mutex<Vec<CommandSpec>>>,
    fail_at: Option<usize>,
}
impl CommandRunner for Recorder {
    fn run(&mut self, command: &CommandSpec) -> Result<(), TransportError> {
        let mut commands = self.commands.lock().unwrap();
        commands.push(command.clone());
        if self.fail_at == Some(commands.len()) {
            return Err(TransportError::Network("injected".into()));
        }
        Ok(())
    }
}
fn tools(name: &str) -> (LinuxTools, PathBuf) {
    let directory = std::env::temp_dir().join(format!("cyberia-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir(&directory).unwrap();
    let ip = directory.join("ip");
    let wg = directory.join("wg");
    let key = directory.join("key");
    fs::write(&ip, "").unwrap();
    fs::write(&wg, "").unwrap();
    fs::write(&key, "private").unwrap();
    fs::set_permissions(&ip, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&wg, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    (
        LinuxTools {
            ip,
            wg,
            private_key: key,
        },
        directory,
    )
}
fn profile() -> WireGuardConfig {
    WireGuardConfig {
        peer_public_key: [1; 32],
        endpoint: Endpoint {
            host: "2001:db8::1".into(),
            port: NonZeroU16::new(51820).unwrap(),
        },
        tunnel_addresses: vec![TunnelAddress {
            address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            prefix_length: 24,
        }],
        allowed_ips: vec![
            AllowedIp {
                network: "0.0.0.0".parse().unwrap(),
                prefix_length: 0,
            },
            AllowedIp {
                network: "::".parse().unwrap(),
                prefix_length: 0,
            },
        ],
        persistent_keepalive_seconds: Some(25),
        mtu: 1420,
    }
}
fn context() -> ConnectContext {
    ConnectContext {
        deadline: Instant::now() + Duration::from_secs(1),
        cancellation: CancellationToken::default(),
    }
}

fn backend(tools: LinuxTools, recorder: Recorder) -> LinuxWireGuardBackend<Recorder> {
    LinuxWireGuardBackend::new(tools, recorder, NonZeroU32::new(51_820).unwrap()).unwrap()
}

#[test]
fn configures_and_removes_linux_wireguard_interface() {
    let (tools, directory) = tools("success");
    let commands = Arc::new(Mutex::new(vec![]));
    let recorder = Recorder {
        commands: Arc::clone(&commands),
        fail_at: None,
    };
    let mut backend = backend(tools, recorder);
    backend.bring_up("wg0", &profile(), &context()).unwrap();
    backend.bring_down("wg0").unwrap();
    let commands = commands.lock().unwrap();
    let wireguard = &commands[1].arguments;
    let allowed_index = wireguard
        .iter()
        .position(|argument| argument == "allowed-ips")
        .unwrap();
    assert_eq!(wireguard[allowed_index + 1], "0.0.0.0/0,::/0");
    assert!(wireguard.windows(2).any(|pair| pair == ["fwmark", "51820"]));
    assert!(commands.iter().any(|command| {
        command.arguments
            == [
                "-4", "route", "replace", "default", "dev", "wg0", "table", "51820",
            ]
    }));
    assert!(commands.iter().any(|command| {
        command.arguments
            == [
                "-6", "rule", "add", "not", "fwmark", "51820", "table", "51820",
            ]
    }));
    assert!(commands.iter().any(|command| {
        command.arguments
            == [
                "-4",
                "rule",
                "delete",
                "table",
                "main",
                "suppress_prefixlength",
                "0",
            ]
    }));
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn setup_failure_attempts_interface_cleanup() {
    let (tools, directory) = tools("rollback");
    let commands = Arc::new(Mutex::new(vec![]));
    let recorder = Recorder {
        commands: Arc::clone(&commands),
        fail_at: Some(2),
    };
    let mut backend = backend(tools, recorder);
    assert!(backend.bring_up("wg0", &profile(), &context()).is_err());
    assert!(matches!(
        backend.bring_down("wg0"),
        Err(TransportError::NotConnected)
    ));
    let commands = commands.lock().unwrap();
    assert_eq!(commands.len(), 3);
    assert_eq!(
        commands[0].arguments,
        ["link", "add", "dev", "wg0", "type", "wireguard"]
    );
    assert_eq!(commands[2].arguments, ["link", "delete", "dev", "wg0"]);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn interface_creation_failure_does_not_delete_an_existing_interface() {
    let (tools, directory) = tools("create-failure");
    let commands = Arc::new(Mutex::new(vec![]));
    let recorder = Recorder {
        commands: Arc::clone(&commands),
        fail_at: Some(1),
    };
    let mut backend = backend(tools, recorder);
    assert!(backend.bring_up("wg0", &profile(), &context()).is_err());
    assert_eq!(commands.lock().unwrap().len(), 1);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn installs_non_default_prefixes_in_the_main_table() {
    let (tools, directory) = tools("split-route");
    let commands = Arc::new(Mutex::new(vec![]));
    let recorder = Recorder {
        commands: Arc::clone(&commands),
        fail_at: None,
    };
    let mut split_profile = profile();
    split_profile.allowed_ips = vec![AllowedIp {
        network: "10.10.0.0".parse().unwrap(),
        prefix_length: 16,
    }];
    let mut backend = backend(tools, recorder);

    backend.bring_up("wg0", &split_profile, &context()).unwrap();

    assert!(commands.lock().unwrap().iter().any(|command| {
        command.arguments == ["-4", "route", "replace", "10.10.0.0/16", "dev", "wg0"]
    }));
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn route_failure_removes_installed_rules_before_interface_cleanup() {
    let (tools, directory) = tools("route-rollback");
    let commands = Arc::new(Mutex::new(vec![]));
    let recorder = Recorder {
        commands: Arc::clone(&commands),
        fail_at: Some(8),
    };
    let mut backend = backend(tools, recorder);

    assert!(backend.bring_up("wg0", &profile(), &context()).is_err());

    let commands = commands.lock().unwrap();
    assert!(commands.iter().any(|command| {
        command.arguments
            == [
                "-4", "rule", "delete", "not", "fwmark", "51820", "table", "51820",
            ]
    }));
    assert_eq!(
        commands.last().unwrap().arguments,
        ["link", "delete", "dev", "wg0"]
    );
    fs::remove_dir_all(directory).unwrap();
}
