#![cfg(target_os = "linux")]

use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroU16;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cyberia_transport::linux::{CommandRunner, CommandSpec, LinuxTools, LinuxWireGuardBackend};
use cyberia_transport::{
    CancellationToken, ConnectContext, Endpoint, TransportError, TunnelAddress, WireGuardBackend,
    WireGuardConfig,
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

#[test]
fn configures_and_removes_linux_wireguard_interface() {
    let (tools, directory) = tools("success");
    let recorder = Recorder {
        commands: Arc::new(Mutex::new(vec![])),
        fail_at: None,
    };
    let mut backend = LinuxWireGuardBackend::new(tools, recorder).unwrap();
    backend.bring_up("wg0", &profile(), &context()).unwrap();
    backend.bring_down("wg0").unwrap();
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
    let mut backend = LinuxWireGuardBackend::new(tools, recorder).unwrap();
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
    let mut backend = LinuxWireGuardBackend::new(tools, recorder).unwrap();
    assert!(backend.bring_up("wg0", &profile(), &context()).is_err());
    assert_eq!(commands.lock().unwrap().len(), 1);
    fs::remove_dir_all(directory).unwrap();
}
