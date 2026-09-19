#![cfg(target_os = "linux")]

use std::fs;
use std::num::NonZeroU16;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cyberia_transport::linux::{CommandRunner, CommandSpec, LinuxTools, LinuxWireGuardNode};
use cyberia_transport::{
    AllowedIp, CancellationToken, ConnectContext, TransportError, TunnelAddress,
    WireGuardNodeConfig, WireGuardNodePeer,
};

struct Recorder {
    commands: Arc<Mutex<Vec<CommandSpec>>>,
    fail_at: Option<usize>,
}

struct HealthRunner {
    commands: Arc<Mutex<Vec<CommandSpec>>>,
    output: Vec<u8>,
    fail_query: bool,
}

impl CommandRunner for HealthRunner {
    fn run(&mut self, command: &CommandSpec) -> Result<(), TransportError> {
        self.commands.lock().unwrap().push(command.clone());
        Ok(())
    }

    fn output(&mut self, command: &CommandSpec) -> Result<Vec<u8>, TransportError> {
        self.commands.lock().unwrap().push(command.clone());
        if self.fail_query {
            Err(TransportError::Network("query failed".into()))
        } else {
            Ok(self.output.clone())
        }
    }
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
    let directory =
        std::env::temp_dir().join(format!("cyberia-node-{name}-{}", std::process::id()));
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

fn context() -> ConnectContext {
    ConnectContext {
        deadline: Instant::now() + Duration::from_secs(1),
        cancellation: CancellationToken::default(),
    }
}

fn node_config() -> WireGuardNodeConfig {
    WireGuardNodeConfig {
        listen_port: NonZeroU16::new(51820).unwrap(),
        interface_addresses: vec![TunnelAddress {
            address: "10.0.0.1".parse().unwrap(),
            prefix_length: 24,
        }],
        mtu: 1420,
    }
}

fn peer(key: u8, address: &str) -> WireGuardNodePeer {
    WireGuardNodePeer {
        public_key: [key; 32],
        allowed_ips: vec![AllowedIp {
            network: address.parse().unwrap(),
            prefix_length: 32,
        }],
        persistent_keepalive_seconds: None,
    }
}

#[test]
fn manages_node_interface_and_peer_lifecycle() {
    let (tools, directory) = tools("lifecycle");
    let commands = Arc::new(Mutex::new(Vec::new()));
    let mut node = LinuxWireGuardNode::new(
        tools,
        Recorder {
            commands: Arc::clone(&commands),
            fail_at: None,
        },
    )
    .unwrap();
    let peer = peer(7, "10.0.0.2");

    node.start("cynode0", &node_config(), &context()).unwrap();
    node.add_peer(&peer).unwrap();
    node.remove_peer(&peer.public_key).unwrap();
    node.stop().unwrap();

    let commands = commands.lock().unwrap();
    assert_eq!(
        commands[0].arguments,
        ["link", "add", "dev", "cynode0", "type", "wireguard"]
    );
    assert!(commands.iter().any(|command| {
        command
            .arguments
            .windows(2)
            .any(|pair| pair == ["listen-port", "51820"])
    }));
    assert!(commands.iter().any(|command| {
        command
            .arguments
            .windows(2)
            .any(|pair| pair == ["allowed-ips", "10.0.0.2/32"])
    }));
    assert!(commands.iter().any(|command| {
        command
            .arguments
            .last()
            .is_some_and(|value| value == "remove")
    }));
    assert_eq!(
        commands.last().unwrap().arguments,
        ["link", "delete", "dev", "cynode0"]
    );
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn rejects_cross_peer_route_collisions_before_platform_work() {
    let (tools, directory) = tools("collision");
    let commands = Arc::new(Mutex::new(Vec::new()));
    let mut node = LinuxWireGuardNode::new(
        tools,
        Recorder {
            commands: Arc::clone(&commands),
            fail_at: None,
        },
    )
    .unwrap();
    node.start("cynode0", &node_config(), &context()).unwrap();
    node.add_peer(&peer(7, "10.0.0.2")).unwrap();
    let count = commands.lock().unwrap().len();

    assert!(node.add_peer(&peer(8, "10.0.0.2")).is_err());
    assert_eq!(commands.lock().unwrap().len(), count);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn partial_node_setup_deletes_the_created_interface() {
    let (tools, directory) = tools("rollback");
    let commands = Arc::new(Mutex::new(Vec::new()));
    let mut node = LinuxWireGuardNode::new(
        tools,
        Recorder {
            commands: Arc::clone(&commands),
            fail_at: Some(2),
        },
    )
    .unwrap();

    assert!(node.start("cynode0", &node_config(), &context()).is_err());

    let commands = commands.lock().unwrap();
    assert_eq!(commands.len(), 3);
    assert_eq!(commands[2].arguments, ["link", "delete", "dev", "cynode0"]);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn reports_managed_peer_drift_and_recent_handshakes() {
    let (tools, directory) = tools("health");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut node = LinuxWireGuardNode::new(
        tools,
        HealthRunner {
            commands: Arc::new(Mutex::new(Vec::new())),
            output: format!("peer-key\t{now}\n").into_bytes(),
            fail_query: false,
        },
    )
    .unwrap();
    node.start("cynode0", &node_config(), &context()).unwrap();
    node.add_peer(&peer(7, "10.0.0.2")).unwrap();

    let health = node.health();

    assert_eq!(health.status, cyberia_transport::HealthStatus::Healthy);
    assert_eq!(health.configured_peers, 1);
    assert_eq!(health.observed_peers, 1);
    assert_eq!(health.recent_handshakes, 1);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn degrades_when_kernel_peer_state_differs_from_managed_state() {
    let (tools, directory) = tools("drift");
    let mut node = LinuxWireGuardNode::new(
        tools,
        HealthRunner {
            commands: Arc::new(Mutex::new(Vec::new())),
            output: Vec::new(),
            fail_query: false,
        },
    )
    .unwrap();
    node.start("cynode0", &node_config(), &context()).unwrap();
    node.add_peer(&peer(7, "10.0.0.2")).unwrap();

    let health = node.health();

    assert_eq!(health.status, cyberia_transport::HealthStatus::Degraded);
    assert_eq!(health.configured_peers, 1);
    assert_eq!(health.observed_peers, 0);
    fs::remove_dir_all(directory).unwrap();
}
