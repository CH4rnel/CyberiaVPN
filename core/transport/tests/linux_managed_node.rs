#![cfg(target_os = "linux")]

use std::fs;
use std::num::NonZeroU16;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cyberia_transport::linux::{
    CommandRunner, CommandSpec, LinuxManagedWireGuardNode, LinuxNodeGatewayTools, LinuxTools,
    LinuxWireGuardNode, LinuxWireGuardNodeGateway,
};
use cyberia_transport::{
    AllowedIp, CancellationToken, ConnectContext, TransportError, TunnelAddress,
    WireGuardNodeConfig, WireGuardNodeGatewayPolicy, WireGuardNodePeer,
};

struct NodeRecorder(Arc<Mutex<Vec<CommandSpec>>>);
impl CommandRunner for NodeRecorder {
    fn run(&mut self, command: &CommandSpec) -> Result<(), TransportError> {
        self.0.lock().unwrap().push(command.clone());
        Ok(())
    }
}

struct GatewayRecorder {
    inputs: Arc<Mutex<Vec<Vec<u8>>>>,
    fail_input_at: Option<usize>,
}
impl CommandRunner for GatewayRecorder {
    fn run(&mut self, _: &CommandSpec) -> Result<(), TransportError> {
        Ok(())
    }
    fn output(&mut self, _: &CommandSpec) -> Result<Vec<u8>, TransportError> {
        Ok(b"1\n".to_vec())
    }
    fn input(&mut self, _: &CommandSpec, input: &[u8]) -> Result<(), TransportError> {
        let mut inputs = self.inputs.lock().unwrap();
        inputs.push(input.to_vec());
        if self.fail_input_at == Some(inputs.len()) {
            Err(TransportError::Network("injected".into()))
        } else {
            Ok(())
        }
    }
}

type Managed = LinuxManagedWireGuardNode<NodeRecorder, GatewayRecorder>;

struct Harness {
    node: Managed,
    node_commands: Arc<Mutex<Vec<CommandSpec>>>,
    gateway_inputs: Arc<Mutex<Vec<Vec<u8>>>>,
    directory: PathBuf,
}

fn tool_file(directory: &std::path::Path, name: &str, mode: u32) -> PathBuf {
    let path = directory.join(name);
    fs::write(&path, "private").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    path
}

fn managed_node(name: &str, gateway_failure: Option<usize>) -> Harness {
    let directory = std::env::temp_dir().join(format!(
        "cyberia-managed-node-{name}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir(&directory).unwrap();
    let node_commands = Arc::new(Mutex::new(Vec::new()));
    let gateway_inputs = Arc::new(Mutex::new(Vec::new()));
    let node = LinuxWireGuardNode::new(
        LinuxTools {
            ip: tool_file(&directory, "ip", 0o700),
            wg: tool_file(&directory, "wg", 0o700),
            private_key: tool_file(&directory, "key", 0o600),
        },
        NodeRecorder(Arc::clone(&node_commands)),
    )
    .unwrap();
    let gateway = LinuxWireGuardNodeGateway::new(
        LinuxNodeGatewayTools {
            nft: tool_file(&directory, "nft", 0o700),
            sysctl: tool_file(&directory, "sysctl", 0o700),
        },
        GatewayRecorder {
            inputs: Arc::clone(&gateway_inputs),
            fail_input_at: gateway_failure,
        },
    )
    .unwrap();
    let managed =
        LinuxManagedWireGuardNode::new("cynode0".into(), "eth0".into(), node, gateway).unwrap();
    Harness {
        node: managed,
        node_commands,
        gateway_inputs,
        directory,
    }
}

fn context() -> ConnectContext {
    ConnectContext {
        deadline: Instant::now() + Duration::from_secs(1),
        cancellation: CancellationToken::default(),
    }
}
fn config() -> WireGuardNodeConfig {
    WireGuardNodeConfig {
        listen_port: NonZeroU16::new(51820).unwrap(),
        interface_addresses: vec![TunnelAddress {
            address: "10.20.0.1".parse().unwrap(),
            prefix_length: 24,
        }],
        mtu: 1420,
    }
}
fn policy() -> WireGuardNodeGatewayPolicy {
    WireGuardNodeGatewayPolicy {
        client_networks: vec![AllowedIp {
            network: "10.20.0.0".parse().unwrap(),
            prefix_length: 24,
        }],
    }
}
fn peer() -> WireGuardNodePeer {
    WireGuardNodePeer {
        public_key: [7; 32],
        allowed_ips: vec![AllowedIp {
            network: "10.20.0.2".parse().unwrap(),
            prefix_length: 32,
        }],
        persistent_keepalive_seconds: None,
    }
}

#[test]
fn composes_node_gateway_and_peer_lifecycle() {
    let mut harness = managed_node("lifecycle", None);
    harness
        .node
        .start(&config(), &policy(), &context())
        .unwrap();
    harness.node.add_peer(&peer()).unwrap();
    harness.node.remove_peer(&peer().public_key).unwrap();
    harness.node.stop().unwrap();
    assert_eq!(harness.gateway_inputs.lock().unwrap().len(), 2);
    assert_eq!(
        harness
            .node_commands
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .arguments,
        ["link", "delete", "dev", "cynode0"]
    );
    fs::remove_dir_all(harness.directory).unwrap();
}

#[test]
fn gateway_setup_failure_removes_the_node_interface() {
    let mut harness = managed_node("setup-failure", Some(1));
    assert!(
        harness
            .node
            .start(&config(), &policy(), &context())
            .is_err()
    );
    assert_eq!(
        harness
            .node_commands
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .arguments,
        ["link", "delete", "dev", "cynode0"]
    );
    fs::remove_dir_all(harness.directory).unwrap();
}

#[test]
fn gateway_teardown_failure_retains_the_node_interface() {
    let mut harness = managed_node("teardown-failure", Some(2));
    harness
        .node
        .start(&config(), &policy(), &context())
        .unwrap();
    let command_count = harness.node_commands.lock().unwrap().len();
    assert!(harness.node.stop().is_err());
    assert_eq!(harness.node_commands.lock().unwrap().len(), command_count);
    fs::remove_dir_all(harness.directory).unwrap();
}
