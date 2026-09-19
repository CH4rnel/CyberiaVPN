#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cyberia_transport::linux::{
    CommandRunner, CommandSpec, LinuxNodeGatewayTools, LinuxWireGuardNodeGateway,
};
use cyberia_transport::{
    AllowedIp, CancellationToken, ConnectContext, TransportError, WireGuardNodeGatewayPolicy,
};

#[derive(Clone, Debug, Eq, PartialEq)]
struct Invocation {
    command: CommandSpec,
    input: Vec<u8>,
}

struct Recorder {
    invocations: Arc<Mutex<Vec<Invocation>>>,
    forwarding: Vec<u8>,
    fail_input: bool,
}

impl CommandRunner for Recorder {
    fn run(&mut self, _command: &CommandSpec) -> Result<(), TransportError> {
        Ok(())
    }

    fn output(&mut self, command: &CommandSpec) -> Result<Vec<u8>, TransportError> {
        self.invocations.lock().unwrap().push(Invocation {
            command: command.clone(),
            input: Vec::new(),
        });
        Ok(self.forwarding.clone())
    }

    fn input(&mut self, command: &CommandSpec, input: &[u8]) -> Result<(), TransportError> {
        self.invocations.lock().unwrap().push(Invocation {
            command: command.clone(),
            input: input.to_vec(),
        });
        if self.fail_input {
            Err(TransportError::Network("injected".into()))
        } else {
            Ok(())
        }
    }
}

fn tools(name: &str) -> (LinuxNodeGatewayTools, PathBuf) {
    let directory =
        std::env::temp_dir().join(format!("cyberia-gateway-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir(&directory).unwrap();
    let nft = directory.join("nft");
    let sysctl = directory.join("sysctl");
    fs::write(&nft, "").unwrap();
    fs::write(&sysctl, "").unwrap();
    fs::set_permissions(&nft, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&sysctl, fs::Permissions::from_mode(0o700)).unwrap();
    (LinuxNodeGatewayTools { nft, sysctl }, directory)
}

fn context() -> ConnectContext {
    ConnectContext {
        deadline: Instant::now() + Duration::from_secs(1),
        cancellation: CancellationToken::default(),
    }
}

fn policy() -> WireGuardNodeGatewayPolicy {
    WireGuardNodeGatewayPolicy {
        client_networks: vec![
            AllowedIp {
                network: "10.20.0.0".parse().unwrap(),
                prefix_length: 24,
            },
            AllowedIp {
                network: "fd00:20::".parse().unwrap(),
                prefix_length: 64,
            },
        ],
    }
}

#[test]
fn installs_and_removes_restricted_gateway_transactionally() {
    let (tools, directory) = tools("lifecycle");
    let invocations = Arc::new(Mutex::new(Vec::new()));
    let mut gateway = LinuxWireGuardNodeGateway::new(
        tools,
        Recorder {
            invocations: Arc::clone(&invocations),
            forwarding: b"1\n".to_vec(),
            fail_input: false,
        },
    )
    .unwrap();

    gateway
        .enable("cynode0", "eth0", &policy(), &context())
        .unwrap();
    gateway.disable().unwrap();

    let invocations = invocations.lock().unwrap();
    assert_eq!(
        invocations[0].command.arguments,
        ["-n", "net.ipv4.ip_forward"]
    );
    assert_eq!(
        invocations[1].command.arguments,
        ["-n", "net.ipv6.conf.all.forwarding"]
    );
    let rules = String::from_utf8(invocations[2].input.clone()).unwrap();
    assert!(rules.contains("policy drop"));
    assert!(rules.contains("iifname \"cynode0\" oifname \"eth0\" ip saddr 10.20.0.0/24 accept"));
    assert!(rules.contains("ip6 saddr fd00:20::/64 masquerade"));
    assert_eq!(
        invocations[3].input,
        b"delete table inet cyberia_vpn_node\n"
    );
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn refuses_to_open_forwarding_when_kernel_forwarding_is_disabled() {
    let (tools, directory) = tools("disabled");
    let invocations = Arc::new(Mutex::new(Vec::new()));
    let mut gateway = LinuxWireGuardNodeGateway::new(
        tools,
        Recorder {
            invocations: Arc::clone(&invocations),
            forwarding: b"0\n".to_vec(),
            fail_input: false,
        },
    )
    .unwrap();

    assert!(matches!(
        gateway.enable("cynode0", "eth0", &policy(), &context()),
        Err(TransportError::InvalidConfig(
            "kernel IP forwarding is disabled"
        ))
    ));
    assert_eq!(invocations.lock().unwrap().len(), 1);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn failed_nft_transaction_does_not_claim_gateway_ownership() {
    let (tools, directory) = tools("rollback");
    let mut gateway = LinuxWireGuardNodeGateway::new(
        tools,
        Recorder {
            invocations: Arc::new(Mutex::new(Vec::new())),
            forwarding: b"1\n".to_vec(),
            fail_input: true,
        },
    )
    .unwrap();

    assert!(
        gateway
            .enable("cynode0", "eth0", &policy(), &context())
            .is_err()
    );
    assert_eq!(gateway.disable(), Err(TransportError::NotConnected));
    fs::remove_dir_all(directory).unwrap();
}
