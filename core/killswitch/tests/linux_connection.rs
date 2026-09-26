#![cfg(target_os = "linux")]

use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::num::{NonZeroU16, NonZeroU32};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cyberia_killswitch::TrafficPolicy;
use cyberia_killswitch::linux::{NftablesError, NftablesRunner};
use cyberia_killswitch::linux_connection::{
    LinuxConnectionBuildError, LinuxConnectionSettings, LinuxWireGuardConnection,
};
use cyberia_transport::linux::{CommandRunner, CommandSpec, LinuxDnsTools, LinuxTools};
use cyberia_transport::{
    AllowedIp, CancellationToken, DnsConfig, Endpoint, HealthStatus, TransportError, TunnelAddress,
    WireGuardConfig,
};

struct Commands {
    recorded: Arc<Mutex<Vec<CommandSpec>>>,
}

impl CommandRunner for Commands {
    fn run(&mut self, command: &CommandSpec) -> Result<(), TransportError> {
        self.recorded.lock().unwrap().push(command.clone());
        Ok(())
    }

    fn output(&mut self, command: &CommandSpec) -> Result<Vec<u8>, TransportError> {
        self.recorded.lock().unwrap().push(command.clone());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Ok(format!("peer-key\t{now}\n").into_bytes())
    }
}

struct FirewallRules {
    recorded: Arc<Mutex<Vec<String>>>,
}

struct FailingFirewallRules {
    recorded: Arc<Mutex<Vec<String>>>,
}

struct FailingDns {
    commands: Arc<Mutex<Vec<CommandSpec>>>,
    fail_at: usize,
}

impl CommandRunner for FailingDns {
    fn run(&mut self, command: &CommandSpec) -> Result<(), TransportError> {
        let mut commands = self.commands.lock().unwrap();
        commands.push(command.clone());
        if commands.len() == self.fail_at {
            return Err(TransportError::Network("DNS failure".into()));
        }
        Ok(())
    }
}

impl NftablesRunner for FirewallRules {
    fn apply(&mut self, rules: &str) -> Result<(), NftablesError> {
        self.recorded.lock().unwrap().push(rules.into());
        Ok(())
    }
}

impl NftablesRunner for FailingFirewallRules {
    fn apply(&mut self, rules: &str) -> Result<(), NftablesError> {
        self.recorded.lock().unwrap().push(rules.into());
        Err(NftablesError::Command("injected firewall failure".into()))
    }
}

fn settings(name: &str, host: &str) -> (LinuxConnectionSettings, PathBuf) {
    let directory =
        std::env::temp_dir().join(format!("cyberia-managed-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir(&directory).unwrap();
    let ip = directory.join("ip");
    let wg = directory.join("wg");
    let key = directory.join("key");
    let resolvectl = directory.join("resolvectl");
    fs::write(&ip, "").unwrap();
    fs::write(&wg, "").unwrap();
    fs::write(&key, "private").unwrap();
    fs::write(&resolvectl, "").unwrap();
    fs::set_permissions(&ip, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&wg, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(&resolvectl, fs::Permissions::from_mode(0o700)).unwrap();
    (
        LinuxConnectionSettings {
            interface: "wg0".into(),
            profile: WireGuardConfig {
                peer_public_key: [1; 32],
                endpoint: Endpoint {
                    host: host.into(),
                    port: NonZeroU16::new(51820).unwrap(),
                },
                tunnel_addresses: vec![TunnelAddress {
                    address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                    prefix_length: 24,
                }],
                allowed_ips: vec![AllowedIp {
                    network: "0.0.0.0".parse().unwrap(),
                    prefix_length: 0,
                }],
                persistent_keepalive_seconds: Some(25),
                mtu: 1420,
            },
            dns: DnsConfig {
                resolvers: vec!["192.0.2.53".parse().unwrap()],
            },
            tools: LinuxTools {
                ip,
                wg,
                private_key: key,
            },
            dns_tools: LinuxDnsTools { resolvectl },
            routing_mark: NonZeroU32::new(51_820).unwrap(),
            connect_timeout: Duration::from_secs(1),
            always_on: false,
        },
        directory,
    )
}

#[test]
fn composes_firewall_transport_routes_health_and_teardown() {
    let (settings, directory) = settings("lifecycle", "198.51.100.7");
    let commands = Arc::new(Mutex::new(Vec::new()));
    let rules = Arc::new(Mutex::new(Vec::new()));
    let mut connection = LinuxWireGuardConnection::with_runners(
        settings,
        Commands {
            recorded: Arc::clone(&commands),
        },
        Commands {
            recorded: Arc::clone(&commands),
        },
        FirewallRules {
            recorded: Arc::clone(&rules),
        },
    )
    .unwrap();

    connection.connect(CancellationToken::default()).unwrap();
    assert_eq!(
        connection.policy(),
        &TrafficPolicy::TunnelOnly {
            interface: "wg0".into()
        }
    );
    assert_eq!(connection.health().status, HealthStatus::Healthy);
    connection.disconnect().unwrap();
    connection.disable().unwrap();

    let rules = rules.lock().unwrap();
    assert_eq!(rules.len(), 5);
    assert!(!rules[0].contains("policy drop"));
    assert!(rules[1].contains("policy drop"));
    assert!(rules[2].contains("oifname \"wg0\" accept"));
    assert!(rules[3].contains("policy drop"));
    assert!(!rules[4].contains("policy drop"));
    let commands = commands.lock().unwrap();
    assert_eq!(commands[0].arguments[0..3], ["link", "add", "dev"]);
    assert!(
        commands
            .iter()
            .any(|command| { command.arguments == ["show", "wg0", "latest-handshakes"] })
    );
    assert!(
        commands
            .iter()
            .any(|command| { command.arguments == ["dns", "wg0", "192.0.2.53"] })
    );
    assert!(
        commands
            .iter()
            .any(|command| { command.arguments == ["revert", "wg0"] })
    );
    assert_eq!(
        commands.last().unwrap().arguments,
        ["link", "delete", "dev", "wg0"]
    );
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn rejects_a_hostname_before_applying_any_platform_state() {
    let (settings, directory) = settings("hostname", "node.example");
    let commands = Arc::new(Mutex::new(Vec::new()));
    let rules = Arc::new(Mutex::new(Vec::new()));

    let result = LinuxWireGuardConnection::with_runners(
        settings,
        Commands {
            recorded: Arc::clone(&commands),
        },
        Commands {
            recorded: Arc::clone(&commands),
        },
        FirewallRules {
            recorded: Arc::clone(&rules),
        },
    );

    assert!(matches!(
        result,
        Err(LinuxConnectionBuildError::EndpointMustBeIpAddress)
    ));
    assert!(commands.lock().unwrap().is_empty());
    assert!(rules.lock().unwrap().is_empty());
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn rejects_a_zero_timeout_before_applying_any_platform_state() {
    let (mut settings, directory) = settings("timeout", "198.51.100.7");
    settings.connect_timeout = Duration::ZERO;
    let commands = Arc::new(Mutex::new(Vec::new()));
    let rules = Arc::new(Mutex::new(Vec::new()));

    let result = LinuxWireGuardConnection::with_runners(
        settings,
        Commands {
            recorded: Arc::clone(&commands),
        },
        Commands {
            recorded: Arc::clone(&commands),
        },
        FirewallRules {
            recorded: Arc::clone(&rules),
        },
    );

    assert!(matches!(
        result,
        Err(LinuxConnectionBuildError::Transport(
            TransportError::InvalidConfig("connect timeout is zero")
        ))
    ));
    assert!(commands.lock().unwrap().is_empty());
    assert!(rules.lock().unwrap().is_empty());
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn refuses_to_build_when_initial_firewall_policy_cannot_be_applied() {
    let (settings, directory) = settings("initial-firewall-failure", "198.51.100.7");
    let commands = Arc::new(Mutex::new(Vec::new()));
    let rules = Arc::new(Mutex::new(Vec::new()));

    let result = LinuxWireGuardConnection::with_runners(
        settings,
        Commands {
            recorded: Arc::clone(&commands),
        },
        Commands {
            recorded: Arc::clone(&commands),
        },
        FailingFirewallRules {
            recorded: Arc::clone(&rules),
        },
    );

    assert!(matches!(result, Err(LinuxConnectionBuildError::Firewall(_))));
    assert!(commands.lock().unwrap().is_empty());
    assert_eq!(rules.lock().unwrap().len(), 1);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn dns_failure_restores_blocking_and_tears_down_the_tunnel() {
    let (settings, directory) = settings("dns-failure", "198.51.100.7");
    let commands = Arc::new(Mutex::new(Vec::new()));
    let dns_commands = Arc::new(Mutex::new(Vec::new()));
    let rules = Arc::new(Mutex::new(Vec::new()));
    let mut connection = LinuxWireGuardConnection::with_runners(
        settings,
        Commands {
            recorded: Arc::clone(&commands),
        },
        FailingDns {
            commands: Arc::clone(&dns_commands),
            fail_at: 2,
        },
        FirewallRules {
            recorded: Arc::clone(&rules),
        },
    )
    .unwrap();

    assert!(connection.connect(CancellationToken::default()).is_err());

    assert_eq!(connection.policy(), &TrafficPolicy::BlockNonTunnel);
    assert_eq!(
        dns_commands.lock().unwrap().last().unwrap().arguments,
        ["revert", "wg0"]
    );
    assert_eq!(
        commands.lock().unwrap().last().unwrap().arguments,
        ["link", "delete", "dev", "wg0"]
    );
    assert!(
        rules
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .contains("policy drop")
    );
    fs::remove_dir_all(directory).unwrap();
}
