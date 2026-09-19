//! Linux process boundary used by platform transport backends.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    AllowedIp, ConnectContext, DnsConfig, HealthStatus, TransportError, TransportHealth,
    WireGuardBackend, WireGuardConfig, WireGuardNodeConfig, WireGuardNodePeer,
};

const MAXIMUM_HANDSHAKE_AGE_SECONDS: u64 = 180;
const MAXIMUM_NODE_PEERS: usize = 4_096;

/// One command invocation represented as an executable plus literal arguments.
/// No shell parses these values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandSpec {
    pub program: PathBuf,
    pub arguments: Vec<String>,
}

/// Injectable process boundary for deterministic platform-backend tests.
pub trait CommandRunner: Send {
    /// Runs one command without a shell.
    ///
    /// # Errors
    ///
    /// Returns a bounded network error for spawn failures or non-zero status.
    fn run(&mut self, command: &CommandSpec) -> Result<(), TransportError>;

    /// Runs one command and returns its bounded standard output.
    ///
    /// # Errors
    ///
    /// Returns the same execution errors as [`CommandRunner::run`]. Runners
    /// that do not expose output may retain the default empty result.
    fn output(&mut self, command: &CommandSpec) -> Result<Vec<u8>, TransportError> {
        self.run(command)?;
        Ok(Vec::new())
    }
}

#[derive(Debug, Default)]
pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&mut self, command: &CommandSpec) -> Result<(), TransportError> {
        self.output(command).map(drop)
    }

    fn output(&mut self, command: &CommandSpec) -> Result<Vec<u8>, TransportError> {
        let output = Command::new(&command.program)
            .args(&command.arguments)
            .output()
            .map_err(|error| {
                TransportError::Network(format!("platform command failed to start: {error}"))
            })?;
        if output.status.success() {
            if output.stdout.len() > 64 * 1024 {
                return Err(TransportError::Network(
                    "platform command output exceeds safe bounds".into(),
                ));
            }
            return Ok(output.stdout);
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        let reason: String = stderr.chars().take(256).collect();
        Err(TransportError::Network(format!(
            "platform command exited with {}: {}",
            output.status,
            reason.trim()
        )))
    }
}

/// Validated executable and private-key references for a Linux `WireGuard` backend.
#[derive(Clone, Debug)]
pub struct LinuxTools {
    pub ip: PathBuf,
    pub wg: PathBuf,
    pub private_key: PathBuf,
}

/// Validated executable reference for systemd-resolved integration.
#[derive(Clone, Debug)]
pub struct LinuxDnsTools {
    pub resolvectl: PathBuf,
}

impl LinuxDnsTools {
    /// Validates the absolute `resolvectl` executable reference.
    ///
    /// # Errors
    ///
    /// Returns invalid configuration when the path is relative, is a symbolic
    /// link or does not identify an executable regular file.
    pub fn validate(&self) -> Result<(), TransportError> {
        validate_executable(&self.resolvectl)
    }
}

/// Applies and reverts per-interface DNS through systemd-resolved.
pub struct LinuxDnsBackend<R> {
    tools: LinuxDnsTools,
    runner: R,
    active_interface: Option<String>,
}

impl<R: CommandRunner> LinuxDnsBackend<R> {
    /// Creates a DNS backend from a validated `resolvectl` executable.
    ///
    /// # Errors
    ///
    /// Returns invalid configuration when the executable cannot be trusted.
    pub fn new(tools: LinuxDnsTools, runner: R) -> Result<Self, TransportError> {
        tools.validate()?;
        Ok(Self {
            tools,
            runner,
            active_interface: None,
        })
    }

    fn command(&mut self, arguments: Vec<String>) -> Result<(), TransportError> {
        self.runner.run(&CommandSpec {
            program: self.tools.resolvectl.clone(),
            arguments,
        })
    }

    /// Installs resolver addresses and routes all DNS lookups to the interface.
    ///
    /// # Errors
    ///
    /// Returns a validation or command error. A failure after resolver setup
    /// attempts `resolvectl revert` before returning.
    pub fn configure(
        &mut self,
        interface: &str,
        config: &DnsConfig,
        context: &ConnectContext,
    ) -> Result<(), TransportError> {
        if self.active_interface.is_some() {
            return Err(TransportError::AlreadyConnected);
        }
        if !valid_interface(interface) {
            return Err(TransportError::InvalidConfig("invalid DNS interface name"));
        }
        config.validate()?;
        context.check()?;
        let mut arguments = vec!["dns".into(), interface.into()];
        arguments.extend(config.resolvers.iter().map(ToString::to_string));
        self.command(arguments)?;

        let setup_result = (|| {
            context.check()?;
            self.command(vec!["domain".into(), interface.into(), "~.".into()])?;
            context.check()?;
            self.command(vec!["default-route".into(), interface.into(), "yes".into()])
        })();
        if let Err(setup_error) = setup_result {
            if let Err(cleanup_error) = self.command(vec!["revert".into(), interface.into()]) {
                return Err(TransportError::Network(format!(
                    "DNS setup failed: {setup_error}; cleanup failed: {cleanup_error}"
                )));
            }
            return Err(setup_error);
        }
        self.active_interface = Some(interface.into());
        Ok(())
    }

    /// Reverts all DNS state owned by the active interface.
    ///
    /// # Errors
    ///
    /// Returns not connected for a foreign interface or the command error
    /// while retaining active ownership for a later retry.
    pub fn revert(&mut self, interface: &str) -> Result<(), TransportError> {
        if self.active_interface.as_deref() != Some(interface) {
            return Err(TransportError::NotConnected);
        }
        self.command(vec!["revert".into(), interface.into()])?;
        self.active_interface = None;
        Ok(())
    }
}

impl LinuxTools {
    /// Validates absolute executable references and a private regular key file.
    ///
    /// # Errors
    ///
    /// Returns invalid configuration when paths are relative, executables are
    /// unusable, or the key file has permissions broader than `0600`.
    pub fn validate(&self) -> Result<(), TransportError> {
        validate_executable(&self.ip)?;
        validate_executable(&self.wg)?;
        let metadata = fs::symlink_metadata(&self.private_key)
            .map_err(|_| TransportError::InvalidConfig("WireGuard private key is unavailable"))?;
        if !self.private_key.is_absolute()
            || !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(TransportError::InvalidConfig(
                "WireGuard private key must be a private regular file",
            ));
        }
        Ok(())
    }
}

/// Managed Linux `WireGuard` node interface and peer lifecycle.
pub struct LinuxWireGuardNode<R> {
    tools: LinuxTools,
    runner: R,
    active_interface: Option<String>,
    peers: HashSet<[u8; 32]>,
    assigned_routes: HashMap<AllowedIp, [u8; 32]>,
}

impl<R: CommandRunner> LinuxWireGuardNode<R> {
    /// Creates a node manager from validated Linux tools and private key.
    ///
    /// # Errors
    ///
    /// Returns invalid configuration when the executables or key file cannot
    /// be safely used.
    pub fn new(tools: LinuxTools, runner: R) -> Result<Self, TransportError> {
        tools.validate()?;
        if tools.private_key.to_str().is_none() {
            return Err(TransportError::InvalidConfig(
                "WireGuard private key path is not UTF-8",
            ));
        }
        Ok(Self {
            tools,
            runner,
            active_interface: None,
            peers: HashSet::new(),
            assigned_routes: HashMap::new(),
        })
    }

    fn command(&mut self, program: PathBuf, arguments: Vec<String>) -> Result<(), TransportError> {
        self.runner.run(&CommandSpec { program, arguments })
    }

    fn delete_interface(&mut self, interface: &str) -> Result<(), TransportError> {
        self.command(
            self.tools.ip.clone(),
            vec![
                "link".into(),
                "delete".into(),
                "dev".into(),
                interface.into(),
            ],
        )
    }

    /// Creates and configures the managed node interface.
    ///
    /// # Errors
    ///
    /// Returns a validation or command error and removes a partially configured
    /// interface before returning when creation itself succeeded.
    pub fn start(
        &mut self,
        interface: &str,
        config: &WireGuardNodeConfig,
        context: &ConnectContext,
    ) -> Result<(), TransportError> {
        if self.active_interface.is_some() {
            return Err(TransportError::AlreadyConnected);
        }
        if !valid_interface(interface) {
            return Err(TransportError::InvalidConfig(
                "invalid WireGuard node interface name",
            ));
        }
        config.validate()?;
        context.check()?;
        self.command(
            self.tools.ip.clone(),
            vec![
                "link".into(),
                "add".into(),
                "dev".into(),
                interface.into(),
                "type".into(),
                "wireguard".into(),
            ],
        )?;
        if let Err(setup_error) = self.configure_node(interface, config, context) {
            if let Err(cleanup_error) = self.delete_interface(interface) {
                return Err(TransportError::Network(format!(
                    "WireGuard node setup failed: {setup_error}; cleanup failed: {cleanup_error}"
                )));
            }
            return Err(setup_error);
        }
        self.active_interface = Some(interface.into());
        Ok(())
    }

    fn configure_node(
        &mut self,
        interface: &str,
        config: &WireGuardNodeConfig,
        context: &ConnectContext,
    ) -> Result<(), TransportError> {
        context.check()?;
        self.command(
            self.tools.wg.clone(),
            vec![
                "set".into(),
                interface.into(),
                "private-key".into(),
                self.tools.private_key.to_string_lossy().into_owned(),
                "listen-port".into(),
                config.listen_port.to_string(),
            ],
        )?;
        for address in &config.interface_addresses {
            context.check()?;
            self.command(
                self.tools.ip.clone(),
                vec![
                    "address".into(),
                    "add".into(),
                    format!("{}/{}", address.address, address.prefix_length),
                    "dev".into(),
                    interface.into(),
                ],
            )?;
        }
        context.check()?;
        self.command(
            self.tools.ip.clone(),
            vec![
                "link".into(),
                "set".into(),
                "dev".into(),
                interface.into(),
                "mtu".into(),
                config.mtu.to_string(),
                "up".into(),
            ],
        )
    }

    /// Adds one peer after checking global key and route ownership.
    ///
    /// # Errors
    ///
    /// Returns an error for inactive nodes, duplicate keys/routes, capacity or
    /// command failures. State changes only after the command succeeds.
    pub fn add_peer(&mut self, peer: &WireGuardNodePeer) -> Result<(), TransportError> {
        peer.validate()?;
        let interface = self
            .active_interface
            .clone()
            .ok_or(TransportError::NotConnected)?;
        if self.peers.len() >= MAXIMUM_NODE_PEERS {
            return Err(TransportError::InvalidConfig(
                "WireGuard node peer capacity reached",
            ));
        }
        if self.peers.contains(&peer.public_key) {
            return Err(TransportError::InvalidConfig(
                "WireGuard node peer is already managed",
            ));
        }
        if peer
            .allowed_ips
            .iter()
            .any(|route| self.assigned_routes.contains_key(route))
        {
            return Err(TransportError::InvalidConfig(
                "WireGuard node peer route is already assigned",
            ));
        }
        let mut arguments = vec![
            "set".into(),
            interface,
            "peer".into(),
            encode_key(&peer.public_key),
            "allowed-ips".into(),
            peer.allowed_ips
                .iter()
                .map(|route| format!("{}/{}", route.network, route.prefix_length))
                .collect::<Vec<_>>()
                .join(","),
        ];
        if let Some(seconds) = peer.persistent_keepalive_seconds {
            arguments.extend(["persistent-keepalive".into(), seconds.to_string()]);
        }
        self.command(self.tools.wg.clone(), arguments)?;
        self.peers.insert(peer.public_key);
        for route in &peer.allowed_ips {
            self.assigned_routes.insert(*route, peer.public_key);
        }
        Ok(())
    }

    /// Removes one peer and releases all of its host routes.
    ///
    /// # Errors
    ///
    /// Returns an error for inactive or unknown peers and command failures.
    pub fn remove_peer(&mut self, public_key: &[u8; 32]) -> Result<(), TransportError> {
        let interface = self
            .active_interface
            .clone()
            .ok_or(TransportError::NotConnected)?;
        if !self.peers.contains(public_key) {
            return Err(TransportError::InvalidConfig(
                "WireGuard node peer is not managed",
            ));
        }
        self.command(
            self.tools.wg.clone(),
            vec![
                "set".into(),
                interface,
                "peer".into(),
                encode_key(public_key),
                "remove".into(),
            ],
        )?;
        self.peers.remove(public_key);
        self.assigned_routes.retain(|_, owner| owner != public_key);
        Ok(())
    }

    /// Removes the node interface and clears peer ownership after success.
    ///
    /// # Errors
    ///
    /// Returns not connected or the interface deletion error while retaining
    /// ownership state for a later retry.
    pub fn stop(&mut self) -> Result<(), TransportError> {
        let interface = self
            .active_interface
            .clone()
            .ok_or(TransportError::NotConnected)?;
        self.delete_interface(&interface)?;
        self.active_interface = None;
        self.peers.clear();
        self.assigned_routes.clear();
        Ok(())
    }
}

/// Linux `WireGuard` backend implemented with `ip` and `wg` command-line tools.
/// Construction validates all executable and key-file references before use.
pub struct LinuxWireGuardBackend<R> {
    tools: LinuxTools,
    runner: R,
    routing_mark: NonZeroU32,
    active_rules: Vec<PolicyRule>,
    active_interface: Option<String>,
    health_failures: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AddressFamily {
    V4,
    V6,
}

impl AddressFamily {
    fn argument(self) -> &'static str {
        match self {
            Self::V4 => "-4",
            Self::V6 => "-6",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PolicyRule {
    NotFirewallMark(AddressFamily),
    SuppressDefault(AddressFamily),
}

impl<R: CommandRunner> LinuxWireGuardBackend<R> {
    /// Creates a backend from validated Linux tools.
    ///
    /// # Errors
    ///
    /// Returns invalid configuration when tool paths or the private-key path
    /// cannot be safely passed as literal command arguments.
    pub fn new(
        tools: LinuxTools,
        runner: R,
        routing_mark: NonZeroU32,
    ) -> Result<Self, TransportError> {
        tools.validate()?;
        if tools.private_key.to_str().is_none() {
            return Err(TransportError::InvalidConfig(
                "WireGuard private key path is not UTF-8",
            ));
        }
        Ok(Self {
            tools,
            runner,
            routing_mark,
            active_rules: Vec::new(),
            active_interface: None,
            health_failures: 0,
        })
    }

    fn command(&mut self, program: PathBuf, arguments: Vec<String>) -> Result<(), TransportError> {
        self.runner.run(&CommandSpec { program, arguments })
    }

    fn delete_interface(&mut self, interface: &str) -> Result<(), TransportError> {
        self.command(
            self.tools.ip.clone(),
            vec![
                "link".into(),
                "delete".into(),
                "dev".into(),
                interface.into(),
            ],
        )
    }

    fn configure(
        &mut self,
        interface: &str,
        profile: &WireGuardConfig,
        context: &ConnectContext,
    ) -> Result<(), TransportError> {
        let mut arguments = vec![
            "set".into(),
            interface.into(),
            "private-key".into(),
            self.tools.private_key.to_string_lossy().into_owned(),
            "fwmark".into(),
            self.routing_mark.to_string(),
            "peer".into(),
            encode_key(&profile.peer_public_key),
            "endpoint".into(),
            endpoint(&profile.endpoint),
            "allowed-ips".into(),
            profile
                .allowed_ips
                .iter()
                .map(|allowed_ip| format!("{}/{}", allowed_ip.network, allowed_ip.prefix_length))
                .collect::<Vec<_>>()
                .join(","),
        ];
        if let Some(seconds) = profile.persistent_keepalive_seconds {
            arguments.extend(["persistent-keepalive".into(), seconds.to_string()]);
        }
        context.check()?;
        self.command(self.tools.wg.clone(), arguments)?;
        for address in &profile.tunnel_addresses {
            context.check()?;
            self.command(
                self.tools.ip.clone(),
                vec![
                    "address".into(),
                    "add".into(),
                    format!("{}/{}", address.address, address.prefix_length),
                    "dev".into(),
                    interface.into(),
                ],
            )?;
        }
        context.check()?;
        self.command(
            self.tools.ip.clone(),
            vec![
                "link".into(),
                "set".into(),
                "dev".into(),
                interface.into(),
                "mtu".into(),
                profile.mtu.to_string(),
                "up".into(),
            ],
        )
    }

    fn install_routes(
        &mut self,
        interface: &str,
        profile: &WireGuardConfig,
        context: &ConnectContext,
        rules: &mut Vec<PolicyRule>,
    ) -> Result<(), TransportError> {
        for allowed_ip in &profile.allowed_ips {
            context.check()?;
            let family = match allowed_ip.network {
                IpAddr::V4(_) => AddressFamily::V4,
                IpAddr::V6(_) => AddressFamily::V6,
            };
            let prefix = format!("{}/{}", allowed_ip.network, allowed_ip.prefix_length);
            if allowed_ip.prefix_length != 0 {
                self.command(
                    self.tools.ip.clone(),
                    vec![
                        family.argument().into(),
                        "route".into(),
                        "replace".into(),
                        prefix,
                        "dev".into(),
                        interface.into(),
                    ],
                )?;
                continue;
            }

            let mark = self.routing_mark.to_string();
            self.command(
                self.tools.ip.clone(),
                vec![
                    family.argument().into(),
                    "route".into(),
                    "replace".into(),
                    "default".into(),
                    "dev".into(),
                    interface.into(),
                    "table".into(),
                    mark.clone(),
                ],
            )?;
            self.command(
                self.tools.ip.clone(),
                vec![
                    family.argument().into(),
                    "rule".into(),
                    "add".into(),
                    "not".into(),
                    "fwmark".into(),
                    mark.clone(),
                    "table".into(),
                    mark,
                ],
            )?;
            rules.push(PolicyRule::NotFirewallMark(family));
            self.command(
                self.tools.ip.clone(),
                vec![
                    family.argument().into(),
                    "rule".into(),
                    "add".into(),
                    "table".into(),
                    "main".into(),
                    "suppress_prefixlength".into(),
                    "0".into(),
                ],
            )?;
            rules.push(PolicyRule::SuppressDefault(family));
        }
        Ok(())
    }

    fn remove_policy_rule(&mut self, rule: PolicyRule) -> Result<(), TransportError> {
        let (family, mut arguments) = match rule {
            PolicyRule::NotFirewallMark(family) => (
                family,
                vec![
                    "rule".into(),
                    "delete".into(),
                    "not".into(),
                    "fwmark".into(),
                    self.routing_mark.to_string(),
                    "table".into(),
                    self.routing_mark.to_string(),
                ],
            ),
            PolicyRule::SuppressDefault(family) => (
                family,
                vec![
                    "rule".into(),
                    "delete".into(),
                    "table".into(),
                    "main".into(),
                    "suppress_prefixlength".into(),
                    "0".into(),
                ],
            ),
        };
        arguments.insert(0, family.argument().into());
        self.command(self.tools.ip.clone(), arguments)
    }

    fn remove_policy_rules(&mut self, rules: &mut Vec<PolicyRule>) -> Result<(), TransportError> {
        while let Some(rule) = rules.last().copied() {
            self.remove_policy_rule(rule)?;
            rules.pop();
        }
        Ok(())
    }

    fn rollback_setup(
        &mut self,
        interface: &str,
        rules: &mut Vec<PolicyRule>,
        setup_error: TransportError,
    ) -> TransportError {
        let rules_result = self.remove_policy_rules(rules);
        let interface_result = self.delete_interface(interface);
        match (rules_result, interface_result) {
            (Ok(()), Ok(())) => setup_error,
            (rules, interface) => TransportError::Network(format!(
                "WireGuard setup failed: {setup_error}; cleanup failed: rules={rules:?}, interface={interface:?}"
            )),
        }
    }
}

impl<R: CommandRunner> WireGuardBackend for LinuxWireGuardBackend<R> {
    fn bring_up(
        &mut self,
        interface: &str,
        profile: &WireGuardConfig,
        context: &ConnectContext,
    ) -> Result<(), TransportError> {
        if self.active_interface.is_some() {
            return Err(TransportError::AlreadyConnected);
        }
        context.check()?;
        self.command(
            self.tools.ip.clone(),
            vec![
                "link".into(),
                "add".into(),
                "dev".into(),
                interface.into(),
                "type".into(),
                "wireguard".into(),
            ],
        )?;
        let mut rules = Vec::new();
        if let Err(setup_error) = self.configure(interface, profile, context) {
            return Err(self.rollback_setup(interface, &mut rules, setup_error));
        }
        if let Err(setup_error) = self.install_routes(interface, profile, context, &mut rules) {
            return Err(self.rollback_setup(interface, &mut rules, setup_error));
        }
        self.active_rules = rules;
        self.active_interface = Some(interface.into());
        Ok(())
    }

    fn bring_down(&mut self, interface: &str) -> Result<(), TransportError> {
        if self.active_interface.as_deref() != Some(interface) {
            return Err(TransportError::NotConnected);
        }
        let mut rules = std::mem::take(&mut self.active_rules);
        if let Err(error) = self.remove_policy_rules(&mut rules) {
            self.active_rules = rules;
            return Err(error);
        }
        self.delete_interface(interface)?;
        self.active_interface = None;
        Ok(())
    }

    fn health(&mut self) -> TransportHealth {
        let Some(interface) = self.active_interface.clone() else {
            return TransportHealth {
                status: HealthStatus::Unavailable,
                round_trip_time: None,
                consecutive_failures: self.health_failures,
            };
        };
        let command = CommandSpec {
            program: self.tools.wg.clone(),
            arguments: vec!["show".into(), interface, "latest-handshakes".into()],
        };
        let Ok(output) = self.runner.output(&command) else {
            self.health_failures = self.health_failures.saturating_add(1);
            return TransportHealth {
                status: HealthStatus::Unavailable,
                round_trip_time: None,
                consecutive_failures: self.health_failures,
            };
        };
        self.health_failures = 0;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let fresh = latest_handshake(&output).is_some_and(|timestamp| {
            timestamp <= now && now - timestamp <= MAXIMUM_HANDSHAKE_AGE_SECONDS
        });
        TransportHealth {
            status: if fresh {
                HealthStatus::Healthy
            } else {
                HealthStatus::Degraded
            },
            round_trip_time: None,
            consecutive_failures: 0,
        }
    }
}

fn latest_handshake(output: &[u8]) -> Option<u64> {
    std::str::from_utf8(output)
        .ok()?
        .lines()
        .filter_map(|line| line.split_ascii_whitespace().nth(1)?.parse().ok())
        .max()
        .filter(|timestamp| *timestamp != 0)
}

fn validate_executable(path: &Path) -> Result<(), TransportError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| TransportError::InvalidConfig("platform executable is unavailable"))?;
    if !path.is_absolute()
        || !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o111 == 0
    {
        return Err(TransportError::InvalidConfig(
            "platform executable must be an absolute executable regular file",
        ));
    }
    Ok(())
}

fn valid_interface(interface: &str) -> bool {
    !interface.is_empty()
        && interface.len() <= 15
        && interface
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn endpoint(endpoint: &crate::Endpoint) -> String {
    if endpoint.host.contains(':') {
        format!("[{}]:{}", endpoint.host, endpoint.port)
    } else {
        format!("{}:{}", endpoint.host, endpoint.port)
    }
}

fn encode_key(key: &[u8; 32]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(44);
    for chunk in key.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(ALPHABET[(first >> 2) as usize] as char);
        output.push(ALPHABET[(((first & 3) << 4) | (second >> 4)) as usize] as char);
        output.push(if chunk.len() > 1 {
            ALPHABET[(((second & 15) << 2) | (third >> 6)) as usize] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            ALPHABET[(third & 63) as usize] as char
        } else {
            '='
        });
    }
    output
}
