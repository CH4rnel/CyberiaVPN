//! Linux process boundary used by platform transport backends.

use std::fs;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{
    ConnectContext, HealthStatus, TransportError, TransportHealth, WireGuardBackend,
    WireGuardConfig,
};

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
}

#[derive(Debug, Default)]
pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&mut self, command: &CommandSpec) -> Result<(), TransportError> {
        let output = Command::new(&command.program)
            .args(&command.arguments)
            .output()
            .map_err(|error| {
                TransportError::Network(format!("platform command failed to start: {error}"))
            })?;
        if output.status.success() {
            return Ok(());
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

/// Linux `WireGuard` backend implemented with `ip` and `wg` command-line tools.
/// Construction validates all executable and key-file references before use.
pub struct LinuxWireGuardBackend<R> {
    tools: LinuxTools,
    runner: R,
    routing_mark: NonZeroU32,
    active_rules: Vec<PolicyRule>,
    active_interface: Option<String>,
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

    fn health(&self) -> TransportHealth {
        TransportHealth {
            status: if self.active_interface.is_some() {
                HealthStatus::Healthy
            } else {
                HealthStatus::Unavailable
            },
            round_trip_time: None,
            consecutive_failures: 0,
        }
    }
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
