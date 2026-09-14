//! Linux process boundary used by platform transport backends.

use std::fs;
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
    active_interface: Option<String>,
}

impl<R: CommandRunner> LinuxWireGuardBackend<R> {
    /// Creates a backend from validated Linux tools.
    ///
    /// # Errors
    ///
    /// Returns invalid configuration when tool paths or the private-key path
    /// cannot be safely passed as literal command arguments.
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
            "peer".into(),
            encode_key(&profile.peer_public_key),
            "endpoint".into(),
            endpoint(&profile.endpoint),
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
        if let Err(setup_error) = self.configure(interface, profile, context) {
            if let Err(cleanup_error) = self.delete_interface(interface) {
                return Err(TransportError::Network(format!(
                    "WireGuard setup failed: {setup_error}; cleanup failed: {cleanup_error}"
                )));
            }
            return Err(setup_error);
        }
        self.active_interface = Some(interface.into());
        Ok(())
    }

    fn bring_down(&mut self, interface: &str) -> Result<(), TransportError> {
        if self.active_interface.as_deref() != Some(interface) {
            return Err(TransportError::NotConnected);
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
