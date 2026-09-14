//! Linux process boundary used by platform transport backends.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::TransportError;

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
