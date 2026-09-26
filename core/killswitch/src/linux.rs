//! Linux nftables policy rendering for the kill switch.

use std::net::IpAddr;
use std::num::NonZeroU16;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::{error::Error, fmt, fs, io::Write};

use crate::{Firewall, FirewallError, TrafficPolicy};

const TABLE_NAME: &str = "cyberia_vpn";

/// Network values that must remain reachable while non-tunnel traffic is
/// blocked. The endpoint is restricted to an IP address so nftables never
/// performs name resolution while applying the policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NftablesConfig {
    pub endpoint_address: IpAddr,
    pub endpoint_port: NonZeroU16,
}

/// Injectable nftables boundary used by the Linux policy backend.
pub trait NftablesRunner: Send {
    /// Applies one complete ruleset transaction.
    ///
    /// # Errors
    ///
    /// Returns a bounded operational error when nftables cannot accept the
    /// transaction.
    fn apply(&mut self, rules: &str) -> Result<(), NftablesError>;
}

/// Applies kill-switch policies with an injected nftables runner.
pub struct NftablesBackend<R> {
    config: NftablesConfig,
    runner: R,
}

impl<R: NftablesRunner> NftablesBackend<R> {
    pub fn new(config: NftablesConfig, runner: R) -> Self {
        Self { config, runner }
    }

    /// Renders and atomically applies one policy.
    ///
    /// # Errors
    ///
    /// Returns an error without running nftables when rendering fails, or the
    /// runner error when the transaction cannot be applied.
    pub fn apply(&mut self, policy: &TrafficPolicy) -> Result<(), NftablesError> {
        let rules = self.config.render(policy)?;
        self.runner.apply(&rules)
    }
}

impl<R: NftablesRunner> Firewall for NftablesBackend<R> {
    fn apply(&mut self, policy: &TrafficPolicy) -> Result<(), FirewallError> {
        Self::apply(self, policy).map_err(|error| FirewallError(error.to_string()))
    }
}

/// Shell-free process runner for the system `nft` executable.
pub struct SystemNftablesRunner {
    executable: PathBuf,
}

impl SystemNftablesRunner {
    /// Creates a runner for an operator-controlled executable.
    ///
    /// # Errors
    ///
    /// Returns [`NftablesError::InvalidExecutable`] unless the path is absolute
    /// and names an executable regular file rather than a symbolic link.
    pub fn new(executable: PathBuf) -> Result<Self, NftablesError> {
        validate_executable(&executable)?;
        Ok(Self { executable })
    }
}

impl NftablesRunner for SystemNftablesRunner {
    fn apply(&mut self, rules: &str) -> Result<(), NftablesError> {
        let mut child = Command::new(&self.executable)
            .args(["--file", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| NftablesError::Command(format!("failed to start nft: {error}")))?;
        let write_result = child
            .stdin
            .take()
            .ok_or_else(|| NftablesError::Command("nft stdin is unavailable".into()))?
            .write_all(rules.as_bytes());
        if let Err(error) = write_result {
            let _ = child.kill();
            let _ = child.wait();
            return Err(NftablesError::Command(format!(
                "failed to write nft rules: {error}"
            )));
        }
        let output = child
            .wait_with_output()
            .map_err(|error| NftablesError::Command(format!("failed to wait for nft: {error}")))?;
        if output.status.success() {
            return Ok(());
        }
        let reason: String = String::from_utf8_lossy(&output.stderr)
            .chars()
            .take(256)
            .collect();
        Err(NftablesError::Command(format!(
            "nft exited with {}: {}",
            output.status,
            reason.trim()
        )))
    }
}

impl NftablesConfig {
    /// Renders a complete ruleset for the private Cyberia VPN table.
    ///
    /// Applying the returned input through `nft --file -` updates the table in
    /// one nftables transaction. The rules never flush tables owned by other
    /// applications.
    ///
    /// # Errors
    ///
    /// Returns [`NftablesError::InvalidInterface`] when a caller supplies a
    /// tunnel policy that was not produced by the validated state machine.
    pub fn render(&self, policy: &TrafficPolicy) -> Result<String, NftablesError> {
        let mut rules = format!("add table inet {TABLE_NAME}\nflush table inet {TABLE_NAME}\n");
        if policy == &TrafficPolicy::Disabled {
            rules.push_str(&format!("delete table inet {TABLE_NAME}\n"));
            return Ok(rules);
        }

        rules.push_str(&format!(
            "add chain inet {TABLE_NAME} output {{ type filter hook output priority -100; policy drop; }}\n"
        ));
        rules.push_str(&format!(
            "add rule inet {TABLE_NAME} output oifname \"lo\" accept\n"
        ));
        let address_family = if self.endpoint_address.is_ipv4() {
            "ip"
        } else {
            "ip6"
        };
        rules.push_str(&format!(
            "add rule inet {TABLE_NAME} output {address_family} daddr {} udp dport {} accept\n",
            self.endpoint_address, self.endpoint_port
        ));
        if let TrafficPolicy::TunnelOnly { interface } = policy {
            if !valid_interface(interface) {
                return Err(NftablesError::InvalidInterface);
            }
            rules.push_str(&format!(
                "add rule inet {TABLE_NAME} output oifname \"{interface}\" accept\n"
            ));
        }
        Ok(rules)
    }
}

fn valid_interface(interface: &str) -> bool {
    !interface.is_empty()
        && interface.len() <= 63
        && interface.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'.'
        })
}

fn validate_executable(path: &Path) -> Result<(), NftablesError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| NftablesError::InvalidExecutable)?;
    if !path.is_absolute()
        || !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o111 == 0
    {
        return Err(NftablesError::InvalidExecutable);
    }
    Ok(())
}

/// A policy cannot be represented safely as nftables input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NftablesError {
    InvalidInterface,
    InvalidExecutable,
    Command(String),
}

impl fmt::Display for NftablesError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInterface => formatter.write_str("invalid nftables tunnel interface"),
            Self::InvalidExecutable => formatter.write_str("invalid nftables executable"),
            Self::Command(reason) => write!(formatter, "nftables command failed: {reason}"),
        }
    }
}

impl Error for NftablesError {}
