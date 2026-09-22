//! Configuration and lifecycle support for the Cyberia Linux client.

#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::net::IpAddr;
use std::num::{NonZeroU16, NonZeroU32};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use fs2::FileExt;
use serde::Deserialize;

use cyberia_killswitch::ConnectionError;
use cyberia_killswitch::linux::NftablesRunner;
use cyberia_killswitch::linux_connection::{LinuxConnectionSettings, LinuxWireGuardConnection};
use cyberia_transport::linux::{CommandRunner, LinuxDnsTools, LinuxTools};
use cyberia_transport::{
    AllowedIp, CancellationToken, DnsConfig, Endpoint, Session, TunnelAddress, WireGuardConfig,
};

const MAXIMUM_CONFIG_SIZE: u64 = 1024 * 1024;

/// Exclusive ownership of one managed interface lifecycle.
pub struct InterfaceLease {
    _file: File,
}

/// Acquires a nonblocking exclusive lease for a validated interface name.
///
/// # Errors
///
/// Returns [`LeaseError::InUse`] while another client owns the same interface,
/// or an error for unsafe runtime state.
pub fn acquire_interface_lease(
    runtime_directory: &Path,
    interface: &str,
) -> Result<InterfaceLease, LeaseError> {
    validate_lease_directory(runtime_directory)?;
    if !valid_interface_name(interface) {
        return Err(LeaseError::UnsafeInterface);
    }
    let path = runtime_directory.join(format!("interface-{interface}.lock"));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(LeaseError::Io)?;
    let metadata = file.metadata().map_err(LeaseError::Io)?;
    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(LeaseError::UnsafeState);
    }
    file.try_lock_exclusive().map_err(|error| {
        if error.kind() == std::io::ErrorKind::WouldBlock {
            LeaseError::InUse
        } else {
            LeaseError::Io(error)
        }
    })?;
    Ok(InterfaceLease { _file: file })
}

fn validate_lease_directory(runtime_directory: &Path) -> Result<(), LeaseError> {
    if !runtime_directory.is_absolute() {
        return Err(LeaseError::UnsafeState);
    }
    let metadata = std::fs::symlink_metadata(runtime_directory).map_err(LeaseError::Io)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(LeaseError::UnsafeState);
    }
    Ok(())
}

fn valid_interface_name(interface: &str) -> bool {
    !interface.is_empty()
        && interface.len() <= 15
        && interface.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'.'
        })
}

#[derive(Debug)]
pub enum LeaseError {
    UnsafeInterface,
    UnsafeState,
    InUse,
    Io(std::io::Error),
}

impl Display for LeaseError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsafeInterface => formatter.write_str("client interface name is unsafe"),
            Self::UnsafeState => formatter.write_str("client interface lock state is unsafe"),
            Self::InUse => formatter.write_str("another client already manages this interface"),
            Self::Io(error) => write!(formatter, "client interface lease failed: {error}"),
        }
    }
}

impl Error for LeaseError {}

/// Private local inputs needed to build one managed Linux connection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub interface: String,
    pub runtime_directory: PathBuf,
    pub endpoint_address: IpAddr,
    pub endpoint_port: u16,
    pub peer_public_key_hex: String,
    pub tunnel_addresses: Vec<String>,
    pub allowed_ips: Vec<String>,
    pub dns_resolvers: Vec<IpAddr>,
    pub mtu: u16,
    pub persistent_keepalive_seconds: Option<u16>,
    pub routing_mark: u32,
    pub connect_timeout_seconds: u64,
    pub always_on: bool,
    pub tools: ClientTools,
}

/// Operator-controlled executable and secret-key paths.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClientTools {
    pub ip: PathBuf,
    pub wg: PathBuf,
    pub nft: PathBuf,
    pub resolvectl: PathBuf,
    pub private_key: PathBuf,
}

/// Reads one bounded, private, non-symlink JSON configuration file.
///
/// # Errors
///
/// Returns an error for a relative path, unsafe metadata, oversized input,
/// malformed JSON, trailing data or unknown fields.
pub fn load_config(path: &Path) -> Result<ClientConfig, ConfigError> {
    if !path.is_absolute() {
        return Err(ConfigError::UnsafeFile);
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| {
            if error.raw_os_error() == Some(libc::ELOOP) {
                ConfigError::UnsafeFile
            } else {
                ConfigError::Io(error)
            }
        })?;
    let metadata = file.metadata().map_err(ConfigError::Io)?;
    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(ConfigError::UnsafeFile);
    }
    if metadata.len() > MAXIMUM_CONFIG_SIZE {
        return Err(ConfigError::Oversized);
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_| ConfigError::Oversized)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.by_ref()
        .take(MAXIMUM_CONFIG_SIZE + 1)
        .read_to_end(&mut bytes)
        .map_err(ConfigError::Io)?;
    if bytes.len() as u64 > MAXIMUM_CONFIG_SIZE {
        return Err(ConfigError::Oversized);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(&bytes);
    let config = ClientConfig::deserialize(&mut deserializer).map_err(ConfigError::Json)?;
    deserializer.end().map_err(ConfigError::Json)?;
    validate_private_directory(&config.runtime_directory)?;
    Ok(config)
}

fn validate_private_directory(path: &Path) -> Result<(), ConfigError> {
    if !path.is_absolute() {
        return Err(ConfigError::UnsafeRuntimeDirectory);
    }
    let metadata = std::fs::symlink_metadata(path).map_err(ConfigError::Io)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(ConfigError::UnsafeRuntimeDirectory);
    }
    Ok(())
}

impl ClientConfig {
    /// Converts serialized values into managed-connection settings.
    ///
    /// # Errors
    ///
    /// Returns an error for zero numeric values, malformed keys or CIDRs. The
    /// connection constructor performs the remaining transport validation.
    pub fn into_connection_settings(self) -> Result<LinuxConnectionSettings, ConfigError> {
        let endpoint_port = NonZeroU16::new(self.endpoint_port)
            .ok_or(ConfigError::InvalidField("endpoint_port must be nonzero"))?;
        let routing_mark = NonZeroU32::new(self.routing_mark)
            .ok_or(ConfigError::InvalidField("routing_mark must be nonzero"))?;
        let peer_public_key = decode_key(&self.peer_public_key_hex)?;
        let tunnel_addresses = self
            .tunnel_addresses
            .iter()
            .map(|value| {
                parse_cidr(value).map(|(address, prefix_length)| TunnelAddress {
                    address,
                    prefix_length,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let allowed_ips = self
            .allowed_ips
            .iter()
            .map(|value| {
                parse_cidr(value).map(|(network, prefix_length)| AllowedIp {
                    network,
                    prefix_length,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(LinuxConnectionSettings {
            interface: self.interface,
            profile: WireGuardConfig {
                peer_public_key,
                endpoint: Endpoint {
                    host: self.endpoint_address.to_string(),
                    port: endpoint_port,
                },
                tunnel_addresses,
                allowed_ips,
                persistent_keepalive_seconds: self.persistent_keepalive_seconds,
                mtu: self.mtu,
            },
            dns: DnsConfig {
                resolvers: self.dns_resolvers,
            },
            tools: LinuxTools {
                ip: self.tools.ip,
                wg: self.tools.wg,
                private_key: self.tools.private_key,
            },
            dns_tools: LinuxDnsTools {
                resolvectl: self.tools.resolvectl,
            },
            routing_mark,
            connect_timeout: std::time::Duration::from_secs(self.connect_timeout_seconds),
            always_on: self.always_on,
        })
    }
}

/// Narrow lifecycle used by the executable and deterministic tests.
pub trait ManagedClientConnection {
    /// Establishes the tunnel with cooperative cancellation.
    ///
    /// # Errors
    ///
    /// Returns the managed lifecycle error while retaining fail-secure state.
    fn connect(&mut self, cancellation: CancellationToken) -> Result<Session, ConnectionError>;

    /// Restores blocking and tears down the tunnel.
    ///
    /// # Errors
    ///
    /// Returns an error when protected teardown cannot complete.
    fn disconnect(&mut self) -> Result<(), ConnectionError>;

    /// Disables filtering after teardown for non-always-on clients.
    ///
    /// # Errors
    ///
    /// Returns an error when the effective firewall policy cannot be updated.
    fn disable(&mut self) -> Result<(), ConnectionError>;
}

impl<C: CommandRunner, D: CommandRunner, N: NftablesRunner> ManagedClientConnection
    for LinuxWireGuardConnection<C, D, N>
{
    fn connect(&mut self, cancellation: CancellationToken) -> Result<Session, ConnectionError> {
        self.connect(cancellation)
    }

    fn disconnect(&mut self) -> Result<(), ConnectionError> {
        self.disconnect()
    }

    fn disable(&mut self) -> Result<(), ConnectionError> {
        self.disable()
    }
}

/// Connects, waits for a shutdown signal and tears down in fail-secure order.
///
/// # Errors
///
/// Returns the first connection or teardown error. A failed connection attempts
/// to release filtering only when always-on mode is disabled.
pub fn run_until_shutdown<C: ManagedClientConnection>(
    connection: &mut C,
    always_on: bool,
    cancellation: CancellationToken,
    wait_for_shutdown: impl FnOnce(),
) -> Result<(), ConnectionError> {
    if let Err(error) = connection.connect(cancellation) {
        if !always_on {
            let _ = connection.disable();
        }
        return Err(error);
    }
    wait_for_shutdown();
    connection.disconnect()?;
    if !always_on {
        connection.disable()?;
    }
    Ok(())
}

fn decode_key(value: &str) -> Result<[u8; 32], ConfigError> {
    if value.len() != 64 {
        return Err(ConfigError::InvalidField(
            "peer_public_key_hex must contain 64 hexadecimal characters",
        ));
    }
    let mut key = [0; 32];
    for (index, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|_| {
            ConfigError::InvalidField("peer_public_key_hex must contain 64 hexadecimal characters")
        })?;
    }
    Ok(key)
}

fn parse_cidr(value: &str) -> Result<(IpAddr, u8), ConfigError> {
    let (address, prefix_length) = value
        .split_once('/')
        .ok_or(ConfigError::InvalidField("invalid CIDR prefix"))?;
    let address = address
        .parse::<IpAddr>()
        .map_err(|_| ConfigError::InvalidField("invalid CIDR address"))?;
    let prefix_length = prefix_length
        .parse::<u8>()
        .map_err(|_| ConfigError::InvalidField("invalid CIDR prefix length"))?;
    let maximum = if address.is_ipv4() { 32 } else { 128 };
    if prefix_length > maximum {
        return Err(ConfigError::InvalidField(
            "CIDR prefix length exceeds address family",
        ));
    }
    Ok((address, prefix_length))
}

#[derive(Debug)]
pub enum ConfigError {
    UnsafeFile,
    Oversized,
    Io(std::io::Error),
    Json(serde_json::Error),
    InvalidField(&'static str),
    UnsafeRuntimeDirectory,
}

impl Display for ConfigError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsafeFile => {
                formatter.write_str("client configuration must be an absolute private regular file")
            }
            Self::Oversized => formatter.write_str("client configuration exceeds 1 MiB"),
            Self::Io(error) => write!(formatter, "client configuration I/O failed: {error}"),
            Self::Json(error) => write!(formatter, "client configuration JSON is invalid: {error}"),
            Self::InvalidField(reason) => {
                write!(formatter, "client configuration is invalid: {reason}")
            }
            Self::UnsafeRuntimeDirectory => formatter
                .write_str("client runtime directory must be an absolute private directory"),
        }
    }
}

impl Error for ConfigError {}
