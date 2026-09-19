//! Configuration and lifecycle support for the Cyberia Linux client.

#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs;
use std::net::IpAddr;
use std::num::{NonZeroU16, NonZeroU32};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use cyberia_killswitch::linux_connection::LinuxConnectionSettings;
use cyberia_transport::linux::{LinuxDnsTools, LinuxTools};
use cyberia_transport::{AllowedIp, DnsConfig, Endpoint, TunnelAddress, WireGuardConfig};

const MAXIMUM_CONFIG_SIZE: u64 = 1024 * 1024;

/// Private local inputs needed to build one managed Linux connection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub interface: String,
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
    let metadata = fs::symlink_metadata(path).map_err(ConfigError::Io)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(ConfigError::UnsafeFile);
    }
    if metadata.len() > MAXIMUM_CONFIG_SIZE {
        return Err(ConfigError::Oversized);
    }
    let bytes = fs::read(path).map_err(ConfigError::Io)?;
    let mut deserializer = serde_json::Deserializer::from_slice(&bytes);
    let config = ClientConfig::deserialize(&mut deserializer).map_err(ConfigError::Json)?;
    deserializer.end().map_err(ConfigError::Json)?;
    Ok(config)
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
        }
    }
}

impl Error for ConfigError {}
