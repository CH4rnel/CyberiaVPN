//! Configuration and lifecycle support for the Cyberia Linux client.

#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs;
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde::Deserialize;

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

#[derive(Debug)]
pub enum ConfigError {
    UnsafeFile,
    Oversized,
    Io(std::io::Error),
    Json(serde_json::Error),
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
        }
    }
}

impl Error for ConfigError {}
