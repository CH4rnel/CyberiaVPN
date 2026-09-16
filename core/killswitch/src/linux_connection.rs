//! Managed composition of the Linux `WireGuard` and nftables backends.

use std::error::Error;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use cyberia_transport::linux::{
    CommandRunner, LinuxTools, LinuxWireGuardBackend, SystemCommandRunner,
};
use cyberia_transport::{
    CancellationToken, ConnectContext, Session, Transport, TransportConfig, TransportError,
    TransportHealth, TransportKind, WireGuardAdapter, WireGuardConfig,
};

use crate::linux::{
    NftablesBackend, NftablesConfig, NftablesError, NftablesRunner, SystemNftablesRunner,
};
use crate::{ConnectionController, ConnectionError, FirewallError, KillSwitch, TrafficPolicy};

/// Inputs required to assemble one managed Linux `WireGuard` connection.
pub struct LinuxConnectionSettings {
    pub interface: String,
    pub profile: WireGuardConfig,
    pub tools: LinuxTools,
    pub routing_mark: NonZeroU32,
    pub connect_timeout: Duration,
    pub always_on: bool,
}

type LinuxController<C, N> =
    ConnectionController<WireGuardAdapter<LinuxWireGuardBackend<C>>, NftablesBackend<N>>;

/// Owns the complete Linux tunnel, routing and firewall lifecycle.
pub struct LinuxWireGuardConnection<C, N> {
    controller: LinuxController<C, N>,
    transport: TransportConfig,
}

impl<C: CommandRunner, N: NftablesRunner> LinuxWireGuardConnection<C, N> {
    /// Builds a connection with injectable platform runners.
    ///
    /// # Errors
    ///
    /// Returns an error for a hostname endpoint, invalid tools/profile or an
    /// initial firewall policy that cannot be applied.
    pub fn with_runners(
        settings: LinuxConnectionSettings,
        command_runner: C,
        nftables_runner: N,
    ) -> Result<Self, LinuxConnectionBuildError> {
        let endpoint_address = settings
            .profile
            .endpoint
            .host
            .parse::<IpAddr>()
            .map_err(|_| LinuxConnectionBuildError::EndpointMustBeIpAddress)?;
        let endpoint = settings.profile.endpoint.clone();
        let transport = TransportConfig {
            kind: TransportKind::WireGuard,
            endpoint: endpoint.clone(),
            connect_timeout: settings.connect_timeout,
        };
        transport.validate()?;
        let backend =
            LinuxWireGuardBackend::new(settings.tools, command_runner, settings.routing_mark)?;
        let adapter = WireGuardAdapter::new(settings.interface, settings.profile, backend)?;
        let firewall = NftablesBackend::new(
            NftablesConfig {
                endpoint_address,
                endpoint_port: endpoint.port,
            },
            nftables_runner,
        );
        let controller =
            ConnectionController::new(KillSwitch::new(settings.always_on), adapter, firewall)?;
        Ok(Self {
            controller,
            transport,
        })
    }

    /// Arms the firewall and establishes the configured tunnel within its
    /// declared timeout.
    ///
    /// # Errors
    ///
    /// Returns a firewall or transport lifecycle error while preserving the
    /// controller's fail-secure policy.
    pub fn connect(&mut self, cancellation: CancellationToken) -> Result<Session, ConnectionError> {
        let context = ConnectContext {
            deadline: Instant::now() + self.transport.connect_timeout,
            cancellation,
        };
        self.controller.connect(&self.transport, &context)
    }

    /// Blocks non-tunnel traffic before removing routes and the interface.
    ///
    /// # Errors
    ///
    /// Returns the lifecycle error when blocking or teardown cannot complete.
    pub fn disconnect(&mut self) -> Result<(), ConnectionError> {
        self.controller.disconnect()
    }

    pub fn health(&mut self) -> TransportHealth {
        self.controller.transport_mut().health()
    }

    pub fn policy(&self) -> &TrafficPolicy {
        self.controller.policy()
    }

    /// Disables filtering after a successful teardown when always-on mode is
    /// not configured.
    ///
    /// # Errors
    ///
    /// Returns a state or firewall error without changing effective policy.
    pub fn disable(&mut self) -> Result<(), ConnectionError> {
        self.controller.disable()
    }
}

impl LinuxWireGuardConnection<SystemCommandRunner, SystemNftablesRunner> {
    /// Builds the production connection from validated system executables.
    ///
    /// # Errors
    ///
    /// Returns an error before use when `nft`, `ip`, `wg`, the key file, the
    /// profile or the initial firewall policy is invalid.
    pub fn system(
        settings: LinuxConnectionSettings,
        nft_executable: PathBuf,
    ) -> Result<Self, LinuxConnectionBuildError> {
        let nftables = SystemNftablesRunner::new(nft_executable)?;
        Self::with_runners(settings, SystemCommandRunner, nftables)
    }
}

#[derive(Debug)]
pub enum LinuxConnectionBuildError {
    EndpointMustBeIpAddress,
    Firewall(FirewallError),
    Nftables(NftablesError),
    Transport(TransportError),
}

impl From<FirewallError> for LinuxConnectionBuildError {
    fn from(error: FirewallError) -> Self {
        Self::Firewall(error)
    }
}

impl From<NftablesError> for LinuxConnectionBuildError {
    fn from(error: NftablesError) -> Self {
        Self::Nftables(error)
    }
}

impl From<TransportError> for LinuxConnectionBuildError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

impl Display for LinuxConnectionBuildError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EndpointMustBeIpAddress => {
                formatter.write_str("Linux WireGuard endpoint must be an IP address")
            }
            Self::Firewall(error) => error.fmt(formatter),
            Self::Nftables(error) => error.fmt(formatter),
            Self::Transport(error) => error.fmt(formatter),
        }
    }
}

impl Error for LinuxConnectionBuildError {}
