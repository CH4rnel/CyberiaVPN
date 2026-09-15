//! Platform-neutral, fail-secure kill switch state machine.

#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt::{Display, Formatter};

use cyberia_transport::{ConnectContext, Session, Transport, TransportConfig, TransportError};

#[cfg(target_os = "linux")]
pub mod linux;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrafficPolicy {
    Disabled,
    BlockNonTunnel,
    TunnelOnly { interface: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KillSwitch {
    always_on: bool,
    policy: TrafficPolicy,
}

impl KillSwitch {
    pub fn new(always_on: bool) -> Self {
        Self {
            always_on,
            policy: if always_on {
                TrafficPolicy::BlockNonTunnel
            } else {
                TrafficPolicy::Disabled
            },
        }
    }

    pub fn policy(&self) -> &TrafficPolicy {
        &self.policy
    }

    pub fn enable(&mut self) {
        self.policy = TrafficPolicy::BlockNonTunnel;
    }

    /// Disables filtering when the controller is not configured as always-on.
    ///
    /// # Errors
    ///
    /// Returns [`KillSwitchError::AlwaysOn`] without changing policy when an
    /// always-on controller receives a disable request.
    pub fn disable(&mut self) -> Result<(), KillSwitchError> {
        if self.always_on {
            return Err(KillSwitchError::AlwaysOn);
        }
        self.policy = TrafficPolicy::Disabled;
        Ok(())
    }

    /// Allows traffic only through a validated tunnel interface.
    ///
    /// # Errors
    ///
    /// Returns [`KillSwitchError::NotEnabled`] if blocking was not armed, or
    /// [`KillSwitchError::InvalidInterface`] for an unsafe interface name. The
    /// previous policy is retained on every error.
    pub fn tunnel_established(&mut self, interface: &str) -> Result<(), KillSwitchError> {
        if self.policy == TrafficPolicy::Disabled {
            return Err(KillSwitchError::NotEnabled);
        }
        if !valid_interface(interface) {
            return Err(KillSwitchError::InvalidInterface);
        }
        self.policy = TrafficPolicy::TunnelOnly {
            interface: interface.to_owned(),
        };
        Ok(())
    }

    /// Restores blocking before an adapter tears down tunnel resources.
    pub fn tunnel_lost(&mut self) {
        if self.policy != TrafficPolicy::Disabled {
            self.policy = TrafficPolicy::BlockNonTunnel;
        }
    }
}

fn valid_interface(interface: &str) -> bool {
    !interface.is_empty()
        && interface.len() <= 63
        && interface.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'.'
        })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KillSwitchError {
    AlwaysOn,
    NotEnabled,
    InvalidInterface,
}

impl Display for KillSwitchError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlwaysOn => formatter.write_str("always-on kill switch cannot be disabled"),
            Self::NotEnabled => formatter.write_str("kill switch is not enabled"),
            Self::InvalidInterface => formatter.write_str("invalid tunnel interface name"),
        }
    }
}

impl Error for KillSwitchError {}

/// Platform boundary that makes one complete traffic policy effective.
/// Implementations must apply changes atomically and leave the previous policy
/// effective when an update fails.
pub trait Firewall: Send {
    /// Applies a complete policy at the operating-system boundary.
    ///
    /// # Errors
    ///
    /// Returns an operational error when the policy cannot be made effective.
    fn apply(&mut self, policy: &TrafficPolicy) -> Result<(), FirewallError>;
}

/// Explicit in-memory backend for domain tests.
#[derive(Debug, Default)]
pub struct MemoryFirewall;

impl Firewall for MemoryFirewall {
    fn apply(&mut self, _: &TrafficPolicy) -> Result<(), FirewallError> {
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FirewallError(pub String);

impl Display for FirewallError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "firewall policy failed: {}", self.0)
    }
}

impl Error for FirewallError {}

/// Coordinates a transport with the kill-switch state machine. It arms blocking
/// before connect and restores it before every disconnect attempt.
pub struct ConnectionController<T, F> {
    kill_switch: KillSwitch,
    transport: T,
    firewall: F,
}

impl<T: Transport, F: Firewall> ConnectionController<T, F> {
    /// Creates a controller only after applying its initial traffic policy.
    ///
    /// # Errors
    ///
    /// Returns the firewall error instead of creating a controller whose
    /// in-memory policy is not effective at the operating-system boundary.
    pub fn new(
        kill_switch: KillSwitch,
        transport: T,
        mut firewall: F,
    ) -> Result<Self, FirewallError> {
        firewall.apply(kill_switch.policy())?;
        Ok(Self {
            kill_switch,
            transport,
            firewall,
        })
    }

    pub fn policy(&self) -> &TrafficPolicy {
        self.kill_switch.policy()
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Connects after arming non-tunnel blocking.
    ///
    /// # Errors
    ///
    /// Returns the transport error while retaining `BlockNonTunnel` when a
    /// tunnel cannot be created or its interface cannot be accepted.
    pub fn connect(
        &mut self,
        config: &TransportConfig,
        context: &ConnectContext,
    ) -> Result<Session, ConnectionError> {
        let mut blocking = self.kill_switch.clone();
        blocking.enable();
        self.firewall
            .apply(blocking.policy())
            .map_err(ConnectionError::Firewall)?;
        self.kill_switch = blocking;
        let session = self
            .transport
            .connect(config, context)
            .map_err(ConnectionError::Transport)?;
        let mut tunnel = self.kill_switch.clone();
        if let Err(error) = tunnel.tunnel_established(&session.id) {
            let _ = self.transport.disconnect();
            return Err(ConnectionError::KillSwitch(error));
        }
        if let Err(error) = self.firewall.apply(tunnel.policy()) {
            let _ = self.transport.disconnect();
            return Err(ConnectionError::Firewall(error));
        }
        self.kill_switch = tunnel;
        Ok(session)
    }

    /// Restores blocking before attempting transport teardown.
    ///
    /// # Errors
    ///
    /// Returns the transport error while retaining `BlockNonTunnel` if teardown
    /// fails, so traffic cannot bypass a possibly live tunnel.
    pub fn disconnect(&mut self) -> Result<(), ConnectionError> {
        let mut blocking = self.kill_switch.clone();
        blocking.tunnel_lost();
        self.firewall
            .apply(blocking.policy())
            .map_err(ConnectionError::Firewall)?;
        self.kill_switch = blocking;
        self.transport
            .disconnect()
            .map_err(ConnectionError::Transport)
    }

    /// Disables filtering only when the connection is already torn down.
    ///
    /// # Errors
    ///
    /// Returns a state-machine or firewall error without changing the effective
    /// policy.
    pub fn disable(&mut self) -> Result<(), ConnectionError> {
        if matches!(self.kill_switch.policy(), TrafficPolicy::TunnelOnly { .. }) {
            return Err(ConnectionError::KillSwitch(KillSwitchError::NotEnabled));
        }
        let mut disabled = self.kill_switch.clone();
        disabled.disable().map_err(ConnectionError::KillSwitch)?;
        self.firewall
            .apply(disabled.policy())
            .map_err(ConnectionError::Firewall)?;
        self.kill_switch = disabled;
        Ok(())
    }
}

#[derive(Debug)]
pub enum ConnectionError {
    Firewall(FirewallError),
    KillSwitch(KillSwitchError),
    Transport(TransportError),
}
impl Display for ConnectionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Firewall(error) => error.fmt(formatter),
            Self::KillSwitch(error) => error.fmt(formatter),
            Self::Transport(error) => error.fmt(formatter),
        }
    }
}
impl Error for ConnectionError {}
