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

/// Coordinates a transport with the kill-switch state machine. It arms blocking
/// before connect and restores it before every disconnect attempt.
pub struct ConnectionController<T> {
    kill_switch: KillSwitch,
    transport: T,
}

impl<T: Transport> ConnectionController<T> {
    pub fn new(kill_switch: KillSwitch, transport: T) -> Self {
        Self {
            kill_switch,
            transport,
        }
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
        self.kill_switch.enable();
        let session = self
            .transport
            .connect(config, context)
            .map_err(ConnectionError::Transport)?;
        if let Err(error) = self.kill_switch.tunnel_established(&session.id) {
            self.kill_switch.tunnel_lost();
            let _ = self.transport.disconnect();
            return Err(ConnectionError::KillSwitch(error));
        }
        Ok(session)
    }

    /// Restores blocking before attempting transport teardown.
    ///
    /// # Errors
    ///
    /// Returns the transport error while retaining `BlockNonTunnel` if teardown
    /// fails, so traffic cannot bypass a possibly live tunnel.
    pub fn disconnect(&mut self) -> Result<(), ConnectionError> {
        self.kill_switch.tunnel_lost();
        self.transport
            .disconnect()
            .map_err(ConnectionError::Transport)
    }

    /// Disables filtering only when the connection is already torn down.
    ///
    /// # Errors
    ///
    /// Returns `KillSwitchError::AlwaysOn` or `KillSwitchError::NotEnabled`
    /// without changing an active tunnel policy.
    pub fn disable(&mut self) -> Result<(), KillSwitchError> {
        if matches!(self.kill_switch.policy(), TrafficPolicy::TunnelOnly { .. }) {
            return Err(KillSwitchError::NotEnabled);
        }
        self.kill_switch.disable()
    }
}

#[derive(Debug)]
pub enum ConnectionError {
    KillSwitch(KillSwitchError),
    Transport(TransportError),
}
impl Display for ConnectionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KillSwitch(error) => error.fmt(formatter),
            Self::Transport(error) => error.fmt(formatter),
        }
    }
}
impl Error for ConnectionError {}
