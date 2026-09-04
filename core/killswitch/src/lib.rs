//! Platform-neutral, fail-secure kill switch state machine.

#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt::{Display, Formatter};

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
