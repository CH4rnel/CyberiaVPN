use std::num::NonZeroU16;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cyberia_killswitch::{
    ConnectionController, Firewall, FirewallError, KillSwitch, MemoryFirewall, TrafficPolicy,
};
use cyberia_transport::{
    CancellationToken, ConnectContext, Endpoint, HealthStatus, Session, Transport, TransportConfig,
    TransportError, TransportHealth, TransportKind,
};

struct Fake {
    connected: bool,
    fail_connect: bool,
    fail_disconnect: bool,
}

struct RecordingFirewall {
    policies: Arc<Mutex<Vec<TrafficPolicy>>>,
    fail_at: Option<usize>,
}

impl Firewall for RecordingFirewall {
    fn apply(&mut self, policy: &TrafficPolicy) -> Result<(), FirewallError> {
        let mut policies = self.policies.lock().unwrap();
        if self.fail_at == Some(policies.len() + 1) {
            return Err(FirewallError("injected".into()));
        }
        policies.push(policy.clone());
        Ok(())
    }
}
impl Transport for Fake {
    fn kind(&self) -> TransportKind {
        TransportKind::WireGuard
    }
    fn connect(
        &mut self,
        _: &TransportConfig,
        _: &ConnectContext,
    ) -> Result<Session, TransportError> {
        if self.fail_connect {
            return Err(TransportError::Network("unreachable".into()));
        };
        self.connected = true;
        Ok(Session {
            id: "wg0".into(),
            transport: TransportKind::WireGuard,
            established_at: Instant::now(),
        })
    }
    fn disconnect(&mut self) -> Result<(), TransportError> {
        if self.fail_disconnect {
            return Err(TransportError::Network("teardown".into()));
        };
        self.connected = false;
        Ok(())
    }
    fn health(&self) -> TransportHealth {
        TransportHealth {
            status: if self.connected {
                HealthStatus::Healthy
            } else {
                HealthStatus::Unavailable
            },
            round_trip_time: None,
            consecutive_failures: 0,
        }
    }
}
fn config() -> TransportConfig {
    TransportConfig {
        kind: TransportKind::WireGuard,
        endpoint: Endpoint {
            host: "node".into(),
            port: NonZeroU16::new(51820).unwrap(),
        },
        connect_timeout: Duration::from_secs(1),
    }
}
fn context() -> ConnectContext {
    ConnectContext {
        deadline: Instant::now() + Duration::from_secs(1),
        cancellation: CancellationToken::default(),
    }
}

#[test]
fn controller_allows_only_tunnel_after_connect() {
    let mut controller = ConnectionController::new(
        KillSwitch::new(false),
        Fake {
            connected: false,
            fail_connect: false,
            fail_disconnect: false,
        },
        MemoryFirewall,
    )
    .unwrap();
    controller.connect(&config(), &context()).unwrap();
    assert_eq!(
        controller.policy(),
        &TrafficPolicy::TunnelOnly {
            interface: "wg0".into()
        }
    );
    controller.disconnect().unwrap();
    assert_eq!(controller.policy(), &TrafficPolicy::BlockNonTunnel);
    controller.disable().unwrap();
    assert_eq!(controller.policy(), &TrafficPolicy::Disabled);
}
#[test]
fn controller_stays_blocking_after_connect_or_teardown_failure() {
    let mut failed_connect = ConnectionController::new(
        KillSwitch::new(false),
        Fake {
            connected: false,
            fail_connect: true,
            fail_disconnect: false,
        },
        MemoryFirewall,
    )
    .unwrap();
    assert!(failed_connect.connect(&config(), &context()).is_err());
    assert_eq!(failed_connect.policy(), &TrafficPolicy::BlockNonTunnel);
    let mut failed_disconnect = ConnectionController::new(
        KillSwitch::new(false),
        Fake {
            connected: false,
            fail_connect: false,
            fail_disconnect: true,
        },
        MemoryFirewall,
    )
    .unwrap();
    failed_disconnect.connect(&config(), &context()).unwrap();
    assert!(failed_disconnect.disconnect().is_err());
    assert_eq!(failed_disconnect.policy(), &TrafficPolicy::BlockNonTunnel);
}

#[test]
fn controller_applies_firewall_transitions_around_transport_lifecycle() {
    let policies = Arc::new(Mutex::new(Vec::new()));
    let firewall = RecordingFirewall {
        policies: Arc::clone(&policies),
        fail_at: None,
    };
    let mut controller = ConnectionController::new(
        KillSwitch::new(false),
        Fake {
            connected: false,
            fail_connect: false,
            fail_disconnect: false,
        },
        firewall,
    )
    .unwrap();

    controller.connect(&config(), &context()).unwrap();
    controller.disconnect().unwrap();
    controller.disable().unwrap();

    assert_eq!(
        *policies.lock().unwrap(),
        [
            TrafficPolicy::Disabled,
            TrafficPolicy::BlockNonTunnel,
            TrafficPolicy::TunnelOnly {
                interface: "wg0".into()
            },
            TrafficPolicy::BlockNonTunnel,
            TrafficPolicy::Disabled,
        ]
    );
}

#[test]
fn controller_does_not_start_transport_when_blocking_cannot_be_armed() {
    let mut controller = ConnectionController::new(
        KillSwitch::new(false),
        Fake {
            connected: false,
            fail_connect: false,
            fail_disconnect: false,
        },
        RecordingFirewall {
            policies: Arc::new(Mutex::new(Vec::new())),
            fail_at: Some(2),
        },
    )
    .unwrap();

    assert!(controller.connect(&config(), &context()).is_err());
    assert!(!controller.transport().connected);
    assert_eq!(controller.policy(), &TrafficPolicy::Disabled);
}

#[test]
fn controller_tears_down_transport_when_tunnel_policy_cannot_be_applied() {
    let mut controller = ConnectionController::new(
        KillSwitch::new(false),
        Fake {
            connected: false,
            fail_connect: false,
            fail_disconnect: false,
        },
        RecordingFirewall {
            policies: Arc::new(Mutex::new(Vec::new())),
            fail_at: Some(3),
        },
    )
    .unwrap();

    assert!(controller.connect(&config(), &context()).is_err());
    assert!(!controller.transport().connected);
    assert_eq!(controller.policy(), &TrafficPolicy::BlockNonTunnel);
}

#[test]
fn controller_keeps_tunnel_when_blocking_cannot_precede_teardown() {
    let mut controller = ConnectionController::new(
        KillSwitch::new(false),
        Fake {
            connected: false,
            fail_connect: false,
            fail_disconnect: false,
        },
        RecordingFirewall {
            policies: Arc::new(Mutex::new(Vec::new())),
            fail_at: Some(4),
        },
    )
    .unwrap();
    controller.connect(&config(), &context()).unwrap();

    assert!(controller.disconnect().is_err());
    assert!(controller.transport().connected);
    assert_eq!(
        controller.policy(),
        &TrafficPolicy::TunnelOnly {
            interface: "wg0".into()
        }
    );
}

#[test]
fn controller_creation_fails_when_initial_policy_cannot_be_applied() {
    let result = ConnectionController::new(
        KillSwitch::new(true),
        Fake {
            connected: false,
            fail_connect: false,
            fail_disconnect: false,
        },
        RecordingFirewall {
            policies: Arc::new(Mutex::new(Vec::new())),
            fail_at: Some(1),
        },
    );

    assert!(result.is_err());
}
