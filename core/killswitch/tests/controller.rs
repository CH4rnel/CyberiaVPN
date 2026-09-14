use std::num::NonZeroU16;
use std::time::{Duration, Instant};

use cyberia_killswitch::{ConnectionController, KillSwitch, TrafficPolicy};
use cyberia_transport::{
    CancellationToken, ConnectContext, Endpoint, HealthStatus, Session, Transport, TransportConfig,
    TransportError, TransportHealth, TransportKind,
};

struct Fake {
    connected: bool,
    fail_connect: bool,
    fail_disconnect: bool,
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
    );
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
    );
    assert!(failed_connect.connect(&config(), &context()).is_err());
    assert_eq!(failed_connect.policy(), &TrafficPolicy::BlockNonTunnel);
    let mut failed_disconnect = ConnectionController::new(
        KillSwitch::new(false),
        Fake {
            connected: false,
            fail_connect: false,
            fail_disconnect: true,
        },
    );
    failed_disconnect.connect(&config(), &context()).unwrap();
    assert!(failed_disconnect.disconnect().is_err());
    assert_eq!(failed_disconnect.policy(), &TrafficPolicy::BlockNonTunnel);
}
