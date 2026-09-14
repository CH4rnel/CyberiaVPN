use std::num::NonZeroU16;
use std::time::{Duration, Instant};

use cyberia_transport::{
    AllowedIp, CancellationToken, ConnectContext, Endpoint, HealthStatus, Transport,
    TransportConfig, TransportError, TransportHealth, TransportKind, TunnelAddress,
    WireGuardAdapter, WireGuardBackend, WireGuardConfig,
};

#[derive(Default)]
struct Backend {
    up: usize,
    down: usize,
    fail_down: bool,
}
impl WireGuardBackend for Backend {
    fn bring_up(
        &mut self,
        _: &str,
        _: &WireGuardConfig,
        context: &ConnectContext,
    ) -> Result<(), TransportError> {
        context.check()?;
        self.up += 1;
        Ok(())
    }
    fn bring_down(&mut self, _: &str) -> Result<(), TransportError> {
        self.down += 1;
        if self.fail_down {
            Err(TransportError::Network("teardown failed".into()))
        } else {
            Ok(())
        }
    }
    fn health(&self) -> TransportHealth {
        TransportHealth {
            status: HealthStatus::Healthy,
            round_trip_time: Some(Duration::from_millis(3)),
            consecutive_failures: 0,
        }
    }
}
fn profile() -> WireGuardConfig {
    WireGuardConfig {
        peer_public_key: [1; 32],
        endpoint: Endpoint {
            host: "198.51.100.1".into(),
            port: NonZeroU16::new(51820).unwrap(),
        },
        tunnel_addresses: vec![TunnelAddress {
            address: "10.0.0.2".parse().unwrap(),
            prefix_length: 24,
        }],
        allowed_ips: vec![AllowedIp {
            network: "0.0.0.0".parse().unwrap(),
            prefix_length: 0,
        }],
        persistent_keepalive_seconds: Some(25),
        mtu: 1420,
    }
}
fn context() -> ConnectContext {
    ConnectContext {
        deadline: Instant::now() + Duration::from_secs(1),
        cancellation: CancellationToken::default(),
    }
}
fn config() -> TransportConfig {
    TransportConfig {
        kind: TransportKind::WireGuard,
        endpoint: profile().endpoint,
        connect_timeout: Duration::from_secs(1),
    }
}

#[test]
fn adapter_owns_wireguard_lifecycle() {
    let mut adapter = WireGuardAdapter::new("wg0".into(), profile(), Backend::default()).unwrap();
    assert_eq!(adapter.health().status, HealthStatus::Unavailable);
    let session = adapter.connect(&config(), &context()).unwrap();
    assert_eq!(session.id, "wg0");
    assert_eq!(adapter.health().status, HealthStatus::Healthy);
    assert_eq!(
        adapter.connect(&config(), &context()),
        Err(TransportError::AlreadyConnected)
    );
    adapter.disconnect().unwrap();
    assert_eq!(adapter.disconnect(), Err(TransportError::NotConnected));
}

#[test]
fn adapter_checks_bounds_before_platform_work() {
    assert!(WireGuardAdapter::new("bad/name".into(), profile(), Backend::default()).is_err());
    let mut adapter = WireGuardAdapter::new("wg0".into(), profile(), Backend::default()).unwrap();
    let mut wrong = config();
    wrong.kind = TransportKind::OpenVpn;
    assert!(matches!(
        adapter.connect(&wrong, &context()),
        Err(TransportError::InvalidConfig(_))
    ));
    let cancellation = CancellationToken::default();
    cancellation.cancel();
    assert_eq!(
        adapter.connect(
            &config(),
            &ConnectContext {
                deadline: Instant::now() + Duration::from_secs(1),
                cancellation
            }
        ),
        Err(TransportError::Cancelled)
    );
}

#[test]
fn failed_teardown_keeps_adapter_connected() {
    let mut adapter = WireGuardAdapter::new(
        "wg0".into(),
        profile(),
        Backend {
            fail_down: true,
            ..Backend::default()
        },
    )
    .unwrap();
    adapter.connect(&config(), &context()).unwrap();
    assert!(matches!(
        adapter.disconnect(),
        Err(TransportError::Network(_))
    ));
    assert_eq!(
        adapter.connect(&config(), &context()),
        Err(TransportError::AlreadyConnected)
    );
}
