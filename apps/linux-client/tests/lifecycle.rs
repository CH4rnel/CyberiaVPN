use std::sync::{Arc, Mutex};
use std::time::Instant;

use cyberia_killswitch::{ConnectionError, FirewallError};
use cyberia_linux_client::{ManagedClientConnection, run_until_shutdown};
use cyberia_transport::{CancellationToken, Session, TransportKind};

struct Connection {
    events: Arc<Mutex<Vec<&'static str>>>,
    fail_connect: bool,
}

impl ManagedClientConnection for Connection {
    fn connect(&mut self, _: CancellationToken) -> Result<Session, ConnectionError> {
        self.events.lock().unwrap().push("connect");
        if self.fail_connect {
            return Err(ConnectionError::Firewall(FirewallError("injected".into())));
        }
        Ok(Session {
            id: "wg0".into(),
            transport: TransportKind::WireGuard,
            established_at: Instant::now(),
        })
    }

    fn disconnect(&mut self) -> Result<(), ConnectionError> {
        self.events.lock().unwrap().push("disconnect");
        Ok(())
    }

    fn disable(&mut self) -> Result<(), ConnectionError> {
        self.events.lock().unwrap().push("disable");
        Ok(())
    }
}

#[test]
fn waits_between_connect_and_fail_secure_teardown() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut connection = Connection {
        events: Arc::clone(&events),
        fail_connect: false,
    };
    run_until_shutdown(&mut connection, false, CancellationToken::default(), || {
        events.lock().unwrap().push("signal");
    })
    .unwrap();
    assert_eq!(
        *events.lock().unwrap(),
        ["connect", "signal", "disconnect", "disable"]
    );
}

#[test]
fn connection_failure_only_releases_non_always_on_filtering() {
    for (always_on, expected) in [(false, vec!["connect", "disable"]), (true, vec!["connect"])] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut connection = Connection {
            events: Arc::clone(&events),
            fail_connect: true,
        };
        assert!(
            run_until_shutdown(
                &mut connection,
                always_on,
                CancellationToken::default(),
                || {}
            )
            .is_err()
        );
        assert_eq!(*events.lock().unwrap(), expected);
    }
}
