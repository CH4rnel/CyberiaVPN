#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cyberia_transport::linux::{CommandRunner, CommandSpec, LinuxDnsBackend, LinuxDnsTools};
use cyberia_transport::{CancellationToken, ConnectContext, DnsConfig, TransportError};

struct Recorder {
    commands: Arc<Mutex<Vec<CommandSpec>>>,
    fail_at: Vec<usize>,
}

impl CommandRunner for Recorder {
    fn run(&mut self, command: &CommandSpec) -> Result<(), TransportError> {
        let mut commands = self.commands.lock().unwrap();
        commands.push(command.clone());
        if self.fail_at.contains(&commands.len()) {
            return Err(TransportError::Network("injected".into()));
        }
        Ok(())
    }
}

fn tools(name: &str) -> (LinuxDnsTools, PathBuf) {
    let directory = std::env::temp_dir().join(format!("cyberia-dns-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir(&directory).unwrap();
    let resolvectl = directory.join("resolvectl");
    fs::write(&resolvectl, "").unwrap();
    fs::set_permissions(&resolvectl, fs::Permissions::from_mode(0o700)).unwrap();
    (LinuxDnsTools { resolvectl }, directory)
}

fn context() -> ConnectContext {
    ConnectContext {
        deadline: Instant::now() + Duration::from_secs(1),
        cancellation: CancellationToken::default(),
    }
}

fn config() -> DnsConfig {
    DnsConfig {
        resolvers: vec![
            "192.0.2.53".parse().unwrap(),
            "2001:db8::53".parse().unwrap(),
        ],
    }
}

#[test]
fn configures_and_reverts_per_interface_dns() {
    let (tools, directory) = tools("lifecycle");
    let commands = Arc::new(Mutex::new(Vec::new()));
    let mut backend = LinuxDnsBackend::new(
        tools,
        Recorder {
            commands: Arc::clone(&commands),
            fail_at: vec![],
        },
    )
    .unwrap();

    backend.configure("wg0", &config(), &context()).unwrap();
    backend.revert("wg0").unwrap();

    let commands = commands.lock().unwrap();
    assert_eq!(
        commands[0].arguments,
        ["dns", "wg0", "192.0.2.53", "2001:db8::53"]
    );
    assert_eq!(commands[1].arguments, ["domain", "wg0", "~."]);
    assert_eq!(commands[2].arguments, ["default-route", "wg0", "yes"]);
    assert_eq!(commands[3].arguments, ["revert", "wg0"]);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn partial_dns_setup_is_reverted() {
    let (tools, directory) = tools("rollback");
    let commands = Arc::new(Mutex::new(Vec::new()));
    let mut backend = LinuxDnsBackend::new(
        tools,
        Recorder {
            commands: Arc::clone(&commands),
            fail_at: vec![2],
        },
    )
    .unwrap();

    assert!(backend.configure("wg0", &config(), &context()).is_err());

    let commands = commands.lock().unwrap();
    assert_eq!(commands.len(), 3);
    assert_eq!(commands[2].arguments, ["revert", "wg0"]);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn initial_dns_command_failure_is_reverted() {
    let (tools, directory) = tools("initial-failure");
    let commands = Arc::new(Mutex::new(Vec::new()));
    let mut backend = LinuxDnsBackend::new(
        tools,
        Recorder {
            commands: Arc::clone(&commands),
            fail_at: vec![1],
        },
    )
    .unwrap();

    assert!(backend.configure("wg0", &config(), &context()).is_err());
    let commands = commands.lock().unwrap();
    assert_eq!(commands.len(), 2);
    assert_eq!(commands[0].arguments[0], "dns");
    assert_eq!(commands[1].arguments, ["revert", "wg0"]);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn failed_dns_cleanup_remains_retryable() {
    for (name, failures) in [
        ("initial-cleanup-failure", vec![1, 2]),
        ("partial-cleanup-failure", vec![2, 3]),
    ] {
        let (tools, directory) = tools(name);
        let commands = Arc::new(Mutex::new(Vec::new()));
        let mut backend = LinuxDnsBackend::new(
            tools,
            Recorder {
                commands: Arc::clone(&commands),
                fail_at: failures,
            },
        )
        .unwrap();

        assert!(backend.configure("wg0", &config(), &context()).is_err());
        assert!(backend.needs_revert());
        assert!(matches!(
            backend.configure("wg0", &config(), &context()),
            Err(TransportError::AlreadyConnected)
        ));
        backend.revert("wg0").unwrap();
        assert!(!backend.needs_revert());
        assert_eq!(
            commands.lock().unwrap().last().unwrap().arguments,
            ["revert", "wg0"]
        );
        fs::remove_dir_all(directory).unwrap();
    }
}

#[test]
fn rejects_invalid_policy_before_platform_work() {
    let (tools, directory) = tools("invalid");
    let commands = Arc::new(Mutex::new(Vec::new()));
    let mut backend = LinuxDnsBackend::new(
        tools,
        Recorder {
            commands: Arc::clone(&commands),
            fail_at: vec![],
        },
    )
    .unwrap();

    assert!(
        backend
            .configure("bad/name", &config(), &context())
            .is_err()
    );
    assert!(commands.lock().unwrap().is_empty());
    fs::remove_dir_all(directory).unwrap();
}
