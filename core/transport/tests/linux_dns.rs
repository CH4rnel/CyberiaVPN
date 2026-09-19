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
    fail_at: Option<usize>,
}

impl CommandRunner for Recorder {
    fn run(&mut self, command: &CommandSpec) -> Result<(), TransportError> {
        let mut commands = self.commands.lock().unwrap();
        commands.push(command.clone());
        if self.fail_at == Some(commands.len()) {
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
            fail_at: None,
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
            fail_at: Some(2),
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
fn rejects_invalid_policy_before_platform_work() {
    let (tools, directory) = tools("invalid");
    let commands = Arc::new(Mutex::new(Vec::new()));
    let mut backend = LinuxDnsBackend::new(
        tools,
        Recorder {
            commands: Arc::clone(&commands),
            fail_at: None,
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
