#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};

use cyberia_linux_client::{LeaseError, acquire_interface_lease};

fn runtime_directory(name: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "cyberia-client-lease-{name}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

#[test]
fn prevents_two_clients_from_managing_the_same_interface() {
    let directory = runtime_directory("exclusive");
    let first = acquire_interface_lease(&directory, "wg0").unwrap();
    assert!(matches!(
        acquire_interface_lease(&directory, "wg0"),
        Err(LeaseError::InUse)
    ));
    drop(first);
    acquire_interface_lease(&directory, "wg0").unwrap();
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn rejects_unsafe_interface_names_before_creating_lock_state() {
    let directory = runtime_directory("invalid");
    for interface in ["", "../wg0", "wg 0", "wireguard-interface-too-long"] {
        assert!(matches!(
            acquire_interface_lease(&directory, interface),
            Err(LeaseError::UnsafeInterface)
        ));
    }
    assert!(fs::read_dir(&directory).unwrap().next().is_none());
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn rejects_broad_or_symbolic_link_runtime_directories() {
    let directory = runtime_directory("unsafe-directory");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        acquire_interface_lease(&directory, "wg0"),
        Err(LeaseError::UnsafeState)
    ));
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let link = directory.with_extension("link");
    symlink(&directory, &link).unwrap();
    assert!(matches!(
        acquire_interface_lease(&link, "wg0"),
        Err(LeaseError::UnsafeState)
    ));
    fs::remove_file(link).unwrap();
    fs::remove_dir_all(directory).unwrap();
}
