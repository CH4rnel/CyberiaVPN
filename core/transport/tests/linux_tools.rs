#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt;

use cyberia_transport::linux::LinuxTools;

#[test]
fn linux_tools_require_absolute_executables_and_private_key() {
    let directory = std::env::temp_dir().join(format!("cyberia-tools-{}", std::process::id()));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir(&directory).unwrap();
    let ip = directory.join("ip");
    let wg = directory.join("wg");
    let key = directory.join("key");
    fs::write(&ip, "").unwrap();
    fs::write(&wg, "").unwrap();
    fs::write(&key, "secret").unwrap();
    fs::set_permissions(&ip, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&wg, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    let tools = LinuxTools {
        ip,
        wg,
        private_key: key.clone(),
    };
    assert!(tools.validate().is_ok());
    fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(tools.validate().is_err());
    fs::remove_dir_all(directory).unwrap();
}
