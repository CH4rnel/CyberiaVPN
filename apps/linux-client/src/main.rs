use std::error::Error;
use std::path::PathBuf;
use std::sync::mpsc;

use cyberia_killswitch::linux_connection::LinuxWireGuardConnection;
use cyberia_linux_client::{load_config, run_until_shutdown};
use cyberia_transport::CancellationToken;

fn main() {
    if let Err(error) = run() {
        eprintln!("cyberia-linux-client: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let config_path = arguments
        .next()
        .map(PathBuf::from)
        .ok_or("usage: cyberia-linux-client /absolute/path/to/client.json")?;
    if arguments.next().is_some() {
        return Err("usage: cyberia-linux-client /absolute/path/to/client.json".into());
    }

    let config = load_config(&config_path)?;
    let nft_executable = config.tools.nft.clone();
    let always_on = config.always_on;
    let settings = config.into_connection_settings()?;
    let mut connection = LinuxWireGuardConnection::system(settings, nft_executable)?;

    let cancellation = CancellationToken::default();
    let signal_cancellation = cancellation.clone();
    let (shutdown_sender, shutdown_receiver) = mpsc::sync_channel(1);
    ctrlc::set_handler(move || {
        signal_cancellation.cancel();
        let _ = shutdown_sender.try_send(());
    })?;

    run_until_shutdown(&mut connection, always_on, cancellation, || {
        let _ = shutdown_receiver.recv();
    })?;
    Ok(())
}
