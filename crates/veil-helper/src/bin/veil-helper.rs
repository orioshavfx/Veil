//! Privileged helper that runs the engine in TUN mode on behalf of one user.

#[cfg(unix)]
#[path = "../daemon_unix.rs"]
mod daemon;

#[cfg(unix)]
fn main() -> anyhow::Result<()> {
    daemon::main()
}

#[cfg(windows)]
fn main() {
    eprintln!("veil-helper: the Windows service is not implemented yet");
    std::process::exit(1);
}
