//! Root daemon that runs the engine in TUN mode on behalf of one user.

use std::ffi::{CString, OsStr};
use std::fs::File;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use veil_engine::tun::TunOptions;
use veil_engine::{Engine, EngineConfig};
use veil_helper::{Request, Response, SOCKET_PATH, Status, VERSION};

#[derive(Default)]
struct State {
    binary_hash: String,
    engine: Option<Engine>,
    watcher: Option<tokio::task::JoinHandle<()>>,
}

type Shared = Arc<Mutex<State>>;

async fn stop(state: &mut State) {
    if let Some(w) = state.watcher.take() {
        w.abort();
    }
    if let Some(engine) = state.engine.take() {
        engine.stop().await;
    }
}

fn process_alive(pid: u32) -> bool {
    // errno is read right after kill(2), before anything else can overwrite it.
    unsafe { libc::kill(pid as i32, 0) == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM) }
}

/// Root-only DNS backup written by the helper itself; never taken from the client.
#[cfg(target_os = "macos")]
const DNS_BACKUP_DIR: &str = "/Library/Application Support/dev.veil.helper";
#[cfg(target_os = "linux")]
const DNS_BACKUP_DIR: &str = "/var/lib/veil";
const DNS_BACKUP_FILE: &str = "dns-backup.json";

fn home_dir_of(uid: u32) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    let mut buf = vec![0u8; 16384];
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut res: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr().cast(), buf.len(), &mut res) };
    if rc != 0 || res.is_null() || pwd.pw_dir.is_null() {
        return None;
    }
    let dir = unsafe { std::ffi::CStr::from_ptr(pwd.pw_dir) };
    Some(PathBuf::from(std::ffi::OsStr::from_bytes(dir.to_bytes())))
}

fn cstring(name: &OsStr) -> std::io::Result<CString> {
    use std::os::unix::ffi::OsStrExt;
    CString::new(name.as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "name contains NUL"))
}

/// `openat(2)` returning an owned `File` (also used for directories); retries on EINTR.
fn openat_fd(dir: RawFd, name: &OsStr, flags: libc::c_int, mode: libc::mode_t) -> std::io::Result<File> {
    let c = cstring(name)?;
    loop {
        let fd = unsafe { libc::openat(dir, c.as_ptr(), flags, libc::c_uint::from(mode)) };
        if fd >= 0 {
            return Ok(unsafe { File::from_raw_fd(fd) });
        }
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

const DIR_FLAGS: libc::c_int = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

/// Walk an absolute, normalized path from "/" one component at a time with
/// `openat(O_DIRECTORY|O_NOFOLLOW)`. Any symlink on the way (including the last
/// component) is an error, so the returned descriptor refers to exactly the directory
/// named by the path, whatever other processes do to the tree afterwards.
fn open_dir_nofollow(path: &Path) -> Result<File> {
    use std::path::Component;
    if !path.is_absolute() {
        bail!("{} is not an absolute path", path.display());
    }
    let mut cur = openat_fd(libc::AT_FDCWD, OsStr::new("/"), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC, 0)
        .context("cannot open /")?;
    for comp in path.components() {
        match comp {
            Component::RootDir => {}
            Component::Normal(name) => {
                cur = openat_fd(cur.as_raw_fd(), name, DIR_FLAGS, 0).with_context(|| {
                    format!("cannot open {} (symlink or not a directory at {:?})", path.display(), name)
                })?;
            }
            _ => bail!("{} is not a normalized path", path.display()),
        }
    }
    Ok(cur)
}

/// The client chooses where root reads geoip/geosite from, so accept only a
/// canonical directory owned by that client inside its home directory.
fn check_geo_dir(dir: &Path, uid: u32) -> Result<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let canon = dir.canonicalize().with_context(|| format!("invalid geo dir {}", dir.display()))?;
    if uid == 0 {
        return Ok(canon);
    }
    let home = home_dir_of(uid)
        .and_then(|h| h.canonicalize().ok())
        .context("cannot resolve client home directory")?;
    // A home of "/" (service accounts) would make the prefix check below accept any path.
    if home.parent().is_none() || !canon.starts_with(&home) {
        bail!("geo dir {} is outside the client's home directory", canon.display());
    }
    // Re-walk the canonical path without following links and fstat the descriptor.
    let fd = open_dir_nofollow(&canon)?;
    let meta = fd.metadata()?;
    if !meta.is_dir() || meta.uid() != uid {
        bail!("geo dir {} is not owned by the client", canon.display());
    }
    Ok(canon)
}

/// Create (if needed) and verify `name` inside the open directory `parent`: a real
/// directory (never a symlink), owned by `owner`, mode 0700. All steps go through
/// descriptors (mkdirat/openat/fstat/fchmod), nothing is looked up by path twice.
fn private_dir_at(parent: &File, name: &OsStr, owner: u32) -> Result<File> {
    use std::os::unix::fs::MetadataExt;
    let c = cstring(name)?;
    if unsafe { libc::mkdirat(parent.as_raw_fd(), c.as_ptr(), 0o700) } != 0 {
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(e).with_context(|| format!("cannot create {name:?}"));
        }
    }
    let dir = openat_fd(parent.as_raw_fd(), name, DIR_FLAGS, 0)
        .with_context(|| format!("{name:?} is not a regular directory"))?;
    let meta = dir.metadata()?;
    if !meta.is_dir() {
        bail!("{name:?} is not a regular directory");
    }
    if meta.uid() != owner {
        bail!("{name:?} has unexpected owner {}", meta.uid());
    }
    if meta.mode() & 0o7777 != 0o700 {
        dir.set_permissions(std::fs::Permissions::from_mode(0o700))?; // fchmod
    }
    Ok(dir)
}

/// `dir` must be absolute and canonical (no symlinks); its parent is walked with
/// O_NOFOLLOW from "/" and the last component is handled relative to that descriptor.
fn ensure_private_dir_canonical(dir: &Path, owner: u32) -> Result<File> {
    let (Some(parent), Some(name)) = (dir.parent(), dir.file_name()) else {
        bail!("{} has no parent directory", dir.display());
    };
    let parent_fd = open_dir_nofollow(parent)?;
    private_dir_at(&parent_fd, name, owner)
}

/// Create (if needed) and verify a root-only directory: a real directory (never a
/// symlink), owned by `owner`, mode 0700.
fn ensure_private_dir(dir: &Path, owner: u32) -> Result<()> {
    let (Some(parent), Some(name)) = (dir.parent(), dir.file_name()) else {
        bail!("{} has no parent directory", dir.display());
    };
    std::fs::create_dir_all(parent)?;
    // Canonicalize once, then re-walk that path without following links.
    let canon = parent.canonicalize()?.join(name);
    ensure_private_dir_canonical(&canon, owner).map(|_| ())
}

fn dns_backup_path() -> Result<PathBuf> {
    ensure_private_dir(Path::new(DNS_BACKUP_DIR), 0)?;
    Ok(Path::new(DNS_BACKUP_DIR).join(DNS_BACKUP_FILE))
}

/// Root-only copy of the client's geo files; the engine reads only from here.
fn geo_stage_dir() -> Result<PathBuf> {
    ensure_private_dir(Path::new(DNS_BACKUP_DIR), 0)?;
    let dir = Path::new(DNS_BACKUP_DIR).join(GEO_STAGE_SUBDIR);
    ensure_private_dir(&dir, 0)?;
    Ok(dir)
}

const GEO_STAGE_SUBDIR: &str = "geo";
const GEO_FILES: [&str; 2] = ["geoip.dat", "geosite.dat"];
const GEO_MAX_SIZE: u64 = 64 << 20;

fn unlinkat_if_exists(dir: &File, name: &OsStr) -> std::io::Result<()> {
    let c = cstring(name)?;
    if unsafe { libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), 0) } != 0 {
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::NotFound {
            return Err(e);
        }
    }
    Ok(())
}

fn renameat_in(dir: &File, from: &OsStr, to: &OsStr) -> std::io::Result<()> {
    let (f, t) = (cstring(from)?, cstring(to)?);
    if unsafe { libc::renameat(dir.as_raw_fd(), f.as_ptr(), dir.as_raw_fd(), t.as_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Copy one geo file from the client's directory into `dst_dir` without trusting any
/// path. Both directories are given as canonical paths and are walked from "/" with
/// O_NOFOLLOW (a symlink anywhere is an error). The source is opened with
/// openat(dirfd, name, O_NOFOLLOW|O_NONBLOCK) (so a FIFO cannot hang root), checked with
/// fstat on that fd (regular file, owned by the client, size limit) and read through it.
/// The data goes to an O_EXCL temp file created in the destination directory fd, fsynced
/// and renamed with renameat over the old one. A missing source removes any previously
/// staged copy.
fn copy_geo_file_canonical(src_dir: &Path, dst_dir: &Path, name: &str, client_uid: u32, max_size: u64) -> Result<()> {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

    let src_fd = open_dir_nofollow(src_dir).context("cannot open geo source directory")?;
    let dst_fd = open_dir_nofollow(dst_dir).context("cannot open geo staging directory")?;
    let src = src_dir.join(name);
    let dst = dst_dir.join(name);
    let input = match openat_fd(src_fd.as_raw_fd(), OsStr::new(name), libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC, 0) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            unlinkat_if_exists(&dst_fd, OsStr::new(name))
                .with_context(|| format!("cannot remove stale {}", dst.display()))?;
            return Ok(());
        }
        Err(e) => return Err(e).with_context(|| format!("cannot open {}", src.display())),
    };
    let meta = input.metadata()?; // fstat on the opened descriptor
    if !meta.file_type().is_file() {
        bail!("{} is not a regular file", src.display());
    }
    if meta.uid() != client_uid {
        bail!("{} is not owned by the client", src.display());
    }
    if meta.len() > max_size {
        bail!("{} is too large ({} bytes, limit {max_size})", src.display(), meta.len());
    }

    let tmp_name = std::ffi::OsString::from(format!(
        ".{name}.{}.{}.tmp",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let mut out = openat_fd(
        dst_fd.as_raw_fd(),
        &tmp_name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0o600,
    )
    .with_context(|| format!("cannot create temp file for {}", dst.display()))?;
    let written = (|| -> Result<()> {
        // The file may grow after fstat: bound the actual read as well.
        let n = std::io::copy(&mut (&input).take(max_size + 1), &mut out)?;
        if n > max_size {
            bail!("{} grew beyond the {max_size} byte limit", src.display());
        }
        out.sync_all()?;
        Ok(())
    })();
    drop(out);
    if let Err(e) = written.and_then(|()| renameat_in(&dst_fd, &tmp_name, OsStr::new(name)).map_err(Into::into)) {
        let _ = unlinkat_if_exists(&dst_fd, &tmp_name);
        return Err(e);
    }
    Ok(())
}

/// Canonicalize both directories once, then do all work relative to descriptors
/// obtained by a no-symlink walk of the canonical paths.
fn copy_geo_file(src_dir: &Path, dst_dir: &Path, name: &str, client_uid: u32, max_size: u64) -> Result<()> {
    let src = src_dir.canonicalize().with_context(|| format!("invalid geo source {}", src_dir.display()))?;
    let dst = dst_dir.canonicalize().with_context(|| format!("invalid geo staging dir {}", dst_dir.display()))?;
    copy_geo_file_canonical(&src, &dst, name, client_uid, max_size)
}

fn copy_geo_files(src_dir: &Path, dst_dir: &Path, client_uid: u32, max_size: u64) -> Result<()> {
    for name in GEO_FILES {
        copy_geo_file(src_dir, dst_dir, name, client_uid, max_size)?;
    }
    Ok(())
}

/// Validate the client's geo dir and return the root-owned copy the engine may read.
async fn stage_geo(geo_dir: PathBuf, uid: u32) -> Result<PathBuf> {
    tokio::task::spawn_blocking(move || {
        let src = check_geo_dir(&geo_dir, uid)?;
        let dst = geo_stage_dir()?;
        copy_geo_files(&src, &dst, uid, GEO_MAX_SIZE)?;
        Ok(dst)
    })
    .await
    .context("geo copy task failed")?
}

async fn handle(req: Request, shared: &Shared, uid: u32, client_pid: u32) -> Response {
    match req {
        Request::Status => {
            let s = shared.lock().await;
            let (upload, download) = s.engine.as_ref().map_or((0, 0), |e| {
                (e.stats().upload.load(Ordering::Relaxed), e.stats().download.load(Ordering::Relaxed))
            });
            Response::Status(Status {
                version: VERSION.into(),
                binary_hash: s.binary_hash.clone(),
                running: s.engine.is_some(),
                upload,
                download,
                standby: s.engine.as_ref().is_some_and(Engine::is_standby),
            })
        }
        Request::Standby { on } => {
            let s = shared.lock().await;
            match s.engine.as_ref() {
                Some(engine) => {
                    engine.set_standby(on);
                    Response::Ok
                }
                None => Response::Error { message: "not running".into() },
            }
        }
        Request::Update { server, routing, geo_dir } => {
            let geo_dir = match stage_geo(geo_dir, uid).await {
                Ok(d) => d,
                Err(e) => return Response::Error { message: format!("{e:#}") },
            };
            let s = shared.lock().await;
            let Some(engine) = s.engine.as_ref() else {
                return Response::Error { message: "not running".into() };
            };
            if let Some(routing) = routing
                && let Err(e) = engine.set_routing(&routing, &geo_dir)
            {
                return Response::Error { message: format!("{e:#}") };
            }
            if let Some(server) = server
                && let Err(e) = engine.set_server(*server).await
            {
                return Response::Error { message: format!("{e:#}") };
            }
            Response::Ok
        }
        Request::Stop => {
            stop(&mut *shared.lock().await).await;
            Response::Ok
        }
        Request::Start { server, routing, geo_dir, mixed_port, routes, standby } => {
            let geo_dir = match stage_geo(geo_dir, uid).await {
                Ok(d) => d,
                Err(e) => return Response::Error { message: format!("{e:#}") },
            };
            let dns_backup = match dns_backup_path() {
                Ok(p) => p,
                Err(e) => return Response::Error { message: format!("{e:#}") },
            };
            let mut s = shared.lock().await;
            stop(&mut s).await;
            let config = EngineConfig {
                listen: SocketAddr::from(([127, 0, 0, 1], mixed_port)),
                server: *server,
                routing,
                geo_dir,
                tun: Some(TunOptions { mtu: 1500, dns_backup, routes }),
            };
            match Engine::start(config).await {
                Ok(engine) => {
                    if standby {
                        engine.set_standby(true);
                    }
                    s.engine = Some(engine);
                    let shared = shared.clone();
                    s.watcher = Some(tokio::spawn(async move {
                        while process_alive(client_pid) {
                            tokio::time::sleep(Duration::from_secs(2)).await;
                        }
                        tracing::info!("client {client_pid} exited, stopping TUN");
                        let mut s = shared.lock().await;
                        s.watcher = None; // this task; don't abort ourselves
                        if let Some(engine) = s.engine.take() {
                            engine.stop().await;
                        }
                    }));
                    Response::Ok
                }
                Err(e) => Response::Error { message: format!("{e:#}") },
            }
        }
    }
}

async fn serve(mut conn: UnixStream, allowed_uid: u32, shared: Shared) -> Result<()> {
    let cred = conn.peer_cred()?;
    let uid = cred.uid();
    if uid != allowed_uid && uid != 0 {
        bail!("rejected client uid {uid}");
    }
    // The watcher needs a real client pid: 0 would make kill(0, 0) succeed forever.
    let Some(client_pid) = cred.pid().and_then(|p| u32::try_from(p).ok()).filter(|&p| p > 0) else {
        bail!("cannot determine client pid");
    };
    let (r, mut w) = conn.split();
    let mut line = String::new();
    // Bounded size and time: a silent or endless client must not pin the task.
    let read = tokio::time::timeout(
        Duration::from_secs(10),
        BufReader::new(r.take(1 << 20)).read_line(&mut line),
    )
    .await;
    match read {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => bail!("timed out reading request"),
    }
    let resp = match serde_json::from_str::<Request>(&line) {
        Ok(req) => handle(req, &shared, uid, client_pid).await,
        Err(e) => Response::Error { message: format!("{} {e}", veil_helper::BAD_REQUEST) },
    };
    let mut out = serde_json::to_vec(&resp)?;
    out.push(b'\n');
    w.write_all(&out).await?;
    Ok(())
}

async fn interrupted(sig: &mut Option<tokio::signal::unix::Signal>) {
    match sig {
        Some(s) => {
            s.recv().await;
        }
        None => std::future::pending::<()>().await,
    }
}

#[tokio::main]
pub async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with_ansi(false)
        // launchd keeps stderr in /var/log/dev.veil.helper.log, journald under systemd.
        .with_writer(std::io::stderr)
        .init();
    let args: Vec<String> = std::env::args().collect();
    let allowed_uid: u32 = args
        .iter()
        .position(|a| a == "--uid")
        .and_then(|i| args.get(i + 1))
        .and_then(|u| u.parse().ok())
        .context("usage: veil-helper --uid <uid>")?;

    // The helper may have been killed (or crashed) while TUN had DNS overridden; launchd
    // restarts it, but nothing would put DNS back until the next Start. No engine runs yet,
    // so a backup file can only be a leftover.
    match dns_backup_path().and_then(|p| veil_sysproxy::dns_restore(&p)) {
        Ok(true) => tracing::info!("restored DNS settings left by a previous run"),
        Ok(false) => {}
        Err(e) => tracing::warn!("cannot restore leftover DNS settings: {e:#}"),
    }

    // Everything below (TUN, routes, DNS) needs root; fail with a clear message under a wrong unit.
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::geteuid() } != 0 {
            bail!("veil-helper must run as root (it is started by systemd as veil-helper.service)");
        }
        // /run/veil is 0755 root: the user only needs to traverse it to reach the 0666 socket.
        let dir = Path::new(SOCKET_PATH).parent().context("socket path has no parent")?;
        std::fs::create_dir_all(dir).context("cannot create the socket directory")?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))?;
    }

    let _ = std::fs::remove_file(SOCKET_PATH);
    let listener = UnixListener::bind(SOCKET_PATH).context("cannot bind helper socket")?;
    // Access control is done with peer credentials, so anyone may connect.
    std::fs::set_permissions(SOCKET_PATH, std::fs::Permissions::from_mode(0o666))?;
    tracing::info!("veil-helper {VERSION} listening for uid {allowed_uid}");

    let binary_hash = std::env::current_exe()
        .ok()
        .and_then(|p| veil_helper::file_hash(&p).ok())
        .unwrap_or_default();
    let shared: Shared = Arc::new(Mutex::new(State { binary_hash, ..Default::default() }));
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    // SIGINT (manual run) is handled on Linux only; macOS behaviour is unchanged.
    let mut int = if cfg!(target_os = "linux") {
        Some(tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?)
    } else {
        None
    };
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (conn, _) = accepted?;
                let shared = shared.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve(conn, allowed_uid, shared).await {
                        tracing::warn!("{e:#}");
                    }
                });
            }
            _ = term.recv() => {
                tracing::info!("terminating");
                stop(&mut *shared.lock().await).await;
                let _ = std::fs::remove_file(SOCKET_PATH);
                return Ok(());
            }
            _ = interrupted(&mut int) => {
                tracing::info!("interrupted");
                stop(&mut *shared.lock().await).await;
                let _ = std::fs::remove_file(SOCKET_PATH);
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unique directory under the current user's home, removed on drop.
    struct TmpDir(PathBuf);

    impl TmpDir {
        fn new_in_home(uid: u32) -> Option<Self> {
            let home = home_dir_of(uid)?;
            home.parent()?;
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            // Retry on a name collision; any other failure (e.g. read-only home) skips the test.
            for _ in 0..5 {
                let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let p = home.join(format!(".veil-geo-test-{}-{}-{}", std::process::id(), nanos, n));
                match std::fs::create_dir(&p) {
                    Ok(()) => return Some(TmpDir(p)),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(_) => return None,
                }
            }
            None
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn current_uid() -> u32 {
        unsafe { libc::getuid() }
    }

    #[test]
    fn geo_dir_inside_home_is_accepted_and_canonical() {
        let uid = current_uid();
        if uid == 0 {
            eprintln!("skip: running as root");
            return;
        }
        let Some(tmp) = TmpDir::new_in_home(uid) else {
            eprintln!("skip: home directory is not writable in this environment");
            return;
        };
        let got = check_geo_dir(&tmp.0, uid).expect("dir inside home must be accepted");
        assert_eq!(got, tmp.0.canonicalize().unwrap());
    }

    #[test]
    fn geo_dir_outside_home_is_rejected() {
        let uid = current_uid();
        if uid == 0 {
            eprintln!("skip: running as root");
            return;
        }
        assert!(check_geo_dir(Path::new("/"), uid).is_err());
        assert!(check_geo_dir(Path::new("/tmp"), uid).is_err());
    }

    #[test]
    fn geo_dir_symlink_escaping_home_is_rejected() {
        let uid = current_uid();
        if uid == 0 {
            eprintln!("skip: running as root");
            return;
        }
        let Some(tmp) = TmpDir::new_in_home(uid) else {
            eprintln!("skip: home directory is not writable in this environment");
            return;
        };
        let link = tmp.0.join("escape");
        std::os::unix::fs::symlink("/tmp", &link).unwrap();
        assert!(check_geo_dir(&link, uid).is_err());
    }

    #[test]
    fn geo_dir_nonexistent_is_rejected() {
        let uid = current_uid();
        let p = std::env::temp_dir().join(format!(
            "veil-nonexistent-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        assert!(check_geo_dir(&p, uid).is_err());
    }

    #[test]
    fn geo_dir_uid_zero_skips_restrictions() {
        let got = check_geo_dir(Path::new("/tmp"), 0).expect("uid 0 is unrestricted");
        assert_eq!(got, Path::new("/tmp").canonicalize().unwrap());
    }

    /// Unique scratch directory under the system temp dir, removed on drop.
    fn scratch(tag: &str) -> TmpDir {
        static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("veil-copy-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        TmpDir(p)
    }

    fn src_dst(tag: &str) -> (TmpDir, TmpDir) {
        (scratch(&format!("{tag}-src")), scratch(&format!("{tag}-dst")))
    }

    #[test]
    fn copy_regular_file() {
        let (src, dst) = src_dst("ok");
        std::fs::write(src.0.join("geoip.dat"), b"ip-data").unwrap();
        std::fs::write(src.0.join("geosite.dat"), b"site-data").unwrap();
        copy_geo_files(&src.0, &dst.0, current_uid(), 1024).unwrap();
        assert_eq!(std::fs::read(dst.0.join("geoip.dat")).unwrap(), b"ip-data");
        assert_eq!(std::fs::read(dst.0.join("geosite.dat")).unwrap(), b"site-data");
        // No temp files left behind.
        assert_eq!(std::fs::read_dir(&dst.0).unwrap().count(), 2);
    }

    #[test]
    fn copy_missing_file_is_skipped_and_removes_stale_copy() {
        let (src, dst) = src_dst("missing");
        std::fs::write(dst.0.join("geoip.dat"), b"stale").unwrap();
        copy_geo_files(&src.0, &dst.0, current_uid(), 1024).unwrap();
        assert!(!dst.0.join("geoip.dat").exists());
    }

    #[test]
    fn copy_rejects_symlink() {
        let (src, dst) = src_dst("symlink");
        let target = src.0.join("real");
        std::fs::write(&target, b"secret").unwrap();
        std::os::unix::fs::symlink(&target, src.0.join("geoip.dat")).unwrap();
        assert!(copy_geo_files(&src.0, &dst.0, current_uid(), 1024).is_err());
        assert!(!dst.0.join("geoip.dat").exists());
    }

    #[test]
    fn copy_rejects_directory() {
        let (src, dst) = src_dst("dir");
        std::fs::create_dir(src.0.join("geoip.dat")).unwrap();
        assert!(copy_geo_files(&src.0, &dst.0, current_uid(), 1024).is_err());
    }

    #[test]
    fn copy_rejects_oversized_file() {
        let (src, dst) = src_dst("big");
        std::fs::write(src.0.join("geoip.dat"), vec![0u8; 11]).unwrap();
        assert!(copy_geo_files(&src.0, &dst.0, current_uid(), 10).is_err());
        assert!(!dst.0.join("geoip.dat").exists());
        std::fs::write(src.0.join("geoip.dat"), vec![0u8; 10]).unwrap();
        copy_geo_files(&src.0, &dst.0, current_uid(), 10).unwrap();
    }

    #[test]
    fn copy_rejects_foreign_owner() {
        let (src, dst) = src_dst("owner");
        std::fs::write(src.0.join("geoip.dat"), b"x").unwrap();
        assert!(copy_geo_files(&src.0, &dst.0, current_uid().wrapping_add(1), 1024).is_err());
    }

    #[test]
    fn copy_overwrites_existing() {
        let (src, dst) = src_dst("overwrite");
        std::fs::write(dst.0.join("geoip.dat"), b"old-old-old").unwrap();
        std::fs::write(src.0.join("geoip.dat"), b"new").unwrap();
        copy_geo_files(&src.0, &dst.0, current_uid(), 1024).unwrap();
        assert_eq!(std::fs::read(dst.0.join("geoip.dat")).unwrap(), b"new");
    }

    #[test]
    fn private_dir_is_created_0700_and_symlink_rejected() {
        use std::os::unix::fs::MetadataExt;
        let base = scratch("private");
        let d = base.0.join("geo");
        ensure_private_dir(&d, current_uid()).unwrap();
        assert_eq!(std::fs::metadata(&d).unwrap().mode() & 0o7777, 0o700);
        let link = base.0.join("link");
        std::os::unix::fs::symlink(&d, &link).unwrap();
        assert!(ensure_private_dir(&link, current_uid()).is_err());
        assert!(ensure_private_dir(&d, current_uid().wrapping_add(1)).is_err());
    }

    /// Canonical scratch dir (on macOS the temp dir lives behind the /var -> /private/var link).
    fn canon_scratch(tag: &str) -> (TmpDir, PathBuf) {
        let t = scratch(tag);
        let c = t.0.canonicalize().unwrap();
        (t, c)
    }

    #[test]
    fn walk_rejects_symlink_in_intermediate_component() {
        let (_t, base) = canon_scratch("walk-mid");
        std::fs::create_dir_all(base.join("real/sub")).unwrap();
        std::os::unix::fs::symlink(base.join("real"), base.join("link")).unwrap();
        assert!(open_dir_nofollow(&base.join("real/sub")).is_ok());
        assert!(open_dir_nofollow(&base.join("link/sub")).is_err());
        assert!(open_dir_nofollow(&base.join("link")).is_err());
        assert!(open_dir_nofollow(Path::new("relative/path")).is_err());
        assert!(open_dir_nofollow(&base.join("real/../real")).is_err());
    }

    #[test]
    fn copy_rejects_symlink_on_source_intermediate_dir() {
        let (_t, base) = canon_scratch("src-mid");
        std::fs::create_dir_all(base.join("real/geo")).unwrap();
        std::fs::write(base.join("real/geo/geoip.dat"), b"data").unwrap();
        std::os::unix::fs::symlink(base.join("real"), base.join("link")).unwrap();
        let dst = base.join("dst");
        std::fs::create_dir(&dst).unwrap();
        // Same file through the clean path works...
        copy_geo_file_canonical(&base.join("real/geo"), &dst, "geoip.dat", current_uid(), 1024).unwrap();
        std::fs::remove_file(dst.join("geoip.dat")).unwrap();
        // ...but not through a swapped-in intermediate symlink.
        assert!(copy_geo_file_canonical(&base.join("link/geo"), &dst, "geoip.dat", current_uid(), 1024).is_err());
        assert!(!dst.join("geoip.dat").exists());
    }

    #[test]
    fn copy_rejects_symlink_on_destination_dir() {
        let (_t, base) = canon_scratch("dst-mid");
        let src = base.join("src");
        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("geoip.dat"), b"data").unwrap();
        std::fs::create_dir_all(base.join("real/stage")).unwrap();
        std::os::unix::fs::symlink(base.join("real"), base.join("link")).unwrap();
        // symlink on an intermediate component of the destination
        assert!(copy_geo_file_canonical(&src, &base.join("link/stage"), "geoip.dat", current_uid(), 1024).is_err());
        // symlink as the destination directory itself
        assert!(copy_geo_file_canonical(&src, &base.join("link"), "geoip.dat", current_uid(), 1024).is_err());
        assert!(!base.join("real/stage/geoip.dat").exists());
        assert!(!base.join("real/geoip.dat").exists());
    }

    #[test]
    fn private_dir_rejects_symlink_on_intermediate_component() {
        let (_t, base) = canon_scratch("priv-mid");
        std::fs::create_dir_all(base.join("real")).unwrap();
        std::os::unix::fs::symlink(base.join("real"), base.join("link")).unwrap();
        assert!(ensure_private_dir_canonical(&base.join("link/geo"), current_uid()).is_err());
        assert!(!base.join("real/geo").exists());
        ensure_private_dir_canonical(&base.join("real/geo"), current_uid()).unwrap();
        assert!(base.join("real/geo").is_dir());
    }

    #[test]
    fn private_dir_fixes_loose_mode_via_fd() {
        use std::os::unix::fs::MetadataExt;
        let (_t, base) = canon_scratch("priv-mode");
        let d = base.join("geo");
        std::fs::create_dir(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        ensure_private_dir(&d, current_uid()).unwrap();
        assert_eq!(std::fs::metadata(&d).unwrap().mode() & 0o7777, 0o700);
    }

    #[test]
    fn copy_works_through_non_canonical_temp_path() {
        // On macOS std::env::temp_dir() is under /var -> /private/var: the public entry
        // point canonicalizes first, so it must still succeed.
        let (src, dst) = src_dst("noncanon");
        std::fs::write(src.0.join("geosite.dat"), b"abc").unwrap();
        copy_geo_file(&src.0, &dst.0, "geosite.dat", current_uid(), 1024).unwrap();
        assert_eq!(std::fs::read(dst.0.join("geosite.dat")).unwrap(), b"abc");
    }
}
