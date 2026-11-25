//! The sidecar's admin call: a bounded client for `cmn-http`'s private
//! same-UID Unix socket at `<http_dir>/admin/admin.sock`.
//!
//! Like [`crate::local`], this call does not travel over iroh. It talks only to
//! a Unix socket on this machine, never over the network: it accepts the
//! sidecar's directory, not a URL. The framing is the sidecar's own: one
//! request per connection, a JSON object `{"op": …, "params": …}` ended by a
//! newline, and one newline-terminated JSON answer, `{"result": …}` or
//! `{"error": {"code", "message"}}`. The ops are the sidecar's; this client
//! does not name or check them. The sidecar keeps same-UID authorization;
//! this client additionally refuses an `admin` directory or socket that is a
//! symlink, belongs to another user or grants group or other access, and a
//! peer whose uid is not the caller's. A refusal because the socket belongs
//! to another user names that user and how to run as them.
//!
//! Ported from commons-node 7b4694e, `crates/cli/src/http.rs` (`admin`,
//! `check_socket`, `wrong_user`).

use std::path::Path;

/// The largest request line sent to the sidecar's admin socket, its newline
/// included: the sidecar refuses a longer one.
pub const SIDECAR_ADMIN_MAX_REQUEST: usize = 64 * 1024;
/// The largest answer line read from the sidecar's admin socket, its newline
/// included.
pub const SIDECAR_ADMIN_MAX_ANSWER: usize = 16 * 1024 * 1024;
/// The bound on one whole exchange: connect, request and answer.
pub const SIDECAR_ADMIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Why a socket of another user is refused, naming that user and how to run
/// as them. The hint names no program: this crate serves several, and a
/// caller that wants its own command in the hint wraps this message.
pub fn wrong_user(owner: u32) -> String {
    let name = user_name(owner);
    format!(
        "the sidecar's admin socket belongs to {name}, not to this user: run the command as \
         that user, e.g. `sudo -u {name}`"
    )
}

#[cfg(unix)]
fn user_name(uid: u32) -> String {
    /// The leading field of `struct passwd`, which is `pw_name` on every
    /// Unix this crate builds for; nothing past it is read.
    #[repr(C)]
    struct PasswdName {
        pw_name: *const std::ffi::c_char,
    }
    unsafe extern "C" {
        fn getpwuid(uid: u32) -> *const PasswdName;
    }
    // SAFETY: getpwuid returns a pointer into static storage or null; only
    // its first field is read, and the name is copied out before any other
    // call can reuse that storage.
    unsafe {
        let entry = getpwuid(uid);
        if entry.is_null() || (*entry).pw_name.is_null() {
            return format!("uid {uid}");
        }
        std::ffi::CStr::from_ptr((*entry).pw_name)
            .to_string_lossy()
            .into_owned()
    }
}

#[cfg(not(unix))]
fn user_name(uid: u32) -> String {
    format!("uid {uid}")
}

#[cfg(unix)]
fn effective_uid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    // SAFETY: geteuid has no preconditions or memory effects.
    unsafe { geteuid() }
}

/// Calls `op` with `params` on the sidecar's admin socket under `http_dir`
/// and returns the answer's `result`.
///
/// One request per connection. The request line is at most
/// [`SIDECAR_ADMIN_MAX_REQUEST`] bytes and is refused before connecting when
/// larger; the answer must be one newline-terminated line of at most
/// [`SIDECAR_ADMIN_MAX_ANSWER`] bytes; the whole exchange is bounded by
/// [`SIDECAR_ADMIN_TIMEOUT`]. An `error` answer is returned as an error
/// reading `<message> (<code>)`, and an answer without `result` is an error.
#[cfg(unix)]
pub async fn sidecar_admin_call(
    http_dir: &Path,
    op: &str,
    params: serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    use anyhow::{Context, bail, ensure};
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};

    let uid = effective_uid();
    // Reads one path's own metadata. A permission-denied read means a
    // directory on the way belongs to someone else: name its owner.
    let metadata = |path: &Path, what: &str| -> anyhow::Result<std::fs::Metadata> {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => Ok(metadata),
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                let owner = [http_dir.join("admin"), http_dir.to_path_buf()]
                    .iter()
                    .find_map(|dir| std::fs::metadata(dir).ok())
                    .map(|metadata| metadata.uid());
                match owner {
                    Some(owner) if owner != uid => bail!(wrong_user(owner)),
                    _ => Err(error).with_context(|| format!("reading the sidecar's {what}")),
                }
            }
            Err(error) => Err(error).with_context(|| {
                format!(
                    "cmn-http is not running here ({} is absent); start it first",
                    path.display()
                )
            }),
        }
    };

    let parent = http_dir.join("admin");
    let dir = metadata(&parent, "admin directory")?;
    // `symlink_metadata` reports a symlink as itself, never as a directory.
    ensure!(
        dir.is_dir(),
        "the sidecar's admin directory must be a directory, not a symlink"
    );
    if dir.uid() != uid {
        bail!(wrong_user(dir.uid()));
    }
    ensure!(
        dir.permissions().mode() & 0o077 == 0,
        "the sidecar's admin directory must be private (0700)"
    );
    let path = parent.join("admin.sock");
    let socket = metadata(&path, "admin socket")?;
    ensure!(
        socket.file_type().is_socket(),
        "not the sidecar's admin socket"
    );
    if socket.uid() != uid {
        bail!(wrong_user(socket.uid()));
    }
    ensure!(
        socket.permissions().mode() & 0o077 == 0,
        "the sidecar's admin socket must be private (0600)"
    );

    let mut line = serde_json::to_vec(&serde_json::json!({ "op": op, "params": params }))?;
    line.push(b'\n');
    ensure!(
        line.len() <= SIDECAR_ADMIN_MAX_REQUEST,
        "the sidecar admin request exceeds 64 KiB"
    );

    let answer = tokio::time::timeout(SIDECAR_ADMIN_TIMEOUT, async {
        let mut stream = tokio::net::UnixStream::connect(&path)
            .await
            .context("connecting to cmn-http")?;
        let peer = stream.peer_cred()?.uid();
        if peer != uid {
            bail!(wrong_user(peer));
        }
        stream.write_all(&line).await?;
        let mut answer = Vec::new();
        tokio::io::BufReader::new(stream)
            .take(SIDECAR_ADMIN_MAX_ANSWER as u64)
            .read_until(b'\n', &mut answer)
            .await?;
        anyhow::Ok(answer)
    })
    .await
    .context("the sidecar admin request timed out")??;

    if answer.last() != Some(&b'\n') {
        ensure!(
            answer.len() < SIDECAR_ADMIN_MAX_ANSWER,
            "cmn-http's answer exceeds 16 MiB"
        );
        bail!("cmn-http's answer ended without a newline");
    }
    let answer: serde_json::Value =
        serde_json::from_slice(&answer).context("reading cmn-http's answer")?;
    if let Some(error) = answer.get("error") {
        bail!(
            "{} ({})",
            error["message"].as_str().unwrap_or("refused"),
            error["code"].as_str().unwrap_or("error")
        );
    }
    answer
        .get("result")
        .cloned()
        .context("cmn-http's answer omitted its result")
}

/// Non-Unix targets have no sidecar admin socket; the call always fails.
#[cfg(not(unix))]
pub async fn sidecar_admin_call(
    _http_dir: &Path,
    _op: &str,
    _params: serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    anyhow::bail!("the sidecar's admin commands require a Unix socket")
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::{BufRead as _, Write as _};
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;

    /// A sidecar directory under the system temp dir, removed on drop. Kept
    /// short: a Unix socket path is limited to about 104 bytes on macOS.
    struct HttpDir(PathBuf);

    impl HttpDir {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "cnc-sc-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for HttpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Binds `<dir>/admin/admin.sock` as the sidecar does (directory 0700,
    /// socket 0600), then applies `dir_mode` and `socket_mode`.
    fn bind_admin_at(dir: &Path, dir_mode: u32, socket_mode: u32) -> UnixListener {
        let admin = dir.join("admin");
        std::fs::create_dir_all(&admin).unwrap();
        std::fs::set_permissions(&admin, std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = admin.join("admin.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(socket_mode)).unwrap();
        std::fs::set_permissions(&admin, std::fs::Permissions::from_mode(dir_mode)).unwrap();
        listener
    }

    fn bind_admin(dir: &Path) -> UnixListener {
        bind_admin_at(dir, 0o700, 0o600)
    }

    /// Reads one request line, writes `reply` verbatim, closes, and sends the
    /// request line it read back over the channel.
    fn serve_once(listener: UnixListener, reply: Vec<u8>) -> mpsc::Receiver<Vec<u8>> {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            std::io::BufReader::new(&stream)
                .read_until(b'\n', &mut request)
                .unwrap();
            // The client may stop reading at its bound and close; a broken
            // pipe here is the test's subject, not a failure.
            let _ = (&stream).write_all(&reply);
            let _ = (&stream).flush();
            drop(stream);
            let _ = tx.send(request);
        });
        rx
    }

    fn line(value: serde_json::Value) -> Vec<u8> {
        let mut bytes = value.to_string().into_bytes();
        bytes.push(b'\n');
        bytes
    }

    /// True when nothing has connected to the listener.
    fn nobody_connected(listener: &UnixListener) -> bool {
        listener.set_nonblocking(true).unwrap();
        matches!(
            listener.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        )
    }

    /// A success answer returns its `result`, and the request on the wire is
    /// one JSON line `{"op", "params"}` ended by a newline.
    #[tokio::test]
    async fn success_returns_result_and_sends_one_line() {
        let dir = HttpDir::new();
        let seen = serve_once(
            bind_admin(&dir.0),
            line(serde_json::json!({"result": {"running": true}})),
        );
        let result = sidecar_admin_call(&dir.0, "status", serde_json::json!({"verbose": true}))
            .await
            .unwrap();
        assert_eq!(result, serde_json::json!({"running": true}));

        let request = seen.recv().unwrap();
        assert_eq!(request.last(), Some(&b'\n'));
        assert_eq!(
            request.iter().filter(|byte| **byte == b'\n').count(),
            1,
            "exactly one line"
        );
        let request: serde_json::Value = serde_json::from_slice(&request).unwrap();
        assert_eq!(
            request,
            serde_json::json!({"op": "status", "params": {"verbose": true}})
        );
    }

    /// An `error` answer is an error carrying its message and code.
    #[tokio::test]
    async fn error_answer_surfaces_message_and_code() {
        let dir = HttpDir::new();
        let _seen = serve_once(
            bind_admin(&dir.0),
            line(serde_json::json!({"error": {"code": "unknown-op", "message": "no such op"}})),
        );
        let error = sidecar_admin_call(&dir.0, "nope", serde_json::json!({}))
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "no such op (unknown-op)");
    }

    /// An answer with neither `result` nor `error` is an error, not `null`.
    #[tokio::test]
    async fn missing_result_is_an_error() {
        let dir = HttpDir::new();
        let _seen = serve_once(bind_admin(&dir.0), line(serde_json::json!({})));
        let error = sidecar_admin_call(&dir.0, "status", serde_json::json!({}))
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "cmn-http's answer omitted its result");
    }

    /// A complete JSON answer that ends at close without its newline is
    /// refused.
    #[tokio::test]
    async fn answer_without_newline_is_refused() {
        let dir = HttpDir::new();
        let _seen = serve_once(
            bind_admin(&dir.0),
            serde_json::json!({"result": 1}).to_string().into_bytes(),
        );
        let error = sidecar_admin_call(&dir.0, "status", serde_json::json!({}))
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "cmn-http's answer ended without a newline"
        );
    }

    /// An answer line longer than the bound is refused, even when a newline
    /// follows it; one exactly at the bound is accepted.
    #[tokio::test]
    async fn oversized_answer_is_refused() {
        // `{"result":"xxx…"}` plus a newline, `extra` bytes over the bound.
        let answer = |extra: usize| {
            let framing = r#"{"result":""}"#.len() + 1;
            let body = "x".repeat(SIDECAR_ADMIN_MAX_ANSWER + extra - framing);
            line(serde_json::json!({ "result": body }))
        };
        let dir = HttpDir::new();
        let _seen = serve_once(bind_admin(&dir.0), answer(1));
        let error = sidecar_admin_call(&dir.0, "status", serde_json::json!({}))
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "cmn-http's answer exceeds 16 MiB");

        let dir = HttpDir::new();
        let _seen = serve_once(bind_admin(&dir.0), answer(0));
        let result = sidecar_admin_call(&dir.0, "status", serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(
            result.as_str().map(str::len),
            Some(SIDECAR_ADMIN_MAX_ANSWER - 14)
        );
    }

    /// A request line over 64 KiB is refused before any connection is made.
    #[tokio::test]
    async fn oversized_request_is_refused_before_connecting() {
        let dir = HttpDir::new();
        let listener = bind_admin(&dir.0);
        let params = serde_json::json!({"blob": "x".repeat(SIDECAR_ADMIN_MAX_REQUEST)});
        let error = sidecar_admin_call(&dir.0, "source.declare", params)
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "the sidecar admin request exceeds 64 KiB"
        );
        assert!(nobody_connected(&listener));
    }

    /// A socket whose mode grants group or other access is refused before any
    /// connection is made.
    #[tokio::test]
    async fn shared_socket_is_refused() {
        for mode in [0o660, 0o606] {
            let dir = HttpDir::new();
            let listener = bind_admin_at(&dir.0, 0o700, mode);
            let error = sidecar_admin_call(&dir.0, "status", serde_json::json!({}))
                .await
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                "the sidecar's admin socket must be private (0600)",
                "mode {mode:o}"
            );
            assert!(nobody_connected(&listener), "mode {mode:o}");
        }
    }

    /// An admin directory whose mode grants group or other access is refused
    /// before any connection is made.
    #[tokio::test]
    async fn shared_admin_directory_is_refused() {
        for mode in [0o750, 0o705] {
            let dir = HttpDir::new();
            let listener = bind_admin_at(&dir.0, mode, 0o600);
            let error = sidecar_admin_call(&dir.0, "status", serde_json::json!({}))
                .await
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                "the sidecar's admin directory must be private (0700)",
                "mode {mode:o}"
            );
            assert!(nobody_connected(&listener), "mode {mode:o}");
        }
    }

    /// An admin directory that is a symlink to a real, private admin
    /// directory is refused before any connection is made.
    #[tokio::test]
    async fn symlinked_admin_directory_is_refused() {
        let real = HttpDir::new();
        let listener = bind_admin(&real.0);
        let dir = HttpDir::new();
        std::os::unix::fs::symlink(real.0.join("admin"), dir.0.join("admin")).unwrap();
        let error = sidecar_admin_call(&dir.0, "status", serde_json::json!({}))
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "the sidecar's admin directory must be a directory, not a symlink"
        );
        assert!(nobody_connected(&listener));
    }

    /// A socket path that is a symlink to a real, private socket is refused
    /// before any connection is made.
    #[tokio::test]
    async fn symlinked_socket_is_refused() {
        let real = HttpDir::new();
        let listener = bind_admin(&real.0);
        let dir = HttpDir::new();
        let admin = dir.0.join("admin");
        std::fs::create_dir(&admin).unwrap();
        std::fs::set_permissions(&admin, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(real.0.join("admin/admin.sock"), admin.join("admin.sock"))
            .unwrap();
        let error = sidecar_admin_call(&dir.0, "status", serde_json::json!({}))
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "not the sidecar's admin socket");
        assert!(nobody_connected(&listener));
    }

    /// A sidecar that accepts and never answers is cut off by the exchange
    /// bound. Takes [`SIDECAR_ADMIN_TIMEOUT`] of wall time.
    #[tokio::test]
    async fn silent_sidecar_times_out() {
        let dir = HttpDir::new();
        let listener = bind_admin(&dir.0);
        let (release, held) = mpsc::channel::<()>();
        std::thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
            let _ = held.recv();
        });
        let error = tokio::time::timeout(
            SIDECAR_ADMIN_TIMEOUT + std::time::Duration::from_secs(10),
            sidecar_admin_call(&dir.0, "status", serde_json::json!({})),
        )
        .await
        .expect("the call returns within its own bound")
        .unwrap_err();
        drop(release);
        assert_eq!(error.to_string(), "the sidecar admin request timed out");
    }

    /// An absent socket says the sidecar is not running here.
    #[tokio::test]
    async fn absent_socket_says_not_running() {
        let dir = HttpDir::new();
        let admin = dir.0.join("admin");
        std::fs::create_dir(&admin).unwrap();
        std::fs::set_permissions(&admin, std::fs::Permissions::from_mode(0o700)).unwrap();
        let error = sidecar_admin_call(&dir.0, "status", serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .starts_with("cmn-http is not running here"),
            "{error}"
        );
    }

    /// The another-user refusal names that user and how to run as them.
    #[test]
    fn wrong_user_names_the_sidecar_user() {
        let message = wrong_user(0);
        assert!(message.contains(&user_name(0)), "{message}");
        let name = user_name(0);
        assert_eq!(
            message,
            format!(
                "the sidecar's admin socket belongs to {name}, not to this user: run the \
                 command as that user, e.g. `sudo -u {name}`"
            )
        );
        assert_ne!(user_name(0), "uid 0", "root has a name on every Unix");
        assert!(wrong_user(4_000_000).contains("uid 4000000"));
    }
}
