//! The node's local admin call: a bounded HTTP/1 JSON-RPC 2.0 client for the
//! node's private same-UID Unix socket at `<data_dir>/admin/admin.sock`.
//!
//! This is the one call in this crate that does not travel over iroh. It talks
//! only to a Unix socket on this machine, never over the network: it accepts
//! a data directory, not a URL. It reads no keystore material. The node's
//! server keeps method classification and same-UID authorization; this client
//! additionally refuses a socket or directory that is a symlink, belongs to
//! another user or grants group or other access, and a peer whose uid is not
//! the caller's.
//!
//! Ported from commons-node 7b4694e, `crates/rpc/src/local_admin_client.rs`.

use std::path::Path;

/// The largest request body sent to the local admin socket.
pub const LOCAL_ADMIN_MAX_REQUEST: usize = 64 * 1024;
/// The largest response body read from the local admin socket.
pub const LOCAL_ADMIN_MAX_RESPONSE: usize = 8 * 1024 * 1024;
/// The bound on one whole exchange: connect, request and response.
pub const LOCAL_ADMIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Calls `method` with `params` on the node's local admin socket under
/// `data_dir` and returns the JSON-RPC `result`.
///
/// One request per connection (`Connection: close`). The request is at most
/// [`LOCAL_ADMIN_MAX_REQUEST`] bytes and is refused before connecting when
/// larger; the response body is at most [`LOCAL_ADMIN_MAX_RESPONSE`] bytes;
/// the whole exchange is bounded by [`LOCAL_ADMIN_TIMEOUT`]. The response must
/// carry `jsonrpc` `"2.0"` and `id` 1; an `error` object is returned as an
/// error with its message, and a response without `result` is an error.
///
/// The server keeps method classification and same-UID authorization. This
/// client reads no keystore material and accepts no network URL.
#[cfg(unix)]
pub async fn local_admin_call(
    data_dir: &Path,
    method: &str,
    params: serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    use anyhow::{Context, ensure};
    use http_body_util::{BodyExt, Full, Limited};
    use hyper::body::Bytes;
    use hyper_util::rt::TokioIo;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    // SAFETY: geteuid has no preconditions or memory effects.
    let uid = unsafe { geteuid() };
    let parent = data_dir.join("admin");
    let metadata = std::fs::symlink_metadata(&parent).context("reading local Admin directory")?;
    ensure!(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == uid
            && metadata.permissions().mode() & 0o077 == 0,
        "local Admin directory must be private and owned by the current user"
    );
    let path = parent.join("admin.sock");
    let metadata = std::fs::symlink_metadata(&path).context("reading local Admin socket")?;
    ensure!(
        metadata.file_type().is_socket()
            && metadata.uid() == uid
            && metadata.permissions().mode() & 0o077 == 0,
        "local Admin socket must be private and owned by the current user"
    );
    let payload = serde_json::to_vec(
        &serde_json::json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}),
    )?;
    ensure!(
        payload.len() <= LOCAL_ADMIN_MAX_REQUEST,
        "local Admin request exceeds 64 KiB"
    );
    tokio::time::timeout(LOCAL_ADMIN_TIMEOUT, async {
        let stream = tokio::net::UnixStream::connect(&path)
            .await
            .context("connecting to local Admin socket")?;
        ensure!(
            stream.peer_cred()?.uid() == uid,
            "local Admin peer is owned by another user"
        );
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
        let request = hyper::Request::post("http://localhost/")
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .header(hyper::header::CONNECTION, "close")
            .body(Full::new(Bytes::from(payload)))?;
        let response = async {
            let response = sender.send_request(request).await?;
            ensure!(
                response.status().is_success(),
                "local Admin HTTP request failed"
            );
            let bytes = Limited::new(response.into_body(), LOCAL_ADMIN_MAX_RESPONSE)
                .collect()
                .await
                .map_err(|error| anyhow::anyhow!("local Admin response body failed: {error}"))?
                .to_bytes();
            let value: serde_json::Value = serde_json::from_slice(&bytes)?;
            ensure!(
                value.get("jsonrpc").and_then(serde_json::Value::as_str) == Some("2.0")
                    && value.get("id").and_then(serde_json::Value::as_u64) == Some(1),
                "local Admin response binding mismatch"
            );
            if let Some(error) = value.get("error") {
                anyhow::bail!(
                    "local Admin RPC: {}",
                    error
                        .get("message")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("request failed")
                );
            }
            value
                .get("result")
                .cloned()
                .context("local Admin response omitted its result")
        };
        // The server closes this one-shot HTTP connection. Dropping the returned
        // socket avoids a second Unix shutdown after peer close (ENOTCONN on macOS),
        // while still awaiting and checking the complete HTTP transport.
        let (transport, response) = tokio::join!(connection.without_shutdown(), response);
        drop(transport?);
        response
    })
    .await
    .context("local Admin request timed out")?
}

/// Non-Unix targets have no local admin socket; the call always fails.
#[cfg(not(unix))]
pub async fn local_admin_call(
    _data_dir: &Path,
    _method: &str,
    _params: serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    anyhow::bail!("local Admin hosting commands require a Unix socket")
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;

    /// A data directory under the system temp dir, removed on drop. Kept short:
    /// a Unix socket path is limited to about 104 bytes on macOS.
    struct DataDir(PathBuf);

    impl DataDir {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "cnc-la-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for DataDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// What the fake server saw: the request head and the JSON body.
    struct Seen {
        head: String,
        body: serde_json::Value,
    }

    /// Binds `<data_dir>/admin/admin.sock` as the node's server would (the
    /// directory 0700 unless `dir_mode` says otherwise, the socket 0600) and
    /// returns the listener, non-blocking so a test can ask whether anyone
    /// connected.
    fn bind_admin(data_dir: &Path, dir_mode: u32) -> UnixListener {
        let admin = data_dir.join("admin");
        std::fs::create_dir_all(&admin).unwrap();
        std::fs::set_permissions(&admin, std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = admin.join("admin.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&admin, std::fs::Permissions::from_mode(dir_mode)).unwrap();
        listener
    }

    /// Answers one HTTP/1 request with `reply` as a 200 JSON body, then closes,
    /// and sends what it read back over the channel.
    fn serve_once(listener: UnixListener, reply: serde_json::Value) -> mpsc::Receiver<Seen> {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut bytes = Vec::new();
            let mut buf = [0u8; 4096];
            let (header_end, length) = loop {
                let count = stream.read(&mut buf).unwrap();
                assert!(count > 0, "client closed before the request head");
                bytes.extend_from_slice(&buf[..count]);
                if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = std::str::from_utf8(&bytes[..end]).unwrap();
                    let length = head
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())?
                        })
                        .expect("content-length");
                    break (end + 4, length);
                }
            };
            while bytes.len() < header_end + length {
                let count = stream.read(&mut buf).unwrap();
                assert!(count > 0, "client closed before the request body");
                bytes.extend_from_slice(&buf[..count]);
            }
            let head = String::from_utf8(bytes[..header_end].to_vec()).unwrap();
            let body = serde_json::from_slice(&bytes[header_end..header_end + length]).unwrap();
            let reply = reply.to_string();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                reply.len(),
                reply
            )
            .unwrap();
            stream.flush().unwrap();
            let _ = tx.send(Seen { head, body });
        });
        rx
    }

    /// True when nothing has connected to the listener.
    fn nobody_connected(listener: &UnixListener) -> bool {
        listener.set_nonblocking(true).unwrap();
        matches!(
            listener.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        )
    }

    /// A success answer returns its `result`, and the request on the wire is a
    /// one-shot JSON-RPC 2.0 POST with id 1 carrying the method and params.
    #[tokio::test]
    async fn success_returns_result_and_sends_bound_request() {
        let dir = DataDir::new();
        let seen = serve_once(
            bind_admin(&dir.0, 0o700),
            serde_json::json!({"jsonrpc":"2.0","id":1,"result":{"stores":3}}),
        );
        let result = local_admin_call(&dir.0, "store.list", serde_json::json!({"all":true}))
            .await
            .unwrap();
        assert_eq!(result, serde_json::json!({"stores":3}));

        let seen = seen.recv().unwrap();
        // hyper's connection-level client writes the URI as given, so the
        // target is in absolute form, as the node's reference client sends it.
        assert!(
            seen.head.starts_with("POST http://localhost/ HTTP/1.1\r\n"),
            "{}",
            seen.head
        );
        let head = seen.head.to_ascii_lowercase();
        assert!(head.contains("\r\nconnection: close\r\n"), "{head}");
        assert!(
            head.contains("\r\ncontent-type: application/json\r\n"),
            "{head}"
        );
        assert_eq!(
            seen.body,
            serde_json::json!({"jsonrpc":"2.0","id":1,"method":"store.list","params":{"all":true}})
        );
    }

    /// A JSON-RPC `error` object is returned as an error carrying its message.
    #[tokio::test]
    async fn error_answer_surfaces_its_message() {
        let dir = DataDir::new();
        let _seen = serve_once(
            bind_admin(&dir.0, 0o700),
            serde_json::json!({"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}),
        );
        let error = local_admin_call(&dir.0, "no.such", serde_json::Value::Null)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "local Admin RPC: method not found");
    }

    /// A response for another request id is refused, even when it carries a
    /// result.
    #[tokio::test]
    async fn wrong_id_is_a_binding_mismatch() {
        let dir = DataDir::new();
        let _seen = serve_once(
            bind_admin(&dir.0, 0o700),
            serde_json::json!({"jsonrpc":"2.0","id":2,"result":{"stores":3}}),
        );
        let error = local_admin_call(&dir.0, "store.list", serde_json::Value::Null)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "local Admin response binding mismatch");
    }

    /// A response with neither `result` nor `error` is an error, not `null`.
    #[tokio::test]
    async fn missing_result_is_an_error() {
        let dir = DataDir::new();
        let _seen = serve_once(
            bind_admin(&dir.0, 0o700),
            serde_json::json!({"jsonrpc":"2.0","id":1}),
        );
        let error = local_admin_call(&dir.0, "store.list", serde_json::Value::Null)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "local Admin response omitted its result");
    }

    /// A request over 64 KiB is refused before any connection is made.
    #[tokio::test]
    async fn oversized_request_is_refused_before_connecting() {
        let dir = DataDir::new();
        let listener = bind_admin(&dir.0, 0o700);
        let params = serde_json::json!({"blob": "x".repeat(LOCAL_ADMIN_MAX_REQUEST)});
        let error = local_admin_call(&dir.0, "store.put", params)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "local Admin request exceeds 64 KiB");
        assert!(nobody_connected(&listener));
    }

    /// A socket in a directory with group or other bits set is refused before
    /// any connection is made.
    #[tokio::test]
    async fn shared_admin_directory_is_refused() {
        for mode in [0o750, 0o705] {
            let dir = DataDir::new();
            let listener = bind_admin(&dir.0, mode);
            let error = local_admin_call(&dir.0, "store.list", serde_json::Value::Null)
                .await
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                "local Admin directory must be private and owned by the current user",
                "mode {mode:o}"
            );
            assert!(nobody_connected(&listener), "mode {mode:o}");
        }
    }
}
