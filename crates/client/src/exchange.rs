//! Exchanges and subscriptions over a connection on the caller's endpoint.

use std::time::Duration;

use anyhow::Context as _;
use auth_wire::v2::SignedRequest;
use iroh::endpoint::{Connection, RecvStream};
use iroh::{Endpoint, EndpointAddr};
use serde_json::Value;

use crate::wire::{
    CONTROL_ALPN, ControlRequest, ControlResponse, MAX_FRAME, SubscribeFrame, read_frame,
    read_item, write_item, write_stream_head,
};

/// Deadline on one exchange over a fresh connection, from the dial to the
/// answer being read: the node's own bound on an exchange.
const EXCHANGE_DEADLINE: Duration = Duration::from_secs(60);

/// How long a snapshot read may go without progress before it fails. There
/// is no total-time bound: a value of any size streams while bytes arrive.
pub const SNAPSHOT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Sends one request to `node` over a fresh connection on `endpoint` and
/// returns its answer, closing the connection once read.
pub async fn request(
    endpoint: &Endpoint,
    node: impl Into<EndpointAddr>,
    request: ControlRequest,
) -> anyhow::Result<ControlResponse> {
    tokio::time::timeout(EXCHANGE_DEADLINE, async {
        let connection = endpoint
            .connect(node, CONTROL_ALPN)
            .await
            .context("connecting to the node's control protocol")?;
        let response = request_on(&connection, request).await;
        connection.close(0u32.into(), b"done");
        response
    })
    .await
    .context("control exchange timed out")?
}

/// Sends one request over a new bidirectional stream on an open control
/// connection and returns its answer; the connection stays open for the
/// caller's next stream.
pub async fn request_on(
    connection: &Connection,
    request: ControlRequest,
) -> anyhow::Result<ControlResponse> {
    let (mut send, mut recv) = connection.open_bi().await.context("opening stream")?;
    let encoded = postcard::to_stdvec(&request).context("encoding control request")?;
    send.write_all(&encoded).await.context("writing request")?;
    send.finish().context("finishing request")?;
    let raw = recv
        .read_to_end(MAX_FRAME)
        .await
        .context("reading control response")?;
    postcard::from_bytes(&raw).context("decoding control response")
}

/// An open control subscription: the connection and its receive stream, kept
/// so the node keeps writing frames until the holder drops this or the node
/// ends the stream.
pub struct Subscription {
    connection: Connection,
    recv: RecvStream,
}

impl Subscription {
    /// Reads the next frame, or `None` once the node finished the stream.
    pub async fn next(&mut self) -> anyhow::Result<Option<SubscribeFrame>> {
        read_frame(&mut self.recv).await
    }

    /// Closes the connection, telling the node to stop the subscription
    /// (and every other stream on that connection).
    pub fn close(self) {
        self.connection.close(0u32.into(), b"unsubscribe");
    }

    /// Stops this subscription's own stream and leaves the connection to the
    /// other streams sharing it: the node ends the subscription and releases
    /// its slot when it sees the stop.
    pub fn stop(mut self) {
        let _ = self.recv.stop(0u32.into());
    }
}

/// Opens a subscription over a fresh connection on `endpoint`. `request`
/// must be a [`ControlRequest::Subscribe`]; the node answers `Accepted` or
/// `Ended` as its first frame.
pub async fn subscribe(
    endpoint: &Endpoint,
    node: impl Into<EndpointAddr>,
    request: ControlRequest,
) -> anyhow::Result<Subscription> {
    let connection = endpoint
        .connect(node, CONTROL_ALPN)
        .await
        .context("connecting to the node's control protocol")?;
    subscribe_on(&connection, request).await
}

/// Opens a subscription over a new bidirectional stream on an open control
/// connection, which stays open for the caller's other streams.
pub async fn subscribe_on(
    connection: &Connection,
    request: ControlRequest,
) -> anyhow::Result<Subscription> {
    let (mut send, recv) = connection.open_bi().await.context("opening stream")?;
    let encoded = postcard::to_stdvec(&request).context("encoding subscribe request")?;
    send.write_all(&encoded)
        .await
        .context("writing subscribe request")?;
    send.finish().context("finishing subscribe request")?;
    Ok(Subscription {
        connection: connection.clone(),
        recv,
    })
}

/// Sends a `read-value` or `read-release` request on an open connection and
/// returns the signed header and the stream the bytes follow on.
pub async fn read_streamed(
    connection: &Connection,
    request: SignedRequest,
) -> anyhow::Result<(ControlResponse, RecvStream)> {
    let (mut send, mut recv) = connection.open_bi().await.context("opening stream")?;
    let encoded = postcard::to_stdvec(&ControlRequest::Signed(Box::new(request)))?;
    send.write_all(&encoded).await?;
    send.finish()?;
    let header = read_item(&mut recv)
        .await?
        .context("the node answered nothing")?;
    Ok((postcard::from_bytes(&header)?, recv))
}

/// Writes a `put-many` exchange: the tag of [`ControlRequest::Stream`], the
/// signed request length-prefixed, then each item length-prefixed (JSON
/// `{"op":"put","key","value"}` or `{"op":"del","key"}`), then the end of the
/// stream; returns the node's answer.
pub async fn put_many(
    connection: &Connection,
    request: SignedRequest,
    items: impl IntoIterator<Item = Value>,
) -> anyhow::Result<ControlResponse> {
    let (mut send, mut recv) = connection.open_bi().await.context("opening stream")?;
    write_stream_head(&mut send, &request).await?;
    for item in items {
        write_item(&mut send, &serde_json::to_vec(&item)?).await?;
    }
    send.finish()?;
    let raw = recv.read_to_end(MAX_FRAME).await?;
    Ok(postcard::from_bytes(&raw)?)
}

/// Opens one snapshot and verifies the node's signed header against the exact
/// request. There is no reconnect or replay after this stream is opened.
pub async fn snapshot_on(
    connection: &Connection,
    request: SignedRequest,
) -> Result<(crate::OperatorSnapshotHeader, NativeSnapshot), crate::ClientError> {
    let (response, recv) = read_streamed(connection, request.clone())
        .await
        .map_err(crate::ClientError::Unavailable)?;
    let ControlResponse::Signed(response) = response else {
        return Err(crate::ClientError::Invalid("snapshot header is not signed"));
    };
    let payload = crate::verify_response(&response, &request, &connection.remote_id())?;
    let header: crate::OperatorSnapshotHeader = serde_json::from_value(payload)
        .map_err(|_| crate::ClientError::Invalid("snapshot header shape"))?;
    if header.snapshot_id.is_empty() || header.authority.is_empty() {
        return Err(crate::ClientError::Invalid("empty snapshot identity"));
    }
    Ok((
        header,
        NativeSnapshot::new(connection.clone(), recv, SNAPSHOT_IDLE_TIMEOUT),
    ))
}

/// A selected entry, or the verified terminal boundary.
#[derive(Debug)]
pub enum NativeSnapshotItem {
    Entry {
        metadata: crate::Entry,
        /// The entry's complete bytes (empty for a tombstone), or `None` when
        /// the node does not hold them complete; `metadata.content_status`
        /// says how far it is.
        value: Option<Vec<u8>>,
    },
    Complete,
}

/// The node ended a snapshot with an explicit refusal, such as
/// `authority-changed`, rather than completing it.
#[derive(Debug, thiserror::Error)]
#[error("snapshot failed: {code}: {message}")]
pub struct SnapshotFailed {
    pub code: String,
    pub message: String,
}

/// One non-resumable snapshot stream. Dropping it stops this receive stream,
/// leaving other exchanges on the retained connection alone.
pub struct NativeSnapshot {
    _connection: Connection,
    recv: RecvStream,
    idle: Duration,
    ended: bool,
    reading: bool,
}

impl NativeSnapshot {
    /// Constructed only after snapshot_on verifies the signed initial header.
    fn new(connection: Connection, recv: RecvStream, idle: Duration) -> Self {
        Self {
            _connection: connection,
            recv,
            idle,
            ended: false,
            reading: false,
        }
    }

    pub async fn next(&mut self) -> anyhow::Result<Option<NativeSnapshotItem>> {
        if self.ended {
            return Ok(None);
        }
        if self.reading {
            self.ended = true;
            let _ = self.recv.stop(0u32.into());
            anyhow::bail!("a cancelled snapshot read cannot resume");
        }
        // If this future is cancelled after consuming part of a frame/body,
        // the reader remains poisoned rather than interpreting a suffix as a frame.
        self.reading = true;
        let result = self.read_next().await;
        self.reading = false;
        if result.is_err() {
            self.ended = true;
            let _ = self.recv.stop(0u32.into());
        }
        result
    }

    async fn read_next(&mut self) -> anyhow::Result<Option<NativeSnapshotItem>> {
        let bytes = tokio::time::timeout(self.idle, read_item(&mut self.recv))
            .await
            .context("snapshot stalled")??
            .context("snapshot ended before Complete")?;
        let (frame, remainder) = postcard::take_from_bytes::<crate::OperatorSnapshotFrame>(&bytes)?;
        anyhow::ensure!(
            remainder.is_empty(),
            "extra bytes inside snapshot metadata frame"
        );
        match frame {
            crate::OperatorSnapshotFrame::Entry(metadata) => {
                anyhow::ensure!(
                    !metadata.tombstone
                        || (metadata.len == 0 && metadata.content_status == "complete"),
                    "tombstone carries value bytes"
                );
                if metadata.content_status != "complete" {
                    return Ok(Some(NativeSnapshotItem::Entry {
                        metadata,
                        value: None,
                    }));
                }
                let length = usize::try_from(metadata.len)
                    .context("value length cannot be represented on this platform")?;
                let mut value = Vec::new();
                value
                    .try_reserve_exact(length)
                    .context("allocating one snapshot value")?;
                value.resize(length, 0);
                let mut filled = 0;
                while filled < length {
                    let read =
                        tokio::time::timeout(self.idle, self.recv.read(&mut value[filled..]))
                            .await
                            .context("snapshot value stalled")?
                            .context("reading complete snapshot value")?
                            .context("snapshot ended inside a value")?;
                    filled += read;
                }
                Ok(Some(NativeSnapshotItem::Entry {
                    metadata,
                    value: Some(value),
                }))
            }
            crate::OperatorSnapshotFrame::Complete => {
                anyhow::ensure!(
                    tokio::time::timeout(self.idle, read_item(&mut self.recv))
                        .await
                        .context("snapshot stalled after Complete")??
                        .is_none(),
                    "data follows snapshot Complete"
                );
                self.ended = true;
                Ok(Some(NativeSnapshotItem::Complete))
            }
            crate::OperatorSnapshotFrame::Error { code, message } => {
                Err(SnapshotFailed { code, message }.into())
            }
        }
    }
}

impl Drop for NativeSnapshot {
    fn drop(&mut self) {
        if !self.ended {
            let _ = self.recv.stop(0u32.into());
        }
    }
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;
    use crate::{Entry, OperatorSnapshotFrame};
    use iroh::{EndpointAddr, RelayMode, TransportAddr, endpoint::presets};
    use std::sync::Arc;

    struct WireFixture {
        client: Endpoint,
        server: Endpoint,
        peer: Connection,
        reader: NativeSnapshot,
        release: Arc<tokio::sync::Notify>,
        writer: tokio::task::JoinHandle<()>,
    }

    impl WireFixture {
        async fn start(bytes: Vec<u8>, hold_finish: bool) -> Self {
            Self::start_idle(bytes, hold_finish, SNAPSHOT_IDLE_TIMEOUT).await
        }
        async fn start_idle(bytes: Vec<u8>, hold_finish: bool, idle: Duration) -> Self {
            async fn endpoint() -> Endpoint {
                Endpoint::builder(presets::Minimal)
                    .relay_mode(RelayMode::Disabled)
                    .clear_ip_transports()
                    .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
                    .unwrap()
                    .alpns(vec![CONTROL_ALPN.to_vec()])
                    .bind()
                    .await
                    .unwrap()
            }
            let server = endpoint().await;
            let client = endpoint().await;
            let address = EndpointAddr::from_parts(
                server.id(),
                server.bound_sockets().into_iter().map(TransportAddr::Ip),
            );
            let (connected, accepted) =
                tokio::join!(client.connect(address, CONTROL_ALPN), async {
                    server.accept().await.unwrap().await.unwrap()
                });
            let connection = connected.unwrap();
            let peer = accepted;
            let release = Arc::new(tokio::sync::Notify::new());
            let writer = tokio::spawn({
                let peer = peer.clone();
                let release = release.clone();
                async move {
                    let (mut send, _recv) = peer.open_bi().await.unwrap();
                    send.write_all(&bytes).await.unwrap();
                    if hold_finish {
                        release.notified().await;
                    }
                    // A negative/cancelled reader deliberately stops this stream.
                    let _ = send.finish();
                    let _ = send.stopped().await;
                }
            });
            let (_send, recv) = connection.accept_bi().await.unwrap();
            Self {
                client,
                server,
                peer,
                reader: NativeSnapshot::new(connection, recv, idle),
                release,
                writer,
            }
        }
        async fn close(self) {
            drop(self.reader);
            self.release.notify_one();
            self.writer.await.unwrap();
            self.peer.close(0u32.into(), b"done");
            self.client.close().await;
            self.server.close().await;
        }
    }

    fn frame(out: &mut Vec<u8>, frame: OperatorSnapshotFrame) {
        let bytes = postcard::to_stdvec(&frame).unwrap();
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend(bytes);
    }
    fn entry() -> Entry {
        Entry {
            key: "utf8:a".into(),
            author: *iroh::SecretKey::from([3; 32]).public().as_bytes(),
            content_id: "synthetic-content".into(),
            len: 4,
            content_status: "complete".into(),
            version: u64::MAX - 1,
            tombstone: false,
        }
    }

    #[tokio::test]
    async fn snapshots_expose_bytes_then_complete_only_after_clean_eof() {
        let metadata = entry();
        let mut bytes = Vec::new();
        frame(&mut bytes, OperatorSnapshotFrame::Entry(metadata.clone()));
        bytes.extend_from_slice(b"data");
        let mut tombstone = metadata.clone();
        tombstone.key = "utf8:gone".into();
        tombstone.len = 0;
        tombstone.tombstone = true;
        frame(&mut bytes, OperatorSnapshotFrame::Entry(tombstone.clone()));
        frame(&mut bytes, OperatorSnapshotFrame::Complete);
        let mut wire = WireFixture::start(bytes, false).await;
        let NativeSnapshotItem::Entry {
            metadata: actual,
            value,
        } = wire.reader.next().await.unwrap().unwrap()
        else {
            panic!("entry");
        };
        assert_eq!(actual, metadata);
        assert_eq!(value.as_deref(), Some(&b"data"[..]));
        let Some(NativeSnapshotItem::Entry { metadata, value }) = wire.reader.next().await.unwrap()
        else {
            panic!("tombstone");
        };
        assert_eq!(metadata, tombstone);
        assert_eq!(value.as_deref(), Some(&[][..]));
        assert!(matches!(
            wire.reader.next().await.unwrap(),
            Some(NativeSnapshotItem::Complete)
        ));
        assert!(wire.reader.next().await.unwrap().is_none());
        wire.close().await;

        let mut bytes = Vec::new();
        frame(&mut bytes, OperatorSnapshotFrame::Complete);
        let mut wire = WireFixture::start(bytes, false).await;
        assert!(matches!(
            wire.reader.next().await.unwrap(),
            Some(NativeSnapshotItem::Complete)
        ));
        wire.close().await;
    }

    #[tokio::test]
    async fn malformed_or_incomplete_snapshot_streams_never_complete() {
        for case in 0..7 {
            let mut bytes = Vec::new();
            match case {
                0 => {
                    frame(&mut bytes, OperatorSnapshotFrame::Entry(entry()));
                    bytes.extend(b"cut");
                }
                1 => {
                    frame(&mut bytes, OperatorSnapshotFrame::Entry(entry()));
                    bytes.extend(b"data");
                }
                2 => {
                    frame(&mut bytes, OperatorSnapshotFrame::Complete);
                    frame(&mut bytes, OperatorSnapshotFrame::Complete);
                }
                3 => {
                    frame(&mut bytes, OperatorSnapshotFrame::Complete);
                    bytes.push(0);
                }
                4 => frame(
                    &mut bytes,
                    OperatorSnapshotFrame::Error {
                        code: "unavailable".into(),
                        message: "missing content".into(),
                    },
                ),
                5 => {
                    let mut metadata = entry();
                    metadata.tombstone = true;
                    frame(&mut bytes, OperatorSnapshotFrame::Entry(metadata));
                }
                _ => {
                    let mut complete =
                        postcard::to_stdvec(&OperatorSnapshotFrame::Complete).unwrap();
                    complete.push(0);
                    bytes.extend_from_slice(&(complete.len() as u32).to_le_bytes());
                    bytes.extend(complete);
                }
            }
            let mut wire = WireFixture::start(bytes, false).await;
            let mut failed = false;
            loop {
                match wire.reader.next().await {
                    Err(_) => {
                        failed = true;
                        break;
                    }
                    Ok(Some(NativeSnapshotItem::Complete)) => {
                        panic!("case {case} falsely completed")
                    }
                    Ok(Some(NativeSnapshotItem::Entry { .. })) => {}
                    Ok(None) => break,
                }
            }
            assert!(failed, "case {case} must fail explicitly");
            wire.close().await;
        }
    }

    /// Review M6: a row the node does not hold complete carries no bytes and
    /// does not end the snapshot; the node's refusal reaches the reader typed.
    #[tokio::test]
    async fn an_unheld_row_is_reported_and_a_refusal_is_typed() {
        let mut missing = entry();
        missing.content_status = "missing".into();
        let mut bytes = Vec::new();
        frame(&mut bytes, OperatorSnapshotFrame::Entry(missing.clone()));
        frame(&mut bytes, OperatorSnapshotFrame::Entry(entry()));
        bytes.extend_from_slice(b"data");
        frame(
            &mut bytes,
            OperatorSnapshotFrame::Error {
                code: "authority-changed".into(),
                message: "changed".into(),
            },
        );
        let mut wire = WireFixture::start(bytes, false).await;
        let Some(NativeSnapshotItem::Entry { metadata, value }) = wire.reader.next().await.unwrap()
        else {
            panic!("unheld entry");
        };
        assert_eq!((metadata, value), (missing, None));
        let Some(NativeSnapshotItem::Entry { value, .. }) = wire.reader.next().await.unwrap()
        else {
            panic!("held entry");
        };
        assert_eq!(value.as_deref(), Some(&b"data"[..]));
        let error = wire.reader.next().await.unwrap_err();
        let failed = error
            .downcast_ref::<SnapshotFailed>()
            .expect("typed refusal");
        assert_eq!(failed.code, "authority-changed");
        wire.close().await;
    }

    /// A node that stops sending fails the read at the idle deadline rather
    /// than holding the reader forever.
    #[tokio::test]
    async fn a_stalled_snapshot_fails_at_its_idle_deadline() {
        let mut bytes = Vec::new();
        frame(&mut bytes, OperatorSnapshotFrame::Entry(entry()));
        bytes.extend_from_slice(b"da");
        let mut wire = WireFixture::start_idle(bytes, true, Duration::from_millis(300)).await;
        let started = std::time::Instant::now();
        let error = wire.reader.next().await.unwrap_err();
        assert!(format!("{error:#}").contains("stalled"), "{error:#}");
        assert!(started.elapsed() < Duration::from_secs(10));
        wire.close().await;
    }

    #[tokio::test]
    async fn a_cancelled_partial_body_cannot_be_reinterpreted_as_another_frame() {
        use std::{future::Future, task::Poll};
        let mut bytes = Vec::new();
        frame(&mut bytes, OperatorSnapshotFrame::Entry(entry()));
        bytes.push(b'd');
        let mut wire = WireFixture::start(bytes, true).await;
        let mut pending = Box::pin(wire.reader.next());
        std::future::poll_fn(|cx| {
            assert!(pending.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(pending);
        assert!(
            wire.reader
                .next()
                .await
                .unwrap_err()
                .to_string()
                .contains("cancelled")
        );
        wire.close().await;
    }
}
