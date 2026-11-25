//! A signed control session over one connection: open, renew, call,
//! subscribe.

use auth_wire::ResponseStatus;
use auth_wire::v2::{Audience, Principal, SessionCertificate, SignedRequest, SignedResponse};
use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey};
use serde::Serialize;
use serde_json::{Value, json};

use crate::exchange::{Subscription, request_on, subscribe_on};
use crate::wire::{
    AUDIENCE_SERVICE, AdmissionRequestParams, AdmissionStatus, CONTROL_ALPN, ControlRequest,
    ControlResponse, OP_ADMISSION_CANCEL, OP_ADMISSION_REQUEST, OP_ADMISSION_STATUS,
    OP_OPEN_SESSION, OP_SUBSCRIBE, PARAMS_CODEC, RESPONSE_CODEC,
};

/// Why a call did not answer.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The node could not be reached, or the exchange failed in transit.
    #[error("the node could not be reached: {0:#}")]
    Unavailable(anyhow::Error),
    /// The node answered with a signed refusal; `payload` is its JSON body.
    #[error("the node refused: {code}")]
    Refused {
        code: String,
        retryable: bool,
        payload: Value,
    },
    /// The answer, or the session, failed its signature or binding checks.
    #[error("the node's answer is invalid: {0}")]
    Invalid(&'static str),
    /// The session cannot sign this call: expired, or the operation is not
    /// in its certificate.
    #[error("the session cannot make this call: {0}")]
    Session(&'static str),
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or_default()
}

fn random<const N: usize>() -> [u8; N] {
    let seed = SecretKey::generate().to_bytes();
    let mut out = [0u8; N];
    out.copy_from_slice(&seed[..N]);
    out
}

/// A new signed request for `operation`, unsigned yet, valid for the
/// envelope's whole request lifetime.
fn new_request(
    principal: Principal,
    audience: Audience,
    operation: &str,
    payload: Vec<u8>,
    idempotency_key: Option<[u8; 16]>,
) -> SignedRequest {
    let now = now_ms();
    SignedRequest {
        version: auth_wire::v2::VERSION,
        request_id: random(),
        principal,
        audience,
        operation: operation.into(),
        nonce: random(),
        issued_at_ms: now,
        expires_at_ms: now.saturating_add(auth_wire::MAX_REQUEST_LIFETIME_MS),
        idempotency_key,
        payload_codec: PARAMS_CODEC.into(),
        payload,
        proofs: Vec::new(),
    }
}

/// Checks a signed answer against the request it answers and the node that
/// must have signed it, and returns its JSON: the result on success, a
/// [`ClientError::Refused`] carrying the node's error body otherwise.
pub fn verify_response(
    response: &SignedResponse,
    request: &SignedRequest,
    node: &EndpointId,
) -> Result<Value, ClientError> {
    auth_wire::verify(response, node.as_bytes())
        .map_err(|_| ClientError::Invalid("response signature"))?;
    let digest = request
        .digest()
        .map_err(|_| ClientError::Invalid("request digest"))?;
    if response.issuer_key != *node.as_bytes()
        || response.request_id != request.request_id
        || response.request_digest != digest
        || response.audience_principal != request.principal
        || response.payload_codec != RESPONSE_CODEC
    {
        return Err(ClientError::Invalid("response binding"));
    }
    let now = now_ms();
    let skewed = now.saturating_add(auth_wire::MAX_FUTURE_CLOCK_SKEW_MS);
    if response.issued_at_ms > skewed
        || response.authorized_at_ms > skewed
        || now >= response.expires_at_ms
        || now.saturating_sub(response.authorized_at_ms) > auth_wire::MAX_AUTHORIZATION_STALENESS_MS
    {
        return Err(ClientError::Invalid("response validity"));
    }
    let payload = serde_json::from_slice::<Value>(&response.payload);
    match &response.status {
        ResponseStatus::Success => {
            payload.map_err(|_| ClientError::Invalid("the answer is not JSON"))
        }
        ResponseStatus::Error { code, retryable } => Err(ClientError::Refused {
            code: code.clone(),
            retryable: *retryable,
            payload: payload.unwrap_or(Value::Null),
        }),
    }
}

/// The session the node issued: its certificate, the key that signs each
/// session-principal request, and the next sequence.
struct Session {
    certificate: SessionCertificate,
    secret: SecretKey,
    next_sequence: u64,
}

/// A signed control session carried over one QUIC connection on the
/// caller's endpoint, every call and subscription a stream on it. The
/// node's certificate lasts at most five minutes; [`ControlClient::renew`]
/// opens a fresh one over the same connection, so a renewal ends no
/// subscription and dials nothing.
pub struct ControlClient {
    connection: Connection,
    node: EndpointId,
    audience: Audience,
    operations: Vec<String>,
    session: tokio::sync::Mutex<Session>,
}

impl ControlClient {
    /// Dials `node`'s control protocol from `endpoint` and opens a session
    /// on it for `operations`, signed by `key`, the endpoint's own key.
    pub async fn connect(
        endpoint: &Endpoint,
        node: impl Into<EndpointAddr>,
        key: &SecretKey,
        operations: &[&str],
    ) -> Result<Self, ClientError> {
        let connection = endpoint
            .connect(node, CONTROL_ALPN)
            .await
            .map_err(|error| ClientError::Unavailable(error.into()))?;
        Self::open(connection, key, operations).await
    }

    /// Opens a session for `operations` on a control connection the caller
    /// already holds (one from a connection pool, say); the client holds it
    /// from then on.
    pub async fn open(
        connection: Connection,
        key: &SecretKey,
        operations: &[&str],
    ) -> Result<Self, ClientError> {
        let node = connection.remote_id();
        let audience = Audience {
            service: AUDIENCE_SERVICE.into(),
            target_key: *node.as_bytes(),
        };
        let operations: Vec<String> = operations.iter().map(|op| (*op).to_owned()).collect();
        let session = open_session(&connection, &node, &audience, key, &operations).await?;
        Ok(Self {
            connection,
            node,
            audience,
            operations,
            session: tokio::sync::Mutex::new(session),
        })
    }

    /// Opens a fresh session over the held connection and swaps it in; calls
    /// go on over the still-valid session while the node answers. An error
    /// leaves the old session in place.
    pub async fn renew(&self, key: &SecretKey) -> Result<(), ClientError> {
        let session = open_session(
            &self.connection,
            &self.node,
            &self.audience,
            key,
            &self.operations,
        )
        .await?;
        *self.session.lock().await = session;
        Ok(())
    }

    /// When the current certificate ends, in Unix milliseconds.
    pub async fn expires_at_ms(&self) -> u64 {
        self.session.lock().await.certificate.expires_at_ms
    }

    /// The node this client speaks to.
    pub fn node(&self) -> EndpointId {
        self.node
    }

    /// The held connection, for unsigned reads and streamed exchanges on it.
    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    /// Closes the held connection, ending every subscription on it.
    pub fn close(&self) {
        self.connection.close(0u32.into(), b"done");
    }

    /// A session-principal request for `operation`, with a fresh sequence
    /// every call (the node refuses a replayed sequence rather than serving
    /// it again).
    async fn signed(
        &self,
        operation: &str,
        params: &(impl Serialize + ?Sized),
        idempotency_key: Option<[u8; 16]>,
    ) -> Result<SignedRequest, ClientError> {
        let payload = serde_json::to_vec(params).map_err(|_| ClientError::Invalid("params"))?;
        let mut session = self.session.lock().await;
        if now_ms() >= session.certificate.expires_at_ms {
            return Err(ClientError::Session("the session has expired"));
        }
        if !session
            .certificate
            .capabilities
            .iter()
            .any(|c| c == operation)
        {
            return Err(ClientError::Session("the operation is not in the session"));
        }
        let sequence = session.next_sequence;
        session.next_sequence = sequence
            .checked_add(1)
            .ok_or(ClientError::Session("the session's sequence is exhausted"))?;
        let mut request = new_request(
            Principal::Session {
                session_id: session.certificate.session_id,
                session_public: *session.secret.public().as_bytes(),
                sequence,
            },
            self.audience.clone(),
            operation,
            payload,
            idempotency_key,
        );
        request.expires_at_ms = request.expires_at_ms.min(session.certificate.expires_at_ms);
        request
            .add_proof(&session.secret)
            .map_err(|_| ClientError::Invalid("signing"))?;
        Ok(request)
    }

    /// One signed exchange: `params` are the operation's JSON arguments, the
    /// answer is the verified result.
    pub async fn call(
        &self,
        operation: &str,
        params: &(impl Serialize + ?Sized),
        idempotency_key: Option<[u8; 16]>,
    ) -> Result<Value, ClientError> {
        let request = self.signed(operation, params, idempotency_key).await?;
        let response = request_on(
            &self.connection,
            ControlRequest::Signed(Box::new(request.clone())),
        )
        .await
        .map_err(ClientError::Unavailable)?;
        let ControlResponse::Signed(response) = response else {
            return Err(ClientError::Invalid("not a signed answer"));
        };
        verify_response(&response, &request, &self.node)
    }

    /// Opens a subscription on a new stream of the held connection; the
    /// node's first frame is `Accepted` or `Ended`.
    pub async fn subscribe(
        &self,
        params: &(impl Serialize + ?Sized),
    ) -> Result<Subscription, ClientError> {
        let request = self.signed(OP_SUBSCRIBE, params, None).await?;
        subscribe_on(
            &self.connection,
            ControlRequest::Subscribe(Box::new(request)),
        )
        .await
        .map_err(ClientError::Unavailable)
    }
}

/// Asks the node at the other end of `connection` to admit this endpoint
/// (T296.1): a signed admission request carrying an optional short `note`
/// for the node's operator, waiting `expires_in_secs` (the node's longest,
/// seven days, when `None`). `key` is the endpoint's own key, the one the
/// connection was dialled with. A repeat while the request waits answers it
/// as it stands; a member is answered `Admitted`.
pub async fn request_admission(
    connection: &Connection,
    key: &SecretKey,
    note: Option<&str>,
    expires_in_secs: Option<u64>,
) -> Result<AdmissionStatus, ClientError> {
    let params = AdmissionRequestParams {
        note: note.map(str::to_owned),
        expires_in_secs,
    };
    admission_call(connection, key, OP_ADMISSION_REQUEST, &params).await
}

/// This endpoint's admission request at the node, as the node reads it.
pub async fn admission_status(
    connection: &Connection,
    key: &SecretKey,
) -> Result<AdmissionStatus, ClientError> {
    admission_call(connection, key, OP_ADMISSION_STATUS, &json!({})).await
}

/// Withdraws this endpoint's waiting admission request. Idempotent.
pub async fn cancel_admission(
    connection: &Connection,
    key: &SecretKey,
) -> Result<AdmissionStatus, ClientError> {
    admission_call(connection, key, OP_ADMISSION_CANCEL, &json!({})).await
}

/// One admission-request exchange as the endpoint principal, the answer
/// verified and bound to the request.
async fn admission_call(
    connection: &Connection,
    key: &SecretKey,
    operation: &str,
    params: &(impl Serialize + ?Sized),
) -> Result<AdmissionStatus, ClientError> {
    let node = connection.remote_id();
    let payload = serde_json::to_vec(params).map_err(|_| ClientError::Invalid("params"))?;
    let mut request = new_request(
        Principal::Endpoint {
            peer_id: *key.public().as_bytes(),
        },
        Audience {
            service: AUDIENCE_SERVICE.into(),
            target_key: *node.as_bytes(),
        },
        operation,
        payload,
        None,
    );
    request
        .add_proof(key)
        .map_err(|_| ClientError::Invalid("signing"))?;
    let response = request_on(
        connection,
        ControlRequest::Signed(Box::new(request.clone())),
    )
    .await
    .map_err(ClientError::Unavailable)?;
    let ControlResponse::Signed(response) = response else {
        return Err(ClientError::Invalid("not a signed answer"));
    };
    let value = verify_response(&response, &request, &node)?;
    serde_json::from_value(value).map_err(|_| ClientError::Invalid("not an admission status"))
}

/// `auth_openSession` on `connection` as the endpoint principal, the
/// certificate verified and bound to the request.
async fn open_session(
    connection: &Connection,
    node: &EndpointId,
    audience: &Audience,
    key: &SecretKey,
    operations: &[String],
) -> Result<Session, ClientError> {
    let principal = Principal::Endpoint {
        peer_id: *key.public().as_bytes(),
    };
    let secret = SecretKey::generate();
    let payload = serde_json::to_vec(&json!({
        "sessionPublic": secret.public().as_bytes(),
        "capabilities": operations,
    }))
    .map_err(|_| ClientError::Invalid("params"))?;
    let mut open = new_request(
        principal.clone(),
        audience.clone(),
        OP_OPEN_SESSION,
        payload,
        None,
    );
    open.add_proof(key)
        .map_err(|_| ClientError::Invalid("signing"))?;
    let response = request_on(connection, ControlRequest::Signed(Box::new(open.clone())))
        .await
        .map_err(ClientError::Unavailable)?;
    let certificate = match response {
        ControlResponse::Session(certificate) => *certificate,
        ControlResponse::Signed(refusal) => {
            verify_response(&refusal, &open, node)?;
            return Err(ClientError::Invalid("the session open was not answered"));
        }
        ControlResponse::Unsigned(_) => {
            return Err(ClientError::Invalid("the session open was not answered"));
        }
    };
    auth_wire::verify(&certificate, node.as_bytes())
        .map_err(|_| ClientError::Invalid("session certificate signature"))?;
    let now = now_ms();
    let skewed = now.saturating_add(auth_wire::MAX_FUTURE_CLOCK_SKEW_MS);
    let exact = certificate.capabilities.len() == operations.len()
        && operations
            .iter()
            .all(|op| certificate.capabilities.contains(op));
    if certificate.principal != principal
        || certificate.session_public != *secret.public().as_bytes()
        || certificate.audience != *audience
        || certificate.issuer_key != *node.as_bytes()
        || !exact
        || certificate.issued_at_ms > skewed
        || certificate.authorized_at_ms > skewed
        || now >= certificate.expires_at_ms
    {
        return Err(ClientError::Invalid("session certificate binding"));
    }
    Ok(Session {
        certificate,
        secret,
        next_sequence: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A request signed by `client` to `node`, and the node's signed answer
    /// to it carrying `payload`.
    fn answered(node: &SecretKey, payload: &[u8]) -> (SignedRequest, SignedResponse) {
        let client = SecretKey::generate();
        let mut request = new_request(
            Principal::Endpoint {
                peer_id: *client.public().as_bytes(),
            },
            Audience {
                service: AUDIENCE_SERVICE.into(),
                target_key: *node.public().as_bytes(),
            },
            crate::wire::OP_NODE_STATUS,
            b"[]".to_vec(),
            None,
        );
        request.add_proof(&client).unwrap();
        let now = now_ms();
        let mut response = SignedResponse {
            version: auth_wire::v2::VERSION,
            request_id: request.request_id,
            request_digest: request.digest().unwrap(),
            issuer_key: *node.public().as_bytes(),
            audience_principal: request.principal.clone(),
            issued_at_ms: now,
            expires_at_ms: now + 60_000,
            authorized_at_ms: now,
            status: ResponseStatus::Success,
            payload_codec: RESPONSE_CODEC.into(),
            payload: payload.to_vec(),
            signature: Vec::new(),
        };
        auth_wire::sign(&mut response, node).unwrap();
        (request, response)
    }

    /// The node answers JSON under RESPONSE_CODEC; a signed success whose
    /// payload is not JSON is an invalid answer, not a null result.
    #[test]
    fn verify_response_refuses_a_non_json_success_answer() {
        let node = SecretKey::generate();
        let (request, response) = answered(&node, br#"{"ok":true}"#);
        assert_eq!(
            verify_response(&response, &request, &node.public()).unwrap(),
            serde_json::json!({ "ok": true })
        );
        let (request, response) = answered(&node, b"not json");
        assert!(matches!(
            verify_response(&response, &request, &node.public()),
            Err(ClientError::Invalid(_))
        ));
    }
}
