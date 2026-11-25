//! The key operations an admin asks of the node's HTTP door (node-admin
//! contract 8, part 1): their parameters and answers, the door's signed
//! answer, the frames of the stream the door holds open on its delegate
//! connection, and the seal that keeps a minted secret from the node.
//!
//! The node forwards the admin's own signed request to the door and returns
//! the door's [`KeyDoorAnswer`]: the door signs it with its delegate key over
//! the request's digest and the outcome, so the node cannot alter it. A
//! minted secret is sealed to the `sealTo` key in the request
//! ([`seal`], [`open`]); the node handles only the sealed form.

use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use serde::{Deserialize, Serialize};
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};

/// The most datasets a key an admin makes may name, one by one (S2).
pub const MAX_KEY_DATASETS: usize = 32;
/// The longest overlap a remote rotate may ask for: the old key stays live
/// this long beside its successor (F12).
pub const MAX_KEY_ROTATE_OVERLAP_SECS: u64 = 24 * 60 * 60;
/// The longest expiry an admin may set, from the door's own clock, unless the
/// door's configuration sets another (ruling 145).
pub const DEFAULT_MAX_KEY_LIFETIME_MS: u64 = 365 * 24 * 60 * 60 * 1000;
/// Requests in flight on the door's stream at once: the admin exchange
/// reserve.
pub const KEY_DOOR_IN_FLIGHT: usize = 8;
/// The door answers each request within this many milliseconds, below the
/// node's exchange deadline (L4).
pub const KEY_DOOR_ANSWER_MS: u64 = 30_000;
/// The door keeps the answer to each request id at least this long (S3).
pub const KEY_REQUEST_RETENTION_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// Refusals the door signs ([`KeyOutcome::Refused`]'s `code`), besides the
/// admin codes [`crate::REFUSAL_ADMIN_INVALID_PARAMS`],
/// [`crate::REFUSAL_ADMIN_NOT_FOUND`] and
/// [`crate::REFUSAL_ADMIN_NOT_OPERATOR_DATASET`].
///
/// Not signed by an admin's endpoint key for this node, or not an operation
/// the door serves.
pub const KEY_REFUSAL_UNAUTHORIZED: &str = "unauthorized";
/// Outside the request lifetime, or issued before the door last started.
/// Like [`KEY_REFUSAL_REPLAYED`], it does not say the request was not
/// carried out: re-sign it with the same request id, and the stored answer
/// comes back if it was, or it is carried out once if it was not.
pub const KEY_REFUSAL_STALE: &str = "stale";
/// The request's nonce was seen before: as [`KEY_REFUSAL_STALE`], re-sign
/// it with the same request id.
pub const KEY_REFUSAL_REPLAYED: &str = "replayed";
/// The request id was used before with other parameters (not retryable).
pub const KEY_REFUSAL_REQUEST_ID_REUSED: &str = "request_id_reused";
/// The door failed to carry out the request; nothing was made.
pub const KEY_REFUSAL_INTERNAL: &str = "internal";
/// The door recorded the request but could not put its key in place: the
/// key may be made. Send it again with the same request id; the door adds
/// the key and answers the stored outcome. The node answers this as its own
/// `outcome_unknown` and keeps nothing for an exact resend.
pub const KEY_REFUSAL_OUTCOME_UNKNOWN: &str = "outcome_unknown";
/// An approval came while the door holds as many requested keys awaiting
/// collection as it allows: nothing was made or recorded. Retryable once the
/// sweep revokes one past its deadline or a requester collects one; the node
/// puts the request back to waiting, as when the door is absent.
pub const KEY_REFUSAL_UNCOLLECTED_FULL: &str = "uncollected_full";

/// Who made a key and how. `by` is `"local"` (the operator on the node) or
/// the admin's endpoint id, z-base-32; a key written before this record
/// existed reads as `local` with no `how`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyMadeBy {
    pub by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub how: Option<KeyMadeHow>,
    /// For a key made by approving a person's request: the requester's
    /// endpoint id, z-base-32, the endpoint the key was made for (contract
    /// 8, "Who made each key").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub for_requester: Option<String>,
}

/// [`KeyMadeBy::by`] for the node's operator, and for the node itself when
/// it forwards the operator's approval of a key request.
pub const KEY_MADE_LOCALLY: &str = "local";

impl Default for KeyMadeBy {
    fn default() -> Self {
        Self {
            by: KEY_MADE_LOCALLY.into(),
            how: None,
            for_requester: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum KeyMadeHow {
    Create,
    Rotate,
    /// By approving a person's key request (contract 8, ruling 143).
    Approve,
}

// --- key requests (contract 8, "A person asks for a key, and an admin
// answers") -----------------------------------------------------------------

/// The permissions a key can carry, by name.
pub const KEY_SCOPES: &[&str] = &["read", "write", "ingest", "events", "create"];

/// The permissions never put on a key made for a requester: the one place
/// this rule is set. Open with the owner (contract 8, "What an admin may
/// create", M6); in force until the owner rules. The node refuses a request
/// that asks for one, and the door refuses an approval that grants one.
pub const REQUESTED_KEY_REFUSED_SCOPES: &[&str] = &["create"];

/// How long an approval's answer stands, at most: a key not collected by
/// then is revoked by the door (contract 8, steps 4 and 6).
pub const KEY_ANSWER_LIFETIME_MS: u64 = 24 * 60 * 60 * 1000;
/// The shortest and longest a key request waits, from when it was signed.
pub const MIN_KEY_REQUEST_TTL_MS: u64 = 60 * 1000;
pub const MAX_KEY_REQUEST_TTL_MS: u64 = 7 * 24 * 60 * 60 * 1000;
/// The longest note a key request carries, in bytes of UTF-8.
pub const MAX_KEY_REQUEST_NOTE_BYTES: usize = 280;

/// `keys.request`'s parameters: what a person asks for. Every field but
/// `requestId` and `expiresInSecs` is also what an approval is checked
/// against: the grant is at most this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyRequestParams {
    /// The request's own id, chosen by the App: an approval is kept once
    /// for the requester and this id, whichever admin approves.
    #[serde(with = "hex_array")]
    pub request_id: [u8; 16],
    /// 1 to [`MAX_KEY_DATASETS`] dataset ids, one by one, each once.
    pub datasets: Vec<String>,
    /// 1 or more of [`KEY_SCOPES`], each once, none of
    /// [`REQUESTED_KEY_REFUSED_SCOPES`].
    pub scopes: Vec<String>,
    /// The key's expiry asked, milliseconds since the epoch.
    pub expires_at: u64,
    /// The X25519 public key the key is sealed to.
    #[serde(with = "hex_array")]
    pub seal_to: [u8; 32],
    /// At most [`MAX_KEY_REQUEST_NOTE_BYTES`], shown to admins as plain
    /// text; the node refuses control and Unicode format characters.
    #[serde(default)]
    pub note: Option<String>,
    /// How long the request waits from its signing time, in seconds: 60 to
    /// 604800, seven days when absent.
    #[serde(default)]
    pub expires_in_secs: Option<u64>,
}

/// A key request's body in the node mailbox (family `KeyRequest`, a body of
/// at most 4096 bytes): the terms of [`KeyRequestParams`] as JSON, unknown
/// fields refused. The request's own id is the message id, and how long it
/// waits is the statement's expiry (at most seven days). Both paths read
/// their terms through one check ([`KeyRequestAsk`], [`check_ask`]), so the
/// same terms are refused on both.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyRequestBody {
    pub datasets: Vec<String>,
    pub scopes: Vec<String>,
    /// The key's expiry asked, milliseconds since the epoch.
    pub expires_at: u64,
    /// The X25519 public key the key is sealed to.
    #[serde(with = "hex_array")]
    pub seal_to: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// `keys.request.status`'s, `.cancel`'s and `.collect`'s parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyRequestIdParams {
    #[serde(with = "hex_array")]
    pub request_id: [u8; 16],
}

/// `keys.request.acknowledge`'s parameters: the requester has stored the
/// key `keyId` its request `requestId` was answered with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyRequestAcknowledgeParams {
    #[serde(with = "hex_array")]
    pub request_id: [u8; 16],
    pub key_id: String,
}

/// `keys.request.acknowledge`'s result, which the door signs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyCollected {
    pub key_id: String,
    /// False when it was collected before.
    pub changed: bool,
}

/// A key request's state, as its requester reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum KeyRequestState {
    Waiting,
    /// An admin approved it and the HTTP door is making the key.
    Deciding,
    /// The key is made: collect it.
    Approved,
    Declined,
    Cancelled,
    /// Nobody answered it before it expired.
    Expired,
    /// No request with this id from this endpoint is on record.
    None,
}

/// The answer to `keys.request`, `.status` and `.cancel`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyRequestStatus {
    pub state: KeyRequestState,
    /// While waiting: when the request expires, milliseconds.
    pub expires_at_ms: Option<u64>,
    /// While approved: when the answer stops standing; a key not collected
    /// by then is revoked.
    pub answer_expires_at_ms: Option<u64>,
}

/// `keys.request.collect`'s answer: the status, and the sealed answer while
/// it stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyRequestCollected {
    pub status: KeyRequestStatus,
    pub answer: Option<KeyRequestAnswer>,
}

/// The answer to an approved key request: what the node posts to the
/// requester and hands back on `keys.request.collect`. Only the sealed form
/// travels; the secret, the datasets and the permissions granted are inside
/// it ([`ApprovalGrant`]). The requester opens it only when
/// `request_digest` is of a copy of its request it sent itself, with
/// [`SealBinding`] `{ node, key_for: its own endpoint, request_digest }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyRequestAnswer {
    /// BLAKE3 of the requester's own signed request this answers, in clear.
    #[serde(with = "hex_array")]
    pub request_digest: [u8; 32],
    /// Kind [`SealKind::Approval`]; it carries the key id and the key's
    /// expiry in clear.
    pub sealed: SealedSecret,
    /// When this answer stops standing, milliseconds: one day after the key
    /// was made, never after the key's own expiry.
    pub answer_expires_at: u64,
}

/// The sealed part of an approval: the grant's bitmaps (5 bytes), the API
/// key (65 bytes: `cmnk_`, 16 hex digits, `_`, 43 base64url characters) and
/// the 16-byte tag.
pub const APPROVAL_CIPHERTEXT_BYTES: usize = 86;
/// The size of a key answer's body in the node mailbox (family `KeyAnswer`,
/// a body of at most 512 bytes): one fixed layout.
pub const KEY_ANSWER_BODY_BYTES: usize = 1 + 1 + 8 + 8 + 32 + 24 + 32 + APPROVAL_CIPHERTEXT_BYTES;

impl KeyRequestAnswer {
    /// The answer as the node posts it to the requester's mailbox, fixed at
    /// [`KEY_ANSWER_BODY_BYTES`]: the seal's version (1 byte, now 1), its
    /// kind (1 byte, 3 for an approval), the key id (8), the key's expiry
    /// (8, milliseconds, big-endian), the door's one-time public key (32),
    /// the nonce (24), the request digest (32), then the sealed part
    /// ([`APPROVAL_CIPHERTEXT_BYTES`]). When the answer stops standing is
    /// the statement's own expiry, so it is not in the body.
    pub fn mailbox_body(&self) -> Result<Vec<u8>, String> {
        let sealed = &self.sealed;
        if sealed.version != SEAL_VERSION || sealed.kind != SealKind::Approval {
            return Err("only an approval's seal of version 1 is posted".into());
        }
        if sealed.ciphertext.len() != APPROVAL_CIPHERTEXT_BYTES {
            return Err(format!(
                "an approval's sealed part is {APPROVAL_CIPHERTEXT_BYTES} bytes"
            ));
        }
        let mut body = Vec::with_capacity(KEY_ANSWER_BODY_BYTES);
        body.push(sealed.version);
        body.push(sealed.kind.byte());
        body.extend_from_slice(&sealed.key_id);
        body.extend_from_slice(&sealed.expires_at.to_be_bytes());
        body.extend_from_slice(&sealed.ephemeral);
        body.extend_from_slice(&sealed.nonce);
        body.extend_from_slice(&self.request_digest);
        body.extend_from_slice(&sealed.ciphertext);
        Ok(body)
    }

    /// Reads a [`Self::mailbox_body`], standing until `answer_expires_at`
    /// (the statement's expiry, milliseconds). Any other length, version or
    /// kind is refused.
    pub fn from_mailbox_body(body: &[u8], answer_expires_at: u64) -> Result<Self, String> {
        if body.len() != KEY_ANSWER_BODY_BYTES {
            return Err(format!("a key answer is {KEY_ANSWER_BODY_BYTES} bytes"));
        }
        if body[0] != SEAL_VERSION {
            return Err(format!("seal version {} is not supported", body[0]));
        }
        if body[1] != SealKind::Approval.byte() {
            return Err("a key answer carries an approval".into());
        }
        let field = |at: usize, len: usize| &body[at..at + len];
        Ok(Self {
            request_digest: field(74, 32).try_into().expect("32 bytes"),
            sealed: SealedSecret {
                version: body[0],
                kind: SealKind::Approval,
                key_id: field(2, 8).try_into().expect("8 bytes"),
                expires_at: u64::from_be_bytes(field(10, 8).try_into().expect("8 bytes")),
                ephemeral: field(18, 32).try_into().expect("32 bytes"),
                nonce: field(50, 24).try_into().expect("24 bytes"),
                ciphertext: body[106..].to_vec(),
            },
            answer_expires_at,
        })
    }
}

/// The requester's original signed request, as the node holds it: on
/// control/1 its `SignedRequest`, encoded; through the mailbox its
/// statement, the first copy the node read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "via", rename_all = "camelCase", deny_unknown_fields)]
pub enum KeyRequestCopy {
    Control {
        #[serde(with = "hex_vec")]
        bytes: Vec<u8>,
    },
    Mailbox {
        #[serde(with = "hex_vec")]
        bytes: Vec<u8>,
    },
}

impl KeyRequestCopy {
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Control { bytes } | Self::Mailbox { bytes } => bytes,
        }
    }

    /// BLAKE3 of the copy's bytes: what an approval's seal binds.
    pub fn digest(&self) -> [u8; 32] {
        *blake3::hash(self.bytes()).as_bytes()
    }
}

/// `admin.keys.requests.approve`'s parameters. The grant is at most what the
/// request asks: its datasets, its permissions, its expiry. The key is
/// sealed to the request's own `sealTo`, which these parameters cannot name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminKeyRequestApproveParams {
    pub request: KeyRequestCopy,
    pub name: String,
    pub datasets: Vec<String>,
    pub scopes: Vec<String>,
    /// Milliseconds since the epoch: at most the request's own `expiresAt`
    /// and the door's maximum from its own clock.
    pub expires_at: u64,
}

/// `admin.keys.requests.decline`'s parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminKeyRequestParams {
    /// The requester's endpoint id.
    pub requester: String,
    #[serde(with = "hex_array")]
    pub request_id: [u8; 16],
}

/// The door's result for an approval: the key as an admin sees it and the
/// sealed answer for the requester.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyRequestApproved {
    pub key: AdminKey,
    pub answer: KeyRequestAnswer,
}

/// What a key request asks, read from its requester's own signed bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRequestAsk {
    /// The endpoint whose signature the request carries.
    pub requester: [u8; 32],
    /// The request's own id.
    pub request_id: [u8; 16],
    pub datasets: Vec<String>,
    pub scopes: Vec<String>,
    pub expires_at: u64,
    pub seal_to: [u8; 32],
    pub note: Option<String>,
    /// When it was signed, and when it stops waiting, milliseconds.
    pub issued_at: u64,
    pub waits_until: u64,
    /// BLAKE3 of the signed bytes.
    pub digest: [u8; 32],
}

/// Why a copy of a key request is not taken.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum KeyRequestError {
    #[error("not a key request signed by its requester's endpoint key")]
    Signature,
    #[error("the key request is addressed to another node")]
    OtherNode,
    #[error("the key request is outside its lifetime")]
    Lifetime,
    #[error("{0}")]
    Invalid(String),
}

impl KeyRequestAsk {
    /// The request in a control/1 copy, checked offline: one proof, by the
    /// endpoint the principal names, that verifies; addressed to `node`; a
    /// `keys.request` with parameters in bounds. Its lifetime is checked
    /// apart ([`Self::open_at`]).
    pub fn from_control(bytes: &[u8], node: &[u8; 32]) -> Result<Self, KeyRequestError> {
        use auth_wire::v2::{Principal, SignedRequest};
        let request = SignedRequest::decode(bytes).map_err(|_| KeyRequestError::Signature)?;
        let Principal::Endpoint { peer_id } = request.principal else {
            return Err(KeyRequestError::Signature);
        };
        if request.proofs.len() != 1
            || request.proofs[0].signer != peer_id
            || request.verify_proofs().is_err()
        {
            return Err(KeyRequestError::Signature);
        }
        if request.audience.service != crate::AUDIENCE_SERVICE
            || request.audience.target_key != *node
        {
            return Err(KeyRequestError::OtherNode);
        }
        if request.operation != crate::OP_KEYS_REQUEST
            || request.payload_codec != crate::PARAMS_CODEC
        {
            return Err(KeyRequestError::Invalid("not a key request".into()));
        }
        let params: KeyRequestParams = serde_json::from_slice(&request.payload)
            .map_err(|error| KeyRequestError::Invalid(format!("invalid parameters: {error}")))?;
        let ttl = match params.expires_in_secs {
            None => MAX_KEY_REQUEST_TTL_MS,
            Some(secs) => secs.saturating_mul(1000),
        };
        if !(MIN_KEY_REQUEST_TTL_MS..=MAX_KEY_REQUEST_TTL_MS).contains(&ttl) {
            return Err(KeyRequestError::Invalid(
                "expiresInSecs is from 60 to 604800".into(),
            ));
        }
        Self::from_terms(
            peer_id,
            params.request_id,
            KeyRequestBody {
                datasets: params.datasets,
                scopes: params.scopes,
                expires_at: params.expires_at,
                seal_to: params.seal_to,
                note: params.note,
            },
            request.issued_at_ms,
            request.issued_at_ms.saturating_add(ttl),
            *blake3::hash(bytes).as_bytes(),
        )
    }

    /// The request in a mailbox copy, from the parts of its statement once
    /// commons-services `mailbox::read` has checked it (the signature, the
    /// network, this node as its recipient, the family `KeyRequest`, the
    /// body's ceiling): `sender` is its signer, `id` its message id, `body`
    /// a [`KeyRequestBody`], `expires_secs` its expiry, and `raw` the
    /// statement's signed bytes. It waits until its expiry, and reads as
    /// signed seven days before, so [`Self::open_at`] refuses one standing
    /// longer than seven days from now.
    pub fn from_mailbox(
        sender: [u8; 32],
        id: [u8; 16],
        body: &[u8],
        expires_secs: u32,
        raw: &[u8],
    ) -> Result<Self, KeyRequestError> {
        let body: KeyRequestBody = serde_json::from_slice(body)
            .map_err(|error| KeyRequestError::Invalid(format!("invalid parameters: {error}")))?;
        let waits_until = u64::from(expires_secs).saturating_mul(1000);
        Self::from_terms(
            sender,
            id,
            body,
            waits_until.saturating_sub(MAX_KEY_REQUEST_TTL_MS),
            waits_until,
            *blake3::hash(raw).as_bytes(),
        )
    }

    /// The one check of a request's terms, whichever way it came.
    fn from_terms(
        requester: [u8; 32],
        request_id: [u8; 16],
        terms: KeyRequestBody,
        issued_at: u64,
        waits_until: u64,
        digest: [u8; 32],
    ) -> Result<Self, KeyRequestError> {
        check_ask(&terms.datasets, &terms.scopes, terms.note.as_deref())?;
        Ok(Self {
            requester,
            request_id,
            datasets: terms.datasets,
            scopes: terms.scopes,
            expires_at: terms.expires_at,
            seal_to: terms.seal_to,
            note: terms.note,
            issued_at,
            waits_until,
            digest,
        })
    }

    /// Whether the request is within its own lifetime at `now`: signed no
    /// later than the clock skew allows, and still waiting.
    pub fn open_at(&self, now: u64) -> bool {
        self.issued_at <= now.saturating_add(auth_wire::MAX_FUTURE_CLOCK_SKEW_MS)
            && now < self.waits_until
            && self.waits_until.saturating_sub(self.issued_at) <= MAX_KEY_REQUEST_TTL_MS
    }

    /// What `datasets` and `scopes` grant of this request, as bitmaps over
    /// its own lists: each must be asked for, once, and no refused
    /// permission ([`REQUESTED_KEY_REFUSED_SCOPES`]) is ever granted.
    pub fn grant(&self, datasets: &[String], scopes: &[String]) -> Result<ApprovalGrant, String> {
        if datasets.is_empty() || scopes.is_empty() {
            return Err("an approval grants at least one dataset and one permission".into());
        }
        let mut grant = ApprovalGrant {
            datasets: 0,
            scopes: 0,
        };
        for dataset in datasets {
            let index = self
                .datasets
                .iter()
                .position(|asked| asked == dataset)
                .ok_or_else(|| format!("{dataset:?} is not a dataset the request asks for"))?;
            let bit = 1u32 << index;
            if grant.datasets & bit != 0 {
                return Err(format!("{dataset:?} is named twice"));
            }
            grant.datasets |= bit;
        }
        for scope in scopes {
            if REQUESTED_KEY_REFUSED_SCOPES.contains(&scope.as_str()) {
                return Err(format!("{scope:?} is never put on a requested key"));
            }
            let index = self
                .scopes
                .iter()
                .position(|asked| asked == scope)
                .ok_or_else(|| format!("{scope:?} is not a permission the request asks for"))?;
            let bit = 1u8 << index;
            if grant.scopes & bit != 0 {
                return Err(format!("{scope:?} is named twice"));
            }
            grant.scopes |= bit;
        }
        Ok(grant)
    }
}

/// A request's datasets, permissions and note checked against their bounds:
/// what the node files and the door approves.
pub fn check_ask(
    datasets: &[String],
    scopes: &[String],
    note: Option<&str>,
) -> Result<(), KeyRequestError> {
    let invalid = |message: String| Err(KeyRequestError::Invalid(message));
    if datasets.is_empty() || datasets.len() > MAX_KEY_DATASETS {
        return invalid(format!(
            "a key request names 1 to {MAX_KEY_DATASETS} datasets, one by one"
        ));
    }
    if (1..datasets.len()).any(|i| datasets[..i].contains(&datasets[i])) {
        return invalid("a dataset is named twice".into());
    }
    if scopes.is_empty() || scopes.len() > KEY_SCOPES.len() {
        return invalid("a key request asks for at least one permission".into());
    }
    if (1..scopes.len()).any(|i| scopes[..i].contains(&scopes[i])) {
        return invalid("a permission is named twice".into());
    }
    for scope in scopes {
        if !KEY_SCOPES.contains(&scope.as_str()) {
            return invalid(format!("{scope:?} is not a permission"));
        }
        if REQUESTED_KEY_REFUSED_SCOPES.contains(&scope.as_str()) {
            return invalid(format!("{scope:?} cannot be asked for in a key request"));
        }
    }
    if note.is_some_and(|note| note.len() > MAX_KEY_REQUEST_NOTE_BYTES) {
        return invalid(format!(
            "the note is at most {MAX_KEY_REQUEST_NOTE_BYTES} bytes"
        ));
    }
    Ok(())
}

/// What an approval grants, inside the seal: bitmaps over the request's own
/// dataset and permission lists (bit `i` is the `i`th entry), which the
/// requester holds, so the answer has one small fixed size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalGrant {
    pub datasets: u32,
    pub scopes: u8,
}

impl ApprovalGrant {
    /// The sealed plaintext: the dataset bitmap (4 bytes, big-endian), the
    /// permission bitmap (1 byte), then the API key.
    pub fn plaintext(&self, api_key: &str) -> Vec<u8> {
        let mut plaintext = Vec::with_capacity(5 + api_key.len());
        plaintext.extend_from_slice(&self.datasets.to_be_bytes());
        plaintext.push(self.scopes);
        plaintext.extend_from_slice(api_key.as_bytes());
        plaintext
    }

    /// The grant and the API key in an opened approval.
    pub fn read(plaintext: &[u8]) -> Result<(Self, String), SealError> {
        if plaintext.len() < 5 {
            return Err(SealError::Open);
        }
        let datasets = u32::from_be_bytes(plaintext[..4].try_into().expect("four bytes"));
        let api_key = String::from_utf8(plaintext[5..].to_vec()).map_err(|_| SealError::Open)?;
        Ok((
            Self {
                datasets,
                scopes: plaintext[4],
            },
            api_key,
        ))
    }
}

/// `admin.keys.create`'s parameters. Every dataset is named; there is no
/// "all datasets" and no key without an expiry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminKeyCreateParams {
    #[serde(with = "hex_array")]
    pub request_id: [u8; 16],
    pub name: String,
    pub scopes: Vec<String>,
    pub datasets: Vec<String>,
    /// Milliseconds since the epoch: in the future, and at most the door's
    /// maximum from its own clock.
    pub expires_at: u64,
    /// The X25519 public key the new secret is sealed to.
    #[serde(with = "hex_array")]
    pub seal_to: [u8; 32],
}

/// `admin.keys.rotate`'s parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminKeyRotateParams {
    #[serde(with = "hex_array")]
    pub request_id: [u8; 16],
    pub id: String,
    /// At most [`MAX_KEY_ROTATE_OVERLAP_SECS`].
    pub overlap_secs: u64,
    #[serde(with = "hex_array")]
    pub seal_to: [u8; 32],
}

/// `admin.keys.revoke`'s parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminKeyRevokeParams {
    #[serde(with = "hex_array")]
    pub request_id: [u8; 16],
    pub id: String,
}

/// `admin.http.expose`'s and `.unexpose`'s parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminHttpExposeParams {
    #[serde(with = "hex_array")]
    pub request_id: [u8; 16],
    pub dataset: String,
}

/// One key as `admin.keys.list` shows it: never its secret or its hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminKey {
    pub id: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub datasets: Vec<String>,
    pub all_node_datasets: bool,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub predecessor: Option<String>,
    pub last_used_at: Option<u64>,
    pub revoked_at: Option<u64>,
    pub made_by: KeyMadeBy,
}

/// `admin.keys.list`'s result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminKeyList {
    pub keys: Vec<AdminKey>,
}

/// `admin.keys.create`'s and `.rotate`'s result: the new key and its secret,
/// sealed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminKeyMinted {
    pub key: AdminKey,
    pub sealed: SealedSecret,
}

/// `admin.keys.revoke`'s result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminKeyRevoked {
    pub key: AdminKey,
    /// False when the key was already revoked.
    pub changed: bool,
}

/// `admin.http.expose`'s and `.unexpose`'s result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminHttpExposure {
    pub dataset: String,
    pub changed: bool,
}

/// What the door did with one request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "camelCase", deny_unknown_fields)]
pub enum KeyOutcome {
    /// Carried out (or answered from the stored answer): `result` is the
    /// operation's result above.
    Done { result: serde_json::Value },
    /// Refused; nothing changed.
    Refused { code: String, message: String },
}

/// The door's answer to one key request, which the node returns as its
/// success payload. The App checks `signature` against the delegate id
/// `admin.http.status` gave it, and `request_digest` against its own
/// request ([`KeyDoorAnswer::verify`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyDoorAnswer {
    #[serde(with = "hex_array")]
    pub request_digest: [u8; 32],
    /// The [`KeyOutcome`] as JSON text: signed as these bytes.
    pub outcome: String,
    #[serde(with = "hex_array")]
    pub signature: [u8; 64],
}

const ANSWER_DOMAIN: &[u8] = b"commons node-admin key-door answer v1\0";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeyDoorError {
    #[error("the answer is for another request")]
    OtherRequest,
    #[error("the answer is not signed by the HTTP door")]
    Signature,
    #[error("the answer's outcome does not decode: {0}")]
    Outcome(String),
}

impl KeyDoorAnswer {
    fn message(request_digest: &[u8; 32], outcome: &str) -> Vec<u8> {
        let mut message = Vec::with_capacity(ANSWER_DOMAIN.len() + 32 + outcome.len());
        message.extend_from_slice(ANSWER_DOMAIN);
        message.extend_from_slice(request_digest);
        message.extend_from_slice(outcome.as_bytes());
        message
    }

    /// The door's answer to the request with `request_digest`.
    pub fn sign(door: &iroh::SecretKey, request_digest: [u8; 32], outcome: &KeyOutcome) -> Self {
        let outcome = serde_json::to_string(outcome).expect("an outcome encodes");
        let signature = door
            .sign(&Self::message(&request_digest, &outcome))
            .to_bytes();
        Self {
            request_digest,
            outcome,
            signature,
        }
    }

    /// The outcome, once the answer is shown to be the door's (`door`, the
    /// delegate's endpoint id) and to answer the request with
    /// `request_digest`.
    pub fn verify(
        &self,
        door: &[u8; 32],
        request_digest: &[u8; 32],
    ) -> Result<KeyOutcome, KeyDoorError> {
        if &self.request_digest != request_digest {
            return Err(KeyDoorError::OtherRequest);
        }
        let key = iroh::PublicKey::from_bytes(door).map_err(|_| KeyDoorError::Signature)?;
        key.verify(
            &Self::message(&self.request_digest, &self.outcome),
            &iroh::Signature::from_bytes(&self.signature),
        )
        .map_err(|_| KeyDoorError::Signature)?;
        serde_json::from_str(&self.outcome)
            .map_err(|error| KeyDoorError::Outcome(error.to_string()))
    }
}

/// What the node writes on the door's stream, each frame a `u32 LE` length
/// and its postcard bytes ([`crate::write_item`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyDoorFrame {
    /// The node holds the stream as the door's.
    Accepted,
    /// The node refused or ended the stream.
    Ended { reason: String },
    /// The admin list now, and again on each change: the door drops the
    /// stored answers of an admin not on it.
    Admins { admins: Vec<[u8; 32]> },
    /// An admin's signed request, forwarded as the admin sent it
    /// (`SignedRequest::encode`). The answer repeats `id`.
    Request { id: u64, request: Vec<u8> },
}

/// What the door writes back, framed as [`KeyDoorFrame`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyDoorReply {
    pub id: u64,
    pub answer: KeyDoorAnswer,
}

// --- the seal (contract 8, "The secret is sealed to whoever it is for") ----

/// The seal's format version.
pub const SEAL_VERSION: u8 = 1;
/// The `blake3::derive_key` context of the seal key.
pub const SEAL_CONTEXT: &str = "commons node-admin key-seal v1";

/// For whom a secret was made: the associated data's kind byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SealKind {
    Create,
    Rotate,
    /// A key made by approving a person's request: sealed to the requester,
    /// and bound to the digest of the requester's own signed request.
    Approval,
}

impl SealKind {
    fn byte(self) -> u8 {
        match self {
            Self::Create => 1,
            Self::Rotate => 2,
            Self::Approval => 3,
        }
    }
}

/// A sealed secret, and what it carries in clear.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealedSecret {
    pub version: u8,
    pub kind: SealKind,
    #[serde(with = "hex_array")]
    pub key_id: [u8; 8],
    /// The key's expiry, milliseconds since the epoch.
    pub expires_at: u64,
    /// The door's one-time X25519 public key.
    #[serde(with = "hex_array")]
    pub ephemeral: [u8; 32],
    #[serde(with = "hex_array")]
    pub nonce: [u8; 24],
    #[serde(with = "hex_vec")]
    pub ciphertext: Vec<u8>,
}

/// What the opener supplies from what it holds, bound into the seal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealBinding {
    /// The node's endpoint id.
    pub node: [u8; 32],
    /// The endpoint the key is for: the admin, for create and rotate; the
    /// requester, for an approval.
    pub key_for: [u8; 32],
    /// For create and rotate, the digest of the admin's signed request
    /// (`SignedRequest::digest`); for an approval,
    /// [`KeyRequestCopy::digest`] of the requester's own request.
    pub request_digest: [u8; 32],
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SealError {
    #[error("seal version {0} is not supported")]
    Version(u8),
    #[error("the sealTo key gives no shared secret")]
    NonContributory,
    #[error("the sealed secret does not open")]
    Open,
}

/// The X25519 public key of `secret`: what a caller sends as `sealTo`.
pub fn seal_public(secret: [u8; 32]) -> [u8; 32] {
    x25519(secret, X25519_BASEPOINT_BYTES)
}

fn associated_data(
    version: u8,
    kind: SealKind,
    key_id: &[u8; 8],
    expires_at: u64,
    binding: &SealBinding,
) -> Vec<u8> {
    let mut ad = Vec::with_capacity(114);
    ad.push(version);
    ad.push(kind.byte());
    ad.extend_from_slice(&binding.node);
    ad.extend_from_slice(&binding.key_for);
    ad.extend_from_slice(key_id);
    ad.extend_from_slice(&expires_at.to_be_bytes());
    ad.extend_from_slice(&binding.request_digest);
    ad
}

fn cipher(
    shared: [u8; 32],
    ephemeral: &[u8; 32],
    seal_to: &[u8; 32],
) -> Result<XChaCha20Poly1305, SealError> {
    // An all-zero shared secret is what `was_contributory` refuses (L2).
    if shared == [0u8; 32] {
        return Err(SealError::NonContributory);
    }
    let mut material = [0u8; 96];
    material[..32].copy_from_slice(&shared);
    material[32..64].copy_from_slice(ephemeral);
    material[64..].copy_from_slice(seal_to);
    let key = blake3::derive_key(SEAL_CONTEXT, &material);
    Ok(XChaCha20Poly1305::new((&key).into()))
}

/// Seals `secret` to `seal_to`. The caller supplies the one-time key and the
/// nonce, fresh from its own randomness for every seal.
#[allow(clippy::too_many_arguments)]
pub fn seal(
    secret: &[u8],
    kind: SealKind,
    key_id: [u8; 8],
    expires_at: u64,
    seal_to: &[u8; 32],
    binding: &SealBinding,
    ephemeral_secret: [u8; 32],
    nonce: [u8; 24],
) -> Result<SealedSecret, SealError> {
    let ephemeral = seal_public(ephemeral_secret);
    let cipher = cipher(x25519(ephemeral_secret, *seal_to), &ephemeral, seal_to)?;
    let ad = associated_data(SEAL_VERSION, kind, &key_id, expires_at, binding);
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: secret,
                aad: &ad,
            },
        )
        .map_err(|_| SealError::Open)?;
    Ok(SealedSecret {
        version: SEAL_VERSION,
        kind,
        key_id,
        expires_at,
        ephemeral,
        nonce,
        ciphertext,
    })
}

/// Opens `sealed` with the secret of the `sealTo` key it was sealed to.
pub fn open(
    sealed: &SealedSecret,
    seal_to_secret: [u8; 32],
    binding: &SealBinding,
) -> Result<Vec<u8>, SealError> {
    if sealed.version != SEAL_VERSION {
        return Err(SealError::Version(sealed.version));
    }
    let seal_to = seal_public(seal_to_secret);
    let cipher = cipher(
        x25519(seal_to_secret, sealed.ephemeral),
        &sealed.ephemeral,
        &seal_to,
    )?;
    let ad = associated_data(
        sealed.version,
        sealed.kind,
        &sealed.key_id,
        sealed.expires_at,
        binding,
    );
    cipher
        .decrypt(
            &XNonce::from(sealed.nonce),
            Payload {
                msg: &sealed.ciphertext,
                aad: &ad,
            },
        )
        .map_err(|_| SealError::Open)
}

/// Fixed-size byte arrays as lowercase hex.
mod hex_array {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub fn serialize<S: Serializer, const N: usize>(
        bytes: &[u8; N],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        deserializer: D,
    ) -> Result<[u8; N], D::Error> {
        let text = String::deserialize(deserializer)?;
        let bytes = hex::decode(&text).map_err(D::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| D::Error::custom(format!("expected {N} bytes of hex")))
    }
}

mod hex_vec {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        hex::decode(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLAINTEXT: &[u8] = b"cmnk_0102030405060708_c2VjcmV0LXNlY3JldC1zZWNyZXQ";

    fn binding() -> SealBinding {
        SealBinding {
            node: [0x44; 32],
            key_for: [0x55; 32],
            request_digest: [0x66; 32],
        }
    }

    fn vector() -> SealedSecret {
        seal(
            PLAINTEXT,
            SealKind::Create,
            [1, 2, 3, 4, 5, 6, 7, 8],
            1_800_000_000_000,
            &seal_public([0x22; 32]),
            &binding(),
            [0x11; 32],
            [0x33; 24],
        )
        .unwrap()
    }

    /// The construction, fixed: computed independently of this code (X25519
    /// per RFC 7748, BLAKE3 `derive_key`, XChaCha20-Poly1305), so the App's
    /// own implementation can be checked against the same bytes.
    #[test]
    fn seal_test_vector() {
        assert_eq!(
            hex::encode(seal_public([0x22; 32])),
            "0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20"
        );
        let sealed = vector();
        assert_eq!(
            hex::encode(sealed.ephemeral),
            "7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13"
        );
        assert_eq!(
            hex::encode(&sealed.ciphertext),
            "1d6426ae46b883798e8c88ceb57b759c6d350a9693b1591a4fa945b633a419ac\
             0e3e3f6ab05e76c16aef82f13600875d4d49acde10882debb7b981d15b4c20b2f8"
        );
        assert_eq!(open(&sealed, [0x22; 32], &binding()).unwrap(), PLAINTEXT);
    }

    /// Any change to what is sent in clear, the ciphertext, or what the
    /// opener supplies, fails to open; so does the wrong `sealTo` secret and
    /// a version other than 1.
    #[test]
    fn a_tampered_seal_does_not_open() {
        let sealed = vector();
        let mut changes: Vec<SealedSecret> = Vec::new();
        let mut s = sealed.clone();
        s.kind = SealKind::Rotate;
        changes.push(s);
        let mut s = sealed.clone();
        s.key_id[0] ^= 1;
        changes.push(s);
        let mut s = sealed.clone();
        s.expires_at += 1;
        changes.push(s);
        let mut s = sealed.clone();
        s.nonce[0] ^= 1;
        changes.push(s);
        let mut s = sealed.clone();
        s.ciphertext[0] ^= 1;
        changes.push(s);
        let mut s = sealed.clone();
        *s.ciphertext.last_mut().unwrap() ^= 1;
        changes.push(s);
        let mut s = sealed.clone();
        s.ephemeral = seal_public([0x12; 32]);
        changes.push(s);
        for changed in &changes {
            assert_eq!(
                open(changed, [0x22; 32], &binding()),
                Err(SealError::Open),
                "{changed:?}"
            );
        }
        let mut s = sealed.clone();
        s.version = 2;
        assert_eq!(open(&s, [0x22; 32], &binding()), Err(SealError::Version(2)));
        assert_eq!(open(&sealed, [0x23; 32], &binding()), Err(SealError::Open));
        for other in [
            SealBinding {
                node: [0x45; 32],
                ..binding()
            },
            SealBinding {
                key_for: [0x56; 32],
                ..binding()
            },
            SealBinding {
                request_digest: [0x67; 32],
                ..binding()
            },
        ] {
            assert_eq!(open(&sealed, [0x22; 32], &other), Err(SealError::Open));
        }
    }

    /// A `sealTo` of small order gives an all-zero shared secret and is
    /// refused rather than sealed under a key anyone can compute.
    #[test]
    fn a_non_contributory_seal_to_is_refused() {
        for low_order in [[0u8; 32], {
            let mut one = [0u8; 32];
            one[0] = 1;
            one
        }] {
            assert_eq!(
                seal(
                    PLAINTEXT,
                    SealKind::Create,
                    [0; 8],
                    0,
                    &low_order,
                    &binding(),
                    [0x11; 32],
                    [0x33; 24],
                ),
                Err(SealError::NonContributory)
            );
        }
    }

    #[test]
    fn the_sealed_form_round_trips_as_json() {
        let sealed = vector();
        let text = serde_json::to_string(&sealed).unwrap();
        assert!(text.contains("\"keyId\":\"0102030405060708\""), "{text}");
        assert_eq!(serde_json::from_str::<SealedSecret>(&text).unwrap(), sealed);
    }

    /// The door's answer verifies only against the door's key and the request
    /// it answers, and a changed outcome breaks it.
    #[test]
    fn a_door_answer_verifies_only_as_signed() {
        let door = iroh::SecretKey::from_bytes(&[7; 32]);
        let outcome = KeyOutcome::Done {
            result: serde_json::json!({"changed": true}),
        };
        let answer = KeyDoorAnswer::sign(&door, [9; 32], &outcome);
        let id = *door.public().as_bytes();
        assert_eq!(answer.verify(&id, &[9; 32]), Ok(outcome));
        assert_eq!(
            answer.verify(&id, &[8; 32]),
            Err(KeyDoorError::OtherRequest)
        );
        let other = *iroh::SecretKey::from_bytes(&[6; 32]).public().as_bytes();
        assert_eq!(
            answer.verify(&other, &[9; 32]),
            Err(KeyDoorError::Signature)
        );
        let mut forged = answer.clone();
        forged.outcome = serde_json::to_string(&KeyOutcome::Done {
            result: serde_json::json!({"changed": false}),
        })
        .unwrap();
        assert_eq!(forged.verify(&id, &[9; 32]), Err(KeyDoorError::Signature));
    }

    fn request_body() -> KeyRequestBody {
        KeyRequestBody {
            datasets: vec!["field-notes".into(), "survey".into()],
            scopes: vec!["read".into(), "write".into()],
            expires_at: 1_800_000_000_000,
            seal_to: [0x11; 32],
            note: Some("for the field team".into()),
        }
    }

    /// The mailbox key request's body, byte for byte, for the App (T321.5)
    /// to build against: JSON in this field order, `note` left out when
    /// there is none, and unknown fields refused.
    #[test]
    fn a_key_request_body_test_vector() {
        let pinned = concat!(
            r#"{"datasets":["field-notes","survey"],"scopes":["read","write"],"#,
            r#""expiresAt":1800000000000,"#,
            r#""sealTo":"1111111111111111111111111111111111111111111111111111111111111111","#,
            r#""note":"for the field team"}"#
        );
        assert_eq!(serde_json::to_string(&request_body()).unwrap(), pinned);
        assert_eq!(
            serde_json::from_str::<KeyRequestBody>(pinned).unwrap(),
            request_body()
        );
        let bare = KeyRequestBody {
            note: None,
            ..request_body()
        };
        assert!(!serde_json::to_string(&bare).unwrap().contains("\"note\""));
        let extra = pinned.replace("{\"datasets\"", "{\"admin\":true,\"datasets\"");
        assert!(serde_json::from_str::<KeyRequestBody>(&extra).is_err());
    }

    /// A mailbox request is read through the same check as `keys.request`:
    /// the terms come only from the signed body, the digest is of the raw
    /// statement, it waits until the statement's expiry, and the terms
    /// `check_ask` refuses are refused here too.
    ///
    /// Breaks if the mailbox path skips `check_ask`, takes `create`, takes
    /// an unknown field, or binds the wrong digest.
    #[test]
    fn a_mailbox_request_is_read_under_the_same_refusals() {
        let raw = b"the statement's signed bytes";
        let body = serde_json::to_vec(&request_body()).unwrap();
        let ask = KeyRequestAsk::from_mailbox([9; 32], [7; 16], &body, 1_800_000_000, raw).unwrap();
        assert_eq!(ask.requester, [9; 32]);
        assert_eq!(ask.request_id, [7; 16]);
        assert_eq!(ask.datasets, request_body().datasets);
        assert_eq!(ask.seal_to, [0x11; 32]);
        assert_eq!(ask.digest, *blake3::hash(raw).as_bytes());
        assert_eq!(ask.waits_until, 1_800_000_000_000);
        let now = 1_800_000_000_000 - MAX_KEY_REQUEST_TTL_MS;
        assert!(ask.open_at(now));
        assert!(!ask.open_at(1_800_000_000_000), "expired");
        assert!(
            !ask.open_at(now - auth_wire::MAX_FUTURE_CLOCK_SKEW_MS - 1),
            "standing more than seven days from now"
        );
        let refused = |change: &dyn Fn(&mut serde_json::Value)| {
            let mut value = serde_json::to_value(request_body()).unwrap();
            change(&mut value);
            let body = serde_json::to_vec(&value).unwrap();
            KeyRequestAsk::from_mailbox([9; 32], [7; 16], &body, 1_800_000_000, raw).is_err()
        };
        assert!(refused(
            &|v| v["scopes"] = serde_json::json!(["read", "create"])
        ));
        assert!(refused(
            &|v| v["scopes"] = serde_json::json!(["read", "read"])
        ));
        assert!(refused(&|v| v["datasets"] = serde_json::json!([])));
        assert!(refused(&|v| {
            v["datasets"] = (0..=MAX_KEY_DATASETS).map(|i| i.to_string()).collect()
        }));
        assert!(refused(&|v| v["note"] = "x".repeat(281).into()));
        assert!(refused(&|v| v["requestId"] = "00".repeat(16).into()));
        assert!(!refused(&|_| {}));
    }

    fn answer() -> KeyRequestAnswer {
        KeyRequestAnswer {
            request_digest: [0x44; 32],
            sealed: SealedSecret {
                version: 1,
                kind: SealKind::Approval,
                key_id: [1, 2, 3, 4, 5, 6, 7, 8],
                expires_at: 1_800_000_000_000,
                ephemeral: [0x22; 32],
                nonce: [0x33; 24],
                ciphertext: vec![0x55; APPROVAL_CIPHERTEXT_BYTES],
            },
            answer_expires_at: 1_700_086_400_000,
        }
    }

    /// The mailbox key answer's body, byte for byte, for the App (T321.5):
    /// version, kind, key id, key expiry, one-time public key, nonce,
    /// request digest, sealed part. Any other length, version or kind is
    /// refused.
    #[test]
    fn a_key_answer_body_test_vector() {
        let pinned = concat!(
            "01030102030405060708000001a3185c50002222222222222222222222222222",
            "2222222222222222222222222222222222223333333333333333333333333333",
            "3333333333333333333344444444444444444444444444444444444444444444",
            "4444444444444444444455555555555555555555555555555555555555555555",
            "5555555555555555555555555555555555555555555555555555555555555555",
            "5555555555555555555555555555555555555555555555555555555555555555",
        );
        let body = answer().mailbox_body().unwrap();
        assert_eq!(body.len(), KEY_ANSWER_BODY_BYTES);
        assert_eq!(KEY_ANSWER_BODY_BYTES, 192);
        assert_eq!(hex::encode(&body), pinned);
        assert_eq!(
            KeyRequestAnswer::from_mailbox_body(&body, answer().answer_expires_at).unwrap(),
            answer()
        );
        let mut long = body.clone();
        long.push(0);
        assert!(KeyRequestAnswer::from_mailbox_body(&long, 0).is_err());
        assert!(KeyRequestAnswer::from_mailbox_body(&body[..191], 0).is_err());
        let mut version = body.clone();
        version[0] = 2;
        assert!(KeyRequestAnswer::from_mailbox_body(&version, 0).is_err());
        let mut kind = body.clone();
        kind[1] = 1;
        assert!(KeyRequestAnswer::from_mailbox_body(&kind, 0).is_err());
        let mut create = answer();
        create.sealed.kind = SealKind::Create;
        assert!(create.mailbox_body().is_err());
        let mut short = answer();
        short.sealed.ciphertext.pop();
        assert!(short.mailbox_body().is_err());
    }

    /// The sealed part the door makes for an approval is exactly the size
    /// the answer's layout fixes: the grant and an API key of the door's
    /// format.
    #[test]
    fn an_approvals_sealed_part_fits_the_layout() {
        let api_key = format!("cmnk_{}_{}", "0123456789abcdef", "A".repeat(43));
        let grant = ApprovalGrant {
            datasets: 1,
            scopes: 1,
        };
        let sealed = seal(
            &grant.plaintext(&api_key),
            SealKind::Approval,
            [1; 8],
            1_800_000_000_000,
            &seal_public([0x22; 32]),
            &binding(),
            [0x11; 32],
            [0x33; 24],
        )
        .unwrap();
        assert_eq!(sealed.ciphertext.len(), APPROVAL_CIPHERTEXT_BYTES);
    }
}
