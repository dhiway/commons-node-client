//! auth-wire v2: the node's signed RPC envelopes (T199.3).
//!
//! A caller is a native identity only: an iroh endpoint, or a session its
//! endpoint opened. A response or session records `authorized_at_ms`, the
//! time the node checked the caller. Every envelope carries version 2 and
//! signs under the `/v2` domains; an envelope with any other version byte is
//! refused.

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::{
    MAX_CAPABILITIES, MAX_FUTURE_CLOCK_SKEW_MS, MAX_OPERATION_LEN, MAX_PROOFS,
    MAX_REQUEST_LIFETIME_MS, MAX_SESSION_LIFETIME_MS, MAX_WIRE_LEN, NONCE_LEN, Proof, Replayable,
    ResponseStatus, SignedWire, validate_codec_payload, validate_service, validate_versioned,
    verify_ed25519,
};

pub const VERSION: u8 = 2;
pub const REQUEST_DOMAIN: &[u8] = b"commons/auth/request/v2\0";
pub const RESPONSE_DOMAIN: &[u8] = b"commons/auth/response/v2\0";
pub const SESSION_DOMAIN: &[u8] = b"commons/auth/session/v2\0";
pub const STREAM_DOMAIN: &[u8] = b"commons/auth/stream/v2\0";

/// Who signs a request. Both are native identities; there is no chain
/// account.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Principal {
    /// An iroh endpoint, proven by its own key's signature.
    Endpoint { peer_id: [u8; 32] },
    /// A session the node issued to an endpoint, proven by the session key.
    Session {
        session_id: [u8; 16],
        session_public: [u8; 32],
        sequence: u64,
    },
}

/// The service and node a request is for.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Audience {
    pub service: String,
    pub target_key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRequest {
    pub version: u8,
    pub request_id: [u8; 16],
    pub principal: Principal,
    pub audience: Audience,
    pub operation: String,
    pub nonce: [u8; NONCE_LEN],
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub idempotency_key: Option<[u8; 16]>,
    pub payload_codec: String,
    pub payload: Vec<u8>,
    pub proofs: Vec<Proof>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedResponse {
    pub version: u8,
    pub request_id: [u8; 16],
    pub request_digest: [u8; 32],
    pub issuer_key: [u8; 32],
    pub audience_principal: Principal,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    /// When the node checked the caller's authority for this response.
    pub authorized_at_ms: u64,
    pub status: ResponseStatus,
    pub payload_codec: String,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionCertificate {
    pub version: u8,
    pub session_id: [u8; 16],
    /// The endpoint the session speaks for; never another session.
    pub principal: Principal,
    pub session_public: [u8; 32],
    pub audience: Audience,
    pub capabilities: Vec<String>,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    /// When the node checked the endpoint's authority to open the session.
    pub authorized_at_ms: u64,
    pub issuer_key: [u8; 32],
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedStreamFrame {
    pub version: u8,
    pub stream_id: [u8; 16],
    pub sequence: u64,
    pub previous_hash: [u8; 32],
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub payload_codec: String,
    pub payload: Vec<u8>,
    pub issuer_key: [u8; 32],
    pub signature: Vec<u8>,
}

/// The replay identity of a v2 request.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReplayKey {
    pub principal: Principal,
    pub audience: Audience,
    pub nonce: [u8; NONCE_LEN],
}

/// The idempotency identity of a v2 request that carries a key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdempotencyScope {
    pub principal: Principal,
    pub audience: Audience,
    pub operation: String,
    pub key: [u8; 16],
}

impl SignedRequest {
    pub fn unsigned_bytes(&self) -> Result<Vec<u8>> {
        let mut unsigned = self.clone();
        unsigned.proofs.clear();
        Ok(postcard::to_stdvec(&unsigned)?)
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let body = self.unsigned_bytes()?;
        let mut message = Vec::with_capacity(REQUEST_DOMAIN.len() + body.len());
        message.extend_from_slice(REQUEST_DOMAIN);
        message.extend_from_slice(&body);
        Ok(message)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = postcard::to_stdvec(self)?;
        ensure!(bytes.len() <= MAX_WIRE_LEN, "wire envelope exceeds limit");
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= MAX_WIRE_LEN, "wire envelope exceeds limit");
        let request: Self = postcard::from_bytes(bytes).context("decoding signed request")?;
        request.validate()?;
        ensure!(
            request.encode()? == bytes,
            "non-canonical signed request encoding"
        );
        Ok(request)
    }

    pub fn validate(&self) -> Result<()> {
        validate_versioned(
            VERSION,
            self.version,
            self.issued_at_ms,
            self.expires_at_ms,
            MAX_REQUEST_LIFETIME_MS,
        )?;
        validate_service(&self.audience.service)?;
        ensure!(!self.operation.is_empty(), "operation is empty");
        ensure!(
            self.operation.len() <= MAX_OPERATION_LEN,
            "operation exceeds limit"
        );
        validate_codec_payload(&self.payload_codec, &self.payload)?;
        ensure!(!self.proofs.is_empty(), "request has no proof");
        ensure!(self.proofs.len() <= MAX_PROOFS, "too many proofs");
        ensure!(
            self.proofs.iter().all(|p| p.signature.len() == 64),
            "proof signature must be 64 bytes"
        );
        Ok(())
    }

    pub fn digest(&self) -> Result<[u8; 32]> {
        Ok(*blake3::hash(&self.encode()?).as_bytes())
    }

    pub fn replay_key(&self) -> ReplayKey {
        ReplayKey {
            principal: self.principal.clone(),
            audience: self.audience.clone(),
            nonce: self.nonce,
        }
    }

    pub fn idempotency_scope(&self) -> Option<IdempotencyScope> {
        self.idempotency_key.map(|key| IdempotencyScope {
            principal: self.principal.clone(),
            audience: self.audience.clone(),
            operation: self.operation.clone(),
            key,
        })
    }

    pub fn verify_time(&self, now_ms: u64) -> Result<()> {
        ensure!(
            self.issued_at_ms <= now_ms.saturating_add(MAX_FUTURE_CLOCK_SKEW_MS),
            "request issued too far in future"
        );
        ensure!(now_ms < self.expires_at_ms, "request expired");
        Ok(())
    }

    pub fn add_proof(&mut self, key: &iroh::SecretKey) -> Result<()> {
        ensure!(self.proofs.len() < MAX_PROOFS, "too many proofs");
        let message = self.signing_bytes()?;
        self.proofs.push(Proof {
            signer: *key.public().as_bytes(),
            signature: key.sign(&message).to_bytes().to_vec(),
        });
        Ok(())
    }

    pub fn verify_proofs(&self) -> Result<()> {
        self.validate()?;
        let message = self.signing_bytes()?;
        for proof in &self.proofs {
            verify_ed25519(&proof.signer, &proof.signature, &message)?;
        }
        Ok(())
    }
}

impl Replayable for SignedRequest {
    type Key = ReplayKey;
    type Principal = Principal;
    fn replay_key(&self) -> ReplayKey {
        SignedRequest::replay_key(self)
    }
    fn key_principal(key: &ReplayKey) -> &Principal {
        &key.principal
    }
    fn digest(&self) -> Result<[u8; 32]> {
        SignedRequest::digest(self)
    }
    fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
}

impl SignedWire for SignedResponse {
    const DOMAIN: &'static [u8] = RESPONSE_DOMAIN;
    fn signature(&self) -> &[u8] {
        &self.signature
    }
    fn signature_mut(&mut self) -> &mut Vec<u8> {
        &mut self.signature
    }
    fn validate(&self) -> Result<()> {
        validate_versioned(
            VERSION,
            self.version,
            self.issued_at_ms,
            self.expires_at_ms,
            MAX_REQUEST_LIFETIME_MS,
        )?;
        validate_codec_payload(&self.payload_codec, &self.payload)?;
        ensure!(
            self.signature.len() == 64,
            "response signature must be 64 bytes"
        );
        if let ResponseStatus::Error { code, .. } = &self.status {
            ensure!(!code.is_empty() && code.len() <= 64, "invalid error code");
        }
        Ok(())
    }
}

impl SignedWire for SessionCertificate {
    const DOMAIN: &'static [u8] = SESSION_DOMAIN;
    fn signature(&self) -> &[u8] {
        &self.signature
    }
    fn signature_mut(&mut self) -> &mut Vec<u8> {
        &mut self.signature
    }
    fn validate(&self) -> Result<()> {
        validate_versioned(
            VERSION,
            self.version,
            self.issued_at_ms,
            self.expires_at_ms,
            MAX_SESSION_LIFETIME_MS,
        )?;
        validate_service(&self.audience.service)?;
        ensure!(
            matches!(self.principal, Principal::Endpoint { .. }),
            "a session speaks for an endpoint"
        );
        ensure!(
            !self.capabilities.is_empty() && self.capabilities.len() <= MAX_CAPABILITIES,
            "invalid capability count"
        );
        ensure!(
            self.capabilities
                .iter()
                .all(|c| !c.is_empty() && c.len() <= MAX_OPERATION_LEN),
            "invalid capability"
        );
        ensure!(
            self.signature.len() == 64,
            "session signature must be 64 bytes"
        );
        Ok(())
    }
}

impl SignedWire for SignedStreamFrame {
    const DOMAIN: &'static [u8] = STREAM_DOMAIN;
    fn signature(&self) -> &[u8] {
        &self.signature
    }
    fn signature_mut(&mut self) -> &mut Vec<u8> {
        &mut self.signature
    }
    fn validate(&self) -> Result<()> {
        validate_versioned(
            VERSION,
            self.version,
            self.issued_at_ms,
            self.expires_at_ms,
            MAX_SESSION_LIFETIME_MS,
        )?;
        validate_codec_payload(&self.payload_codec, &self.payload)?;
        ensure!(
            self.signature.len() == 64,
            "stream signature must be 64 bytes"
        );
        Ok(())
    }
}

/// The hash a stream frame chains its successor to.
pub fn stream_frame_hash(frame: &SignedStreamFrame) -> Result<[u8; 32]> {
    Ok(*blake3::hash(&frame.encode()?).as_bytes())
}

/// Deterministic example envelopes, the source of the v2 golden fixture.
#[doc(hidden)]
pub mod golden {
    use super::*;

    /// The key that signs the golden request's proof.
    pub const REQUEST_SIGNER: [u8; 32] = [9; 32];
    /// The node key that signs the golden response, session and stream frame.
    pub const ISSUER: [u8; 32] = [8; 32];

    pub fn request() -> SignedRequest {
        let mut request = SignedRequest {
            version: VERSION,
            request_id: [1; 16],
            principal: Principal::Endpoint { peer_id: [2; 32] },
            audience: Audience {
                service: "origin.node".into(),
                target_key: [3; 32],
            },
            operation: "origin.node/store.create".into(),
            nonce: [5; 32],
            issued_at_ms: 1_000,
            expires_at_ms: 2_000,
            idempotency_key: Some([6; 16]),
            payload_codec: "application/json".into(),
            payload: br#"[{"name":"golden"}]"#.to_vec(),
            proofs: Vec::new(),
        };
        request
            .add_proof(&iroh::SecretKey::from_bytes(&REQUEST_SIGNER))
            .expect("golden request signs");
        request
    }

    pub fn response() -> SignedResponse {
        let issuer = iroh::SecretKey::from_bytes(&ISSUER);
        let mut response = SignedResponse {
            version: VERSION,
            request_id: [1; 16],
            request_digest: request().digest().expect("golden digest"),
            issuer_key: *issuer.public().as_bytes(),
            audience_principal: Principal::Endpoint { peer_id: [2; 32] },
            issued_at_ms: 1_000,
            expires_at_ms: 2_000,
            authorized_at_ms: 999,
            status: ResponseStatus::Success,
            payload_codec: "application/json".into(),
            payload: b"{}".to_vec(),
            signature: Vec::new(),
        };
        crate::sign(&mut response, &issuer).expect("golden response signs");
        response
    }

    pub fn session() -> SessionCertificate {
        let issuer = iroh::SecretKey::from_bytes(&ISSUER);
        let mut session = SessionCertificate {
            version: VERSION,
            session_id: [4; 16],
            principal: Principal::Endpoint { peer_id: [2; 32] },
            session_public: [5; 32],
            audience: Audience {
                service: "origin.node".into(),
                target_key: [3; 32],
            },
            capabilities: vec!["origin.node/store.get-entry".into()],
            issued_at_ms: 1_000,
            expires_at_ms: 2_000,
            authorized_at_ms: 999,
            issuer_key: *issuer.public().as_bytes(),
            signature: Vec::new(),
        };
        crate::sign(&mut session, &issuer).expect("golden session signs");
        session
    }

    pub fn stream() -> SignedStreamFrame {
        let issuer = iroh::SecretKey::from_bytes(&ISSUER);
        let mut frame = SignedStreamFrame {
            version: VERSION,
            stream_id: [6; 16],
            sequence: 0,
            previous_hash: [0; 32],
            issued_at_ms: 1_000,
            expires_at_ms: 2_000,
            payload_codec: "application/json".into(),
            payload: b"{}".to_vec(),
            issuer_key: *issuer.public().as_bytes(),
            signature: Vec::new(),
        };
        crate::sign(&mut frame, &issuer).expect("golden stream frame signs");
        frame
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_round_trip_canonically_and_every_field_is_signed() {
        let request = golden::request();
        let bytes = request.encode().unwrap();
        assert_eq!(SignedRequest::decode(&bytes).unwrap(), request);
        request.verify_proofs().unwrap();
        let mutations: Vec<fn(&mut SignedRequest)> = vec![
            |r| r.request_id[0] ^= 1,
            |r| r.principal = Principal::Endpoint { peer_id: [7; 32] },
            |r| r.audience.service = "other".into(),
            |r| r.audience.target_key[0] ^= 1,
            |r| r.operation.push('x'),
            |r| r.nonce[0] ^= 1,
            |r| r.issued_at_ms += 1,
            |r| r.expires_at_ms += 1,
            |r| r.idempotency_key = None,
            |r| r.payload_codec.push('x'),
            |r| r.payload.push(b' '),
        ];
        for mutate in mutations {
            let mut changed = request.clone();
            mutate(&mut changed);
            assert!(changed.verify_proofs().is_err());
        }
    }

    #[test]
    fn signed_requests_enforce_lifetime_boundary() {
        let signer = iroh::SecretKey::from_bytes(&golden::REQUEST_SIGNER);
        for extra_ms in [0, 1] {
            let mut request = golden::request();
            request.expires_at_ms = request.issued_at_ms + MAX_REQUEST_LIFETIME_MS + extra_ms;
            request.proofs.clear();
            request.add_proof(&signer).unwrap();

            // Both signatures are valid, so rejection isolates the lifetime bound.
            let proof = &request.proofs[0];
            verify_ed25519(
                &proof.signer,
                &proof.signature,
                &request.signing_bytes().unwrap(),
            )
            .unwrap();

            let result = request.verify_proofs();
            if extra_ms == 0 {
                result.unwrap();
            } else {
                assert_eq!(result.unwrap_err().to_string(), "lifetime exceeds limit");
            }
        }
    }

    /// An envelope of another version is refused before its signature is
    /// read, and the encoded bytes of one do not decode.
    #[test]
    fn another_version_byte_is_refused() {
        let request = golden::request();
        let mut bytes = request.encode().unwrap();
        for version in [VERSION - 1, VERSION + 1] {
            let mut wrong = request.clone();
            wrong.version = version;
            assert!(wrong.validate().is_err(), "version {version}");
            assert!(wrong.verify_proofs().is_err(), "version {version}");
            bytes[0] = version;
            assert!(SignedRequest::decode(&bytes).is_err(), "version {version}");
        }
        let mut response = golden::response();
        response.version = VERSION - 1;
        let issuer = iroh::SecretKey::from_bytes(&golden::ISSUER).public();
        assert!(crate::verify(&response, issuer.as_bytes()).is_err());
    }

    #[test]
    fn signed_wire_types_verify_under_the_issuer_and_refuse_tampering() {
        let issuer = iroh::SecretKey::from_bytes(&golden::ISSUER).public();
        let response = golden::response();
        crate::verify(&response, issuer.as_bytes()).unwrap();
        let mut tampered = response.clone();
        tampered.authorized_at_ms += 1;
        assert!(crate::verify(&tampered, issuer.as_bytes()).is_err());

        let session = golden::session();
        crate::verify(&session, issuer.as_bytes()).unwrap();
        let mut nested = session.clone();
        nested.principal = Principal::Session {
            session_id: [1; 16],
            session_public: [1; 32],
            sequence: 0,
        };
        assert!(
            nested.validate().is_err(),
            "a session never speaks for a session"
        );

        let frame = golden::stream();
        crate::verify(&frame, issuer.as_bytes()).unwrap();
        assert_eq!(
            stream_frame_hash(&frame).unwrap(),
            *blake3::hash(&frame.encode().unwrap()).as_bytes()
        );
    }

    #[test]
    fn the_replay_cache_tracks_v2_requests() {
        let request = golden::request();
        let mut cache: crate::ReplayCache<SignedRequest> = crate::ReplayCache::default();
        assert_eq!(
            cache.check(&request, 1_500).unwrap(),
            crate::ReplayDecision::Fresh
        );
        assert_eq!(
            cache.check(&request, 1_500).unwrap(),
            crate::ReplayDecision::InFlight
        );
        cache.record(&request, b"answer".to_vec()).unwrap();
        assert_eq!(
            cache.check(&request, 1_500).unwrap(),
            crate::ReplayDecision::ExactRetry(b"answer".to_vec())
        );
    }
}
