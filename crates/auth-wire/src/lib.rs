//! Deterministic, transport-neutral Commons authentication envelopes.
//!
//! Every signature covers fixed-order postcard bytes prefixed by one of the
//! domain separators below. JSON is only an opaque bounded payload; it is
//! never parsed and reserialized while verifying a signature.

use std::collections::HashMap;

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};

pub mod v2;

pub const MAX_REQUEST_LIFETIME_MS: u64 = 120_000;
pub const MAX_FUTURE_CLOCK_SKEW_MS: u64 = 60_000;
pub const REPLAY_RETENTION_AFTER_EXPIRY_MS: u64 = 60_000;
pub const MAX_SESSION_LIFETIME_MS: u64 = 300_000;
pub const MAX_AUTHORIZATION_STALENESS_MS: u64 = 30_000;
pub const NONCE_LEN: usize = 32;
pub const MAX_PROOFS: usize = 2;
pub const SESSION_SEQUENCE_WINDOW: u64 = 64;
pub const MAX_REPLAY_ENTRIES: usize = 65_536;
pub const MAX_REPLAY_ENTRIES_PER_PRINCIPAL: usize = 1_024;
pub const MAX_REPLAY_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_REPLAY_RESPONSE_BYTES_PER_PRINCIPAL: usize = 4 * 1024 * 1024;

pub const MAX_SERVICE_LEN: usize = 128;
pub const MAX_OPERATION_LEN: usize = 192;
pub const MAX_CODEC_LEN: usize = 64;
pub const MAX_CAPABILITIES: usize = 128;
pub const MAX_PAYLOAD_LEN: usize = 4 * 1024 * 1024;
pub const MAX_WIRE_LEN: usize = MAX_PAYLOAD_LEN + 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    pub signer: [u8; 32],
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseStatus {
    Success,
    Error { code: String, retryable: bool },
}

pub trait SignedWire: Serialize + for<'de> Deserialize<'de> + Sized {
    const DOMAIN: &'static [u8];
    fn signature(&self) -> &[u8];
    fn signature_mut(&mut self) -> &mut Vec<u8>;
    fn validate(&self) -> Result<()>;

    fn unsigned_bytes(&self) -> Result<Vec<u8>> {
        let mut value = postcard::to_stdvec(self)?;
        let signature_len = self.signature().len();
        ensure!(signature_len <= value.len(), "invalid signature encoding");
        // Every signed type deliberately places its Vec<u8> signature last.
        // Re-encode with it empty rather than attempting to strip postcard's
        // variable-length prefix from serialized bytes.
        let mut unsigned: Self = postcard::from_bytes(&value)?;
        unsigned.signature_mut().clear();
        value = postcard::to_stdvec(&unsigned)?;
        Ok(value)
    }

    fn signing_bytes(&self) -> Result<Vec<u8>> {
        let body = self.unsigned_bytes()?;
        let mut message = Vec::with_capacity(Self::DOMAIN.len() + body.len());
        message.extend_from_slice(Self::DOMAIN);
        message.extend_from_slice(&body);
        Ok(message)
    }

    fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = postcard::to_stdvec(self)?;
        ensure!(bytes.len() <= MAX_WIRE_LEN, "wire envelope exceeds limit");
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= MAX_WIRE_LEN, "wire envelope exceeds limit");
        let value: Self = postcard::from_bytes(bytes).context("decoding auth envelope")?;
        value.validate()?;
        ensure!(
            value.encode()? == bytes,
            "non-canonical auth envelope encoding"
        );
        Ok(value)
    }
}

pub(crate) fn validate_versioned(
    expected: u8,
    version: u8,
    issued: u64,
    expires: u64,
    max_lifetime: u64,
) -> Result<()> {
    ensure!(version == expected, "unsupported auth version");
    ensure!(expires > issued, "expiry must follow issuance");
    ensure!(expires - issued <= max_lifetime, "lifetime exceeds limit");
    Ok(())
}

pub(crate) fn validate_service(service: &str) -> Result<()> {
    ensure!(!service.is_empty(), "service is empty");
    ensure!(service.len() <= MAX_SERVICE_LEN, "service exceeds limit");
    Ok(())
}

pub(crate) fn validate_codec_payload(codec: &str, payload: &[u8]) -> Result<()> {
    ensure!(!codec.is_empty(), "payload codec is empty");
    ensure!(codec.len() <= MAX_CODEC_LEN, "payload codec exceeds limit");
    ensure!(payload.len() <= MAX_PAYLOAD_LEN, "payload exceeds limit");
    Ok(())
}

pub fn sign<T: SignedWire>(value: &mut T, key: &iroh::SecretKey) -> Result<()> {
    value.signature_mut().clear();
    let message = value.signing_bytes()?;
    *value.signature_mut() = key.sign(&message).to_bytes().to_vec();
    value.validate()
}

pub fn verify<T: SignedWire>(value: &T, expected_key: &[u8; 32]) -> Result<()> {
    value.validate()?;
    verify_ed25519(expected_key, value.signature(), &value.signing_bytes()?)
}

pub(crate) fn verify_ed25519(key: &[u8; 32], signature: &[u8], message: &[u8]) -> Result<()> {
    let public = iroh::PublicKey::from_bytes(key).context("invalid Ed25519 public key")?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| anyhow::anyhow!("signature must be 64 bytes"))?;
    public
        .verify(message, &iroh::Signature::from_bytes(&signature))
        .map_err(|_| anyhow::anyhow!("signature invalid"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayDecision {
    Fresh,
    ExactRetry(Vec<u8>),
    InFlight,
    NonceConflict,
}

/// A signed request the [`ReplayCache`] can track: its replay key (whose
/// principal part bounds per-principal use), its digest and its expiry.
pub trait Replayable {
    type Key: Clone + Eq + std::hash::Hash;
    type Principal: Eq;
    fn replay_key(&self) -> Self::Key;
    fn key_principal(key: &Self::Key) -> &Self::Principal;
    fn digest(&self) -> Result<[u8; 32]>;
    fn expires_at_ms(&self) -> u64;
}

/// The bounds of one [`ReplayCache`]: entries and recorded response bytes,
/// in all and per principal. The default is the shared bounds every
/// principal of a cache competes under; a cache that serves one principal
/// alone (the node's delegate) is sized for it instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayLimits {
    pub entries: usize,
    pub entries_per_principal: usize,
    pub response_bytes: usize,
    pub response_bytes_per_principal: usize,
}

impl Default for ReplayLimits {
    fn default() -> Self {
        Self {
            entries: MAX_REPLAY_ENTRIES,
            entries_per_principal: MAX_REPLAY_ENTRIES_PER_PRINCIPAL,
            response_bytes: MAX_REPLAY_RESPONSE_BYTES,
            response_bytes_per_principal: MAX_REPLAY_RESPONSE_BYTES_PER_PRINCIPAL,
        }
    }
}

pub struct ReplayCache<R: Replayable> {
    entries: HashMap<R::Key, ([u8; 32], u64, Vec<u8>)>,
    response_bytes: usize,
    limits: ReplayLimits,
}

impl<R: Replayable> Default for ReplayCache<R> {
    fn default() -> Self {
        Self::with_limits(ReplayLimits::default())
    }
}

impl<R: Replayable> ReplayCache<R> {
    pub fn with_limits(limits: ReplayLimits) -> Self {
        Self {
            entries: HashMap::new(),
            response_bytes: 0,
            limits,
        }
    }

    pub fn check(&mut self, request: &R, now_ms: u64) -> Result<ReplayDecision> {
        self.entries
            .retain(|_, (_, retain_until, _)| now_ms < *retain_until);
        self.response_bytes = self
            .entries
            .values()
            .map(|(_, _, response)| response.len())
            .sum();
        let key = request.replay_key();
        let digest = request.digest()?;
        let decision = match self.entries.get(&key) {
            None => ReplayDecision::Fresh,
            Some((prior, _, response)) if prior == &digest && response.is_empty() => {
                ReplayDecision::InFlight
            }
            Some((prior, _, response)) if prior == &digest => {
                ReplayDecision::ExactRetry(response.clone())
            }
            Some(_) => ReplayDecision::NonceConflict,
        };
        if matches!(decision, ReplayDecision::Fresh) {
            ensure!(
                self.entries.len() < self.limits.entries,
                "replay cache capacity reached"
            );
            ensure!(
                self.entries
                    .keys()
                    .filter(|existing| R::key_principal(existing) == R::key_principal(&key))
                    .count()
                    < self.limits.entries_per_principal,
                "principal replay capacity reached"
            );
            self.entries.insert(
                key,
                (
                    digest,
                    request
                        .expires_at_ms()
                        .saturating_add(REPLAY_RETENTION_AFTER_EXPIRY_MS),
                    Vec::new(),
                ),
            );
        }
        Ok(decision)
    }

    pub fn record(&mut self, request: &R, signed_response_bytes: Vec<u8>) -> Result<()> {
        let key = request.replay_key();
        let digest = request.digest()?;
        let principal_bytes: usize = self
            .entries
            .iter()
            .filter(|(existing, _)| R::key_principal(existing) == R::key_principal(&key))
            .map(|(_, (_, _, bytes))| bytes.len())
            .sum();
        match self.entries.get_mut(&key) {
            Some((prior, _, response)) if *prior == digest => {
                let old = response.len();
                let next_total = self
                    .response_bytes
                    .saturating_sub(old)
                    .saturating_add(signed_response_bytes.len());
                ensure!(
                    next_total <= self.limits.response_bytes,
                    "replay response byte capacity reached"
                );
                ensure!(
                    principal_bytes
                        .saturating_sub(old)
                        .saturating_add(signed_response_bytes.len())
                        <= self.limits.response_bytes_per_principal,
                    "principal replay byte capacity reached"
                );
                *response = signed_response_bytes;
                self.response_bytes = next_total;
            }
            _ => bail!("replay response has no matching reservation"),
        }
        Ok(())
    }

    pub fn cancel(&mut self, request: &R) {
        let key = request.replay_key();
        if self
            .entries
            .get(&key)
            .is_some_and(|(_, _, response)| response.is_empty())
        {
            self.entries.remove(&key);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SequenceDecision {
    Fresh,
    InFlight,
    ExactRetry(Vec<u8>),
}

#[derive(Default)]
pub struct SequenceWindow {
    highest: Option<u64>,
    // None is in flight; Some(empty) is a completed response whose payload
    // could not be retained. Keep its digest until the window advances.
    entries: HashMap<u64, ([u8; 32], Option<Vec<u8>>)>,
}

impl SequenceWindow {
    pub fn check(&self, sequence: u64, digest: [u8; 32]) -> Result<SequenceDecision> {
        if let Some((prior, response)) = self.entries.get(&sequence) {
            ensure!(prior == &digest, "sequence reused with different request");
            let Some(response) = response else {
                return Ok(SequenceDecision::InFlight);
            };
            ensure!(!response.is_empty(), "sequence response not retained");
            return Ok(SequenceDecision::ExactRetry(response.clone()));
        }
        if let Some(highest) = self.highest {
            ensure!(
                sequence.saturating_add(SESSION_SEQUENCE_WINDOW) > highest,
                "sequence outside replay window"
            );
        }
        Ok(SequenceDecision::Fresh)
    }

    pub fn reserve(&mut self, sequence: u64, digest: [u8; 32]) -> Result<SequenceDecision> {
        let decision = self.check(sequence, digest)?;
        if matches!(decision, SequenceDecision::Fresh) {
            self.highest = Some(
                self.highest
                    .map_or(sequence, |highest| highest.max(sequence)),
            );
            let floor = self
                .highest
                .unwrap()
                .saturating_sub(SESSION_SEQUENCE_WINDOW - 1);
            self.entries.retain(|seq, _| *seq >= floor);
            self.entries.insert(sequence, (digest, None));
        }
        Ok(decision)
    }

    pub fn record(&mut self, sequence: u64, digest: [u8; 32], response: Vec<u8>) -> Result<()> {
        let retained = self.record_with_limit(
            sequence,
            digest,
            response,
            MAX_REPLAY_RESPONSE_BYTES_PER_PRINCIPAL,
        )?;
        ensure!(retained, "sequence response byte limit reached");
        Ok(())
    }

    /// Bytes retained by this window (at most 64 entries).
    pub fn response_bytes(&self) -> usize {
        self.entries
            .values()
            .filter_map(|(_, response)| response.as_ref())
            .map(Vec::len)
            .sum()
    }

    /// Complete a reservation under a total payload budget. A false result
    /// retains a digest-only tombstone: it refuses retries rather than treating
    /// the executed sequence as fresh. Other sequences remain usable.
    pub fn record_with_limit(
        &mut self,
        sequence: u64,
        digest: [u8; 32],
        response: Vec<u8>,
        max_bytes: usize,
    ) -> Result<bool> {
        ensure!(!response.is_empty(), "empty sequence response");
        match self.reserve(sequence, digest)? {
            SequenceDecision::Fresh | SequenceDecision::InFlight => {}
            SequenceDecision::ExactRetry(_) => bail!("sequence already recorded"),
        }
        let retained = response.len() <= max_bytes.saturating_sub(self.response_bytes());
        self.entries
            .get_mut(&sequence)
            .expect("sequence reserved")
            .1 = Some(if retained { response } else { Vec::new() });
        Ok(retained)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::{SignedRequest, golden};

    #[test]
    fn evicted_inflight_sequence_cannot_be_resurrected_by_late_completion() {
        let mut window = SequenceWindow::default();
        assert_eq!(window.reserve(1, [1; 32]).unwrap(), SequenceDecision::Fresh);
        assert_eq!(
            window.reserve(65, [2; 32]).unwrap(),
            SequenceDecision::Fresh
        );
        assert!(window.record_with_limit(1, [1; 32], vec![1], 10).is_err());
        assert_eq!(window.response_bytes(), 0);
        assert_eq!(
            window.reserve(65, [2; 32]).unwrap(),
            SequenceDecision::InFlight
        );
        assert!(window.reserve(1, [1; 32]).is_err());
    }

    #[test]
    fn sequence_byte_exhaustion_keeps_tombstones_and_releases_window_bytes() {
        let mut window = SequenceWindow::default();
        assert!(window.record_with_limit(1, [1; 32], vec![1; 2], 2).unwrap());
        assert!(!window.record_with_limit(2, [2; 32], vec![2], 2).unwrap());
        assert_eq!(window.response_bytes(), 2);
        assert_eq!(
            window.reserve(1, [1; 32]).unwrap(),
            SequenceDecision::ExactRetry(vec![1; 2])
        );
        assert!(window.reserve(2, [2; 32]).is_err());
        assert!(window.reserve(2, [3; 32]).is_err());
        assert!(window.record_with_limit(65, [4; 32], vec![4], 2).unwrap());
        assert_eq!(window.response_bytes(), 1);
        assert!(window.record_with_limit(1, [1; 32], vec![1; 2], 2).is_err());
        assert_eq!(
            window.response_bytes(),
            1,
            "late completion cannot resurrect an evicted sequence"
        );
        assert!(
            window.reserve(2, [2; 32]).is_err(),
            "unretained completion still cannot execute again"
        );
    }

    /// A cache's bounds are its own: one sized for a single busy principal
    /// takes what the default cache refuses past 1,024 entries.
    #[test]
    fn replay_limits_are_per_cache() {
        let fresh = |n: u32| {
            let mut req = golden::request();
            req.nonce[..4].copy_from_slice(&n.to_le_bytes());
            req
        };
        let mut wide: ReplayCache<SignedRequest> = ReplayCache::with_limits(ReplayLimits {
            entries: 4_096,
            entries_per_principal: 4_096,
            response_bytes: MAX_REPLAY_RESPONSE_BYTES,
            response_bytes_per_principal: MAX_REPLAY_RESPONSE_BYTES,
        });
        let mut default: ReplayCache<SignedRequest> = ReplayCache::default();
        for n in 0..1_500u32 {
            assert_eq!(wide.check(&fresh(n), 1_500).unwrap(), ReplayDecision::Fresh);
            let decided = default.check(&fresh(n), 1_500);
            if (n as usize) < MAX_REPLAY_ENTRIES_PER_PRINCIPAL {
                assert_eq!(decided.unwrap(), ReplayDecision::Fresh);
            } else {
                assert!(decided.is_err(), "the default cache keeps today's bound");
            }
        }
    }

    #[test]
    fn replay_and_sequence_rules_are_fail_closed() {
        let key = iroh::SecretKey::from_bytes(&golden::REQUEST_SIGNER);
        let req = golden::request();
        let mut cache: ReplayCache<SignedRequest> = ReplayCache::default();
        assert_eq!(cache.check(&req, 1_500).unwrap(), ReplayDecision::Fresh);
        cache.record(&req, b"signed".to_vec()).unwrap();
        assert_eq!(
            cache.check(&req, 1_500).unwrap(),
            ReplayDecision::ExactRetry(b"signed".to_vec())
        );
        let mut conflict = req.clone();
        conflict.payload.push(1);
        conflict.proofs.clear();
        conflict.add_proof(&key).unwrap();
        assert_eq!(
            cache.check(&conflict, 1_500).unwrap(),
            ReplayDecision::NonceConflict
        );
        assert_eq!(
            cache
                .check(&req, req.expires_at_ms + REPLAY_RETENTION_AFTER_EXPIRY_MS)
                .unwrap(),
            ReplayDecision::Fresh
        );

        let mut window = SequenceWindow::default();
        window.record(64, [1; 32], b"r".to_vec()).unwrap();
        assert_eq!(
            window.check(64, [1; 32]).unwrap(),
            SequenceDecision::ExactRetry(b"r".to_vec())
        );
        assert!(window.check(64, [2; 32]).is_err());
        window.record(128, [3; 32], b"s".to_vec()).unwrap();
        assert!(window.check(64, [1; 32]).is_err());
        assert!(window.check(65, [4; 32]).is_ok());
    }
}
