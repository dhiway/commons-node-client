//! The Commons node's control/1 client (spec node-access 8.2): the wire types
//! of `commons-node/control/1` and a client for them, which the node, its HTTP
//! sidecar and native programs share, so none of them mirrors the wire.
//!
//! The client binds no endpoint of its own. Every call takes the endpoint, or
//! a connection on it, that the program built from the Commons profile (8.1),
//! so the client never chooses a network (N2). It follows origin's and
//! control/1's versions in lockstep until release (ruling 80).
//!
//! Framing: one request and one response per bidirectional stream,
//! postcard-encoded, each read under [`MAX_FRAME`] (the `auth_wire` envelope
//! bound, a framing guard not a data bound). A subscription's frames, a
//! streamed request's items and a streamed answer's header are each a
//! `u32 LE` length and their bytes. Method arguments and results are JSON
//! under [`PARAMS_CODEC`] and [`RESPONSE_CODEC`]; on every outward interface a
//! version is a decimal string and an author is written in the endpoint's
//! z-base-32 form ([`Entry`], spec 1.6).
//!
//! Two calls do not use iroh: [`local::local_admin_call`] speaks JSON-RPC to
//! the node's private same-UID Unix socket, and
//! [`sidecar::sidecar_admin_call`] speaks the sidecar's JSON lines to
//! `cmn-http`'s, each on this machine and never over the network.

mod exchange;
pub mod key_door;
pub mod local;
/// The Commons network profile (8.1), under the `commons-profile` feature.
#[cfg(feature = "commons-profile")]
pub mod profile;
mod session;
pub mod sidecar;
mod wire;

pub use exchange::{
    NativeSnapshot, NativeSnapshotItem, SNAPSHOT_IDLE_TIMEOUT, SnapshotFailed, Subscription,
    put_many, read_streamed, request, request_on, snapshot_on, subscribe, subscribe_on,
};
pub use session::{
    ClientError, ControlClient, admission_status, cancel_admission, request_admission,
    verify_response,
};
pub use wire::*;
