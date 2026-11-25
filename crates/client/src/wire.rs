//! control/1's names, wire types and frame codecs.

use anyhow::{Context as _, bail};
use auth_wire::v2::{SessionCertificate, SignedRequest, SignedResponse};
use iroh::endpoint::{ReadExactError, RecvStream, SendStream};
use serde::{Deserialize, Serialize};

/// The protocol's ALPN; its version is part of the string.
pub const CONTROL_ALPN: &[u8] = b"commons-node/control/1";

/// Framing guard for one request, response or frame: the `auth_wire`
/// envelope bound.
pub const MAX_FRAME: usize = auth_wire::MAX_WIRE_LEN;

/// The audience service every signed control/1 request names.
pub const AUDIENCE_SERVICE: &str = "origin.node";

/// The request payload codec: JSON method arguments.
pub const PARAMS_CODEC: &str = "commons/jsonrpc-params/v1";
/// The response payload codec: JSON method results.
pub const RESPONSE_CODEC: &str = "commons/jsonrpc-response/v1";

/// A signed operation's name: the prefix, then `<family>.<op>`.
macro_rules! op {
    ($name:literal) => {
        concat!("commons-node/", $name)
    };
}

/// The prefix of every signed operation name.
pub const OP_PREFIX: &str = op!("");

pub const OP_OPEN_SESSION: &str = op!("auth.open-session");
pub const OP_STORE_CREATE: &str = op!("store.create");
pub const OP_STORE_LIST: &str = op!("store.list");
pub const OP_STORE_COUNT: &str = op!("store.count");
pub const OP_NODE_STATUS: &str = op!("node.status");
pub const OP_COMMONS_HOST: &str = op!("commons.host");
pub const OP_STORE_SERVING_FACTS: &str = op!("store.serving-facts");
pub const OP_STORE_PROFILE: &str = op!("store.profile");
pub const OP_STORE_FACTS: &str = op!("store.facts");
/// Admission requests (T296.1, App UI ruling 131): an endpoint the node does
/// not admit yet asks to be admitted. Each is signed by the requester's own
/// endpoint key as an endpoint principal, needs no membership, and is never
/// in a session (not in [`MEMBER_OPERATIONS`]). Each answers an
/// [`AdmissionStatus`].
pub const OP_ADMISSION_REQUEST: &str = op!("admission.request");
pub const OP_ADMISSION_STATUS: &str = op!("admission.status");
pub const OP_ADMISSION_CANCEL: &str = op!("admission.cancel");
/// A requester's own request to subscribe to one of the node's datasets
/// ([`SubscribeRequestStatusParams`]; node-admin contract 9, M7): answers
/// [`SubscribeRequestStatus`] for the request the caller's own endpoint
/// filed through the mailbox, and `none` for any dataset the node holds no
/// request of the caller's for, its own or not. On the admission path:
/// signed by the requester's endpoint key, no membership, no session. The
/// node posts an access notice when an admin decides, but the mailbox is
/// best effort, so this is how a requester learns the outcome for sure.
pub const OP_SUBSCRIBE_REQUEST_STATUS: &str = op!("subscribe.request.status");
/// The admission-request operations, and the subscribe request's status,
/// which shares their path.
pub const ADMISSION_OPERATIONS: &[&str] = &[
    OP_ADMISSION_REQUEST,
    OP_ADMISSION_STATUS,
    OP_ADMISSION_CANCEL,
    OP_SUBSCRIBE_REQUEST_STATUS,
];
/// A person's own request for an API key, and what follows it (node-admin
/// contract 8, "A person asks for a key, and an admin answers"). Each is
/// signed by the requester's endpoint key as an endpoint principal, needs no
/// membership, is never in a session, and goes by the admission path with
/// its own limits. `keys.request` files a
/// [`crate::key_door::KeyRequestParams`]; `.status` and `.cancel` take a
/// [`crate::key_door::KeyRequestIdParams`] and, like it, answer a
/// [`crate::key_door::KeyRequestStatus`]; `.collect` answers a
/// [`crate::key_door::KeyRequestCollected`] with the sealed answer while it
/// stands.
pub const OP_KEYS_REQUEST: &str = op!("keys.request");
pub const OP_KEYS_REQUEST_STATUS: &str = op!("keys.request.status");
pub const OP_KEYS_REQUEST_CANCEL: &str = op!("keys.request.cancel");
pub const OP_KEYS_REQUEST_COLLECT: &str = op!("keys.request.collect");
/// The requester has stored its key
/// ([`crate::key_door::KeyRequestAcknowledgeParams`]): the node forwards it
/// unchanged to the HTTP door, which checks the requester's own signature,
/// marks the key collected and answers a signed
/// [`crate::key_door::KeyCollected`]. A key not collected by its answer's
/// expiry is revoked.
pub const OP_KEYS_REQUEST_ACKNOWLEDGE: &str = op!("keys.request.acknowledge");
/// The requester's key-request operations.
pub const KEY_REQUEST_OPERATIONS: &[&str] = &[
    OP_KEYS_REQUEST,
    OP_KEYS_REQUEST_STATUS,
    OP_KEYS_REQUEST_CANCEL,
    OP_KEYS_REQUEST_COLLECT,
    OP_KEYS_REQUEST_ACKNOWLEDGE,
];
/// The streaming subscription operation: opens a long-lived bidirectional
/// stream over which the node writes [`SubscribeFrame`]s. The payload names
/// the family and, for store families, the namespace and filter.
pub const OP_SUBSCRIBE: &str = op!("subscribe");

/// The delegate's family (spec 3.4), which the node serves to its HTTP
/// sidecar only.
pub const OP_OPERATOR_DATA: &str = op!("operator-data.");
pub const OP_OD_CREATE: &str = op!("operator-data.create");
pub const OP_OD_LIST: &str = op!("operator-data.list");
pub const OP_OD_GET: &str = op!("operator-data.get");
pub const OP_OD_SCAN: &str = op!("operator-data.scan");
pub const OP_OD_AUTHORITY: &str = op!("operator-data.authority");
pub const OP_OD_SNAPSHOT: &str = op!("operator-data.snapshot");
pub const OP_OD_COUNT: &str = op!("operator-data.count");
pub const OP_OD_HISTORY: &str = op!("operator-data.history");
pub const OP_OD_VERSIONS: &str = op!("operator-data.versions");
pub const OP_OD_READ_VALUE: &str = op!("operator-data.read-value");
/// Conditional mutation acknowledged only after native flush. Requires expectedVersion.
pub const OP_OD_PUT_DURABLE: &str = op!("operator-data.put-durable");
/// Owned application-area batch or conditional native mutation.
pub const OP_OD_WRITE_APPLICATION: &str = op!("operator-data.write-application");
/// Same-delegate completion observation; contains no dataset or outcome data.
pub const OP_OD_EFFECT_STATUS: &str = op!("operator-data.effect-status");
/// Persist accepted native batches; never an implicit mutation retry.
pub const OP_OD_FLUSH: &str = op!("operator-data.flush");
pub const OP_OD_PUT: &str = op!("operator-data.put");
pub const OP_OD_PUT_MANY: &str = op!("operator-data.put-many");
pub const OP_OD_DEL: &str = op!("operator-data.del");
pub const OP_OD_STAGE: &str = op!("operator-data.stage");
pub const OP_OD_PUT_HASH: &str = op!("operator-data.put-hash");
pub const OP_OD_READ_RELEASE: &str = op!("operator-data.read-release");
pub const OP_OD_SUBSCRIBE: &str = op!("operator-data.subscribe");
/// The card and the Schema slot, which origin hides from `get` and `scan`.
pub const OP_OD_DESCRIBE: &str = op!("operator-data.describe");
/// The plugin documents this node publishes that the operator made public
/// and listed, with the facts the keyless capability routes show (T327.13,
/// ruling 32): params `{}` or `{namespace}`.
pub const OP_OD_PUBLISHED_PLUGINS: &str = op!("operator-data.published-plugins");
/// The node's definition of a webhook source, `_cmns/ingestion/<source>`,
/// built by the node from the release the request names, and nothing else
/// (spec 6.3, L6).
pub const OP_OD_DECLARE_SOURCE: &str = op!("operator-data.declare-source");
/// The node's source checkpoints, `_cmns/sources/<node>`, and nothing else
/// (spec 6.3, L6).
pub const OP_OD_WRITE_CHECKPOINTS: &str = op!("operator-data.write-checkpoints");
/// The key door (node-admin contract 8): a [`ControlRequest::Stream`] the
/// delegate opens and holds, on which the node forwards admins' key requests
/// and the delegate answers them ([`crate::key_door::KeyDoorFrame`],
/// [`crate::key_door::KeyDoorReply`], each framed by [`write_item`]).
pub const OP_OD_KEY_DOOR: &str = op!("operator-data.key-door");
/// The node's public activity summary (register item 30): `{"window":
/// "now" | "24h" | "7d"}`, answered in the coarsened form any visitor may
/// read, only on a node whose `metrics.access` is `public`.
pub const OP_OD_NODE_ACTIVITY: &str = op!("operator-data.node-activity");

/// How long the node lets a delegate write exchange (`put`, `put-many`,
/// `del`, `put-hash`) run from the moment it reads the request; its handler is
/// dropped then, and when its stream ends, so no handler outlives its
/// exchange by more than this (spec 3.4, review-t209-281 R2-A1). It is the
/// node's default (`[sidecar] write_deadline_secs`); the sidecar journals an
/// unknown outcome only after it.
pub const WRITE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

/// The unsigned public-catalog method names (no signed envelope: the catalog
/// is public). They are method names, not operations, and keep their names.
pub const CATALOG_LIST: &str = "catalog_list";
pub const CATALOG_GET: &str = "catalog_get";
/// The unsigned facts read for stores in the public catalog.
pub const CATALOG_FACTS: &str = "catalog_facts";

/// The operations a member may request in a session certificate, and the
/// set the node grants. Operator control stays local-only, so
/// `auth_openSession` never grants it.
pub const MEMBER_OPERATIONS: &[&str] = &[
    OP_STORE_CREATE,
    OP_STORE_LIST,
    OP_STORE_COUNT,
    OP_NODE_STATUS,
    OP_COMMONS_HOST,
    OP_STORE_SERVING_FACTS,
    OP_STORE_PROFILE,
    OP_STORE_FACTS,
    OP_SUBSCRIBE,
];

/// The admin family (node-admin contract, sections 3 and 4): what an
/// endpoint on the node's admin list may ask, over control/1. The family is
/// decided by this prefix alone: every operation under it is checked against
/// the admin list and never the member list, and every other operation
/// against the member list and never the admin list. A caller that is not an
/// admin gets the same denial as for an unknown operation. Admin operations
/// are never in [`MEMBER_OPERATIONS`], never skip the gate as the admission
/// operations do, and are never served to the delegate. No operation here
/// changes the admin list: only the operator does, on the node.
pub const OP_ADMIN: &str = op!("admin.");

/// [`AdminNodeInfo`]: health, reach, admission mode, storage, version and
/// running since. Takes `{}`.
pub const OP_ADMIN_NODE_INFO: &str = op!("admin.node-info");
/// The node's storage and network checks: the JSON object the local method
/// `admin_doctorChecks` answers. Takes `{}`.
pub const OP_ADMIN_CHECKS: &str = op!("admin.checks");
/// [`AdminHttpStatus`]: whether the node's HTTP door is connected. Takes `{}`.
pub const OP_ADMIN_HTTP_STATUS: &str = op!("admin.http.status");
/// [`AdminList`], read only. Takes `{}`.
pub const OP_ADMIN_ADMINS_LIST: &str = op!("admin.admins.list");
/// [`AdminMemberPage`] for [`AdminMembersListParams`].
pub const OP_ADMIN_MEMBERS_LIST: &str = op!("admin.members.list");
/// [`AdminAdmissionList`]: waiting and decided requests, with who decided.
/// Takes `{}`.
pub const OP_ADMIN_ADMISSION_LIST: &str = op!("admin.admission.list");
/// The hosted datasets, their owners, intake mode and terms: the JSON object
/// the local method `commons_hostingOperator` answers. Takes `{}`.
pub const OP_ADMIN_HOSTING_STATUS: &str = op!("admin.hosting.status");
/// The node's own datasets, one page: the JSON object the local method
/// `dataset_list` answers, for [`AdminDatasetsListParams`].
pub const OP_ADMIN_DATASETS_LIST: &str = op!("admin.datasets.list");
/// One of the node's own datasets, with its owners and peers and their
/// rights and never a ticket: the JSON object the local method
/// `dataset_show` answers, for [`AdminDatasetParams`].
pub const OP_ADMIN_DATASETS_SHOW: &str = op!("admin.datasets.show");
/// [`AdminMetricsSnapshot`], the latest sample. Takes `{}`.
pub const OP_ADMIN_METRICS_SNAPSHOT: &str = op!("admin.metrics.snapshot");
/// [`AdminMetricsHistory`] for [`AdminMetricsHistoryParams`].
pub const OP_ADMIN_METRICS_HISTORY: &str = op!("admin.metrics.history");
/// [`AdminActivityPage`] for [`AdminActivityListParams`].
pub const OP_ADMIN_ACTIVITY_LIST: &str = op!("admin.activity.list");
/// [`AdminRequestList`]: every request the node holds, of every kind, in one
/// shape (node-admin contract 9). Takes `{}`.
pub const OP_ADMIN_REQUESTS_LIST: &str = op!("admin.requests.list");

/// Approve a request ([`AdminLabelParams`]); answers
/// [`AdminAdmissionDecision`]. A request that is no longer waiting is left as
/// it is and answered as it stands, with who decided it.
pub const OP_ADMIN_ADMISSION_APPROVE: &str = op!("admin.admission.approve");
/// Decline a request ([`AdminPeerParams`]); answers
/// [`AdminAdmissionDecision`], as approve does.
pub const OP_ADMIN_ADMISSION_DECLINE: &str = op!("admin.admission.decline");
/// Approve a waiting hosting request ([`AdminHostingRequestParams`]); answers
/// [`AdminRequestDecision`]. The node checks again its terms, the owner's
/// standing under `registered`, `max_stores`, that it has not retired the
/// dataset, and that the consent was not replaced or cancelled. A request
/// that is no longer waiting is left as it is and answered as it stands.
pub const OP_ADMIN_HOSTING_REQUESTS_APPROVE: &str = op!("admin.hosting.requests.approve");
/// Decline a waiting hosting request ([`AdminHostingRequestParams`]);
/// answers [`AdminRequestDecision`], as approve does.
pub const OP_ADMIN_HOSTING_REQUESTS_DECLINE: &str = op!("admin.hosting.requests.decline");
/// Admit an endpoint ([`AdminLabelParams`]); answers [`AdminMemberChange`].
pub const OP_ADMIN_MEMBERS_ADD: &str = op!("admin.members.add");
/// Revoke an endpoint the node has a record of ([`AdminPeerParams`]);
/// answers [`AdminMemberChange`]. An endpoint with no record is refused
/// [`REFUSAL_ADMIN_UNKNOWN_ENDPOINT`].
pub const OP_ADMIN_MEMBERS_REVOKE: &str = op!("admin.members.revoke");
/// Restore a revoked endpoint ([`AdminPeerParams`]); answers
/// [`AdminMemberChange`].
pub const OP_ADMIN_MEMBERS_RESTORE: &str = op!("admin.members.restore");
/// Delete an endpoint's record ([`AdminPeerParams`]); answers
/// [`AdminMemberChange`].
pub const OP_ADMIN_MEMBERS_FORGET: &str = op!("admin.members.forget");
/// Set or clear a member's label ([`AdminLabelParams`]); answers
/// [`AdminMemberChange`].
pub const OP_ADMIN_MEMBERS_LABEL: &str = op!("admin.members.label");
/// Keep or pause intake, or cancel one hosting: the local method
/// `commons_setHostingOperator`'s action object.
pub const OP_ADMIN_HOSTING_SET: &str = op!("admin.hosting.set");
/// The node's own datasets' changes: each takes the parameters of the local
/// `dataset_*` method of the same name.
pub const OP_ADMIN_DATASETS_CREATE: &str = op!("admin.datasets.create");
pub const OP_ADMIN_DATASETS_SET_CARD: &str = op!("admin.datasets.set-card");
pub const OP_ADMIN_DATASETS_SET_SCHEMA: &str = op!("admin.datasets.set-schema");
pub const OP_ADMIN_DATASETS_SET_LISTING: &str = op!("admin.datasets.set-listing");
pub const OP_ADMIN_DATASETS_SET_PUBLIC: &str = op!("admin.datasets.set-public");
pub const OP_ADMIN_DATASETS_SET_CAPABILITY: &str = op!("admin.datasets.set-capability");
pub const OP_ADMIN_DATASETS_PEER_ADD: &str = op!("admin.datasets.peer-add");
pub const OP_ADMIN_DATASETS_PEER_REMOVE: &str = op!("admin.datasets.peer-remove");
/// Retire one of the node's own datasets ([`AdminDatasetDropParams`]): it is
/// withdrawn from service (not served, not synced, no updates, out of the
/// catalog) and nothing is deleted; [`OP_ADMIN_DATASETS_RESTORE`] puts it
/// back. Only the operator deletes for good, on the node (ruling 144).
/// Answers [`AdminDatasetRetireChange`]. Any store that is not one of the
/// node's own datasets is refused [`REFUSAL_ADMIN_NOT_OPERATOR_DATASET`].
pub const OP_ADMIN_DATASETS_DROP: &str = op!("admin.datasets.drop");
/// Return a retired dataset to service ([`AdminDatasetParams`]); answers
/// [`AdminDatasetRetireChange`].
pub const OP_ADMIN_DATASETS_RESTORE: &str = op!("admin.datasets.restore");
/// Approve a waiting request to subscribe to one of the node's datasets
/// ([`AdminSubscribeRequestParams`]); answers [`AdminRequestDecision`]. The
/// node checks again that the dataset is its own, in service and still says
/// "approve", then adds the requester as a reader and nothing more, and owes
/// it an access notice (none for a public dataset). A requester already a
/// reader keeps its rights unchanged. A request that is no longer waiting is
/// left as it is and answered as it stands.
pub const OP_ADMIN_DATASETS_SUBSCRIBE_APPROVE: &str = op!("admin.datasets.subscribe.approve");
/// Decline a waiting request to subscribe ([`AdminSubscribeRequestParams`]);
/// answers [`AdminRequestDecision`]. A decline notice is posted only when
/// the node's quarter of its mailbox share has room.
pub const OP_ADMIN_DATASETS_SUBSCRIBE_DECLINE: &str = op!("admin.datasets.subscribe.decline");

/// A stream of [`AdminEvent`] frames, each naming an area that changed and
/// carrying no data. Sent as [`ControlRequest::Subscribe`] with this
/// operation and `{}`; its own operation, not a family of [`OP_SUBSCRIBE`].
pub const OP_ADMIN_EVENTS: &str = op!("admin.events");
/// A stream of [`AdminMetricsSnapshot`] frames, one per sample the node's
/// sampler takes. Sent as [`ControlRequest::Subscribe`] with this operation
/// and `{}`.
pub const OP_ADMIN_METRICS_STREAM: &str = op!("admin.metrics.stream");

/// The admin reads.
pub const ADMIN_READ_OPERATIONS: &[&str] = &[
    OP_ADMIN_NODE_INFO,
    OP_ADMIN_CHECKS,
    OP_ADMIN_HTTP_STATUS,
    OP_ADMIN_ADMINS_LIST,
    OP_ADMIN_MEMBERS_LIST,
    OP_ADMIN_ADMISSION_LIST,
    OP_ADMIN_HOSTING_STATUS,
    OP_ADMIN_DATASETS_LIST,
    OP_ADMIN_DATASETS_SHOW,
    OP_ADMIN_METRICS_SNAPSHOT,
    OP_ADMIN_METRICS_HISTORY,
    OP_ADMIN_ACTIVITY_LIST,
    OP_ADMIN_REQUESTS_LIST,
];
/// The admin changes. Each is applied once (a retry with the same session
/// sequence gets the first answer), logged with its actor, and rate-limited
/// per admin ([`REFUSAL_ADMIN_RATE_LIMITED`]).
pub const ADMIN_CHANGE_OPERATIONS: &[&str] = &[
    OP_ADMIN_ADMISSION_APPROVE,
    OP_ADMIN_ADMISSION_DECLINE,
    OP_ADMIN_HOSTING_REQUESTS_APPROVE,
    OP_ADMIN_HOSTING_REQUESTS_DECLINE,
    OP_ADMIN_MEMBERS_ADD,
    OP_ADMIN_MEMBERS_REVOKE,
    OP_ADMIN_MEMBERS_RESTORE,
    OP_ADMIN_MEMBERS_FORGET,
    OP_ADMIN_MEMBERS_LABEL,
    OP_ADMIN_HOSTING_SET,
    OP_ADMIN_DATASETS_CREATE,
    OP_ADMIN_DATASETS_SET_CARD,
    OP_ADMIN_DATASETS_SET_SCHEMA,
    OP_ADMIN_DATASETS_SET_LISTING,
    OP_ADMIN_DATASETS_SET_PUBLIC,
    OP_ADMIN_DATASETS_SET_CAPABILITY,
    OP_ADMIN_DATASETS_PEER_ADD,
    OP_ADMIN_DATASETS_PEER_REMOVE,
    OP_ADMIN_DATASETS_DROP,
    OP_ADMIN_DATASETS_RESTORE,
    OP_ADMIN_DATASETS_SUBSCRIBE_APPROVE,
    OP_ADMIN_DATASETS_SUBSCRIBE_DECLINE,
];
/// The admin streams.
pub const ADMIN_STREAM_OPERATIONS: &[&str] = &[OP_ADMIN_EVENTS, OP_ADMIN_METRICS_STREAM];
/// Every admin operation: the set an admin may request in a session
/// certificate. A certificate holds operations of one role only, so a
/// session request that mixes these with [`MEMBER_OPERATIONS`] is denied.
pub const ADMIN_OPERATIONS: &[&str] = &[
    OP_ADMIN_NODE_INFO,
    OP_ADMIN_CHECKS,
    OP_ADMIN_HTTP_STATUS,
    OP_ADMIN_ADMINS_LIST,
    OP_ADMIN_MEMBERS_LIST,
    OP_ADMIN_ADMISSION_LIST,
    OP_ADMIN_HOSTING_STATUS,
    OP_ADMIN_DATASETS_LIST,
    OP_ADMIN_DATASETS_SHOW,
    OP_ADMIN_METRICS_SNAPSHOT,
    OP_ADMIN_METRICS_HISTORY,
    OP_ADMIN_ACTIVITY_LIST,
    OP_ADMIN_REQUESTS_LIST,
    OP_ADMIN_ADMISSION_APPROVE,
    OP_ADMIN_ADMISSION_DECLINE,
    OP_ADMIN_HOSTING_REQUESTS_APPROVE,
    OP_ADMIN_HOSTING_REQUESTS_DECLINE,
    OP_ADMIN_MEMBERS_ADD,
    OP_ADMIN_MEMBERS_REVOKE,
    OP_ADMIN_MEMBERS_RESTORE,
    OP_ADMIN_MEMBERS_FORGET,
    OP_ADMIN_MEMBERS_LABEL,
    OP_ADMIN_HOSTING_SET,
    OP_ADMIN_DATASETS_CREATE,
    OP_ADMIN_DATASETS_SET_CARD,
    OP_ADMIN_DATASETS_SET_SCHEMA,
    OP_ADMIN_DATASETS_SET_LISTING,
    OP_ADMIN_DATASETS_SET_PUBLIC,
    OP_ADMIN_DATASETS_SET_CAPABILITY,
    OP_ADMIN_DATASETS_PEER_ADD,
    OP_ADMIN_DATASETS_PEER_REMOVE,
    OP_ADMIN_DATASETS_DROP,
    OP_ADMIN_DATASETS_RESTORE,
    OP_ADMIN_DATASETS_SUBSCRIBE_APPROVE,
    OP_ADMIN_DATASETS_SUBSCRIBE_DECLINE,
    OP_ADMIN_EVENTS,
    OP_ADMIN_METRICS_STREAM,
];

/// The key operations (node-admin contract 3 and 8; second review, 3):
/// carried out by the HTTP door, which verifies the admin's own signature,
/// so they arrive signed by the admin's endpoint key and are never granted
/// in a session certificate. Not in [`ADMIN_OPERATIONS`]. The node forwards
/// each to the door unchanged and answers with the door's signed
/// [`crate::key_door::KeyDoorAnswer`]; it refuses [`REFUSAL_ADMIN_HTTP_ABSENT`]
/// when no door is connected and [`REFUSAL_ADMIN_OUTCOME_UNKNOWN`] when the
/// door's answer was lost.
pub const OP_ADMIN_KEYS_LIST: &str = op!("admin.keys.list");
pub const OP_ADMIN_KEYS_CREATE: &str = op!("admin.keys.create");
pub const OP_ADMIN_KEYS_REVOKE: &str = op!("admin.keys.revoke");
pub const OP_ADMIN_KEYS_ROTATE: &str = op!("admin.keys.rotate");
pub const OP_ADMIN_HTTP_EXPOSE: &str = op!("admin.http.expose");
pub const OP_ADMIN_HTTP_UNEXPOSE: &str = op!("admin.http.unexpose");
/// An admin approves a person's key request
/// ([`crate::key_door::AdminKeyRequestApproveParams`]): the node marks the
/// request deciding and forwards the admin's signed request to the door,
/// which makes the key, seals it to the requester and answers a
/// [`crate::key_door::KeyRequestApproved`].
pub const OP_ADMIN_KEYS_REQUESTS_APPROVE: &str = op!("admin.keys.requests.approve");
/// An admin declines a person's key request
/// ([`crate::key_door::AdminKeyRequestParams`]): answered by the node alone
/// with an [`AdminRequestDecision`], but like every key operation signed by
/// the admin's endpoint key and never in a session.
pub const OP_ADMIN_KEYS_REQUESTS_DECLINE: &str = op!("admin.keys.requests.decline");
/// Every key operation: endpoint-principal only, never in a session.
pub const ADMIN_KEY_OPERATIONS: &[&str] = &[
    OP_ADMIN_KEYS_LIST,
    OP_ADMIN_KEYS_CREATE,
    OP_ADMIN_KEYS_REVOKE,
    OP_ADMIN_KEYS_ROTATE,
    OP_ADMIN_HTTP_EXPOSE,
    OP_ADMIN_HTTP_UNEXPOSE,
    OP_ADMIN_KEYS_REQUESTS_APPROVE,
    OP_ADMIN_KEYS_REQUESTS_DECLINE,
];
/// The key operations that change something: counted against the admin's
/// hourly change limit before anything is forwarded, and logged with intent
/// and outcome (contract 8, "Limits and records").
pub const ADMIN_KEY_CHANGE_OPERATIONS: &[&str] = &[
    OP_ADMIN_KEYS_CREATE,
    OP_ADMIN_KEYS_REVOKE,
    OP_ADMIN_KEYS_ROTATE,
    OP_ADMIN_HTTP_EXPOSE,
    OP_ADMIN_HTTP_UNEXPOSE,
    OP_ADMIN_KEYS_REQUESTS_APPROVE,
    OP_ADMIN_KEYS_REQUESTS_DECLINE,
];

/// Whether `operation` is in the admin family ([`OP_ADMIN`]), known or not.
pub fn is_admin_operation(operation: &str) -> bool {
    operation.starts_with(OP_ADMIN)
}

/// A signed `store.facts`, `store.serving-facts` or `store.profile` answer to
/// a caller the store's keys let read, when the node's operator or an admin
/// has retired the dataset (ruling 144): it is out of service, nothing is
/// deleted, and it may be restored. Carries no records, addresses or ticket.
/// `catalog_get` marks a listed retired dataset's card `retired: true`.
pub const REFUSAL_STORE_RETIRED: &str = "retired";

/// The longest free text an admin may set (a label, a card field, listing
/// text), in bytes of UTF-8 with no control characters: the bound an
/// admission request's note already has (F11).
pub const MAX_ADMIN_LABEL_BYTES: usize = 280;

/// Refusal codes of the admin operations (signed `ResponseStatus::Error`,
/// payload `{"message": …}`). A caller that is not an admin never sees
/// these: it gets the plain `unauthorized` denial.
///
/// An admin may not revoke an endpoint the node has no record of (not
/// retryable).
pub const REFUSAL_ADMIN_UNKNOWN_ENDPOINT: &str = "unknown_endpoint";
/// The admin has made its changes for this hour (60 by default, the node's
/// `membership.admin_changes_per_hour`); retry later (retryable).
pub const REFUSAL_ADMIN_RATE_LIMITED: &str = "rate_limited";
/// The parameters are not valid for the operation (not retryable).
pub const REFUSAL_ADMIN_INVALID_PARAMS: &str = "invalid_params";
/// The thing asked about does not exist (not retryable).
pub const REFUSAL_ADMIN_NOT_FOUND: &str = "not_found";
/// This node does not offer the operation yet, or the part of the node that
/// answers it is not running (not retryable).
pub const REFUSAL_ADMIN_NOT_AVAILABLE: &str = "not_available";
/// The namespace is not one of the node's own datasets, or does not exist:
/// the answer does not say which (not retryable).
pub const REFUSAL_ADMIN_NOT_OPERATOR_DATASET: &str = "not_operator_dataset";
/// The drop's confirmation does not repeat the dataset's id (not retryable).
pub const REFUSAL_ADMIN_UNCONFIRMED: &str = "unconfirmed";
/// A Write peer was asked for without `confirmOutsideWriters` (not
/// retryable); the message names the consequences.
pub const REFUSAL_ADMIN_OUTSIDE_WRITERS_UNCONFIRMED: &str = "outside_writers_unconfirmed";
/// No HTTP door is connected to the node: nothing was forwarded (retryable).
pub const REFUSAL_ADMIN_HTTP_ABSENT: &str = "http_absent";
/// The request reached the HTTP door but its answer did not come back: send
/// the same operation again with the same request id, which the door answers
/// from its stored answer if it carried it out (retryable).
pub const REFUSAL_ADMIN_OUTCOME_UNKNOWN: &str = "outcome_unknown";

/// Who carried out a change: the node's operator on its admin socket, or an
/// admin, by its endpoint id (z-base-32). Taken only from the authenticated
/// caller; no request field sets it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum AdminActor {
    Local,
    Admin { endpoint: String },
}

/// [`OP_ADMIN_NODE_INFO`]'s answer. It carries no address ticket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminNodeInfo {
    pub node_id: String,
    /// The node's release, as `cmn --version` prints it.
    pub version: String,
    /// When this node process started, as `node.status` gives it.
    pub started_at: u64,
    /// Changes on every node start.
    pub boot_id: String,
    /// `"offline"` or `"relay"`.
    pub mode: String,
    /// `"starting"`, `"recovering"`, `"ready"`, `"degraded"` or `"failed"`.
    pub health: String,
    pub relay_connected: Option<bool>,
    pub detail: Vec<String>,
    pub home_relay: Option<String>,
    pub direct_addresses: Vec<String>,
    /// Distinct endpoints the node has synced with.
    pub peers: u64,
    /// Connections open now.
    pub connections: u64,
    pub storage: AdminStorage,
    /// Its owner, whom it admits and whom it hosts for.
    #[serde(flatten)]
    pub about: NodeAbout,
}

/// The node's disk, as [`AdminNodeInfo`] gives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminStorage {
    pub available_bytes: Option<u64>,
    pub reserve_bytes: u64,
    pub below_reserve: bool,
    /// The metric history's file size on disk; `None` when the node keeps
    /// no history.
    pub metrics_history_bytes: Option<u64>,
}

/// [`OP_ADMIN_HTTP_STATUS`]'s answer: the node's link to its HTTP door, the
/// `cmn-http` sidecar that dials it as its delegate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminHttpStatus {
    /// The node names a delegate (`[sidecar] delegate`).
    pub configured: bool,
    /// The delegate holds a connection to the node now.
    pub connected: bool,
    /// The delegate's endpoint id, z-base-32: the key the door signs its
    /// answers with ([`crate::key_door::KeyDoorAnswer`]). The App pins it
    /// the first time it reads it (A6).
    pub delegate: Option<String>,
}

/// One entry of the node's admin list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminEntry {
    /// The admin's endpoint id, z-base-32.
    pub peer: String,
    pub label: Option<String>,
    pub added_at_ms: u64,
    /// Changes whenever the entry is added again; sessions and streams are
    /// bound to it.
    pub epoch: u32,
}

/// [`OP_ADMIN_ADMINS_LIST`]'s answer, in endpoint id byte order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminList {
    pub admins: Vec<AdminEntry>,
}

/// A member record's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AdminMemberState {
    Active,
    /// The endpoint left by itself.
    Left,
    /// Revoked; it cannot join until restored.
    Revoked,
}

/// What an endpoint is to the node, as the member list an admin reads shows
/// it (node-admin contract 10): its operator (the node's own endpoint), an
/// admin (on the admin list), or a member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AdminMemberRole {
    Operator,
    Admin,
    Member,
}

/// One member record, as `admin_membersList` lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminMember {
    pub peer: String,
    /// [`OP_ADMIN_MEMBERS_LIST`] only: the endpoint's role. An admin keeps
    /// its member state beside it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<AdminMemberRole>,
    pub state: AdminMemberState,
    pub generation: u32,
    pub label: Option<String>,
    pub admitted_at_ms: u64,
    pub changed_at_ms: u64,
}

/// [`OP_ADMIN_MEMBERS_LIST`]'s parameters: records after `after`, in
/// endpoint id byte order, at most `limit` (1..=100, default 100).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminMembersListParams {
    #[serde(default)]
    pub after: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
}

/// [`OP_ADMIN_MEMBERS_LIST`]'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminMemberPage {
    pub members: Vec<AdminMember>,
    /// Pass as the next page's `after`; `None` on the last page.
    pub next: Option<String>,
    /// The node's operator: the node's own endpoint id, whose changes the
    /// activity log shows as `local`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
    /// On the first page only: the admins with no member record, so that
    /// the pages together list every member, every admin and the operator.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub admins: Vec<String>,
}

/// The parameters of a change that names one endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminPeerParams {
    pub peer: String,
}

/// The parameters of a change that names one endpoint and may label it.
/// `label` is at most [`MAX_ADMIN_LABEL_BYTES`]; `None` clears it where the
/// operation sets labels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminLabelParams {
    pub peer: String,
    #[serde(default)]
    pub label: Option<String>,
}

/// The answer to a change of a member record: whether it changed anything,
/// and the record afterwards (`None` once forgotten, or for an endpoint
/// with no record).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminMemberChange {
    pub changed: bool,
    pub member: Option<AdminMember>,
}

/// An admission request's state, as an admin reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AdminRequestState {
    Waiting,
    /// Key requests only: an admin approved it and the HTTP door is making
    /// the key. A second decision gets this state and who decided.
    Deciding,
    Approved,
    Declined,
    /// The requester withdrew it.
    Cancelled,
    /// Nobody answered it before it expired.
    Expired,
    /// Hosting only: the node's hosting terms changed while it waited, or
    /// after its approval and before its transfer began. The owner may
    /// consent to the new terms.
    TermsChanged,
}

/// One admission request, waiting or decided.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminAdmissionRequest {
    pub peer: String,
    /// The requester's own text: show it as plain text.
    pub note: Option<String>,
    pub filed_at_ms: u64,
    pub expires_at_ms: u64,
    pub state: AdminRequestState,
    /// Who approved or declined it; `None` while it waits, and when the
    /// requester cancelled it or it expired.
    pub decided_by: Option<AdminActor>,
    pub decided_at_ms: Option<u64>,
}

/// [`OP_ADMIN_ADMISSION_LIST`]'s answer, oldest filing first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminAdmissionList {
    pub requests: Vec<AdminAdmissionRequest>,
}

/// The answer to approving or declining a request: whether this call
/// decided it, and the request as it stands now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminAdmissionDecision {
    pub changed: bool,
    pub request: AdminAdmissionRequest,
}

/// A request's kind in [`AdminRequestList`]. More kinds come (key
/// requests): a reader that does not know a kind shows the request's common
/// fields and offers no decision on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AdminRequestKind {
    /// To be admitted as a member ([`OP_ADMISSION_REQUEST`]).
    Join,
    /// To have a dataset hosted (`commons.host` with `hosting.approve` on).
    Hosting,
    /// To subscribe to one of the node's own datasets whose card says
    /// "approve" (the mailbox's subscribe request).
    Subscribe,
    /// For an API key ([`OP_KEYS_REQUEST`]); approved with
    /// [`OP_ADMIN_KEYS_REQUESTS_APPROVE`] on the key door.
    Key,
}

/// What a key request carries beside the common fields: what it asks, and
/// the requester's own signed request, which an approval sends back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminKeyRequest {
    /// The request's own id, hex.
    pub request_id: String,
    pub datasets: Vec<String>,
    pub scopes: Vec<String>,
    /// The key's expiry asked, milliseconds since the epoch.
    pub key_expires_at: u64,
    /// The requester's signed request, the first copy the node took: an
    /// approval names it in [`crate::key_door::AdminKeyRequestApproveParams`].
    pub request: crate::key_door::KeyRequestCopy,
    /// While approved: the key made, and when its answer stops standing.
    pub key_id: Option<String>,
    pub answer_expires_at_ms: Option<u64>,
}

/// What a subscribe request carries beside the common fields: the dataset.
/// It has no note.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminSubscribeRequest {
    pub namespace: String,
}

/// The parameters of a decision on one subscribe request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminSubscribeRequestParams {
    pub namespace: String,
    pub requester: String,
}

/// What a hosting request carries beside the common fields. `name` and
/// `size` are the requester's own statement: the node cannot check them
/// before the transfer and they bound nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminHostingRequest {
    pub namespace: String,
    pub consent_revision: u64,
    pub name: Option<String>,
    pub size: Option<u64>,
    /// While approved: when the approval lapses unless the transfer has
    /// begun (24 hours after it, never past the request's expiry).
    pub transfer_by_ms: Option<u64>,
}

/// One request the node holds, of any kind (node-admin contract 9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminRequest {
    /// The id `cmn requests approve|decline` takes.
    pub id: String,
    pub kind: AdminRequestKind,
    /// The endpoint the request's signature proves.
    pub requester: String,
    /// Joining only: the requester's own text. Show it as plain text.
    pub note: Option<String>,
    pub sent_at_ms: u64,
    pub expires_at_ms: u64,
    pub state: AdminRequestState,
    /// Who approved or declined it; `None` while it waits, and when the
    /// requester cancelled it, it expired or its terms changed.
    pub decided_by: Option<AdminActor>,
    pub decided_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosting: Option<AdminHostingRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subscribe: Option<AdminSubscribeRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<AdminKeyRequest>,
}

/// [`OP_ADMIN_REQUESTS_LIST`]'s answer, oldest first. Each kind is bounded
/// on the node, so this is one page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminRequestList {
    pub requests: Vec<AdminRequest>,
}

/// The parameters of a decision on one hosting request: the consent as the
/// list shows it, so a consent the owner replaced since is not decided.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminHostingRequestParams {
    pub namespace: String,
    pub owner: String,
    pub consent_revision: u64,
}

/// The answer to deciding a request: whether this call decided it, and the
/// request as it stands now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminRequestDecision {
    pub changed: bool,
    pub request: AdminRequest,
}

/// [`OP_ADMIN_DATASETS_LIST`]'s parameters: the page after `cursor`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminDatasetsListParams {
    #[serde(default)]
    pub cursor: Option<String>,
}

/// The parameters of an operation on one of the node's own datasets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminDatasetParams {
    pub namespace: String,
}

/// [`OP_ADMIN_DATASETS_DROP`]'s parameters: `confirm` repeats `namespace`
/// as it is written there; anything else is refused
/// [`REFUSAL_ADMIN_UNCONFIRMED`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminDatasetDropParams {
    pub namespace: String,
    pub confirm: String,
}

/// Who retired a dataset and when. `admin.datasets.list` and `.show` carry
/// it as `retired` (absent or `null` for a dataset in service).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminDatasetRetired {
    pub by: AdminActor,
    pub at_ms: u64,
}

/// The answer to retiring or restoring a dataset: whether this call changed
/// it, and its retired state afterwards (`None` in service).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminDatasetRetireChange {
    pub namespace: String,
    pub changed: bool,
    pub retired: Option<AdminDatasetRetired>,
}

/// One named value of a metrics sample.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminMetricSample {
    pub name: String,
    /// `"gauge"` (a level) or `"counter"` (monotonic within one process
    /// instance).
    pub kind: String,
    pub unit: String,
    /// Absent when the node has no exact source for the value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<i64>,
}

/// One metrics sample, the shape the local `admin_metricsSnapshot` answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminMetricsSnapshot {
    /// Random per node process: a change means the counters restarted.
    pub process_instance: String,
    pub build: String,
    /// Increases by one per sample within a process instance.
    pub sequence: u64,
    /// Milliseconds since the Unix epoch.
    pub observed_at: u64,
    /// `"summary"`, or a store's namespace id for a store's samples.
    pub scope: String,
    pub samples: Vec<AdminMetricSample>,
}

/// [`OP_ADMIN_METRICS_HISTORY`]'s parameters: the samples from `start_ms`
/// to `end_ms`, thinned to one per `step_ms`. A range at a step that would
/// select more than 1,441 records, or whose answer would not fit one frame
/// (4 MiB), is refused with `invalid_params` before the answer is built:
/// ask again at a larger step. A record takes about 3 KB plus 0.6 KB for
/// each of the node's datasets and hosted stores, so a day at one minute
/// fits a node with none of them, a day at two minutes one with up to five,
/// and a node with more needs a larger step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminMetricsHistoryParams {
    pub start_ms: u64,
    pub end_ms: u64,
    pub step_ms: u64,
}

/// [`OP_ADMIN_METRICS_HISTORY`]'s answer, oldest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminMetricsHistory {
    pub samples: Vec<AdminMetricsSnapshot>,
}

/// One activity log entry: a change to the node, by an admin or on the
/// admin socket. It holds no secret and no dataset content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminActivityEntry {
    /// Increases with every entry; pass as `before` for the next page.
    pub id: u64,
    pub at_ms: u64,
    pub actor: AdminActor,
    /// What was done, as the operation's short name (`members.revoke`,
    /// `admins.add`, ...).
    pub action: String,
    /// What it was done to: an endpoint id, or a namespace id.
    pub target: Option<String>,
    /// What came of it (`revoked`, `admitted`, ...). A dataset, hosting or
    /// retire change is logged `pending` before it is made and settled with
    /// its outcome after; one still pending at a restart is settled from the
    /// real state (`applied` or `not applied`).
    pub outcome: String,
    /// For a card, schema, listing or other dataset setting change, the
    /// value before it, so a mistake can be put back (JSON text).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<String>,
    /// For a dataset peer change, what it gave: the peer's endpoint id and,
    /// for `datasets.peer-add`, the capability granted (JSON text,
    /// `{"endpoint": ..., "capability": "read" | "write"}`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// [`OP_ADMIN_ACTIVITY_LIST`]'s parameters: entries older than `before`
/// (all when `None`), newest first, at most `limit` (1..=100, default 50).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminActivityListParams {
    #[serde(default)]
    pub before: Option<u64>,
    #[serde(default)]
    pub limit: Option<u32>,
}

/// [`OP_ADMIN_ACTIVITY_LIST`]'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminActivityPage {
    pub entries: Vec<AdminActivityEntry>,
    /// Pass as the next page's `before`; `None` on the last page.
    pub next: Option<u64>,
}

/// The area an [`AdminEvent`] names: read it again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AdminArea {
    Admission,
    Members,
    Hosting,
    Datasets,
    Admins,
    Activity,
    Keys,
    /// [`OP_ADMIN_REQUESTS_LIST`]. A reader that does not know an area reads
    /// every area again.
    Requests,
}

/// One [`OP_ADMIN_EVENTS`] frame's JSON payload. A stream that falls behind
/// ends `"lagged"`; the reader then reads every area again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminEvent {
    pub area: AdminArea,
}

/// [`OP_ADMISSION_REQUEST`]'s parameters (JSON). `note` is at most 280
/// bytes of UTF-8 with no control or Unicode format characters;
/// `expires_in_secs` is in 60..=604800 and defaults to the most, seven days.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdmissionRequestParams {
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub expires_in_secs: Option<u64>,
}

/// A requester's admission request, as the node reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AdmissionState {
    /// Waiting for the node's operator, until `expires_at_ms`.
    Waiting,
    /// The endpoint is admitted to the node. That grants nothing in any
    /// dataset: each store's own keys decide (ruling 58).
    Admitted,
    /// The operator declined it, or has revoked the endpoint.
    Declined,
    /// Nobody answered it before it expired.
    Expired,
    /// No request is on record, or the requester cancelled it.
    None,
}

/// [`OP_SUBSCRIBE_REQUEST_STATUS`]'s parameters: the dataset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubscribeRequestStatusParams {
    pub namespace: String,
}

/// A requester's request to subscribe, as the node reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SubscribeRequestState {
    /// Waiting for an admin, until `expires_at_ms`.
    Waiting,
    /// The requester is a reader of the dataset. That is all: it is not
    /// made a member of the node.
    Approved,
    Declined,
    /// Nobody answered it before it expired.
    Expired,
    /// No request is on record.
    None,
}

/// [`OP_SUBSCRIBE_REQUEST_STATUS`]'s answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscribeRequestStatus {
    pub state: SubscribeRequestState,
    /// When a waiting request expires, in Unix milliseconds; `None` in every
    /// other state.
    pub expires_at_ms: Option<u64>,
}

/// The answer to every admission-request operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionStatus {
    pub state: AdmissionState,
    /// When a waiting request expires, in Unix milliseconds; `None` in every
    /// other state.
    pub expires_at_ms: Option<u64>,
}

/// The JSON body of a mailbox `AdmissionRequest` (ruling 133): the request
/// a node reads from its Statement Store topic when it starts and while it
/// runs, so it reaches a node that was offline. The sender is the
/// statement's signer, the requester; the statement's expiry (at most seven
/// days) is the request's. The node files it under the same checks and
/// bounds as [`OP_ADMISSION_REQUEST`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdmissionMailboxRequest {
    #[serde(default)]
    pub note: Option<String>,
}

/// The JSON body of a mailbox `AdmissionAnswer`, which the node posts to the
/// requester's topic when its operator approves or declines. `request` is
/// the answered `AdmissionRequest` message's id, hex; `state` is
/// [`AdmissionState::Admitted`] or [`AdmissionState::Declined`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdmissionMailboxAnswer {
    pub request: String,
    pub state: AdmissionState,
}

/// Whom a node admits: its `membership.admission` rule, in plain data. Being
/// admitted lets an endpoint create and publish stores on the node; it grants
/// nothing in any dataset, whose own typed keys decide (ruling 58).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NodeAdmits {
    /// Anyone who asks: an endpoint's own join or admission request admits
    /// it. A node's default.
    Open,
    /// Only the endpoints its operator approves (`cmn` lists, approves and
    /// declines the requests, ruling 131).
    Permissioned,
}

/// Whom a node hosts datasets for: its `[hosting] accept` setting, in plain
/// data. [`OP_NODE_STATUS`] answers it beside [`NodeAdmits`], and
/// [`OP_COMMONS_HOST`]'s `terms` action beside the terms, so a client can
/// tell before it asks. A node that predates the setting answers neither;
/// read as [`NodeHosting::Anyone`], which is what such a node does. A value
/// this client does not know (a later node's) reads as [`NodeHosting::None`],
/// the conservative answer, so the rest of the answer it came in still
/// parses.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum NodeHosting {
    /// Any member endpoint may ask it to host a dataset.
    #[default]
    Anyone,
    /// Only an endpoint that holds a handle (the chain links it to a Name)
    /// and that Commons Services shows registered and allowed now; others
    /// are refused [`REFUSAL_HOSTING_HANDLE_REQUIRED`] (no handle) or
    /// [`REFUSAL_HOSTING_DENIED`] (a handle, not allowed now).
    Registered,
    /// No one: it serves its own datasets only and refuses
    /// [`REFUSAL_HOSTING_CLOSED`].
    None,
}

impl<'de> Deserialize<'de> for NodeHosting {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = std::borrow::Cow::<'de, str>::deserialize(deserializer)?;
        Ok(match value.as_ref() {
            "anyone" => Self::Anyone,
            "registered" => Self::Registered,
            // "none", and any value a later node may add: hosts for no one
            // as far as this client can tell.
            _ => Self::None,
        })
    }
}

/// The refusal codes of the node's hosting policy (signed
/// `ResponseStatus::Error { code, retryable }`, payload `{"message": …}`),
/// answered to `commons.host`'s `accept` and `transfer` and to
/// `store.create`.
///
/// The node hosts nothing for others, or (to `store.create` on a node that
/// hosts for registered endpoints) creates no store for them: a store is
/// placed there by a hosting consent only (not retryable).
pub const REFUSAL_HOSTING_CLOSED: &str = "hosting_closed";
/// The endpoint holds no handle (the chain links it to no Name): claim a
/// handle first (not retryable).
pub const REFUSAL_HOSTING_HANDLE_REQUIRED: &str = "hosting_handle_required";
/// The endpoint holds a handle, but Commons Services does not allow it now:
/// its registration is denied or expired (not retryable).
pub const REFUSAL_HOSTING_DENIED: &str = "hosting_denied";
/// The node could not check the endpoint with Commons Services; retry later
/// (retryable).
pub const REFUSAL_HOSTING_CHECK_UNAVAILABLE: &str = "hosting_check_unavailable";

/// A node's owner and admission terms, as [`OP_NODE_STATUS`] answers them
/// beside its health and address (flattened into the same JSON object, so
/// a reader of the whole answer parses this type out of it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeAbout {
    /// The handle the node's owner linked it to, without its `@`, as the
    /// node last read it from the chain's link set (ruling 121: only the
    /// owner links a node to a name). `None`: the node knows of no linked
    /// handle.
    pub owner: Option<String>,
    /// Whom it admits.
    pub admits: NodeAdmits,
    /// Whom it hosts datasets for; absent from an older node's answer.
    #[serde(default)]
    pub hosting: NodeHosting,
}

/// What a peer asks over one control stream.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ControlRequest {
    /// A signed `auth_wire` v2 request; its `operation` names the method.
    Signed(Box<SignedRequest>),
    /// An unsigned public-catalog read; `method` is [`CATALOG_LIST`],
    /// [`CATALOG_GET`] or [`CATALOG_FACTS`], `payload` the JSON arguments.
    Unsigned { method: String, payload: Vec<u8> },
    /// A streaming subscription: the signed request's `operation` is
    /// [`OP_SUBSCRIBE`], or one of [`ADMIN_STREAM_OPERATIONS`]. The node
    /// answers `Accepted` or `Ended` first, then writes event frames until
    /// the peer closes the connection.
    Subscribe(Box<SignedRequest>),
    /// A streamed request (the delegate's `put-many`): never postcard-encoded
    /// whole. The stream carries [`STREAM_TAG`], the signed request as a
    /// `u32 LE` length and its postcard bytes, then items, each a `u32 LE`
    /// length and its bytes, until the peer finishes its send side
    /// ([`write_stream_head`], [`write_item`]).
    Stream(Box<SignedRequest>),
}

/// The first byte of a streamed request: [`ControlRequest::Stream`]'s
/// postcard variant tag, which no whole-encoded request of the other
/// variants starts with.
pub const STREAM_TAG: u8 = 3;

/// What the node answers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ControlResponse {
    /// The signed answer to a signed request.
    Signed(Box<SignedResponse>),
    /// `auth_openSession`'s session certificate.
    Session(Box<SessionCertificate>),
    /// An unsigned catalog answer: `Ok(JSON result)` or `Err(reason)`.
    Unsigned(Result<Vec<u8>, String>),
}

/// The four member event families of `subscribe`. The variant names are the
/// wire `family` strings (camelCase).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SubscribeFamily {
    StoreEvents,
    SyncProgress,
    ContentProgress,
    NodeEvents,
}

/// One frame the node writes over an open subscription stream.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SubscribeFrame {
    /// Written once, first: the subscription is accepted and live frames
    /// follow.
    Accepted,
    /// One live event. `payload` is the JSON event object of the subscribed
    /// family.
    Event { payload: Vec<u8> },
    /// Terminal: no further frames. `reason` is a short, stable code:
    /// `"ended"` (the engine stream closed), `"lagged"`, `"gap"`,
    /// `"unauthorized"`, `"busy"`, `"invalid-parameters"`, `"store-not-open"`,
    /// `"unavailable"`, or `"replaced"`. `"replaced"` ends an admin stream
    /// ([`ADMIN_STREAM_OPERATIONS`]) when another client of the same admin
    /// opens one of the same kind: each admin holds one of each, and the
    /// newer takes it. It is final: do not reopen, or two clients of one
    /// admin will keep replacing each other.
    Ended { reason: String },
}

/// An entry as control/1's frames and the delegate's answers spell it: the
/// key in the node's `utf8:`/`hex:` form, the author in the endpoint's
/// z-base-32 form, the content id in base32 and the version as a decimal
/// string (spec 1.6). Rust keeps the version a `u64` and the author its
/// bytes; only the text form changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub key: String,
    #[serde(with = "author")]
    pub author: [u8; 32],
    pub content_id: String,
    pub len: u64,
    pub content_status: String,
    #[serde(with = "decimal")]
    pub version: u64,
    pub tombstone: bool,
}

/// Inline response content and native batch receipts fit beneath this budget.
/// This is the existing control/1 framing budget, not a record/value size limit.
/// Larger values remain available through native blob transfer.
pub const INLINE_VALUE_BUDGET: u64 = 3 * 1024 * 1024;

/// Exact native identity. Keys are full native keys, including application area.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeEntryIdentity {
    pub key: String,
    #[serde(with = "author")]
    pub author: [u8; 32],
    pub content_id: String,
    pub len: u64,
    #[serde(with = "decimal")]
    pub version: u64,
    pub tombstone: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApplicationArea {
    Ordinary,
    DerivedV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum ApplicationValue {
    Inline { value: String },
    Hash { hash: String, length: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicationItem {
    pub key: String,
    pub value: ApplicationValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "camelCase", deny_unknown_fields)]
pub enum ApplicationMutation {
    Batch {
        items: Vec<ApplicationItem>,
    },
    Conditional {
        key: String,
        value: ApplicationValue,
        expected: Option<NativeEntryIdentity>,
    },
}

/// A finite signed payload. Derived-v1 mutation keys are relative raw suffixes;
/// predecessor and receipt identities always carry full expanded native keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicationWrite {
    pub namespace: String,
    pub boot_id: String,
    pub authority: String,
    pub area: ApplicationArea,
    pub mutation: ApplicationMutation,
}

/// One authenticated snapshot attempt. Its rows are as-of the native capture,
/// not a claim that the store has stopped changing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperatorSnapshotHeader {
    pub snapshot_id: String,
    pub authority: String,
}

/// Metadata is framed under MAX_FRAME; an Entry is immediately followed by
/// exactly Entry.len unframed value bytes (zero for a tombstone).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperatorSnapshotFrame {
    Entry(Entry),
    Complete,
    Error { code: String, message: String },
}

pub async fn write_snapshot_frame(
    send: &mut SendStream,
    frame: &OperatorSnapshotFrame,
) -> anyhow::Result<()> {
    let bytes = postcard::to_stdvec(frame)?;
    anyhow::ensure!(
        bytes.len() <= MAX_FRAME,
        "snapshot metadata exceeds MAX_FRAME"
    );
    write_item(send, &bytes).await
}

/// A version (or any `u64` the interface carries past 2^53) as a decimal
/// string in every serializer, read back only from a decimal string.
pub mod decimal {
    use serde::{Deserialize as _, Deserializer, Serializer, de::Error as _};

    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(value)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let text = std::borrow::Cow::<str>::deserialize(deserializer)?;
        if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
            return Err(D::Error::custom("a version is a decimal string"));
        }
        text.parse().map_err(D::Error::custom)
    }
}

/// An author as the endpoint it is: z-base-32 text in a human-readable
/// serializer (hex for bytes that are no endpoint key), its 32 bytes in a
/// binary one. Reading accepts any of origin's three id forms
/// (`origin::id::parse`).
pub mod author {
    use serde::{Deserialize as _, Deserializer, Serialize as _, Serializer, de::Error as _};

    /// The endpoint form of 32 author bytes.
    pub fn text(bytes: &[u8; 32]) -> String {
        iroh::EndpointId::from_bytes(bytes)
            .map(|id| origin::id::z32(&id))
            .unwrap_or_else(|_| hex::encode(bytes))
    }

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&text(bytes))
        } else {
            bytes.serialize(serializer)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        if deserializer.is_human_readable() {
            let text = std::borrow::Cow::<str>::deserialize(deserializer)?;
            origin::id::parse(&text).map_err(D::Error::custom)
        } else {
            <[u8; 32]>::deserialize(deserializer)
        }
    }
}

/// Writes one length-prefixed (u32 LE) postcard subscription frame.
pub async fn write_frame(send: &mut SendStream, frame: &SubscribeFrame) -> anyhow::Result<()> {
    let bytes = postcard::to_stdvec(frame).context("encoding subscribe frame")?;
    if bytes.len() > MAX_FRAME {
        bail!("subscribe frame exceeds MAX_FRAME");
    }
    let len = u32::try_from(bytes.len()).context("subscribe frame exceeds u32")?;
    send.write_all(&len.to_le_bytes())
        .await
        .context("writing subscribe frame length")?;
    send.write_all(&bytes)
        .await
        .context("writing subscribe frame")?;
    Ok(())
}

/// Reads one length-prefixed postcard subscription frame, or `None` on a
/// clean end of stream (the node finished its send side).
pub async fn read_frame(recv: &mut RecvStream) -> anyhow::Result<Option<SubscribeFrame>> {
    let Some(bytes) = read_item(recv).await? else {
        return Ok(None);
    };
    Ok(Some(
        postcard::from_bytes(&bytes).context("decoding subscribe frame")?,
    ))
}

/// The head of a streamed request: [`STREAM_TAG`], then the signed request
/// length-prefixed.
pub async fn write_stream_head(
    send: &mut SendStream,
    request: &SignedRequest,
) -> anyhow::Result<()> {
    let encoded = postcard::to_stdvec(request)?;
    send.write_all(&[STREAM_TAG]).await?;
    send.write_all(&u32::try_from(encoded.len())?.to_le_bytes())
        .await?;
    send.write_all(&encoded).await?;
    Ok(())
}

/// One length-prefixed item of a streamed request or answer.
pub async fn write_item(send: &mut SendStream, item: &[u8]) -> anyhow::Result<()> {
    send.write_all(&u32::try_from(item.len())?.to_le_bytes())
        .await?;
    send.write_all(item).await?;
    Ok(())
}

/// Reads one `u32 LE` length-prefixed item, or `None` at a clean end.
pub async fn read_item(recv: &mut RecvStream) -> anyhow::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match recv.read_exact(&mut len).await {
        Ok(()) => {}
        Err(ReadExactError::FinishedEarly(0)) => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let len = u32::from_le_bytes(len) as usize;
    anyhow::ensure!(len <= MAX_FRAME, "item exceeds the frame bound");
    let mut item = vec![0u8; len];
    recv.read_exact(&mut item).await.context("reading item")?;
    Ok(Some(item))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Review t311-verify-node-3 A5: the three values round-trip; one this
    /// client does not know reads as hosting for no one, and the node status
    /// it came in still parses with its owner and admission rule; an older
    /// node's answer, without the field, reads as hosting for anyone.
    #[test]
    fn node_hosting_reads_an_unknown_value_as_closed() {
        for hosting in [
            NodeHosting::Anyone,
            NodeHosting::Registered,
            NodeHosting::None,
        ] {
            let wire = serde_json::to_value(hosting).unwrap();
            assert_eq!(
                serde_json::from_value::<NodeHosting>(wire).unwrap(),
                hosting
            );
        }
        let later: NodeAbout = serde_json::from_value(json!({
            "owner": "asha_rao", "admits": "open", "hosting": "invitedOnly", "health": "ready",
        }))
        .unwrap();
        assert_eq!(later.hosting, NodeHosting::None);
        assert_eq!(later.owner.as_deref(), Some("asha_rao"));
        assert_eq!(later.admits, NodeAdmits::Open);
        let older: NodeAbout =
            serde_json::from_value(json!({"owner": null, "admits": "open"})).unwrap();
        assert_eq!(older.hosting, NodeHosting::Anyone);
    }

    #[test]
    fn application_storage_wire_keeps_exact_identity_and_closed_shapes() {
        let (entry, _) = entry();
        let identity = NativeEntryIdentity {
            key: "hex:00ff".into(),
            author: entry.author,
            content_id: entry.content_id,
            len: u64::MAX,
            version: u64::MAX,
            tombstone: true,
        };
        let encoded = serde_json::to_value(&identity).unwrap();
        assert_eq!(encoded["version"], u64::MAX.to_string());
        assert_eq!(
            serde_json::from_value::<NativeEntryIdentity>(encoded.clone()).unwrap(),
            identity
        );
        for invalid in [
            json!(-1),
            json!(7),
            json!("-1"),
            json!("18446744073709551616"),
        ] {
            let mut value = encoded.clone();
            value["version"] = invalid;
            assert!(serde_json::from_value::<NativeEntryIdentity>(value).is_err());
        }
        let request = ApplicationWrite {
            namespace: "dataset".into(),
            boot_id: "original-boot".into(),
            authority: "original-stamp".into(),
            area: ApplicationArea::DerivedV1,
            mutation: ApplicationMutation::Conditional {
                key: "hex:00ff".into(),
                value: ApplicationValue::Hash {
                    hash: "hash".into(),
                    length: u64::MAX,
                },
                expected: Some(identity),
            },
        };
        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(value["area"], "derived-v1");
        assert_eq!(
            serde_json::from_value::<ApplicationWrite>(value.clone()).unwrap(),
            request
        );
        for location in ["root", "mutation", "value", "expected"] {
            let mut bad = value.clone();
            match location {
                "root" => bad["extra"] = json!(true),
                "mutation" => bad["mutation"]["extra"] = json!(true),
                "value" => bad["mutation"]["value"]["extra"] = json!(true),
                _ => bad["mutation"]["expected"]["extra"] = json!(true),
            }
            assert!(serde_json::from_value::<ApplicationWrite>(bad).is_err());
        }
        let bad =
            json!({"op":"batch","items":[{"key":"utf8:k","value":{"kind":"inline","value":42}}]});
        assert!(serde_json::from_value::<ApplicationMutation>(bad).is_err());
    }

    fn entry() -> (Entry, iroh::EndpointId) {
        let author = iroh::SecretKey::from([3u8; 32]).public();
        let entry = Entry {
            key: "utf8:orders/1".into(),
            author: *author.as_bytes(),
            content_id: "b".repeat(52),
            len: 4,
            content_status: "complete".into(),
            version: 7_200_000_000_000_000_123,
            tombstone: false,
        };
        (entry, author)
    }

    /// Decision 2 and spec 1.6: every signed operation is named under
    /// `commons-node/`, while the unsigned catalog methods keep their names.
    #[test]
    fn operation_names_use_commons_node_prefix_catalog_names_unchanged() {
        assert_eq!(OP_PREFIX, "commons-node/");
        let delegate = [
            OP_OD_CREATE,
            OP_OD_LIST,
            OP_OD_GET,
            OP_OD_SCAN,
            OP_OD_COUNT,
            OP_OD_HISTORY,
            OP_OD_VERSIONS,
            OP_OD_READ_VALUE,
            OP_OD_PUT,
            OP_OD_PUT_DURABLE,
            OP_OD_WRITE_APPLICATION,
            OP_OD_FLUSH,
            OP_OD_EFFECT_STATUS,
            OP_OD_PUT_MANY,
            OP_OD_DEL,
            OP_OD_STAGE,
            OP_OD_PUT_HASH,
            OP_OD_READ_RELEASE,
            OP_OD_PUBLISHED_PLUGINS,
            OP_OD_SUBSCRIBE,
            OP_OD_DESCRIBE,
            OP_OD_NODE_ACTIVITY,
        ];
        assert!(delegate.iter().all(|op| op.starts_with(OP_OPERATOR_DATA)));
        let signed = MEMBER_OPERATIONS
            .iter()
            .chain([&OP_OPEN_SESSION])
            .chain(delegate.iter());
        for operation in signed {
            let family_op = operation
                .strip_prefix("commons-node/")
                .unwrap_or_else(|| panic!("{operation} is not under commons-node/"));
            assert!(
                !family_op.is_empty() && !family_op.contains('/'),
                "{operation}"
            );
        }
        assert_eq!(
            [CATALOG_LIST, CATALOG_GET, CATALOG_FACTS],
            ["catalog_list", "catalog_get", "catalog_facts"]
        );
    }

    /// Node-admin contract 3: the admin family is told by its prefix alone,
    /// shares no name with the member or admission operations, lists every
    /// admin operation once, and has no operation that changes the admin
    /// list (only the operator does, on the node).
    #[test]
    fn admin_operations_are_one_family_apart_from_members() {
        let mut union: Vec<&str> = ADMIN_READ_OPERATIONS
            .iter()
            .chain(ADMIN_CHANGE_OPERATIONS)
            .chain(ADMIN_STREAM_OPERATIONS)
            .copied()
            .collect();
        let mut all = ADMIN_OPERATIONS.to_vec();
        union.sort_unstable();
        all.sort_unstable();
        assert_eq!(union, all);
        let before = all.len();
        all.dedup();
        assert_eq!(all.len(), before, "each admin operation is listed once");
        for operation in ADMIN_OPERATIONS {
            assert!(is_admin_operation(operation), "{operation}");
            let family_op = operation.strip_prefix(OP_PREFIX).unwrap();
            assert!(!family_op.contains('/'), "{operation}");
            assert!(
                !family_op.starts_with("admin.admins.") || *operation == OP_ADMIN_ADMINS_LIST,
                "{operation} would change the admin list"
            );
        }
        for operation in MEMBER_OPERATIONS
            .iter()
            .chain(ADMISSION_OPERATIONS)
            .chain(KEY_REQUEST_OPERATIONS)
            .chain([&OP_OPEN_SESSION, &OP_OPERATOR_DATA])
        {
            assert!(!is_admin_operation(operation), "{operation}");
        }
        // Contract 8: a requester's key operations are in no session and no
        // other path's list.
        for operation in KEY_REQUEST_OPERATIONS {
            assert!(!MEMBER_OPERATIONS.contains(operation), "{operation}");
            assert!(!ADMISSION_OPERATIONS.contains(operation), "{operation}");
        }
        assert!(is_admin_operation("commons-node/admin.not-yet-known"));
        assert!(!is_admin_operation("commons-node/administer"));
        // Second review, 3: key operations are admin-family but never
        // grantable in a session certificate.
        for operation in ADMIN_KEY_OPERATIONS {
            assert!(is_admin_operation(operation), "{operation}");
            assert!(!ADMIN_OPERATIONS.contains(operation), "{operation}");
        }
    }

    /// Spec 1.6: a version above 2^53 travels as a decimal string and an
    /// author as its endpoint's z-base-32 id; both read back to the same
    /// `u64` and bytes, the author from any of origin's three forms, and
    /// the binary encoding keeps the same values.
    #[test]
    fn wire_round_trip_versions_decimal_authors_z32() {
        let (entry, author) = entry();
        let text = serde_json::to_value(&entry).unwrap();
        assert_eq!(text["version"], json!("7200000000000000123"));
        assert_eq!(text["author"], json!(author.to_z32()));
        assert_eq!(
            serde_json::from_value::<Entry>(text.clone()).unwrap(),
            entry
        );

        for form in [
            hex::encode(author.as_bytes()),
            origin::id::b32(author.as_bytes()),
        ] {
            let mut other = text.clone();
            other["author"] = json!(form);
            assert_eq!(serde_json::from_value::<Entry>(other).unwrap(), entry);
        }

        for refused in [
            json!(7_200_000_000_000_000_123u64),
            json!("-1"),
            json!(""),
            json!("+123"),
            json!(" 1"),
        ] {
            let mut other = text.clone();
            other["version"] = refused;
            assert!(serde_json::from_value::<Entry>(other).is_err());
        }

        let bytes = postcard::to_stdvec(&entry).unwrap();
        assert_eq!(postcard::from_bytes::<Entry>(&bytes).unwrap(), entry);
    }
}
