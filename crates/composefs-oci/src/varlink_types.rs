//! Wire types and the client proxy for the `io.cncf.composefs.OciTransfer`
//! varlink interface: moving OCI images and layers between stores.
//!
//! Every store serves the same interface. A composefs repository (cfsctl's
//! `CfsctlService`) serves all of it; a read-only store, such as the
//! containers-storage service (`CstorLayerService` in composefs-storage),
//! advertises the [`FEATURE_READ_ONLY`] token in `GetInfo` and answers the
//! Put methods (`PutLayer`, `FinalizeImage`) with
//! [`OciTransferError::ReadOnly`].
//!
//! These types live here (in `composefs-oci`) rather than `composefs-ctl` so
//! that the repository service and the containers-storage client in
//! `crate::cstor` share them. composefs-storage can't depend on this crate
//! (that would be a cycle), so `CstorLayerService` keeps wire-compatible
//! copies.
//!
//! # Feature gate
//!
//! This module is compiled only when the `varlink` feature is enabled on
//! `composefs-oci` (which pulls in `zlink`).

#![allow(missing_docs)]

use serde::{Deserialize, Serialize};

/// The varlink interface name.
pub const OCI_TRANSFER_INTERFACE: &str = "io.cncf.composefs.OciTransfer";

/// `GetInfo` feature token: layers are streamed as `splitdirfdstream`, with
/// the fd layout described on [`GetLayerReply`].
pub const FEATURE_SPLITDIRFDSTREAM_V0: &str = "splitdirfdstream-v0";

/// `GetInfo` feature token: the store is read-only, and its Put methods
/// return [`OciTransferError::ReadOnly`].
pub const FEATURE_READ_ONLY: &str = "read-only";

/// `GetInfo` feature token: the store is a containers-storage root, and
/// `GetLayer` takes [`GetLayerParams::storage`].
pub const FEATURE_SOURCE_CONTAINERS_STORAGE: &str = "source-containers-storage";

// ── Locator for a layer inside containers-storage ────────────────────────────

/// Locator for a layer that lives inside a containers-storage store.
///
/// Both fields are required when routing a `GetLayer` call to the
/// `CstorLayerService`; the repo-side service ignores this field entirely.
#[derive(Debug, Clone, Serialize, Deserialize, zlink::introspect::Type)]
pub struct StorageLocator {
    /// Absolute path to the containers-storage root directory
    /// (e.g. `/var/lib/containers/storage`).
    pub storage_path: String,
    /// The layer ID within that storage root, as returned by
    /// `storage_layer_ids()`.
    pub layer_id: String,
}

/// Parameters for the `GetLayer` method.
///
/// Exactly one of `diff_id` or `storage` must be set:
/// - **Repo service** (`CfsctlService`): reads `diff_id`, errors if `None`.
/// - **Cstor service** (`CstorLayerService`): reads `storage`, errors if `None`.
///
/// Both fields are `Option` for forward-compatibility: new locator kinds can
/// be added in future without breaking old clients.
#[derive(Debug, Clone, Default, Serialize, Deserialize, zlink::introspect::Type)]
pub struct GetLayerParams {
    /// OCI diff-id (`sha256:…`) identifying the layer in a composefs repo.
    pub diff_id: Option<String>,
    /// Location of a specific layer inside a containers-storage store.
    pub storage: Option<StorageLocator>,
    /// Whether the consumer of this layer's bytes can bypass file DAC
    /// permissions (real root or `CAP_DAC_OVERRIDE`).  When `true`, the cstor
    /// service may emit `FileBackedData` chunks even for non-world-readable
    /// files, since the consumer can open them directly.  Defaults to `false`
    /// for backward compatibility.
    #[serde(default)]
    pub consumer_has_cap_dac_override: bool,
}

// ── Reply types ───────────────────────────────────────────────────────────────

/// Reply from `GetInfo`: capability tokens supported by this service.
#[derive(Debug, Clone, Serialize, Deserialize, zlink::introspect::Type)]
pub struct GetInfoReply {
    /// Capability tokens advertised by this service instance: the
    /// `FEATURE_*` constants in this module.
    pub features: Vec<String>,
}

/// Reply from `HasLayer`: whether the layer is present in the store.
#[derive(Debug, Clone, Serialize, Deserialize, zlink::introspect::Type)]
pub struct HasLayerReply {
    /// Whether the layer splitstream for the given diff-id is present.
    pub present: bool,
    /// Hex-encoded fs-verity hash of the layer splitstream, if present.
    pub layer_verity: Option<String>,
}

/// Reply from `GetLayer`: the number of diff-directory slots in the logical FD
/// array.
///
/// `GetLayer` is a **streaming** method (`more`): it yields multiple frames,
/// each carrying a batch of FDs.  The client MUST concatenate the FD batches
/// from all frames (in arrival order) to reconstruct the full logical FD array:
///
/// - `fds[0]` — data pipe read end (carries the `splitdirfdstream` bytes).
/// - `fds[1..=dir_count]` — the dirfds region (`dir_count` slots total).  The
///   real objects-directory fd sits at a sparse, hash-determined index within
///   this region; the remaining (gap) slots hold inert dummy fds that
///   `reconstruct` never dereferences.  The sparse placement is encoded in each
///   `FileBackedData` chunk's `dirfd_index`; the client passes the whole region
///   to `drain_splitdirfdstream` / `reconstruct` unchanged and must NOT assume
///   the dir is at a fixed index.
/// - `fds[dir_count+1..]` — opaque lifetime FDs.  The client MUST hold every
///   one of these open until it has finished reading and processing all dir fds,
///   then close them all to signal completion to the server.  The count of
///   trailing FDs is unspecified by contract; the client keeps open whatever it
///   does not otherwise recognise.  This lifetime-FD convention is part of the
///   `splitdirfdstream-v0` feature.
///
/// Each transport frame carries at most `MAX_FDS_PER_FRAME` (240) fds, safely
/// below the kernel `SCM_MAX_FD` (253) limit.  Every frame carries the same
/// `dir_count`; the client should use the value from any frame (they are all
/// identical).  The stream terminates when a frame with `continues=false` is
/// received.
///
/// A non-streaming (`more=false`) call delivers all fds in a single frame; if
/// the layer requires more than `MAX_FDS_PER_FRAME` fds the call returns
/// `FdLimitExceeded` and the client must retry with `more=true`.
#[derive(Debug, Clone, Serialize, Deserialize, zlink::introspect::Type)]
pub struct GetLayerReply {
    /// Number of diff-directory file descriptors in the full logical FD array
    /// (i.e. `fds[1..=dir_count]` after concatenating all frames' batches).
    pub dir_count: u32,
}

/// Reply from `PutLayer`: the verity hash of the imported layer, whether
/// it was already present, and per-object transfer statistics.
///
/// The object-count fields let the client verify that zero-copy transfer
/// actually took place (e.g. assert `objects_reflinked > 0` in tests) and
/// accumulate aggregate stats for user-facing output.
#[derive(Debug, Clone, Serialize, Deserialize, zlink::introspect::Type)]
pub struct PutLayerReply {
    /// Hex-encoded fs-verity hash of the committed layer splitstream.
    pub layer_verity: String,
    /// `true` if the layer was already present before this call.
    ///
    /// The server always drains the pipe regardless (to avoid wedging
    /// the client's writer), so the stream is re-imported idempotently.
    pub already_present: bool,

    /// Number of objects that were reflinked (FICLONE) into the
    /// destination. Non-zero only when source and dest share a filesystem.
    #[serde(default)]
    pub objects_reflinked: u64,
    /// Number of objects hardlinked into the destination (zerocopy mode).
    #[serde(default)]
    pub objects_hardlinked: u64,
    /// Number of objects byte-copied into the destination.
    #[serde(default)]
    pub objects_copied: u64,
    /// Number of objects already present in the destination (skipped).
    #[serde(default)]
    pub objects_already_present: u64,
}

/// A single (diff_id, layer_verity) pair passed to `FinalizeImage`.
///
/// The client builds this list from the `PutLayer` replies it received while
/// copying layers to the destination repository.  The order must match the
/// manifest layer order.
#[derive(Debug, Clone, Serialize, Deserialize, zlink::introspect::Type)]
pub struct LayerRef {
    /// OCI diff-id of the layer (e.g. `"sha256:abcd..."`).
    pub diff_id: String,
    /// Hex-encoded fs-verity hash of the layer splitstream in the destination
    /// repository, as returned by `PutLayer`.
    pub layer_verity: String,
}

/// Reply from `FinalizeImage`: digest and verity strings for the manifest
/// and config splitstreams that were written (or already existed).
#[derive(Debug, Clone, Serialize, Deserialize, zlink::introspect::Type)]
pub struct FinalizeImageReply {
    /// OCI digest of the manifest (e.g. `"sha256:abcd..."`).
    pub manifest_digest: String,
    /// Hex-encoded fs-verity hash of the manifest splitstream.
    pub manifest_verity: String,
    /// OCI digest of the config (e.g. `"sha256:abcd..."`).
    pub config_digest: String,
    /// Hex-encoded fs-verity hash of the config splitstream.
    pub config_verity: String,
}

// ── OciTransferError ──────────────────────────────────────────────────────────

/// Errors returned by the `io.cncf.composefs.OciTransfer` interface.
#[derive(Debug, zlink::ReplyError, zlink::introspect::ReplyError)]
#[zlink(interface = "io.cncf.composefs.OciTransfer")]
pub enum OciTransferError {
    /// The store could not be found or opened.
    RepoNotFound {
        /// Description of the failure.
        message: String,
    },
    /// The given handle does not refer to an open repository.
    InvalidHandle {
        /// The handle that was not found.
        handle: u64,
    },
    /// An unexpected internal error occurred while servicing the request.
    InternalError {
        /// Description of the failure.
        message: String,
    },
    /// The requested layer (by diff-id) is not present in the store.
    NoSuchLayer {
        /// The diff-id that was not found.
        diff_id: String,
    },
    /// A supplied digest/diff-id string was malformed.
    InvalidDigest {
        /// Human-readable description of the parse failure.
        message: String,
    },
    /// Received layer content did not hash to the declared diff-id.
    ///
    /// The stream was NOT committed; the client must retry with correct data.
    DiffIdMismatch {
        /// The diff_id that was declared by the client.
        expected: String,
        /// The sha256 digest of the data that was actually received.
        actual: String,
    },
    /// The request was malformed (e.g. wrong fd count).
    InvalidRequest {
        /// Human-readable description of what was wrong.
        message: String,
    },
    /// The total fd count exceeds the per-frame cap for a `more=false` call.
    ///
    /// The client must retry with `more=true` (streaming mode).
    FdLimitExceeded {
        /// Total number of fds that would be sent.
        fd_count: u64,
        /// The per-frame cap that was exceeded.
        max_per_frame: u64,
    },
    /// The store is read-only: it serves `GetLayer` but not the Put methods.
    /// Such a store advertises the `read-only` feature token in `GetInfo`.
    ReadOnly,
}

// ── OciTransferProxy trait ────────────────────────────────────────────────────

/// Typed client proxy for the `io.cncf.composefs.OciTransfer` varlink
/// interface.
///
/// Every store serves this interface (the composefs repository service and
/// the containers-storage service), so this proxy works against either.
#[zlink::proxy(interface = "io.cncf.composefs.OciTransfer")]
pub trait OciTransferProxy {
    /// Query capability tokens supported by the service.
    async fn get_info(&mut self) -> zlink::Result<Result<GetInfoReply, OciTransferError>>;

    /// Check whether a layer is present in the store.
    async fn has_layer(
        &mut self,
        handle: u64,
        diff_id: &str,
    ) -> zlink::Result<Result<HasLayerReply, OciTransferError>>;

    /// Stream the layer as a `splitdirfdstream` with full hardened fd-transport
    /// contract (sparse dirfds, keepalive, lifetime fds, multi-frame).
    ///
    /// Drive the returned stream to completion (until `continues=false`),
    /// concatenating each frame's fd batch in order to reconstruct the full
    /// logical FD array `[pipe_read, dirfds.., lifetime_fds..]`.
    /// `params.diff_id` is used by the repo service; `params.storage` is used
    /// by the cstor service.
    #[zlink(more, return_fds)]
    async fn get_layer(
        &mut self,
        handle: u64,
        params: GetLayerParams,
    ) -> zlink::Result<
        impl zlink::futures_util::Stream<
            Item = zlink::Result<(
                Result<GetLayerReply, OciTransferError>,
                Vec<std::os::fd::OwnedFd>,
            )>,
        >,
    >;

    /// Receive a layer as a `splitdirfdstream` from the client and import
    /// it into the server's store with diff_id verification.
    ///
    /// `fds[0]` is the pipe read end; `fds[1..]` are source object dirs.
    async fn put_layer(
        &mut self,
        handle: u64,
        diff_id: &str,
        zerocopy: bool,
        #[zlink(fds)] fds: Vec<std::os::fd::OwnedFd>,
    ) -> zlink::Result<Result<PutLayerReply, OciTransferError>>;

    /// Finalize an OCI image after all layers have been imported.
    ///
    /// `layers` must be in manifest layer order; each entry pairs the layer's
    /// OCI diff-id with the hex verity returned by `PutLayer`.  `name` is the
    /// tag to assign (optional). Idempotent.
    async fn finalize_image(
        &mut self,
        handle: u64,
        manifest_json: &str,
        config_json: &str,
        layers: Vec<LayerRef>,
        name: Option<&str>,
    ) -> zlink::Result<Result<FinalizeImageReply, OciTransferError>>;
}
