#![forbid(unsafe_code)]
#![allow(
    dead_code,
    unused_variables,
    unused_imports,
    clippy::doc_markdown,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value
)]

//! Transactional outbox worker and private preview delivery boundary skeleton
//! for Proof (work item P-0012).
//!
//! This crate is the fourth dependency-ordered successor of the accepted
//! [single-Workspace collaboration-server contract]: the ordered
//! generation-scoped outbox worker with bounded leases and counted attempts,
//! at-least-once delivery without an exactly-once claim, dead-letter and poison
//! management, and the private content-addressed preview materialization whose
//! ready manifest is written last and whose alias advances monotonically by
//! Release sequence.
//!
//! The public surface is stable: every type and function declared here is the
//! contract shape the delivery operations and worker tests exercise. It depends
//! only on [`proof_remote`] (P-0009
//! registries/identity/authority/oracle), [`proof_pg`] (P-0010 persistence),
//! [`proof_domain`], [`proof_canonical`], and [`proof_attestation`]; never the
//! reverse.
//!
//! [single-Workspace collaboration-server contract]: https://proof.dev/docs/architecture/collaboration-server
//! [`proof_remote`]: ../proof_remote/index.html
//! [`proof_pg`]: ../proof_pg/index.html
//! [`proof_domain`]: ../proof_domain/index.html
//! [`proof_canonical`]: ../proof_canonical/index.html
//! [`proof_attestation`]: ../proof_attestation/index.html

pub mod preview;
pub mod worker;

/// Re-exported shared domain vocabulary (Workspace/Principal identities,
/// digests, timestamps) so delivery consumers need only one dependency edge.
pub use proof_domain;

/// Re-exported P-0010 PostgreSQL parity foundation so the worker drives the
/// same durable authority store as the server boundary.
pub use proof_pg;

/// Re-exported P-0009 remote registries, identity, authority, and oracle types
/// that the delivery boundary projects and manages.
pub use proof_remote;

use thiserror::Error;

/// Closed error taxonomy for the outbox worker and private preview delivery
/// boundary (contract §"Transactional outbox and delivery", §"Preview
/// delivery").
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DeliveryError {
    /// An ordered claim could not be taken or committed.
    #[error("worker claim failed: {0}")]
    Claim(String),
    /// A compare-and-set acknowledgement failed or was rejected.
    #[error("worker acknowledgement failed: {0}")]
    Acknowledge(String),
    /// A random lease token could not be generated or decoded.
    #[error("lease token failed: {0}")]
    Lease(String),
    /// The 30-second attempt deadline was exhausted.
    #[error("delivery deadline exceeded: {0}")]
    Deadline(String),
    /// A dead-letter transition could not be committed.
    #[error("delivery dead-letter failed: {0}")]
    DeadLetter(String),
    /// Private preview materialization or alias resolution failed.
    #[error("preview failed: {0}")]
    Preview(String),
    /// A digest, length, or ready-boundary integrity check failed closed.
    #[error("delivery integrity failed: {0}")]
    Integrity(String),
    /// The PostgreSQL authority store failed.
    #[error("storage failed: {0}")]
    Storage(#[from] proof_pg::PgError),
}
