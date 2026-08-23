//! Projection rebuild and atomic generation swap (contract §"Migration and
//! projection rebuild").

use postgres::Client;
use proof_domain::ContentDigest;

use crate::{PgError, transaction::WorkspaceHeadSnapshot};

/// One verified projection generation (contract §"Migration and projection
/// rebuild").
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionGeneration {
    /// Monotonic generation number.
    pub generation: u64,
    /// Exact heads captured at rebuild time.
    pub heads: WorkspaceHeadSnapshot,
    /// Per-kind derived-row counts.
    pub counts: ProjectionCounts,
    /// Domain-separated digest of the complete derived state.
    pub state_digest: ContentDigest,
}

/// Per-kind derived-row counts captured by a rebuild (contract §"Migration and
/// projection rebuild").
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProjectionCounts {
    /// Derived Object count.
    pub objects: u64,
    /// Derived exact-locale rendition count.
    pub renditions: u64,
    /// Derived Schema count.
    pub schemas: u64,
    /// Derived Release count.
    pub releases: u64,
}

/// Rebuilds every derived row into a new generation under the Workspace head
/// lock.
///
/// # Errors
///
/// Returns [`PgError::Projection`] on chain verification or rebuild failure.
pub fn rebuild_into_new_generation(client: &mut Client) -> Result<ProjectionGeneration, PgError> {
    todo!()
}

/// Atomically swaps the single active-generation pointer after comparing
/// identities, counts, foreign keys, versions, sequences, and state digest.
///
/// # Errors
///
/// Returns [`PgError::Projection`] when any comparison fails or the swap
/// cannot commit.
pub fn atomic_swap_active_generation(
    client: &mut Client,
    generation: &ProjectionGeneration,
) -> Result<(), PgError> {
    todo!()
}

/// A read-side pin that keeps one retired generation readable (contract
/// §"Migration and projection rebuild").
///
/// A read transaction pins exactly one projection generation for its lifetime.
/// A retired generation remains readable until no transaction still holds that
/// pin; only then may a separately qualified garbage collector remove it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetiredGenerationPin {
    /// The pinned generation number.
    pub generation: u64,
}
