//! Deterministic local/server semantic oracle over the SQLite-backed local
//! application path.
//!
//! The oracle replays the shared application operations (the 14 Agent rows and
//! the shared Human rows) against `proof-local` and produces byte-identical,
//! replayable [`OracleTraceV1`] records. It also carries deterministic
//! [`IdentityFixtureV1`] test identity data with no live provider or network
//! (contract §"Conformance and falsification plan",
//! §"PostgreSQL authoritative unit of work").

use proof_domain::ContentDigest;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    AuthorityHeadV1, RemoteError, RemoteOperationV1,
    identity::{
        AuthenticatedActorContextV2, OidcIssuerConfigurationV1, OidcPrincipalBindingPrivateV1,
        OidcPrincipalBindingV1,
    },
};

/// A stable application problem projected into a trace.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StableProblem {
    /// Stable machine-readable problem code.
    pub code: String,
    /// Exact operation/version that produced the problem.
    pub operation: RemoteOperationV1,
}

/// The typed outcome of one oracle evaluation.
#[derive(Clone, Debug, PartialEq)]
pub enum OracleOutcome {
    /// A successful typed application result.
    TypedResult(Value),
    /// A stable application problem.
    StableProblem(StableProblem),
}

/// The consequence bound to one oracle evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OracleConsequence {
    /// Exact domain-separated consequence digest.
    ConsequenceDigest(ContentDigest),
    /// No signed consequence was produced.
    Null,
}

/// One deterministic, replayable oracle trace.
#[derive(Clone, Debug, PartialEq)]
pub struct OracleTraceV1 {
    /// `proof:remote-normalized-operation-input:v1` digest of the exact input.
    pub normalized_input_digest: ContentDigest,
    /// Exact authority head evaluated by the trace.
    pub evaluated_authority_head: AuthorityHeadV1,
    /// Typed application outcome.
    pub outcome: OracleOutcome,
    /// Consequence digest or null.
    pub consequence: OracleConsequence,
}

/// Deterministic test identity data: an issuer configuration, an enrollment
/// challenge, and binding fixtures. This fixture never performs network I/O or
/// contacts a live OIDC provider.
#[derive(Clone, Debug, PartialEq)]
pub struct IdentityFixtureV1 {
    /// Pinned public issuer configuration.
    pub issuer_configuration: OidcIssuerConfigurationV1,
    /// One-use enrollment challenge (state, nonce, PKCE verifier).
    pub enrollment_challenge: OidcEnrollmentChallengeV1,
    /// Public OIDC Principal bindings.
    pub oidc_bindings: Vec<OidcPrincipalBindingV1>,
    /// Protected OIDC Principal binding lookups.
    pub oidc_bindings_private: Vec<OidcPrincipalBindingPrivateV1>,
}

/// One deterministic OIDC enrollment challenge. This is local fixture data
/// only; it never performs network I/O.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OidcEnrollmentChallengeV1 {
    /// Exact fixture api version.
    pub api_version: String,
    /// One-use `state` value.
    pub state: String,
    /// One-use OIDC `nonce` value.
    pub nonce: String,
    /// PKCE `S256` code verifier.
    pub code_verifier: String,
}

/// Deterministic trace runner over the SQLite-backed local application path.
///
/// Repeated execution of the same trace inputs produces byte-identical
/// [`OracleTraceV1`] records; mutated inputs land in the contracted consequence
/// class without executing an HTTP or PostgreSQL adapter.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RemoteSemanticOracle;

impl RemoteSemanticOracle {
    /// Constructs the deterministic oracle.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Evaluates one normalized operation input plus actor context against the
    /// supplied local Workspace and returns a deterministic trace.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteError::Oracle`] when the operation cannot be dispatched
    /// or evaluated deterministically.
    pub fn run(
        &self,
        workspace: &proof_local::LocalWorkspace,
        normalized_input: &Value,
        actor_context: &AuthenticatedActorContextV2,
    ) -> Result<OracleTraceV1, RemoteError> {
        todo!()
    }
}
