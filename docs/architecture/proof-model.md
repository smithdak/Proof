# Proof model

**Status:** Ratified architecture; bounded local Linux content and authority closure complete through P-0006
**Baseline:** August 23, 2026

> **Implemented P-0004/P-0005/P-0006 profile:** The authority additions below are
> normative architecture; local authority records and localized consequence
> cross-links, portable `AuthorityEvidenceBundleV1`, storage v14 presentation
> evidence, and independent verifier are implemented. They do not change
> existing Release Proof bytes.
> The normative contract is the [authenticated actor contract](authenticated-actor.md).
>
> **Ratified P-0002 profile:** The localized-content and exact-delta additions
> below are project-owner accepted. They require versioned Release and
> predicate artifacts and do not change existing Release Proof bytes. The
> normative proposal is the
> [delegated localized-content contract](delegated-content.md).

## Purpose

A Proof is portable, signed operational evidence for a consequential state transition. The first required artifact is a Release Proof.

A Release Proof allows a verifier to answer:

- Which immutable Edition was released?
- To which Environment?
- Which ChangeSets and base state produced it?
- Which Principal acted under what Delegation?
- Which policies, validators, and approvals applied?
- Which canonicalization and digest algorithms were used?
- Does the signature chain to a trusted key?
- Do all referenced subject digests still match?

## What a Proof does not establish

A Proof does not establish the factual truth, quality, legality, or desirability of content unless a named validator or approval process specifically attests to that property. It establishes operational evidence and binds that evidence to immutable subjects.

## Artifact layers

Proof adopts established attestation concepts rather than inventing a raw signature format.

```text
DSSE envelope
└── in-toto Statement v1
    ├── subject[]: immutable Edition and Release artifacts
    ├── predicateType: Proof Release predicate URI
    └── predicate: Proof-specific operational evidence
```

### Envelope

DSSE authenticates the payload bytes and payload type using pre-authentication encoding. It prevents type-confusion problems associated with signing arbitrary bytes directly.

### Statement

The in-toto Statement binds a typed predicate to immutable subjects identified by digest. Proof uses `_type: https://in-toto.io/Statement/v1`.

### Predicate

The versioned Proof predicate carries CMS-specific evidence. The initial pre-domain URI is:

```text
urn:proof:attestation:release:v1
```

The final controlled HTTPS URI is ratified before the first public compatibility release. The URN prevents an unowned domain from becoming a trust dependency during pre-implementation.

## Proposed Release predicate

```json
{
  "release": {
    "release_id": "019c...",
    "edition_id": "019b...",
    "environment_id": "preview",
    "previous_release_id": "019a...",
    "released_at": "2026-08-03T15:04:05Z"
  },
  "origin": {
    "workspace_id": "0198...",
    "base_state_digest": "blake3:...",
    "changeset_digests": ["blake3:..."]
  },
  "authority": {
    "principal_id": "0197...",
    "principal_type": "agent",
    "delegation_chain": ["0196..."],
    "authorization_decision_digest": "blake3:..."
  },
  "context": {
    "context_pack_digest": "blake3:..."
  },
  "validation": {
    "profile": "production-release/v1",
    "policy_bundle_digest": "blake3:...",
    "results_digest": "blake3:...",
    "approvals": [
      {
        "principal_id": "0195...",
        "changeset_digest": "blake3:..."
      }
    ]
  },
  "implementation": {
    "proof_version": "0.1.0",
    "canonicalization": "jcs-rfc8785",
    "digest_algorithm": "blake3-256",
    "predicate_version": "1"
  }
}
```

This example is illustrative. The released Schema and golden vectors become the contract.

## Ratified P-0003 profile — authority commitments

The next versioned Release predicate will distinguish the requesting Human from
the authenticated operating Agent and commit the authority evidence needed to
verify that distinction. Its authority portion carries or references:

```json
{
  "requesting_principal_id": "019a...",
  "operating_principal_id": "019b...",
  "requesting_subject_commitment": "blake3:...",
  "actor_context_digest": "blake3:...",
  "principal_binding": {
    "binding_id": "019c...",
    "authority_sequence": 12,
    "record_digest": "blake3:...",
    "supersedes_binding_id": null,
    "credential_key_id": "ed25519:..."
  },
  "delegation": {
    "delegation_id": "019d...",
    "delegation_version": "proof.dev/delegation/v2",
    "delegation_digest": "blake3:...",
    "revocation_position": 41
  },
  "command_digest": "blake3:...",
  "authenticated_command_envelope_digest": "blake3:...",
  "authorization_decision": {
    "version": "proof.dev/authorization-decision/v2",
    "digest": "blake3:..."
  },
  "authority_log": {
    "position": 42,
    "root_digest": "blake3:...",
    "authority_key_id": "ed25519:..."
  }
}
```

This presentation shape is illustrative; P-0004 implements the exact ratified
Schemas, canonical authority records, and golden vectors. `DelegationV2`
supports exactly one Human issuer and one Agent recipient; it does not encode a
chain. Existing `AuthorizationDecisionV1` remains legacy and is not assigned new
semantics.

The bounded P-0005 implementation does not rewrite P-0007 Release or Release
Proof identity. `ReleaseV2.principal_id` remains the requesting Human, and its
`authorization_decision_digest` remains the P-0007 Human release-policy
decision. Agent identity, authority decision, result commitment, and raw P-0007
effect are cross-linked in the retained localized consequence. P-0006 carries
and independently verifies both closures; the illustrative embedded Agent
authority block above is not a claim about current Release Proof bytes.

`requesting_subject_commitment` is a hiding commitment formed with a 32-byte
blind, not a checksum of a raw UID. The actor-context digest uses only that
public commitment and never the raw `os/unix` subject or blind. Audit policy
controls disclosure of the private subject-plus-blind opening. Exact canonical
semantics and vectors live in the
[authenticated actor contract](authenticated-actor.md) and
[`conformance/v1/authority/`](../../conformance/v1/authority/README.md).

P-0004/P-0005 record canonical `PrincipalBindingV1`, `AuthenticatedCommandV1`,
`AuthenticatedActorContextEvidenceV1`, `DelegationV2`,
`AuthorizationDecisionV2`, and `AuthorityRecordV1` artifacts in
the separately rooted authority log. A localized Allow also signs its exact
result contract, result kind and digest, and application-consequence digest;
storage v14 preserves the localized consequence and Workspace-global
application-key record and additionally persists the canonical command input
and signed presentation envelope. These local rows alone do not claim to be a
portable bundle.

Here `command_digest` is the semantic `CommandInputV1` digest. It is not an
additional signed-payload digest; the authenticated-command envelope digest
already commits the exact signed payload.

P-0006 implements `AuthorityEvidenceBundleV1`. The bundle carries or resolves
the transitive authority records needed to verify the recorded action at its
causal position, using explicit external commitments for unavailable bytes. It
is authenticated by an authority root distinct from the
Release-signing root, and is consumed with explicit caller-supplied trust
policy. Producer-exported identifiers, digests, or self-described keys
establish consistency only, not trust.
The bundle carries or resolves the strict raw-UID-free
`AuthenticatedActorContextEvidenceV1` digest preimage used by P-0004.
The authority hash chain detects mutation, deletion, or reordering only relative
to a trusted later head. A supplied signed prefix cannot establish that no valid
older prefix or fork was restored from the same mutable store. P-0006 therefore
accepts an independently retained expected authority head or later committing
checkpoint when the caller requires rollback or truncation detection. That pin
does not prove that the supplied Release is globally latest or the true
immediate same-Environment Release.
Loss of the predecessor authority private key before a dual-signed transition
makes v1 continuity unrecoverable. Existing history remains verifiable, but no
current-profile export may claim recovered continuity. A new authority epoch or
re-anchor requires a future ADR and Schema plus explicit caller trust.

## Ratified P-0002 profile — localized-content causality

The localized-content Release predicate version commits enough evidence
to distinguish an authorized target set from the exact state actually released.
It carries or references:

- the `ContentResourceIntentV1` digest, exact ContextPack digest, and complete
  sorted `(object_id, schema_id, locale)` target set;
- the unchanged baseline Environment Release, Edition, Known State, and
  authoritative sequence;
- the complete `ChangeSetV2` `proposal_digest`, including superseded invalid
  attempts and repair-to-result edges, its effective-leaf digest, the complete
  predecessor-digest-linked `ValidationResultsV2` attempt chain, and resulting
  noncircular `sealed_changeset_digest`;
- each resulting `ObjectLocaleRevisionV1` digest and its exact source
  `ObjectRevisionV1` and Schema digests;
- the one-ChangeSet `EditionV2` digest and an exact base-to-target delta
  commitment; and
- the `ReleaseV2` transition that compares and advances the expected
  Environment pointer atomically.

`EditionV2` creation is valid only for the exact state produced by that one
ChangeSet and before any later authoritative commit. `ReleaseV2` is valid only
when the Environment still points to the named baseline and the Edition delta
contains no source Object, Schema, relationship, lifecycle, unrelated Object,
unrelated locale, or unrelated ChangeSet mutation. Merely proving that every
changed resource belongs to the broad Delegation dimension product is
insufficient; the delta MUST equal the exact authorized ChangeSet result.

The base Release, Edition, and Known State references carry exact artifact API
versions. The first v2 predicate proves the explicit v1-to-v2 state bridge and
an in-memory empty-rendition comparison without changing v1 bytes. Later
predicates prove v2 predecessors. A rollback predicate may target an exact
historical `EditionV1`, but it does not claim that Workspace authoring state
reverted.

The content predicate does not claim that translated text is factually,
legally, culturally, or editorially correct. It identifies the exact validator
and policy results that made the ChangeSet acceptable. A legal-quality claim is
supported only by a named validator or approval whose artifact digest is in the
closure.

The portable authority closure defined by P-0003 remains separately rooted.
P-0005 binds `AuthorizationDecisionV2` to the content operation, exact resource intent,
application result, and effect closure. P-0006 verifies both closures under
explicit caller-supplied trust roots and reports content integrity, validation,
authority, Release signature, and evidence completeness as separate verdict
dimensions.

Existing `ReleaseV1`, its predicate, `EditionV1`, `ChangeSetV1`,
`ObjectRevisionV1`, and their digest contexts are never reserialized or
reinterpreted. A new Release records the exact Edition artifact version, so an
explicit rollback may select a historical `EditionV1` while preserving the
historical `ReleaseV1`. Migration MUST NOT synthesize localized renditions or
infer source locales from legacy Objects.

## Canonical artifacts

All domain-separation contexts are normative in the
[`conformance/v1/authority/` digest registry](../../conformance/v1/authority/README.md),
including `proof:policy-bundle:v1` for the canonical policy bundle and
`proof:authority-record-envelope:v1` for authority/root-transition DSSE
envelopes. Implementations consume that registry and its vectors; they do not
reverse-engineer contexts from example digests.

Proof distinguishes three byte representations:

1. **Human JSON:** formatted for inspection and not hashed directly.
2. **Canonical JSON:** RFC 8785 JCS bytes used to reproduce domain-artifact digests.
3. **DSSE payload bytes:** the exact in-toto Statement bytes authenticated by the envelope.

The implementation SHOULD use canonical JSON for the Statement payload so equivalent generation produces identical bytes. DSSE verification still authenticates the exact payload and does not depend on a verifier reserializing JSON.

## Digests

Internal content-addressed identifiers use BLAKE3-256 with explicit domain separation. Digest strings include their algorithm:

```text
blake3:2f3c...
```

Different artifact types use distinct derive-key contexts, for example:

```text
proof:edition:v1
proof:changeset:v1
proof:context-pack:v1
proof:operation-effect:v1
proof:validation-results:v1
```

`OperationEffectV1` is an internal reconstruction commitment over an
operation's normalized request, canonical identity, and immutable result. It
detects incomplete or inconsistent local evidence; it is not a signature and
does not extend the portable Proof trust boundary beyond signed envelopes.

Proof subjects exported through ecosystems that require SHA-256 MAY include both BLAKE3 and SHA-256 digests. Algorithms are never inferred from digest length.

## Signatures and keys

The first signature profile uses Ed25519 with explicit key identifiers. The key provider is a port supporting local development keys and enterprise KMS or HSM-backed implementations.

Requirements:

- Private keys never enter the domain model, logs, or Proof payload.
- Every signature identifies its algorithm and key ID.
- Verification resolves the key's validity and revocation state at signing time.
- Key rotation does not invalidate historical Proofs.
- Trust policy is external to the signature: a valid signature from an untrusted key is not an accepted Proof.
- Multi-signature envelopes MAY represent threshold or independent approvals later.

## Verification algorithm

A verifier:

1. Parses the DSSE envelope under strict size and Schema limits.
2. Confirms the expected payload type.
3. Verifies pre-authentication encoding and signature.
4. Resolves the key and applicable trust policy.
5. Parses and validates the in-toto Statement.
6. Confirms the expected Proof predicate type and version.
7. Recomputes available subject digests from artifact bytes.
8. Validates required evidence references and authority policy.
9. Checks revocation and time-sensitive policy using recorded evidence.
10. Returns a structured verification report.

**Implemented P-0006 profile:** Full authority verification validates
`AuthorityEvidenceBundleV1`, its authority-root authentication, the
subject commitment and active binding at the recorded position, the single-use
`AuthenticatedCommandV1`, direct `DelegationV2` issue and revocation records,
and `AuthorizationDecisionV2`. Cryptographic validity, Release-subject
validity, authority validity, policy validity, and evidence completeness are
separate verdict dimensions.
Without an independently pinned expected authority head, the verifier may
report internal validity of the supplied authority prefix but not prefix
freshness or rollback resistance. With a matching pin, it still does not claim
globally latest Release history.

Historical direct-Human v2 evidence without the delegated Agent consequence
companion is conservatively Incomplete. Unavailable pre-v14 presentations and
some malformed idempotency reconstructions may also report Incomplete;
exhaustive Invalid classification is not claimed.

Verification does not fetch arbitrary URLs automatically. External resolution requires an allowlisted resolver and explicit network policy.

## Proposed P-0008 remote evidence profile

`RemoteEvidenceBundleV2` prospectively describes an exact uncompressed logical
member map, not an archive or compressed carrier. Its manifest has exactly six
P8 roots: one authority-neutral `RemoteReleaseArtifactClosureV1`, one canonical
`RemoteAuthorityRecordSetV1`, public actor evidence, a remote authentication
event, `CommandInputV1`, and the Agent authenticated-command DSSE envelope. The
Release closure enumerates each nested accepted artifact. The verifier decodes
and verifies `AuthenticatedCommandV1` from the envelope payload; no standalone
authenticated-command payload member exists. An included root is in the
producer map, while an external-required authority, actor, or authentication
root arrives only through exact caller-controlled descriptor and byte input.
Outbox delivery and artifact-catalog verification are not requested by this
selected claim.

Existing `AuthorityEvidenceBundleV1` bytes, outcomes, and verifier remain
unchanged for historical local evidence. They are not relabeled, projected, or
executed as the authority entrypoint for a remote OIDC attempt and are not a P8
root.
`RemoteEvidenceClosureBindingsV1` instead commits the exact Release-artifact
closure, remote record set/head, typed attempt companions, target remote
decision/consequence, and Workspace/Environment/Release/Proof/result/effect
cross-links. A future verifier validates all three inputs independently before
enforcing those links. The P-0008 fixture is explicitly an unmaterialized
successor contract: it retains neither a bundle nor an observed verifier
report, and its Complete/Incomplete/Invalid scenarios are conditional
requirements only.

Outer export and snapshot labels are not authenticated by the selected
historical release chain. Until a non-circular detached post-build receipt is
versioned and retained, `export_id`, snapshot heads, manifest readiness, and
capture/build/ready state remain producer metadata outside a Complete verified
claim. Matching repetitions are checked for contradiction, but the profile
makes no authenticated current-at-snapshot, immediate-predecessor, or globally
latest claim. A required remote authority checkpoint must exactly equal the
included head; a larger sequence without every intervening verified record is
not an ancestry proof.

The first-profile `untrusted_hints` arrays are exactly empty, with
`trusted:false` and `auto_fetch:false`. A clean verifier instead receives one
exact caller-controlled `VerificationTrustPolicyV2`, including usable
role-separated authority, Release, and historical Agent key bytes, its initial
remote head, accepted policy/registry selectors and closed offline resolver,
plus optional typed checkpoints, required subject openings, and any external
artifact bytes. It performs no producer database or network fetch. With no
authenticated base-state snapshot, every authority fact consumed for the
selected attempt must occur in the supplied suffix after that initial head.

`RemoteVerificationReportV2` is the general closed observed runtime report for
Complete, missing-material Incomplete, and integrity or semantic Invalid
outcomes. The `conformanceReport` subtype narrows it to the exact three P-0008
qualification scenarios. The retained fixture scenarios are unobserved
normative requirements, not runtime reports, and the retained decoded decision
and `RemoteApplicationConsequenceV1` values are signable candidate payloads
rather than a signed pair. The normative proposal is the
[collaboration-server contract](collaboration-server.md).

## Redaction and disclosure

Proof payloads minimize sensitive data. They contain identifiers and digests rather than full ContextPacks, content bodies, prompts, or credentials.

When evidence is restricted:

- The public Proof retains a digest commitment.
- Authorized systems can resolve the protected artifact separately.
- Redaction creates a new disclosure artifact; it does not mutate the original signed envelope.
- Verification distinguishes “cryptographically valid” from “all required evidence disclosed.”

## Portability

Proof artifacts are independent of a running CMS instance. The `proof verify`
command validates one envelope and its supplied subjects offline. The separate
`proof-verifier` validates the transitive portable Release, content, approval,
policy, and authority closure from `AuthorityEvidenceBundleV1`, caller trust,
and an optional authority-head checkpoint without the producing Workspace or
private keys.

Under the **Ratified P-0003 profile**, raw provider subjects, private keys, and
credential handles are never portable evidence. The public
`requesting_subject_commitment` is portable; its private raw-subject and
32-byte-blind opening is disclosed only under audit policy. If policy withholds
a required opening or component, offline verification returns an explicit
incomplete authority verdict rather than treating a matching digest as proof of
authorization.
