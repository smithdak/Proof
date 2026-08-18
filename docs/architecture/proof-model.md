# Proof model

**Status:** Ratified architecture; P-0002 content ratified, P-0003 authority closure proposed
**Baseline:** August 3, 2026

> **Proposed P-0003 profile:** The authority additions below are pending
> project-owner acceptance. They do not change existing Release Proof bytes or
> claim that portable authority verification is implemented.
> The normative proposal is the [authenticated actor contract](authenticated-actor.md).
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

## Proposed P-0003 profile — authority commitments

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

This shape is illustrative until P-0003 is accepted and its Schemas and golden
vectors are reviewed. `DelegationV2` supports exactly one Human issuer and one
Agent recipient; it does not encode a chain. `AuthorizationDecisionV2` is a new
contract. Existing `AuthorizationDecisionV1` remains legacy and is not assigned
new semantics.

`requesting_subject_commitment` is a hiding commitment formed with a 32-byte
blind, not a checksum of a raw UID. The actor-context digest uses only that
public commitment and never the raw `os/unix` subject or blind. Audit policy
controls disclosure of the private subject-plus-blind opening. Exact canonical
semantics and vectors live in the
[authenticated actor contract](authenticated-actor.md) and
[`conformance/v1/authority/`](../../conformance/v1/authority/README.md).

P-0004 records canonical `PrincipalBindingV1`, `AuthenticatedCommandV1`,
`AuthenticatedActorContextEvidenceV1`, `DelegationV2`,
`AuthorizationDecisionV2`, and `AuthorityRecordV1` artifacts in
the separately rooted authority log. It does not claim to produce a portable
bundle.

Here `command_digest` is the semantic `CommandInputV1` digest. It is not an
additional signed-payload digest; the authenticated-command envelope digest
already commits the exact signed payload.

P-0006 defines the future `AuthorityEvidenceBundleV1`. That bundle must include
the transitive authority records needed to verify the recorded action at its
causal position, be authenticated by an authority root distinct from the
Release-signing root, and be consumable with explicit caller-supplied trust
policy. Producer-exported identifiers, digests, or self-described keys establish
consistency only, not trust.
The bundle carries or resolves the strict raw-UID-free
`AuthenticatedActorContextEvidenceV1` digest preimage used by P-0004.
The authority hash chain detects mutation, deletion, or reordering only relative
to a trusted later head. A supplied signed prefix cannot establish that no valid
older prefix or fork was restored from the same mutable store. Any P-0006 claim
of rollback resistance or complete latest history therefore requires an
independently retained expected authority head or a later checkpoint committing
it.
Loss of the predecessor authority private key before a dual-signed transition
makes v1 continuity unrecoverable. Existing history remains verifiable, but no
current-profile export may claim recovered continuity. A new authority epoch or
re-anchor requires a future ADR and Schema plus explicit caller trust.

## Ratified P-0002 profile — localized-content causality

The next localized-content Release predicate version commits enough evidence
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

The portable authority closure proposed by P-0003 remains separate. P-0005
binds its `AuthorizationDecisionV2` to the content operation and exact resource
intent. P-0006 then verifies both closures under explicit caller-supplied trust
roots and reports content integrity, validation, authority, Release signature,
and evidence completeness as separate verdict dimensions.

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

**Proposed P-0003 profile:** Full authority verification additionally validates
the future `AuthorityEvidenceBundleV1`, its authority-root authentication, the
subject commitment and active binding at the recorded position, the single-use
`AuthenticatedCommandV1`, direct `DelegationV2` issue and revocation records,
and `AuthorizationDecisionV2`. Cryptographic validity, Release-subject
validity, authority validity, policy validity, and evidence completeness are
separate verdict dimensions.
Without an independently pinned expected authority head, the verifier may
report internal validity of the supplied authority prefix but not latest-history
completeness or rollback resistance.

Verification does not fetch arbitrary URLs automatically. External resolution requires an allowlisted resolver and explicit network policy.

## Redaction and disclosure

Proof payloads minimize sensitive data. They contain identifiers and digests rather than full ContextPacks, content bodies, prompts, or credentials.

When evidence is restricted:

- The public Proof retains a digest commitment.
- Authorized systems can resolve the protected artifact separately.
- Redaction creates a new disclosure artifact; it does not mutate the original signed envelope.
- Verification distinguishes “cryptographically valid” from “all required evidence disclosed.”

## Portability

Proof artifacts are independent of a running CMS instance. A standalone `proof verify` implementation must be able to validate an envelope and supplied subjects offline, provided the trust roots and required evidence are available.

Under the **Proposed P-0003 profile**, raw provider subjects, private keys, and
credential handles are never portable evidence. The public
`requesting_subject_commitment` is portable; its private raw-subject and
32-byte-blind opening is disclosed only under audit policy. If policy withholds
a required opening or component, offline verification returns an explicit
incomplete authority verdict rather than treating a matching digest as proof of
authorization.
