# Proof model

**Status:** Ratified architecture; predicate Schema pending implementation  
**Baseline:** August 3, 2026

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

## Canonical artifacts

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
proof:validation-results:v1
```

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
