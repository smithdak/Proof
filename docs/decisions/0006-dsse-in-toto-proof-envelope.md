# ADR-0006: DSSE and in-toto structure for portable Proofs

**Status:** Accepted  
**Date:** 2026-08-03

## Context

Signing a bespoke JSON object directly creates risks around canonicalization, type confusion, key handling, and interoperability. Proof needs a portable envelope that binds typed operational evidence to immutable subjects.

## Decision

Represent a Proof predicate inside an in-toto Statement v1 and authenticate the exact statement payload through a DSSE envelope. Define a versioned Proof Release predicate. Use an Ed25519 initial signature profile behind a key-provider port.

Canonical JSON is used to make payload generation reproducible, but DSSE verification always authenticates the exact enclosed payload bytes.

## Consequences

- Proof can reuse established attestation tooling and concepts.
- Subject digests, predicate type, and payload type are explicit.
- Trust policy and key resolution remain separate from signature validity.
- A Proof-specific predicate Schema and conformance suite are still required.
- Enterprise Sigstore, KMS, HSM, and transparency integrations remain possible.

## Alternatives considered

- **Raw detached signatures:** too fragile and vulnerable to type confusion.
- **JWS:** mature but larger option surface and less aligned with in-toto/SLSA attestations.
- **Custom signed event chain:** does not provide portable subject-bound attestation semantics by itself.

## Verification

- DSSE PAE and signature golden vectors.
- Independent producer and verifier paths.
- Tamper, wrong-type, wrong-subject, untrusted-key, and revoked-key tests.
