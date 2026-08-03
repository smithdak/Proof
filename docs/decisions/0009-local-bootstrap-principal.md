# ADR-0009: Bind the local bootstrap Principal to the operating-system user

**Status:** Accepted  
**Date:** 2026-08-03

## Context

Proof requires every consequential action to identify an authenticated
Principal. The local proof loop must satisfy that invariant before remote
identity, Delegation, and policy administration arrive in later milestones.
Using an anonymous local user, a shared “system” identity, or a caller-supplied
UUID would record identity without authenticating it.

## Decision

`proof init` creates one UUIDv7 Human Principal and binds it to the
authenticated operating-system user running the command. On Unix, the initial
identity-provider contract is `os/unix` with a subject of `uid:<effective-uid>`.

The binding is stored only in private local state, not in `proof.toml`. Every
operation that opens the local Workspace resolves the current operating-system
identity and fails authentication if it does not match an enabled Principal
binding. The bootstrap Principal is scoped to that Workspace. Copying private
state to another operating-system account does not silently rebind authority.

Server mode uses OIDC or workload identity and does not treat a local Unix UID
as a portable enterprise identity. Additional local platforms require their own
versioned identity-provider subject format before local mode is supported on
those platforms.

## Consequences

- The first local operation has a distinct authenticated Principal.
- Principal identifiers remain globally unique while provider subjects remain
  adapter-specific.
- Private state and operating-system access controls are part of the local
  authentication boundary.
- Moving a Workspace between operating-system accounts requires an explicit,
  auditable recovery or transfer operation in a later slice.
- The first implementation supports this identity adapter on Unix platforms.

## Alternatives considered

- **Anonymous or shared local Principal:** rejected because it violates the
  identity invariant and weakens evidence.
- **Caller-supplied Principal UUID:** rejected because an identifier is not
  authentication.
- **Commit the operating-system user to `proof.toml`:** rejected because local
  identity bindings are private and not portable repository configuration.
- **Wait for OIDC:** rejected because it would prevent the offline local MVP.

## Verification

- Initialization persists one Human Principal and its provider binding.
- Structured operation metadata identifies that Principal.
- A different operating-system subject cannot inspect or mutate the Workspace.
- Configuration exports do not contain the provider subject.
