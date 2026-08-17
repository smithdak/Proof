---
id: P-0001
title: Stabilize and qualify the current Release and read-authority baseline
status: review
wave: now
kind: qualification
blocked_by: []
claimed_by: codex:/root:p-0001
claimed_at: 2026-08-17T13:48:31.664Z
base_sha: 3373f3768a4e07a0e5680d88cb7fe4b2c2848f0d
review_gate: none
accepted_by: null
accepted_at: null
---

# Stabilize and qualify the current Release and read-authority baseline

[Back to the work map](../map.md)

## Outcome

The current dirty Release, attestation, Environment, read-authority, CLI, MCP,
and projection-rebuild slice becomes one intentionally scoped baseline
implementation commit plus one narrow control-plane completion commit with a
durable qualification receipt. Repository status and milestone claims then
describe a real baseline rather than session-local candidate state.

## Why now

Every later item depends on types, migrations, Proof formats, and capability
contracts in this slice. Building on uncommitted state would make dependency
boundaries and regression attribution ambiguous.

## Authorized scope

- Audit and retain the current intended changes across the workspace manifest,
  domain/application/local/CLI crates, new `proof-attestation` and `proof-mcp`
  crates, tests, README, changelog, reference docs, and ADR 0010.
- Include `docs/work/` and its discoverability links in the baseline.
- Replace “Linux CI is the release gate” with “Linux CI is the current quality
  gate,” and explicitly record that release eligibility, signed artifacts,
  SBOM, provenance, and public distribution remain unqualified and out of
  scope.
- Fix defects revealed by review or qualification only when they are intrinsic
  to this candidate slice.
- Add the minimal work-item validator: required metadata, unique IDs, valid
  statuses and transitions, existing blockers, acyclic dependencies,
  map/frontmatter parity, and required evidence files for `done` items.
- Create `docs/work/evidence/P-0001/receipt.md` and `manifest.json` with the exact
  environment, revisions, dirty inventory, commands, results, artifact digests,
  and residual limitations.
- Create one intentionally scoped baseline commit, then a narrow control-plane
  completion commit that records the baseline commit SHA in the receipt, this
  item, and the map without self-reference.

## Explicit non-goals

- No delegated mutation, new content semantics, server adapter, or Windows
  support work.
- No push, tag, GitHub release, package publication, or remote mutation.
- No rewriting or squashing earlier commits unless separately authorized.

## Applicable contracts

- [Core invariants](../../architecture/constitution.md)
- [Testing strategy](../../architecture/testing.md)
- [Roadmap](../../product/roadmap.md)
- [Dual-era MCP decision](../../decisions/0010-dual-era-mcp.md)

## Acceptance criteria

- [x] Every dirty and untracked path is classified as intended, generated, or
      unrelated; unrelated user work is preserved and excluded.
- [x] A falsification review finds no unresolved high-severity integrity,
      authorization, migration, or evidence defect in the candidate.
- [x] Exact v1 through v9 fixtures reach v10 with
      `PRAGMA foreign_key_check` clean; pre-existing authoritative facts, Known
      State, and Edition artifacts reproduce byte-for-byte and
      digest-for-digest; no unsupported v10 authority or Release state is
      fabricated; injected migration failures roll back atomically and retry
      successfully.
- [x] The exact Ubuntu 24.04 quality gate passes against the final bytes.
- [x] Windows compilation boundaries are reported without a Windows runtime
      support claim.
- [x] Documentation status, changelog, ADR index, and CLI/MCP contracts agree
      with implemented behavior.
- [x] The work-item validator passes and is part of the Linux quality gate.
- [x] The qualification receipt contains exact commands and results, not a
      summary copied from chat.
- [x] The intended baseline is committed and has no remaining uncommitted
      baseline changes; any pre-existing unrelated user work remains preserved
      and explicitly inventoried; no push occurred.
- [ ] This item is `done`, the commit SHA is recorded, and P-0002/P-0003 are
      reshaped and promoted if their scopes remain valid.

## Required verification

Run the qualification commands under Ubuntu 24.04 with the pinned Rust
toolchain:

```text
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-targets --all-features
cargo test --locked --doc --workspace --all-features
node scripts/check-doc-links.mjs
node scripts/check-work-items.mjs
git diff --check
```

Because this item changes Markdown and its lint configuration, also run:

```text
npm exec --yes --package=markdownlint-cli2@0.23.2 -- markdownlint-cli2
```

On the Windows checkout, also compile every target and record that this is not
live runtime qualification:

```text
cargo check --locked --workspace --all-targets --all-features
```

If WSL reads a Windows CRLF checkout, record that fact and run whitespace
validation with the checkout's Git normalization; do not rewrite unrelated
files merely to make WSL's raw worktree view quiet.

## Evidence contract

The receipt and manifest must bind at least: starting HEAD, baseline
implementation commit, parent/base SHA, local `origin/main` tracking SHA, file
inventory, OS/distribution, Rust/Cargo/Node versions, exact commands and exit
codes, test and link counts, artifact digests, evidence paths, and every
platform or publication boundary. They must not contain credentials or private
key material.

## Completion record

Claimed by `codex:/root:p-0001` at `2026-08-17T13:48:31.664Z` from
`3373f3768a4e07a0e5680d88cb7fe4b2c2848f0d`.

Implementation, independent falsification, and qualification are complete.
This item is in `review` only long enough for the follow-up control-plane
commit to bind the item-work commit SHA and promote its successors.

## Residual risks and next-wave update

- The local SQLite adapter now binds consequential operation identities and
  immutable results with internal effect commitments. These are integrity
  checks inside the local trust domain, not portable signatures and not a
  defense against an actor that can rewrite every database fact and digest.
- Direct ChangeSet inspection verifies creation and ordered Edit evidence but
  does not reconstruct complete submission, approval, and commit evidence for
  its reported lifecycle status. Consequential consumers and repair paths do.
- Release-proof filesystem export is recovered on replay or Release read; no
  autonomous outbox drainer or pending-export status exists yet.
- MCP delegated reads still accept caller-declared Agent and Delegation IDs
  beneath the authenticated local Human boundary. P-0003 owns cryptographic or
  adapter-authenticated Agent subject binding and is the recommended next item.
- Windows runtime identity, public distribution, signed release eligibility,
  SBOM/provenance publication, remote verification, and provider traffic were
  deliberately excluded. No push, tag, release, or publication occurred.
