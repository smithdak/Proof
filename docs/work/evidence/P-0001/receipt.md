# P-0001 qualification receipt

## Outcome

P-0001 qualified the Release, attestation, Environment, Principal,
Delegation, ContextPack, projection-rebuild, CLI, and MCP candidate as one
local baseline. Independent falsification found no unresolved high-severity
integrity, authorization, migration, or evidence-acceptance defect in the
qualified scope.

The item-work commit is the commit containing this review record. Its SHA is
`pending-completion-record` until the narrow follow-up control-plane commit
records it without self-reference. Nothing was pushed, tagged, released, or
published.

## Revision and checkout

| Field | Exact value |
| --- | --- |
| Checkout | `D:\github\Proof` |
| Branch | `main` |
| Worktrees | `1` |
| Starting HEAD / parent | `3373f3768a4e07a0e5680d88cb7fe4b2c2848f0d` |
| Local `origin/main` ref | `9f69e80cc631385b4f1942b76c584924d756aea9` |
| Remote URL | `https://github.com/smithdak/Proof.git` |
| Live remote verification | Not performed |
| Claim | `codex:/root:p-0001` at `2026-08-17T13:48:31.664Z` |
| Review evidence frozen | `2026-08-17T19:44:53.684Z` |

## Qualified inventory

Immediately before adding this receipt and manifest, the baseline contained
52 non-ignored paths relative to the starting HEAD: 26 tracked modifications
and 26 untracked files. Every path was classified as intended P-0001 scope;
there was no unrelated user work to exclude.

Tracked modifications:

```text
.github/workflows/ci.yml
.markdownlint-cli2.yaml
CHANGELOG.md
CONTRIBUTING.md
Cargo.lock
Cargo.toml
README.md
crates/proof-application/src/lib.rs
crates/proof-cli/Cargo.toml
crates/proof-cli/src/main.rs
crates/proof-cli/tests/architecture.rs
crates/proof-cli/tests/cli.rs
crates/proof-domain/src/lib.rs
crates/proof-local/Cargo.toml
crates/proof-local/src/lib.rs
crates/proof-local/tests/initialize.rs
docs/README.md
docs/architecture/agent-authority.md
docs/architecture/proof-model.md
docs/architecture/testing.md
docs/decisions/0008-mcp-adapter-version.md
docs/decisions/README.md
docs/reference/cli.md
docs/reference/errors.md
docs/reference/standards.md
docs/reference/technology-baseline.md
```

Untracked intended files:

```text
crates/proof-attestation/Cargo.toml
crates/proof-attestation/src/lib.rs
crates/proof-cli/src/authority_cli.rs
crates/proof-cli/src/release_cli.rs
crates/proof-mcp/Cargo.toml
crates/proof-mcp/src/backend.rs
crates/proof-mcp/src/lib.rs
crates/proof-mcp/src/main.rs
crates/proof-mcp/tests/fixtures/initialize-and-list.ndjson
crates/proof-mcp/tests/fixtures/invalid-id.ndjson
crates/proof-mcp/tests/fixtures/modern-discover-list-call.ndjson
crates/proof-mcp/tests/fixtures/modern-missing-meta.ndjson
crates/proof-mcp/tests/fixtures/modern-stateless.ndjson
crates/proof-mcp/tests/fixtures/modern-unsupported-version.ndjson
crates/proof-mcp/tests/fixtures/tool-error.ndjson
crates/proof-mcp/tests/protocol.rs
docs/decisions/0010-dual-era-mcp.md
docs/work/README.md
docs/work/items/P-0001-stabilize-current-baseline.md
docs/work/items/P-0002-ratify-delegated-content-contract.md
docs/work/items/P-0003-ratify-authenticated-actor.md
docs/work/items/P-0004-implement-authorization-kernel.md
docs/work/items/P-0005-deliver-delegated-mutation.md
docs/work/items/P-0006-close-milestone-2.md
docs/work/map.md
scripts/check-work-items.mjs
```

This receipt and `manifest.json` add two evidence paths, so the item-work
commit contains 54 changed or added paths relative to the starting HEAD.

Generated `target/` content was excluded: 20,027 files totaling
8,704,856,843 bytes (approximately 8.11 GiB). No `.proof/` runtime directory
existed. A credential-shaped literal scan found no matches; no credentials,
private keys, runtime databases, or generated proof artifacts are evidence.

## Environment

| Surface | Exact value |
| --- | --- |
| Windows checkout | Windows 11 Professional, NT `10.0.26100.0`, x86-64 |
| Windows Rust | `rustc 1.97.1 (8bab26f4f 2026-07-14)` |
| Windows Cargo | `cargo 1.97.1 (c980f4866 2026-06-30)` |
| Windows Node | `v26.1.0` |
| Windows Git | `2.43.0.windows.1` |
| Linux execution | Ubuntu `24.04.4 LTS` under WSL2 |
| Linux kernel | `5.15.167.4-microsoft-standard-WSL2` |
| Linux Rust | `rustc 1.97.1 (8bab26f4f 2026-07-14)` |
| Linux Cargo | `cargo 1.97.1 (c980f4866 2026-06-30)` |
| Linux Node | `v22.23.1` |
| Linux Git | `2.43.0` |

WSL read the Windows checkout. The final whitespace check therefore used
Git's checkout normalization with `core.autocrlf=true`; it did not rewrite
files merely to silence line-ending advisories.

## Verification results

The final Windows compile boundary passed:

```text
cargo metadata --locked --no-deps --format-version 1
cargo check --locked --workspace --all-targets --all-features
```

This proves compilation only. Proof's local identity adapter intentionally
does not provide live authenticated operation on non-Unix builds, so Windows
runtime support is not claimed.

The final Ubuntu 24.04 qualification sequence passed:

```text
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-targets --all-features
cargo test --locked --doc --workspace --all-features
node scripts/check-doc-links.mjs
node scripts/check-work-items.mjs
git -c safe.directory=/mnt/d/github/Proof -c core.autocrlf=true diff --check
```

Results:

- 197 workspace tests passed: 5 application, 10 attestation, 11 canonical,
  1 architecture, 27 CLI, 12 domain, 114 local integration, 9 MCP unit, and
  8 MCP protocol tests.
- Six crate doc-test targets passed with zero examples and zero failures.
- 103 internal documentation links passed.
- Six work items passed metadata, lifecycle, dependency, map-parity,
  transition, and evidence-contract validation.
- Formatting, strict Clippy, and normalized whitespace passed.
- Markdown lint passed 40 Markdown files with zero issues after this evidence
  was added.

The local integration suite includes exact v1 through v9 migration, atomic
rollback/retry, byte- and digest-stable legacy evidence, operation-effect
commitments, lifecycle chronology, canonical-key aliases, missing commit
coverage, Release proof/outbox recovery, and projection-independent v8/v9
migration plus repair.

## Falsification result and residual boundaries

The strongest falsifier was a circular dependency between migration or rebuild
and the projections they must repair. The final implementation reconstructs
legacy commit and Edition meaning from immutable ChangeSet, Edit, validation,
submission, approval, and commit facts before comparing derived projections.
Normal reads remain projection-strict. Exact v8 and v9 drift-repair tests and
the CLI Release/rebuild end-to-end test pass.

No unresolved high-severity blocker remains. Confidence is high because the
review traced normal reads, delegated reads, writes, migration, dry-run,
repair, Release verification, and delayed idempotent replay separately rather
than relying on the broad green suite alone.

Accepted medium residuals:

- Direct ChangeSet inspection verifies creation and ordered Edit evidence but
  does not reconstruct all lifecycle evidence for its reported status. No
  policy, authorization, mutation, or repair path consumes that diagnostic
  result without independent verification.
- Release proof export recovery is demand-driven. A committed Release, proof,
  pointer, and outbox row survive export failure; replay or Release read repairs
  the artifact. There is no autonomous drainer or pending-export status.

Deliberate trust and product boundaries:

- `proof:operation-effect:v1` commitments bind local operation identity and
  immutable result. They are not signatures and do not extend the portable
  Proof trust boundary to hostile arbitrary SQLite rewrites.
- Signed Release Proofs commit the Release result. The idempotency-key mapping
  remains a local integrity property and is not claimed as signed evidence.
- MCP delegated reads still take caller-declared Agent and Delegation IDs under
  the authenticated local Human boundary. P-0003 owns authenticated workload
  subject binding; delegated mutation remains unavailable.
- Offline verification checks the supplied envelope digest, trusted public key,
  signature, statement type, and subject binding. It does not independently
  verify Workspace policy or fetch missing evidence.
- Linux is the current quality gate, not a release gate. Public distribution,
  SBOM, release provenance publication, Windows runtime identity, provider
  traffic, remote verification, and customer or production claims remain
  unqualified.

## Artifact digests

All values are SHA-256 over the qualified precommit bytes:

```text
aa1cf91cf9561a994ae2757018db33ccf3cc923b02bbbe61d8984e8a04a9748e  Cargo.lock
b345b365fd181326d42190961a175ed417a0c4146feb01010b11d939333854bf  .github/workflows/ci.yml
68b191d9baca785a9de0e4e97ba98b465b951acbd9b326ae47ce68c2e66c08f6  scripts/check-work-items.mjs
e71641320ec105911c8b4712238e7ae25b86c0fe6011f1e958b81b4a57d8b203  crates/proof-domain/src/lib.rs
f407f3c5339e690dcb17d32ee4bceae9e9ee69b24f9c978a7967656b5c4851dd  crates/proof-application/src/lib.rs
b2cef121b6659316a2a73f5b30ddc15cc1b75c4abc4d0a4b80bbce12259b4698  crates/proof-attestation/src/lib.rs
ffc2e757058c60e201cdb7ff643138da74469af80ac0c74b48bea40bd898f407  crates/proof-local/src/lib.rs
27802d35d212f8fd0a339a46dd7083db6837663c06aab9da1f974245d47ed23a  crates/proof-local/tests/initialize.rs
2822c44f5bcc06dec2bcd11b1fda29a8c45c837dec528eae115e442ead56b169  crates/proof-cli/src/main.rs
2b568f971bf4c57b4d01417e054c2f25548c678187bc57e969cd1f3c87349f75  crates/proof-mcp/src/lib.rs
3b6e92dc1ae1b0ae3e2a31c1777b8b518773cb2961f08004aa8a71c52e9ce963  crates/proof-mcp/src/backend.rs
```

## Evidence paths

- `docs/work/evidence/P-0001/receipt.md`
- `docs/work/evidence/P-0001/manifest.json`
