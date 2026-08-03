# Contributing to Proof

Proof is in its pre-implementation architecture phase. Contributions should strengthen the product contract, eliminate ambiguity, or advance the next complete milestone.

## Current contribution policy

Issues and documentation proposals are welcome. External code contributions are not accepted until the project selects an open-source license and contribution-signing policy. This prevents contributors and users from operating under unclear rights.

## Before proposing a change

Read:

1. [Product vision](docs/product/vision.md)
2. [Core invariants](docs/architecture/constitution.md)
3. [Architecture overview](docs/architecture/overview.md)
4. [ADR index](docs/decisions/README.md)

Search existing issues and decisions before opening a new proposal.

## Documentation changes

A strong proposal:

- States the user or system outcome.
- Names the invariant or boundary it affects.
- Distinguishes current behavior from proposed behavior.
- Includes consequences and credible alternatives.
- Updates every affected term, example, and cross-reference.
- Adds or updates an ADR for a durable architecture decision.
- Uses requirement words deliberately.

Do not introduce an implementation dependency as though it were a domain requirement.

## Decision process

Changes to ratified architecture use an ADR. Constitutional changes require the additional process in [Core invariants](docs/architecture/constitution.md#changing-the-constitution).

An accepted ADR records why the decision was reasonable at the time. It is not rewritten to hide later changes; a new ADR supersedes it.

## Writing style

- Use **Proof** for the product and `proof` for the executable.
- Capitalize defined domain terms: ChangeSet, Edition, Release, Proof, Principal, Delegation, ContextPack, Environment, Workspace, Object, and Schema.
- Prefer direct, testable statements.
- Keep examples free of real credentials, personal data, and unverified domain names.
- Label illustrative examples that are not compatibility contracts.
- Link to external standards rather than copying them.
- Include an `as of` date for current-version claims.

## Documentation checks

Run both checks before proposing a documentation change:

```bash
npm exec --yes --package=markdownlint-cli2@0.23.2 -- markdownlint-cli2
node scripts/check-doc-links.mjs
```

The Markdown lint version is pinned so local and review results use the same
rules engine. Update the command, validation evidence, and baseline together
when intentionally upgrading it.

## Future implementation checks

Once code exists, changes will be expected to pass:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo nextest run --workspace --all-features
cargo test --doc --workspace
cargo deny check
```

Contributions affecting public contracts will also update conformance fixtures, golden vectors, compatibility notes, and the changelog.

## Security

Do not report vulnerabilities in a public issue. Follow [SECURITY.md](SECURITY.md).
