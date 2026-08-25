# P-0019 execution receipt

[Back to the work item](../../items/P-0019-docs-quickstart.md)

## Result

The quickstart ships at `docs/quickstart.md`: one page takes an operator from
`docker compose -f deploy/compose.yml up -d --build` through Human sign-in,
the governed localized flow (intent → context → edits → validate → submit →
approve → commit → edition → release), Agent enrollment and delegation, and an
independent `proof-verifier verify` reaching exit code 0 (`Complete`). Every
section links the retained suite that asserts that leg, so the page cannot
drift from reality without failing a named test.

## Boundary decision (criterion 2)

The strategy names MCP; no MCP surface exists in this destination. The
quickstart therefore ships the equivalent frozen HTTP path and records the
decision in the item log before implementation. Agent-invocation signing stays
with provisioning per the P-0017 boundary.

## Criterion-4 mapping (criterion 4)

Per-leg guards are the assertion surface: boot (`deployable_artifact.rs`),
login (`session_impl.rs`, `bff_impl.rs`), full two-Humans-one-Agent lifecycle
ending in a `Complete` verification (`north_star_remote_impl.rs`), enrollment
(`enrollment_impl.rs`), verifier exit semantics (`portable_matrix.rs`). A
single wrapper re-run would duplicate a 2,600-line flow for no added
guarantee.

## Commands

| Command | Exit |
| --- | --- |
| `node scripts/check-work-items.mjs` | 0 (19 items) |
| `node scripts/check-doc-links.mjs` | 0 (399 links) |
| `cargo fmt --all --check` / clippy `-D warnings` | 0 |

No push, tag, or public release was performed.
