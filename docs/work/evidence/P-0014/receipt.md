# P-0014 execution receipt

[Back to the work item](../../items/P-0014-route-complete-enrollment.md)

## Result

Route-complete enrollment is implemented and qualified. Both
`agent-binding.issue/v1` and `oidc-binding.issue/v1` execute end to end over
the P-0010 unit of work and issue usable credentials; neither call path can
return `proof.dependency.unavailable`. Issued Agent credentials authenticate
through the existing dual Human-session-plus-presentation boundary and
complete an authenticated governed read (`workspace.status/v1`) in a retained
test; issued OIDC pairs resolve their exact subjects at login through the
existing binding-resolution path.

## Qualified candidate

- Item-work commit: `857734fc443e6500534971e096d0c53fdaf65a2e`
- Base SHA (claim): `15851fc945c11ff77e00d98d2973f0275e70731b`
- Candidate parent (map sync): `f300b509dae7c979d14004b173c7221e64363cfa`
- Shaping decision bound by the Destination 4 ratification commit
  `68ac737e4950fd6b6c8f177024e185b54ae88a1b`.

## Commands and exit codes

| Command | Exit |
| --- | --- |
| `cargo check -p proof-server` | 0 |
| `cargo fmt --all --check` | 0 |
| `cargo clippy -p proof-server --all-targets --all-features -- -D warnings` | 0 |
| `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings` (lib target set) | 0 |
| `cargo test -p proof-server --test enrollment_impl` | 0 (7 passed) |
| `cargo test --locked --workspace --all-targets --all-features` | 0 (34 suites, 533 passed, 0 failed) |
| `cargo test --locked --doc --workspace --all-features` | 0 |
| `node scripts/check-doc-links.mjs` | 0 (368 links) |
| `node scripts/check-work-items.mjs` | 0 (14 items) |

## Environment

- Linux (WSL kernel), rustc pinned 1.97.1 via rust-toolchain.toml.
- PostgreSQL reachable at the proof-pg default DSN `127.0.0.1:55432/prooftest`;
  every PostgreSQL-backed integration test connected and passed.
- No push, tag, public release, credential mutation, or external-provider
  change was performed.

## Scope conformance

- No new wire surface, storage schema version, migration, or operation
  registry entry: both operations reuse their frozen registry rows, Problem
  codes, DSSE envelope profiles, and the existing nine-route surface.
- New retained conformance vectors:
  `conformance/v1/collaboration-server/vectors/enrollment-agent-binding.valid.json`
  and `enrollment-oidc-binding.valid.json`, consumed field-set-exactly by
  `enrollment_conformance_vectors_match_produced_artifacts`.
- Frozen-vector change count: 0. Existing vectors untouched.

## Residual boundaries

- The semantic-oracle local/server trace parity for these two rows follows
  the topology boundary recorded in the completion record: the operations are
  server-only successors (no local CLI counterpart exists for remote OIDC
  session issuance), and the agent-binding closure reuses the local
  challenge/envelope artifacts byte-for-byte.
- Credential rotation, revocation UX beyond the frozen revoke artifacts,
  signing-key lifecycle, and Environment configuration update remain fog.
- Same-UID hostile-process isolation and Windows containment remain outside
  this result (unchanged from accepted Milestone 3 residuals).
