# Proof work control

This directory is the canonical execution control plane for Proof. Chat history,
GitHub Issues, and local notes may provide context, but they do not define an
item's scope, dependency state, claim, or completion.

The product roadmap remains the strategic sequence, ADRs remain the durable
home for architecture decisions, and the changelog records delivered behavior.
Work items connect those artifacts to bounded implementation and qualification
chunks.

## Rolling-wave model

- [The work map](map.md) is an index. It names the destination, current
  frontier, dependencies, fog, and consciously excluded work.
- `items/` is the single home for each work item's scope, acceptance evidence,
  and completion record.
- `evidence/<item-id>/` is created when an item executes. Every executed item
  produces both `receipt.md` and `manifest.json`. They record exact commands,
  environment, revisions, exit codes, artifact digests, and evidence paths; they
  do not store secrets, credentials, private keys, runtime databases, or large
  generated artifacts.
- Only the immediate frontier is implementation-ready. Later items describe
  outcomes and are reshaped when their blockers close.

## Status model

| Status | Meaning |
| --- | --- |
| `proposed` | Outcome is visible, but the item is not claimable yet. |
| `ready` | Scope and acceptance evidence are sufficient for autonomous execution. |
| `claimed` | One named executor owns the item. |
| `blocked` | A listed dependency or external decision prevents execution. |
| `review` | Implementation is complete and awaiting its stated review gate. |
| `done` | Acceptance evidence and completion record are present. |
| `superseded` | The item was replaced; its completion record links the replacement. |

Item frontmatter is authoritative for status and blockers. The map columns are
derived. If they disagree, stop, repair both in one narrow change, and do not
claim work.

Frontmatter metadata uses these profiles:

- `claimed_by`: stable executor name plus session or thread identifier.
- `claimed_at` and `accepted_at`: RFC 3339 UTC timestamps.
- `base_sha`: repository HEAD immediately before the claim mutation.
- `review_gate`: `none` or the named human/independent gate required before
  `done`.
- `accepted_by` and `accepted_at`: populated only by the named gate.

Allowed transitions are `blocked → proposed` after blockers close and the item
needs more shaping, `blocked → ready` when the same reviewed change closes its
blockers and makes the item implementation-ready, `proposed → ready`,
`ready → claimed`, `claimed → review`, and `review → done` or
`review → claimed` for rework. A newly discovered external blocker may move
`claimed → blocked` with a recorded handoff. Any non-done item may become
`superseded` when it links its replacement. `review → done` requires the named
review gate; decision items and acceptance of residual risk always require the
project owner.

For a `project-owner` review gate, `review -> done` requires `accepted_by` and
`accepted_at` in frontmatter plus an item completion record that names the
manifest's `item_work_commit` and records the owner's accept-or-rework verdict.
The receipt and manifest remain the candidate evidence; no separate verdict
file is required unless the item explicitly requires one.

Run `node scripts/check-work-items.mjs` after changing this control plane. The
validator checks metadata, lifecycle state, dependency existence and cycles,
map parity, status transitions, and required evidence for executed items.

## Claim and completion protocol

1. Read the map, then the complete named item.
2. Re-read repository status and the item immediately before claiming it.
3. Set `status`, `claimed_by`, `claimed_at`, and `base_sha` in one narrow
   change. When multiple synchronized worktrees exist, commit that claim before
   implementation; an uncommitted file is not a distributed lock.
4. Execute the full item autonomously inside its authorized scope. Do not absorb
   adjacent work merely because it is convenient.
5. Record exact evidence, residual risks, and newly sharpened work. The JSON
   manifest binds the qualified item-work commit—implementation,
   qualification, or decision proposal as applicable—parent/base SHA,
   commands, exit codes, environment/tool versions, artifact digests, and
   evidence paths.
   Update the map and item completion record in one narrow follow-up change.
6. Shape only the newly visible frontier. Leave later uncertainty in fog.

For a `proof-assurance` review gate, `done` additionally requires a committed
`assurance-verdict.md` with `verdict: supported`. The verdict's candidate must
match the manifest's `item_work_commit`; its Engineering evidence commit must
contain the current receipt and manifest; and the item completion record must
include `Assurance record commit: <full-sha>` naming the commit that contains
the current verdict. The validator proves that candidate → Engineering
evidence → Assurance record → completion ancestry and requires the item's
acceptance actor and timestamp to match the Assurance verdict. CI therefore
requires complete Git history for work-control validation.

Claims never expire automatically. Takeover requires a recorded handoff or an
explicit stale-claim decision. Selecting a work item does not authorize a push,
tag, public release, credential change, or external-provider mutation unless
the item and the user's execution request explicitly include it.

## Canonical-source rule

GitHub Issues may mirror a work item for discussion or visibility, but the
repository item remains authoritative. A mirror must link back here and must
not introduce a second status, dependency graph, or acceptance contract.

The strongest alternative is a GitHub-only backlog. It provides better hosted
assignment, but it separates execution state from the exact code and contracts
being changed and is unavailable offline. Proof starts repo-local; automated
validation or issue mirroring should be added only when observed concurrency or
drift justifies the overhead.
