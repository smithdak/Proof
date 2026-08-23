# P-0008 AC1-AC14 traceability

## Binding and result

This matrix applies only to immutable decision candidate
`c461b1b60bece277b88c6a5aee55c200658ab327`, tree
`20385096a71904103ae898bc127eea6c13980cc8`, qualified at
`2026-08-23T11:29:42.553Z`. The controlling complete gate is
`rtk cargo test --locked --workspace --all-targets --all-features`: 614 tests
passed across 37 suites with no failure in 383.63 seconds.

AC1-AC12 and AC14 are supported for the bounded decision contract. AC13 is
**Pending** because project-owner acceptance has not occurred. “Supported” in
this matrix means that the candidate makes the required architecture and
future conformance boundary exact; it does not claim that a collaboration
server, provider, PostgreSQL adapter, outbox, preview service, or remote
verifier was implemented or executed.

## Evidence legend

| ID | Retained source |
| --- | --- |
| CS | [Proposed collaboration-server contract](../../../architecture/collaboration-server.md) |
| ADR | [Proposed ADR-0013](../../../decisions/0013-single-workspace-collaboration-server.md) |
| CP | [Collaboration conformance profile](../../../../conformance/v1/collaboration-server/README.md) |
| RA | `conformance/v1/collaboration-server/schemas/remote-auth-v1.schema.json` and its OIDC, binding, status, role, authentication-event, and actor-context vectors |
| HR | `http-envelope-v1.schema.json`, `application-operations-v1.schema.json`, `http-operation-registry-v1.schema.json`, and `http-operation-registry.valid.json` |
| CA | `collaboration-artifacts-v1.schema.json` and the retained remote authority, approval, role, configuration, decision, and consequence vectors |
| ST | `storage-transaction-v1.schema.json`, `migration-rebuild-v1.schema.json`, `storage-transaction-traces.valid.json`, and `migration-rebuild.valid.json` |
| DO | `artifact-catalog-v1.schema.json`, `outbox-delivery-v1.schema.json`, `preview-delivery-v1.schema.json`, and their retained vectors |
| EV | `remote-evidence-v2.schema.json`, `remote-evidence-v2.valid.json`, and the exact export/artifact fixtures |
| RM | `rejected-case-manifest-v1.schema.json` and `rejected-cases.json` |
| TM | [Threat model](../../../architecture/threat-model.md) and [testing strategy](../../../architecture/testing.md) |
| RT | `crates/proof-local/tests/p0008_collaboration_contract.rs`, ten tests included in the complete candidate gate |

## Criterion matrix

| Criterion | Required meaning | Primary retained evidence | Qualification and rejection boundary | Result |
| --- | --- | --- | --- | --- |
| AC1 | One exact remote north star identifies all actors, transactions, artifacts, responses, and independent verifier inputs. | CS “Exact remote north star”; CP; RA; CA; ST; DO; EV; RT | The ordered scenario names the authenticated requesting Human, operating Agent, distinct reviewer/approver and publisher, exact causal heads and facts, Release and preview, export capture/status/artifacts, and caller-controlled trust/checkpoint/external bytes. Actor, fact, artifact, or verifier-input substitution is reserved in RM. | **Supported** |
| AC2 | Remote subject, Principal, binding, token/session, Agent proof, and transport connection remain distinct; untrusted input selects none of them. | CS topology and identity vocabulary; RA; HR; RT | Deployment-pinned OIDC plus protected lookup derives the Human. Dual-actor routes independently verify a fresh Agent presentation. Request-selected Workspace/Principal/issuer/binding, Delegation-as-authentication, and Agent-only requester are rejected requirements. | **Supported** |
| AC3 | OIDC validation, binding lifecycle, public redaction, session/CSRF, and disclosure-neutral failures are exact. | CS OIDC/session boundary; ADR Human and Agent authentication; CP OIDC/session profile; RA; RM; RT | The contract fixes issuer discovery and JWKS constraints, algorithm/key/audience/issuer/time/nonce/state/PKCE checks, one-use transactions, opaque sessions, exact Origin plus CSRF, disablement/revocation, commitment-only public evidence, and uniform pre-actor 401 behavior. Wrong claims, mix-up, fixation, replay, CSRF, hostile Origin, and secret leakage are closed future rejection rows. | **Supported** |
| AC4 | Every required HTTP operation maps to one shared application contract with stable Schemas, Problems, idempotency, concurrency, versioning, discovery, and no adapter-only mutation. | CS HTTP boundary; ADR versioned HTTP adapter; CP HTTP/application mapping; HR; RT | Nine exact routes contain 23 ordered Human rows and 40 total rows. Every row resolves strict input/result Schemas, authorization, Problems, limits, concurrency, idempotency, and effect semantics. Route/name/version/authentication mismatch, unknown members, HTTP-only writes, stale preconditions, changed-input replay, and oversize input reject. | **Supported** |
| AC5 | Review, approval, policy administration, and separation of duties are authoritative rather than UI convention. | CS Human roles, causal approval, and Environment administration; ADR review/configuration; CA; RT | Immutable role, approval, Environment creation, proposal, activation, revocation, and disablement facts bind exact actors, digests, heads, and time. Reviewer differs from requester/Agent; config activator differs from proposer; Release rechecks current closure. Self/Agent approval, stale validation/configuration, comments, UI state, and disabled roles cannot satisfy authority. | **Supported** |
| AC6 | PostgreSQL transaction, isolation, retry, migration, rebuild, and crash contracts preserve local observable semantics. | CS PostgreSQL unit of work and migration/rebuild; ADR persistence boundary; ST; RT | One serializable Workspace write lane atomically covers presentation, decision, application facts, consequence, idempotency, Proof/Release, projections, artifact catalog, and enqueue. Full retries, ambiguous-commit reconciliation, locked heads, migration ledger, generation swap, and recovery phases are exact. Partial writes, check-then-act gaps, fabricated history, and unknown Schemas reject by contract; runtime parity remains successor work. | **Supported** |
| AC7 | Artifacts and outbox cannot expose effects before authoritative commit; delivery is idempotent without exactly-once. | CS artifact/outbox/preview sections; ADR artifacts and delivery; DO; RT | Fork-capable signed bytes commit atomically; neutral staging remains private until catalog commit. Outbox state uses ordered generation, lease, acknowledgement, replay, dead-letter, and abandonment facts. Release and delivery states stay distinct. Precommit exposure, substitution, stale lease acknowledgement, changed duplicate payload, sequence regression, and exactly-once claims reject. | **Supported** |
| AC8 | Remote evidence keeps producer references separate from caller trust/checkpoints and makes no latest/immediate-Release overclaim. | CS evidence export/verification; ADR evidence; CP preview/evidence limits; EV; RT | The exact logical member map has six roots, kind-plus-digest acquisition, included versus external-required bytes, and empty untrusted hints. `VerificationTrustPolicyV2`, caller head, checkpoints, keys, resolver, disclosure, and limits are independent inputs. Missing required material is Incomplete; tamper or contradiction is Invalid; producer metadata cannot establish snapshot freshness, readiness, immediate ancestry, or global latest history. | **Supported** |
| AC9 | Every P-0006 residual is classified as retained nonclaim, required Milestone 3 closure, or later fog. | CS “P-0006 and P-0007 residual disposition”; receipt residuals | The classification covers latest/immediate Release, Environment chronology, approval causal heads, direct-Human v2 completeness, pre-v14 evidence, same-UID and Windows containment, structural finding coverage, `EditBatchV1`, total database forgery, local retry UX, Release-history stack safety, and power-loss qualification. Architecture does not silently close implementation residuals. | **Supported** |
| AC10 | A local/server conformance matrix covers operations, concurrency, recovery, OIDC/network abuse, outbox, artifact substitution, and verification. | CS conformance/falsification plan; CP; RM; TM; RT | The matrix separates retained local execution, decision-contract qualification, and future server execution. RM has 158 unique non-executable rows: 88 HTTP rows with 276 exact route/operation bindings and 70 non-HTTP rows. Each reserves one future test ID; documentation and structural validation do not count as a passing server test. | **Supported** |
| AC11 | The threat model covers network attackers, confused deputies, browser/session attacks, token replay, database/operator tamper, SSRF/webhooks, and Workspace isolation. | TM; CS topology and falsification plan; ADR consequences/nonclaims; RM | Boundaries cover forwarded-header spoofing, OIDC mix-up/JWKS SSRF, fixation/CSRF/replay, Principal and Workspace substitution, artifact/outbox injection, webhook/event replay and SSRF, resource enumeration, bounded denial of service, operator rollback, and alternate-Workspace spoofing. Complete server compromise remains outside the bounded guarantee. | **Supported** |
| AC12 | The strongest rejected decomposition and its kill or pivot triggers are recorded. | CS “Strongest rejected decomposition”; ADR alternatives | A split identity/workflow/content/evidence/delivery event-bus design and a generic HTTP/ORM façade are rejected because they fracture one accepted atomic authority/application boundary or privilege UI/database state. Pivot triggers require an unexpressible application contract, lost atomicity, UI-defined approval, precommit publication, measured contention, unmet objectives, required isolation, or stable ownership evidence. | **Supported** |
| AC13 | The project owner accepts the exact decision before an implementation successor becomes `ready`. | P-0008 work item; receipt disposition; manifest gate state | The exact candidate and residuals are review-eligible, but no post-presentation owner disposition exists. `accepted_by` and `accepted_at` remain null, ADR-0013 remains Proposed, and no successor is `ready`. | **Pending** |
| AC14 | Only decision-complete successors are created; SDK, console, deployment, and remaining uncertainty stay in fog. | CS “Successor order after owner acceptance”; ADR consequences/nonclaims; work map | The candidate specifies a five-stage dependency order and the acceptance-gated first frontier without creating any successor item. Zero successors exist. SDK, console, provider selection/provisioning, deployment, public preview, workload identity, KMS/HSM, operations, multi-Workspace work, and public release remain fog. | **Supported** |

## Exact gate

| Command | Result |
| --- | --- |
| `rtk cargo fmt --all -- --check` | Passed |
| `rtk cargo clippy --locked --workspace --all-targets --all-features -- -D warnings` | Passed with warnings denied |
| `rtk cargo test --locked --workspace --all-targets --all-features` | 614 passed across 37 suites; 0 failed; 383.63s |
| `rtk cargo test --locked --doc --workspace --all-features` | Seven suites; 0 tests; 0 failures |
| `rtk node scripts/check-doc-links.mjs` | 203 internal links passed |
| `rtk node scripts/check-work-items.mjs` | Eight work items passed |
| `rtk git diff --check` | Passed |

## Boundary carried to owner review

The candidate is decision-complete for the proposed single-Workspace slice.
It does not establish runtime local/server parity, a deployed identity or
database boundary, materialized remote evidence, an observed verifier report,
exactly-once delivery, global Release freshness, multi-Workspace isolation, or
any provider, operational, deployment, publication, or production claim.

Owner acceptance remains the only open P-0008 acceptance criterion. Until the
project owner explicitly accepts this exact candidate, the evidence commit,
and the residual boundaries after presentation, P-0008 remains in review,
ADR-0013 remains Proposed, and the successor count remains zero.
