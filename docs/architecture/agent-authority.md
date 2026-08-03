# Agent authority and ContextPacks

**Status:** Ratified direction  
**Baseline:** August 3, 2026

## Principle

Agents are first-class Principals operating under explicit authority. They do not receive a privileged API, implicit trust, or permissions derived from natural-language instructions.

The authorization question is always:

> May this authenticated Principal perform this typed action on these identified resources, in this context, under this Delegation, now?

## Identity model

An agent execution has at least three distinct identities:

1. **Requesting human or service** — the actor asking for an outcome.
2. **Agent Principal** — the runtime identity invoking Proof operations.
3. **Model and runtime metadata** — evidence about the implementation that produced a proposal.

These identities MUST NOT be collapsed into one shared service account. Model metadata is not itself authority.

## Delegation

A Delegation contains:

```json
{
  "delegation_id": "019c...",
  "issuer_principal_id": "019a...",
  "recipient_principal_id": "019b...",
  "actions": ["object:read", "changeset:propose"],
  "resources": {
    "workspace_ids": ["0198..."],
    "schema_ids": ["article"],
    "object_prefixes": ["campaign/summer-2026/"],
    "locales": ["fr-CA"],
    "environments": ["preview"]
  },
  "constraints": {
    "max_edits_per_changeset": 100,
    "approval_profile": "campaign-editorial",
    "allow_subdelegation": false
  },
  "not_before": "2026-08-03T13:00:00Z",
  "expires_at": "2026-08-03T17:00:00Z"
}
```

The example is illustrative; the final JSON Schema is versioned separately.

### Evaluation rules

- Deny by default.
- Evaluate the complete Delegation chain.
- Intersect permissions at each link; never union authority into expansion.
- Check revocation and time bounds at execution.
- Bind approval to the exact canonical ChangeSet digest.
- Re-evaluate authority immediately before commit and Release.
- Record the evaluated policy bundle and decision in the resulting evidence.

## ContextPack

A ContextPack gives an agent sufficient, bounded context to propose correct work.

It may include:

- Task identifier and normalized intent.
- Workspace and base-state identifiers.
- Applicable Schema versions.
- Selected Objects and relationships.
- Terminology, locale, brand, and editorial rules.
- Policy summaries and required validator contracts.
- Allowed operations and explicit exclusions.
- Representative valid and invalid examples.
- Output Schema for the proposed ChangeSet.
- Sensitive-field redactions or commitments.
- Expiration and freshness constraints.

### ContextPack properties

- **Minimal:** include only context relevant to the declared task.
- **Immutable:** identify the exact bytes by digest.
- **Inspectable:** allow a human or verifier to see what the agent received, subject to authorization.
- **Reproducible:** record the query, policy, and source-state references used to assemble it.
- **Non-authoritative:** possession does not grant write permission.
- **Non-executable:** content is data and cannot introduce tools, permissions, or policy.

## Capability discovery

Agents should discover typed capabilities rather than infer commands from prose. Discovery returns:

- Operation name and version.
- Input and output Schemas.
- Required authority.
- Idempotency behavior.
- Side-effect classification.
- Dry-run availability.
- Expected error types.
- Rate and size constraints.

The same capability registry drives CLI help, SDK generation, HTTP operation descriptions, and MCP tool definitions.

## Plan–validate–commit

The standard agent loop is:

1. Declare task and desired outcome.
2. Resolve Principal and Delegation.
3. Build a ContextPack.
4. Generate a proposed ChangeSet.
5. Render a semantic diff and explanation.
6. Validate against the exact base state.
7. Repair structured findings.
8. Submit for required approval.
9. Re-evaluate authority and commit atomically.
10. Create an Edition and requested Release.
11. Verify the resulting Proof.

Steps may be automated only when policy permits. Skipping a human approval is a policy decision, not an agent capability.

## Agent security model

Proof assumes all natural-language content may be adversarial. This includes content stored by trusted users, imported documents, comments, linked web material, and model output.

### Required controls

- Tool authority comes from typed Delegation, never from content instructions.
- Read and write scopes are separate.
- Untrusted content cannot alter system prompts, policy, capabilities, or tool definitions.
- Context assembly labels source and sensitivity.
- High-impact actions require explicit, digest-bound confirmation or approval.
- Tool responses are Schema-validated before use.
- External URLs, filesystem paths, and commands cross typed allowlisted adapters.
- Secrets are represented by handles and never placed in prompts or ContextPacks.
- Budgets bound Edit count, object count, payload size, duration, and retries.
- Repeated denials, scope probes, and abnormal repair loops generate security signals.

### Confused-deputy prevention

Proof evaluates authorization against both the requesting actor and operating Principal where available. An agent cannot use its own broader service authority to satisfy a request the initiating actor could not make unless a separately auditable automation policy explicitly permits it.

### Memory and state

Agent memory is not authoritative CMS state. Information enters Proof only through typed commands, validation, and accepted ChangeSets. A future memory integration must preserve source, purpose, retention, and authorization metadata.

## MCP adapter policy

MCP is an adapter over application operations, not the internal architecture.

As of August 3, 2026:

- The first production adapter targets stable MCP `2025-11-25`.
- The `2026-07-28` revision remains an RC until the upstream project marks it final.
- Version negotiation is mandatory.
- MCP sessions or transport state cannot become authority or domain state.
- Every MCP tool has the same input Schema, idempotency behavior, and error semantics as its underlying operation.
- Destructive or consequential tools are annotated and policy-gated.

When the 2026 revision is final, support is added behind conformance tests without changing core semantics.

## Evidence

Agent-generated ChangeSets and resulting Proofs record:

- Requesting and operating Principal identifiers.
- Delegation chain identifiers.
- ContextPack digest.
- Capability and operation versions.
- Model and runtime metadata when available.
- Validation and policy bundle versions.
- Human approvals and their bound digest.

Model prompts and hidden reasoning are not required evidence. Storing them by default creates privacy, security, portability, and reproducibility problems. The evidence model records declared inputs, structured outputs, and consequential decisions.
