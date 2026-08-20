# Vision and product thesis

**Status:** Ratified  
**Baseline:** August 3, 2026

## Product statement

> Proof is the agent-first enterprise CMS where every change is governed, every published state is reproducible, and every release carries its proof.

## The problem

The dominant CMS interaction model assumes a person operating a graphical administration interface. Automation is usually implemented through secondary APIs that expose mutable records under broad service credentials. AI is then added as an assistant inside the same model.

That approach can generate content, but it does not provide a trustworthy operating model for agents. A consequential content system needs to know:

- Who or what initiated the work?
- Under whose authority did it act?
- What task and scope were declared?
- Which source state and context were used?
- What exact mutations were proposed?
- Which deterministic policies and validators ran?
- Which approvals were required and received?
- What immutable state resulted?
- Where was that state released?
- Can another system reproduce and verify the result?

Proof makes those questions part of the write path instead of reconstructing incomplete answers after an incident.

## The thesis

### Content mutation is a transaction

A content change is not merely a field update. It is a governed state transition with intent, authority, preconditions, validation, and evidence. Proof groups related Edits into a ChangeSet and commits them atomically.

### Agents are operating identities

An agent is not a magical feature flag and does not receive a privileged write path. It is a Principal operating under scoped Delegation. The same rules govern a person, a service, and an agent; what differs is their identity and authority.

### Determinism belongs at the boundary of consequence

Models are useful for interpretation and generation. They are not the authority on whether a mutation is permitted or safe to publish. Deterministic code evaluates invariants, authorization, policy, schema validity, concurrency, and release conditions.

### Publication should create evidence, not erase history

Published content is represented by immutable Editions. A Release points a delivery target at an Edition. Corrections create new Editions and Releases. They do not rewrite the evidence chain.

### The interface hierarchy should be inverted

The machine interface is primary. The CLI is the first complete product surface and future UIs consume the same application contracts. This makes agent operation native without making the product hostile to humans.

## Target users

### Platform and content engineering teams

Teams that need structured content infrastructure with predictable automation, strong delivery semantics, and no UI-only capabilities.

### Enterprise content operations

Organizations that require approvals, separation of duties, localization, auditability, and evidence for high-impact content changes.

### Agent builders

Builders who need a CMS where agents can discover capabilities, obtain bounded context, propose atomic changes, receive structured repair guidance, and operate within explicit authority.

### Agencies and migration partners

Teams replacing expensive or inflexible enterprise CMS products and needing an auditable migration path rather than another monolithic DXP.

## Product promise

An authorized Principal can propose, inspect, validate, approve, commit, publish, release, reproduce, and verify content changes through stable machine-readable interfaces without UI automation or governance bypasses.

## What makes Proof different

Proof is not differentiated by including a text-generation button. Its differentiation is structural:

- Intent is data.
- Authority is explicit.
- Context is bounded and reproducible.
- Mutations are atomic.
- Validation is deterministic.
- Publication is immutable.
- Failures are repairable by machines.
- Evidence is produced at the time of action.
- Every interface shares the same semantics.

## North-star scenario

An enterprise delegates an agent authority to localize a product launch into two locales, but only for a specified campaign, content subtree, and preview Environment. Proof assembles the relevant schemas, source Objects, terminology, policies, and current state into a ContextPack. The agent proposes all changes in one ChangeSet. Proof rejects one prohibited legal-claim translation with a structured finding. The agent repairs the Edit without exceeding its scope. A human approves the resulting diff. Proof atomically commits the ChangeSet, creates an Edition, releases it to preview, and emits a signed Proof. Another operator independently verifies the Edition, authority chain, validations, approval, and released state.

That complete loop—not content generation alone—is the product.

### Ratified P-0002 interpretation

This interpretation is project-owner accepted but not implemented. It does not
change the ratified north-star outcome.

For Milestone 2, the campaign and content-subtree descriptions are task intent,
not dynamic authorization resources. Before work begins, the Human resolves
them to a finite, sorted set of exact Objects, Schemas, target locales, and one
preview Environment and issues an immutable resource-intent control artifact.
The Agent
cannot create, narrow, or widen it. The ContextPack, ChangeSet, Delegation, and
authorization evidence all bind that closed set. Proof does not infer a
campaign entity, hierarchy, path prefix, or descendant grant from prose.

Each existing locale-neutral Object revision is the immutable source for this
operation. A localized result is a separate append-only rendition identified by
the exact `(object_id, locale)` pair. Localization cannot mutate the source
Object, relationships, lifecycle, or Schema; does not select a general variant;
and performs no locale fallback. Repair appends a superseding Edit inside the
same ChangeSet rather than rewriting the failed attempt.

The preview Release is valid only when its baseline Environment Release is
unchanged and its Edition is the exact causal result of that one approved
ChangeSet. Unrelated committed state cannot ride along with the delegated
release. The ratified mechanism and versioned artifacts are defined by P-0002;
P-0007 has implemented and qualified the Human-path content foundation;
delegated mutation remains disabled until P-0003 is accepted and P-0004/P-0005
complete.
