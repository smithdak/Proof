# Security policy

Proof is pre-release software with no deployable version yet. Security reports about the architecture, documentation, repository configuration, or future implementation are still welcome.

## Reporting a vulnerability

Use GitHub's private vulnerability-reporting flow:

<https://github.com/smithdak/Proof/security/advisories/new>

Do not open a public issue containing exploit details, credentials, private content, or information that would make exploitation easier.

Include, when available:

- Affected component or document.
- Impact and required attacker access.
- Reproduction steps or proof of concept.
- Whether the issue is already being exploited.
- Suggested mitigation.
- Any disclosure deadline or coordination constraint.

## Response targets

- Acknowledge a complete report within 3 business days.
- Establish severity and next action within 7 business days.
- Coordinate remediation and disclosure according to impact and deployment exposure.

These are response targets, not automated guarantees.

## Supported versions

There are no released versions. A supported-version table will be added before the first public binary release.

## Security design

The current security architecture is documented in:

- [Core invariants](docs/architecture/constitution.md)
- [Agent authority](docs/architecture/agent-authority.md)
- [Proof model](docs/architecture/proof-model.md)
- [Threat model](docs/architecture/threat-model.md)
- [Testing strategy](docs/architecture/testing.md)

## Handling sensitive reports

Security artifacts are shared only with people required to validate and remediate the issue. Public disclosure should include affected versions, impact, remediation, and verification guidance without exposing unrelated private data.
