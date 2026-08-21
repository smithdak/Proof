# Portable Proof v1 conformance

This directory freezes the independently produced portable-verification vectors for
`proof-verifier`. The bounded generator lives in
`crates/proof-verifier/tests/support/mod.rs`; it uses deterministic public test keys
and constructs every canonical artifact, signature, trust input, and checkpoint
without a producer database or any producer-side Proof crate dependency.

The canonical wire fixtures are intentionally compact and reviewable:

- `bundle.json`, `trust.complete.json`, and `checkpoint.json` are the Complete inputs;
- `trust.required-opening.json` changes only caller disclosure policy;
- `report.complete.json`, `report.incomplete.json`, and `report.invalid.json` freeze
  the structured outcomes and stable finding codes.

`hashes.json` pins the domain-separated identities of those three outcomes:

- `complete`: optional subject opening withheld, exact checkpoint accepted;
- `incomplete`: the same commitment and bundle under caller-required disclosure;
- `invalid`: the complete closure with one corrupted authority decision signature.

The verifier-owned matrix additionally exercises included/withheld commitment parity,
missing checkpoints, byte and digest tampering, deterministic reports, and raw UID and
blind canaries. The public CLI integration freezes semantic exit codes `0`, `20`, and
`21`, usage/input exit `64`, canonical report stdout, and stable stderr codes. Run both
from the repository root:

```text
cargo test --locked -p proof-verifier --test portable_matrix
cargo test --locked -p proof-verifier --test public_cli
```

Changing a canonical schema, domain separator, signed preimage, report code, or
verification rule changes at least one frozen digest and requires an explicit v1
conformance decision.
