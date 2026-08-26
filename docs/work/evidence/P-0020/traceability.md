# P-0020 acceptance-criteria traceability

[Back to the work item](../../items/P-0020-authoring-contract.md)

| AC | Where satisfied |
| --- | --- |
| 1. Exact authoring north-star | [contract.md](contract.md) "Ratified authoring north-star" — Human intent-v2 issuer, delegated Agent, Human approver, created Objects, ChangeSet composition, Edition/Release, verifier `Complete`. |
| 2. Creation mechanism frozen with rejected alternative and triggers | D1 — second v2 edit kind with intra-ChangeSet causality; standalone-op, legacy-v1, and Human-only-carve-out alternatives recorded with reasons/triggers. |
| 3. Schema reads and draft register frozen, no wildcard overclaim | D3 (`schema.list/get`, cursor + page caps, exact-tuple misses) and D4 (`object.list` bounded filters/cursors, envelope states committed-not-released semantics). |
| 4. Draft-read authorization exact | D4 role set mirrors `release.get/v2`; choke-point and locked-head re-check citations (dispatch.rs:626-631, authz.rs:479-496, operations.rs:543-554); Authorization analysis section bounds disclosure to authenticated roles. |
| 5. Flat stance, deferred subtree authority, escape hatch, trigger verbatim | D5 — flat ratified; deferred-not-decided record; structure-as-view escape hatch; falsifiable reopening trigger (>100 exact IDs or two consecutive friction-dominant qualification runs). |
| 6. Blueprints compose only ratified operations | D6 — client-side presets over existing ops, no domain entity, cannot exit intent closure; revisit trigger named. |
| 7. Storage/vector plan complete for the successor | D7 (SQLite v15 kind column, PG facts arm, no projection change, oracle arms) and D8 (per-artifact impact matrix with hash effects). |
| 8. Conformance-matrix extension across surfaces | Conformance matrix extension section — accepted/rejected paths per local CLI, HTTP server, oracle/PG parity, MCP descriptor validity. |
| 9. Only decision-complete successors exist in dependency order | Successor graph and promotion order — P-0021 sole promotion on acceptance; P-0022/P-0023/P-0024 named intent only. |
| 10. Owner acceptance precedes successor promotion | Recorded in the item completion record: project owner `smithdak` accepted candidate `137e752c3457713a26c40ef3bf66f6b14e346a9a` at `2026-08-26T11:57:40.118Z`; P-0021 promoted in the same narrow change. |
