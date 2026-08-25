# Console design-system contract (p0016)

Law for every stream building UI tonight. The direction world is the
notarial register: laid-paper ground, iron-gall ink text, prussian ruling
hairlines as the only chrome, stamp-ink status colors, one reserved
consequential ink for irreversible actions. If a choice is not covered here,
derive it from `src/design-system/tokens.css` and the direction contract in
`index.html`; never invent new color families.

## Craft rules (binding)

1. Chrome is hairline: borders use `border-ruling-200` at 1px. No drop
   shadows except dialog overlays (shadow-lg max). Radii: 4px default,
   full-round only for stamp/badge pills.
2. Hierarchy comes from spacing, hairlines, and type - never nested boxes.
3. All identifiers, digests, timestamps render in `font-mono`. Labels use
   small-caps style: `text-2xs uppercase tracking-[0.14em] text-ink-600`.
4. Status colors appear ONLY inside Stamp/Finding components:
   passed/approved/committed = `seal-*`; rejected/failed/error =
   `vermilion-*`; running/pending/submitted = `amber-screen-*`;
   draft/informational = `ruling-*` or ink neutrals.
5. `consequential-*` ink is reserved for irreversible actions (Approve,
   Commit, Release, Revoke) and for the register's single primary action
   (New ChangeSet). It must not decorate anything else.
6. Motion: 120-200ms ease-out micro-transitions only; nothing moves while
   the user reads; honor `prefers-reduced-motion`.
7. Every interactive element is keyboard reachable with visible focus
   (`focus-visible` ring in `ruling-600`). Target WCAG 2.2 AA contrast.
8. Density: ledger-dense but breathing; table rows >= 44px tall; page
   gutters >= 24px; `max-w-prose` for long prose passages.
