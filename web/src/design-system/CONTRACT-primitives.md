# Primitive API contract (continuation)

Components live in `src/design-system/primitives/`, one file each, exported
from `src/design-system/index.ts`. Forward-ref where native props forward.
No component may hardcode hex values; use token classes only.

- Button.tsx: variant "default" (ruled outline) | "consequential" (solid
  consequential-600 bg, paper text) | "ghost" (bare ink) | "danger"
  (vermilion outline); size "sm" | "md".
- IconButton.tsx: square ghost button wrapping a Lucide icon; aria-label
  required prop type.
- FieldLabel.tsx: small-caps label above controls.
- Input.tsx / Textarea.tsx / Select.tsx: ruled underline-first fields:
  transparent bg, border-b ruling-300, focus border-b ruling-600.
- Stamp.tsx: status pill rendered as a rubber stamp - 1.5px double-effect
  pill border (inset box-shadow offset), slight -1deg rotation, uppercase
  mono 11px letterspaced text. Tone: "seal" | "vermilion" | "amber" |
  "ruling". Also export stampToneForStatus(status) mapping ChangeSetStatus,
  verification verdicts, and delivery states per craft rule 4 of CONTRACT.md.
- RegisterPanel.tsx: the card. bg-paper-25, border-ruling-200, rounded,
  optional small-caps title over a hairline. No shadow.
- DataTable.tsx: generic entry-line table. Props: columns
  ({key, header, render?, align?, width?}[]), rows, rowKey, onRowClick?,
  emptyState?. Header small-caps with double hairline underneath; row hover
  bg-paper-100; selected row shows 2px ruling-600 inset left border;
  tabular numerals throughout.
- Dialog.tsx: Radix wrapper - paper panel bg-paper-25 border-ruling-200
  rounded-md shadow-lg over ink-950/40 scrim; Title/Description/Close built in.
- Tooltip.tsx: Radix tooltip, ink-900 background, paper text.
- Tabs.tsx: Radix tabs as ledger index tabs; active = ink text + 2px
  ruling-700 underline; inactive = ink-500.
- Toast.tsx: context + bottom-right viewport; tones reuse Stamp tones;
  auto-dismiss 5s; role="status"; export useToast().
- Skeleton.tsx: pulse block bg-paper-150.
- EmptyState.tsx: blank-folio state - centered small-caps title, one-line
  ink-500 explanation, optional action slot.
- Kbd.tsx: mono 10px key cap with ruled border and baseline shadow.
- CopyButton.tsx + DigestText.tsx: mono digest display truncated at both
  ends (first 10 / last 8 chars) with copy-to-clipboard affordance and a
  tiny "copied" confirmation via useToast or local state.
- LifecycleRail.tsx: horizontal station rail for the ChangeSet lifecycle:
  draft -> validated -> submitted -> approved -> committed (+ rejected as a
  vermilion side-branch from validated/submitted). Stations are small-caps
  labels on the shared hairline; the active station carries a filled dot in
  amber-screen-600 while pending action is outside Proof, seal-600 once
  passed irreversibly. Rejected stations get a vermilion cross tick.
- FindingCard.tsx: validation finding display - code chip (mono), severity
  tone per rule 4, message as prose, repair_guidance as an indented
  "REPAIR" small-caps block when present, subject ids as DigestText.
- DiffRowView.tsx: one entry-line diff - object id + field path mono header,
  before (ink-500, strikethrough none, prefixed "-") and after ("+") lines
  set on the ledger hairline grid; superseded edits show an amber note line.
- PageHeader.tsx: register page header - small-caps kicker, title (2xl
  semibold tracking-tight), optional meta line (mono), optional actions slot.
- SectionHeading.tsx: small-caps section label with trailing hairline.

## Shell contract (app stream)

AppShell owns: left nav rail with sections Overview (/overview), ChangeSets
(/changesets, detail /changesets/:changesetId), Released content (/objects),
Editions and Releases (/releases), Proofs and Evidence (/proofs),
Authority (/authority). Topbar carries workspace register identity (name,
Known State digest as DigestText, session principal menu with logout).
Command palette opens with Cmd/Ctrl+K anywhere: fuzzy list of route
destinations plus seeded quick actions; arrow keys + enter navigate; Esc
closes; focus returns to trigger. SessionProvider loads getSession() and
feeds csrf token to api client setCsrfProvider. Unknown routes redirect to
/overview. The rail collapses to icons under lg breakpoint.
