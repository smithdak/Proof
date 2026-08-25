---
name: Proof Console
description: A notarial-ledger operating surface for governed content change — hairline chrome, stamped verdicts, one reserved consequential ink.
colors:
  paper-25: "#fcfdfb"
  paper-50: "#f7f9f4"
  paper-100: "#eff3ea"
  paper-150: "#e7ecdf"
  paper-200: "#dde4d4"
  paper-300: "#c8d2bd"
  ink-950: "#0d1615"
  ink-900: "#18231f"
  ink-800: "#26332e"
  ink-700: "#3a4842"
  ink-600: "#55635c"
  ink-500: "#707d75"
  ink-400: "#97a29a"
  ink-300: "#b8c0b8"
  ruling-700: "#47719a"
  ruling-600: "#5588aa"
  ruling-500: "#6e93b8"
  ruling-400: "#93b3cf"
  ruling-300: "#b7cde2"
  ruling-200: "#d3e1ed"
  ruling-100: "#e5eef5"
  ruling-50: "#f2f7fb"
  seal-800: "#1c5638"
  seal-700: "#236b46"
  seal-600: "#2f7d4f"
  seal-500: "#43936a"
  seal-100: "#dcebe1"
  seal-50: "#edf5ef"
  vermilion-700: "#a32d1e"
  vermilion-600: "#c43d2b"
  vermilion-500: "#d45944"
  vermilion-100: "#f7ddd7"
  vermilion-50: "#faeeeb"
  amber-screen-700: "#8a5a06"
  amber-screen-600: "#a16207"
  amber-screen-100: "#f5ecd4"
  amber-screen-50: "#faf5e6"
  consequential-700: "#8f3014"
  consequential-600: "#b03a12"
  consequential-100: "#f9e2d7"
typography:
  title:
    fontFamily: "Hanken Grotesk Variable, Hanken Grotesk, ui-sans-serif, system-ui, sans-serif"
    fontSize: "1.5rem"
    fontWeight: 600
    lineHeight: 1.3
    letterSpacing: "-0.025em"
  body:
    fontFamily: "Hanken Grotesk Variable, Hanken Grotesk, ui-sans-serif, system-ui, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 400
    lineHeight: 1.5
    letterSpacing: "normal"
  label:
    fontFamily: "Hanken Grotesk Variable, Hanken Grotesk, ui-sans-serif, system-ui, sans-serif"
    fontSize: "0.6875rem"
    fontWeight: 500
    lineHeight: 1rem
    letterSpacing: "0.14em"
    fontFeature: "uppercase via text-transform"
  mono:
    fontFamily: "Spline Sans Mono, ui-monospace, SF Mono, Menlo, Consolas, monospace"
    fontSize: "0.75rem"
    fontWeight: 400
    lineHeight: 1.5
    letterSpacing: "normal"
rounded:
  sm: "4px"
  md: "6px"
  kbd: "3px"
  pill: "9999px"
spacing:
  xs: "8px"
  sm: "12px"
  md: "16px"
  lg: "24px"
  xl: "32px"
  row-min: "44px"
components:
  button-consequential:
    backgroundColor: "{colors.consequential-600}"
    textColor: "{colors.paper-25}"
    rounded: "{rounded.sm}"
    padding: "0 16px"
    height: "40px"
  button-consequential-hover:
    backgroundColor: "{colors.consequential-700}"
  button-default:
    backgroundColor: "{colors.paper-25}"
    textColor: "{colors.ink-800}"
    rounded: "{rounded.sm}"
    padding: "0 16px"
    height: "40px"
  button-ghost:
    backgroundColor: "transparent"
    textColor: "{colors.ink-700}"
    rounded: "{rounded.sm}"
    padding: "0 16px"
    height: "40px"
  button-danger:
    backgroundColor: "{colors.paper-25}"
    textColor: "{colors.vermilion-700}"
    rounded: "{rounded.sm}"
    padding: "0 16px"
    height: "40px"
  input-underline:
    backgroundColor: "transparent"
    textColor: "{colors.ink-900}"
    rounded: "0"
    padding: "8px 2px"
  register-panel:
    backgroundColor: "{colors.paper-25}"
    textColor: "{colors.ink-900}"
    rounded: "{rounded.sm}"
    padding: "16px"
  stamp-seal:
    backgroundColor: "{colors.seal-50}"
    textColor: "{colors.seal-700}"
    rounded: "{rounded.pill}"
    padding: "1px 10px"
  table-header-label:
    textColor: "{colors.ink-600}"
    typography: "{typography.label}"
    padding: "8px 12px"
---

# Design System: Proof Console

## Overview

**Creative North Star: "The Notarial Register"**

The console is a notarial register, not an admin dashboard. Every row is an entry that will never change, and the interface's only chrome is the ledger's own ruling: faded prussian hairlines on a cool laid-paper ground. Iron-gall ink carries the writing; verdicts are struck as rubber stamps in their own ink; a single rust-colored consequential ink is reserved for the acts that can never be undone. It refuses the treeview-and-modal enterprise CMS: no nested boxes, no drop-shadow furniture, no decorative color.

Density is ledger-dense but breathing — 44px entry rows, tabular numerals, authority columns always visible — because the reader is verifying, not browsing. Identifiers are the world's verifiable core: UUIDv7 ids, BLAKE3 digests, and timestamps render in mono, truncated digest-style and copyable, never broken mid-identifier. Hierarchy comes from three voices only: grotesk prose, mono identifiers, small-caps labels. One deliberate divergence from the written world: the laid-paper texture ships as a flat ground — the build omits physicality rather than faking it, and stamps are typographic double rings with no bevel or embossing.

**Key Characteristics:**
- Flat laid-paper ground (`paper-50`) with a cool green cast; panels one step brighter (`paper-25`)
- 1px prussian hairlines (`ruling-200`) as the only chrome; zero shadows at rest
- Status ink appears exclusively inside stamp-shaped verdicts (and the lifecycle rail's station marks)
- One reserved consequential rust for irreversible actions and the register's single primary action
- Mono for everything verifiable; small-caps tracked labels for everything structural
- Micro-motion only: 150ms color fades, disabled entirely under `prefers-reduced-motion`

## Colors

A paper-and-ink palette: warm-neutral papers carry cool blue-black writing ink, prussian ruling lines do the structural work, and three stamp inks (seal green, vermilion, amber) are quarantined inside status marks. One saturated rust stands apart as the consequential ink.

### Primary
- **Laid Paper** (`paper-*`, ground `paper-50` #f7f9f4): page and html background; `paper-25` lifts panels, dialogs, and the palette one step; `paper-100` is hover/selection wash; `paper-150` is skeleton pulse; `paper-200/300` are deep wash steps for pressed and avatar fills.
- **Iron-Gall Ink** (`ink-*`, text `ink-900` #18231f): all prose and titles; `ink-950` is the overlay scrim and selection text; `ink-800/700` for secondary prose and digest text; `ink-600/500` for small-caps labels and placeholders; `ink-400/300` for faint mono metadata and unfilled station dots.

### Secondary
- **Prussian Ruling** (`ruling-*`, chrome `ruling-200` #d3e1ed): the only border color — hairlines, table rules, panel edges, chips. Also the system's interactive ink: `ruling-300` field underlines, `ruling-500` hover strokes, `ruling-600` focus rings/active markers, `ruling-700` active tab underlines and stamp outlines, `ruling-50` neutral stamp wash, `ruling-200` selection background.

### Tertiary
- **Seal Green** (`seal-*`, `seal-700` #236b46): approval verdict ink inside stamps — approved, committed, delivered, passed, validated, complete — plus the logo's seal dot.
- **Vermilion** (`vermilion-*`, `vermilion-700` #a32d1e): rejection verdict ink inside stamps (rejected, failed, error, invalid) and the danger button outline.
- **Amber Screen** (`amber-screen-*`, `amber-screen-600` #a16207): in-flight verdict ink — pending, running, submitted, incomplete, warning — and the active lifecycle station dot.

### Reserved
- **Consequential Rust** (`consequential-*`, `consequential-600` #b03a12): solid fill for irreversible actions only — Approve, Commit, Release, Revoke — and the register's single primary action (New ChangeSet). `consequential-700` is its hover; `consequential-100` exists for rare wash contexts. Never decoration.

### Named Rules
**The Hairline Chrome Rule.** Every border in the system is 1px `ruling-200`. Drop shadows exist only under floating overlays (dialogs, command palette, menus) at `shadow-lg` maximum, always over an `ink-950/40` scrim.

**The Stamp Ink Rule.** Seal, vermilion, and amber appear only inside stamp-shaped verdicts (`Stamp`, `FindingCard`) — and, as the one documented exception, as the lifecycle rail's station dots and rejection cross, where they carry progress semantics. Status ink never colors links, headings, backgrounds, or prose.

**The Consequential Ink Rule.** `consequential-600` marks exactly the acts that cannot be undone plus the register's primary action. If an action can be repeated safely, it does not get this ink.

## Typography

**Display/Body Font:** Hanken Grotesk Variable (self-hosted via Fontsource; fallbacks ui-sans-serif/system-ui)
**Mono Font:** Spline Sans Mono 400/500/600 (self-hosted; fallbacks ui-monospace/SF Mono)

**Character:** A workaday grotesk against a precise engineering mono — the clerk's hand and the registry machine. Prose stays quiet; the mono voice owns anything verifiable; small caps own anything structural.

### Hierarchy
- **Page Title** (Hanken Grotesk, 600, 1.5rem/24px, tracking −0.025em): `h1` in PageHeader, one per route, over a small-caps kicker and hairline.
- **Section/Dialog Title** (600, 18px, tracking tight): dialog titles; workspace name in the topbar.
- **Body** (400, 14px, leading 1.5, max-w-prose ≈65ch for passages): descriptions, finding messages, explanations.
- **Identifier/Mono** (Spline Sans Mono, 400–600, 11–14px): ids, digests (truncated first-10…last-8), timestamps, routes, key caps, stamp text, code chips. Tabular numerals everywhere numeric (`td`, `time`, `[data-numeric]`).
- **Small-Caps Label** (500, 11px, uppercase, letter-spacing 0.14em, ink-500/600): kickers, column headers, panel titles, station names, form labels, palette group headers.

### Named Rules
**The Three Voices Rule.** Text is either grotesk prose, mono identifier, or a small-caps tracked label. Nothing else — no serif, no display face, no italic emphasis.

## Layout

A fixed left register rail and a sticky topbar frame the ledger. The rail is 56px wide (icons only, tooltips stand in for labels) and expands to 256px with labels at `lg` (1024px). The 56px topbar holds the workspace identity block (small-caps WORKSPACE kicker, name, SYNTHETIC DEMO DATA chip), the Known State digest (from `md`/768px up), the ⌘K palette trigger, and the session principal menu. Content sits on 16px/24px gutters on mobile growing to 32px/32px at `lg`.

Density: entry rows are ≥44px tall (`h-11`); table cells pad 8px vertical / 12px horizontal; panels pad 16px; long prose caps at `max-w-prose`. Breakpoints: `sm` 640px switches tables to stacked entry cards; `md` reveals the digest; `lg` expands the rail and full gutters; `xl` reveals the workspace id.

Responsive entry cards: any `DataTable` given `renderMobileCard` renders rows under `sm` as a stacked list of hairline-separated entry cards (`border-b ruling-200`, `py-4`, full-width wrapping) carrying the row's stamp, ids, and receipts; without it, the table scrolls horizontally at a 640px minimum width.

## Elevation & Depth

Flat by default. Depth is conveyed by tonal steps of paper (ground `paper-50`, surfaces `paper-25`, washes `paper-100`) and by hairlines — never by shadow. The only elevated objects are floating overlays: dialogs, the command palette, and the principal menu (`shadow-lg` over `ink-950/40` scrims). Box-shadow also serves two non-elevation duties as inset state markers: a 2px `ruling-600` left bar marks the selected table row, active nav item, and active palette option; a 1px `ink-200` baseline under key caps gives them their keycap lip.

### Shadow Vocabulary
- **Overlay lift** (`0 10px 15px -3px rgba(0,0,0,.1), 0 4px 6px -4px rgba(0,0,0,.1)` — Tailwind `shadow-lg`): floating surfaces only, maximum allowed.
- **Active marker** (`inset 2px 0 0 0 var(--color-ruling-600)`): structural selection bar, not elevation.
- **Key-cap baseline** (`inset 0 -1px 0 0 var(--color-ink-200)`): `Kbd` only.

### Named Rules
**The Flat Ledger Rule.** Surfaces are flat at rest; nothing casts a shadow onto the ledger. If an element floats above the page it takes the scrim and the one permitted shadow; otherwise it earns depth from paper tone alone.

**The Quiet Ledger Rule.** Nothing moves while the user reads. Transitions are 150ms ease-out color fades (within the 120–200ms budget) on interactive elements only, each paired with `motion-reduce:transition-none`; the sole animation is the loading skeleton's pulse.

## Shapes

Corners are nearly square: 4px is the default radius (buttons, panels, toasts, code chips); floating overlays take 6px; key caps take 3px; full rounding belongs exclusively to pills — stamps, badge chips (SYNTHETIC DEMO DATA), and the round principal-avatar. Fields invert the box convention: inputs, textareas, and selects are ruled underlines (transparent ground, 1px `ruling-300` base) rather than boxed wells. Structure is drawn as ledger rules — single hairlines between siblings, a double rule (border + 2px offset shadow) under table headers, and a 2px left bar for indented repair guidance.

## Components

All 23 primitives live in `web/src/design-system/primitives/`, exported from `web/src/design-system/index.ts`. None may hardcode hex values; tokens only.

- **Button** — four variants × two sizes (sm 32px / md 40px, 4px radius, 150ms fade): `default` ruled outline (paper-25 ground, ruling-300 stroke, ink-800 text; hover darkens stroke to ruling-500); `consequential` solid rust fill, paper text, hover consequential-700; `ghost` bare ink-700 text with paper-100 hover wash; `danger` vermilion outline on paper with vermilion-50 hover. Disabled at 50% opacity.
- **IconButton** — square ghost wrapper for Lucide icons; `aria-label` required.
- **FieldLabel** — small-caps label placed above controls.
- **Input / Textarea / Select** — ruled underline-first fields: transparent, `ruling-300` underline, focus darkens to `ruling-600`; no boxes, no glow.
- **Stamp** — the rubber stamp: full-round pill, 1.5px outer border plus an inner 1px ring (inset 2.5px, current color), −1° rotation, uppercase mono 11px tracked 0.12em. Four tones: `seal`, `vermilion`, `amber`, `ruling`.
- **stampToneForStatus** — the binding tone map: approved/committed/delivered/passed/validated/complete → seal; rejected/failed/error/invalid → vermilion; pending/running/submitted/incomplete/warning → amber; draft/abandoned/not_evaluated/info/informational (and any unknown) → ruling.
- **RegisterPanel** — the card: `paper-25`, ruling-200 hairline, 4px radius, optional small-caps title over a hairline, 16px padding, no shadow.
- **DataTable** — the entry-line table: small-caps header over a double hairline, 44px hairline-ruled rows, paper-100 hover, selected row marked with the 2px ruling-600 inset bar, tabular numerals throughout, optional mobile stacked cards, optional custom empty state.
- **Dialog** — Radix modal: paper-25 panel, 6px radius, ruling-200 hairline, `shadow-lg` over `ink-950/40` scrim; built-in Title/Description/Close.
- **Tooltip** — Radix tooltip inverted to ink-900 ground, paper text.
- **Tabs** — Radix tabs as ledger index tabs; active is ink text over a 2px ruling-700 underline; inactive is ink-500.
- **Toast** — bottom-right viewport; tones reuse Stamp tones; 5s auto-dismiss; `role="status"`; `useToast()` hook.
- **Skeleton** — pulsing `paper-150` block for loading registers.
- **EmptyState** — blank folio: centered small-caps title, one-line ink-500 explanation, optional action slot.
- **Kbd** — 10px mono key cap, 3px radius, ruled border, ink-200 baseline shadow.
- **CopyButton / DigestText** — mono digest display truncated first-10…last-8 with copy-to-clipboard and a copied confirmation.
- **LifecycleRail** — horizontal station rail draft → validated → submitted → approved → committed: small-caps stations strung on the shared hairline; passed dots seal-600, the active dot amber-screen-600, future dots hollow ruling-400 outlines; rejection renders a vermilion branch with a cross tick. `aria-current="step"` rides the active station.
- **FindingCard** — validation finding: severity Stamp (error→vermilion, warning→amber, info→ruling), mono code chip, prose message, indented REPAIR small-caps block, subject ids as DigestText.
- **DiffRowView** — one entry-line diff: mono object-id/field-path header; `-` before-lines in ink-500 and `+` after-lines set on the hairline grid; superseded edits flagged with an amber note.
- **PageHeader** — register page header: small-caps kicker, 24px semibold title, optional mono meta line, right-aligned actions slot, closing hairline.
- **SectionHeading** — small-caps section label with trailing hairline.

**Navigation:** rail items are 44px tall, icon 17px at 1.75 stroke; active state is paper-100 ground plus the 2px ruling-600 inset bar; collapsed mode explains itself with right-side tooltips. Six destinations: Overview, ChangeSets, Released Content, Editions & Releases, Proofs & Evidence, Authority. Unknown routes redirect to /overview.

## Do's and Don'ts

### Do:
- **Do** draw all structure with 1px `ruling-200` hairlines and earn hierarchy from spacing and type, not boxes.
- **Do** render every status through `Stamp` with `stampToneForStatus`; new statuses join the map, never bypass it.
- **Do** reserve `consequential-600` for Approve, Commit, Release, Revoke, and New ChangeSet.
- **Do** set every id, digest, and timestamp in Spline Sans Mono; truncate digests 10…8 and offer copy.
- **Do** keep identifiers unbroken — nowrap with ellipsis, digest-style.
- **Do** use tabular numerals for all aligned figures.
- **Do** gate every transition at 150ms color-only with `motion-reduce:transition-none`.
- **Do** mark synthetic records visibly (SYNTHETIC DEMO DATA chip beside the workspace name).

### Don't:
- **Don't** add drop shadows outside dialogs, the palette, and menus — depth is paper tone and hairlines.
- **Don't** nest bordered boxes; panels don't go inside panels.
- **Don't** invent color families, and never let seal/vermilion/amber decorate non-status UI.
- **Don't** box inputs — fields are ruled underlines.
- **Don't** fake physicality (no bevels, embossing, or paper texture images); the stamp is typographic.
- **Don't** exceed the 24px title size or introduce new type voices.

## Keyboard & Command Palette

The console is keyboard-first. Global `:focus-visible` is a 2px `ruling-600` outline offset 2px. The command palette opens with Cmd/Ctrl+K anywhere (or the topbar search button): a paper-25 sheet at 12vh, max-w-xl, over the ink scrim. Its mono input (`role="combobox"`) fuzzy-scores destinations and quick actions (New ChangeSet, Validate a ChangeSet, Cut an edition) into small-caps-grouped results; arrow keys move with `aria-activedescendant`, Enter opens, Esc closes, and focus returns to the trigger. A Kbd footer documents ↑↓ Move · ↵ Open · Esc Close; empty groups render nothing rather than orphaned headers. Table rows are tabbable and commit with Enter/Space; menus close on Esc and outside-pointer-down; Radix handles dialog/tab focus trapping.

## Accessibility Floor

Target WCAG 2.2 AA. Color-scheme is light-only with a themed selection (`ruling-200` ground, `ink-950` text). Every interactive element is keyboard reachable with visible focus; icon buttons require `aria-label`; table headers carry `scope="col"`; toasts announce via `role="status"`; the lifecycle rail exposes `aria-current="step"`; the demo-data chip explains itself in its `title`. All motion collapses under `prefers-reduced-motion` (transitions removed, skeleton pulse aside per implementation — verify per element when extending). Status is never carried by color alone: every verdict pairs its stamp ink with readable uppercase text, and rail stations pair dots with labels.
