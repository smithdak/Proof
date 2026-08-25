# P-0016 execution receipt

- Item: P-0016 Initial human web console with notarial-register design system
- Executor: ox-alpha (overnight swarm, streams A-H)
- Date: 2026-08-24/25
- Base SHA: 7e8162e (feat(p0015): mirror context.build/v2 onto the postgres parity backend)

## Environment

- node v22.23.2, pnpm 11.22.0, Rust toolchain untouched
- Chromium (Playwright build 1234) with local LD_LIBRARY_PATH shim
  (/tmp/opencode/libs) because passwordless sudo was unavailable for
  system browser dependencies

## Command log (all run from web/ unless noted)

| Command | Result |
| --- | --- |
| pnpm install | ok (lockfile created; esbuild/msw builds approved via pnpm-workspace.yaml) |
| pnpm exec msw init public/ | ok (mockServiceWorker.js generated) |
| pnpm typecheck | ok at every wave commit |
| pnpm lint | 0 errors; 2 pre-existing react-refresh warnings from contract-mandated co-exports |
| pnpm test | 12/12 (wave 1) -> 43/43 (wave 2) -> 45/45 (final) |
| pnpm build | ok; final bundle ~451 kB JS / 34 kB CSS gzip 145/34 kB |
| node scripts/capture.mjs | 19 captures (9 routes x 2 viewports + palette), .impeccable/review/ |
| node .agents/skills/impeccable/scripts/detect.mjs --json src | [] (zero findings) |
| node scripts/check-work-items.mjs (repo root) | run at close-out; see manifest |

## Swarm streams

- A primitives (23 components + tests), B shell/palette/session,
  D changesets workspace, E releases/proofs, F objects/authority,
  G batched visual fix round (8 findings), H mobile card layout (2 fixes).
- Reports: .swarm-reports/p0016-*.md

## Residual risks / follow-ups

1. Mock payload shapes are console-side projections; byte-level parity with
   proof-remote payloads is unverified (tracked in item non-goals).
2. Production embedding into axum requires an ADR (frozen route contract).
3. Live OIDC/PostgreSQL wiring unattempted; MSW-only tonight.
4. Two lint warnings (react-refresh) accepted from contract-mandated
   co-exports (stampToneForStatus, useToast).
5. Playwright browsers need LD_LIBRARY_PATH shim on this machine until
   system libs are installed with sudo.
