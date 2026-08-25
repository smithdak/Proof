import type {
  ChangeSet,
  DelegationRef,
  Principal,
  SessionInfo,
  WorkspaceStatus,
} from "@/api/types";

/**
 * Synthetic demonstration workspace — generated material for console
 * development, never customer data.
 *
 * Narrative follows the ratified north-star: a delegated localization
 * campaign (fr-CA, de-DE) over a product-launch subtree, with one prohibited
 * legal-claim translation rejected by deterministic validation.
 */

const NOW = Date.UTC(2026, 7, 24, 14, 5, 0);

export function minutesAgo(minutes: number): string {
  return new Date(NOW - minutes * 60_000).toISOString();
}

export const principals: Record<string, Principal> = {
  "prin-human-smithdak": {
    principal_id: "prin-human-smithdak",
    kind: "human",
    display_name: "Dakota Smith",
  },
  "prin-human-amara": {
    principal_id: "prin-human-amara",
    kind: "human",
    display_name: "Amara Okafor",
  },
  "prin-agent-locale7": {
    principal_id: "prin-agent-locale7",
    kind: "agent",
    display_name: "locale-agent-7",
    key_id:
      "ed25519:9f1c44e0a2b6d8f3c7e15a09b4d26f8831c0e5ad7b9f23c468ae1d5f0b7c9",
  },
  "prin-agent-migration": {
    principal_id: "prin-agent-migration",
    kind: "agent",
    display_name: "migration-partner-bot",
    key_id:
      "ed25519:41d8a9c2e67b05f31c9e8a74d20fb6c95e13a7f08bd4c62e91f75a3dc80e",
  },
};

export const session: SessionInfo = {
  authenticated: true,
  principal: {
    subject: "smithdak@proof-local",
    display_name: "Dakota Smith",
    kind: "human",
  },
  csrf_token: "csrf-dev-rotating-token",
};

export const workspaceStatus: WorkspaceStatus = {
  workspace_id: "ws-01j9x7q2vbn8k4m3",
  name: "Meridian Launch",
  known_state_digest: "blake3:6c1de83fa09b4725d8e3c1f0a49b62d7e5f80c3ba19d2467",
  environments: [
    { name: "preview", required_approval: "release" },
    { name: "staging", required_approval: "release" },
    { name: "production", required_approval: "release" },
  ],
  principal_count: 4,
  open_changesets: 4,
  last_release: {
    release_id: "rel-01j9x86kfm2w9d71",
    environment: "preview",
    created_at: minutesAgo(38),
  },
};

export const delegations: DelegationRef[] = [
  {
    delegation_id: "del-01j9x84pqt3n6r52",
    issued_by: "prin-human-smithdak",
    granted_to: "prin-agent-locale7",
    scope_summary:
      "Localize launch homepage + pricing subtree to fr-CA, de-DE for preview only",
    expires_at: new Date(Date.UTC(2026, 8, 7, 23, 59, 59)).toISOString(),
    revoked: false,
  },
  {
    delegation_id: "del-01j9x51hcn8q2z90",
    issued_by: "prin-human-smithdak",
    granted_to: "prin-agent-migration",
    scope_summary: "Import legacy articles (read-only source) for migration QA",
    expires_at: new Date(Date.UTC(2026, 7, 30, 23, 59, 59)).toISOString(),
    revoked: false,
  },
  {
    delegation_id: "del-01j9x22gkw5m8t14",
    issued_by: "prin-human-amara",
    granted_to: "prin-agent-locale7",
    scope_summary: "Terminology refresh for de-DE legal strings",
    expires_at: null,
    revoked: true,
  },
];

export const changesets: ChangeSet[] = [
  {
    changeset_id: "cs-01j9x85rfq7h3n20",
    intent:
      "Localize the launch homepage hero and navigation into fr-CA per campaign brief v3",
    status: "submitted",
    created_at: minutesAgo(52),
    created_by: principals["prin-agent-locale7"]!,
    delegation: {
      delegation_id: "del-01j9x84pqt3n6r52",
      granted_to: "prin-agent-locale7",
      issued_by: "prin-human-smithdak",
    },
    base_state_digest: "blake3:41d9a07ce58b3416d2f97c05be83a4617d29f5c08e3b6a42",
    locale_scope: ["fr-CA"],
    environment_scope: "preview",
    edit_count: 12,
    updated_at: minutesAgo(31),
  },
  {
    changeset_id: "cs-01j9x82mjw4k9t65",
    intent:
      "Localize pricing page tiers and billing FAQ into fr-CA and de-DE; exclude regulated claims",
    status: "draft",
    created_at: minutesAgo(95),
    created_by: principals["prin-agent-locale7"]!,
    delegation: {
      delegation_id: "del-01j9x84pqt3n6r52",
      granted_to: "prin-agent-locale7",
      issued_by: "prin-human-smithdak",
    },
    base_state_digest: "blake3:41d9a07ce58b3416d2f97c05be83a4617d29f5c08e3b6a42",
    locale_scope: ["fr-CA", "de-DE"],
    environment_scope: "preview",
    edit_count: 27,
    updated_at: minutesAgo(44),
  },
  {
    changeset_id: "cs-01j9x77bwz2d6s48",
    intent:
      "Legal-claim repair pass: replace prohibited superlative in fr-CA warranty copy",
    status: "rejected",
    created_at: minutesAgo(240),
    created_by: principals["prin-agent-locale7"]!,
    delegation: {
      delegation_id: "del-01j9x84pqt3n6r52",
      granted_to: "prin-agent-locale7",
      issued_by: "prin-human-smithdak",
    },
    base_state_digest: "blake3:9931cf57ae204b68d10e73c9f25a8d04b6173e92c508af11",
    locale_scope: ["fr-CA"],
    environment_scope: "preview",
    edit_count: 3,
    updated_at: minutesAgo(198),
  },
  {
    changeset_id: "cs-01j9x69hnq8f1v33",
    intent: "Refresh de-DE terminology per legal glossary 2026-08 revision",
    status: "committed",
    created_at: minutesAgo(420),
    created_by: principals["prin-human-amara"]!,
    base_state_digest: "blake3:0a74e91bd3562f80c9614e7ab28f50d13c6e94072b5d18ac",
    locale_scope: ["de-DE"],
    environment_scope: "preview",
    edit_count: 9,
    updated_at: minutesAgo(310),
  },
];
