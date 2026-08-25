import type {
  ChangesetDiff,
  DeliveryRecord,
  Edition,
  EvidenceExportSummary,
  Release,
  ReleasedObject,
  ValidationResult,
  VerificationReport,
} from "@/api/types";
import { minutesAgo } from "./seed-core";

export const diffs: Record<string, ChangesetDiff> = {
  "cs-01j9x85rfq7h3n20": {
    changeset_id: "cs-01j9x85rfq7h3n20",
    rows: [
      {
        object_id: "obj-home-hero",
        schema_id: "sch-hero@3",
        locale: "fr-CA",
        field_path: "headline",
        before: "Ship content you can prove.",
        after: "Publiez du contenu verifiable de bout en bout.",
        edit_ids: ["ed-01j9x85s1a2b3c40"],
      },
      {
        object_id: "obj-home-hero",
        schema_id: "sch-hero@3",
        locale: "fr-CA",
        field_path: "subheadline",
        before: "Governed changes. Verifiable releases.",
        after: "Modifications gouvernees. Publications verificables.",
        edit_ids: ["ed-01j9x85s1a2b3c41"],
      },
      {
        object_id: "obj-home-nav",
        schema_id: "sch-navigation@1",
        locale: "fr-CA",
        field_path: "items[0].label",
        before: "Product",
        after: "Produit",
        edit_ids: ["ed-01j9x85s1a2b3c42"],
      },
      {
        object_id: "obj-home-cta",
        schema_id: "sch-cta@2",
        locale: "fr-CA",
        field_path: "label",
        before: "Start free",
        after: "Commencer gratuitement",
        edit_ids: ["ed-01j9x85s1a2b3c43"],
      },
    ],
  },
};

export const validationResults: Record<string, ValidationResult> = {
  "cs-01j9x85rfq7h3n20": {
    changeset_id: "cs-01j9x85rfq7h3n20",
    verdict: "accepted",
    findings: [
      {
        code: "VAL-108",
        severity: "info",
        message:
          "Locale rendition fr-CA created for obj-home-hero; source revision untouched.",
        subject: { object_id: "obj-home-hero", field_path: "headline" },
      },
      {
        code: "VAL-204",
        severity: "warning",
        message:
          "Glossary term 'verifiable' preferred over 'prouvable' in fr-CA marketing register.",
        repair_guidance:
          "Optional: align with terminology pack 2026-06 entry 12.",
        subject: { edit_id: "ed-01j9x85s1a2b3c40", field_path: "headline" },
      },
    ],
    ruleset_digest: "blake3:c02f41ae89d73b5610e48c2fa96b50d17e382c64b09513ad",
    validated_at: minutesAgo(33),
  },
  "cs-01j9x77bwz2d6s48": {
    changeset_id: "cs-01j9x77bwz2d6s48",
    verdict: "rejected",
    findings: [
      {
        code: "VAL-311",
        severity: "error",
        message:
          "Prohibited legal claim: superlative warranty assertion in fr-CA is not permitted by policy legal-claims-v4.",
        repair_guidance:
          "Remove the superlative or cite a substantiated source; append a superseding Edit to this ChangeSet.",
        subject: {
          edit_id: "ed-01j9x77c0f1g2h60",
          object_id: "obj-warranty-fr",
          field_path: "claims[0].text",
        },
      },
    ],
    ruleset_digest: "blake3:88e04c17ba62d95310f7cb4ea05821d609374f52ac8631be",
    validated_at: minutesAgo(199),
  },
};

export const editions: Record<string, Edition> = {
  "edn-01j9x70cdk5m2v81": {
    edition_id: "edn-01j9x70cdk5m2v81",
    changeset_id: "cs-01j9x69hnq8f1v33",
    created_at: minutesAgo(300),
    content_digest: "blake3:f31b82ce40597a26d8014c7fb39e50a24d6170c93e582bf0",
    object_count: 4,
    locales: ["de-DE"],
  },
  "edn-01j9x86kgq3n8w92": {
    edition_id: "edn-01j9x86kgq3n8w92",
    changeset_id: "cs-01j9x85rfq7h3n20",
    created_at: minutesAgo(40),
    content_digest: "blake3:a47d10fe93b52c68d0714e2ca85f30b96d2405187cef36a1",
    object_count: 3,
    locales: ["fr-CA"],
  },
};

export const releases: Record<string, Release> = {
  "rel-01j9x71dlm6p3x42": {
    release_id: "rel-01j9x71dlm6p3x42",
    edition_id: "edn-01j9x70cdk5m2v81",
    environment: "preview",
    created_at: minutesAgo(295),
    created_by: {
      principal_id: "prin-human-amara",
      kind: "human",
      display_name: "Amara Okafor",
    },
    envelope_digest: "blake3:d5820aec74f19b3602e84d51ca730b85e2946170d3cf28a1",
    signature_key_id:
      "ed25519:2c94f61ba08e35d72c419fa60bd25e83f170c49b3ae581d2",
  },
  "rel-01j9x86kfm2w9d71": {
    release_id: "rel-01j9x86kfm2w9d71",
    edition_id: "edn-01j9x86kgq3n8w92",
    environment: "preview",
    created_at: minutesAgo(38),
    created_by: {
      principal_id: "prin-human-smithdak",
      kind: "human",
      display_name: "Dakota Smith",
    },
    envelope_digest: "blake3:71c03e59da8462b15093e6c4fa2817d50b3496e281acf702",
    signature_key_id:
      "ed25519:2c94f61ba08e35d72c419fa60bd25e83f170c49b3ae581d2",
  },
};

export const verificationReports: Record<string, VerificationReport> = {
  "rel-01j9x71dlm6p3x42": {
    release_id: "rel-01j9x71dlm6p3x42",
    verdict: "Complete",
    checked_at: minutesAgo(280),
    trust_basis: "Caller-supplied Ed25519 trust set + authority-head checkpoint",
    roots: [
      { root: "content", label: "Edition content closure", status: "passed" },
      { root: "authority", label: "Authority and delegation chain", status: "passed" },
      { root: "validation", label: "Deterministic validation evidence", status: "passed" },
      { root: "approval", label: "Human approval decision", status: "passed" },
      { root: "policy", label: "Policy evaluation closure", status: "passed" },
      { root: "release", label: "Release binding and signature", status: "passed" },
    ],
  },
  "rel-01j9x86kfm2w9d71": {
    release_id: "rel-01j9x86kfm2w9d71",
    verdict: "Incomplete",
    checked_at: minutesAgo(20),
    trust_basis: "Caller-supplied Ed25519 trust set (no checkpoint supplied)",
    roots: [
      { root: "content", label: "Edition content closure", status: "passed" },
      { root: "authority", label: "Authority and delegation chain", status: "passed" },
      { root: "validation", label: "Deterministic validation evidence", status: "passed" },
      { root: "approval", label: "Human approval decision", status: "passed" },
      {
        root: "policy",
        label: "Policy evaluation closure",
        status: "not_evaluated",
        detail: "Policy root requires an authority-head checkpoint that was not supplied.",
      },
      { root: "release", label: "Release binding and signature", status: "passed" },
    ],
  },
};

export const releasedObjects: ReleasedObject[] = [
  {
    object_id: "obj-home-hero",
    schema_id: "sch-hero@3",
    locale: "fr-CA",
    fields: {
      headline: "Publiez du contenu verifiable de bout en bout.",
      subheadline: "Modifications gouvernees. Publications verificables.",
      cta_label: "Commencer gratuitement",
    },
    edition_id: "edn-01j9x86kgq3n8w92",
    release_id: "rel-01j9x86kfm2w9d71",
    released_at: minutesAgo(38),
  },
  {
    object_id: "obj-terms-de",
    schema_id: "sch-terms@5",
    locale: "de-DE",
    fields: {
      sections: "5 sections; section 4 body updated per glossary 2026-08",
    },
    edition_id: "edn-01j9x70cdk5m2v81",
    release_id: "rel-01j9x71dlm6p3x42",
    released_at: minutesAgo(295),
  },
];

export const deliveries: DeliveryRecord[] = [
  {
    delivery_id: "dlv-01j9x87hnr4t1y83",
    environment: "preview",
    subscriber: "preview-render-service",
    state: "delivered",
    attempts: 1,
    last_attempt_at: minutesAgo(37),
  },
  {
    delivery_id: "dlv-01j9x87jps5u2z94",
    environment: "staging",
    subscriber: "search-indexer",
    state: "pending",
    attempts: 0,
    next_attempt_at: minutesAgo(-2),
  },
];

export const evidenceExports: EvidenceExportSummary[] = [
  {
    export_id: "evx-01j9x88ktu6v3a05",
    release_id: "rel-01j9x86kfm2w9d71",
    created_at: minutesAgo(15),
    artifact_count: 42,
    bundle_format: "RemoteEvidenceBundleV2",
    verifier_conclusion: "Incomplete",
  },
];
