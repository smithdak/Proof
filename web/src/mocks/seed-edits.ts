import type { ChangeSetEdit } from "@/api/types";

export const edits: Record<string, ChangeSetEdit[]> = {
  "cs-01j9x85rfq7h3n20": [
    {
      edit_id: "ed-01j9x85s1a2b3c40",
      object_id: "obj-home-hero",
      schema_id: "sch-hero@3",
      locale: "fr-CA",
      op: "set",
      field_path: "headline",
      before: "Ship content you can prove.",
      after: "Publiez du contenu verifiable de bout en bout.",
      rationale: "Campaign brief v3 section 2.1; avoids the legal sense of the literal translation",
    },
    {
      edit_id: "ed-01j9x85s1a2b3c41",
      object_id: "obj-home-hero",
      schema_id: "sch-hero@3",
      locale: "fr-CA",
      op: "set",
      field_path: "subheadline",
      before: "Governed changes. Verifiable releases.",
      after: "Modifications gouvernees. Publications verificables.",
    },
    {
      edit_id: "ed-01j9x85s1a2b3c42",
      object_id: "obj-home-nav",
      schema_id: "sch-navigation@1",
      locale: "fr-CA",
      op: "set",
      field_path: "items[0].label",
      before: "Product",
      after: "Produit",
    },
    {
      edit_id: "ed-01j9x85s1a2b3c43",
      object_id: "obj-home-cta",
      schema_id: "sch-cta@2",
      locale: "fr-CA",
      op: "set",
      field_path: "label",
      before: "Start free",
      after: "Commencer gratuitement",
    },
  ],
  "cs-01j9x82mjw4k9t65": [
    {
      edit_id: "ed-01j9x82m2d4e6f80",
      object_id: "obj-pricing-tiers",
      schema_id: "sch-pricing@4",
      locale: "fr-CA",
      op: "set",
      field_path: "tiers[0].name",
      before: "Starter",
      after: "Depart",
    },
    {
      edit_id: "ed-01j9x82m2d4e6f81",
      object_id: "obj-pricing-faq",
      schema_id: "sch-faq@2",
      locale: "de-DE",
      op: "set",
      field_path: "entries[2].answer",
      before: "Rechnungen werden monatlich gestellt.",
      after: "Rechnungen werden monatlich am ersten Werktag gestellt.",
      rationale: "Billing FAQ alignment with EU invoicing terms",
    },
  ],
  "cs-01j9x77bwz2d6s48": [
    {
      edit_id: "ed-01j9x77c0f1g2h60",
      object_id: "obj-warranty-fr",
      schema_id: "sch-warranty@1",
      locale: "fr-CA",
      op: "set",
      field_path: "claims[0].text",
      before: "La garantie la plus fiable du marche.",
      after: "Une garantie backed par un proces-verifiable.",
      rationale: "Repair attempt for finding VAL-311; still prohibited phrasing",
    },
  ],
  "cs-01j9x69hnq8f1v33": [
    {
      edit_id: "ed-01j9x69i2j3k4l80",
      object_id: "obj-terms-de",
      schema_id: "sch-terms@5",
      locale: "de-DE",
      op: "replace",
      field_path: "sections[4].body",
      before: "Der Anbieter haftet unbeschadet...",
      after: "Der Anbieter haftet im Rahmen der gesetzlichen Bestimmungen...",
      rationale: "Glossary 2026-08 revision, term 41",
    },
  ],
};

/** Superseding-edit chains keyed by the superseded edit id (repair model). */
export const supersessions: Record<string, string> = {
  "ed-01j9x77c0f1g2h60":
    "Repair appended in-place; second attempt also rejected by VAL-311",
};
