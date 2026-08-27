import type {
  LocalizedObjectCreateEditInput,
  LocalizedObjectLocalePutEditInput,
  LocalizedSemanticEditInput,
} from "../src/types";

const freshCreate: LocalizedObjectCreateEditInput = {
  api_version: "proof.dev/edit/v2",
  kind: "object.create",
  object_id: "019e0000-0000-7000-8000-000000000101",
  schema_id: "article",
  schema_version: 1,
  content: { title: "Created" },
  repair_of_validation_result_digest: null,
  supersedes_edit_id: null,
};

const localePut: LocalizedObjectLocalePutEditInput = {
  api_version: "proof.dev/edit/v2",
  kind: "object.locale.put",
  object_id: "019e0000-0000-7000-8000-000000000101",
  locale: "en-US",
  content: { title: "Localized" },
  expected_source: {
    digest: "blake3:source",
    revision: 1,
    schema_id: "article",
    schema_version: 1,
  },
  expected_target: null,
  repair_of_validation_result_digest: null,
  supersedes_edit_id: null,
};

const accepted: LocalizedSemanticEditInput[] = [freshCreate, localePut];
void accepted;

const mixedCreate: LocalizedObjectCreateEditInput = {
  ...freshCreate,
  // @ts-expect-error object.create forbids locale-put members.
  locale: "en-US",
};
void mixedCreate;

const mixedPut: LocalizedObjectLocalePutEditInput = {
  ...localePut,
  // @ts-expect-error object.locale.put forbids creation-only members.
  schema_id: "article",
};
void mixedPut;
