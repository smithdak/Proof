import { useSyncExternalStore } from "react";
import type { ChangeSet, ChangeSetStatus } from "@/api/types";
import { changesets as seededChangesets, principals, workspaceStatus } from "@/mocks/seed-core";

const listeners = new Set<() => void>();

let entries: ChangeSet[] = [...seededChangesets];

function publish(next: ChangeSet[]): void {
  entries = next;
  listeners.forEach((listener) => listener());
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

function getSnapshot(): ChangeSet[] {
  return entries;
}

export function useChangesets(): ChangeSet[] {
  return useSyncExternalStore(subscribe, getSnapshot, getSnapshot);
}

export function readChangeset(changesetId: string): ChangeSet | undefined {
  return entries.find((entry) => entry.changeset_id === changesetId);
}

let localSequence = 0;

function nextLocalId(): string {
  localSequence += 1;
  const stem = Date.now().toString(36).toUpperCase();
  return `cs-local-${stem}${String(localSequence).padStart(3, "0")}`;
}

export function createDraft(input: { intent: string }): ChangeSet {
  const intent = input.intent.trim();
  if (!intent) {
    throw new Error("A ChangeSet requires an intent");
  }
  const now = new Date().toISOString();
  const entry: ChangeSet = {
    changeset_id: nextLocalId(),
    intent,
    status: "draft",
    created_at: now,
    created_by: principals["prin-human-smithdak"]!,
    base_state_digest: workspaceStatus.known_state_digest,
    locale_scope: [],
    edit_count: 0,
    updated_at: now,
  };
  publish([entry, ...entries]);
  return entry;
}

function recordStatus(changesetId: string, status: ChangeSetStatus): void {
  const now = new Date().toISOString();
  publish(
    entries.map((entry) =>
      entry.changeset_id === changesetId
        ? { ...entry, status, updated_at: now }
        : entry,
    ),
  );
}

export const operations = {
  validate: (changesetId: string) => recordStatus(changesetId, "validated"),
  submit: (changesetId: string) => recordStatus(changesetId, "submitted"),
  approve: (changesetId: string) => recordStatus(changesetId, "approved"),
  commit: (changesetId: string) => recordStatus(changesetId, "committed"),
};
