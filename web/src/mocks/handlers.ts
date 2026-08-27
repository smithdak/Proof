import { delay, http, HttpResponse, type HttpHandler } from "msw";
import type { ChangeSet, OperationResult } from "@/api/types";
import { principals, session, workspaceStatus } from "./seed-core";
import { edits, supersessions } from "./seed-edits";
import {
  deliveries,
  diffs,
  evidenceExports,
  releasedObjects,
  releases,
  validationResults,
  verificationReports,
} from "./seed-content";

/**
 * Contract-faithful mock handlers over the exact nine-route surface.
 * Operations resolve against the seeded synthetic workspace with realistic
 * latency so loading and pending states are exercised honestly.
 */

function ok<T>(result: T): HttpResponse<OperationResult<T>> {
  return HttpResponse.json({ outcome: "committed", result });
}

const LATENCY: [number, number] = [180, 420];

const latency = () =>
  delay(LATENCY[0] + Math.random() * (LATENCY[1] - LATENCY[0]));

export const handlers: HttpHandler[] = [
  // -- transport-session routes ------------------------------------------------
  http.get("*/api/v1/session", async () => {
    return HttpResponse.json(session);
  }),

  http.post("*/api/v1/session/logout", async ({ request }) => {
    await latency();
    if (request.headers.get("proof-csrf") !== session.csrf_token) {
      return HttpResponse.json(
        { code: "proof.csrf_invalid", detail: "Invalid CSRF synchronizer" },
        { status: 403 },
      );
    }
    return HttpResponse.json({
      api_version: "proof.dev/session-logout-result/v1",
      logged_out: true,
    });
  }),

  http.get("*/api/v1/capabilities", async () => {
    await latency();
    return HttpResponse.json({
      route_count: 9,
      operations: [
        "workspace.status",
        "capabilities.discover",
        "changeset.create",
        "changeset.add",
        "changeset.diff",
        "changeset.get",
        "changeset.validate",
        "changeset.submit",
        "changeset.approve",
        "changeset.commit",
        "edition.create",
        "release.create",
        "release.get",
        "release.verify",
        "object.query_released",
        "evidence.export",
        "delegation.issue",
        "delegation.revoke",
        "delivery.get",
        "delivery.replay",
        "delivery.abandon",
        "context.build",
      ],
    });
  }),

  // -- human operations dispatch ----------------------------------------------
  http.post(
    "*/api/v1/human/operations/workspace.status/1",
    async () => {
      await latency();
      return ok(workspaceStatus);
    },
  ),

  http.post("*/api/v1/human/operations/changeset.get/1", async ({ request }) => {
    await latency();
    const body = (await request.json()) as { changeset_id?: string };
    const { changesets } = await import("./seed-core");
    const found = changesets.find((c) => c.changeset_id === body.changeset_id);
    if (!found) {
      return HttpResponse.json(
        { code: "changeset.not_found", detail: "No such ChangeSet" },
        { status: 404 },
      );
    }
    return ok(found satisfies ChangeSet);
  }),

  http.post("*/api/v1/human/operations/changeset.diff/1", async ({ request }) => {
    await latency();
    const body = (await request.json()) as { changeset_id?: string };
    const diff = diffs[body.changeset_id ?? ""];
    if (!diff) {
      return HttpResponse.json(
        { code: "changeset.diff_unavailable", detail: "Diff not available" },
        { status: 404 },
      );
    }
    return ok(diff);
  }),

  http.post("*/api/v1/human/operations/changeset.validate/1", async () => {
    await latency();
    return ok(validationResults["cs-01j9x85rfq7h3n20"]!);
  }),

  http.post("*/api/v1/human/operations/release.get/1", async ({ request }) => {
    await latency();
    const body = (await request.json()) as { release_id?: string };
    const found = releases[body.release_id ?? ""];
    if (!found) {
      return HttpResponse.json(
        { code: "release.not_found", detail: "No such Release" },
        { status: 404 },
      );
    }
    return ok({ ...found, latest_verification: verificationReports[body.release_id ?? ""] });
  }),

  http.post("*/api/v1/human/operations/release.verify/1", async ({ request }) => {
    await latency();
    const body = (await request.json()) as { release_id?: string };
    const report = verificationReports[body.release_id ?? ""];
    if (!report) {
      return HttpResponse.json(
        { code: "release.not_verified", detail: "No persisted verification" },
        { status: 404 },
      );
    }
    return ok(report);
  }),

  http.post(
    "*/api/v1/human/operations/object.query_released/1",
    async () => {
      await latency();
      return ok(releasedObjects);
    },
  ),

  http.post("*/api/v1/human/operations/evidence.export/1", async () => {
    await latency();
    return ok(evidenceExports);
  }),

  http.post("*/api/v1/human/operations/delivery.get/1", async () => {
    await latency();
    return ok(deliveries);
  }),

  http.post(
    "*/api/v1/human/operations/delegation.issue/1",
    async ({ request }) => {
      await latency();
      const body = (await request.json()) as Record<string, unknown>;
      void principals;
      void edits;
      void supersessions;
      void session;
      return ok({ acknowledged: true, delegation: body });
    },
  ),
];
