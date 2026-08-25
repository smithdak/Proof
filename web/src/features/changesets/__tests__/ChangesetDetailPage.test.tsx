import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import type { ChangeSet } from "@/api/types";
import { changesets } from "@/mocks/seed-core";
import ChangesetDetailPage from "../ChangesetDetailPage";

const server = setupServer(
  http.post("*/api/v1/human/operations/changeset.get/1", async ({ request }) => {
    const body = (await request.json()) as { changeset_id?: string };
    const found: ChangeSet | undefined = changesets.find(
      (candidate) => candidate.changeset_id === body.changeset_id,
    );
    if (!found) {
      return HttpResponse.json(
        { code: "changeset.not_found", detail: "No such ChangeSet" },
        { status: 404 },
      );
    }
    return HttpResponse.json({ outcome: "committed", result: found });
  }),
);

beforeAll(() => server.listen());
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

function renderDetail(changesetId: string) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[`/changesets/${changesetId}`]}>
        <Routes>
          <Route path="/changesets" element={<div>register-marker</div>} />
          <Route
            path="/changesets/:changesetId"
            element={<ChangesetDetailPage />}
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("ChangesetDetailPage", () => {
  it("shows a reading skeleton while the entry loads", () => {
    renderDetail("cs-01j9x85rfq7h3n20");

    expect(
      screen.getByRole("status", { name: "Reading ChangeSet entry" }),
    ).toBeInTheDocument();
  });

  it("offers the register way back for an unknown id", async () => {
    renderDetail("cs-does-not-exist");

    expect(await screen.findByText("No such entry")).toBeInTheDocument();

    fireEvent.click(
      screen.getByRole("button", { name: /back to register/i }),
    );
    expect(screen.getByText("register-marker")).toBeInTheDocument();
  });

  it("walks a submitted entry through approval and commit with toasts", async () => {
    renderDetail("cs-01j9x85rfq7h3n20");

    expect(
      await screen.findByRole("heading", {
        level: 1,
        name: /localize the launch homepage hero/i,
      }),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Publiez du contenu verifiable de bout en bout."),
    ).toBeInTheDocument();

    fireEvent.mouseDown(screen.getByRole("tab", { name: "Findings" }));
    expect(
      await screen.findByText(
        "Glossary term 'verifiable' preferred over 'prouvable' in fr-CA marketing register.",
      ),
    ).toBeInTheDocument();

    fireEvent.mouseDown(screen.getByRole("tab", { name: "Edits" }));
    expect(await screen.findByText("ed-01j9x85s1a2b3c40")).toBeInTheDocument();

    fireEvent.mouseDown(screen.getByRole("tab", { name: "Diff" }));
    fireEvent.click(screen.getByRole("button", { name: "Approve" }));
    expect(await screen.findByRole("dialog")).toHaveTextContent(
      "Approve this ChangeSet?",
    );

    fireEvent.click(screen.getByRole("button", { name: "Approve entry" }));
    expect(await screen.findByText("Approval recorded")).toBeInTheDocument();
    expect(await screen.findByRole("button", { name: "Commit" })).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Commit" }));
    expect(await screen.findByRole("dialog")).toHaveTextContent(
      "Commit this ChangeSet?",
    );

    fireEvent.click(
      screen.getByRole("button", { name: "Commit irreversibly" }),
    );
    expect(await screen.findByText("ChangeSet committed")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Approve" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Commit" }),
    ).not.toBeInTheDocument();
  });

  it("surfaces the refusal banner, findings, and supersession note for a rejected entry", async () => {
    renderDetail("cs-01j9x77bwz2d6s48");

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("VAL-311");
    expect(alert).toHaveTextContent(/append a superseding edit/i);

    fireEvent.mouseDown(screen.getByRole("tab", { name: "Findings" }));
    expect(await screen.findByText(/prohibited legal claim/i)).toBeInTheDocument();

    fireEvent.mouseDown(screen.getByRole("tab", { name: "Edits" }));
    expect(
      await screen.findByText(/second attempt also rejected/i),
    ).toBeInTheDocument();
  });

  it("validates and submits a draft entry", async () => {
    renderDetail("cs-01j9x82mjw4k9t65");

    fireEvent.click(
      await screen.findByRole("button", { name: "Validate" }),
    );
    expect(
      await screen.findByText("Validation recorded"),
    ).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Submit" }));
    expect(
      await screen.findByText("Submitted for approval"),
    ).toBeInTheDocument();
    expect(
      await screen.findByRole("button", { name: "Approve" }),
    ).toBeInTheDocument();
  });
});
