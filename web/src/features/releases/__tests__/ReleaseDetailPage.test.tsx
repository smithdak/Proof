import { describe, expect, it } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router";
import ReleaseDetailPage from "../ReleaseDetailPage";

const COMPLETE_RELEASE = "rel-01j9x71dlm6p3x42";
const INCOMPLETE_RELEASE = "rel-01j9x86kfm2w9d71";

function renderDetail(releaseId: string) {
  return render(
    <MemoryRouter initialEntries={[`/releases/${releaseId}`]}>
      <Routes>
        <Route path="/releases" element={<div>register-marker</div>} />
        <Route path="/releases/:releaseId" element={<ReleaseDetailPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("ReleaseDetailPage", () => {
  it("renders the release record with signature key and envelope digests", () => {
    renderDetail(COMPLETE_RELEASE);

    expect(screen.getByText(COMPLETE_RELEASE)).toBeInTheDocument();
    expect(
      screen.getByTitle(
        "ed25519:2c94f61ba08e35d72c419fa60bd25e83f170c49b3ae581d2",
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByTitle(
        "blake3:d5820aec74f19b3602e84d51ca730b85e2946170d3cf28a1",
      ),
    ).toBeInTheDocument();
  });

  it("renders the verification report with a big verdict stamp and the six-root checklist", () => {
    renderDetail(COMPLETE_RELEASE);

    expect(screen.getByText("Verification report")).toBeInTheDocument();
    expect(screen.getByText("Complete")).toBeInTheDocument();

    for (const label of [
      "Edition content closure",
      "Authority and delegation chain",
      "Deterministic validation evidence",
      "Human approval decision",
      "Policy evaluation closure",
      "Release binding and signature",
    ]) {
      expect(screen.getByText(label)).toBeInTheDocument();
    }
    expect(screen.getAllByText("passed")).toHaveLength(6);
  });

  it("renders trust basis as small-caps meta and checked_at as a mono timestamp", () => {
    renderDetail(COMPLETE_RELEASE);

    expect(screen.getByText("Trust basis")).toBeInTheDocument();
    expect(
      screen.getByText(
        "Caller-supplied Ed25519 trust set + authority-head checkpoint",
      ),
    ).toBeInTheDocument();
    // seed clock: 2026-08-24T14:05Z minus 280min -> 09:25Z
    expect(
      screen.getByText((_, element) => element?.textContent === "2026-08-24 09:25Z"),
    ).toBeInTheDocument();
  });

  it("renders not_evaluated roots with their detail line", () => {
    renderDetail(INCOMPLETE_RELEASE);

    expect(screen.getByText("Incomplete")).toBeInTheDocument();
    expect(screen.getByText("not_evaluated")).toBeInTheDocument();
    expect(screen.getAllByText("passed")).toHaveLength(5);
    expect(
      screen.getByText(
        "Policy root requires an authority-head checkpoint that was not supplied.",
      ),
    ).toBeInTheDocument();
  });

  it("falls back to a not-found state with a way back to the register", () => {
    renderDetail("rel-does-not-exist");

    expect(screen.getByText("No such entry")).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /Back to register/ }));
    expect(screen.getByText("register-marker")).toBeInTheDocument();
  });

  it("queues a replay for an actionable delivery by toast", async () => {
    renderDetail(COMPLETE_RELEASE);

    fireEvent.click(
      screen.getByRole("button", { name: "Replay delivery dlv-01j9x87jps5u2z94" }),
    );

    expect(await screen.findByText("Replay queued")).toBeInTheDocument();
  });

  it("disables replay and abandon for settled deliveries", () => {
    renderDetail(COMPLETE_RELEASE);

    expect(
      screen.getByRole("button", { name: "Replay delivery dlv-01j9x87hnr4t1y83" }),
    ).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "Abandon delivery dlv-01j9x87hnr4t1y83" }),
    ).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "Abandon delivery dlv-01j9x87jps5u2z94" }),
    ).toBeEnabled();
  });
});
