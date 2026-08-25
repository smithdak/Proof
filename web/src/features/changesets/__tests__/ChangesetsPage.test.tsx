import { describe, expect, it } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router";
import ChangesetsPage from "../ChangesetsPage";

function renderRegister() {
  return render(
    <MemoryRouter initialEntries={["/changesets"]}>
      <Routes>
        <Route path="/changesets" element={<ChangesetsPage />} />
        <Route
          path="/changesets/:changesetId"
          element={<div>detail-marker</div>}
        />
      </Routes>
    </MemoryRouter>,
  );
}

describe("ChangesetsPage", () => {
  it("renders an entry line for every seeded changeset", () => {
    renderRegister();

    expect(
      screen.getByText(
        "Localize the launch homepage hero and navigation into fr-CA per campaign brief v3",
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        "Refresh de-DE terminology per legal glossary 2026-08 revision",
      ),
    ).toBeInTheDocument();
    expect(screen.getAllByRole("columnheader")).toHaveLength(7);
  });

  it("navigates to the detail route on row click", () => {
    renderRegister();

    const row = screen.getByText("cs-01j9x77bwz2d6s48").closest("tr")!;
    fireEvent.click(row);

    expect(screen.getByText("detail-marker")).toBeInTheDocument();
  });

  it("navigates to the detail route via keyboard activation", () => {
    renderRegister();

    const row = screen.getByText("cs-01j9x69hnq8f1v33").closest("tr")!;
    fireEvent.keyDown(row, { key: "Enter" });

    expect(screen.getByText("detail-marker")).toBeInTheDocument();
  });

  it("opens a draft entry optimistically from the New ChangeSet dialog", async () => {
    renderRegister();

    fireEvent.click(screen.getByRole("button", { name: "New ChangeSet" }));
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Open entry" }),
    ).toBeDisabled();

    fireEvent.change(screen.getByLabelText("Intent"), {
      target: { value: "Add FAQ entry covering enterprise billing" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Open entry" }));

    expect(
      await screen.findByText("Add FAQ entry covering enterprise billing"),
    ).toBeInTheDocument();
    expect(screen.getByText("ChangeSet opened")).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
});
