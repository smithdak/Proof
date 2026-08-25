import { describe, expect, it } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router";
import ReleasesPage from "../ReleasesPage";

function renderRegister() {
  return render(
    <MemoryRouter initialEntries={["/releases"]}>
      <Routes>
        <Route path="/releases" element={<ReleasesPage />} />
        <Route path="/releases/:releaseId" element={<div>detail-marker</div>} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("ReleasesPage", () => {
  it("renders an entry line for every seeded edition and release", () => {
    renderRegister();

    for (const id of [
      "edn-01j9x70cdk5m2v81",
      "edn-01j9x86kgq3n8w92",
      "rel-01j9x71dlm6p3x42",
      "rel-01j9x86kfm2w9d71",
    ]) {
      expect(screen.getAllByText(id).length).toBeGreaterThan(0);
    }

    const tables = screen.getAllByRole("table");
    expect(tables).toHaveLength(2);
    const editionTable = tables[0]!;
    const releaseTable = tables[1]!;
    expect(editionTable.querySelectorAll("thead th")).toHaveLength(5);
    expect(releaseTable.querySelectorAll("thead th")).toHaveLength(6);
  });

  it("shows the latest verification verdict as a stamp per release", () => {
    renderRegister();

    expect(screen.getByText("Complete")).toBeInTheDocument();
    expect(screen.getByText("Incomplete")).toBeInTheDocument();
  });

  it("renders content digests as mono digest text with full value in title", () => {
    renderRegister();

    expect(
      screen.getByTitle(
        "blake3:a47d10fe93b52c68d0714e2ca85f30b96d2405187cef36a1",
      ),
    ).toBeInTheDocument();
  });

  it("navigates to the detail route on row click", () => {
    renderRegister();

    const row = screen.getByText("rel-01j9x71dlm6p3x42").closest("tr")!;
    fireEvent.click(row);

    expect(screen.getByText("detail-marker")).toBeInTheDocument();
  });

  it("navigates to the detail route via keyboard activation", () => {
    renderRegister();

    const row = screen.getByText("rel-01j9x86kfm2w9d71").closest("tr")!;
    fireEvent.keyDown(row, { key: "Enter" });

    expect(screen.getByText("detail-marker")).toBeInTheDocument();
  });
});
