import { describe, expect, it } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
import ProofsPage from "../ProofsPage";

describe("ProofsPage", () => {
  it("renders an evidence export entry line for every seeded export", () => {
    render(<ProofsPage />);

    // Row content renders twice by design (mobile cards + desktop table).
    expect(screen.getAllByText("evx-01j9x88ktu6v3a05")).not.toHaveLength(0);
    expect(screen.getAllByText("rel-01j9x86kfm2w9d71")).not.toHaveLength(0);
    expect(screen.getAllByText("RemoteEvidenceBundleV2")).not.toHaveLength(0);
    expect(screen.getByText("42")).toBeInTheDocument();
    expect(screen.getAllByText("Incomplete")).not.toHaveLength(0);
    expect(screen.getAllByRole("columnheader")).toHaveLength(6);
  });

  it("states the product promise and lists the six roots in prose", () => {
    render(<ProofsPage />);

    expect(
      screen.getByText(/Every release carries its proof/),
    ).toBeInTheDocument();

    expect(screen.getByText("How verification works")).toBeInTheDocument();
    const explainer = screen
      .getByText("How verification works")
      .closest("section")!;
    for (const root of [
      "Content",
      "Authority",
      "Validation",
      "Approval",
      "Policy",
      "Release",
    ]) {
      expect(within(explainer).getByText(root)).toBeInTheDocument();
    }
    expect(
      screen.getByText(/A verdict of Complete means all six roots passed/),
    ).toBeInTheDocument();
  });

  it("exports evidence through the dialog stub and confirms by toast", async () => {
    render(<ProofsPage />);

    fireEvent.click(screen.getByRole("button", { name: "Export Evidence" }));
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Export bundle" }),
    ).toBeDisabled();

    fireEvent.change(screen.getByLabelText("Release"), {
      target: { value: "rel-01j9x86kfm2w9d71" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Export bundle" }));

    expect(
      await screen.findByText("Evidence export recorded"),
    ).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
});
