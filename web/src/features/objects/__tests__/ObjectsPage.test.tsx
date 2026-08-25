import { describe, expect, it } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import ObjectsPage from "../ObjectsPage";

describe("ObjectsPage", () => {
  it("lists released objects for the preview environment", () => {
    render(<ObjectsPage />);

    expect(screen.getByText("obj-home-hero")).toBeInTheDocument();
    expect(screen.getByText("sch-hero@3")).toBeInTheDocument();
    expect(screen.getByText("fr-CA")).toBeInTheDocument();
    expect(
      screen.getByRole("columnheader", { name: "Edition" }),
    ).toBeInTheDocument();
  });

  it("shows the empty state for an environment with no releases", () => {
    render(<ObjectsPage />);

    fireEvent.change(screen.getByLabelText("Environment"), {
      target: { value: "production" },
    });

    expect(
      screen.getByText("Nothing released in production"),
    ).toBeInTheDocument();
    expect(screen.queryByText("obj-home-hero")).not.toBeInTheDocument();
  });

  it("expands the fields record on row activation and collapses on repeat activation", () => {
    render(<ObjectsPage />);

    expect(
      screen.queryByText(
        "Publiez du contenu verifiable de bout en bout.",
      ),
    ).not.toBeInTheDocument();

    const row = screen.getByText("obj-home-hero").closest("tr")!;
    fireEvent.click(row);

    expect(
      screen.getByText("Publiez du contenu verifiable de bout en bout."),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("region", { name: "Fields record for obj-home-hero" }),
    ).toBeInTheDocument();

    fireEvent.click(row);
    expect(
      screen.queryByText(
        "Publiez du contenu verifiable de bout en bout.",
      ),
    ).not.toBeInTheDocument();
  });
});
