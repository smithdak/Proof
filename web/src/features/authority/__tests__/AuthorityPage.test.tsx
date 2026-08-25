import { describe, expect, it } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
import AuthorityPage from "../AuthorityPage";

describe("AuthorityPage", () => {
  it("renders all four seeded principals with kind stamps and key ids where present", () => {
    render(<AuthorityPage />);

    for (const name of [
      "Dakota Smith",
      "Amara Okafor",
      "locale-agent-7",
      "migration-partner-bot",
    ]) {
      expect(screen.getAllByText(name).length).toBeGreaterThan(0);
    }
    const table = within(screen.getByRole("table"));
    expect(table.getAllByText("human")).toHaveLength(2);
    expect(table.getAllByText("agent")).toHaveLength(2);
    expect(table.getByText("prin-agent-locale7")).toBeInTheDocument();
  });

  it("composes issuer -> grantee delegation entry lines with expiry and revocation", () => {
    render(<AuthorityPage />);

    expect(
      screen.getByText(
        "Localize launch homepage + pricing subtree to fr-CA, de-DE for preview only",
      ),
    ).toBeInTheDocument();
    expect(screen.getByText(/expires 2026-09-07/)).toBeInTheDocument();
    expect(screen.getByText("no expiry")).toBeInTheDocument();
    expect(screen.getByText("REVOKED")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Issue Delegation" }),
    ).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Revoke" })).toHaveLength(2);
  });

  it("issues a stub delegation through the dialog and confirms by toast", async () => {
    render(<AuthorityPage />);

    fireEvent.click(screen.getByRole("button", { name: "Issue Delegation" }));
    fireEvent.change(screen.getByLabelText("Grantee"), {
      target: { value: "prin-agent-migration" },
    });
    fireEvent.change(screen.getByLabelText("Scope"), {
      target: { value: "Read-only audit of released objects" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Record delegation" }));

    expect(await screen.findByText("Delegation issued")).toBeInTheDocument();
    expect(
      screen.queryByRole("dialog", { name: "Issue a delegation" }),
    ).not.toBeInTheDocument();
  });

  it("revokes an active delegation only after consequential confirmation", async () => {
    render(<AuthorityPage />);

    const revokeButtons = screen.getAllByRole("button", { name: "Revoke" });
    fireEvent.click(revokeButtons[0]!);

    const dialog = await screen.findByRole("dialog", {
      name: "Revoke this delegation?",
    });
    expect(dialog).toBeInTheDocument();

    fireEvent.click(
      screen.getByRole("button", { name: "Revoke delegation" }),
    );

    expect(await screen.findByText("Delegation revoked")).toBeInTheDocument();
    expect(screen.getAllByText("REVOKED")).toHaveLength(2);
  });
});
