import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { Stamp, stampToneForStatus } from "@/design-system";

describe("stampToneForStatus", () => {
  it("maps ChangeSet statuses per craft rule 4", () => {
    expect(stampToneForStatus("draft")).toBe("ruling");
    expect(stampToneForStatus("validated")).toBe("seal");
    expect(stampToneForStatus("submitted")).toBe("amber");
    expect(stampToneForStatus("approved")).toBe("seal");
    expect(stampToneForStatus("committed")).toBe("seal");
    expect(stampToneForStatus("rejected")).toBe("vermilion");
  });

  it("maps verification verdicts", () => {
    expect(stampToneForStatus("Complete")).toBe("seal");
    expect(stampToneForStatus("Incomplete")).toBe("amber");
    expect(stampToneForStatus("Invalid")).toBe("vermilion");
  });

  it("maps delivery states and root check statuses", () => {
    expect(stampToneForStatus("pending")).toBe("amber");
    expect(stampToneForStatus("delivered")).toBe("seal");
    expect(stampToneForStatus("failed")).toBe("vermilion");
    expect(stampToneForStatus("abandoned")).toBe("ruling");
    expect(stampToneForStatus("passed")).toBe("seal");
    expect(stampToneForStatus("not_evaluated")).toBe("ruling");
  });

  it("falls back to ruling for unknown statuses", () => {
    expect(stampToneForStatus("mystery-state")).toBe("ruling");
  });
});

describe("Stamp", () => {
  it("renders uppercase mono stamp text with the requested tone", () => {
    render(<Stamp tone="seal">Approved</Stamp>);
    const stamp = screen.getByText("Approved");
    expect(stamp).toHaveClass("font-mono", "uppercase");
    expect(stamp).toHaveClass("border-seal-700", "text-seal-700", "bg-seal-50");
  });

  it("renders vermilion tone for rejection wording", () => {
    render(<Stamp tone="vermilion">Rejected</Stamp>);
    const stamp = screen.getByText("Rejected");
    expect(stamp).toHaveClass("border-vermilion-700", "text-vermilion-700", "bg-vermilion-50");
  });
});
