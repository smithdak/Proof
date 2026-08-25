import { describe, expect, it } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { DataTable } from "@/design-system";

interface Row {
  id: string;
  intent: string;
  edits: number;
}

const columns = [
  { key: "intent", header: "Intent" },
  { key: "edits", header: "Edits", align: "right" as const },
];

const rows: Row[] = [
  { id: "cs_1", intent: "Rewrite landing hero", edits: 3 },
  { id: "cs_2", intent: "Fix pricing typos", edits: 1 },
];

describe("DataTable", () => {
  it("renders header row and one entry-line row per record", () => {
    render(<DataTable columns={columns} rows={rows} rowKey={(row) => row.id} />);

    expect(screen.getByRole("columnheader", { name: "Intent" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Edits" })).toBeInTheDocument();
    expect(screen.getByText("Rewrite landing hero")).toBeInTheDocument();
    expect(screen.getByText("Fix pricing typos")).toBeInTheDocument();

    const tableRows = screen.getAllByRole("row");
    expect(tableRows).toHaveLength(3);
  });

  it("renders cell values through custom render when provided", () => {
    render(
      <DataTable
        columns={[
          {
            key: "intent",
            header: "Intent",
            render: (row) => `Filed: ${row.intent}`,
          },
        ]}
        rows={rows}
        rowKey={(row) => row.id}
      />,
    );

    expect(screen.getByText("Filed: Rewrite landing hero")).toBeInTheDocument();
  });

  it("invokes onRowClick for click and keyboard activation", () => {
    let clickedId = "";
    render(
      <DataTable
        columns={columns}
        rows={rows}
        rowKey={(row) => row.id}
        onRowClick={(row) => {
          clickedId = row.id;
        }}
      />,
    );

    const targetRow = screen.getByText("Fix pricing typos").closest("tr")!;
    fireEvent.click(targetRow);
    expect(clickedId).toBe("cs_2");

    fireEvent.keyDown(targetRow, { key: "Enter" });
    expect(clickedId).toBe("cs_2");
  });

  it("marks the selected row and renders emptyState when no rows exist", () => {
    const { rerender } = render(
      <DataTable columns={columns} rows={rows} rowKey={(row) => row.id} selectedKey="cs_1" />,
    );
    const selectedRow = screen.getByText("Rewrite landing hero").closest("tr")!;
    expect(selectedRow).toHaveAttribute("data-state", "selected");

    rerender(
      <DataTable
        columns={columns}
        rows={[] as Row[]}
        rowKey={(row) => row.id}
        emptyState={<p>Nothing filed yet.</p>}
      />,
    );
    expect(screen.getByText("Nothing filed yet.")).toBeInTheDocument();
  });
});
