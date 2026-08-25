import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { DigestText } from "@/design-system";

const DIGEST =
  "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef01a2b3c4d5e6f70809";

function stubClipboard(): ReturnType<typeof vi.fn> {
  const writeText = vi.fn().mockResolvedValue(undefined);
  Object.defineProperty(navigator, "clipboard", {
    value: { writeText },
    configurable: true,
    writable: true,
  });
  return writeText;
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("DigestText", () => {
  it("renders a mono digest truncated at both ends with full value in title", () => {
    render(<DigestText value={DIGEST} />);

    const truncated = `${DIGEST.slice(0, 10)}…${DIGEST.slice(-8)}`;
    expect(screen.getByText(truncated)).toBeInTheDocument();
    expect(screen.getByTitle(DIGEST)).toBeInTheDocument();
  });

  it("copies the full digest to the clipboard and confirms", async () => {
    const writeText = stubClipboard();
    render(<DigestText value={DIGEST} />);

    fireEvent.click(screen.getByRole("button", { name: "Copy digest" }));

    await waitFor(() => expect(writeText).toHaveBeenCalledTimes(1));
    expect(writeText).toHaveBeenCalledWith(DIGEST);
    expect(await screen.findByText("Copied")).toBeInTheDocument();
  });
});
