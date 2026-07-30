import { fireEvent, render, screen } from "@testing-library/react";

import { CertificateCard } from "@/components/certificate-card";
import { certificateFixture, CERT_ID, SEALED_SHA } from "@/test/fixtures";

describe("public Birth Certificate", () => {
  beforeEach(() => {
    Object.assign(navigator, { clipboard: { writeText: vi.fn().mockResolvedValue(undefined) } });
  });

  it("renders active public evidence and copy controls", async () => {
    render(<CertificateCard certificate={certificateFixture} />);
    expect(screen.getByText("Active")).toBeInTheDocument();
    expect(screen.getByText(CERT_ID)).toBeInTheDocument();
    expect(screen.getByText(SEALED_SHA)).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: /Copy/i }).length).toBeGreaterThan(4);
    expect(screen.getByRole("link", { name: "Download Proof Pack" })).toHaveAttribute(
      "href",
      `/api/proof-pack/${CERT_ID}`,
    );
    fireEvent.click(screen.getByRole("button", { name: "Copy Certificate ID value" }));
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(CERT_ID);
  });

  it("never renders private record fields or sentinel values", () => {
    render(<CertificateCard certificate={certificateFixture} />);
    const page = document.body.textContent ?? "";
    for (const value of [
      "private-prompt-sentinel",
      "private-parameters-sentinel",
      "private-seed-sentinel",
      "private-vault-version-sentinel",
    ]) {
      expect(page).not.toContain(value);
    }
    expect(screen.getByText("Public manifest")).toBeInTheDocument();
  });

  it("renders invalid status without claiming active evidence", () => {
    render(
      <CertificateCard certificate={{ ...certificateFixture, certificate_status: "invalid" }} />,
    );
    expect(screen.getByText("Invalid")).toBeInTheDocument();
    expect(screen.getByText("Certificate needs review")).toBeInTheDocument();
  });

  it("renders audio provider context without pre-authorizing playback", () => {
    render(
      <CertificateCard
        certificate={{
          ...certificateFixture,
          media_type: "audio",
          mime_type: "audio/mpeg",
          provider: "elevenlabs",
          model: "eleven_multilingual_v2",
          width: null,
          height: null,
          duration_ms: 1000,
        }}
      />,
    );
    expect(screen.getByText("elevenlabs")).toBeInTheDocument();
    expect(screen.getByText(/Audio playback becomes available/)).toBeInTheDocument();
    expect(screen.queryByRole("audio")).not.toBeInTheDocument();
  });
});
