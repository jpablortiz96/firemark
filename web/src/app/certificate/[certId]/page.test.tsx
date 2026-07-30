import { render, screen } from "@testing-library/react";

import CertificatePage from "@/app/certificate/[certId]/page";
import { getCertificate } from "@/lib/api";

vi.mock("@/lib/api", () => ({ getCertificate: vi.fn() }));

describe("certificate route states", () => {
  it.each([
    ["revoked", "Certificate revoked"],
    ["not_found", "Certificate not found"],
    ["error", "Certificate unavailable"],
  ] as const)("renders a safe %s state", async (state, heading) => {
    vi.mocked(getCertificate).mockResolvedValueOnce({ state });
    const view = await CertificatePage({ params: Promise.resolve({ certId: `fm-cert-${state}` }) });
    render(view);
    expect(screen.getByRole("heading", { name: heading })).toBeInTheDocument();
    expect(screen.queryByText(/private service failure/i)).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open Verify Gate" })).toHaveAttribute(
      "href",
      "/verify",
    );
  });

  it("rejects a malformed route identifier before calling the backend", async () => {
    const view = await CertificatePage({ params: Promise.resolve({ certId: "unsafe/id" }) });
    render(view);
    expect(screen.getByRole("heading", { name: "Certificate not found" })).toBeInTheDocument();
    expect(getCertificate).not.toHaveBeenCalled();
  });
});
