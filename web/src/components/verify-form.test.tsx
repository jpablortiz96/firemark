import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { VerifyForm } from "@/components/verify-form";
import { verifyCertificate } from "@/lib/api";
import { SafeApiError } from "@/lib/errors";
import { CERT_ID, SEALED_SHA, verificationFixture } from "@/test/fixtures";

vi.mock("@/lib/api", () => ({ verifyCertificate: vi.fn() }));

async function submitWith(status = verificationFixture()) {
  vi.mocked(verifyCertificate).mockResolvedValueOnce(status);
  const user = userEvent.setup();
  render(<VerifyForm initialCertId={CERT_ID} initialSha256={SEALED_SHA} />);
  await user.click(screen.getByRole("button", { name: "Run Verify Gate" }));
  return user;
}

describe("Verify Gate experience", () => {
  it("shows a complete verified result and delivery action", async () => {
    await submitWith();
    expect(await screen.findByRole("heading", { name: "Evidence verified" })).toBeInTheDocument();
    expect(screen.getByText("Signature valid")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Request secure delivery" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "View Birth Certificate" })).toHaveAttribute(
      "href",
      `/certificate/${CERT_ID}`,
    );
  });

  it.each([
    ["hash_mismatch", "Asset hash does not match"],
    ["certificate_revoked", "Certificate revoked"],
    ["certificate_not_found", "Certificate not found"],
    ["signature_invalid", "Signature could not be validated"],
    ["malformed_evidence", "Evidence is malformed"],
  ] as const)("renders the safe %s outcome without delivery", async (status, title) => {
    await submitWith(verificationFixture(status));
    expect(await screen.findByRole("heading", { name: title })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Request secure delivery" })).not.toBeInTheDocument();
  });

  it("rejects a malformed digest locally", async () => {
    const user = userEvent.setup();
    render(<VerifyForm initialCertId={CERT_ID} initialSha256="not-a-digest" />);
    await user.click(screen.getByRole("button", { name: "Run Verify Gate" }));
    expect(screen.getByRole("alert")).toHaveTextContent("exactly 64 lowercase hexadecimal");
    expect(verifyCertificate).not.toHaveBeenCalled();
  });

  it("announces a loading state while verification is pending", async () => {
    let resolve!: (result: ReturnType<typeof verificationFixture>) => void;
    vi.mocked(verifyCertificate).mockReturnValueOnce(
      new Promise((done) => {
        resolve = done;
      }),
    );
    const user = userEvent.setup();
    render(<VerifyForm initialCertId={CERT_ID} />);
    await user.click(screen.getByRole("button", { name: "Run Verify Gate" }));
    expect(screen.getByRole("status")).toHaveTextContent("Validating signed evidence");
    resolve(verificationFixture());
    await waitFor(() => expect(screen.queryByRole("status")).not.toBeInTheDocument());
  });

  it("submits from the keyboard and normalizes safe API errors", async () => {
    vi.mocked(verifyCertificate).mockRejectedValueOnce(
      new SafeApiError("network", "NETWORK_FAILURE"),
    );
    const user = userEvent.setup();
    render(<VerifyForm initialCertId={CERT_ID} />);
    await user.click(screen.getByLabelText(/Certificate ID/));
    await user.keyboard("{Enter}");
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "verification service could not be reached",
    );
    expect(verifyCertificate).toHaveBeenCalledWith({ cert_id: CERT_ID });
  });
});
