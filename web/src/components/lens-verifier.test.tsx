import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { LensVerifier } from "@/components/lens-verifier";
import { VerifyExperience } from "@/components/verify-experience";
import { verifyLocalPng } from "@/lib/file-verification/verify-file";

vi.mock("@/lib/file-verification/verify-file", () => ({ verifyLocalPng: vi.fn() }));

const layers = [
  "File format",
  "Embedded FIREMARK capsule",
  "Sealed file hash",
  "Certificate found",
  "Ed25519 signature",
  "Certificate status",
  "B2 custody reference",
  "Delivery eligibility",
].map((label, index) => ({
  key: [
    "file_format",
    "public_capsule",
    "sealed_hash",
    "certificate_found",
    "signature",
    "certificate_status",
    "custody_reference",
    "delivery_eligibility",
  ][index] as never,
  label,
  status: "PASS" as const,
}));

function localResult(name = "sealed.png") {
  return {
    state: "verified" as const,
    fileName: name,
    fileSize: 128,
    sealedSha256: "a".repeat(64),
    capsule: {
      schema_version: "firemark.public-capsule.v1" as const,
      cert_id: "fm-cert-lens",
      asset_id: "fm-asset-lens",
      run_id: "fm-run-lens",
      canonical_hash: "b".repeat(64),
      source_sha256: "c".repeat(64),
      signer_key_id: "fm-signer-lens",
      verify_url: "https://verify.firemark.test/v1/certificates/fm-cert-lens",
      issued_at: "2026-07-30T12:00:00.000000Z",
    },
    layers,
  };
}

describe("FIREMARK Lens interaction", () => {
  it("is the primary verification mode and keeps certificate lookup available", async () => {
    const user = userEvent.setup();
    render(<VerifyExperience />);
    expect(screen.getByRole("heading", { name: "Verify an AI asset without uploading it." })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Image · PNG" })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("tab", { name: "Audio · MP3" })).toHaveAttribute("aria-selected", "false");
    await user.click(screen.getByRole("tab", { name: "Verify by certificate ID" }));
    expect(screen.getByLabelText(/Certificate ID/)).toBeInTheDocument();
  });

  it("supports keyboard file selection", async () => {
    const user = userEvent.setup();
    render(<LensVerifier />);
    const input = screen.getByLabelText("Choose PNG file");
    const click = vi.spyOn(input, "click");
    screen.getByRole("button", { name: "Choose or drop a FIREMARK sealed PNG" }).focus();
    await user.keyboard("{Enter}");
    expect(click).toHaveBeenCalled();
  });

  it("announces processing and then all verification layers", async () => {
    let resolve!: (value: ReturnType<typeof localResult>) => void;
    vi.mocked(verifyLocalPng).mockImplementationOnce((_file, options) => {
      options?.onProgress?.({ phase: "hashing", percent: 55 });
      return new Promise((done) => { resolve = done; });
    });
    const user = userEvent.setup();
    render(<LensVerifier />);
    await user.upload(
      screen.getByLabelText("Choose PNG file"),
      new File(["png"], "sealed.png", { type: "image/png" }),
    );
    expect(screen.getByRole("status")).toHaveTextContent("Calculating sealed SHA-256");
    resolve(localResult());
    expect(await screen.findByRole("heading", { name: "Asset is authentic and unchanged" })).toBeInTheDocument();
    expect(screen.getByRole("list", { name: "Independent verification layers" }).children).toHaveLength(8);
    expect(screen.getByText("Processed locally — your image is not uploaded")).toBeInTheDocument();
    expect(document.querySelector(".result-region")).toHaveAttribute("aria-live", "polite");
  });

  it("resets safely and accepts a second file", async () => {
    vi.mocked(verifyLocalPng)
      .mockResolvedValueOnce(localResult("first.png"))
      .mockResolvedValueOnce(localResult("second.png"));
    const user = userEvent.setup();
    render(<LensVerifier />);
    const input = screen.getByLabelText("Choose PNG file");
    await user.upload(input, new File(["one"], "first.png", { type: "image/png" }));
    await screen.findByText("first.png");
    await user.click(screen.getByRole("button", { name: "Reset" }));
    await waitFor(() => expect(screen.queryByText("first.png")).not.toBeInTheDocument());
    await user.upload(input, new File(["two"], "second.png", { type: "image/png" }));
    expect(await screen.findByText("second.png")).toBeInTheDocument();
    expect(verifyLocalPng).toHaveBeenCalledTimes(2);
  });

  it("aborts the first operation when the user changes file", async () => {
    const signals: AbortSignal[] = [];
    vi.mocked(verifyLocalPng).mockImplementation((_file, options) => {
      if (options?.signal) signals.push(options.signal);
      return new Promise(() => undefined);
    });
    const user = userEvent.setup();
    render(<LensVerifier />);
    const input = screen.getByLabelText("Choose PNG file");
    await user.upload(input, new File(["one"], "first.png", { type: "image/png" }));
    await user.upload(input, new File(["two"], "second.png", { type: "image/png" }));
    expect(signals).toHaveLength(2);
    expect(signals[0].aborted).toBe(true);
    expect(signals[1].aborted).toBe(false);
  });
});
