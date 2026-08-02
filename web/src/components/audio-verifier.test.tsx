import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { AudioVerifier } from "@/components/audio-verifier";
import { CertificateCard } from "@/components/certificate-card";
import { VerifyExperience } from "@/components/verify-experience";
import * as verifyAudio from "@/lib/file-verification/verify-audio";
import { AUDIO_CERT_ID, audioCertificateFixture, certificateFixture } from "@/test/fixtures";

const ID3_BYTES = new Uint8Array([0x49, 0x44, 0x33, 0x04, 0x00, 0x00, 0x00, 0x00]);

function mp3File(name = "sealed.mp3", type = "audio/mpeg"): File {
  return new File([ID3_BYTES], name, { type });
}

function passingResult(overrides: Record<string, unknown> = {}) {
  return {
    state: "verified" as const,
    fileName: "sealed.mp3",
    fileSize: ID3_BYTES.length,
    mediaType: "audio" as const,
    mimeType: "audio/mpeg",
    certId: AUDIO_CERT_ID,
    layers: verifyAudio.audioLayers({
      local_processing: { status: "PASS" },
      mp3_format: { status: "PASS" },
      public_certificate: { status: "PASS" },
      media_contract: { status: "PASS" },
      byte_preserving_seal: { status: "PASS" },
      local_file_hash: { status: "PASS" },
      cryptographic_verification: { status: "PASS" },
    }),
    ...overrides,
  };
}

describe("Lens media selection", () => {
  it("defaults to PNG mode when no media parameter is present", () => {
    render(<VerifyExperience />);
    expect(screen.getByRole("tab", { name: "Image · PNG" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    expect(screen.getByRole("tab", { name: "Audio · MP3" })).toHaveAttribute(
      "aria-selected",
      "false",
    );
  });

  it("selects audio mode from the media query parameter and prefills the certificate ID", () => {
    render(<VerifyExperience initialMedia="audio" initialCertId={AUDIO_CERT_ID} />);
    expect(screen.getByRole("tab", { name: "Audio · MP3" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    expect(screen.getByLabelText(/Certificate ID/)).toHaveValue(AUDIO_CERT_ID);
  });

  it("never claims success before a file is selected", () => {
    render(<VerifyExperience initialMedia="audio" initialCertId={AUDIO_CERT_ID} />);
    expect(screen.getByRole("heading", { name: "Audio verification result" })).toBeInTheDocument();
    expect(screen.queryByText(/VERIFIED/i)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Verify this MP3 locally/ })).toBeDisabled();
  });

  it("does not trust a sha256 query parameter as expected evidence", () => {
    render(
      <VerifyExperience
        initialMedia="audio"
        initialCertId={AUDIO_CERT_ID}
        initialSha256={"f".repeat(64)}
      />,
    );
    // The audio panel exposes no hash input: the local file is the only evidence.
    expect(screen.queryByDisplayValue("f".repeat(64))).not.toBeInTheDocument();
    expect(document.body.textContent).not.toContain("f".repeat(64));
  });

  it("can be switched to audio mode with the keyboard", async () => {
    const user = userEvent.setup();
    render(<VerifyExperience />);
    await user.tab();
    expect(screen.getByRole("tab", { name: "Image · PNG" })).toHaveFocus();
    await user.tab();
    const audioTab = screen.getByRole("tab", { name: "Audio · MP3" });
    expect(audioTab).toHaveFocus();
    await user.keyboard("{Enter}");
    expect(audioTab).toHaveAttribute("aria-selected", "true");
  });

  it("resets a previous decision when the media mode changes", async () => {
    const user = userEvent.setup();
    vi.spyOn(verifyAudio, "verifyLocalAudio").mockResolvedValue(passingResult());
    render(<VerifyExperience initialMedia="audio" initialCertId={AUDIO_CERT_ID} />);

    await user.upload(screen.getByLabelText("Choose MP3 file"), mp3File());
    await user.click(screen.getByRole("button", { name: /Verify this MP3 locally/ }));
    await waitFor(() =>
      expect(screen.getByRole("heading", { name: "This MP3 is verified" })).toBeInTheDocument(),
    );

    await user.click(screen.getByRole("tab", { name: "Image · PNG" }));
    await user.click(screen.getByRole("tab", { name: "Audio · MP3" }));
    expect(screen.getByRole("heading", { name: "Audio verification result" })).toBeInTheDocument();
    vi.restoreAllMocks();
  });
});

describe("audio drop zone", () => {
  it("accepts only MP3 types on the file input", () => {
    render(<AudioVerifier />);
    expect(screen.getByLabelText("Choose MP3 file")).toHaveAttribute(
      "accept",
      "audio/mpeg,audio/mp3,.mp3",
    );
  });

  it("accepts only PNG types in image mode", () => {
    render(<VerifyExperience />);
    expect(screen.getByLabelText("Choose PNG file")).toHaveAttribute(
      "accept",
      "image/png,.png",
    );
  });

  it("rejects a dropped non-MP3 file without processing it", async () => {
    const verify = vi.spyOn(verifyAudio, "verifyLocalAudio");
    render(<AudioVerifier initialCertId={AUDIO_CERT_ID} />);
    const zone = screen.getByRole("button", { name: /Choose a FIREMARK sealed MP3/ });

    const png = new File([new Uint8Array([0x89, 0x50])], "asset.png", { type: "image/png" });
    const dropEvent = new Event("drop", { bubbles: true });
    Object.defineProperty(dropEvent, "dataTransfer", { value: { files: [png] } });
    zone.dispatchEvent(dropEvent);

    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent(/not an MP3/i));
    expect(verify).not.toHaveBeenCalled();
    verify.mockRestore();
  });

  it("exposes the result through an accessible live region", () => {
    const { container } = render(<AudioVerifier initialCertId={AUDIO_CERT_ID} />);
    const live = container.querySelector('[aria-live="polite"]');
    expect(live).not.toBeNull();
    expect(live).toHaveAttribute("aria-busy", "false");
  });

  it("communicates layer status with text, not colour alone", async () => {
    const user = userEvent.setup();
    vi.spyOn(verifyAudio, "verifyLocalAudio").mockResolvedValue(passingResult());
    render(<AudioVerifier initialCertId={AUDIO_CERT_ID} />);

    await user.upload(screen.getByLabelText("Choose MP3 file"), mp3File());
    await user.click(screen.getByRole("button", { name: /Verify this MP3 locally/ }));

    const layers = await screen.findByRole("list", { name: /verification layers/i });
    expect(within(layers).getAllByText(/PASS/).length).toBeGreaterThanOrEqual(7);
    expect(within(layers).getByText("Byte-preserving seal")).toBeInTheDocument();
    expect(within(layers).getByText("Local file hash")).toBeInTheDocument();
    vi.restoreAllMocks();
  });
});

describe("audio verification state isolation", () => {
  it("discards a stale result when the file changes", async () => {
    const user = userEvent.setup();
    vi.spyOn(verifyAudio, "verifyLocalAudio").mockResolvedValue(passingResult());
    render(<AudioVerifier initialCertId={AUDIO_CERT_ID} />);
    const input = screen.getByLabelText("Choose MP3 file");

    await user.upload(input, mp3File());
    await user.click(screen.getByRole("button", { name: /Verify this MP3 locally/ }));
    await waitFor(() =>
      expect(screen.getByRole("heading", { name: "This MP3 is verified" })).toBeInTheDocument(),
    );

    await user.upload(input, mp3File("other.mp3"));
    expect(screen.getByRole("heading", { name: "Audio verification result" })).toBeInTheDocument();
    vi.restoreAllMocks();
  });

  it("resets a previous success when the certificate ID changes", async () => {
    const user = userEvent.setup();
    vi.spyOn(verifyAudio, "verifyLocalAudio").mockResolvedValue(passingResult());
    render(<AudioVerifier initialCertId={AUDIO_CERT_ID} />);

    await user.upload(screen.getByLabelText("Choose MP3 file"), mp3File());
    await user.click(screen.getByRole("button", { name: /Verify this MP3 locally/ }));
    await waitFor(() =>
      expect(screen.getByRole("heading", { name: "This MP3 is verified" })).toBeInTheDocument(),
    );

    await user.type(screen.getByLabelText(/Certificate ID/), "x");
    expect(screen.getByRole("heading", { name: "Audio verification result" })).toBeInTheDocument();
    vi.restoreAllMocks();
  });

  it("creates and revokes the local object URL as the file changes and on unmount", async () => {
    const user = userEvent.setup();
    const create = vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:firemark-local");
    const revoke = vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {});

    const view = render(<AudioVerifier initialCertId={AUDIO_CERT_ID} />);
    const input = screen.getByLabelText("Choose MP3 file");

    await user.upload(input, mp3File());
    expect(create).toHaveBeenCalledTimes(1);

    await user.upload(input, mp3File("second.mp3"));
    expect(revoke).toHaveBeenCalledWith("blob:firemark-local");

    view.unmount();
    expect(revoke).toHaveBeenCalledTimes(2);
    create.mockRestore();
    revoke.mockRestore();
  });
});

describe("certificate page integration", () => {
  it("links an audio certificate to local MP3 verification with cert_id and media only", () => {
    render(<CertificateCard certificate={audioCertificateFixture()} />);
    const cta = screen.getByRole("link", { name: "Verify this MP3 locally" });
    const href = cta.getAttribute("href") ?? "";
    expect(href).toBe(`/verify?cert_id=${encodeURIComponent(AUDIO_CERT_ID)}&media=audio`);
    expect(href).not.toContain("sha256");
    expect(href).not.toContain("token");
    expect(href).not.toContain("http");
    expect(href).not.toContain("X-Amz");
  });

  it("keeps an image certificate on the PNG Lens without exposing a hash", () => {
    render(<CertificateCard certificate={certificateFixture} />);
    const href = screen.getByRole("link", { name: "Verify this asset" }).getAttribute("href") ?? "";
    expect(href).toContain("media=image");
    expect(href).not.toContain("sha256");
  });
});
