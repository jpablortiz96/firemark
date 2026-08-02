import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { resultCopy } from "@/components/verification-layers";
import { VerifyExperience } from "@/components/verify-experience";
import * as api from "@/lib/api";
import type { AudioFailureReason, LensResult } from "@/lib/file-verification/types";
import { AUDIO_LAYER_ORDER } from "@/lib/file-verification/types";
import { audioLayers, firstFailedAudioLayer } from "@/lib/file-verification/verify-audio";
import { sha256Hex } from "@/lib/file-verification/hash";
import { AUDIO_CERT_ID, audioCertificateFixture, verificationFixture } from "@/test/fixtures";

const ID3_BYTES = new Uint8Array([0x49, 0x44, 0x33, 0x04, 0x00, 0x00, 0x00, 0x00]);

/** Words that must never appear inside an audio result. */
const IMAGE_WORDS = [/\bPNG\b/i, /capsule/i, /EXIF/i, /\bimage\b/i];

function mp3File(name = "sealed.mp3"): File {
  return new File([ID3_BYTES], name, { type: "audio/mpeg" });
}

function pngFile(name = "asset.png"): File {
  return new File([new Uint8Array([0x89, 0x50, 0x4e, 0x47])], name, { type: "image/png" });
}

async function renderAudio(certId = "") {
  const user = userEvent.setup();
  render(<VerifyExperience initialMedia="audio" initialCertId={certId} />);
  return user;
}

function audioResultRegion(): HTMLElement {
  const region = document.querySelector('[aria-live="polite"]');
  if (!region) throw new Error("audio result region is missing");
  return region as HTMLElement;
}

async function runAudio(user: ReturnType<typeof userEvent.setup>, file = mp3File()) {
  await user.upload(screen.getByLabelText("Choose MP3 file"), file);
  await user.click(screen.getByRole("button", { name: /Verify this MP3 locally/ }));
}

// --------------------------------------------------------------------------
// The reported production defect
// --------------------------------------------------------------------------

describe("audio result copy is derived from the failed layer, not a shared file state", () => {
  it("reports a missing certificate ID without calling the MP3 invalid", async () => {
    const verify = vi.spyOn(api, "verifyCertificate");
    const lookup = vi.spyOn(api, "getCertificate");
    const user = await renderAudio(""); // no certificate ID, exactly as reported

    await runAudio(user);

    // The headline names the real cause.
    expect(
      await screen.findByRole("heading", { name: "Certificate ID required" }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        "Enter the FIREMARK certificate ID associated with this MP3 before verifying it.",
      ),
    ).toBeInTheDocument();

    // The MP3 was never classified as invalid.
    expect(screen.queryByText(/File is not a valid supported PNG/)).not.toBeInTheDocument();
    expect(screen.queryByText(/File is not a valid supported MP3/)).not.toBeInTheDocument();

    const region = audioResultRegion();
    const rows = region.querySelectorAll(".verification-layers li");
    const text = (index: number) => rows[index].textContent ?? "";
    expect(text(0)).toContain("Local processing");
    expect(text(0)).toContain("PASS");
    expect(text(1)).toContain("MP3 format");
    expect(text(1)).toContain("NOT CHECKED");
    expect(text(2)).toContain("Public certificate");
    expect(text(2)).toContain("FAIL");

    // Nothing was requested from the backend.
    expect(verify).not.toHaveBeenCalled();
    expect(lookup).not.toHaveBeenCalled();
    verify.mockRestore();
    lookup.mockRestore();
  });

  it("names invalid MP3 bytes without PNG language", async () => {
    const user = await renderAudio(AUDIO_CERT_ID);
    const notMp3 = new File([new TextEncoder().encode("definitely-not-audio")], "sealed.mp3", {
      type: "audio/mpeg",
    });

    await runAudio(user, notMp3);

    expect(
      await screen.findByRole("heading", { name: "File is not a valid supported MP3" }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        "FIREMARK Lens rejected the MP3 signature, structure, size, or format locally.",
      ),
    ).toBeInTheDocument();
    for (const word of IMAGE_WORDS) {
      expect(audioResultRegion().textContent ?? "").not.toMatch(word);
    }
  });

  it("uses audio-only language for every audio failure category", () => {
    const reasons: AudioFailureReason[] = [
      "certificate_id_required",
      "invalid_mp3",
      "certificate_not_found",
      "certificate_revoked",
      "media_contract_mismatch",
      "seal_contract_inconsistent",
      "local_hash_mismatch",
      "verification_rejected",
      "verification_unavailable",
    ];
    for (const reason of reasons) {
      const copy = resultCopy({
        state: "invalid_file",
        mediaType: "audio",
        fileName: "sealed.mp3",
        fileSize: 8,
        audioFailure: reason,
        layers: audioLayers({}),
      } as LensResult);
      const rendered = `${copy.title} ${copy.body}`;
      for (const word of IMAGE_WORDS) expect(rendered).not.toMatch(word);
      expect(copy.tone).toBe("warning");
    }
  });

  it("reports a verified MP3 with audio-specific success copy", async () => {
    const digest = await sha256Hex(ID3_BYTES);
    const lookup = vi.spyOn(api, "getCertificate").mockResolvedValue({
      state: "found",
      certificate: audioCertificateFixture({ source_sha256: digest, sealed_sha256: digest }),
    });
    const verify = vi.spyOn(api, "verifyCertificate").mockResolvedValue({
      ...verificationFixture(),
      cert_id: AUDIO_CERT_ID,
      media_type: "audio",
      mime_type: "audio/mpeg",
      provider: "elevenlabs",
      model: "eleven_multilingual_v2",
    });
    const user = await renderAudio(AUDIO_CERT_ID);

    await runAudio(user);

    expect(await screen.findByRole("heading", { name: "This MP3 is verified" })).toBeInTheDocument();
    expect(
      screen.getByText(
        "This exact MP3 matches the registered FIREMARK certificate and signed evidence.",
      ),
    ).toBeInTheDocument();

    const region = audioResultRegion();
    const rows = [...region.querySelectorAll(".verification-layers li")];
    expect(rows).toHaveLength(AUDIO_LAYER_ORDER.length);
    for (const row of rows) expect(row.textContent).toContain("PASS");
    expect(region.textContent).toContain("7 trust layers");

    // Only the certificate ID and the local digest were ever sent.
    expect(verify).toHaveBeenCalledWith(
      { cert_id: AUDIO_CERT_ID, presented_sha256: digest },
      expect.anything(),
    );
    lookup.mockRestore();
    verify.mockRestore();
  });
});

// --------------------------------------------------------------------------
// Deterministic precedence
// --------------------------------------------------------------------------

describe("audio failure precedence", () => {
  it("selects the first failed layer in the declared order", () => {
    expect(AUDIO_LAYER_ORDER).toEqual([
      "local_processing",
      "mp3_format",
      "public_certificate",
      "media_contract",
      "byte_preserving_seal",
      "local_file_hash",
      "cryptographic_verification",
    ]);
    const layers = audioLayers({
      local_processing: { status: "PASS" },
      mp3_format: { status: "PASS" },
      public_certificate: { status: "FAIL" },
      media_contract: { status: "FAIL" },
      local_file_hash: { status: "FAIL" },
    });
    expect(firstFailedAudioLayer(layers)).toBe("public_certificate");
    expect(firstFailedAudioLayer(audioLayers({}))).toBeNull();
  });

  it("falls back to the first failed layer when no explicit reason is recorded", () => {
    const copy = resultCopy({
      state: "unverified",
      mediaType: "audio",
      fileName: "sealed.mp3",
      fileSize: 8,
      layers: audioLayers({
        local_processing: { status: "PASS" },
        mp3_format: { status: "PASS" },
        public_certificate: { status: "PASS" },
        media_contract: { status: "PASS" },
        byte_preserving_seal: { status: "FAIL" },
        local_file_hash: { status: "FAIL" },
      }),
    } as LensResult);
    expect(copy.title).toBe("Audio seal contract is inconsistent");
  });

  it("keeps PNG copy for image results", () => {
    const copy = resultCopy({
      state: "invalid_file",
      mediaType: "image",
      fileName: "asset.png",
      fileSize: 4,
      layers: [],
    } as unknown as LensResult);
    expect(copy.title).toBe("File is not a valid supported PNG");
  });
});

// --------------------------------------------------------------------------
// Cross-mode isolation
// --------------------------------------------------------------------------

describe("cross-mode error isolation", () => {
  it("clears an image error when switching to audio", async () => {
    const user = userEvent.setup();
    render(<VerifyExperience />);

    await user.upload(screen.getByLabelText("Choose PNG file"), pngFile());
    await waitFor(() =>
      expect(screen.getByText(/File is not a valid supported PNG/)).toBeInTheDocument(),
    );

    await user.click(screen.getByRole("tab", { name: "Audio · MP3" }));

    expect(screen.queryByText(/File is not a valid supported PNG/)).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Audio verification result" })).toBeInTheDocument();
  });

  it("clears an audio error when switching to image", async () => {
    const user = await renderAudio("");

    await runAudio(user);
    expect(
      await screen.findByRole("heading", { name: "Certificate ID required" }),
    ).toBeInTheDocument();

    await user.click(screen.getByRole("tab", { name: "Image · PNG" }));

    expect(screen.queryByRole("heading", { name: "Certificate ID required" })).not.toBeInTheDocument();
    // The PNG panel starts neutral.
    expect(screen.queryByText(/File is not a valid supported PNG/)).not.toBeInTheDocument();
  });

  it("resets an audio failure when the certificate ID changes", async () => {
    const user = await renderAudio("");

    await runAudio(user);
    expect(
      await screen.findByRole("heading", { name: "Certificate ID required" }),
    ).toBeInTheDocument();

    await user.type(screen.getByRole("textbox", { name: /Certificate ID/ }), AUDIO_CERT_ID);

    expect(screen.queryByRole("heading", { name: "Certificate ID required" })).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Audio verification result" })).toBeInTheDocument();
  });

  it("resets an audio failure when a different MP3 is chosen", async () => {
    const user = await renderAudio("");

    await runAudio(user);
    expect(
      await screen.findByRole("heading", { name: "Certificate ID required" }),
    ).toBeInTheDocument();

    await user.upload(screen.getByLabelText("Choose MP3 file"), mp3File("other.mp3"));

    expect(screen.queryByRole("heading", { name: "Certificate ID required" })).not.toBeInTheDocument();
  });

  it("discards a stale verification that resolves after the file changed", async () => {
    const digest = await sha256Hex(ID3_BYTES);
    vi.spyOn(api, "getCertificate").mockResolvedValue({
      state: "found",
      certificate: audioCertificateFixture({ source_sha256: digest, sealed_sha256: digest }),
    });
    let release: (() => void) | undefined;
    const verify = vi.spyOn(api, "verifyCertificate").mockImplementation(
      () =>
        new Promise((resolve) => {
          release = () =>
            resolve({
              ...verificationFixture(),
              cert_id: AUDIO_CERT_ID,
              media_type: "audio",
              mime_type: "audio/mpeg",
              provider: "elevenlabs",
              model: "eleven_multilingual_v2",
            });
        }),
    );
    const user = await renderAudio(AUDIO_CERT_ID);

    await runAudio(user);
    await waitFor(() => expect(verify).toHaveBeenCalled());

    // The user moves on before the slow request resolves.
    await user.upload(screen.getByLabelText("Choose MP3 file"), mp3File("newer.mp3"));
    release?.();

    await waitFor(() =>
      expect(screen.getByRole("heading", { name: "Audio verification result" })).toBeInTheDocument(),
    );
    expect(screen.queryByRole("heading", { name: "This MP3 is verified" })).not.toBeInTheDocument();
    vi.restoreAllMocks();
  });
});

// --------------------------------------------------------------------------
// URL behaviour and the privacy boundary
// --------------------------------------------------------------------------

describe("URL behaviour", () => {
  it("prefills audio mode without any decision before a file is chosen", () => {
    render(<VerifyExperience initialMedia="audio" initialCertId={AUDIO_CERT_ID} />);
    expect(screen.getByRole("tab", { name: "Audio · MP3" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    expect(screen.getByRole("textbox", { name: /Certificate ID/ })).toHaveValue(AUDIO_CERT_ID);
    expect(screen.getByRole("heading", { name: "Audio verification result" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: /required|verified|failed/i })).not.toBeInTheDocument();
  });

  it("keeps the default image experience on a plain /verify visit", async () => {
    const user = userEvent.setup();
    render(<VerifyExperience />);
    expect(screen.getByRole("tab", { name: "Image · PNG" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    await user.click(screen.getByRole("tab", { name: "Audio · MP3" }));
    expect(screen.getByRole("textbox", { name: /Certificate ID/ })).toHaveValue("");
    expect(screen.getByRole("heading", { name: "Audio verification result" })).toBeInTheDocument();
  });
});

describe("privacy boundary during a failure", () => {
  it("never constructs FormData or sends bytes for any audio outcome", async () => {
    const formData = vi.spyOn(globalThis, "FormData");
    const verify = vi.spyOn(api, "verifyCertificate");
    const user = await renderAudio("");

    await runAudio(user);
    await screen.findByRole("heading", { name: "Certificate ID required" });

    expect(formData).not.toHaveBeenCalled();
    expect(verify).not.toHaveBeenCalled();
    formData.mockRestore();
    verify.mockRestore();
  });
});
