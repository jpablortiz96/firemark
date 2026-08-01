import { sha256Hex } from "@/lib/file-verification/hash";
import {
  isAudioMimeAlias,
  looksLikeMp3,
  MAX_AUDIO_FILE_BYTES,
  verifyLocalAudio,
} from "@/lib/file-verification/verify-audio";
import type { CertificateLookup } from "@/lib/types";
import {
  AUDIO_CERT_ID,
  audioCertificateFixture,
  CERT_ID,
  certificateFixture,
  verificationFixture,
} from "@/test/fixtures";

const ID3_BYTES = new Uint8Array([0x49, 0x44, 0x33, 0x04, 0x00, 0x00, 0x00, 0x00]);
const FRAME_SYNC_BYTES = new Uint8Array([0xff, 0xfb, 0x90, 0x64, 0x00, 0x00, 0x00, 0x00]);

function mp3File(
  bytes: Uint8Array<ArrayBuffer> = ID3_BYTES,
  name = "sealed.mp3",
  type = "audio/mpeg",
): File {
  return new File([bytes], name, { type });
}

function audioVerification(overrides: Record<string, unknown> = {}) {
  return {
    ...verificationFixture(),
    cert_id: AUDIO_CERT_ID,
    media_type: "audio" as const,
    mime_type: "audio/mpeg",
    provider: "elevenlabs",
    model: "eleven_multilingual_v2",
    ...overrides,
  };
}

/** Build a lookup returning a certificate whose sealed hash matches the file. */
async function matchingLookup(
  bytes: Uint8Array<ArrayBuffer>,
  overrides: Record<string, unknown> = {},
): Promise<() => Promise<CertificateLookup>> {
  const digest = await sha256Hex(bytes);
  const certificate = audioCertificateFixture({
    source_sha256: digest,
    sealed_sha256: digest,
    ...overrides,
  });
  return async () => ({ state: "found", certificate });
}

function status(result: Awaited<ReturnType<typeof verifyLocalAudio>>, key: string) {
  return result.layers.find((layer) => layer.key === key)?.status;
}

describe("MP3 structural detection", () => {
  it("recognises an ID3 tagged MP3", () => {
    expect(looksLikeMp3(ID3_BYTES)).toBe(true);
  });

  it("recognises a bare MPEG frame sync", () => {
    expect(looksLikeMp3(FRAME_SYNC_BYTES)).toBe(true);
  });

  it("rejects bytes that are not MP3", () => {
    expect(looksLikeMp3(new TextEncoder().encode("not-an-mp3-at-all"))).toBe(false);
    expect(looksLikeMp3(new Uint8Array([0x89, 0x50, 0x4e, 0x47]))).toBe(false);
    // Frame sync with a reserved layer and a bad bitrate index must not pass.
    expect(looksLikeMp3(new Uint8Array([0xff, 0xe1, 0xf0, 0x00]))).toBe(false);
  });

  it("normalises browser MIME aliases without trusting them alone", () => {
    expect(isAudioMimeAlias("audio/mpeg")).toBe(true);
    expect(isAudioMimeAlias("audio/mp3")).toBe(true);
    expect(isAudioMimeAlias("AUDIO/MPEG")).toBe(true);
    expect(isAudioMimeAlias("image/png")).toBe(false);
    // The alias check is never sufficient: the bytes decide.
    expect(looksLikeMp3(new TextEncoder().encode("still-not-mp3"))).toBe(false);
  });
});

describe("local audio verification", () => {
  it("verifies a real byte-preserving MP3 and passes every layer", async () => {
    const lookup = await matchingLookup(ID3_BYTES);
    const verify = vi.fn().mockResolvedValue(audioVerification());

    const result = await verifyLocalAudio(mp3File(), AUDIO_CERT_ID, { verify, lookup });

    expect(result.state).toBe("verified");
    expect(result.mediaType).toBe("audio");
    expect(result.mimeType).toBe("audio/mpeg");
    for (const key of [
      "local_processing",
      "mp3_format",
      "public_certificate",
      "media_contract",
      "byte_preserving_seal",
      "local_file_hash",
      "cryptographic_verification",
    ]) {
      expect(status(result, key)).toBe("PASS");
    }
  });

  it("accepts a frame-sync MP3 and the audio/mp3 browser alias", async () => {
    const lookup = await matchingLookup(FRAME_SYNC_BYTES);
    const verify = vi.fn().mockResolvedValue(audioVerification());
    const result = await verifyLocalAudio(
      mp3File(FRAME_SYNC_BYTES, "sealed.mp3", "audio/mp3"),
      AUDIO_CERT_ID,
      { verify, lookup },
    );
    expect(result.state).toBe("verified");
    expect(status(result, "mp3_format")).toBe("PASS");
  });

  it("sends only the certificate ID and the locally computed SHA-256", async () => {
    const lookup = await matchingLookup(ID3_BYTES);
    const verify = vi.fn().mockResolvedValue(audioVerification());
    const expected = await sha256Hex(ID3_BYTES);

    await verifyLocalAudio(mp3File(), AUDIO_CERT_ID, { verify, lookup });

    expect(verify).toHaveBeenCalledTimes(1);
    const [request] = verify.mock.calls[0];
    expect(Object.keys(request).sort()).toEqual(["cert_id", "presented_sha256"]);
    expect(request.cert_id).toBe(AUDIO_CERT_ID);
    expect(request.presented_sha256).toBe(expected);
    const serialized = JSON.stringify(request);
    expect(serialized).not.toContain("sealed.mp3");
    expect(serialized).not.toContain("SUQz");
    expect(request.presented_sha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it("never passes file bytes or FormData to the network boundary", async () => {
    const lookup = await matchingLookup(ID3_BYTES);
    const verify = vi.fn().mockResolvedValue(audioVerification());
    const formData = vi.spyOn(globalThis, "FormData");

    await verifyLocalAudio(mp3File(), AUDIO_CERT_ID, { verify, lookup });

    expect(formData).not.toHaveBeenCalled();
    for (const [request] of verify.mock.calls) {
      for (const value of Object.values(request)) {
        expect(value instanceof ArrayBuffer).toBe(false);
        expect(value instanceof Uint8Array).toBe(false);
        expect(value instanceof Blob).toBe(false);
        expect(value instanceof File).toBe(false);
      }
    }
    formData.mockRestore();
  });

  it("blocks verification when the certificate ID is missing or malformed", async () => {
    const verify = vi.fn();
    const lookup = vi.fn();
    for (const identifier of ["", "   ", "not a cert id", "../../etc/passwd", "x".repeat(300)]) {
      const result = await verifyLocalAudio(mp3File(), identifier, { verify, lookup });
      expect(result.state).toBe("invalid_file");
      expect(status(result, "public_certificate")).toBe("FAIL");
    }
    expect(verify).not.toHaveBeenCalled();
    expect(lookup).not.toHaveBeenCalled();
  });

  it("rejects invalid, empty and oversized files before any request", async () => {
    const verify = vi.fn();
    const lookup = vi.fn();

    const notMp3 = await verifyLocalAudio(
      mp3File(new TextEncoder().encode("definitely-not-mp3")),
      AUDIO_CERT_ID,
      { verify, lookup },
    );
    expect(notMp3.state).toBe("invalid_file");
    expect(status(notMp3, "mp3_format")).toBe("FAIL");

    const wrongType = await verifyLocalAudio(
      new File([ID3_BYTES], "sealed.wav", { type: "audio/wav" }),
      AUDIO_CERT_ID,
      { verify, lookup },
    );
    expect(wrongType.state).toBe("invalid_file");

    const empty = await verifyLocalAudio(mp3File(new Uint8Array()), AUDIO_CERT_ID, {
      verify,
      lookup,
    });
    expect(empty.state).toBe("invalid_file");

    const oversized = new File([ID3_BYTES], "sealed.mp3", { type: "audio/mpeg" });
    Object.defineProperty(oversized, "size", { value: MAX_AUDIO_FILE_BYTES + 1 });
    const tooLarge = await verifyLocalAudio(oversized, AUDIO_CERT_ID, { verify, lookup });
    expect(tooLarge.state).toBe("invalid_file");

    expect(verify).not.toHaveBeenCalled();
    expect(lookup).not.toHaveBeenCalled();
  });

  it("handles a missing, revoked or unavailable certificate safely", async () => {
    const verify = vi.fn();
    for (const [state, expected] of [
      ["not_found", "not_found"],
      ["revoked", "revoked"],
      ["error", "unavailable"],
    ] as const) {
      const result = await verifyLocalAudio(mp3File(), AUDIO_CERT_ID, {
        verify,
        lookup: async () => ({ state }) as CertificateLookup,
      });
      expect(result.state).toBe(expected);
      expect(status(result, "public_certificate")).toBe("FAIL");
    }
    expect(verify).not.toHaveBeenCalled();
  });

  it("rejects a certificate whose media type or MIME type is not canonical MP3", async () => {
    const verify = vi.fn();

    const imageCertificate = await verifyLocalAudio(mp3File(), CERT_ID, {
      verify,
      lookup: async () => ({ state: "found", certificate: certificateFixture }),
    });
    expect(imageCertificate.state).toBe("invalid_file");
    expect(status(imageCertificate, "media_contract")).toBe("FAIL");

    const wrongMime = await verifyLocalAudio(mp3File(), AUDIO_CERT_ID, {
      verify,
      lookup: async () => ({
        state: "found",
        certificate: audioCertificateFixture({ mime_type: "audio/wav" }),
      }),
    });
    expect(wrongMime.state).toBe("invalid_file");
    expect(status(wrongMime, "media_contract")).toBe("FAIL");

    expect(verify).not.toHaveBeenCalled();
  });

  it("rejects malformed certificate hashes", async () => {
    const verify = vi.fn();
    for (const overrides of [
      { source_sha256: "not-a-hash" },
      { sealed_sha256: "zz".repeat(32) },
      { source_sha256: "", sealed_sha256: "" },
    ]) {
      const result = await verifyLocalAudio(mp3File(), AUDIO_CERT_ID, {
        verify,
        lookup: async () => ({
          state: "found",
          certificate: audioCertificateFixture(overrides),
        }),
      });
      expect(result.state).toBe("unverified");
      expect(status(result, "byte_preserving_seal")).toBe("FAIL");
    }
    expect(verify).not.toHaveBeenCalled();
  });

  it("rejects a certificate that breaks the byte-preserving MP3 contract", async () => {
    const verify = vi.fn();
    const result = await verifyLocalAudio(mp3File(), AUDIO_CERT_ID, {
      verify,
      lookup: async () => ({
        state: "found",
        certificate: audioCertificateFixture({
          source_sha256: "1".repeat(64),
          sealed_sha256: "2".repeat(64),
        }),
      }),
    });
    expect(result.state).toBe("unverified");
    expect(status(result, "byte_preserving_seal")).toBe("FAIL");
    expect(verify).not.toHaveBeenCalled();
  });

  it("fails when the local hash does not match the certificate", async () => {
    const verify = vi.fn();
    const result = await verifyLocalAudio(mp3File(), AUDIO_CERT_ID, {
      verify,
      lookup: async () => ({
        state: "found",
        certificate: audioCertificateFixture({
          source_sha256: "9".repeat(64),
          sealed_sha256: "9".repeat(64),
        }),
      }),
    });
    expect(result.state).toBe("tampered");
    expect(status(result, "local_file_hash")).toBe("FAIL");
    // A hash mismatch is decided locally: the Verify Gate is never consulted.
    expect(verify).not.toHaveBeenCalled();
  });

  it("fails when the Verify Gate rejects the evidence", async () => {
    const lookup = await matchingLookup(ID3_BYTES);
    const verify = vi.fn().mockResolvedValue(
      audioVerification({ status: "signature_invalid", verified: false, signature_valid: false }),
    );
    const result = await verifyLocalAudio(mp3File(), AUDIO_CERT_ID, { verify, lookup });
    expect(result.state).not.toBe("verified");
    expect(status(result, "cryptographic_verification")).toBe("FAIL");
  });

  it("fails closed when the Verify Gate is unavailable", async () => {
    const lookup = await matchingLookup(ID3_BYTES);
    const verify = vi.fn().mockRejectedValue(new Error("network down"));
    const result = await verifyLocalAudio(mp3File(), AUDIO_CERT_ID, { verify, lookup });
    expect(result.state).toBe("unavailable");
    expect(status(result, "cryptographic_verification")).toBe("FAIL");
  });

  it("requires every layer to pass before reporting VERIFIED", async () => {
    const lookup = await matchingLookup(ID3_BYTES);
    const verify = vi.fn().mockResolvedValue(audioVerification({ verified: false }));
    const result = await verifyLocalAudio(mp3File(), AUDIO_CERT_ID, { verify, lookup });
    expect(result.layers.every((layer) => layer.status === "PASS")).toBe(false);
    expect(status(result, "cryptographic_verification")).toBe("FAIL");
  });

  it("rejects a verification response for a different certificate or medium", async () => {
    const lookup = await matchingLookup(ID3_BYTES);
    const mismatched = vi.fn().mockResolvedValue(audioVerification({ cert_id: "fm-cert-other" }));
    await expect(
      verifyLocalAudio(mp3File(), AUDIO_CERT_ID, { verify: mismatched, lookup }),
    ).resolves.toMatchObject({ state: "unavailable" });

    const wrongMedium = vi.fn().mockResolvedValue(audioVerification({ media_type: "image" }));
    await expect(
      verifyLocalAudio(mp3File(), AUDIO_CERT_ID, { verify: wrongMedium, lookup }),
    ).resolves.toMatchObject({ state: "unavailable" });
  });

  it("aborts cleanly so a stale result can be discarded", async () => {
    const lookup = await matchingLookup(ID3_BYTES);
    const controller = new AbortController();
    controller.abort();
    await expect(
      verifyLocalAudio(mp3File(), AUDIO_CERT_ID, {
        verify: vi.fn(),
        lookup,
        signal: controller.signal,
      }),
    ).rejects.toMatchObject({ name: "AbortError" });
  });

  it("reports local progress phases", async () => {
    const lookup = await matchingLookup(ID3_BYTES);
    const verify = vi.fn().mockResolvedValue(audioVerification());
    const phases: string[] = [];
    await verifyLocalAudio(mp3File(), AUDIO_CERT_ID, {
      verify,
      lookup,
      onProgress: (progress) => phases.push(progress.phase),
    });
    expect(phases).toContain("reading");
    expect(phases).toContain("hashing");
    expect(phases).toContain("complete");
  });
});
