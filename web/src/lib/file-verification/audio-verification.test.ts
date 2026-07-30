import { verifyLocalAudio } from "@/lib/file-verification/verify-audio";
import { CERT_ID, verificationFixture } from "@/test/fixtures";

function mp3File(bytes = new Uint8Array([0x49, 0x44, 0x33, 0x04, 0x00, 0x00])): File {
  return new File([bytes], "sealed.mp3", { type: "audio/mpeg" });
}

describe("local audio verification", () => {
  it("hashes MP3 bytes locally and sends only cert_id plus SHA-256", async () => {
    const verify = vi.fn().mockResolvedValue({
      ...verificationFixture(),
      media_type: "audio",
      mime_type: "audio/mpeg",
      provider: "elevenlabs",
      model: "eleven_multilingual_v2",
    });
    const result = await verifyLocalAudio(mp3File(), CERT_ID, { verify });
    expect(result).toMatchObject({
      state: "verified",
      mediaType: "audio",
      certId: CERT_ID,
    });
    expect(verify).toHaveBeenCalledWith(
      { cert_id: CERT_ID, presented_sha256: expect.stringMatching(/^[0-9a-f]{64}$/) },
      undefined,
    );
    expect(result.layers.find((layer) => layer.key === "public_capsule")?.status).toBe(
      "NOT CHECKED",
    );
  });

  it("rejects wrong media, malformed bytes, and missing certificate before API use", async () => {
    const verify = vi.fn();
    const wrongType = new File(["ID3"], "sealed.wav", { type: "audio/wav" });
    await expect(verifyLocalAudio(wrongType, CERT_ID, { verify })).resolves.toMatchObject({
      state: "invalid_file",
    });
    await expect(
      verifyLocalAudio(new File(["not-mp3"], "sealed.mp3", { type: "audio/mpeg" }), CERT_ID, {
        verify,
      }),
    ).resolves.toMatchObject({ state: "invalid_file" });
    await expect(verifyLocalAudio(mp3File(), "", { verify })).resolves.toMatchObject({
      state: "invalid_file",
    });
    expect(verify).not.toHaveBeenCalled();
  });
});
