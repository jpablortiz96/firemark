import { strFromU8, unzipSync } from "fflate";

import { buildProofPack, canonicalPublicCertificate, PROOF_PACK_ENTRIES } from "@/lib/proof-pack";
import type { PublicCertificate } from "@/lib/types";
import { certificateFixture } from "@/test/fixtures";

function entries(certificate: PublicCertificate = certificateFixture): Record<string, Uint8Array> {
  return unzipSync(buildProofPack(certificate).bytes);
}

describe("public Proof Pack", () => {
  it("uses the safe filename and contains exactly the required entries", () => {
    const pack = buildProofPack(certificateFixture);
    expect(pack.filename).toBe(`firemark-proof-${certificateFixture.cert_id}.zip`);
    expect(Object.keys(unzipSync(pack.bytes)).sort()).toEqual([...PROOF_PACK_ENTRIES].sort());
  });

  it("writes a canonical sorted-key public certificate projection", () => {
    const certificate = strFromU8(entries()["certificate.json"]);
    expect(certificate).toBe(canonicalPublicCertificate(certificateFixture));
    expect(certificate.startsWith('{"ai_generated"')).toBe(true);
    expect(JSON.parse(certificate)).toEqual(
      expect.objectContaining({
        cert_id: certificateFixture.cert_id,
        sealed_sha256: certificateFixture.sealed_sha256,
        public_manifest: certificateFixture.public_manifest,
      }),
    );
  });

  it("includes the verification summary, Ed25519 public key, and instructions", () => {
    const files = entries();
    const summary = strFromU8(files["verification-summary.txt"]);
    const publicKey = strFromU8(files["public-key.txt"]);
    const readme = strFromU8(files["README.txt"]);
    expect(summary).toContain(`Certificate ID: ${certificateFixture.cert_id}`);
    expect(summary).toContain(`Public verification URL: ${certificateFixture.verify_url}`);
    expect(publicKey).toContain("algorithm: Ed25519");
    expect(publicKey).toContain(certificateFixture.signer_public_key_b64);
    expect(readme).toContain(certificateFixture.verify_url);
    expect(readme).toContain("Drop the sealed PNG into FIREMARK Lens");
  });

  it("describes detached hash verification for audio without adding private entries", () => {
    const audio = {
      ...certificateFixture,
      media_type: "audio" as const,
      mime_type: "audio/mpeg",
      provider: "elevenlabs",
      model: "eleven_multilingual_v2",
      width: null,
      height: null,
      duration_ms: 1200,
      public_manifest: {
        schema_version: "firemark.public-audio-reference.v1",
        embedded: false,
      },
    };
    const files = unzipSync(buildProofPack(audio).bytes);
    expect(Object.keys(files).sort()).toEqual([...PROOF_PACK_ENTRIES].sort());
    expect(strFromU8(files["README.txt"])).toContain("only its SHA-256 is sent");
    expect(strFromU8(files["verification-summary.txt"])).toContain("Media type: audio");
  });

  it("generates a local valid SVG QR without making a fetch request", () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const svg = strFromU8(entries()["qr-code.svg"]);
    expect(svg).toMatch(/^<\?xml[^>]*>\s*<svg/);
    expect(svg).toContain("xmlns=\"http://www.w3.org/2000/svg\"");
    expect(svg).toContain("<path");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("excludes private fields, secrets, media, and delivery URLs", () => {
    const sentinelValues = [
      "private-prompt-sentinel",
      "private-manifest-sentinel",
      "service-role-secret-sentinel",
      "b2-credential-sentinel",
      "openai-secret-sentinel",
      "presigned-delivery-url-sentinel",
    ];
    const unsafeRuntime = Object.assign({}, certificateFixture, {
      prompt_private: sentinelValues[0],
      private_manifest: sentinelValues[1],
      service_role_key: sentinelValues[2],
      b2_application_key: sentinelValues[3],
      openai_api_key: sentinelValues[4],
      download_url: sentinelValues[5],
      sealed_media: new Uint8Array([1, 2, 3]),
    }) as PublicCertificate;
    const serialized = Object.values(entries(unsafeRuntime)).map((value) => strFromU8(value)).join("\n");
    for (const sentinel of sentinelValues) expect(serialized).not.toContain(sentinel);
    expect(serialized).not.toContain("download_url");
    expect(serialized).not.toContain("authorization");
  });

  it("rejects private fields inside the public manifest", () => {
    expect(() =>
      buildProofPack({
        ...certificateFixture,
        public_manifest: { ...certificateFixture.public_manifest, prompt_private: "forbidden" },
      }),
    ).toThrow("PUBLIC_CERTIFICATE_INVALID");
  });
});
