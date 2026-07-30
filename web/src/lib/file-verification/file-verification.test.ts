import { webcrypto } from "node:crypto";

import fixture from "@/test/fixtures/public-capsule-v1.json";
import { LensVerificationError } from "@/lib/file-verification/errors";
import { sha256Hex } from "@/lib/file-verification/hash";
import { extractPublicCapsulePng, hasPngMagic } from "@/lib/file-verification/png";
import { MAX_FILE_BYTES, PUBLIC_CAPSULE_KEY } from "@/lib/file-verification/types";
import { verifyLocalPng } from "@/lib/file-verification/verify-file";
import type { VerificationResult } from "@/lib/types";
import { verificationFixture } from "@/test/fixtures";

function bytes(base64: string): Uint8Array {
  return Uint8Array.from(Buffer.from(base64, "base64"));
}

const CRC_TABLE = new Uint32Array(256).map((_, index) => {
  let value = index;
  for (let bit = 0; bit < 8; bit += 1) {
    value = (value & 1) !== 0 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
  }
  return value >>> 0;
});

function crc32(value: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of value) crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function chunk(kind: string, data: Uint8Array): Uint8Array {
  const type = new TextEncoder().encode(kind);
  const output = new Uint8Array(12 + data.length);
  const view = new DataView(output.buffer);
  view.setUint32(0, data.length, false);
  output.set(type, 4);
  output.set(data, 8);
  view.setUint32(8 + data.length, crc32(output.subarray(4, 8 + data.length)), false);
  return output;
}

function capsuleChunk(payload: Uint8Array): Uint8Array {
  const key = new TextEncoder().encode(`${PUBLIC_CAPSULE_KEY}\0`);
  const data = new Uint8Array(key.length + payload.length);
  data.set(key);
  data.set(payload, key.length);
  return chunk("tEXt", data);
}

function capsuleBounds(png: Uint8Array): [number, number] {
  const marker = new TextEncoder().encode(`${PUBLIC_CAPSULE_KEY}\0`);
  const markerStart = png.findIndex((_, index) =>
    marker.every((byte, offset) => png[index + offset] === byte),
  );
  const start = markerStart - 8;
  const length = new DataView(png.buffer, png.byteOffset).getUint32(start, false);
  return [start, start + 12 + length];
}

function replaceCapsule(png: Uint8Array, payload: Uint8Array): Uint8Array {
  const [start, end] = capsuleBounds(png);
  const replacement = capsuleChunk(payload);
  const output = new Uint8Array(png.length - (end - start) + replacement.length);
  output.set(png.subarray(0, start));
  output.set(replacement, start);
  output.set(png.subarray(end), start + replacement.length);
  return output;
}

function duplicateCapsule(png: Uint8Array, payload: Uint8Array): Uint8Array {
  const extra = capsuleChunk(payload);
  const output = new Uint8Array(png.length + extra.length);
  output.set(png.subarray(0, -12));
  output.set(extra, png.length - 12);
  output.set(png.subarray(-12), png.length - 12 + extra.length);
  return output;
}

function modifyIdatByte(png: Uint8Array): Uint8Array {
  const output = png.slice();
  let offset = 8;
  const view = new DataView(output.buffer);
  while (offset < output.length) {
    const length = view.getUint32(offset, false);
    const type = String.fromCharCode(...output.subarray(offset + 4, offset + 8));
    if (type === "IDAT") {
      output[offset + 8] ^= 1;
      view.setUint32(
        offset + 8 + length,
        crc32(output.subarray(offset + 4, offset + 8 + length)),
        false,
      );
      return output;
    }
    offset += 12 + length;
  }
  throw new Error("fixture has no IDAT");
}

function pngFile(value: Uint8Array, name = "sealed.png", type = "image/png"): File {
  return new File([new Uint8Array(value).buffer], name, { type });
}

function result(status: VerificationResult["status"]): VerificationResult {
  return { ...verificationFixture(status), cert_id: fixture.capsule.cert_id };
}

describe("browser PNG and public capsule contract", () => {
  const sealed = bytes(fixture.sealed_png_base64);
  const source = bytes(fixture.source_png_base64);

  it("recognizes real PNG magic and rejects renamed non-PNG bytes", () => {
    expect(hasPngMagic(sealed)).toBe(true);
    expect(hasPngMagic(new TextEncoder().encode("not a png"))).toBe(false);
    expect(() => extractPublicCapsulePng(new TextEncoder().encode("not a png"))).toThrowError(
      expect.objectContaining({ code: "PNG_MAGIC_INVALID" }),
    );
  });

  it("parses the Python-generated canonical FiremarkPublicCapsuleV1 fixture", () => {
    const capsule = extractPublicCapsulePng(sealed);
    expect(capsule).toMatchObject({
      ...fixture.capsule,
      issued_at: "2026-07-30T12:00:00.000000Z",
    });
    expect(capsule).not.toHaveProperty("sealed_sha256");
  });

  it("rejects truncated PNGs and impossible chunk lengths", () => {
    expect(() => extractPublicCapsulePng(sealed.subarray(0, sealed.length - 5))).toThrow(
      LensVerificationError,
    );
    const invalidLength = sealed.slice();
    new DataView(invalidLength.buffer).setUint32(8, 0xffffffff, false);
    expect(() => extractPublicCapsulePng(invalidLength)).toThrowError(
      expect.objectContaining({ code: "PNG_CHUNK_LENGTH_INVALID" }),
    );
  });

  it("distinguishes a missing capsule from duplicate and conflicting metadata", () => {
    expect(() => extractPublicCapsulePng(source)).toThrowError(
      expect.objectContaining({ code: "CAPSULE_MISSING" }),
    );
    const canonical = new TextEncoder().encode(fixture.canonical_json);
    expect(() => extractPublicCapsulePng(duplicateCapsule(sealed, canonical))).toThrowError(
      expect.objectContaining({ code: "CAPSULE_DUPLICATE" }),
    );
    const conflicting = canonical.slice();
    conflicting[20] ^= 1;
    expect(() => extractPublicCapsulePng(duplicateCapsule(sealed, conflicting))).toThrowError(
      expect.objectContaining({ code: "CAPSULE_CONFLICTING" }),
    );
  });

  it.each([
    ["malformed JSON", new TextEncoder().encode("not-json"), "CAPSULE_JSON_INVALID"],
    [
      "unknown schema",
      new TextEncoder().encode(fixture.canonical_json.replace("public-capsule.v1", "public-capsule.v2")),
      "CAPSULE_SCHEMA_INVALID",
    ],
    [
      "private field",
      new TextEncoder().encode(
        JSON.stringify({ ...JSON.parse(fixture.canonical_json), prompt_private: "forbidden" }),
      ),
      "CAPSULE_PRIVATE_FIELD",
    ],
    ["oversized capsule", new Uint8Array(8 * 1024 + 1).fill(65), "CAPSULE_TOO_LARGE"],
  ])("rejects %s", (_label, payload, code) => {
    expect(() => extractPublicCapsulePng(replaceCapsule(sealed, payload))).toThrowError(
      expect.objectContaining({ code }),
    );
  });

  it("computes lowercase SHA-256 locally with Web Crypto", async () => {
    vi.stubGlobal("crypto", webcrypto);
    await expect(sha256Hex(sealed)).resolves.toBe(fixture.sealed_sha256);
  });

  it("enforces MIME, extension, and the 25 MiB bound before reading", async () => {
    const verify = vi.fn();
    await expect(verifyLocalPng(pngFile(sealed, "sealed.jpg"), { verify })).resolves.toMatchObject({
      state: "invalid_file",
    });
    await expect(verifyLocalPng(pngFile(sealed, "sealed.png", "image/jpeg"), { verify })).resolves.toMatchObject({
      state: "invalid_file",
    });
    const oversized = new File([new Uint8Array(MAX_FILE_BYTES + 1).buffer], "large.png", { type: "image/png" });
    await expect(verifyLocalPng(oversized, { verify })).resolves.toMatchObject({ state: "invalid_file" });
    expect(verify).not.toHaveBeenCalled();
  });

  it("sends only cert_id and the separately calculated hash", async () => {
    vi.stubGlobal("crypto", webcrypto);
    const verify = vi.fn().mockResolvedValue(result("verified"));
    const file = pngFile(sealed);
    const output = await verifyLocalPng(file, { verify });
    expect(output.state).toBe("verified");
    expect(verify).toHaveBeenCalledWith(
      {
        cert_id: fixture.capsule.cert_id,
        presented_sha256: fixture.sealed_sha256,
      },
      undefined,
    );
    expect(JSON.stringify(verify.mock.calls)).not.toContain(file.name);
  });

  it("never places file bytes in the real fetch body", async () => {
    vi.stubGlobal("crypto", webcrypto);
    vi.stubEnv("NEXT_PUBLIC_FIREMARK_API_BASE_URL", "https://api.firemark.test");
    const backend = result("verified");
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(backend), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    await expect(verifyLocalPng(pngFile(sealed))).resolves.toMatchObject({ state: "verified" });
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(JSON.parse(String(init.body))).toEqual({
      cert_id: fixture.capsule.cert_id,
      presented_sha256: fixture.sealed_sha256,
    });
    expect(init.body).not.toBeInstanceOf(ArrayBuffer);
    expect(init.body).not.toBeInstanceOf(Uint8Array);
  });

  it.each([
    ["hash_mismatch", "tampered"],
    ["certificate_revoked", "revoked"],
    ["certificate_not_found", "not_found"],
  ] as const)("maps backend %s to the layered %s result", async (status, state) => {
    vi.stubGlobal("crypto", webcrypto);
    const verify = vi.fn().mockResolvedValue(result(status));
    const fileBytes = status === "hash_mismatch" ? modifyIdatByte(sealed) : sealed;
    const output = await verifyLocalPng(pngFile(fileBytes), { verify });
    expect(output.state).toBe(state);
    expect(output.layers).toHaveLength(8);
    expect(output.layers.at(-1)?.status).toBe("FAIL");
  });

  it("does not call the API for a PNG without a capsule", async () => {
    const verify = vi.fn();
    const output = await verifyLocalPng(pngFile(source), { verify });
    expect(output.state).toBe("no_capsule");
    expect(verify).not.toHaveBeenCalled();
  });

  it("does not trust or submit malformed reserved metadata", async () => {
    const verify = vi.fn();
    const malformed = replaceCapsule(sealed, new TextEncoder().encode("not-json"));
    const output = await verifyLocalPng(pngFile(malformed), { verify });
    expect(output.state).toBe("malformed_capsule");
    expect(verify).not.toHaveBeenCalled();
  });
});
