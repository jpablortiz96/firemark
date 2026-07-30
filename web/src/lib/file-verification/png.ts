import { LensVerificationError } from "@/lib/file-verification/errors";
import { parsePublicCapsule } from "@/lib/file-verification/capsule";
import type { FiremarkPublicCapsuleV1 } from "@/lib/file-verification/types";
import { PUBLIC_CAPSULE_KEY } from "@/lib/file-verification/types";

export const PNG_MAGIC = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]);
const TEXT_CHUNKS = new Set(["tEXt", "zTXt", "iTXt"]);
const keyword = new TextEncoder().encode(PUBLIC_CAPSULE_KEY);

const CRC_TABLE = new Uint32Array(256).map((_, index) => {
  let value = index;
  for (let bit = 0; bit < 8; bit += 1) {
    value = (value & 1) !== 0 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
  }
  return value >>> 0;
});

function crc32(bytes: Uint8Array): number {
  let value = 0xffffffff;
  for (const byte of bytes) value = CRC_TABLE[(value ^ byte) & 0xff] ^ (value >>> 8);
  return (value ^ 0xffffffff) >>> 0;
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.byteLength === right.byteLength && left.every((byte, index) => byte === right[index]);
}

function chunkName(bytes: Uint8Array): string {
  return String.fromCharCode(...bytes);
}

export function hasPngMagic(bytes: Uint8Array): boolean {
  return bytes.byteLength >= PNG_MAGIC.byteLength && sameBytes(bytes.subarray(0, 8), PNG_MAGIC);
}

export function extractPublicCapsulePng(bytes: Uint8Array): FiremarkPublicCapsuleV1 {
  if (!hasPngMagic(bytes)) {
    throw new LensVerificationError("PNG_MAGIC_INVALID", "file");
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const payloads: Uint8Array[] = [];
  let offset = PNG_MAGIC.byteLength;
  let sawEnd = false;
  while (offset < bytes.byteLength) {
    if (bytes.byteLength - offset < 12) {
      throw new LensVerificationError("PNG_TRUNCATED", "file");
    }
    const length = view.getUint32(offset, false);
    const dataStart = offset + 8;
    const dataEnd = dataStart + length;
    const chunkEnd = dataEnd + 4;
    if (dataEnd < dataStart || chunkEnd > bytes.byteLength) {
      throw new LensVerificationError("PNG_CHUNK_LENGTH_INVALID", "file");
    }
    const typeBytes = bytes.subarray(offset + 4, offset + 8);
    const expectedCrc = view.getUint32(dataEnd, false);
    if (crc32(bytes.subarray(offset + 4, dataEnd)) !== expectedCrc) {
      throw new LensVerificationError("PNG_CHUNK_CRC_INVALID", "file");
    }
    const type = chunkName(typeBytes);
    const data = bytes.subarray(dataStart, dataEnd);
    if (TEXT_CHUNKS.has(type)) {
      const separator = data.indexOf(0);
      if (separator >= 0 && sameBytes(data.subarray(0, separator), keyword)) {
        if (type !== "tEXt") {
          throw new LensVerificationError(
            "CAPSULE_ENCODING_UNSUPPORTED",
            "malformed_capsule",
          );
        }
        payloads.push(data.slice(separator + 1));
      }
    }
    offset = chunkEnd;
    if (type === "IEND") {
      sawEnd = true;
      break;
    }
  }
  if (!sawEnd || offset !== bytes.byteLength) {
    throw new LensVerificationError("PNG_IEND_INVALID", "file");
  }
  if (payloads.length === 0) {
    throw new LensVerificationError("CAPSULE_MISSING", "no_capsule");
  }
  if (payloads.length > 1) {
    const identical = payloads.slice(1).every((payload) => sameBytes(payload, payloads[0]));
    throw new LensVerificationError(
      identical ? "CAPSULE_DUPLICATE" : "CAPSULE_CONFLICTING",
      "malformed_capsule",
    );
  }
  return parsePublicCapsule(payloads[0]);
}
