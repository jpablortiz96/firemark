import { abortError, LensVerificationError } from "@/lib/file-verification/errors";

function hex(bytes: ArrayBuffer): string {
  return Array.from(new Uint8Array(bytes), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function digestOnMainThread(bytes: Uint8Array, signal?: AbortSignal): Promise<string> {
  if (signal?.aborted) throw abortError();
  try {
    const input = bytes.slice().buffer;
    const digest = await crypto.subtle.digest("SHA-256", input);
    if (signal?.aborted) throw abortError();
    return hex(digest);
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    throw new LensVerificationError("HASH_UNAVAILABLE", "hash");
  }
}

async function digestInWorker(bytes: Uint8Array, signal?: AbortSignal): Promise<string> {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL("./hash.worker.ts", import.meta.url), { type: "module" });
    const abort = () => {
      worker.terminate();
      reject(abortError());
    };
    signal?.addEventListener("abort", abort, { once: true });
    worker.onmessage = (event: MessageEvent<{ digest?: ArrayBuffer; error?: string }>) => {
      signal?.removeEventListener("abort", abort);
      worker.terminate();
      if (event.data.digest) resolve(hex(event.data.digest));
      else reject(new LensVerificationError("HASH_UNAVAILABLE", "hash"));
    };
    worker.onerror = () => {
      signal?.removeEventListener("abort", abort);
      worker.terminate();
      reject(new LensVerificationError("HASH_UNAVAILABLE", "hash"));
    };
    const input = bytes.slice().buffer;
    worker.postMessage(input, [input]);
  });
}

export async function sha256Hex(bytes: Uint8Array, signal?: AbortSignal): Promise<string> {
  if (signal?.aborted) throw abortError();
  if (typeof Worker !== "undefined") {
    try {
      return await digestInWorker(bytes, signal);
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") throw error;
    }
  }
  return digestOnMainThread(bytes, signal);
}
