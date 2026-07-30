import { getCertificate, verifyCertificate } from "@/lib/api";
import { SafeApiError } from "@/lib/errors";
import { certificateFixture, CERT_ID, SEALED_SHA, verificationFixture } from "@/test/fixtures";

function response(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("typed public API client", () => {
  beforeEach(() => {
    vi.stubEnv("NEXT_PUBLIC_FIREMARK_API_BASE_URL", "https://api.firemark.test");
  });

  it("accepts an allowlisted active certificate response", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response(certificateFixture)));
    await expect(getCertificate(CERT_ID)).resolves.toEqual({
      state: "found",
      certificate: certificateFixture,
    });
  });

  it.each([
    [404, "not_found"],
    [410, "revoked"],
  ] as const)("normalizes certificate HTTP %s", async (status, state) => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response({}, status)));
    await expect(getCertificate(`${CERT_ID}-${status}`)).resolves.toEqual({ state });
  });

  it("rejects a public manifest containing private fields", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        response({
          ...certificateFixture,
          public_manifest: { ...certificateFixture.public_manifest, prompt: "secret-sentinel" },
        }),
      ),
    );
    await expect(getCertificate(CERT_ID)).resolves.toEqual({ state: "error" });
  });

  it("sends typed verification requests and parses safe results", async () => {
    const fetchMock = vi.fn().mockResolvedValue(response(verificationFixture()));
    vi.stubGlobal("fetch", fetchMock);
    await expect(
      verifyCertificate({ cert_id: CERT_ID, presented_sha256: SEALED_SHA }),
    ).resolves.toEqual(verificationFixture());
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.firemark.test/v1/verify",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ cert_id: CERT_ID, presented_sha256: SEALED_SHA }),
      }),
    );
  });

  it("normalizes backend and network errors without exposing raw details", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        response({ error: { code: "MALFORMED_REQUEST", message: "raw private detail" } }, 422),
      ),
    );
    await expect(verifyCertificate({ cert_id: CERT_ID })).rejects.toMatchObject({
      code: "MALFORMED_REQUEST",
      message: "The supplied evidence is not in a valid FIREMARK format.",
    });
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("raw network secret")));
    await expect(verifyCertificate({ cert_id: CERT_ID })).rejects.toBeInstanceOf(SafeApiError);
  });
});
