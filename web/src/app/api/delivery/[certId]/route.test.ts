import { POST } from "@/app/api/delivery/[certId]/route";
import { CERT_ID, SEALED_SHA } from "@/test/fixtures";

const SECRET = "server-only-delivery-key-sentinel";
const DOWNLOAD_URL = "https://private.example.test/file?short-lived=sentinel";

function request(body: unknown): Request {
  return new Request(`http://localhost/api/delivery/${CERT_ID}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

function backendResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

const context = { params: Promise.resolve({ certId: CERT_ID }) };

describe("server-side delivery boundary", () => {
  beforeEach(() => {
    vi.stubEnv("NEXT_PUBLIC_FIREMARK_API_BASE_URL", "https://api.firemark.test");
  });

  it("fails safely when the server-only key is absent", async () => {
    vi.stubEnv("FIREMARK_DELIVERY_API_KEY", "");
    const response = await POST(
      request({ cert_id: CERT_ID, presented_sha256: SEALED_SHA }),
      context,
    );
    expect(response.status).toBe(503);
    expect(await response.text()).not.toContain("download_url");
  });

  it("sends the bearer only to FastAPI and returns a URL only on success", async () => {
    vi.stubEnv("FIREMARK_DELIVERY_API_KEY", SECRET);
    const fetchMock = vi.fn().mockResolvedValue(
      backendResponse({
        cert_id: CERT_ID,
        status: "issued",
        download_url: DOWNLOAD_URL,
        expires_at: "2026-07-30T12:05:00Z",
        expires_in: 300,
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const consoleLog = vi.spyOn(console, "log").mockImplementation(() => undefined);
    const response = await POST(
      request({ cert_id: CERT_ID, presented_sha256: SEALED_SHA }),
      context,
    );
    const text = await response.text();
    expect(response.status).toBe(200);
    expect(text).toContain(DOWNLOAD_URL.replace("?", "?"));
    expect(text).not.toContain(SECRET);
    expect(consoleLog).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledWith(
      `https://api.firemark.test/v1/delivery/${CERT_ID}`,
      expect.objectContaining({
        headers: expect.objectContaining({ Authorization: `Bearer ${SECRET}` }),
        body: JSON.stringify({ presented_sha256: SEALED_SHA }),
      }),
    );
  });

  it.each([
    [403, "DELIVERY_BLOCKED"],
    [503, "DELIVERY_BACKEND_UNAVAILABLE"],
  ] as const)("never returns a URL for backend HTTP %s", async (status, code) => {
    vi.stubEnv("FIREMARK_DELIVERY_API_KEY", SECRET);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(backendResponse({}, status)));
    const response = await POST(
      request({ cert_id: CERT_ID, presented_sha256: SEALED_SHA }),
      context,
    );
    const text = await response.text();
    expect(response.status).toBe(status === 403 ? 403 : 503);
    expect(text).toContain(code);
    expect(text).not.toContain("download_url");
    expect(text).not.toContain(SECRET);
  });

  it("normalizes network and malformed success responses", async () => {
    vi.stubEnv("FIREMARK_DELIVERY_API_KEY", SECRET);
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("raw bearer detail")));
    const unavailable = await POST(
      request({ cert_id: CERT_ID, presented_sha256: SEALED_SHA }),
      context,
    );
    expect(await unavailable.text()).not.toContain("raw bearer detail");

    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(backendResponse({ status: "issued" })));
    const invalid = await POST(
      request({ cert_id: CERT_ID, presented_sha256: SEALED_SHA }),
      context,
    );
    expect(invalid.status).toBe(503);
    expect(await invalid.text()).not.toContain("download_url");
  });

  it("requires matching certificate identity and a valid sealed hash", async () => {
    vi.stubEnv("FIREMARK_DELIVERY_API_KEY", SECRET);
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const response = await POST(
      request({ cert_id: "different-cert", presented_sha256: "invalid" }),
      context,
    );
    expect(response.status).toBe(422);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
