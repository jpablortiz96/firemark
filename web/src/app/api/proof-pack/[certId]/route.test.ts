import { strFromU8, unzipSync } from "fflate";

import { GET } from "@/app/api/proof-pack/[certId]/route";
import { getCertificate } from "@/lib/api";
import { certificateFixture, CERT_ID } from "@/test/fixtures";

vi.mock("@/lib/api", () => ({ getCertificate: vi.fn() }));

describe("Proof Pack route", () => {
  it("returns a no-store ZIP from the public certificate only", async () => {
    vi.mocked(getCertificate).mockResolvedValueOnce({
      state: "found",
      certificate: certificateFixture,
    });
    const response = await GET(new Request(`https://web.test/api/proof-pack/${CERT_ID}`), {
      params: Promise.resolve({ certId: CERT_ID }),
    });
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/zip");
    expect(response.headers.get("cache-control")).toContain("no-store");
    expect(response.headers.get("content-disposition")).toBe(
      `attachment; filename="firemark-proof-${CERT_ID}.zip"`,
    );
    const files = unzipSync(new Uint8Array(await response.arrayBuffer()));
    expect(strFromU8(files["certificate.json"])).toContain(CERT_ID);
    expect(getCertificate).toHaveBeenCalledWith(CERT_ID);
  });

  it.each([
    ["unsafe/id", 404],
    [CERT_ID, 404],
  ] as const)("returns a safe failure for %s", async (certId, expected) => {
    if (certId === CERT_ID) vi.mocked(getCertificate).mockResolvedValueOnce({ state: "not_found" });
    const response = await GET(new Request("https://web.test/api/proof-pack/check"), {
      params: Promise.resolve({ certId }),
    });
    expect(response.status).toBe(expected);
    expect(await response.text()).not.toContain("private service failure");
  });
});
