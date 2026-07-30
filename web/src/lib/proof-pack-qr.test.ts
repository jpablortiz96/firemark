import { buildProofPack } from "@/lib/proof-pack";
import { certificateFixture } from "@/test/fixtures";

const qrOptions = vi.hoisted(() => vi.fn());

vi.mock("qrcode-svg", () => ({
  default: class MockQRCode {
    constructor(options: unknown) {
      qrOptions(options);
    }

    svg() {
      return '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><path /></svg>';
    }
  },
}));

it("encodes the certificate public verification URL in the local QR generator", () => {
  const fetchMock = vi.fn();
  vi.stubGlobal("fetch", fetchMock);
  buildProofPack(certificateFixture);
  expect(qrOptions).toHaveBeenCalledWith(
    expect.objectContaining({ content: certificateFixture.verify_url }),
  );
  expect(fetchMock).not.toHaveBeenCalled();
});
