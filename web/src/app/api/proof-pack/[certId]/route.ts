import { NextResponse } from "next/server";

import { getCertificate } from "@/lib/api";
import { buildProofPack } from "@/lib/proof-pack";
import { isCertificateId } from "@/lib/validation";

export const dynamic = "force-dynamic";

function safeFailure(status: number, code: string): NextResponse {
  return NextResponse.json(
    { error: { code, message: "A public Proof Pack could not be created." } },
    { status, headers: { "Cache-Control": "no-store" } },
  );
}

export async function GET(
  _request: Request,
  context: { params: Promise<{ certId: string }> },
): Promise<Response> {
  const { certId } = await context.params;
  if (!isCertificateId(certId)) return safeFailure(404, "CERTIFICATE_NOT_FOUND");
  const lookup = await getCertificate(certId);
  if (lookup.state !== "found") {
    return safeFailure(
      lookup.state === "revoked" ? 410 : lookup.state === "not_found" ? 404 : 503,
      lookup.state === "revoked" ? "CERTIFICATE_REVOKED" : "CERTIFICATE_UNAVAILABLE",
    );
  }
  try {
    const pack = buildProofPack(lookup.certificate);
    return new Response(new Uint8Array(pack.bytes).buffer, {
      status: 200,
      headers: {
        "Cache-Control": "private, no-store, max-age=0",
        "Content-Disposition": `attachment; filename="${pack.filename}"`,
        "Content-Type": "application/zip",
        "X-Content-Type-Options": "nosniff",
      },
    });
  } catch {
    return safeFailure(503, "PROOF_PACK_UNAVAILABLE");
  }
}
