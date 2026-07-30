import { NextResponse } from "next/server";

import { isCertificateId, isSha256, safeHttpUrl } from "@/lib/validation";

const DELIVERY_TIMEOUT_MS = 8_000;

function safeFailure(status: number, code: string, message: string): NextResponse {
  return NextResponse.json(
    { error: { code, message } },
    { status, headers: { "Cache-Control": "no-store" } },
  );
}

function deliveryResponse(value: unknown): Record<string, unknown> | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const body = value as Record<string, unknown>;
  const downloadUrl = safeHttpUrl(body.download_url);
  if (
    body.status !== "issued" ||
    !isCertificateId(String(body.cert_id ?? "")) ||
    !downloadUrl ||
    typeof body.expires_at !== "string" ||
    typeof body.expires_in !== "number" ||
    !Number.isInteger(body.expires_in) ||
    body.expires_in < 1 ||
    body.expires_in > 900
  ) {
    return null;
  }
  return {
    cert_id: body.cert_id,
    status: "issued",
    download_url: downloadUrl,
    expires_at: body.expires_at,
    expires_in: body.expires_in,
  };
}

export async function POST(
  request: Request,
  context: { params: Promise<{ certId: string }> },
): Promise<NextResponse> {
  const { certId } = await context.params;
  let value: unknown;
  try {
    value = await request.json();
  } catch {
    return safeFailure(400, "MALFORMED_REQUEST", "Delivery request is malformed.");
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return safeFailure(400, "MALFORMED_REQUEST", "Delivery request is malformed.");
  }
  const body = value as Record<string, unknown>;
  const suppliedCertId = typeof body.cert_id === "string" ? body.cert_id : "";
  const presentedSha256 =
    typeof body.presented_sha256 === "string" ? body.presented_sha256 : "";
  if (
    !isCertificateId(certId) ||
    suppliedCertId !== certId ||
    !isSha256(presentedSha256)
  ) {
    return safeFailure(422, "MALFORMED_EVIDENCE", "Delivery evidence is invalid.");
  }

  const deliveryKey = process.env.FIREMARK_DELIVERY_API_KEY;
  const apiBase = safeHttpUrl(
    process.env.NEXT_PUBLIC_FIREMARK_API_BASE_URL ?? "http://127.0.0.1:8000",
  );
  if (!deliveryKey?.trim() || !apiBase) {
    return safeFailure(503, "DELIVERY_NOT_CONFIGURED", "Secure delivery is unavailable.");
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), DELIVERY_TIMEOUT_MS);
  let response: Response;
  try {
    response = await fetch(
      `${apiBase.replace(/\/$/, "")}/v1/delivery/${encodeURIComponent(certId)}`,
      {
        method: "POST",
        headers: {
          Accept: "application/json",
          Authorization: `Bearer ${deliveryKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ presented_sha256: presentedSha256 }),
        cache: "no-store",
        signal: controller.signal,
      },
    );
  } catch {
    return safeFailure(503, "DELIVERY_BACKEND_UNAVAILABLE", "Secure delivery is unavailable.");
  } finally {
    clearTimeout(timeout);
  }

  if (!response.ok) {
    const status = response.status === 403 ? 403 : response.status === 422 ? 422 : 503;
    return safeFailure(
      status,
      status === 403 ? "DELIVERY_BLOCKED" : "DELIVERY_BACKEND_UNAVAILABLE",
      status === 403
        ? "Verification did not authorize delivery."
        : "Secure delivery is unavailable.",
    );
  }
  let parsed: unknown;
  try {
    parsed = await response.json();
  } catch {
    return safeFailure(503, "DELIVERY_BACKEND_INVALID", "Secure delivery is unavailable.");
  }
  const safe = deliveryResponse(parsed);
  if (!safe || safe.cert_id !== certId) {
    return safeFailure(503, "DELIVERY_BACKEND_INVALID", "Secure delivery is unavailable.");
  }
  return NextResponse.json(safe, {
    status: 200,
    headers: { "Cache-Control": "private, no-store, max-age=0" },
  });
}
