"use client";

import { useState } from "react";

import { formatDuration } from "@/lib/format";
import type { DeliverySuccess } from "@/lib/types";
import { safeHttpUrl } from "@/lib/validation";

export function DeliveryButton({ certId, presentedSha256, mimeType }: { certId: string; presentedSha256: string; mimeType?: string | null }) {
  const [delivery, setDelivery] = useState<DeliverySuccess | null>(null);
  const [state, setState] = useState<"idle" | "loading" | "error">("idle");

  async function requestDelivery() {
    setState("loading");
    setDelivery(null);
    try {
      const response = await fetch(`/api/delivery/${encodeURIComponent(certId)}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ cert_id: certId, presented_sha256: presentedSha256 }),
      });
      const value = (await response.json()) as Partial<DeliverySuccess>;
      const url = safeHttpUrl(value.download_url);
      if (
        !response.ok ||
        value.status !== "issued" ||
        value.cert_id !== certId ||
        !url ||
        typeof value.expires_at !== "string" ||
        typeof value.expires_in !== "number"
      ) {
        throw new Error("safe-delivery-failure");
      }
      setDelivery({
        cert_id: certId,
        status: "issued",
        download_url: url,
        expires_at: value.expires_at,
        expires_in: value.expires_in,
      });
      setState("idle");
    } catch {
      setState("error");
    }
  }

  return (
    <div className="delivery-action" aria-live="polite">
      {delivery ? (
        <>
          {mimeType?.startsWith("audio/") && (
            <audio controls preload="none" src={delivery.download_url}>
              Your browser does not support secure audio playback.
            </audio>
          )}
          <a className="button button-primary" href={delivery.download_url} rel="noreferrer">
            Download verified asset
          </a>
          <small>Private link expires in {formatDuration(delivery.expires_in)}.</small>
        </>
      ) : (
        <button
          className="button button-primary"
          type="button"
          onClick={requestDelivery}
          disabled={state === "loading"}
        >
          {state === "loading" ? "Authorizing…" : "Request secure delivery"}
        </button>
      )}
      {state === "error" && (
        <p className="inline-error" role="alert">Delivery was not authorized. Recheck the evidence.</p>
      )}
    </div>
  );
}
