"use client";

import { useState } from "react";

import { LensVerifier } from "@/components/lens-verifier";
import { AudioVerifier } from "@/components/audio-verifier";
import { VerifyForm } from "@/components/verify-form";

export function VerifyExperience({
  initialCertId = "",
  initialSha256 = "",
}: {
  initialCertId?: string;
  initialSha256?: string;
}) {
  const [mode, setMode] = useState<"image" | "audio" | "certificate">(
    initialCertId ? "certificate" : "image",
  );
  return (
    <div>
      <div className="verify-mode-tabs" role="tablist" aria-label="Verification mode">
        <button type="button" role="tab" aria-selected={mode === "image"} onClick={() => setMode("image")}>
          Image Lens
        </button>
        <button type="button" role="tab" aria-selected={mode === "audio"} onClick={() => setMode("audio")}>
          Audio hash
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={mode === "certificate"}
          onClick={() => setMode("certificate")}
        >
          Verify by certificate ID
        </button>
      </div>
      {mode === "image" ? (
        <LensVerifier />
      ) : mode === "audio" ? (
        <AudioVerifier />
      ) : (
        <VerifyForm initialCertId={initialCertId} initialSha256={initialSha256} />
      )}
    </div>
  );
}
