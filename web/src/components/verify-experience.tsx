"use client";

import { useState } from "react";

import { AudioVerifier } from "@/components/audio-verifier";
import { LensVerifier } from "@/components/lens-verifier";
import { VerifyForm } from "@/components/verify-form";
import type { MediaMode } from "@/lib/file-verification/types";

type Mode = MediaMode | "certificate";

const MEDIA_TABS: { mode: MediaMode; label: string; hint: string }[] = [
  { mode: "image", label: "Image · PNG", hint: "Reads the embedded FIREMARK capsule" },
  { mode: "audio", label: "Audio · MP3", hint: "Uses a certificate ID and a local SHA-256" },
];

export function VerifyExperience({
  initialCertId = "",
  initialSha256 = "",
  initialMedia,
}: {
  initialCertId?: string;
  initialSha256?: string;
  initialMedia?: MediaMode;
}) {
  // An explicit media request always wins. A bare cert_id still opens the
  // manual certificate form, preserving the previous behaviour.
  const [mode, setMode] = useState<Mode>(
    initialMedia ?? (initialCertId ? "certificate" : "image"),
  );

  return (
    <div>
      <div className="verify-mode-tabs" role="tablist" aria-label="Verification mode">
        {MEDIA_TABS.map((tab) => (
          <button
            key={tab.mode}
            type="button"
            role="tab"
            id={`verify-tab-${tab.mode}`}
            aria-selected={mode === tab.mode}
            aria-controls={`verify-panel-${tab.mode}`}
            title={tab.hint}
            onClick={() => setMode(tab.mode)}
          >
            {tab.label}
          </button>
        ))}
        <button
          type="button"
          role="tab"
          id="verify-tab-certificate"
          aria-selected={mode === "certificate"}
          aria-controls="verify-panel-certificate"
          onClick={() => setMode("certificate")}
        >
          Verify by certificate ID
        </button>
      </div>
      <div
        id={`verify-panel-${mode}`}
        role="tabpanel"
        aria-labelledby={`verify-tab-${mode}`}
        tabIndex={-1}
      >
        {/* The key forces a fresh panel per mode, so no result, error or
            in-flight request can survive a media switch. */}
        {mode === "image" ? (
          <LensVerifier key="image" />
        ) : mode === "audio" ? (
          <AudioVerifier key="audio" initialCertId={initialCertId} />
        ) : (
          <VerifyForm key="certificate" initialCertId={initialCertId} initialSha256={initialSha256} />
        )}
      </div>
    </div>
  );
}
