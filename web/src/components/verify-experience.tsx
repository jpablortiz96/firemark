"use client";

import { useState } from "react";

import { LensVerifier } from "@/components/lens-verifier";
import { VerifyForm } from "@/components/verify-form";

export function VerifyExperience({
  initialCertId = "",
  initialSha256 = "",
}: {
  initialCertId?: string;
  initialSha256?: string;
}) {
  const [mode, setMode] = useState<"file" | "certificate">(
    initialCertId ? "certificate" : "file",
  );
  return (
    <div>
      <div className="verify-mode-tabs" role="tablist" aria-label="Verification mode">
        <button type="button" role="tab" aria-selected={mode === "file"} onClick={() => setMode("file")}>
          Verify by file
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
      {mode === "file" ? (
        <LensVerifier />
      ) : (
        <VerifyForm initialCertId={initialCertId} initialSha256={initialSha256} />
      )}
    </div>
  );
}
