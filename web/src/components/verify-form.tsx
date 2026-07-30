"use client";

import { FormEvent, useState } from "react";

import { VerificationResult } from "@/components/verification-result";
import { SafeApiError, safeErrorMessage } from "@/lib/errors";
import { verifyCertificate } from "@/lib/api";
import type { VerificationResult as Result } from "@/lib/types";
import { isCertificateId, isSha256 } from "@/lib/validation";

export function VerifyForm({ initialCertId = "", initialSha256 = "" }: { initialCertId?: string; initialSha256?: string }) {
  const [certId, setCertId] = useState(initialCertId);
  const [sha256, setSha256] = useState(initialSha256);
  const [result, setResult] = useState<Result | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setResult(null);
    setError("");
    const normalizedId = certId.trim();
    const normalizedHash = sha256.trim().toLowerCase();
    if (!isCertificateId(normalizedId)) {
      setError("Enter a valid FIREMARK certificate ID using 1–128 safe characters.");
      return;
    }
    if (normalizedHash && !isSha256(normalizedHash)) {
      setError("A sealed SHA-256 must contain exactly 64 lowercase hexadecimal characters.");
      return;
    }
    setLoading(true);
    try {
      setResult(
        await verifyCertificate({
          cert_id: normalizedId,
          ...(normalizedHash ? { presented_sha256: normalizedHash } : {}),
        }),
      );
    } catch (caught) {
      setError(
        caught instanceof SafeApiError
          ? safeErrorMessage(caught)
          : "Verification could not be completed safely. Please retry.",
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="verify-workspace" id="certificate-lookup">
      <form className="verify-form" onSubmit={submit} noValidate>
        <div className="form-heading">
          <span className="step-label">LIVE VERIFY GATE</span>
          <h1>Check evidence before you trust the asset.</h1>
          <p>Certificate lookup is public. Add the final file hash to prove byte-for-byte identity.</p>
        </div>
        <label htmlFor="cert-id">Certificate ID <span>Required</span></label>
        <input
          id="cert-id"
          name="cert_id"
          value={certId}
          onChange={(event) => setCertId(event.target.value)}
          autoComplete="off"
          spellCheck={false}
          placeholder="fm-cert-…"
          required
        />
        <label htmlFor="sha256">Sealed SHA-256 <span>Optional for verification · required for delivery</span></label>
        <input
          id="sha256"
          name="presented_sha256"
          value={sha256}
          onChange={(event) => setSha256(event.target.value)}
          autoComplete="off"
          spellCheck={false}
          placeholder="64 lowercase hexadecimal characters"
        />
        <div className="upload-placeholder" aria-disabled="true">
          <span aria-hidden="true">↥</span>
          <div><strong>Media upload verification</strong><small>Coming in a future release</small></div>
        </div>
        <button className="button button-primary submit-button" type="submit" disabled={loading}>
          {loading ? "Verifying evidence…" : "Run Verify Gate"}
        </button>
        <p className="form-privacy">No prompt, private manifest, or storage reference is requested.</p>
      </form>
      <div className="result-region" aria-live="polite" aria-busy={loading}>
        {loading && (
          <div className="verification-loading" role="status">
            <span className="loading-ring" aria-hidden="true" />
            <div><strong>Validating signed evidence</strong><p>Checking certificate, signature, custody, and hash…</p></div>
          </div>
        )}
        {error && <div className="safe-error" role="alert"><strong>Unable to verify</strong><p>{error}</p></div>}
        {result && <VerificationResult result={result} presentedSha256={sha256.trim().toLowerCase() || undefined} />}
        {!loading && !error && !result && (
          <div className="result-empty">
            <div className="empty-shield" aria-hidden="true">FM</div>
            <h2>Verification result</h2>
            <p>Your result will appear here with clear evidence checks and a safe next action.</p>
          </div>
        )}
      </div>
    </div>
  );
}
