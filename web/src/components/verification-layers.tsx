import Link from "next/link";

import { DeliveryButton } from "@/components/delivery-button";
import type { LensResult } from "@/lib/file-verification/types";

const RESULT_COPY: Record<
  LensResult["state"],
  { title: string; body: string; tone: "verified" | "warning" }
> = {
  verified: {
    title: "Asset is authentic and unchanged",
    body: "The local file hash agrees with the active signed FIREMARK record.",
    tone: "verified",
  },
  tampered: {
    title: "Asset hash does not match",
    body: "The capsule and certificate exist, but these file bytes differ from the sealed asset.",
    tone: "warning",
  },
  no_capsule: {
    title: "No FIREMARK provenance found",
    body: "This PNG has no FIREMARK public capsule. No verification request was sent.",
    tone: "warning",
  },
  malformed_capsule: {
    title: "FIREMARK metadata is invalid",
    body: "Reserved metadata was found but could not be trusted. No identifier was submitted.",
    tone: "warning",
  },
  invalid_file: {
    title: "File is not a valid supported PNG",
    body: "FIREMARK Lens rejected the type, size, signature, or PNG structure locally.",
    tone: "warning",
  },
  revoked: {
    title: "Certificate revoked",
    body: "The capsule may be intact, but the issuer revoked this certificate. Delivery is blocked.",
    tone: "warning",
  },
  not_found: {
    title: "Certificate not found",
    body: "The capsule is syntactically valid, but no registered public certificate was found.",
    tone: "warning",
  },
  unverified: {
    title: "Asset could not be verified",
    body: "One or more signed evidence layers failed. Treat this asset as unverified.",
    tone: "warning",
  },
  unavailable: {
    title: "Verification service unavailable",
    body: "Local parsing completed, but the final Verify Gate decision could not be obtained safely.",
    tone: "warning",
  },
};

export function VerificationLayers({ result }: { result: LensResult }) {
  const copy = RESULT_COPY[result.state];
  return (
    <section className={`lens-result lens-result-${copy.tone}`} aria-labelledby="lens-result-title">
      <div className="lens-result-heading">
        <span className={`status-badge status-${copy.tone}`}>
          <span aria-hidden="true" /> {copy.tone === "verified" ? "Verified" : "Review required"}
        </span>
        <span>8 trust layers</span>
      </div>
      <h2 id="lens-result-title">{copy.title}</h2>
      <p>{copy.body}</p>
      {(result.capsule || result.certId) && (
        <div className="lens-evidence-summary">
          <div><span>{result.mediaType === "audio" ? "Entered certificate" : "Extracted certificate"}</span><code>{result.certId ?? result.capsule?.cert_id}</code></div>
          {result.sealedSha256 && (
            <div><span>Calculated sealed SHA-256</span><code>{result.sealedSha256}</code></div>
          )}
        </div>
      )}
      <ol className="verification-layers" aria-label="Independent verification layers">
        {result.layers.map((layer) => (
          <li key={layer.key} className={`layer-${layer.status.toLowerCase().replace(" ", "-")}`}>
            <span aria-hidden="true">
              {layer.status === "PASS" ? "✓" : layer.status === "FAIL" ? "×" : "–"}
            </span>
            <strong>{layer.label}</strong>
            <em>
              {layer.status}
              {layer.detail ? <span className="layer-detail"> — {layer.detail}</span> : null}
            </em>
          </li>
        ))}
      </ol>
      <p className="lens-custody-note">
        Local parsing proves neither B2 custody nor certificate validity by itself. Those layers
        come only from the backend Verify Gate.
      </p>
      <div className="result-actions">
        {(result.certId || result.capsule) && result.state !== "not_found" && (
          <Link
            className="button button-secondary"
            href={`/certificate/${encodeURIComponent(result.certId ?? result.capsule!.cert_id)}`}
          >
            View Birth Certificate
          </Link>
        )}
        {result.state === "verified" && (result.certId || result.capsule) && result.sealedSha256 && (
          <DeliveryButton
            certId={result.certId ?? result.capsule!.cert_id}
            presentedSha256={result.sealedSha256}
            mimeType={result.verification?.mime_type ?? result.mimeType}
          />
        )}
      </div>
    </section>
  );
}
