import Link from "next/link";

import { DeliveryButton } from "@/components/delivery-button";
import { StatusBadge } from "@/components/status-badge";
import { formatTimestamp } from "@/lib/format";
import type { VerificationResult as Result } from "@/lib/types";

const COPY = {
  verified: {
    title: "Evidence verified",
    body: "The signature, certificate, custody references, and presented asset hash agree.",
    action: "This asset can proceed through the secure delivery gate.",
  },
  hash_mismatch: {
    title: "Asset hash does not match",
    body: "The presented SHA-256 is not the sealed hash recorded by this certificate.",
    action: "Do not distribute this file. Obtain the original sealed asset and verify again.",
  },
  signature_invalid: {
    title: "Signature could not be validated",
    body: "The published signature does not validate against the certificate evidence.",
    action: "Treat the asset as untrusted and contact its issuer.",
  },
  certificate_revoked: {
    title: "Certificate revoked",
    body: "The issuer has revoked this Birth Certificate.",
    action: "Do not deliver the asset. Contact the issuer for current evidence.",
  },
  certificate_not_found: {
    title: "Certificate not found",
    body: "No public FIREMARK record matches that certificate ID.",
    action: "Check the identifier exactly or request a valid Birth Certificate.",
  },
  malformed_evidence: {
    title: "Evidence is malformed",
    body: "The certificate evidence is incomplete or internally inconsistent.",
    action: "Do not rely on this asset. Ask the issuer to regenerate valid evidence.",
  },
} as const;

function Indicator({ valid, label }: { valid: boolean; label: string }) {
  return (
    <li className={valid ? "indicator-valid" : "indicator-invalid"}>
      <span aria-hidden="true">{valid ? "✓" : "×"}</span> {label}
    </li>
  );
}

export function VerificationResult({ result, presentedSha256 }: { result: Result; presentedSha256?: string }) {
  const copy = COPY[result.status];
  return (
    <section
      className={`verification-result ${result.verified ? "result-verified" : "result-failed"}`}
      aria-labelledby="verification-result-title"
    >
      <div className="result-heading">
        <StatusBadge status={result.verified ? "verified" : "warning"} />
        <p>{formatTimestamp(result.verified_at)} · UTC</p>
      </div>
      <h2 id="verification-result-title">{copy.title}</h2>
      <p className="result-body">{copy.body}</p>
      <ul className="result-indicators">
        <Indicator valid={result.signature_valid} label="Signature valid" />
        <Indicator valid={result.envelope_valid} label="Envelope consistent" />
        <Indicator valid={result.custody_reference_valid} label="Custody references valid" />
        <Indicator valid={result.hash_match !== false} label="Presented hash matches" />
      </ul>
      <div className="reason-code">
        <span>Safe reason</span><code>{result.safe_reason_code}</code>
      </div>
      <p className="next-action"><strong>Next action:</strong> {copy.action}</p>
      <div className="result-actions">
        {result.status !== "certificate_not_found" && (
          <Link className="button button-secondary" href={`/certificate/${encodeURIComponent(result.cert_id)}`}>
            View Birth Certificate
          </Link>
        )}
        {result.verified && presentedSha256 && (
          <DeliveryButton certId={result.cert_id} presentedSha256={presentedSha256} mimeType={result.mime_type} />
        )}
      </div>
    </section>
  );
}
