import Link from "next/link";

import { DeliveryButton } from "@/components/delivery-button";
import type { AudioFailureReason, LensResult } from "@/lib/file-verification/types";
import { firstFailedAudioLayer } from "@/lib/file-verification/verify-audio";

interface ResultCopy {
  title: string;
  body: string;
  tone: "verified" | "warning";
}

/**
 * PNG copy. It is only ever reached when the active result is an image result,
 * so audio can never inherit capsule or PNG language.
 */
const IMAGE_RESULT_COPY: Record<LensResult["state"], ResultCopy> = {
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

/** Audio copy. No entry mentions PNG, capsules, EXIF or images. */
const AUDIO_FAILURE_COPY: Record<AudioFailureReason, ResultCopy> = {
  certificate_id_required: {
    title: "Certificate ID required",
    body: "Enter the FIREMARK certificate ID associated with this MP3 before verifying it.",
    tone: "warning",
  },
  invalid_mp3: {
    title: "File is not a valid supported MP3",
    body: "FIREMARK Lens rejected the MP3 signature, structure, size, or format locally.",
    tone: "warning",
  },
  certificate_not_found: {
    title: "Public certificate not found",
    body: "FIREMARK could not find a public certificate for this certificate ID.",
    tone: "warning",
  },
  certificate_revoked: {
    title: "Certificate revoked",
    body: "The issuer revoked this certificate. Verification is blocked for this MP3.",
    tone: "warning",
  },
  media_contract_mismatch: {
    title: "Certificate does not represent an MP3",
    body: "The public certificate does not declare the required audio/mpeg contract.",
    tone: "warning",
  },
  seal_contract_inconsistent: {
    title: "Audio seal contract is inconsistent",
    body:
      "The certificate source and sealed SHA-256 values do not match the byte-preserving MP3 contract.",
    tone: "warning",
  },
  local_hash_mismatch: {
    title: "This MP3 does not match the certificate",
    body:
      "The SHA-256 calculated from this local MP3 differs from the sealed hash in the public certificate.",
    tone: "warning",
  },
  verification_rejected: {
    title: "Cryptographic verification failed",
    body: "The public Verify Gate did not accept the certificate and locally calculated SHA-256.",
    tone: "warning",
  },
  verification_unavailable: {
    title: "Verification service unavailable",
    body:
      "FIREMARK could not complete cryptographic verification. No file bytes were uploaded.",
    tone: "warning",
  },
};

const AUDIO_VERIFIED_COPY: ResultCopy = {
  title: "This MP3 is verified",
  body: "This exact MP3 matches the registered FIREMARK certificate and signed evidence.",
  tone: "verified",
};

/** Map the first actually failed layer to its failure reason. */
const LAYER_FAILURE_FALLBACK: Record<string, AudioFailureReason> = {
  local_processing: "verification_unavailable",
  mp3_format: "invalid_mp3",
  public_certificate: "certificate_not_found",
  media_contract: "media_contract_mismatch",
  byte_preserving_seal: "seal_contract_inconsistent",
  local_file_hash: "local_hash_mismatch",
  cryptographic_verification: "verification_rejected",
};

function audioCopy(result: LensResult): ResultCopy {
  if (result.state === "verified") return AUDIO_VERIFIED_COPY;
  // The reason recorded where the cause was known wins; otherwise fall back to
  // the first failed layer in the declared precedence order.
  const failedLayer = firstFailedAudioLayer(result.layers);
  const reason =
    result.audioFailure ??
    (failedLayer ? LAYER_FAILURE_FALLBACK[failedLayer] : undefined) ??
    "verification_unavailable";
  return AUDIO_FAILURE_COPY[reason];
}

/**
 * Result copy is always derived from the active media mode and the exact failed
 * layer of the current result — never from a shared file-state enum.
 */
export function resultCopy(result: LensResult): ResultCopy {
  return result.mediaType === "audio" ? audioCopy(result) : IMAGE_RESULT_COPY[result.state];
}

export function VerificationLayers({ result }: { result: LensResult }) {
  const copy = resultCopy(result);
  return (
    <section className={`lens-result lens-result-${copy.tone}`} aria-labelledby="lens-result-title">
      <div className="lens-result-heading">
        <span className={`status-badge status-${copy.tone}`}>
          <span aria-hidden="true" /> {copy.tone === "verified" ? "Verified" : "Review required"}
        </span>
        <span>{result.layers.length} trust layers</span>
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
