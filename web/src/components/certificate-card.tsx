import Link from "next/link";

import { HashDisplay } from "@/components/hash-display";
import { StatusBadge } from "@/components/status-badge";
import { CopyButton } from "@/components/copy-button";
import { formatTimestamp } from "@/lib/format";
import type { PublicCertificate } from "@/lib/types";

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div className="certificate-detail">
      <dt>{label}</dt>
      <dd><code>{value}</code><CopyButton value={value} label={`Copy ${label}`} /></dd>
    </div>
  );
}

export function CertificateCard({ certificate }: { certificate: PublicCertificate }) {
  const status = certificate.certificate_status;
  return (
    <article className="certificate-card">
      <header className="certificate-header">
        <div>
          <div className="eyebrow"><span /> FIREMARK BIRTH CERTIFICATE</div>
          <h1>Public proof for sealed AI {certificate.media_type === "audio" ? "audio" : "imagery"}</h1>
          <p>Issued {formatTimestamp(certificate.issued_at)} · UTC</p>
        </div>
        <StatusBadge status={status} />
      </header>

      <section className="trust-summary" aria-label="Human-readable trust summary">
        <div className="trust-seal" aria-hidden="true">✓</div>
        <div>
          <h2>{status === "active" ? "Certificate evidence is active" : "Certificate needs review"}</h2>
          <p>
            This public record binds the final asset hash to signed provenance and a FIREMARK
            signer. Run Verify Gate with the file&apos;s SHA-256 before relying on or downloading it.
          </p>
        </div>
      </section>

      <dl className="certificate-grid">
        <Detail label="Certificate ID" value={certificate.cert_id} />
        <Detail label="Asset ID" value={certificate.asset_id} />
        <Detail label="Run ID" value={certificate.run_id} />
        <Detail label="Signer key ID" value={certificate.signer_key_id} />
        <Detail label="Provider" value={certificate.provider} />
        <Detail label="Model" value={certificate.model} />
        <Detail label="Media" value={`${certificate.media_type} · ${certificate.mime_type}`} />
        <Detail label="Byte size" value={String(certificate.byte_size)} />
      </dl>

      <section className="hashes" aria-labelledby="hashes-title">
        <div className="section-kicker">BYTE IDENTITY</div>
        <h2 id="hashes-title">Cryptographic fingerprints</h2>
        <HashDisplay label="Source SHA-256" value={certificate.source_sha256} />
        <HashDisplay label="Sealed SHA-256" value={certificate.sealed_sha256} />
        <HashDisplay label="Canonical hash" value={certificate.canonical_hash} />
      </section>

      <section className="proof-indicators" aria-label="Cryptographic status indicators">
        <div><span aria-hidden="true">✓</span><strong>Signature material</strong><small>Published</small></div>
        <div><span aria-hidden="true">✓</span><strong>Canonical provenance</strong><small>Bound</small></div>
        <div><span aria-hidden="true">✓</span><strong>Sealed bytes</strong><small>Identified</small></div>
      </section>

      <details className="technical-details">
        <summary>Technical certificate details</summary>
        <div className="technical-body">
          <HashDisplay label="Signer public key" value={certificate.signer_public_key_b64} />
          <HashDisplay label="Signature" value={certificate.signature_b64} />
          <HashDisplay label="Verification URL" value={certificate.verify_url} />
          <div className="manifest-block">
            <div><span>Public manifest</span><CopyButton value={JSON.stringify(certificate.public_manifest)} /></div>
            <pre>{JSON.stringify(certificate.public_manifest, null, 2)}</pre>
          </div>
        </div>
      </details>

      <div className="certificate-actions">
        {/* The CTA carries only the public certificate ID and the media mode.
            No hash, token or delivery URL: the local file is the evidence. */}
        <Link
          className="button button-primary"
          href={
            certificate.media_type === "audio"
              ? `/verify?cert_id=${encodeURIComponent(certificate.cert_id)}&media=audio`
              : `/verify?cert_id=${encodeURIComponent(certificate.cert_id)}&media=image`
          }
        >
          {certificate.media_type === "audio" ? "Verify this MP3 locally" : "Verify this asset"}
        </Link>
        <a
          className="button button-secondary"
          href={`/api/proof-pack/${encodeURIComponent(certificate.cert_id)}`}
          download={`firemark-proof-${certificate.cert_id}.zip`}
        >
          Download Proof Pack
        </a>
        <span>Verification is independent of certificate display.</span>
        {certificate.media_type === "audio" && (
          <span>Audio playback becomes available only after hash verification and secure delivery.</span>
        )}
      </div>
    </article>
  );
}
