import type { Metadata } from "next";
import Link from "next/link";
import { cache } from "react";

import { CertificateCard } from "@/components/certificate-card";
import { StatusBadge } from "@/components/status-badge";
import { getCertificate } from "@/lib/api";
import { isCertificateId } from "@/lib/validation";

const lookupCertificate = cache(getCertificate);

export const dynamic = "force-dynamic";

export async function generateMetadata({ params }: { params: Promise<{ certId: string }> }): Promise<Metadata> {
  const { certId } = await params;
  if (!isCertificateId(certId)) {
    return { title: "Invalid certificate", robots: { index: false, follow: false } };
  }
  const result = await lookupCertificate(certId);
  if (result.state !== "found") {
    return {
      title: result.state === "revoked" ? "Revoked certificate" : "Certificate unavailable",
      robots: { index: false, follow: false },
    };
  }
  return {
    title: `Birth Certificate ${certId}`,
    description: `Public FIREMARK Birth Certificate for sealed asset ${result.certificate.asset_id}.`,
    alternates: { canonical: `/certificate/${encodeURIComponent(certId)}` },
    robots: { index: true, follow: true },
  };
}

function CertificateState({ state }: { state: "revoked" | "not_found" | "error" }) {
  const content = {
    revoked: ["Certificate revoked", "This public certificate was revoked and cannot authorize delivery."],
    not_found: ["Certificate not found", "No public FIREMARK Birth Certificate matches this identifier."],
    error: ["Certificate unavailable", "The certificate service could not return a safe public record."],
  } as const;
  return (
    <section className="certificate-state">
      <StatusBadge status={state === "revoked" ? "revoked" : state === "not_found" ? "not-found" : "warning"} />
      <h1>{content[state][0]}</h1>
      <p>{content[state][1]}</p>
      <div><Link className="button button-primary" href="/verify">Open Verify Gate</Link><Link className="button button-secondary" href="/">Return home</Link></div>
    </section>
  );
}

export default async function CertificatePage({ params }: { params: Promise<{ certId: string }> }) {
  const { certId } = await params;
  if (!isCertificateId(certId)) return <CertificateState state="not_found" />;
  const result = await lookupCertificate(certId);
  return (
    <section className="certificate-page">
      {result.state === "found" ? <CertificateCard certificate={result.certificate} /> : <CertificateState state={result.state} />}
    </section>
  );
}
