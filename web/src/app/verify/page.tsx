import type { Metadata } from "next";

import { VerifyForm } from "@/components/verify-form";

export const metadata: Metadata = {
  title: "Verify Gate",
  description: "Verify a FIREMARK certificate, signature, custody evidence, and sealed SHA-256.",
  alternates: { canonical: "/verify" },
};

export default async function VerifyPage({
  searchParams,
}: {
  searchParams: Promise<{ cert_id?: string; sha256?: string }>;
}) {
  const query = await searchParams;
  return (
    <section className="verify-page">
      <div className="page-intro">
        <span className="section-kicker">PUBLIC VERIFICATION</span>
        <p>One evidence check. One clear decision. No private provenance leaves FIREMARK.</p>
      </div>
      <VerifyForm initialCertId={query.cert_id ?? ""} initialSha256={query.sha256 ?? ""} />
    </section>
  );
}
