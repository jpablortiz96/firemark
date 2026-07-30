import type { Metadata } from "next";

import { VerifyExperience } from "@/components/verify-experience";

export const metadata: Metadata = {
  title: "Verify Gate",
  description: "Verify sealed AI images or audio locally without uploading media.",
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
        <p>Local image or audio evidence. One clear backend decision. Selected media never leaves your browser.</p>
      </div>
      <VerifyExperience initialCertId={query.cert_id ?? ""} initialSha256={query.sha256 ?? ""} />
    </section>
  );
}
