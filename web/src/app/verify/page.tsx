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
  searchParams: Promise<{ cert_id?: string; sha256?: string; media?: string }>;
}) {
  const query = await searchParams;
  // Only an explicit, known media value selects a Lens mode. A `sha256`
  // parameter is never treated as verification evidence — the local file is.
  const media =
    query.media === "audio" ? "audio" : query.media === "image" ? "image" : undefined;
  return (
    <section className="verify-page">
      <div className="page-intro">
        <span className="section-kicker">PUBLIC VERIFICATION</span>
        <p>Local image or audio evidence. One clear backend decision. Selected media never leaves your browser.</p>
      </div>
      <VerifyExperience
        initialCertId={query.cert_id ?? ""}
        initialSha256={query.sha256 ?? ""}
        initialMedia={media}
      />
    </section>
  );
}
