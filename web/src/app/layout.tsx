import type { Metadata } from "next";
import type { ReactNode } from "react";

import { SiteFooter } from "@/components/site-footer";
import { SiteHeader } from "@/components/site-header";
import { safeHttpUrl } from "@/lib/validation";

import "./globals.css";

const configuredSite = safeHttpUrl(
  process.env.FIREMARK_PUBLIC_SITE_URL ?? "http://localhost:3000",
);
const metadataBase = new URL(configuredSite ?? "http://localhost:3000");

export const metadata: Metadata = {
  metadataBase,
  title: { default: "FIREMARK — Evidence before delivery", template: "%s · FIREMARK" },
  description:
    "Birth Certificates and verification-gated delivery for AI-generated media.",
  alternates: { canonical: "/" },
  openGraph: {
    type: "website",
    title: "FIREMARK — Evidence before delivery",
    description: "Signed provenance, immutable custody, and verification-gated delivery.",
    siteName: "FIREMARK",
  },
  twitter: {
    card: "summary_large_image",
    title: "FIREMARK — Evidence before delivery",
    description: "Every AI asset ships with a Birth Certificate — or it does not ship.",
  },
};

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <html lang="en">
      <body>
        <a className="skip-link" href="#main-content">Skip to content</a>
        <div className="site-shell">
          <SiteHeader />
          <main id="main-content">{children}</main>
          <SiteFooter />
        </div>
      </body>
    </html>
  );
}
