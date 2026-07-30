import Link from "next/link";

import { CapabilityCard } from "@/components/capability-card";
import { Hero } from "@/components/hero";
import { TrustTimeline } from "@/components/trust-timeline";

const capabilities = [
  {
    index: "01",
    title: "Generate & Seal",
    description: "Create the media, preserve its private origin record, then seal the public bytes once.",
    proof: "Source hash → provenance → sealed hash",
  },
  {
    index: "02",
    title: "Birth Certificate",
    description: "Publish the identity, signature, and safe provenance needed to assess one asset.",
    proof: "Public proof without private prompts",
  },
  {
    index: "03",
    title: "Verify Gate",
    description: "Release the private asset only when status, signature, custody, and hash all pass.",
    proof: "Verification first → delivery second",
  },
] as const;

export default function HomePage() {
  const structuredData = {
    "@context": "https://schema.org",
    "@type": "SoftwareApplication",
    name: "FIREMARK",
    applicationCategory: "SecurityApplication",
    description: "Provenance and verification-gated delivery for AI-generated media.",
  };
  return (
    <>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(structuredData).replace(/</g, "\\u003c") }}
      />
      <Hero />

      <section className="thesis-band" aria-label="Product thesis">
        <p>TRUST IS NOT A LABEL</p>
        <h2>Evidence must travel with the asset.</h2>
        <p>
          FIREMARK connects what was generated, what was sealed, who signed it, where its private
          evidence is retained, and whether the bytes presented now are the bytes certified then.
        </p>
      </section>

      <section className="section" aria-labelledby="capabilities-title">
        <div className="section-heading">
          <div><span className="section-kicker">THREE CAPABILITIES</span><h2 id="capabilities-title">One controlled path from creation to release.</h2></div>
          <p>No dashboard sprawl. Each capability closes a specific gap in the chain of trust.</p>
        </div>
        <div className="capability-grid">
          {capabilities.map((capability) => <CapabilityCard key={capability.index} {...capability} />)}
        </div>
      </section>

      <section className="section process-section" aria-labelledby="process-title">
        <div className="section-heading">
          <div><span className="section-kicker">GENERATE & SEAL</span><h2 id="process-title">A chain that is understandable — and inspectable.</h2></div>
          <p>Each boundary produces a different kind of proof. No single badge stands in for all of them.</p>
        </div>
        <TrustTimeline />
      </section>

      <section className="section certificate-explainer" aria-labelledby="certificate-title">
        <div className="certificate-demo" aria-hidden="true">
          <div className="demo-top"><span>FIREMARK / CERTIFICATE</span><b>ACTIVE</b></div>
          <div className="demo-id">FM—CERT—7A91</div>
          <div className="demo-rule" />
          <div className="demo-metrics"><span>HASH<strong>BOUND</strong></span><span>SIGNATURE<strong>VALID</strong></span><span>CUSTODY<strong>LOCKED</strong></span></div>
          <div className="demo-hash">4d7f0d9f2a8645c9····7c81e436</div>
        </div>
        <div>
          <span className="section-kicker">PUBLIC BIRTH CERTIFICATE</span>
          <h2 id="certificate-title">A compact public record of what can be proven.</h2>
          <p>A certificate names the sealed asset, its provenance record, its signer, and its current status. It intentionally omits prompts, private parameters, storage coordinates, and custody internals.</p>
          <ul className="proof-list">
            <li><span>01</span><div><strong>Source hash</strong><p>Identifies the untouched generated output.</p></div></li>
            <li><span>02</span><div><strong>Sealed hash</strong><p>Identifies the exact file intended for delivery.</p></div></li>
            <li><span>03</span><div><strong>Provenance</strong><p>Binds the asset to a canonical creation record.</p></div></li>
            <li><span>04</span><div><strong>Signature</strong><p>Detects changes to the signed evidence envelope.</p></div></li>
          </ul>
        </div>
      </section>

      <section className="section gate-section" aria-labelledby="gate-title">
        <div>
          <span className="section-kicker">VERIFY GATE</span>
          <h2 id="gate-title">Delivery is a decision, not a link.</h2>
          <p>The browser presents a certificate ID and sealed hash. FIREMARK checks status, signature, envelope, custody references, and byte identity. Only a verified result can ask the server for a short-lived private download.</p>
          <Link className="text-link" href="/verify">Open Verify Gate <span aria-hidden="true">→</span></Link>
        </div>
        <div className="gate-console" aria-hidden="true">
          <div className="console-head"><span>VERIFY_GATE / 01</span><i /><i /><i /></div>
          <div className="console-row"><span>Certificate status</span><b>ACTIVE</b></div>
          <div className="console-row"><span>Envelope signature</span><b>VALID</b></div>
          <div className="console-row"><span>Presented SHA-256</span><b>MATCH</b></div>
          <div className="console-result"><span>✓</span><strong>DELIVERY AUTHORIZED</strong></div>
        </div>
      </section>

      <section className="section architecture" id="architecture" aria-labelledby="architecture-title">
        <div className="section-heading">
          <div><span className="section-kicker">TRUST ARCHITECTURE</span><h2 id="architecture-title">Public confidence. Private evidence. Explicit boundaries.</h2></div>
        </div>
        <div className="architecture-grid" id="trust">
          <article><span>PUBLIC</span><h3>Certificate plane</h3><p>Allowlisted identity, hashes, signature material, status, and public capsule.</p></article>
          <article><span>CONTROLLED</span><h3>Verification plane</h3><p>Deterministic checks and auditable decisions without revealing private storage.</p></article>
          <article><span>PRIVATE</span><h3>Custody plane</h3><p>Canonical provenance and source evidence held under immutable retention.</p></article>
        </div>
      </section>

      <section className="final-cta">
        <span className="section-kicker">EVIDENCE BEFORE DELIVERY</span>
        <h2>Know exactly what you are about to trust.</h2>
        <p>Run Verify Gate against a FIREMARK certificate and the sealed asset hash.</p>
        <Link className="button button-primary" href="/verify">Verify an asset</Link>
      </section>
    </>
  );
}
