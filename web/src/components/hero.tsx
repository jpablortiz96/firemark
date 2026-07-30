import Link from "next/link";

export function Hero() {
  return (
    <section className="hero" aria-labelledby="hero-title">
      <div className="hero-copy">
        <div className="eyebrow"><span /> PROVENANCE-GATED DELIVERY</div>
        <h1 id="hero-title">
          Every AI asset ships with a <em>Birth Certificate</em> — or it doesn&apos;t ship at all.
        </h1>
        <p className="hero-lede">
          FIREMARK binds AI images and AI voice to signed provenance, immutable custody, and a clear
          verification decision before a private byte is released.
        </p>
        <div className="hero-actions">
          <Link className="button button-primary" href="/verify">Verify an asset</Link>
          <Link className="button button-secondary" href="/verify#certificate-lookup">
            View a Birth Certificate
          </Link>
        </div>
        <p className="hero-footnote">Open verification · Private evidence stays private</p>
      </div>
      <div className="seal-visual" aria-label="A sealed AI asset linked to its certificate">
        <div className="asset-frame">
          <div className="asset-grid" />
          <div className="asset-orb" />
          <div className="asset-label"><span>SEALED MEDIA</span><strong>IMAGE + AUDIO</strong></div>
          <div className="hash-strip">9f2a ··· 7c81</div>
        </div>
        <div className="proof-line" aria-hidden="true"><span /><i /></div>
        <div className="certificate-sheet">
          <div className="sheet-head"><span>FM</span><small>BIRTH CERTIFICATE</small></div>
          <div className="sheet-status">● ACTIVE</div>
          <div className="sheet-row"><span>SOURCE HASH</span><b>BOUND</b></div>
          <div className="sheet-row"><span>SIGNATURE</span><b>VALID</b></div>
          <div className="sheet-row"><span>CUSTODY</span><b>LOCKED</b></div>
          <div className="sheet-code" aria-hidden="true" />
        </div>
      </div>
    </section>
  );
}
