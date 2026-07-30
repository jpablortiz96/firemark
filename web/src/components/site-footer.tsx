import Link from "next/link";

export function SiteFooter() {
  return (
    <footer className="site-footer">
      <div>
        <span className="wordmark">FIREMARK</span>
        <p>Evidence before delivery.</p>
      </div>
      <div className="footer-links">
        <Link href="/verify">Verify an asset</Link>
        <Link href="/#architecture">Trust architecture</Link>
      </div>
      <p className="footer-note">Public proof without private provenance exposure.</p>
    </footer>
  );
}
