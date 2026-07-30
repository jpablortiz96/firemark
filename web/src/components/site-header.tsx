import Link from "next/link";

export function SiteHeader() {
  return (
    <header className="site-header">
      <Link className="wordmark" href="/" aria-label="FIREMARK home">
        <span className="wordmark-mark" aria-hidden="true">F</span>
        FIREMARK
      </Link>
      <nav aria-label="Primary navigation">
        <Link href="/#trust">Trust model</Link>
        <Link href="/verify">Verify</Link>
      </nav>
    </header>
  );
}
