import Link from "next/link";

export default function NotFound() {
  return (
    <section className="certificate-state">
      <span className="error-code">404 / NOT FOUND</span>
      <h1>This route has no FIREMARK record.</h1>
      <p>Check the address or verify a certificate directly.</p>
      <div><Link className="button button-primary" href="/verify">Open Verify Gate</Link><Link className="button button-secondary" href="/">Return home</Link></div>
    </section>
  );
}
