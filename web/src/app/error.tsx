"use client";

export default function ErrorPage({ reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <section className="certificate-state">
      <span className="error-code">SAFE ERROR</span>
      <h1>FIREMARK could not complete this view.</h1>
      <p>No private service detail was exposed. Retry the request or return to verification.</p>
      <button className="button button-primary" type="button" onClick={reset}>Try again</button>
    </section>
  );
}
