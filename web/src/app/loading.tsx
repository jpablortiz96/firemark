export default function Loading() {
  return (
    <div className="page-loading" role="status" aria-label="Loading FIREMARK evidence">
      <div className="skeleton skeleton-short" />
      <div className="skeleton skeleton-title" />
      <div className="skeleton" />
      <div className="skeleton-grid"><span /><span /><span /><span /></div>
    </div>
  );
}
