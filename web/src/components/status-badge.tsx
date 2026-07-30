type Status = "active" | "revoked" | "invalid" | "verified" | "warning" | "not-found";

const labels: Record<Status, string> = {
  active: "Active",
  revoked: "Revoked",
  invalid: "Invalid",
  verified: "Verified",
  warning: "Needs attention",
  "not-found": "Not found",
};

export function StatusBadge({ status }: { status: Status }) {
  return (
    <span className={`status-badge status-${status}`}>
      <span aria-hidden="true" /> {labels[status]}
    </span>
  );
}
