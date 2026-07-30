interface CapabilityCardProps {
  index: string;
  title: string;
  description: string;
  proof: string;
}

export function CapabilityCard({ index, title, description, proof }: CapabilityCardProps) {
  return (
    <article className="capability-card">
      <span className="capability-index" aria-hidden="true">{index}</span>
      <h3>{title}</h3>
      <p>{description}</p>
      <div className="capability-proof">{proof}</div>
    </article>
  );
}
