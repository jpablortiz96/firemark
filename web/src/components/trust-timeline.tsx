const stages = [
  ["01", "Generate", "The provider output is hashed before anything is embedded."],
  ["02", "Prove", "Private canonical provenance records how the asset came to exist."],
  ["03", "Seal", "A public capsule is embedded and the final distributed bytes are hashed."],
  ["04", "Retain", "Source evidence and the private manifest enter immutable custody."],
  ["05", "Sign", "An Ed25519 signature binds identity, hashes, custody references, and time."],
  ["06", "Verify", "Delivery opens only when the certificate and presented hash agree."],
] as const;

export function TrustTimeline() {
  return (
    <ol className="trust-timeline">
      {stages.map(([number, title, description]) => (
        <li key={number}>
          <span>{number}</span>
          <div><h3>{title}</h3><p>{description}</p></div>
        </li>
      ))}
    </ol>
  );
}
