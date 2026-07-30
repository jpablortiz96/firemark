import { CopyButton } from "@/components/copy-button";

export function HashDisplay({ label, value }: { label: string; value: string }) {
  return (
    <div className="hash-display">
      <div><span>{label}</span><CopyButton value={value} label={`Copy ${label}`} /></div>
      <code>{value}</code>
    </div>
  );
}
