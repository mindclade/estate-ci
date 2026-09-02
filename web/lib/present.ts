export function shortSHA(value: string): string {
  return /^[0-9a-f]{40}$/.test(value) ? value.slice(0, 8) : "unbound";
}

export function duration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return "n/a";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
}

export function percent(basisPoints: number): string {
  if (!Number.isInteger(basisPoints) || basisPoints < 0 || basisPoints > 10000) return "n/a";
  return `${(basisPoints / 100).toFixed(1)}%`;
}

export function timestamp(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Invalid timestamp";
  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
    timeZoneName: "short",
  }).format(date);
}

export function operationLabel(value: string): string {
  const labels: Record<string, string> = {
    refresh_estate_health: "Refresh estate health",
    rerun_failed_required_workflow: "Rerun failed required workflow",
    cancel_superseded_workflow_run: "Cancel superseded workflow run",
  };
  return labels[value] ?? "Unsupported operation";
}
