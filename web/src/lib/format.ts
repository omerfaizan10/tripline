export function secs(s: number): string {
  if (s < 60) return `${s.toFixed(s < 10 ? 1 : 0)} s`;
  const m = Math.floor(s / 60);
  const r = Math.round(s % 60);
  return `${m} min ${String(r).padStart(2, "0")} s`;
}

export function offset(t: number): string {
  return `+${t.toFixed(2)}`;
}

export function usd(x: number): string {
  if (x === 0) return "$0";
  if (x < 0.01) return `$${x.toFixed(4)}`;
  return `$${x.toFixed(3)}`;
}

export function count(n: number): string {
  return n.toLocaleString("en-US");
}

export function kb(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}
