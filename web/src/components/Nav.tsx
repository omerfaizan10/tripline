import Link from "next/link";

export function Mark({ size = 18 }: { size?: number }) {
  // A time rule with two event ticks; the last one is a blocked action.
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
      <rect x="9" y="3" width="2" height="26" fill="var(--ink)" />
      <rect x="4" y="9" width="12" height="2" fill="var(--ink)" />
      <rect x="4" y="16" width="12" height="2" fill="var(--ink)" />
      <rect x="3" y="22" width="26" height="4" fill="var(--accent)" />
    </svg>
  );
}

export function Nav({ current, meta }: { current: "runs" | "results" | "how"; meta?: string }) {
  return (
    <header className="nav">
      <div className="wrap">
        <Link href="/" className="wordmark">
          <Mark />
          Tripline
        </Link>
        <nav className="navlinks" aria-label="Main">
          <Link href="/" aria-current={current === "runs" ? "page" : undefined}>
            Runs
          </Link>
          <Link href="/results/" aria-current={current === "results" ? "page" : undefined}>
            Results
          </Link>
          <Link href="/how-it-works/" aria-current={current === "how" ? "page" : undefined}>
            How it works
          </Link>
        </nav>
        {meta && <div className="navmeta mono">{meta}</div>}
      </div>
    </header>
  );
}
