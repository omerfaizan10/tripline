"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";

export type StripPoint = {
  id: string;
  label: string;
  value: number;
  group: string;
  detail: string;
};

// Strip plot: one dot per run on a shared value axis, one row per group.
// Groups are told apart by position and their row label, not by colour.
export function Strip({
  points,
  groups,
  ticks,
  axisLabel,
}: {
  points: StripPoint[];
  groups: string[];
  ticks: { v: number; label: string }[];
  axisLabel: string;
}) {
  const max = ticks[ticks.length - 1].v;
  const [hover, setHover] = useState<StripPoint | null>(null);
  const x = (v: number) => `${Math.min(v / max, 1) * 100}%`;
  // Lane packing: walk dots by value and put each in the first lane whose last
  // dot is at least one dot-width away, so no two dots cover each other.
  // Spacing is 10px, converted to value units from the measured plot width.
  const ref = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(800);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver(([e]) => {
      const w = e.contentRect.width;
      // Plot area: minus the name column (140 + 16 gap) and right margin on
      // wide screens; minus the side margins when rows stack on phones.
      setWidth(Math.max(w > 600 ? w - 180 : w - 24, 100));
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  const gap = max * (10 / width);
  const LANE = 11;
  const lanes = (pts: StripPoint[]) => {
    const last: number[] = [];
    const lane = new Map<string, number>();
    for (const p of [...pts].sort((a, b) => a.value - b.value)) {
      let l = last.findIndex((v) => p.value - v >= gap);
      if (l === -1) {
        l = last.length;
        last.push(p.value);
      } else last[l] = p.value;
      lane.set(p.id, l);
    }
    return { lane, count: Math.max(last.length, 1) };
  };

  return (
    <div className="strip" ref={ref}>
      {groups.map((g) => {
        const pts = points.filter((p) => p.group === g);
        const { lane, count } = lanes(pts);
        const height = 24 + count * LANE;
        return (
          <div className="strip-row" key={g}>
            <div className="strip-name">
              {g} <span className="dim num">{pts.length}</span>
            </div>
            <div className="strip-plot" style={{ height }}>
              {ticks.map((t) => (
                <span
                  key={t.v}
                  className="strip-grid"
                  style={{ left: x(t.v) }}
                  aria-hidden="true"
                />
              ))}
              {pts.map((p) => (
                <Link
                  key={p.id}
                  href={`/runs/${p.id}/`}
                  className="strip-dot"
                  style={{
                    left: x(p.value),
                    top: `${12 + (lane.get(p.id) ?? 0) * LANE + LANE / 2}px`,
                  }}
                  aria-label={`${p.label}: ${p.detail}`}
                  onMouseEnter={() => setHover(p)}
                  onMouseLeave={() => setHover(null)}
                  onFocus={() => setHover(p)}
                  onBlur={() => setHover(null)}
                >
                  <span aria-hidden="true" />
                </Link>
              ))}
              {hover && hover.group === g && (
                <div
                  className="strip-tip"
                  style={{ left: x(hover.value) }}
                  role="status"
                >
                  <div className="mono">{hover.label}</div>
                  <div>{hover.detail}</div>
                </div>
              )}
            </div>
          </div>
        );
      })}
      <div className="strip-row strip-axis" aria-hidden="true">
        <div className="strip-name dim">{axisLabel}</div>
        <div className="strip-plot">
          {ticks.map((t) => (
            <span key={t.v} className="strip-tick mono" style={{ left: x(t.v) }}>
              {t.label}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}
