"use client";

import { useState } from "react";
import type { TimelineItem } from "@/lib/data";
import { count, offset } from "@/lib/format";

const KIND: Record<TimelineItem["k"], string> = {
  start: "Start",
  setup: "Startup",
  exec: "Ran",
  model: "Model",
  net: "Network",
  blocked: "Blocked",
  flag: "Flagged",
};

const LONG = 120; // longer timelines show the head and tail first
const HEAD = 60;
const TAIL = 40;

function Line({ it }: { it: TimelineItem }) {
  let text: React.ReactNode = it.x;
  if (it.k === "model") {
    text = `Request to ${it.x}: ${count(it.in ?? 0)} tokens in (${count(it.cached ?? 0)} cached), ${count(it.out ?? 0)} out`;
  } else if (it.k === "start") {
    text = `Agent started (${it.x})`;
  }
  return (
    <li className={it.k}>
      <span className="t">{offset(it.t)}</span>
      <span className="rail" aria-hidden="true" />
      <span className="k">{KIND[it.k]}</span>
      <span className="x">
        {text}
        {it.n && it.n > 1 ? <span className="rep">×{it.n}</span> : null}
      </span>
    </li>
  );
}

export function Timeline({ items }: { items: TimelineItem[] }) {
  const setup = items.filter((i) => i.k === "setup");
  const rest = items.filter((i) => i.k !== "setup");
  const [showSetup, setShowSetup] = useState(false);
  const [showAll, setShowAll] = useState(rest.length <= LONG);

  const shown = showAll ? rest : [...rest.slice(0, HEAD), ...rest.slice(-TAIL)];
  const hidden = rest.length - shown.length;
  const firstStart = rest.findIndex((i) => i.k === "start");

  return (
    <>
      <ol className="tl">
        {shown.map((it, i) => (
          <FragmentRow key={i}>
            <Line it={it} />
            {i === firstStart && setup.length > 0 && (
              <li className="setup">
                <span className="t" />
                <span className="rail" aria-hidden="true" />
                <span className="k">Startup</span>
                <span className="x">
                  {showSetup ? (
                    <button
                      className="plain"
                      onClick={() => setShowSetup(false)}
                    >
                      Hide {setup.length} startup checks
                    </button>
                  ) : (
                    <button
                      className="plain"
                      onClick={() => setShowSetup(true)}
                    >
                      {setup.length} startup checks by Codex before its first
                      model request
                    </button>
                  )}
                </span>
              </li>
            )}
            {i === firstStart &&
              showSetup &&
              setup.map((s, j) => <Line key={`s${j}`} it={s} />)}
            {!showAll && i === HEAD - 1 && (
              <li className="setup">
                <span className="t" />
                <span className="rail" aria-hidden="true" />
                <span className="k" />
                <span className="x">
                  <button className="plain" onClick={() => setShowAll(true)}>
                    Show {hidden} more events
                  </button>
                </span>
              </li>
            )}
          </FragmentRow>
        ))}
      </ol>
    </>
  );
}

function FragmentRow({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
