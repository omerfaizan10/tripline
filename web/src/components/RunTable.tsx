"use client";

import Link from "next/link";
import { useState } from "react";
import type { Row } from "@/lib/data";
import { secs, usd } from "@/lib/format";

type Filter = "all" | "resolved" | "unresolved";

export function RunTable({ runs }: { runs: Row[] }) {
  const [filter, setFilter] = useState<Filter>("all");
  const shown = runs.filter(
    (r) =>
      filter === "all" || (filter === "resolved" ? r.resolved : !r.resolved),
  );
  const n = {
    all: runs.length,
    resolved: runs.filter((r) => r.resolved).length,
    unresolved: runs.filter((r) => !r.resolved).length,
  };

  return (
    <>
      <div className="filters" role="group" aria-label="Filter runs">
        {(["all", "resolved", "unresolved"] as Filter[]).map((f) => (
          <button
            key={f}
            aria-pressed={filter === f}
            onClick={() => setFilter(f)}
          >
            {f === "all"
              ? "All"
              : f === "resolved"
                ? "Resolved"
                : "Not resolved"}{" "}
            <span className="num">{n[f]}</span>
          </button>
        ))}
      </div>
      <table className="table runs">
        <thead>
          <tr>
            <th>Task</th>
            <th>Issue</th>
            <th>Difficulty</th>
            <th>Result</th>
            <th className="r">Time</th>
            <th className="r">Cost</th>
            <th className="r">Blocked</th>
          </tr>
        </thead>
        <tbody>
          {shown.map((r) => (
            <tr key={r.id}>
              <td className="task">
                <Link href={`/runs/${r.id}/`}>
                  {r.id.replace("django__django-", "django-")}
                </Link>
              </td>
              <td className="title">{r.title}</td>
              <td className="hide-sm dim nowrap">{r.difficulty}</td>
              <td className={`verdict nowrap ${r.resolved ? "yes" : "no"}`}>
                {r.resolved ? "Resolved" : "Not resolved"}
              </td>
              <td className="r num hide-sm">{secs(r.seconds)}</td>
              <td className="r num hide-sm">{usd(r.cost)}</td>
              <td className="r num hide-sm">{r.denied}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
