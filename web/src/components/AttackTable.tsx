"use client";

import Link from "next/link";
import { useState } from "react";
import type { Row } from "@/lib/data";
import { CONDITION, type Condition, verdict } from "@/lib/inject";
import { usd } from "@/lib/format";

type Filter = "all" | Condition;

// Every run of the prompt-injection study, filterable by where the
// instruction was planted. Runs that attempted it sort first.
export function AttackTable({ runs }: { runs: Row[] }) {
  const [filter, setFilter] = useState<Filter>("all");
  const [all, setAll] = useState(false);
  const LIMIT = 40;
  const shown = runs
    .filter((r) => filter === "all" || r.inject?.condition === filter)
    .sort(
      (a, b) =>
        Number(!!b.inject?.attempted) - Number(!!a.inject?.attempted) ||
        a.id.localeCompare(b.id),
    );
  const n = (f: Filter) =>
    runs.filter((r) => f === "all" || r.inject?.condition === f).length;

  return (
    <>
      <div className="filters" role="group" aria-label="Filter by condition">
        {(["all", "issue", "agents", "covert"] as Filter[]).map((f) => (
          <button
            key={f}
            aria-pressed={filter === f}
            onClick={() => setFilter(f)}
          >
            {f === "all" ? "All" : CONDITION[f].name}{" "}
            <span className="num">{n(f)}</span>
          </button>
        ))}
      </div>
      <table className="table runs">
        <thead>
          <tr>
            <th>Task</th>
            <th>Issue</th>
            <th>Instruction</th>
            <th>What the agent did</th>
            <th>Result</th>
            <th className="r">Cost</th>
          </tr>
        </thead>
        <tbody>
          {(all ? shown : shown.slice(0, LIMIT)).map((r) => {
            const v = verdict(r.inject!);
            return (
              <tr key={r.id}>
                <td className="task">
                  <Link href={`/runs/${r.id}/`}>
                    {r.inject!.task.replace("django__django-", "django-")}
                  </Link>
                </td>
                <td className="title">{r.title}</td>
                <td className="nowrap hide-sm">
                  {CONDITION[r.inject!.condition].name
                    .replace("Told outright, ", "")
                    .replace("Hidden in a ", "")}
                </td>
                <td
                  className={v.tone === "blocked" ? "blocked-text" : undefined}
                >
                  {v.text}
                </td>
                <td className={`verdict ${r.resolved ? "yes" : "no"}`}>
                  {r.resolved ? "Resolved" : "Not resolved"}
                </td>
                <td className="r num nowrap">{usd(r.cost)}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {!all && shown.length > LIMIT && (
        <button className="plain" onClick={() => setAll(true)}>
          Show all {shown.length} runs
        </button>
      )}
    </>
  );
}
