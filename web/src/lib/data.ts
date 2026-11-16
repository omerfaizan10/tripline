import fs from "node:fs";
import path from "node:path";

// Data comes from bench/export.py, read at build time only.
const DATA = path.join(process.cwd(), "data");

export type Severity = "high" | "medium" | "low";

export type Row = {
  id: string;
  title: string;
  kind: "bench" | "rogue";
  mode: string;
  seconds: number;
  cost: number;
  requests: number;
  denied: number;
  findings: Partial<Record<Severity, number>>;
  ran_tests: boolean;
  slept: number;
  difficulty?: string;
  resolved?: boolean;
  model?: string;
  f2p?: { passed: number; total: number };
  p2p?: { passed: number; total: number };
};

export type TimelineItem = {
  t: number;
  k: "start" | "setup" | "exec" | "model" | "net" | "blocked" | "flag" | "pause";
  x: string;
  n?: number;
  in?: number;
  cached?: number;
  out?: number;
};

export type Host = {
  host: string;
  allowed: number;
  denied: number;
  failed: number;
  bytes_down: number;
  model?: boolean;
};
export type Radius = {
  root: string;
  files: number;
  writes: number;
  decoy?: boolean;
};
export type Finding = {
  severity: Severity;
  kind: string;
  title: string;
  detail: string;
  t: number;
  count: number;
};

export type Run = Row & {
  started: number;
  policy: string;
  landlock: string;
  exit: number;
  tokens: { in: number; cached: number; out: number };
  files: { read: number; written: number; events: number };
  programs: string[];
  hosts: Host[];
  radius: Radius[];
  findings_list: Finding[];
  timeline: TimelineItem[];
  writes: { path: string; t: number }[];
  diff: string;
  issue: string;
  not_ok: string[];
};

export function getIndex(): { tag: string; runs: Row[] } {
  return JSON.parse(fs.readFileSync(path.join(DATA, "index.json"), "utf8"));
}

export function getRun(id: string): Run {
  return JSON.parse(
    fs.readFileSync(path.join(DATA, "runs", `${id}.json`), "utf8"),
  );
}

export function shortId(id: string): string {
  return id.replace(/^django__django-/, "django-");
}
