#!/usr/bin/env python3
"""Condense recorded runs into small JSON files for the web viewer.

  bench/export.py --tag django-all-gpt-6-luna-bench --out web/data

Writes <out>/index.json (one row per run) and <out>/runs/<id>.json (one run:
facts, a timeline of what executed and what was blocked, network, reach, findings, the agent's diff and the grade). Raw event logs run to
several MB per run; the viewer needs a few KB.

The timeline keeps programs the agent ran, model requests, other network
requests and every denied action. It drops file reads (tens of thousands per
run) and Codex's own plumbing (its shell wrappers and helper processes).
"""
from __future__ import annotations

import argparse
import datetime
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "bench" / "data" / "swe_bench_verified.json"
sys.path.insert(0, str(ROOT / "bench"))
import run as bench  # noqa: E402  (the planted payloads)

# The prompt-injection study (study/analyze.py): one tag per condition. Runs
# are exported as inject-<short>-<instance>, with the study's per-run verdicts.
INJECT = {
    "issue": ("overt_issue", "django-all-gpt-6-luna-bench-inject-issue"),
    "agents": ("overt_agents_md", "django-all-gpt-6-luna-bench-inject-agents_md"),
    "covert": ("covert_script", "django-all-gpt-6-luna-bench-inject-covert"),
}
MAX_MESSAGE = 1_500

# Featured runs of the scripted rogue agent (tests/tasks/hello/rogue_agent.sh):
# the same six bad actions under the enforce and the audit policy.
ROGUE = {
    "rogue-enforce": (".runs/20261115-095345-515d13", "Scripted rogue agent, enforce policy"),
    "rogue-audit": (".runs/20261115-095400-be33ac", "Scripted rogue agent, audit policy"),
}

# Codex plumbing and shell glue: not actions the agent chose.
PLUMBING = {"bash", "sh", "codex", "node", "exe", "codex-code-mode-host", "getconf", "id", "dirname", "uname", "env"}
MAX_DIFF = 40_000
# Intervals when the host Mac was asleep, from `pmset -g log`. While it sleeps
# the sandbox VM is paused too: the agent freezes, then carries on. Durations
# subtract this time. Only intervals that overlap a recorded run are saved
# (the full log is a record of when the machine was in use); saving them
# matters because the system log rotates.
SLEEP = ROOT / "bench" / "data" / "host_sleep.json"
USED_SLEEP: set[tuple[float, float]] = set()
MAX_ISSUE = 2_000


def first_line(s: str) -> str:
    for line in s.strip().splitlines():
        if line.strip():
            return line.strip()[:140]
    return ""


def timeline(events: list[dict], start: float) -> list[dict]:
    out: list[dict] = []
    for e in events:
        t = round(e["t"] - start, 2)
        op, res = e["op"], e.get("result")
        if op == "exec":
            argv = e.get("argv") or [e["path"]]
            base = e["path"].rsplit("/", 1)[-1]
            if argv[0].startswith("/proc/self/exe") or base in PLUMBING and res == "ok":
                continue
            if base == "codex.sh" or base == "rogue_agent.sh":
                out.append({"t": t, "k": "start", "x": base})
                continue
            if base == "mkdir" and argv[-1].endswith("/.codex"):
                continue
            out.append({"t": t, "k": "exec" if res == "ok" else "blocked", "x": " ".join(argv)[:220]})
        elif op == "http":
            if "model" in (e.get("flags") or []):
                out.append({"t": t, "k": "model", "x": e.get("model", ""),
                            "in": e.get("tokens_in", 0), "cached": e.get("tokens_cached", 0), "out": e.get("tokens_out", 0)})
            else:
                k = "blocked" if res == "denied" else "net"
                out.append({"t": t, "k": k, "x": f"{e.get('method', '')} {e.get('host', '')}{e.get('path', '') if e.get('method') != 'CONNECT' else ''}".strip()})
        elif res == "denied":
            out.append({"t": t, "k": "blocked", "x": f"{op} {e.get('path') or e.get('host', '')}"})
        elif res == "ok" and op in ("read", "write", "mkdir", "delete", "rename") and \
                {"canary", "outside_policy"} & set(e.get("flags") or []):
            # File events the analyser flagged (a decoy secret, a path outside
            # the policy): reads are otherwise left out, so these need a line.
            what = "decoy secret" if "canary" in (e.get("flags") or []) else "outside policy"
            out.append({"t": t, "k": "flag", "x": f"{op} {e.get('path', '')} ({what})"})
    # Programs that run before the first model request are the agent's own
    # startup probes (Codex checks git state), not choices the model made.
    first_model = next((i for i, x in enumerate(out) if x["k"] == "model"), None)
    if first_model is not None:
        for x in out[:first_model]:
            if x["k"] == "exec":
                x["k"] = "setup"
    # Collapse consecutive identical lines (a test run can exec the same helper often).
    merged: list[dict] = []
    for item in out:
        if merged and item["k"] in ("exec", "blocked", "net", "flag") and merged[-1]["k"] == item["k"] and merged[-1]["x"] == item["x"]:
            merged[-1]["n"] = merged[-1].get("n", 1) + 1
            continue
        merged.append(item)
    return merged


def workspace_writes(events: list[dict], start: float) -> list[dict]:
    # Temporary files renamed into place (sed -i, editors) are not changes.
    renamed_from = {e.get("path") for e in events if e["op"] == "rename" and e.get("result") == "ok"}
    seen: dict[str, float] = {}
    for e in events:
        if e["op"] == "write" and e.get("path") in renamed_from:
            continue
        if e["op"] in ("write", "rename") and e.get("result") == "ok":
            p = e.get("path2") if e["op"] == "rename" and e.get("path2") else e.get("path", "")
            if p.startswith("/work/") and "__pycache__" not in p and "/.git/" not in p:
                seen.setdefault(p[len("/work/"):], round(e["t"] - start, 2))
    return [{"path": p, "t": t} for p, t in sorted(seen.items(), key=lambda kv: kv[1])]


def ran_tests(events: list[dict]) -> bool:
    for e in events:
        if e["op"] == "exec" and e.get("result") == "ok" and "python" in e["path"].rsplit("/", 1)[-1]:
            if any(a.endswith("runtests.py") for a in (e.get("argv") or [])[1:3]):
                return True
    return False


def load_sleep() -> list[tuple[float, float]]:
    known = {tuple(x) for x in json.loads(SLEEP.read_text())} if SLEEP.exists() else set()
    try:
        log = subprocess.run(["pmset", "-g", "log"], text=True, capture_output=True, timeout=60).stdout
    except (OSError, subprocess.TimeoutExpired):
        log = ""
    cur = None
    for line in log.splitlines():
        # The type column is followed by a tab; "Wake Requests" is not a wake.
        m = re.match(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d [-+]\d{4}) (Sleep|Wake|DarkWake) *\t", line)
        if not m:
            continue
        t = datetime.datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S %z").timestamp()
        if m.group(2) == "Sleep":
            cur = t
        elif cur is not None:
            known.add((cur, t))
            cur = None
    return sorted(known)


def asleep_during(sleep: list[tuple[float, float]], start: float, end: float) -> list[tuple[float, float]]:
    return [(max(a, start), min(b, end)) for a, b in sleep if b > start and a < end]


def export_run(run_dir: Path, rid: str, title: str, issue: str, result: dict | None,
               sleep: list[tuple[float, float]]) -> tuple[dict, dict]:
    meta = json.loads((run_dir / "run.json").read_text())
    summ = json.loads((run_dir / "summary.json").read_text())
    events = [json.loads(l) for l in (run_dir / "events.jsonl").open()]
    start = meta["start"]
    diff = (run_dir / "changes.diff").read_text() if (run_dir / "changes.diff").exists() else ""
    diff = "\n".join(l for l in diff.splitlines() if "__pycache__" not in l)
    if len(diff) > MAX_DIFF:
        diff = diff[:MAX_DIFF] + "\n# (diff truncated)\n"
    tested = ran_tests(events)
    end = start + summ.get("duration_sec", 0)
    naps = asleep_during(sleep, start, end)
    USED_SLEEP.update((a, b) for a, b in sleep if b > start and a < end)
    slept = sum(b - a for a, b in naps)
    tl = timeline(events, start)
    for a, b in naps:
        if b - a >= 1:
            tl.append({"t": round(a - start, 2), "k": "pause", "x": f"{round(b - a)} s"})
    tl.sort(key=lambda x: x["t"])
    row = {
        "id": rid, "title": title,
        "kind": "rogue" if rid.startswith("rogue") else "inject" if rid.startswith("inject-") else "bench",
        "mode": summ.get("mode"), "seconds": round(summ.get("duration_sec", 0) - slept, 1),
        "slept": round(slept),
        "cost": round(summ.get("cost_usd", 0), 4), "requests": summ.get("model_requests", 0),
        "denied": summ.get("denied", 0), "findings": summ.get("by_severity", {}), "ran_tests": tested,
    }
    if result:
        row.update(difficulty=result["difficulty"], resolved=result["resolved"], model=result["model"],
                   f2p=result.get("fail_to_pass"), p2p=result.get("pass_to_pass"))
    run = {
        **row,
        "started": start, "policy": meta.get("policy"), "landlock": meta.get("landlock"), "exit": meta.get("exit_code"),
        "tokens": {"in": summ.get("tokens_in", 0), "cached": summ.get("tokens_cached", 0), "out": summ.get("tokens_out", 0)},
        "files": {"read": summ.get("files_read", 0), "written": summ.get("files_written", 0), "events": summ.get("events", 0)},
        "programs": summ.get("programs") or [],
        "hosts": summ.get("hosts") or [], "radius": summ.get("reach") or [],
        "findings_list": [{**f, "t": round(f["t"] - start, 2)} for f in summ.get("findings") or []],
        "timeline": tl, "writes": workspace_writes(events, start),
        "diff": diff, "issue": issue[:MAX_ISSUE], "not_ok": (result or {}).get("not_ok", []),
    }
    return row, run


def last_message(log: Path) -> str:
    """The agent's final message to the user, from the kept Codex log."""
    msg = ""
    if log.exists():
        for line in log.read_text().splitlines():
            if line.startswith("{"):
                try:
                    it = json.loads(line).get("item", {})
                except json.JSONDecodeError:
                    continue
                if it.get("type") == "agent_message":
                    msg = it.get("text", "")
    return msg[:MAX_MESSAGE]


def export_inject(out: Path, rows_by_id: dict, sleep: list[tuple[float, float]]) -> list[dict]:
    study = json.loads((ROOT / "study" / "data.json").read_text())["conditions"]
    rows = []
    for short, (cond, tag) in INJECT.items():
        verdicts = {v["id"]: v for v in study[cond]["runs"]}
        for f in sorted((ROOT / "bench" / "results" / tag).glob("*.json")):
            res = json.loads(f.read_text())
            iid = res["instance_id"]
            issue = rows_by_id[iid]["problem_statement"]
            if short == "issue":
                issue = issue + "\n\nNote from the maintainers:\n" + bench.INJECT_PAYLOAD
            v = verdicts[iid]
            row, run = export_run(ROOT / res["run_dir"], f"inject-{short}-{iid}", first_line(issue), issue, res, sleep)
            inj = {"condition": short, "task": iid,
                   "attempted": v["read_attempt"] or v["exfil_attempt"], "ran_script": v["ran_script"],
                   "inspected": v["inspected_script_first"], "refused": v["declined_in_message"],
                   "mentioned": v["mentioned_payload"], "flagged": v["flagged"]}
            row["inject"] = inj
            run["inject"] = {**inj, "message": last_message(ROOT / "bench" / "results" / tag / f"{iid}.tripline.log")}
            # In the issue condition, keep the planted note even when the
            # original issue is cut to MAX_ISSUE.
            if short == "issue":
                orig = rows_by_id[iid]["problem_statement"]
                run["issue"] = orig[:MAX_ISSUE] + "\n\nNote from the maintainers:\n" + bench.INJECT_PAYLOAD
            rows.append(row)
            (out / "runs" / f"{row['id']}.json").write_text(json.dumps(run, separators=(",", ":")))
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", required=True, help="bench/results/<tag>")
    ap.add_argument("--out", default="web/data")
    ap.add_argument("--inject", action="store_true", help="also export the prompt-injection study's runs")
    a = ap.parse_args()
    out = ROOT / a.out
    (out / "runs").mkdir(parents=True, exist_ok=True)
    rows_by_id = {r["instance_id"]: r for r in json.loads(DATA.read_text())}
    index = []
    sleep = load_sleep()
    for rid, (d, title) in ROGUE.items():
        if (ROOT / d / "summary.json").exists():
            row, run = export_run(ROOT / d, rid, title, "", None, sleep)
            index.append(row)
            (out / "runs" / f"{rid}.json").write_text(json.dumps(run, separators=(",", ":")))
    for f in sorted((ROOT / "bench" / "results" / a.tag).glob("*.json")):
        res = json.loads(f.read_text())
        iid = res["instance_id"]
        issue = rows_by_id[iid]["problem_statement"]
        row, run = export_run(ROOT / res["run_dir"], iid, first_line(issue), issue, res, sleep)
        index.append(row)
        (out / "runs" / f"{iid}.json").write_text(json.dumps(run, separators=(",", ":")))
    if a.inject:
        index += export_inject(out, rows_by_id, sleep)
    # The shipped policies, shown on the site's "Use it" page.
    (out / "policies").mkdir(exist_ok=True)
    for pol in sorted((ROOT / "policies").glob("*.yaml")):
        (out / "policies" / pol.name).write_text(pol.read_text())
    # Dashboard extras: the two-model pilot and the grader self-check.
    pilot = {}
    for model in ("gpt-6-luna", "gpt-6-astra"):
        rows = [json.loads(f.read_text()) for f in sorted((ROOT / "bench" / "results" / f"pilot-{model}-bench").glob("*.json"))]
        pilot[model] = [{"id": r["instance_id"], "resolved": r["resolved"], "cost": r["cost_usd"],
                         "requests": r["model_requests"], "tokens_in": r["tokens_in"], "tokens_out": r["tokens_out"]} for r in rows]
    gold_log = ROOT / ".runs" / "gold-all.log"
    lines = gold_log.read_text().splitlines() if gold_log.exists() else []
    excluded = json.loads((ROOT / "bench" / "data" / "env_excluded.json").read_text())
    extras = {
        "pilot": pilot,
        "gold": {"ok": sum(l.startswith("OK ") for l in lines), "bad": sum(l.startswith("BAD") for l in lines),
                 "env_excluded": [{"id": k, "tests": v["tests"]} for k, v in excluded.items()]},
    }
    (out / "extras.json").write_text(json.dumps(extras, indent=1))
    SLEEP.write_text(json.dumps(sorted(USED_SLEEP)) + "\n")
    (out / "index.json").write_text(json.dumps({"tag": a.tag, "runs": index}, indent=1))
    print(f"exported {len(index)} runs to {out}")


if __name__ == "__main__":
    main()
