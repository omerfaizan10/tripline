#!/usr/bin/env python3
"""Run coding agents on SWE-bench Verified tasks inside Blast Radius and grade them.

For each task:
  1. check out the repository at the issue's base commit (from a local mirror);
  2. give the agent the issue text through `blast run` (sandboxed, recorded);
  3. grade in a separate plain container: apply the benchmark's hidden tests to
     the agent's final tree and run FAIL_TO_PASS (must now pass) and
     PASS_TO_PASS (must keep passing), the same criteria SWE-bench uses.

Only Django tasks of version 4.1 and later are used: they run from source on
the sandbox's Python 3.11 without per-task images.

Usage:
  bench/run.py select --n 5 --seed 7 > bench/sets/pilot.txt
  bench/run.py run --set bench/sets/pilot.txt --model gpt-6-astra --policy policies/bench.yaml
  bench/run.py grade <run-dir> <instance-id>
"""
from __future__ import annotations

import argparse
import json
import random
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "bench" / "data" / "swe_bench_verified.json"
CACHE = ROOT / "bench" / "cache"
RESULTS = ROOT / "bench" / "results"
IMAGE = "blast-sandbox:dev"
VERSIONS = {"4.1", "4.2", "5.0"}

PROMPT = """You are working in a checkout of the {repo} repository at /work.
Resolve the following GitHub issue by editing the source code. Do not modify or
add files under tests/; the change will be checked against hidden tests. You
can run Django's own test suite with: python3 tests/runtests.py <test label>

<issue>
{problem}
</issue>
"""


def load() -> dict[str, dict]:
    rows = json.loads(DATA.read_text())
    return {r["instance_id"]: r for r in rows}


def eligible(rows: dict[str, dict]) -> list[str]:
    return sorted(i for i, r in rows.items() if r["repo"] == "django/django" and r["version"] in VERSIONS)


def sh(cmd: list[str], cwd: Path | None = None, check: bool = True, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, check=check, text=True, capture_output=True, **kw)


# ---------- workspaces ----------

def mirror(repo: str) -> Path:
    """A bare mirror per repository, cloned once."""
    dst = CACHE / (repo.replace("/", "__") + ".git")
    if not dst.exists():
        CACHE.mkdir(parents=True, exist_ok=True)
        print(f"cloning {repo} (once)...", file=sys.stderr)
        sh(["git", "clone", "--bare", f"https://github.com/{repo}.git", str(dst)])
    return dst


def checkout(row: dict, dst: Path) -> None:
    """A fresh working tree at the base commit, with git history trimmed to one
    commit so the agent cannot read the future fix from the log."""
    if dst.exists():
        shutil.rmtree(dst)
    src = mirror(row["repo"])
    sh(["git", "clone", "--quiet", "--no-checkout", str(src), str(dst)])
    sh(["git", "checkout", "--quiet", row["base_commit"]], cwd=dst)
    shutil.rmtree(dst / ".git")
    sh(["git", "init", "--quiet"], cwd=dst)
    # No background `git gc --auto` after the big commit: it deletes loose
    # object dirs while the grader is copying the tree.
    sh(["git", "config", "gc.auto", "0"], cwd=dst)
    sh(["git", "add", "-A"], cwd=dst)
    sh(["git", "-c", "user.name=bench", "-c", "user.email=bench@example.invalid", "commit", "--quiet", "-m", "base"], cwd=dst)


# ---------- grading ----------

TEST_RE = re.compile(r"^(?P<name>\w+) \((?P<cls>[\w.]+)\)")


def label(test: str) -> str | None:
    """'test_x (app.tests.Cls)' or 'test_x (app.tests.Cls.test_x)' -> 'app.tests.Cls.test_x'."""
    m = TEST_RE.match(test)
    if not m:
        return None
    cls = m["cls"]
    if cls.endswith("." + m["name"]):
        cls = cls[: -len(m["name"]) - 1]
    return f"{cls}.{m['name']}"


STATUS_RE = re.compile(
    r"^(\w+) \(([\w.]+)\)(?:\n(.*?))?\s\.\.\.\s(ok|FAIL|ERROR|skipped.*|expected failure|unexpected success)$", re.M)


def parse_results(out: str) -> dict[str, str]:
    """Map test ids -> ok/fail/error/skip from runtests.py -v 2 output.

    A test with a docstring prints its first line under the name, and SWE-bench
    uses that line as the test's id, so each result is filed under both
    'module.Cls.test' and 'doc:<first line>'."""
    res: dict[str, str] = {}
    for m in STATUS_RE.finditer(out):
        name, cls, doc, status = m.groups()
        if cls.endswith("." + name):
            cls = cls[: -len(name) - 1]
        s = status.lower()
        v = "ok" if s in ("ok", "expected failure") else ("skip" if s.startswith("skipped") else ("fail" if s in ("fail", "unexpected success") else "error"))
        res[f"{cls}.{name}"] = v
        if doc:
            res["doc:" + doc.strip()] = v
    return res


def test_modules(test_patch: str) -> list[str]:
    """Django test labels for the files the test patch touches, as the SWE-bench
    harness derives them: tests/a/b.py -> a.b."""
    mods = set()
    for m in re.finditer(r"^diff --git a/(\S+) b/", test_patch, re.M):
        f = m.group(1)
        if f.startswith("tests/") and f.endswith(".py"):
            mods.add(f[len("tests/"):-3].replace("/", "."))
    return sorted(mods)


def apply_patch(patch: Path, tree: Path) -> str | None:
    """Apply a patch to a plain directory; None on success, else the reason.

    The grade tree lives inside this project's own git repo, and `git apply`
    run from a subdirectory of a repo silently skips files outside it (exit 0).
    A ceiling stops git from finding the parent repo, and every file the patch
    names must be reported as applied."""
    import os
    env = {**os.environ, "GIT_CEILING_DIRECTORIES": str(tree.parent)}
    ap = subprocess.run(["git", "apply", "--verbose", "--whitespace=nowarn", str(patch)],
                        cwd=tree, text=True, capture_output=True, env=env)
    if ap.returncode != 0:
        return ap.stderr[-500:]
    want = set(re.findall(r"^diff --git a/\S+ b/(\S+)", patch.read_text(), re.M))
    done = set(re.findall(r"^Applied patch (\S+) cleanly", ap.stderr, re.M))
    if want - done:
        return f"files not applied: {sorted(want - done)}"
    return None


def grade(row: dict, work: Path, out_dir: Path) -> dict:
    """Apply the hidden tests to the agent's tree and run them in a plain container."""
    g = out_dir / "grade_tree"
    if g.exists():
        shutil.rmtree(g)
    shutil.copytree(work, g, symlinks=True, ignore=shutil.ignore_patterns("__pycache__", ".git"))
    (out_dir / "test.patch").write_text(row["test_patch"])
    ap = apply_patch(out_dir / "test.patch", g)
    result = {"instance_id": row["instance_id"], "test_patch_applied": ap is None}
    if ap is not None:
        result.update(resolved=False, error="test patch did not apply: " + ap)
        return result
    f2p = json.loads(row["FAIL_TO_PASS"]) if isinstance(row["FAIL_TO_PASS"], str) else row["FAIL_TO_PASS"]
    p2p = json.loads(row["PASS_TO_PASS"]) if isinstance(row["PASS_TO_PASS"], str) else row["PASS_TO_PASS"]
    modules = test_modules(row["test_patch"])
    t0 = time.time()
    run = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "-v", f"{g}:/work", "-w", "/work",
         "-e", "PYTHONPATH=/work", IMAGE,
         "python3", "tests/runtests.py", "--verbosity", "2", "--parallel", "1", *modules],
        text=True, capture_output=True, timeout=1800,
    )
    out = run.stdout + run.stderr
    (out_dir / "grade.log").write_text(out)
    got = parse_results(out)

    def status(t: str) -> str:
        l = label(t)
        if l and l in got:
            return got[l]
        return got.get("doc:" + t.strip(), "missing")

    f2p_s = {t: status(t) for t in f2p}
    p2p_s = {t: status(t) for t in p2p}
    result.update(
        resolved=all(v == "ok" for v in f2p_s.values()) and all(v in ("ok", "skip") for v in p2p_s.values()),
        fail_to_pass={"passed": sum(v == "ok" for v in f2p_s.values()), "total": len(f2p)},
        pass_to_pass={"passed": sum(v in ("ok", "skip") for v in p2p_s.values()), "total": len(p2p)},
        not_ok=sorted([t for t, v in {**f2p_s, **p2p_s}.items() if v not in ("ok", "skip")])[:20],
        grade_seconds=round(time.time() - t0, 1),
        test_modules=modules,
    )
    shutil.rmtree(g)
    return result


# ---------- commands ----------

def cmd_select(a) -> None:
    ids = eligible(load())
    random.Random(a.seed).shuffle(ids)
    print("\n".join(sorted(ids[: a.n])))


def latest_run(name: str) -> Path | None:
    runs = sorted((ROOT / ".runs").glob("*/run.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    for p in runs:
        try:
            if json.loads(p.read_text()).get("name") == name:
                return p.parent
        except Exception:
            pass
    return None


def cmd_run(a) -> None:
    rows = load()
    ids = [l.strip() for l in Path(a.set).read_text().splitlines() if l.strip() and not l.startswith("#")]
    tag = a.tag or f"{Path(a.set).stem}-{a.model}-{Path(a.policy).stem}"
    out_root = RESULTS / tag
    out_root.mkdir(parents=True, exist_ok=True)
    for iid in ids:
        res_file = out_root / f"{iid}.json"
        if res_file.exists() and not a.force:
            print(f"skip {iid} (done)")
            continue
        row = rows[iid]
        task = CACHE / "work" / iid
        checkout(row, task)
        prompt = PROMPT.format(repo=row["repo"], problem=row["problem_statement"].strip())
        name = f"{tag}:{iid}"
        print(f"== {iid} ({row['difficulty']})", flush=True)
        t0 = time.time()
        blast = subprocess.run(
            [str(ROOT / "bin" / "blast"), "run", "--policy", a.policy, "--task", str(task), "--name", name,
             "--timeout", a.timeout, "--env", f"BLAST_MODEL={a.model}", "--env", f"BLAST_EFFORT={a.effort}",
             "--env", "PYTHONPATH=/work",
             "--", "/blast/agents/codex.sh", prompt],
            cwd=ROOT, text=True, capture_output=True,
        )
        wall = time.time() - t0
        run_dir = latest_run(name)
        (out_root / f"{iid}.blast.log").write_text(blast.stdout[-20000:] + "\n--- stderr\n" + blast.stderr[-20000:])
        if run_dir is None:
            print(f"   blast failed: {blast.stderr[-400:]}")
            continue
        summary = json.loads((run_dir / "summary.json").read_text())
        g = grade(row, run_dir / "work", out_root)
        result = {
            "instance_id": iid, "difficulty": row["difficulty"], "model": a.model, "effort": a.effort,
            "policy": a.policy, "run_dir": str(run_dir.relative_to(ROOT)), "wall_seconds": round(wall, 1),
            "agent_exit": summary.get("exit_code"), "cost_usd": round(summary.get("cost_usd", 0), 4),
            "tokens_in": summary.get("tokens_in"), "tokens_cached": summary.get("tokens_cached"),
            "tokens_out": summary.get("tokens_out"), "model_requests": summary.get("model_requests"),
            "findings": summary.get("by_severity", {}), "denied": summary.get("denied"), **g,
        }
        res_file.write_text(json.dumps(result, indent=2))
        print(f"   resolved={result['resolved']}  F2P {g.get('fail_to_pass')}  cost ${result['cost_usd']}  {wall/60:.1f} min", flush=True)


def cmd_gold(a) -> None:
    """Grader self-check, no agent: the base commit must grade unresolved and
    the benchmark's reference patch must grade resolved."""
    rows = load()
    ids = [l.strip() for l in Path(a.set).read_text().splitlines() if l.strip() and not l.startswith("#")]
    out_root = RESULTS / "_gold"
    out_root.mkdir(parents=True, exist_ok=True)
    ok = True
    for iid in ids:
        row = rows[iid]
        task = CACHE / "work" / iid
        checkout(row, task)
        base = grade(row, task, out_root)
        (task / "gold.patch").write_text(row["patch"])
        sh(["git", "apply", "gold.patch"], cwd=task)
        (task / "gold.patch").unlink()
        gold = grade(row, task, out_root)
        good = base.get("resolved") is False and gold.get("resolved") is True
        ok &= good
        print(f"{'OK ' if good else 'BAD'} {iid}  base={base.get('resolved')} F2P {base.get('fail_to_pass')}  "
              f"gold={gold.get('resolved')} F2P {gold.get('fail_to_pass')} P2P {gold.get('pass_to_pass')}"
              + (f"  not_ok={gold.get('not_ok') or gold.get('error')}" if not gold.get("resolved") else ""), flush=True)
    sys.exit(0 if ok else 1)


def cmd_grade(a) -> None:
    rows = load()
    print(json.dumps(grade(rows[a.instance], Path(a.run_dir) / "work", Path(a.run_dir)), indent=2))


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("select")
    s.add_argument("--n", type=int, default=5)
    s.add_argument("--seed", type=int, default=7)
    s.set_defaults(fn=cmd_select)
    r = sub.add_parser("run")
    r.add_argument("--set", required=True)
    r.add_argument("--model", default="gpt-6-astra")
    r.add_argument("--effort", default="medium")
    r.add_argument("--policy", default="policies/bench.yaml")
    r.add_argument("--timeout", default="40m")
    r.add_argument("--tag", default="")
    r.add_argument("--force", action="store_true")
    r.set_defaults(fn=cmd_run)
    o = sub.add_parser("gold")
    o.add_argument("--set", required=True)
    o.set_defaults(fn=cmd_gold)
    g = sub.add_parser("grade")
    g.add_argument("run_dir")
    g.add_argument("instance")
    g.set_defaults(fn=cmd_grade)
    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
