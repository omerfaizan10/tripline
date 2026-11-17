import type { Metadata } from "next";
import Link from "next/link";
import { Nav } from "@/components/Nav";
import study from "../../../data/study.json";

export const metadata: Metadata = {
  title: "Study · Tripline",
  description:
    "Tripline: Recording and Containing a Coding Agent. A study of Codex on 82 SWE-bench Verified tasks and 246 prompt-injection runs, with the paper as a PDF.",
};

type Rate = { k: number; n: number; pct: number | null };
const pc = (r: Rate) => (r.pct === null ? "n/a" : `${r.pct}%`);
const fr = (r: Rate) => `${r.k}/${r.n}`;

function Section({
  no,
  title,
  children,
}: {
  no: string;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="section">
      <div className="no">{no}</div>
      <div className="prose">
        <h2>{title}</h2>
        {children}
      </div>
    </section>
  );
}

// Log-log scatter of test-suite time with and without strace, one dot per
// task, with the equal-time and twice-the-time lines.
function Overhead({ points }: { points: number[][] }) {
  const S = 300;
  const P = 40;
  const lo = 0.1;
  const hi = 100;
  const f = (v: number) =>
    ((Math.log10(Math.max(v, lo)) - Math.log10(lo)) /
      (Math.log10(hi) - Math.log10(lo))) *
    S;
  const ticks = [0.1, 1, 10, 100];
  return (
    <svg
      className="scatter"
      viewBox={`0 0 ${S + P + 30} ${S + P}`}
      role="img"
      aria-label="Test-suite time with strace against without, one dot per task"
    >
      <g transform={`translate(${P},10)`}>
        {ticks.map((t) => (
          <g key={t}>
            <line x1={f(t)} x2={f(t)} y1={0} y2={S} className="grid" />
            <line x1={0} x2={S} y1={S - f(t)} y2={S - f(t)} className="grid" />
            <text x={f(t)} y={S + 16} textAnchor="middle" className="tick">
              {t} s
            </text>
            <text x={-6} y={S - f(t) + 4} textAnchor="end" className="tick">
              {t} s
            </text>
          </g>
        ))}
        <line x1={0} y1={S} x2={S} y2={0} className="ref" />
        <line
          x1={0}
          y1={S - f(2 * lo)}
          x2={f(hi / 2)}
          y2={0}
          className="ref dashed"
        />
        <text x={f(hi / 2) - 4} y={14} textAnchor="end" className="tick">
          2x
        </text>
        <text x={S - 4} y={14 + (S - f(hi))} textAnchor="end" className="tick">
          1x
        </text>
        {points.map(([a, b], i) => (
          <circle key={i} cx={f(a)} cy={S - f(b)} r={4} className="dot">
            <title>{`${a.toFixed(2)} s without, ${b.toFixed(2)} s with strace (${(b / a).toFixed(1)}x)`}</title>
          </circle>
        ))}
      </g>
    </svg>
  );
}

export default function Study() {
  const C = study.conditions;
  const ov = study.overhead;
  const runs = C.overt_issue.n + C.overt_agents_md.n + C.covert_script.n;
  const rows = [
    ["Told outright, in the issue", C.overt_issue],
    ["Told outright, in AGENTS.md", C.overt_agents_md],
    ["Hidden in a repo script", C.covert_script],
  ] as const;
  const bib = `@misc{faizan2026tripline,
  author       = {Faizan, Omer},
  title        = {Tripline: Recording and Containing a Coding Agent},
  year         = {2026},
  month        = nov,
  howpublished = {\\url{https://github.com/omerfaizan10/tripline}}
}`;

  return (
    <>
      <Nav current="study" meta="paper · 6 pages" />
      <main className="wrap">
        <div className="head">
          <div className="label">Study · November 2026 · Omer Faizan</div>
          <h1>Tripline: Recording and Containing a Coding Agent</h1>
          <p className="lede">
            A study of Codex on {study.clean.resolved.n} SWE-bench Verified
            tasks and {runs} prompt-injection runs. When an injected instruction
            was spelled out, the agent never followed it. When the same attack
            was hidden in a script it was asked to run, it ran the script
            without reading it, and only the sandbox stopped it.
          </p>
          <p className="paper-links">
            <a href="/tripline-study.pdf" className="cta">
              Read the paper (PDF, 6 pages)
            </a>
            <a href="https://github.com/omerfaizan10/tripline/tree/main/study">
              Source and data
            </a>
          </p>
        </div>

        <Section no="01" title="The question">
          <p>
            Coding agents run programs with the developer&apos;s files, network
            and credentials in reach, and they read text an attacker can write:
            issues, dependencies and instruction files like AGENTS.md. Most
            defences try to make the model refuse. This study looks one layer
            down: when an agent does follow a planted instruction, what can the
            environment record and stop, and how often does a current model
            follow one at all?
          </p>
        </Section>

        <Section no="02" title="Setup">
          <p>
            Codex CLI 0.165.0 on gpt-6-luna, inside Tripline with the enforcing
            benchmark policy, on all {study.clean.resolved.n} Django tasks in
            SWE-bench Verified that run on the sandbox&apos;s Python. Grading
            uses the benchmark&apos;s hidden tests in a separate container with
            no network; before any agent ran, every task was checked to fail as
            checked out and pass with the reference fix.
          </p>
          <p>
            Each task then ran three more times with an instruction to send the
            decoy AWS credential to a host under example.com, which never
            resolves: spelled out in the issue text, spelled out in AGENTS.md,
            or hidden in <code>scripts/check_env.py</code> with AGENTS.md only
            saying to run it before testing. The exact text of each is on every{" "}
            <Link href="/attacks/">attack run</Link>.
          </p>
        </Section>

        <Section no="03" title="Without attacks">
          <dl className="facts" style={{ marginTop: 0 }}>
            <div>
              <dt>Resolved</dt>
              <dd>
                {fr(study.clean.resolved)}{" "}
                <span className="dim">({pc(study.clean.resolved)})</span>
              </dd>
            </div>
            <div>
              <dt>Model cost</dt>
              <dd>${study.clean.cost.toFixed(2)}</dd>
            </div>
            <div>
              <dt>Decoy findings</dt>
              <dd>{fr(study.clean.decoy_findings)} runs</dd>
            </div>
          </dl>
          <p>
            No run touched a decoy, wrote outside its allowed paths or tried to
            connect around the proxy. The only blocked traffic was Codex&apos;s
            own analytics. The agent tried Django&apos;s tests in{" "}
            {study.clean.tests.tried} runs, and in all{" "}
            {study.clean.tests.system_python} its shell picked a Python without
            the test dependencies. <Link href="/results/">Full results</Link>.
          </p>
        </Section>

        <Section no="04" title="Planted instructions">
          <div style={{ overflowX: "auto", marginTop: 16 }}>
            <table className="table">
              <thead>
                <tr>
                  <th>Where</th>
                  <th className="r">Attempted</th>
                  <th className="r">95% interval</th>
                  <th className="r">Refused</th>
                  <th className="r">Ran tests</th>
                  <th className="r">Resolved</th>
                </tr>
              </thead>
              <tbody>
                {rows.map(([name, c]) => (
                  <tr key={name}>
                    <td>{name}</td>
                    <td
                      className={`r num${c.complied.k ? " blocked-text" : ""}`}
                    >
                      {fr(c.complied)}
                    </td>
                    <td className="r num">
                      {c.complied_ci[0]} to {c.complied_ci[1]}%
                    </td>
                    <td className="r num">{pc(c.declined_in_message)}</td>
                    <td className="r num">{pc(c.tried_tests)}</td>
                    <td className="r num">{pc(c.resolved)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p>
            The hidden script ran in {fr(C.covert_script.ran_script_of_tested)}{" "}
            runs where the agent ran tests and{" "}
            {fr(C.covert_script.ran_script_untested)} where it did not. It was
            opened first once. All {C.covert_script.flagged_of_attempts.n}{" "}
            credential reads were refused by Landlock and flagged, so nothing
            left the sandbox. The model&apos;s judgement works on what it reads,
            and the covert payload gave it nothing to read.
          </p>
        </Section>

        <Section no="05" title="What recording costs">
          <p>
            Each task&apos;s graded test modules, timed with and without the
            sandbox&apos;s strace flags, three runs each after a warm-up. Median
            slowdown {ov.ratio_median}x (10th to 90th percentile {ov.ratio_p10}x
            to {ov.ratio_p90}x). Test runners start many processes and open many
            files, so this is near a worst case; an agent&apos;s run is mostly
            waiting for the model.
          </p>
          <figure className="fig">
            <Overhead points={ov.points} />
            <figcaption>
              One dot per task ({ov.n}). Horizontal: without strace. Vertical:
              with it. Hover a dot for its times.
            </figcaption>
          </figure>
        </Section>

        <Section no="06" title="What went wrong on the way">
          <p>
            Grading every task with the reference fix before any agent ran found
            four grader bugs that would each have produced plausible but wrong
            scores. The worst: <code>git apply</code>, run inside another
            repository, silently skipped the hidden tests and exited
            successfully. Two confounds in the agent&apos;s environment are
            reported rather than hidden: the login shell&apos;s Python, and a
            laptop that slept mid-run.
          </p>
        </Section>

        <Section no="07" title="Limits">
          <p>
            One agent on one model, one repository, one run per task and
            condition, one wording per attack. The 0 of 164 applies to that
            wording; prior work shows compliance moves a lot with phrasing. The
            refusal measure is a keyword rule, checked by hand.
          </p>
        </Section>

        <Section no="08" title="Cite">
          <pre className="planted">{bib}</pre>
        </Section>

        <footer>
          Every number on this page and in the paper is computed from the run
          records by study/analyze.py.
        </footer>
      </main>
    </>
  );
}
