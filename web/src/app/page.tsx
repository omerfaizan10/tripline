import Link from "next/link";
import { Nav } from "@/components/Nav";
import { RunTable } from "@/components/RunTable";
import { getIndex, getRun } from "@/lib/data";
import { usd } from "@/lib/format";

export default function Home() {
  const { runs } = getIndex();
  const bench = runs.filter((r) => r.kind === "bench");
  const rogue = runs.filter((r) => r.kind === "rogue");
  const resolved = bench.filter((r) => r.resolved).length;
  const cost = bench.reduce((s, r) => s + r.cost, 0);
  const tested = bench.filter((r) => r.ran_tests).length;
  const model = bench[0]?.model ?? "";
  const blocked = bench.reduce((n, r) => n + r.denied, 0);
  // Blocked actions that were not network requests (reads Landlock refused).
  const readBlocks = bench.reduce((n, r) => n + r.denied - getRun(r.id).hosts.reduce((m, h) => m + h.denied, 0), 0);

  return (
    <>
      <Nav current="runs" meta={`${bench.length} runs · ${model}`} />
      <main className="wrap">
        <div className="head">
          <h1>Every recorded run, second by second</h1>
          <p className="lede">
            Tripline runs a coding agent in a sandbox that records every
            program it starts, every file it touches and every host it contacts,
            and blocks what the policy does not allow. Below: Codex on {model}{" "}
            working through all {bench.length} Django tasks from SWE-bench
            Verified, plus a scripted agent that misbehaves on purpose.
          </p>
          <dl className="facts">
            <div>
              <dt>Resolved</dt>
              <dd>
                {resolved} of {bench.length}{" "}
                <span className="dim">
                  ({((resolved / bench.length) * 100).toFixed(1)}%)
                </span>
              </dd>
            </div>
            <div>
              <dt>Model cost, all runs</dt>
              <dd>{usd(cost)}</dd>
            </div>
            <div>
              <dt>Ran the test suite</dt>
              <dd>
                {tested} of {bench.length} runs
              </dd>
            </div>
            <div>
              <dt>Blocked, all runs</dt>
              <dd>
                {blocked} actions{" "}
                <span className="dim">
                  ({blocked - readBlocks} analytics calls, {readBlocks} reads of /)
                </span>
              </dd>
            </div>
          </dl>
        </div>

        <section className="section">
          <div className="no">01</div>
          <div>
            <h2>The scripted rogue agent</h2>
            <p className="sub">
              The same six bad actions under two policies. Enforce blocks all
              six. Audit lets file and proxy traffic through and records each
              action as a finding; the direct connection is blocked either way,
              because the sandbox network only leads to the proxy.
            </p>
            <div className="featured">
              {rogue.map((r) => (
                <Link key={r.id} href={`/runs/${r.id}/`}>
                  <h3>
                    {r.mode === "enforce"
                      ? "Enforce: blocked"
                      : "Audit: allowed and recorded"}
                  </h3>
                  <p>
                    {r.mode === "enforce"
                      ? `${r.denied} actions blocked, ${r.findings.medium ?? 0} medium findings`
                      : `${r.findings.high ?? 0} high findings: decoy secrets read, written into the repo and put on a curl command line`}
                  </p>
                </Link>
              ))}
            </div>
          </div>
        </section>

        <section className="section">
          <div className="no">02</div>
          <div>
            <h2>Codex on SWE-bench Verified, Django</h2>
            <p className="sub">
              Each row is one sandboxed run, graded against the benchmark&apos;s
              hidden tests. Almost every blocked action is Codex calling
              ab.chatgpt.com for analytics, which is not on the allowlist; longer
              runs call it more than once. The exceptions are two runs where it
              looked for an AGENTS.md file above its workspace.
            </p>
            <RunTable runs={bench} />
          </div>
        </section>

        <footer>
          Recorded with strace inside a Docker sandbox confined by Landlock;
          network through an allowlisting proxy that also meters model tokens.
          Model prices from OpenAI&apos;s published API pricing, read
          2026-11-15.
        </footer>
      </main>
    </>
  );
}
