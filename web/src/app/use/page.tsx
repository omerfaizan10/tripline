import fs from "node:fs";
import path from "node:path";
import type { Metadata } from "next";
import Link from "next/link";
import { Nav } from "@/components/Nav";

export const metadata: Metadata = {
  title: "Use it · Tripline",
  description:
    "Run your own coding agent in Tripline: build it, write a policy, run a session, read the report and let it write the tightest policy for you.",
};

const DATA = path.join(process.cwd(), "data");
const read = (...p: string[]) => fs.readFileSync(path.join(DATA, ...p), "utf8");

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

function Code({ children }: { children: string }) {
  return <pre className="planted">{children.trim()}</pre>;
}

const FIELDS: [string, string][] = [
  [
    "mode",
    "enforce, audit or ask. Enforce refuses anything outside the policy; audit lets it through and flags it; ask pauses unknown hosts for a decision.",
  ],
  [
    "filesystem.read",
    "Paths the agent may read, beyond its workspace. Landlock enforces it in the kernel.",
  ],
  [
    "filesystem.write",
    "Paths the agent may write. ${WORKSPACE} is the task copy; ${HOME} is the sandbox home, where the decoys live.",
  ],
  [
    "network.allow_hosts",
    "Hostnames the proxy lets through. The model API is always allowed through the gateway, which holds the real key.",
  ],
  [
    "exec.flag",
    "Programs that are allowed but recorded as a finding when run, like curl or ssh.",
  ],
];

export default function Use() {
  const policies = ["default", "bench", "audit"].map((n) => ({
    name: n,
    text: read("policies", `${n}.yaml`),
  }));
  const report = read("samples", "report-rogue-audit.txt");
  const synth = read("samples", "synth-rogue-audit.yaml");

  return (
    <>
      <Nav current="use" />
      <main className="wrap">
        <div className="head">
          <h1>Use it on your own agent</h1>
          <p className="lede">
            Tripline wraps any command: Codex, another agent, or a shell script.
            You give it a task directory and a policy; it gives you back a run
            directory with the full record and a report. It runs on Linux, or on
            macOS inside a Linux VM.
          </p>
        </div>

        <Section no="01" title="Build">
          <p>
            You need Go 1.27 and Docker. On macOS I used Colima 0.10, which
            shares only your home directory into the VM, so keep the project
            under <code>$HOME</code>.
          </p>
          <Code>{`
git clone https://github.com/omerfaizan10/tripline
cd tripline
make all        # host CLI, Linux shim and proxy, sandbox image
echo 'OPENAI_API_KEY=...' > .env   # only the proxy ever sees it
`}</Code>
        </Section>

        <Section no="02" title="Run a session">
          <p>
            Everything after <code>--</code> runs inside the sandbox, in{" "}
            <code>/work</code>, a copy of the task directory. This one runs the
            scripted rogue agent under the audit policy, so its bad actions go
            through and get recorded.
          </p>
          <Code>{`
./bin/tripline run --task testdata/tasks/hello --policy policies/audit.yaml -- /work/rogue_agent.sh
./bin/tripline runs                    # list past runs
./bin/tripline report .runs/<run-id>   # re-analyse and print one
`}</Code>
          <p>
            Useful flags: <code>--name</code> labels a run,{" "}
            <code>--env KEY=VALUE</code> passes settings to the agent,{" "}
            <code>--cpus</code> and <code>--memory</code> cap the container, and{" "}
            <code>--model-upstream</code> points the gateway at a different
            model API.
          </p>
        </Section>

        <Section no="03" title="Read the report">
          <p>
            The report for that run, as the CLI prints it. The same run is{" "}
            <Link href="/runs/rogue-audit/">on the site</Link> with its full
            timeline. Decoy values are redacted everywhere.
          </p>
          <Code>{report}</Code>
        </Section>

        <Section no="04" title="Write a policy">
          <p>
            A policy is a short YAML file. Anything not listed is outside it.
          </p>
          <dl className="modes">
            {FIELDS.map(([k, v]) => (
              <div key={k}>
                <dt>{k}</dt>
                <dd>{v}</dd>
              </div>
            ))}
          </dl>
          <p>The three that ship with Tripline:</p>
          {policies.map((p) => (
            <details key={p.name}>
              <summary>
                <span className="mono">policies/{p.name}.yaml</span>
              </summary>
              <Code>{p.text}</Code>
            </details>
          ))}
        </Section>

        <Section no="05" title="Let it write the policy">
          <p>
            Run an agent a few times under the audit policy, then ask for the
            tightest policy that would have allowed what it did. Decoy paths are
            never granted, even when a run touched them; they are listed in the
            header instead. From the rogue run above:
          </p>
          <Code>{`./bin/tripline policy synth .runs/<run-id> .runs/<run-id-2>`}</Code>
          <Code>{synth}</Code>
          <p>
            Review it before using it: here it would allow writing{" "}
            <code>~/.bashrc</code>, because the rogue agent did.
          </p>
        </Section>

        <Section no="06" title="Run the benchmark">
          <p>
            The SWE-bench harness that produced every run on this site. The gold
            check grades the reference fixes with no model calls, so you can
            confirm the grader before spending anything.
          </p>
          <Code>{`
python3 bench/run.py select --n 5 --seed 7 > bench/sets/pilot.txt
python3 bench/run.py gold --set bench/sets/pilot.txt
python3 bench/run.py run --set bench/sets/pilot.txt --model gpt-6-luna
python3 bench/run.py run --set bench/sets/pilot.txt --model gpt-6-luna --inject covert
`}</Code>
          <p>
            <code>--inject</code> takes <code>issue</code>,{" "}
            <code>agents_md</code> or <code>covert</code>, the three{" "}
            <Link href="/attacks/">attack conditions</Link>.
          </p>
        </Section>

        <footer>
          Source, issues and the paper:{" "}
          <a href="https://github.com/omerfaizan10/tripline">
            github.com/omerfaizan10/tripline
          </a>
          .
        </footer>
      </main>
    </>
  );
}
