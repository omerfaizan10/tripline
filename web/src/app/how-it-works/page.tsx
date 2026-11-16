import type { Metadata } from "next";
import Link from "next/link";
import { Nav } from "@/components/Nav";
import { getIndex } from "@/lib/data";

export const metadata: Metadata = {
  title: "How it works · Tripline",
  description:
    "How Tripline records and confines a coding agent: strace outside a Landlock sandbox, an allowlisting proxy that holds the model key, decoy secrets, and a report built from the record.",
};

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

function Box({
  title,
  items,
  tone,
}: {
  title: string;
  items: string[];
  tone?: "outer";
}) {
  return (
    <div className={`dg-box${tone === "outer" ? " dg-outer" : ""}`}>
      <div className="dg-title">{title}</div>
      <ul>
        {items.map((i) => (
          <li key={i}>{i}</li>
        ))}
      </ul>
    </div>
  );
}

export default function HowItWorks() {
  const model = getIndex().runs.find((r) => r.kind === "bench")?.model ?? "";
  return (
    <>
      <Nav current="how" />
      <main className="wrap">
        <div className="head">
          <h1>How it works</h1>
          <p className="lede">
            A coding agent runs programs on your machine, with your files and
            often your credentials within reach. Tripline runs it in a container
            where every program it starts, every file it touches and every host
            it contacts is written down, and anything the policy does not allow
            is refused. Then it reads the record back as a report.
          </p>
        </div>

        <Section no="01" title="The layout">
          <p>
            One command, <code>tripline run</code>, sets up three things and
            tears them down afterwards: a run directory, a proxy container and
            the agent&apos;s container. The agent&apos;s container sits on an
            internal Docker network whose only route anywhere is the proxy.
          </p>
          <figure className="dg" aria-label="Diagram of the sandbox">
            <div className="dg-row">
              <Box
                title="Agent container"
                items={[
                  "tripline-shim run: starts strace",
                  "strace -f: records every process",
                  "tripline-shim confine: applies Landlock",
                  "the agent, e.g. Codex",
                ]}
              />
              <div className="dg-arrow" aria-hidden="true">
                <span className="dg-a-h">→</span>
                <span className="dg-a-v">↓</span>
                <small>only route out</small>
              </div>
              <Box
                title="Proxy container"
                items={[
                  "allowlist by hostname",
                  "model gateway: holds the real key",
                  "meters tokens, scans for decoys",
                  "logs every request",
                ]}
              />
              <div className="dg-arrow" aria-hidden="true">
                <span className="dg-a-h">→</span>
                <span className="dg-a-v">↓</span>
                <small>allowed hosts</small>
              </div>
              <Box
                title="Internet"
                tone="outer"
                items={[
                  "api.openai.com",
                  "pypi.org, registries",
                  "nothing else",
                ]}
              />
            </div>
            <div className="dg-blocked">
              <span className="dg-x" aria-hidden="true" />
              Agent straight to the internet: no route on the internal network,
              and Landlock refuses TCP connections to anything but the
              proxy&apos;s ports.
            </div>
            <div className="dg-after">
              <strong>Afterwards</strong>, on the host: the strace log and the
              proxy log are parsed into one event stream, analysed against the
              policy and written up as a report.
            </div>
          </figure>
        </Section>

        <Section no="02" title="Recording">
          <p>
            <code>strace -f</code> follows the agent and every process it
            starts, and logs each program run, file opened, written, renamed or
            deleted, and network connection attempted. The parser turns that log
            into events, resolving relative paths against each process&apos;s
            working directory.
          </p>
          <p>
            The order of the two shim stages matters. The outer stage starts
            strace, and strace starts the inner stage, which confines itself
            with Landlock and then becomes the agent. So the tracer is outside
            the sandbox it is watching, and it writes its log to a directory the
            agent cannot open. An agent cannot read or rewrite its own record.
          </p>
        </Section>

        <Section no="03" title="Enforcing">
          <p>
            A policy is a short YAML file: the paths the agent may read, the
            paths it may write, the hosts it may reach and the programs worth
            flagging. Landlock, a Linux kernel feature for unprivileged
            sandboxing, enforces the file rules and limits TCP connections to
            the proxy. The proxy enforces the host list.
          </p>
          <dl className="modes">
            <div>
              <dt>enforce</dt>
              <dd>
                Refuses anything outside the policy and records the attempt.
              </dd>
            </div>
            <div>
              <dt>audit</dt>
              <dd>
                Refuses nothing it does not have to, and flags everything
                outside the policy. Useful for learning what an agent needs.
              </dd>
            </div>
            <div>
              <dt>ask</dt>
              <dd>
                Refuses file access outside the policy, and pauses requests to
                unknown hosts until you answer.
              </dd>
            </div>
          </dl>
          <p>
            After a few audited runs, <code>tripline policy synth</code> writes
            the tightest policy that would have allowed them, leaving out
            anything that touched a decoy.
          </p>
        </Section>

        <Section no="04" title="Decoy secrets">
          <p>
            Each run plants fake credentials where agents and malware look for
            real ones: <code>~/.aws/credentials</code>,{" "}
            <code>~/.ssh/id_ed25519</code>, <code>~/.config/gh/hosts.yml</code>{" "}
            and <code>~/.npmrc</code>. Each holds a unique random value. Reading
            one, putting its value on a command line, sending it to the network
            or writing it into the workspace is a high finding. Reports show{" "}
            <code>[decoy:github]</code> in place of the value.
          </p>
        </Section>

        <Section no="05" title="The model gateway">
          <p>
            The agent never holds the real API key. It talks to a gateway inside
            the proxy with a placeholder key; the gateway swaps in the real one,
            forwards the request and reads the token counts from the response.
            Each run&apos;s cost comes from those counts and a dated price
            table, so the {model} runs on the results page are priced from what
            was metered, not estimated.
          </p>
        </Section>

        <Section no="06" title="From events to a report">
          <p>
            Every event is checked against the run&apos;s policy. The report
            gives:
          </p>
          <ul>
            <li>
              <strong>Findings</strong>, high when the action succeeded (a decoy
              read, a write outside the policy, a connection around the proxy),
              medium when it was refused or is worth a look.
            </li>
            <li>
              <strong>Reach</strong>: every place outside the workspace the
              agent touched, grouped into locations like <code>~/.cache</code>{" "}
              or <code>/tmp</code>, and every host it contacted.
            </li>
            <li>
              <strong>A timeline</strong> of the programs it ran, its model
              requests and what was blocked, and <strong>the diff</strong> of
              what it changed.
            </li>
          </ul>
          <p>
            The{" "}
            <Link href="/runs/rogue-audit/">
              scripted rogue agent under the audit policy
            </Link>{" "}
            shows all of it in one second of activity: two decoy credentials
            read, one written into the repo and put on a curl command line, a
            connection around the proxy refused and <code>~/.bashrc</code>{" "}
            modified.
          </p>
        </Section>

        <Section no="07" title="What it does not catch">
          <ul>
            <li>
              <strong>The contents of HTTPS traffic to other hosts.</strong> The
              proxy tunnels it, so it sees the hostname but not the request.
              Model traffic, plain HTTP and hostnames are checked for decoys;
              the trace still records which program connected and its command
              line.
            </li>
            <li>
              <strong>Anything inside an allowed path.</strong> A policy that
              allows <code>~/.codex</code> allows everything there. Reach shows
              what was touched, but the policy is only as tight as you write it.
            </li>
            <li>
              <strong>An agent that behaves differently when watched.</strong>{" "}
              The sandbox is not hidden. The decoys look real, but an agent
              could still notice the container.
            </li>
            <li>
              <strong>Platforms other than Linux.</strong> Landlock and strace
              are Linux features. On a Mac it runs inside Colima&apos;s Linux
              VM.
            </li>
          </ul>
        </Section>

        <footer>
          The code, the policies and the benchmark harness are in the
          repository; the README covers how to run it.
        </footer>
      </main>
    </>
  );
}
