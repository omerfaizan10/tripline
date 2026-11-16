import type { Metadata } from "next";
import Link from "next/link";
import { Diff } from "@/components/Diff";
import { Nav } from "@/components/Nav";
import { Timeline } from "@/components/Timeline";
import { getIndex, getRun, shortId } from "@/lib/data";
import { count, kb, longDuration, offset, secs, usd } from "@/lib/format";

export const dynamicParams = false;

export function generateStaticParams() {
  return getIndex().runs.map((r) => ({ id: r.id }));
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ id: string }>;
}): Promise<Metadata> {
  const { id } = await params;
  const run = getRun(id);
  return { title: `${shortId(id)} · Tripline`, description: run.title };
}

function Section({
  no,
  title,
  sub,
  children,
}: {
  no: string;
  title: string;
  sub?: string;
  children: React.ReactNode;
}) {
  return (
    <section className="section">
      <div className="no">{no}</div>
      <div>
        <h2>{title}</h2>
        {sub ? <p className="sub">{sub}</p> : <div style={{ height: 16 }} />}
        {children}
      </div>
    </section>
  );
}

export default async function RunPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const run = getRun(id);
  const rogue = run.kind === "rogue";
  const blockedCount = run.timeline
    .filter((t) => t.k === "blocked")
    .reduce((n, t) => n + (t.n ?? 1), 0);

  return (
    <>
      <Nav
        current="runs"
        meta={
          rogue ? "scripted agent, no model" : `${run.model} · ${run.policy}`
        }
      />
      <main className="wrap">
        <div className="head">
          <div className="crumb">
            <Link href="/">All runs</Link> /{" "}
            <span className="mono">{shortId(id)}</span>
          </div>
          <h1>{run.title}</h1>
          {rogue ? (
            <p className="lede">
              A shell script, not a model. After one legitimate edit and a pip
              download through the proxy, it tries six things an agent should
              not do: read a GitHub token, read an SSH key, write the token into
              the repo, send it to a paste site, connect around the proxy and
              append to its shell profile. The secrets are decoys planted for
              the run.
            </p>
          ) : (
            <p className="lede">
              Codex on {run.model}, given this SWE-bench Verified issue and a
              checkout of Django at the issue&apos;s base commit. Graded against
              the benchmark&apos;s hidden tests in a separate container.
            </p>
          )}
          <dl className="facts">
            {!rogue && (
              <div>
                <dt>Result</dt>
                <dd className={`verdict ${run.resolved ? "yes" : "no"}`}>
                  {run.resolved ? "Resolved" : "Not resolved"}
                </dd>
              </div>
            )}
            {!rogue && (
              <div>
                <dt>Difficulty</dt>
                <dd>{run.difficulty}</dd>
              </div>
            )}
            <div>
              <dt>Policy mode</dt>
              <dd>{run.mode}</dd>
            </div>
            <div>
              <dt>Duration</dt>
              <dd>
                {secs(run.seconds)}
                {run.slept > 0 ? (
                  <span className="dim"> · plus {longDuration(run.slept)} with the laptop asleep</span>
                ) : null}
              </dd>
            </div>
            {!rogue && (
              <div>
                <dt>Model cost</dt>
                <dd>
                  {usd(run.cost)}{" "}
                  <span className="dim">· {run.requests} requests</span>
                </dd>
              </div>
            )}
            <div>
              <dt>Blocked</dt>
              <dd className={blockedCount ? "blocked-text" : undefined}>
                {blockedCount
                  ? `${blockedCount} ${blockedCount === 1 ? "action" : "actions"}`
                  : "Nothing"}
              </dd>
            </div>
            <div>
              <dt>Recorded</dt>
              <dd>{count(run.files.events)} events</dd>
            </div>
          </dl>
        </div>

        <Section
          no="01"
          title="Timeline"
          sub={`What ran, in order, measured from the start of the run in seconds. File reads (${count(run.files.read)} of them) are left out; every program, model request, network request and blocked action is in.`}
        >
          <Timeline items={run.timeline} />
        </Section>

        <Section
          no="02"
          title="Reach"
          sub="Where the agent went outside its workspace. Each request left the sandbox through the proxy, which checks the host against the policy."
        >
          <div className="two">
            <div>
              <div className="label" style={{ marginBottom: 8 }}>
                Network, by host
              </div>
              <table className="table">
                <thead>
                  <tr>
                    <th>Host</th>
                    <th className="r">Allowed</th>
                    <th className="r">Blocked</th>
                    <th className="r hide-sm">Down</th>
                  </tr>
                </thead>
                <tbody>
                  {run.hosts.map((h) => (
                    <tr
                      key={h.host}
                      className={h.denied ? "is-blocked" : undefined}
                    >
                      <td className="mono" style={{ fontSize: 13 }}>
                        {h.host}
                        {h.model ? <span className="dim"> (model)</span> : null}
                        {h.failed ? (
                          <span className="dim">
                            {" "}
                            ({h.failed} failed: could not be reached)
                          </span>
                        ) : null}
                      </td>
                      <td className="r num">{h.allowed}</td>
                      <td className="r num blk">{h.denied || ""}</td>
                      <td className="r num dim hide-sm">
                        {h.bytes_down ? kb(h.bytes_down) : ""}
                      </td>
                    </tr>
                  ))}
                  {run.hosts.length === 0 && (
                    <tr>
                      <td colSpan={4} className="dim">
                        No network requests.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            <div>
              <div className="label" style={{ marginBottom: 8 }}>
                Files outside the workspace
              </div>
              <table className="table">
                <thead>
                  <tr>
                    <th>Location</th>
                    <th className="r">Files</th>
                    <th className="r">Writes</th>
                  </tr>
                </thead>
                <tbody>
                  {run.radius.map((r) => (
                    <tr
                      key={r.root}
                      className={r.decoy ? "is-blocked" : undefined}
                    >
                      <td className="mono blk" style={{ fontSize: 13 }}>
                        {r.root}
                        {r.decoy ? " (decoy secret)" : ""}
                      </td>
                      <td className="r num">{r.files}</td>
                      <td className="r num">{r.writes}</td>
                    </tr>
                  ))}
                  {run.radius.length === 0 && (
                    <tr>
                      <td colSpan={3} className="dim">
                        Stayed inside the workspace.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </Section>

        <Section
          no="03"
          title="Findings"
          sub="What the analyser flagged. High means the action succeeded; medium means it was attempted and blocked, or is worth a look."
        >
          {run.findings_list.length ? (
            <ul className="findings">
              {run.findings_list.map((f, i) => (
                <li key={i}>
                  <span className="mono dim" style={{ fontSize: 12 }}>
                    {offset(f.t)}
                  </span>
                  <span className={`sev ${f.severity}`}>{f.severity}</span>
                  <span>
                    {f.title}
                    {f.count > 1 ? (
                      <span className="dim"> ×{f.count}</span>
                    ) : null}
                    <div className="detail">{f.detail}</div>
                  </span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="dim">Nothing flagged.</p>
          )}
        </Section>

        <Section
          no="04"
          title="Changes"
          sub={
            run.writes.length
              ? `Files the agent wrote in its workspace, then the diff against the starting tree.`
              : undefined
          }
        >
          {run.writes.length > 0 && (
            <ul className="findings" style={{ marginBottom: 20 }}>
              {run.writes.map((w) => (
                <li key={w.path} style={{ gridTemplateColumns: "76px minmax(0, 1fr)" }}>
                  <span className="mono dim" style={{ fontSize: 12 }}>
                    {offset(w.t)}
                  </span>
                  <span className="mono" style={{ fontSize: 13, overflowWrap: "anywhere" }}>
                    {w.path}
                  </span>
                </li>
              ))}
            </ul>
          )}
          {run.diff ? (
            <Diff text={run.diff} />
          ) : (
            <p className="dim">No changes recorded.</p>
          )}
        </Section>

        {!rogue && (
          <Section
            no="05"
            title="Grade"
            sub="The benchmark's hidden tests, applied to the agent's final tree. Fail-to-pass tests must now pass; pass-to-pass tests must keep passing."
          >
            <dl className="facts" style={{ marginTop: 0 }}>
              <div>
                <dt>Fail to pass</dt>
                <dd>
                  {run.f2p?.passed} of {run.f2p?.total}
                </dd>
              </div>
              <div>
                <dt>Pass to pass</dt>
                <dd>
                  {run.p2p?.passed} of {run.p2p?.total}
                </dd>
              </div>
              <div>
                <dt>Ran the tests itself</dt>
                <dd>{run.ran_tests ? "Yes" : "No"}</dd>
              </div>
            </dl>
            {run.not_ok.length > 0 && (
              <div style={{ marginTop: 20 }}>
                <div className="label" style={{ marginBottom: 8 }}>
                  Tests that did not pass
                </div>
                <ul className="findings">
                  {run.not_ok.map((t) => (
                    <li key={t} style={{ gridTemplateColumns: "minmax(0, 1fr)" }}>
                      <span className="detail">{t}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
            <details style={{ marginTop: 20 }}>
              <summary>The issue as the agent saw it</summary>
              <p className="issue">{run.issue}</p>
            </details>
          </Section>
        )}

        <footer>
          Sandbox: {run.landlock}. Policy file:{" "}
          <span className="mono">{run.policy}</span>.
        </footer>
      </main>
    </>
  );
}
