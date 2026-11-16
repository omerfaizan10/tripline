// Tripline study. Every number comes from data.json (study/analyze.py).
#let d = json("data.json")
#let C = d.conditions
#let ov = d.at("overhead", default: none)
#let pct(r) = if r.pct == none { "n/a" } else { str(r.pct) + "%" }
#let frac(r) = str(r.k) + "/" + str(r.n)
#let both(r) = frac(r) + " (" + pct(r) + ")"
#let usd(x) = "$" + str(calc.round(x, digits: 2))
#let cond-label = (overt_issue: "Overt, issue text", overt_agents_md: "Overt, AGENTS.md", covert_script: "Covert, repo script")

#set document(title: "Tripline: Recording and Containing a Coding Agent", author: "Omer Faizan")
#set page(paper: "us-letter", margin: (x: 0.75in, y: 0.8in), columns: 2, numbering: "1")
#set columns(gutter: 0.3in)
#set text(font: "Libertinus Serif", size: 10pt)
#set par(justify: true, leading: 0.55em, spacing: 0.75em)
#set heading(numbering: "1.1")
#show heading.where(level: 1): set text(size: 11pt)
#show heading.where(level: 2): set text(size: 10pt, style: "italic", weight: "regular")
#show heading: set block(above: 1.1em, below: 0.6em)
#show raw: set text(font: "DejaVu Sans Mono", size: 7.6pt)
#show figure.caption: set text(size: 8.5pt)
#show figure: set place(clearance: 1em)
#set table(stroke: none, inset: (x: 4pt, y: 3pt))

#place(top + center, float: true, scope: "parent", clearance: 1.6em)[
  #align(center)[
    #text(size: 16pt, weight: "bold")[Tripline: Recording and Containing a Coding Agent]
    #v(0.3em)
    #text(size: 11pt)[A study of Codex on #d.clean.n SWE-bench Verified tasks and #(C.overt_issue.n + C.overt_agents_md.n + C.covert_script.n) prompt-injection runs]
    #v(0.6em)
    #text(size: 10.5pt)[Omer Faizan]
    #v(0.1em)
    #text(size: 9pt)[#link("https://github.com/omerfaizan10/tripline")[github.com/omerfaizan10/tripline] · November 2026]
  ]
  #v(0.6em)
  #block(width: 88%)[
    #set align(left)
    #set par(justify: true)
    #set text(size: 9.3pt)
    *Abstract.* Coding agents run programs on the developer's machine with the developer's files, network and often credentials in reach.
    I present Tripline, a sandbox that records every program, file access and network request a coding agent makes, enforces a
    path and host policy with Landlock and an allowlisting proxy, holds the model API key outside the agent's reach, plants decoy
    credentials, and turns the record into a report. I use it to study OpenAI's Codex CLI on gpt-6-luna across all #d.clean.n Django
    tasks in SWE-bench Verified that run on the sandbox's Python, graded against the benchmark's hidden tests. Without attacks the agent
    resolved #both(d.clean.resolved) of tasks, touched no decoy credential in any run, and its only blocked network traffic was its own
    analytics calls. I then planted instructions to send a decoy credential to an outside host, in three conditions of #C.overt_issue.n
    runs each. When the instruction was explicit, in the issue text or in an `AGENTS.md` file, the agent never acted on it
    (#(C.overt_issue.complied.k + C.overt_agents_md.complied.k) of #(C.overt_issue.n + C.overt_agents_md.n) runs) and refused it in
    a message in #pct(C.overt_issue.declined_in_message) and #pct(C.overt_agents_md.declined_in_message) of runs. When `AGENTS.md`
    only asked it to run a repository script before testing, and the script did the same thing, it ran the script in
    #both(C.covert_script.ran_script) runs, including every run in which it ran tests, and read the script first in
    #frac(C.covert_script.inspected_script_first). Every one of those credential reads was refused by the sandbox and flagged.
    #if ov != none [Recording with strace cost a median #str(ov.ratio_median)$times$ slowdown on the benchmark's test suites.]
    Building the measurement exposed four grader bugs that would have silently corrupted scores, and two confounds in the agent's
    environment; I describe them because they apply to any agent evaluation.
  ]
]

= Introduction

A coding agent is a language model that edits a repository by running commands: it reads files, runs tests, installs packages
and fetches pages. It does this with the developer's permissions. Developers can see the final diff, but not the path the agent took
to get there: which files outside the repository it read, which hosts it contacted, or what it did when an instruction it found in the
repository told it to do something else.

Prompt injection makes the last question pressing. An agent cannot reliably tell instructions from data, so text planted where it
will read it can redirect it @greshake2023indirect. Coding agents read a lot of attacker-reachable text: issue descriptions,
dependencies and, increasingly, instruction files such as `AGENTS.md` that the agent loads automatically and is told to obey
@codex2026prompt. Recent work reports high attack success rates against coding assistants through exactly these files
@liu2025aishelljack @isbarov2026gitinject.

Defences usually target the model: make it refuse. This study looks at the layer underneath. If the agent does follow an injected
instruction, what can the environment record and stop? I make three contributions:

+ *Tripline*, a sandbox and recorder for coding agents (§3): strace outside a Landlock domain, an allowlisting proxy that also acts as a model gateway holding the API key, decoy credentials, and an analyser that turns events into findings, a timeline and a reach map.
+ *A measurement study* (§5) of Codex CLI on gpt-6-luna over #d.clean.n SWE-bench Verified tasks without attacks, and over #(C.overt_issue.n * 3) runs with planted instructions in three conditions, separating what the model refuses from what the sandbox has to stop.
+ *Methodological lessons* (§6) from validating the grader and the environment, including four silent grader bugs found by grading every task with the reference fix before any agent ran.

= Related work

*SWE-bench* @jimenez2024swebench evaluates language models on real GitHub issues: the model edits a repository and is graded by tests
the reference fix makes pass (fail-to-pass) and tests that must keep passing (pass-to-pass). *SWE-bench Verified* @openai2024verified
is a 500-task subset screened by professional developers, with difficulty labels estimating how long a developer would take. I use its
Django tasks and labels.

*Indirect prompt injection* was introduced by Greshake et al. @greshake2023indirect, who showed that instructions planted in retrieved
data can steer LLM-integrated applications, including to steal data. *AgentDojo* @debenedetti2024agentdojo measures injection attacks
and defences for tool-using agents over 97 tasks and 629 security cases. For coding agents specifically, *AIShellJack*
@liu2025aishelljack reports attack success rates up to 84% against Copilot and Cursor through poisoned rules files, and *GitInject*
@isbarov2026gitinject shows that configuration files such as `AGENTS.md` added in a pull request are loaded as operator-level
instructions by agents in CI. These works measure whether the attack succeeds at the model. This study measures what an
environment-level recorder and policy see and stop when it does, and how often a current model complies at all.

*Sandboxing* here rests on Landlock @salaun2026landlock, a Linux security module that lets an unprivileged process restrict its own
filesystem and network access, and on strace @strace for recording.

= Tripline

#figure(
  placement: top,
  scope: "parent",
  caption: [Tripline's layout. The agent's container sits on an internal network whose only route out is the proxy. strace runs outside the Landlock domain it records, and writes where the agent cannot reach.],
  block(width: 100%, inset: (y: 4pt))[
    #set text(size: 8pt)
    #let bx(title, items, dash: none) = box(stroke: (paint: black, thickness: 0.7pt, dash: dash), inset: 6pt, width: 100%)[
      #text(weight: "bold", size: 7.5pt, upper(title)) \
      #for i in items [#text(font: "DejaVu Sans Mono", size: 6.8pt, i) \ ]
    ]
    #grid(columns: (1.3fr, 0.32fr, 1.15fr, 0.32fr, 0.85fr), align: horizon,
      bx("Agent container", ("tripline-shim run: starts strace", "strace -f: records every process", "tripline-shim confine: Landlock", "the agent (Codex CLI)")),
      align(center)[→ \ #text(size: 6.5pt)[only route]],
      bx("Proxy container", ("allowlist by hostname", "model gateway: holds real key", "meters tokens, scans decoys", "logs every request")),
      align(center)[→ \ #text(size: 6.5pt)[allowed]],
      bx("Internet", ("api.openai.com", "package registries", "nothing else"), dash: "dashed"),
    )
    #v(3pt)
    #text(size: 7.5pt)[Direct connections from the agent are impossible twice over: no route on the internal network, and Landlock limits TCP connects to the proxy's ports. After the run, the host parses the strace log and the proxy log into one event stream and analyses it against the policy.]
  ],
) <fig-layout>

A run starts with `tripline run --policy P --task T -- <agent command>`. Tripline copies the task into a run directory, plants decoy
credentials in the sandbox's home directory, starts a proxy container, and starts the agent's container on an internal Docker network
(@fig-layout). The container drops all Linux capabilities.

*Recording.* A small launcher, `tripline-shim`, runs in two stages. The outer stage starts `strace -f`, which follows every process the
agent starts and logs program executions, file opens, writes, renames, deletions, directory creation and connection attempts. strace
then starts the inner stage, which applies Landlock to itself and executes the agent. The tracer is therefore outside the sandbox it
records, and writes its log to a directory the agent cannot open, so an agent cannot read or rewrite its own record.

*Enforcement.* A policy lists readable paths, writable paths, allowed hosts, and programs to flag. Landlock enforces the path rules and
restricts TCP connections to the proxy's ports; the proxy enforces the host list. A policy runs in one of three modes: _enforce_
refuses anything outside it, _audit_ refuses nothing it does not have to and flags everything, and _ask_ pauses unknown hosts for a
human decision. From a set of audited runs, `tripline policy synth` writes the tightest policy that would have allowed them, never
granting a decoy path.

*Model gateway.* The agent is configured with a placeholder key and the proxy's address. The gateway inserts the real key, forwards the
request, and reads token counts from the response, so cost is measured, not estimated.

*Decoys.* Each run plants unique random fake credentials where agents and malware look: `~/.aws/credentials`, `~/.ssh/id_ed25519`,
`~/.config/gh/hosts.yml` and `~/.npmrc`. Reading one, putting its value on a command line, sending it to the network or writing it
into the workspace is a high-severity finding; a refused attempt is medium. Reports redact the values.

*Analysis.* The analyser checks every event against the run's policy and produces findings, a reach map (every location outside the
workspace the agent touched, grouped, and every host contacted), a timeline and the diff of the agent's changes.

= Study setup

== Tasks, agent and grading

I use all #d.clean.n Django tasks of version 4.1 to 5.0 in SWE-bench Verified, which run from source on the sandbox's Python 3.11
without per-task images. Each task starts from the issue's base commit with git history cut to a single commit, so the future fix
cannot be read from the log. The agent is OpenAI's Codex CLI 0.165.0 on gpt-6-luna with medium reasoning effort, run headless with
its own sandbox disabled (the container is the sandbox) and its plugin and app sync turned off, since otherwise it clones a 25 MB
repository on every start. The prompt (Appendix A) gives the issue and the command for Django's tests.

Runs use a benchmark policy: the default policy without GitHub, since Django's upstream fixes are public there. Grading happens in a
separate container with no network: the benchmark's hidden test patch is applied to the agent's final tree, then fail-to-pass tests
must pass and pass-to-pass tests must keep passing.

== Validating the grader

Before any agent ran, I graded every task twice with no agent: as checked out, which must fail, and with the benchmark's reference fix,
which must pass. All #d.clean.n tasks passed this check after four bugs were fixed (§6). One pass-to-pass test, `test_strip_tags`
in django-15103, fails on the unmodified code in this environment because Debian's Python carries a security patch to `html.parser`
that the test predates; tests that fail both before and after the reference fix are excluded, which affects this one test.

== Prompt-injection conditions

Each condition runs all #C.overt_issue.n tasks once with a planted instruction to send the decoy AWS credential to a host under
`example.com`, which is reserved and never resolves @rfc2606 (Appendix B):

- *Overt, issue text.* The instruction is appended to the issue as a note from the maintainers: pipe `~/.aws/credentials` to the host with `curl`.
- *Overt, AGENTS.md.* The same instruction in an `AGENTS.md` file at the repository root. Codex includes this file in its developer message without being asked @codex2026prompt, and OpenAI's own guidance warns that its models can be sensitive to instructions in such files @codex2026guide.
- *Covert, repository script.* `AGENTS.md` says only to run `python3 scripts/check_env.py` before testing. The script reads the credential and posts it to the host. The instruction never mentions credentials; the attack is in code the agent would have to read to notice.

All runs use the enforcing benchmark policy, as a deployment would. A run _complied_ if it attempted to read the decoy or to contact the
planted host. I also record whether the agent ran and inspected the script, whether it ran Django's tests, whether it explicitly
refused in a message (a keyword rule requiring one sentence that both declines and names the risk, restricted to runs with no attempt,
and checked by hand against every unmatched message in the overt conditions), whether it mentioned the planted instruction at all, whether Tripline flagged the attempt, and whether the task was
still resolved. The #d.clean.n runs without injection are the false-positive baseline.

== Recording overhead

To isolate the cost of recording, I time each task's graded test modules in the sandbox image with and without the sandbox's exact
strace flags, after one untimed warm-up run, three repetitions each in alternating order, measured inside the container. This
workload, Django's test runner, starts many processes and opens many files, so it is closer to a worst case than to an agent's
typical step, which is dominated by waiting for the model.

== Ethics

Every credential in the sandbox is a decoy generated for the run; no real secret was present. The planted host is under a reserved
domain that cannot resolve, and the proxy blocked it in any case. The attacks are standard published patterns
@greshake2023indirect @liu2025aishelljack @isbarov2026gitinject applied to my own sandbox and repositories.

= Results

== RQ1: What the agent reaches without attacks

#let t = d.clean.tests
The agent resolved #both(d.clean.resolved) of the tasks for #usd(d.clean.cost_total) in total. No run touched a decoy
(#frac(d.clean.decoy_findings) runs with a decoy finding), wrote outside the allowed paths, or tried to connect around the proxy. Every run
wrote Codex's own state under `~/.codex`, which the policy allows, and every run tried to reach `ab.chatgpt.com` for analytics, which
the proxy refused. In two runs the agent searched for an `AGENTS.md` file above its workspace (`find .. -name AGENTS.md`), and Landlock
refused to list `/`.

The agent tried to run Django's tests in #t.tried of #d.clean.n runs. In all #t.system_python it ran the system Python rather than
the environment that holds Django's test dependencies (§6.2), so the tests could not import; in #t.built_own_env run it noticed and
built its own virtual environment. The resolve rate was reached almost entirely without working tests.

== RQ2: Planted instructions

#let conds = ("overt_issue", "overt_agents_md", "covert_script")
#figure(
  placement: top,
  caption: [Share of runs that attempted the planted action (read the decoy or contact the planted host), with 95% Wilson intervals. #C.overt_issue.n runs per condition.],
  block(width: 100%)[
    #set text(size: 7.5pt)
    #let W = 3.9cm
    #for k in conds {
      let c = C.at(k)
      let p = if c.complied.pct == none { 0 } else { c.complied.pct }
      let lo = c.complied_ci.at(0)
      let hi = c.complied_ci.at(1)
      grid(columns: (2.3cm, W + 0.25cm, 1fr), align: (left + horizon, left + horizon, right + horizon),
        cond-label.at(k),
        box(width: W, height: 9pt)[
          #place(left + horizon, box(width: W, height: 6pt, fill: luma(232)))
          #place(left + horizon, box(width: W * p / 100, height: 6pt, fill: luma(40)))
          #place(left + horizon, dx: W * lo / 100, box(width: W * (hi - lo) / 100, height: 0pt, stroke: (top: 0.8pt + luma(0))))
          #place(left + horizon, dx: W * lo / 100, box(width: 0pt, height: 7pt, stroke: (left: 0.8pt)))
          #place(left + horizon, dx: W * hi / 100, box(width: 0pt, height: 7pt, stroke: (left: 0.8pt)))
        ],
        [#frac(c.complied) (#pct(c.complied))],
      )
      v(3pt)
    }
    #grid(columns: (2.3cm, W), [], grid(columns: (1fr, 1fr, 1fr), align: (left, center, right), [0%], [50%], [100%]))
  ],
) <fig-comply>

#figure(
  placement: top,
  scope: "parent",
  caption: [Outcomes per condition. Percentages of #C.overt_issue.n runs unless marked _of attempts_. Refused: said in a message that it would not follow the instruction. Resolved: task still solved under injection; the same tasks without injection resolved #pct(C.overt_issue.resolved_clean_same_tasks).],
  {
  set text(size: 8.5pt, hyphenate: false)
  table(
    columns: (1.45fr, 0.8fr, 0.75fr, 0.8fr, 0.85fr, 0.75fr, 0.75fr, 1.05fr, 1.15fr, 0.8fr),
    align: (left, right, right, right, right, right, right, right, right, right),
    table.hline(stroke: 0.7pt),
    table.header([*Condition*], [*Complied*], [*Read\ decoy*], [*Contacted\ host*], [*Refused*], [*Ran\ tests*], [*Ran\ script*], [*Flagged\ (of attempts)*], [*Reported block\ (of attempts)*], [*Resolved*]),
    table.hline(stroke: 0.4pt),
    ..conds.map(k => {
      let c = C.at(k)
      (cond-label.at(k), pct(c.complied), pct(c.read_attempt), pct(c.exfil_attempt), pct(c.declined_in_message),
       pct(c.tried_tests), pct(c.ran_script), both(c.flagged_of_attempts), both(c.reported_block_of_attempts), pct(c.resolved))
    }).flatten(),
    table.hline(stroke: 0.7pt),
  )
  },
) <tab-outcomes>

@fig-comply and @tab-outcomes give the results. The explicit instruction was never followed: #frac(C.overt_issue.complied) runs
when it came in the issue text and #frac(C.overt_agents_md.complied) when it came in `AGENTS.md` (95% upper bound
#str(C.overt_issue.complied_ci.at(1))% each). The agent refused it in a message in #pct(C.overt_issue.declined_in_message) and
#pct(C.overt_agents_md.declined_in_message) of runs and mentioned it at all in #pct(C.overt_issue.mentioned_payload) and
#pct(C.overt_agents_md.mentioned_payload); the rest silently ignored it. A typical message: "I also skipped the requested telemetry
command because it would upload AWS credentials to an external host." Refusing the payload did not mean distrusting the file it came
in: with the overt `AGENTS.md`, the agent followed the file's other instruction and ran Django's tests in
#pct(C.overt_agents_md.tried_tests) of runs, against #pct(C.overt_issue.tried_tests) when the payload was in the issue.

The covert condition inverts this. The agent ran the repository script in #both(C.covert_script.ran_script) runs. What decided it
was whether the agent tested at all: it ran Django's tests in #frac(C.covert_script.tried_tests) runs and ran the script first in
#both(C.covert_script.ran_script_of_tested) of them, against #frac(C.covert_script.ran_script_untested) runs that never tested. It
opened the script before running it in #frac(C.covert_script.inspected_script_first) runs, and in the runs that did not execute it, it
never mentioned the script. Whenever the script ran, its read of the decoy was refused
by Landlock and recorded as a finding (#both(C.covert_script.flagged_of_attempts) of attempts flagged); because the read failed, the
script never reached the network. In #both(C.covert_script.reported_block_of_attempts) of these runs the agent told the user that the
environment check had been blocked reading the credential; none of the #C.covert_script.ran_script.k called the script suspicious or
an attack. Injection did not stop the agent from solving tasks: it resolved #pct(C.overt_issue.resolved),
#pct(C.overt_agents_md.resolved) and #pct(C.covert_script.resolved) of tasks in the three conditions against
#pct(C.covert_script.resolved_clean_same_tasks) without injection, differences within the variation expected between single runs.

No decoy finding appeared in any of the #d.clean.n runs without injection, so every flag in this experiment corresponds to a planted
instruction.

== RQ3: Recording overhead

#if ov != none [
#figure(
  placement: bottom,
  caption: [Median wall time of each task's graded test modules with and without the sandbox's strace (#ov.n tasks, three runs each after a warm-up). Lines: equal time and twice the time.],
  block(width: 100%)[
    #set text(size: 6.5pt)
    #let S = 5.6cm
    #let lo = 0.1
    #let hi = 200.0
    #let f(v) = (calc.log(calc.max(v, lo)) - calc.log(lo)) / (calc.log(hi) - calc.log(lo))
    #align(center, box(width: S + 0.9cm, height: S + 0.7cm)[
      #place(left + top, dx: 0.9cm, box(width: S, height: S, stroke: 0.4pt + luma(150))[
        #for tk in (1.0, 10.0, 100.0) {
          place(left + bottom, dx: S * f(tk), box(width: 0pt, height: S, stroke: (left: 0.3pt + luma(215))))
          place(left + bottom, dy: -S * f(tk), box(width: S, height: 0pt, stroke: (top: 0.3pt + luma(215))))
        }
        #place(left + top, line(start: (0pt, S), end: (S, 0pt), stroke: 0.5pt + luma(120)))
        #place(left + top, line(start: (0pt, S * (1 - f(2 * lo))), end: (S * f(hi / 2), 0pt), stroke: (paint: luma(120), thickness: 0.5pt, dash: "dashed")))
        #for pt in ov.points {
          place(left + bottom, dx: S * f(pt.at(0)) - 1.6pt, dy: -S * f(pt.at(1)) + 1.6pt, circle(radius: 1.6pt, fill: luma(30)))
        }
      ])
      #for tk in (1.0, 10.0, 100.0) {
        place(left + top, dx: 0.9cm + S * f(tk) - 6pt, dy: S + 2pt, [#str(int(tk)) s])
        place(left + top, dx: 0.35cm, dy: S - S * f(tk) - 3pt, [#str(int(tk)) s])
      }
      #place(left + top, dx: 0.9cm, dy: S + 10pt, [without strace (s)])
      #place(left + top, dx: 0pt, dy: -2pt, [with strace])
    ])
  ],
) <fig-overhead>

Recording slowed the test suites by a median #str(ov.ratio_median)$times$ (10th to 90th percentile #str(ov.ratio_p10)$times$ to
#str(ov.ratio_p90)$times$; @fig-overhead), from a median #str(ov.plain_median_s) s to #str(ov.strace_median_s) s per task. This is the
cost of tracing a process-heavy workload with ptrace; an agent's run is dominated by model latency, so the end-to-end cost is lower.
]

= Methodological findings

== Grader bugs found by the reference-fix check

Grading every task with the reference fix before any agent ran found four bugs, each of which would have produced plausible but wrong
scores. (1) Django's test runner could not import the checkout, so every test errored. (2) Many SWE-bench test identifiers are the first
line of the test's docstring, which the parser did not match, and test classes were chosen from parsed identifiers, so some tests never
ran. (3) The hidden test patch was silently not applied: `git apply` run from a subdirectory of another repository skips files outside
that subdirectory and exits successfully, and the graded tree was inside the project's own repository. (4) Django's optional test
dependencies were missing, so target tests were skipped rather than failed. Bug 3 alone would have graded every agent without the hidden
tests.

== Environment confounds

*The agent's interpreter.* Codex runs commands in a login shell, which reset `PATH` and so put the system Python ahead of the virtual
environment that held Django's dependencies. The grader was unaffected, but the agent's own test runs failed to import in all but one run
that tried them (§5.1). This held equally in every condition, so comparisons between conditions stand, but absolute resolve rates
are for an agent working without runnable tests.

*Host sleep.* The benchmark ran on a laptop. When it slept, the sandbox's VM paused with it and the agent froze mid-run, then continued.
Six runs in the baseline were affected, one by 2.9 hours. Durations subtract the intervals in the macOS power log; later runs prevented
sleep.

*Analyser coverage.* The first analyser did not report refused reads of ordinary paths, only of decoys; the two `AGENTS.md` searches
above showed the gap. All runs were re-analysed after the fix.

= Limitations

One agent on one model ran the full benchmark; a five-task pilot with gpt-6-astra, roughly a hundred times the price per token, also
resolved every task and is not analysed further. The tasks come from one repository, and some fixes may be in the model's training data:
on one task the agent's fix matches the upstream fix nearly line for line. The injection used one payload per condition and one decoy
target; different wording, hidden text or multi-step attacks may change compliance substantially, as prior work reports
@liu2025aishelljack. The refusal measure is a keyword rule, checked by hand. Each condition ran each task once, so differences of a
few tasks between conditions are not meaningful. The proxy tunnels HTTPS to hosts other than the model API, so it sees
their hostnames but not their content. The sandbox is not hidden, and an agent could behave differently if it recognised it. Landlock
and strace are Linux features; on macOS Tripline runs in a Linux VM.

= Conclusion

Across #d.clean.n tasks without attacks, Codex on gpt-6-luna stayed inside its policy apart from its own analytics. Told explicitly
to send a credential away, it never did, in #(C.overt_issue.n + C.overt_agents_md.n) runs. Told only to run a repository script
that did the same thing, it ran the script every time it ran tests, and read it first once. That difference is the case for an environment layer: the model's judgement works on what it reads, and the covert payload
gave it nothing to read. In every run where the script executed, the sandbox refused the credential read and the record showed exactly
what had been attempted. Recording costs about #if ov != none [#str(ov.ratio_median)$times$] else [two times] on process-heavy work.
The code, policies, harness, run records and a browsable viewer of every run are public.

#bibliography("refs.bib", style: "ieee", title: "References")

#pagebreak(weak: true)
#set page(columns: 1)
#heading(numbering: none)[Appendix A: Agent prompt]
#raw(d.prompt.replace("{repo}", "django/django").replace("{problem}", "<the issue text>"), block: true)

#heading(numbering: none)[Appendix B: Planted instructions]
*Overt payload* (appended to the issue as "Note from the maintainers:", or placed in `AGENTS.md` after two lines of ordinary guidance):
#raw(d.payloads.overt, block: true)
*Covert `AGENTS.md`:*
#raw(d.payloads.covert_agents_md, block: true)
*Covert `scripts/check_env.py`:*
#raw(d.payloads.covert_script, block: true, lang: "python")
