// blast runs coding agents inside a recorded, policy-enforced sandbox.
//
//	blast run [flags] -- <agent command>   run one session
//	blast report <run-dir>                 re-analyse and print a past run
//	blast runs                             list past runs
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/omerfaizan10/blast-radius/internal/canary"
	"github.com/omerfaizan10/blast-radius/internal/events"
	"github.com/omerfaizan10/blast-radius/internal/policy"
	"github.com/omerfaizan10/blast-radius/internal/report"
	"github.com/omerfaizan10/blast-radius/internal/sandbox"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = cmdRun(os.Args[2:])
	case "report":
		err = cmdReport(os.Args[2:])
	case "runs":
		err = cmdRuns(os.Args[2:])
	case "policy":
		err = cmdPolicy(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "blast:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `blast: run coding agents in a recorded, policy-enforced sandbox

  blast run [flags] -- <agent command>   run one session
  blast report <run-dir>                 re-analyse and print a past run
  blast runs                             list past runs
  blast policy synth <run-dir>...        write the tightest policy those runs needed

run flags:
`)
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	pol := fs.String("policy", "policies/default.yaml", "policy file")
	task := fs.String("task", "", "directory copied into the sandbox workspace")
	name := fs.String("name", "", "label for this run")
	image := fs.String("image", "blast-sandbox:dev", "sandbox image")
	runs := fs.String("runs", ".runs", "where run directories are written")
	bin := fs.String("bin", "", "directory with linux blast-shim and blast-proxy (default bin/linux-<arch>)")
	agents := fs.String("agents", "agents", "directory mounted read-only at /blast/agents (\"\" for none)")
	mem := fs.String("memory", "4g", "sandbox memory limit")
	cpus := fs.String("cpus", "2", "sandbox CPU limit")
	timeout := fs.Duration("timeout", 30*time.Minute, "kill the agent after this long")
	upstream := fs.String("model-upstream", "https://api.openai.com", "model API the gateway forwards to")
	var envs multi
	fs.Var(&envs, "env", "extra KEY=VALUE for the agent (repeatable)")
	fs.Usage = func() { usage(); fs.PrintDefaults() }

	dash := indexOf(args, "--")
	if dash < 0 {
		fs.Usage()
		return fmt.Errorf("missing -- before the agent command")
	}
	if err := fs.Parse(args[:dash]); err != nil {
		return err
	}
	cmd := args[dash+1:]

	// SIGTERM too: stopping a background job sends it, and the containers and
	// network are only removed if the run unwinds normally.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *bin == "" {
		*bin = filepath.Join("bin", "linux-"+sandbox.DockerArch(ctx))
	}
	loadDotEnv(".env")
	agentEnv := map[string]string{}
	for _, kv := range envs {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return fmt.Errorf("--env %q is not KEY=VALUE", kv)
		}
		agentEnv[k] = v
	}
	dir, sum, err := sandbox.Run(ctx, sandbox.Options{
		PolicyFile: *pol, TaskDir: *task, Cmd: cmd, Image: *image, RunsDir: *runs, BinDir: *bin, AgentDir: *agents,
		Name: *name, AgentEnv: agentEnv, ModelKey: os.Getenv("OPENAI_API_KEY"), Upstream: *upstream,
		Memory: *mem, CPUs: *cpus, Timeout: *timeout, Ask: askTTY,
	})
	if err != nil {
		if dir != "" {
			fmt.Fprintln(os.Stderr, "run directory:", dir)
		}
		return err
	}
	printSummary(dir, sum)
	return nil
}

func cmdReport(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: blast report <run-dir>")
	}
	sum, err := sandbox.Collect(args[0], nil)
	if err != nil {
		return err
	}
	printSummary(args[0], sum)
	return nil
}

func cmdRuns(args []string) error {
	root := ".runs"
	if len(args) > 0 {
		root = args[0]
	}
	ents, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	sort.Slice(ents, func(i, j int) bool { return ents[i].Name() > ents[j].Name() })
	for _, e := range ents {
		var m sandbox.Meta
		b, err := os.ReadFile(filepath.Join(root, e.Name(), "run.json"))
		if err != nil || json.Unmarshal(b, &m) != nil {
			continue
		}
		var s report.Summary
		if b, err := os.ReadFile(filepath.Join(root, e.Name(), "summary.json")); err == nil {
			_ = json.Unmarshal(b, &s)
		}
		fmt.Printf("%s  %-8s exit=%-3d high=%-2d medium=%-2d  %s\n", m.ID, m.Mode, m.ExitCode, s.BySeverity["high"], s.BySeverity["medium"], strings.Join(m.Cmd, " "))
	}
	return nil
}

// ---------- output ----------

func printSummary(dir string, s *report.Summary) {
	w := os.Stdout
	fmt.Fprintf(w, "\n── blast radius ─────────────────────────────────────\n")
	fmt.Fprintf(w, "run        %s\n", dir)
	fmt.Fprintf(w, "mode       %s   exit %d   %.1fs   %d events\n", s.Mode, s.ExitCode, s.DurationSec, s.Events)
	fmt.Fprintf(w, "files      %d read, %d written\n", s.FilesRead, s.FilesWritten)
	fmt.Fprintf(w, "programs   %s\n", strings.Join(limit(s.Programs, 12), ", "))
	if len(s.Hosts) > 0 {
		var hs []string
		for _, h := range s.Hosts {
			tag := ""
			if h.Model {
				tag = " (model)"
			}
			hs = append(hs, fmt.Sprintf("%s%s %d ok/%d denied/%d failed", h.Host, tag, h.Allowed, h.Denied, h.Failed))
		}
		fmt.Fprintf(w, "network    %s\n", strings.Join(hs, "; "))
	}
	if s.ModelRequests > 0 {
		fmt.Fprintf(w, "model      %d requests, %d tokens in (%d cached), %d out (%s), $%.4f\n", s.ModelRequests, s.TokensIn, s.TokensCached, s.TokensOut, strings.Join(s.Models, ", "), s.CostUSD)
	}
	fmt.Fprintf(w, "denied     %d actions blocked\n", s.Denied)
	if len(s.BlastRadius) == 0 {
		fmt.Fprintf(w, "radius     nothing outside the workspace\n")
	} else {
		var rs []string
		for _, r := range s.BlastRadius {
			tag := ""
			if r.Decoy {
				tag = " DECOY"
			}
			rs = append(rs, fmt.Sprintf("%s (%d files, %d writes%s)", r.Root, r.Files, r.Writes, tag))
		}
		fmt.Fprintf(w, "radius     %s\n", strings.Join(limit(rs, 6), "; "))
	}
	if len(s.Findings) == 0 {
		fmt.Fprintf(w, "findings   none\n")
	} else {
		fmt.Fprintf(w, "findings\n")
		for _, f := range s.Findings {
			n := ""
			if f.Count > 1 {
				n = fmt.Sprintf(" ×%d", f.Count)
			}
			fmt.Fprintf(w, "  %-6s %s%s\n         %s\n", strings.ToUpper(string(f.Severity)), f.Title, n, f.Detail)
		}
	}
	fmt.Fprintln(w, "─────────────────────────────────────────────────────")
}

func limit(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	return append(append([]string{}, in[:n]...), fmt.Sprintf("+%d more", len(in)-n))
}

// askTTY prompts on the terminal in ask mode.
func askTTY(host string, port int) bool {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return false
	}
	defer tty.Close()
	fmt.Fprintf(tty, "\n[blast] the agent wants to reach %s:%d. Allow? [y/N] ", host, port)
	line, _ := bufio.NewReader(tty).ReadString('\n')
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "y")
}

// ---------- helpers ----------

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func indexOf(a []string, s string) int {
	for i, x := range a {
		if x == s {
			return i
		}
	}
	return -1
}

// loadDotEnv sets variables from a KEY=VALUE file without overriding ones
// already in the environment. Values are never printed.
func loadDotEnv(file string) {
	f, err := os.Open(file)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.Trim(strings.TrimSpace(v), `"'`)
		if os.Getenv(k) == "" {
			os.Setenv(k, v)
		}
	}
}

// ---------- policy synthesis ----------

func cmdPolicy(args []string) error {
	if len(args) < 1 || args[0] != "synth" {
		return fmt.Errorf("usage: blast policy synth [-o file] [-name n] <run-dir>...")
	}
	fs := flag.NewFlagSet("policy synth", flag.ExitOnError)
	out := fs.String("o", "", "write the policy here instead of stdout")
	name := fs.String("name", "synthesised", "policy name")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	dirs := fs.Args()
	if len(dirs) == 0 {
		return fmt.Errorf("give at least one run directory")
	}
	var in policy.SynthInput
	in.Workspace, in.Home, in.Name = "/work", "/home/agent", *name
	for _, d := range dirs {
		var m sandbox.Meta
		if b, err := os.ReadFile(filepath.Join(d, "run.json")); err == nil {
			_ = json.Unmarshal(b, &m)
		}
		if m.ExitCode != 0 {
			fmt.Fprintf(os.Stderr, "blast: warning: %s exited %d; its accesses are still used\n", d, m.ExitCode)
		}
		var set canary.Set
		if b, err := os.ReadFile(filepath.Join(d, "decoys-detail.json")); err == nil {
			_ = json.Unmarshal(b, &set)
		}
		for _, dc := range set.Decoys {
			in.Exclude = append(in.Exclude, dc.Path)
		}
		evs, err := events.ReadFile(filepath.Join(d, "events.jsonl"))
		if err != nil {
			return err
		}
		if len(evs) == 0 {
			return fmt.Errorf("%s has no events.jsonl (run blast report on it first)", d)
		}
		for _, e := range evs {
			if e.Result != events.OK {
				continue
			}
			switch e.Op {
			case events.OpRead:
				in.Accesses = append(in.Accesses, policy.Access{Path: e.Path})
			case events.OpExec:
				in.Accesses = append(in.Accesses, policy.Access{Path: e.Path})
			case events.OpWrite, events.OpDelete, events.OpMkdir:
				in.Accesses = append(in.Accesses, policy.Access{Path: e.Path, Write: true})
			case events.OpRename:
				in.Accesses = append(in.Accesses, policy.Access{Path: e.Path, Write: true}, policy.Access{Path: e.Path2, Write: true})
			case events.OpHTTP:
				if !e.HasFlag(events.FlagModel) && e.Host != "" {
					in.Accesses = append(in.Accesses, policy.Access{Host: e.Host})
				}
			}
		}
	}
	res := policy.Synthesize(in)
	y, err := res.Policy.Marshal()
	if err != nil {
		return err
	}
	text := res.Header(len(dirs)) + string(y)
	if *out == "" {
		fmt.Print(text)
		return nil
	}
	return os.WriteFile(*out, []byte(text), 0o644)
}
