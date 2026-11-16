// Package sandbox runs one agent session: it prepares a run directory, starts
// the egress proxy and the sandbox container with Docker, waits for the agent,
// then collects and analyses everything that happened.
package sandbox

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/omerfaizan10/tripline/internal/canary"
	"github.com/omerfaizan10/tripline/internal/events"
	"github.com/omerfaizan10/tripline/internal/policy"
	"github.com/omerfaizan10/tripline/internal/report"
)

const (
	sandboxWork = "/work"
	sandboxHome = "/home/agent"
	shimPath    = "/tripline/bin/tripline-shim"
)

// Options configure a run.
type Options struct {
	PolicyFile string
	TaskDir    string   // copied into the run's workspace ("" = empty workspace)
	Cmd        []string // agent command, run inside the sandbox
	Image      string
	RunsDir    string
	BinDir     string            // holds linux tripline-shim and tripline-proxy
	AgentDir   string            // mounted read-only at /tripline/agents ("" = none)
	Name       string            // label for the run
	AgentEnv   map[string]string // extra environment for the agent
	ModelKey   string            // real API key, given to the proxy only
	Upstream   string            // model API base URL
	Memory     string
	CPUs       string
	Timeout    time.Duration
	Stdout     io.Writer
	Stderr     io.Writer
	Ask        func(host string, port int) bool // ask mode prompt; nil = deny
}

// Meta is saved as run.json.
type Meta struct {
	ID        string      `json:"id"`
	Name      string      `json:"name,omitempty"`
	Cmd       []string    `json:"cmd"`
	Policy    string      `json:"policy"`
	Mode      policy.Mode `json:"mode"`
	Image     string      `json:"image"`
	Start     float64     `json:"start"`
	End       float64     `json:"end"`
	ExitCode  int         `json:"exit_code"`
	TimedOut  bool        `json:"timed_out,omitempty"`
	Landlock  string      `json:"landlock"`
	ProxyIP   string      `json:"proxy_ip"`
	Changed   []string    `json:"changed_files"`
	Truncated bool        `json:"trace_missing,omitempty"`
}

// Run executes one session and returns the run directory and summary.
func Run(ctx context.Context, o Options) (string, *report.Summary, error) {
	if len(o.Cmd) == 0 {
		return "", nil, errors.New("no agent command")
	}
	if o.Stdout == nil {
		o.Stdout = os.Stdout
	}
	if o.Stderr == nil {
		o.Stderr = os.Stderr
	}
	pol, err := policy.Load(o.PolicyFile)
	if err != nil {
		return "", nil, err
	}
	exp := pol.Expand(sandboxWork, sandboxHome)
	if o.AgentDir != "" {
		// The agent's launch scripts must be readable inside the sandbox; the
		// grant is added to the run's policy so it shows up in policy.json.
		exp.Filesystem.Read = append(exp.Filesystem.Read, "/tripline/agents")
	}

	id := newID()
	dir, err := filepath.Abs(filepath.Join(o.RunsDir, id))
	if err != nil {
		return "", nil, err
	}
	for _, d := range []string{"out", "home", "work", "bin"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			return "", nil, err
		}
	}
	// The sandbox user (uid 1000) must own its workspace and home.
	if o.TaskDir != "" {
		if err := copyTree(o.TaskDir, filepath.Join(dir, "work")); err != nil {
			return dir, nil, fmt.Errorf("copy task: %w", err)
		}
		if err := baseline(dir); err != nil {
			return dir, nil, fmt.Errorf("baseline: %w", err)
		}
	}
	// Landlock can only grant paths that exist, so create the home folders
	// the policy makes writable (e.g. ~/.codex, ~/.cache) before the run.
	for _, w := range exp.Filesystem.Write {
		if rel, ok := strings.CutPrefix(w, sandboxHome+"/"); ok {
			if err := os.MkdirAll(filepath.Join(dir, "home", rel), 0o755); err != nil {
				return dir, nil, err
			}
		}
	}
	set, err := canary.Plant(filepath.Join(dir, "home"), sandboxHome)
	if err != nil {
		return dir, nil, err
	}
	if err := writeJSON(filepath.Join(dir, "decoys.json"), set.Tokens()); err != nil {
		return dir, nil, err
	}
	if err := writeJSON(filepath.Join(dir, "decoys-detail.json"), set); err != nil {
		return dir, nil, err
	}
	if err := writeJSON(filepath.Join(dir, "policy.json"), exp); err != nil {
		return dir, nil, err
	}
	for _, b := range []string{"tripline-shim", "tripline-proxy"} {
		if err := copyFile(filepath.Join(o.BinDir, b), filepath.Join(dir, "bin", b), 0o755); err != nil {
			return dir, nil, fmt.Errorf("missing %s in %s (run make linux): %w", b, o.BinDir, err)
		}
	}

	meta := Meta{ID: id, Name: o.Name, Cmd: o.Cmd, Policy: o.PolicyFile, Mode: pol.Mode, Image: o.Image}
	net := "tripline-" + id
	proxyName := "tripline-proxy-" + id
	agentName := "tripline-agent-" + id
	cleanup := func() {
		_ = docker(context.Background(), nil, "stop", "-t", "5", proxyName)
		_ = docker(context.Background(), nil, "rm", "-f", agentName, proxyName)
		_ = docker(context.Background(), nil, "network", "rm", net)
	}
	defer cleanup()

	if err := docker(ctx, nil, "network", "create", "--internal", net); err != nil {
		return dir, nil, err
	}
	proxyArgs := []string{"run", "-d", "--name", proxyName, "--network", "bridge",
		"-p", "127.0.0.1::8090",
		"-v", dir + ":/tripline:ro", "-v", filepath.Join(dir, "out") + ":/tripline/out",
		"-e", "TRIPLINE_MODEL_UPSTREAM=" + o.Upstream,
		"--entrypoint", "/tripline/bin/tripline-proxy"}
	if o.ModelKey != "" {
		// Passed by name so the value never appears in a process listing.
		proxyArgs = append(proxyArgs, "-e", "OPENAI_API_KEY")
	}
	proxyArgs = append(proxyArgs, o.Image)
	env := os.Environ()
	if o.ModelKey != "" {
		env = append(env, "OPENAI_API_KEY="+o.ModelKey)
	}
	if err := dockerEnv(ctx, env, nil, proxyArgs...); err != nil {
		return dir, nil, fmt.Errorf("start proxy: %w", err)
	}
	if err := docker(ctx, nil, "network", "connect", "--alias", "tripline-proxy", net, proxyName); err != nil {
		return dir, nil, err
	}
	meta.ProxyIP = strings.TrimSpace(dockerOut(ctx, "inspect", "-f", "{{(index .NetworkSettings.Networks \""+net+"\").IPAddress}}", proxyName))
	ctl := strings.TrimSpace(dockerOut(ctx, "port", proxyName, "8090/tcp"))
	if i := strings.IndexByte(ctl, '\n'); i > 0 {
		ctl = ctl[:i]
	}
	if err := waitHealthy("http://"+ctl+"/healthz", 15*time.Second); err != nil {
		logs := dockerOut(context.Background(), "logs", proxyName)
		return dir, nil, fmt.Errorf("proxy did not start: %v\n%s", err, logs)
	}

	agentArgs := []string{"run", "--name", agentName, "--network", net, "--init",
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--pids-limit", "1024", "--memory", o.Memory, "--cpus", o.CPUs,
		"-v", filepath.Join(dir, "work") + ":" + sandboxWork,
		"-v", filepath.Join(dir, "home") + ":" + sandboxHome,
		"-v", filepath.Join(dir, "out") + ":/tripline/out",
		"-v", filepath.Join(dir, "bin") + ":/tripline/bin:ro",
		"-v", filepath.Join(dir, "policy.json") + ":/tripline/policy.json:ro",
		"-e", "HTTPS_PROXY=http://tripline-proxy:3128", "-e", "HTTP_PROXY=http://tripline-proxy:3128",
		"-e", "https_proxy=http://tripline-proxy:3128", "-e", "http_proxy=http://tripline-proxy:3128",
		"-e", "NO_PROXY=tripline-proxy", "-e", "no_proxy=tripline-proxy",
		"-e", "OPENAI_BASE_URL=http://tripline-proxy:8081/v1",
		// Agents insist on a key being set; the gateway replaces it.
		"-e", "OPENAI_API_KEY=sk-tripline-sandbox-placeholder",
		"-e", "HOME=" + sandboxHome,
		"-w", sandboxWork,
	}
	if o.AgentDir != "" {
		abs, err := filepath.Abs(o.AgentDir)
		if err != nil {
			return dir, nil, err
		}
		agentArgs = append(agentArgs, "-v", abs+":/tripline/agents:ro")
	}
	for k, v := range o.AgentEnv {
		agentArgs = append(agentArgs, "-e", k+"="+v)
	}
	agentArgs = append(agentArgs, "--entrypoint", shimPath, o.Image, "run", "--policy", "/tripline/policy.json", "--")
	agentArgs = append(agentArgs, o.Cmd...)

	runCtx := ctx
	var cancel context.CancelFunc
	if o.Timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, o.Timeout)
		defer cancel()
	}
	stopAsk := make(chan struct{})
	if pol.Mode == policy.Ask {
		go askLoop("http://"+ctl, o.Ask, stopAsk)
	}
	meta.Start = now()
	runErr := docker(runCtx, &stdio{o.Stdout, o.Stderr}, agentArgs...)
	meta.End = now()
	close(stopAsk)
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		meta.TimedOut = true
		_ = docker(context.Background(), nil, "kill", agentName)
	}
	meta.ExitCode = exitCode(runErr)
	// Stop the proxy gracefully so its last events are flushed.
	_ = docker(context.Background(), nil, "stop", "-t", "5", proxyName)

	sum, err := Collect(dir, &meta)
	return dir, sum, err
}

// Collect parses and analyses a finished run directory, writing events.jsonl,
// summary.json and run.json. It can be re-run on an old run.
func Collect(dir string, meta *Meta) (*report.Summary, error) {
	if meta == nil {
		meta = &Meta{}
		if b, err := os.ReadFile(filepath.Join(dir, "run.json")); err == nil {
			_ = json.Unmarshal(b, meta)
		}
	}
	var res struct {
		Start    float64 `json:"start"`
		End      float64 `json:"end"`
		ExitCode int     `json:"exit_code"`
		Landlock string  `json:"landlock"`
	}
	if b, err := os.ReadFile(filepath.Join(dir, "out", "result.json")); err == nil {
		_ = json.Unmarshal(b, &res)
		meta.Landlock = strings.TrimSpace(res.Landlock)
		if meta.Start == 0 {
			meta.Start, meta.End, meta.ExitCode = res.Start, res.End, res.ExitCode
		}
	}
	var evs []events.Event
	if f, err := os.Open(filepath.Join(dir, "out", "trace.log")); err == nil {
		tr, perr := events.ParseStrace(f, sandboxWork)
		f.Close()
		if perr != nil {
			return nil, perr
		}
		evs = append(evs, tr...)
	} else {
		meta.Truncated = true
	}
	px, err := events.ReadFile(filepath.Join(dir, "out", "proxy.jsonl"))
	if err != nil {
		return nil, err
	}
	evs = append(evs, px...)

	var pol policy.Policy
	if b, err := os.ReadFile(filepath.Join(dir, "policy.json")); err == nil {
		_ = json.Unmarshal(b, &pol)
	}
	var set canary.Set
	if b, err := os.ReadFile(filepath.Join(dir, "decoys-detail.json")); err == nil {
		_ = json.Unmarshal(b, &set)
	}
	flagged, sum := report.Analyze(report.Input{
		Events: evs, Policy: &pol, Decoys: &set, Workspace: sandboxWork,
		HostWork: filepath.Join(dir, "work"), ProxyAddrs: []string{meta.ProxyIP},
		SelfExe: shimPath, ExitCode: meta.ExitCode, Start: meta.Start, End: meta.End,
	})
	meta.Changed = changedFiles(dir)
	f, err := os.Create(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		return nil, err
	}
	if err := events.WriteJSONL(f, flagged); err != nil {
		f.Close()
		return nil, err
	}
	f.Close()
	if err := writeJSON(filepath.Join(dir, "summary.json"), sum); err != nil {
		return nil, err
	}
	if err := writeJSON(filepath.Join(dir, "run.json"), meta); err != nil {
		return nil, err
	}
	if d := gitDiff(dir); d != "" {
		_ = os.WriteFile(filepath.Join(dir, "changes.diff"), []byte(d), 0o644)
	}
	return &sum, nil
}

// ---------- ask mode ----------

func askLoop(base string, ask func(string, int) bool, stop <-chan struct{}) {
	seen := map[string]bool{}
	t := time.NewTicker(300 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		resp, err := http.Get(base + "/pending")
		if err != nil {
			continue
		}
		var holds []struct {
			ID   string `json:"id"`
			Host string `json:"host"`
			Port int    `json:"port"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&holds)
		resp.Body.Close()
		for _, h := range holds {
			if seen[h.ID] {
				continue
			}
			seen[h.ID] = true
			allow := ask != nil && ask(h.Host, h.Port)
			body := fmt.Sprintf(`{"id":%q,"allow":%t}`, h.ID, allow)
			if r, err := http.Post(base+"/decide", "application/json", strings.NewReader(body)); err == nil {
				r.Body.Close()
			}
		}
	}
}

// ---------- docker helpers ----------

type stdio struct{ out, err io.Writer }

func docker(ctx context.Context, s *stdio, args ...string) error {
	return dockerEnv(ctx, nil, s, args...)
}

func dockerEnv(ctx context.Context, env []string, s *stdio, args ...string) error {
	c := exec.CommandContext(ctx, "docker", args...)
	if env != nil {
		c.Env = env
	}
	var errBuf strings.Builder
	if s != nil {
		c.Stdout, c.Stderr = s.out, s.err
	} else {
		c.Stderr = &errBuf
	}
	if err := c.Run(); err != nil {
		if errBuf.Len() > 0 {
			return fmt.Errorf("docker %s: %w: %s", args[0], err, strings.TrimSpace(errBuf.String()))
		}
		return err
	}
	return nil
}

func dockerOut(ctx context.Context, args ...string) string {
	b, _ := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	return string(b)
}

// DockerArch returns the VM architecture as Go names it (arm64, amd64).
func DockerArch(ctx context.Context) string {
	a := strings.TrimSpace(dockerOut(ctx, "info", "-f", "{{.Architecture}}"))
	switch a {
	case "aarch64", "arm64":
		return "arm64"
	case "x86_64", "amd64":
		return "amd64"
	}
	return runtime.GOARCH
}

func waitHealthy(url string, d time.Duration) error {
	deadline := time.Now().Add(d)
	for {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return nil
			}
		}
		if time.Now().After(deadline) {
			if err == nil {
				err = errors.New("unhealthy")
			}
			return err
		}
		time.Sleep(150 * time.Millisecond)
	}
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

// ---------- files ----------

func newID() string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return time.Now().UTC().Format("20060102-150405") + "-" + hex.EncodeToString(b)
}

func now() float64 { return float64(time.Now().UnixMicro()) / 1e6 }

func writeJSON(file string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(file, b, 0o644)
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			return os.MkdirAll(target, 0o755)
		case info.Mode()&fs.ModeSymlink != 0:
			link, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		default:
			return copyFile(p, target, info.Mode().Perm())
		}
	})
}

// baseline snapshots a task that is not a git repo, so the run can still
// record what the agent changed. The repo lives in <run>/base.git, outside
// every directory mounted into the agent's container.
func baseline(dir string) error {
	work := filepath.Join(dir, "work")
	if _, err := os.Stat(filepath.Join(work, ".git")); err == nil {
		return nil // the task's own history is the baseline
	}
	g := gitIn(dir)
	for _, args := range [][]string{
		{"init", "-q"},
		{"add", "-A"},
		{"-c", "user.name=tripline", "-c", "user.email=tripline@example.invalid", "commit", "-q", "--allow-empty", "-m", "base"},
	} {
		if out, err := exec.Command("git", append(g, args...)...).CombinedOutput(); err != nil {
			return fmt.Errorf("git %s: %v: %s", args[len(args)-1], err, out)
		}
	}
	return nil
}

// gitIn returns the git arguments that address the workspace: its own repo
// if the task had one, else the baseline in <run>/base.git.
func gitIn(dir string) []string {
	work := filepath.Join(dir, "work")
	if _, err := os.Stat(filepath.Join(work, ".git")); err == nil {
		return []string{"-C", work}
	}
	return []string{"--git-dir", filepath.Join(dir, "base.git"), "--work-tree", work}
}

func hasBaseline(dir string) bool {
	for _, p := range []string{filepath.Join(dir, "work", ".git"), filepath.Join(dir, "base.git")} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

func gitDiff(dir string) string {
	if !hasBaseline(dir) {
		return ""
	}
	g := gitIn(dir)
	b, _ := exec.Command("git", append(g, "-c", "core.fileMode=false", "diff", "--no-color")...).Output()
	ub, _ := exec.Command("git", append(g, "ls-files", "--others", "--exclude-standard")...).Output()
	out := string(b)
	if s := strings.TrimSpace(string(ub)); s != "" {
		out += "\n# untracked files\n" + s + "\n"
	}
	return out
}

func changedFiles(dir string) []string {
	if !hasBaseline(dir) {
		return nil
	}
	b, _ := exec.Command("git", append(gitIn(dir), "-c", "core.fileMode=false", "status", "--porcelain")...).Output()
	var out []string
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		if line := sc.Text(); len(line) > 3 {
			out = append(out, strings.TrimSpace(line[3:]))
		}
	}
	return out
}
