//go:build linux

// tripline-shim runs inside the sandbox container. It has two stages:
//
//	tripline-shim run     --policy P -- cmd...   (outer, unrestricted)
//	tripline-shim confine --policy P -- cmd...   (inner, applies Landlock, then execs)
//
// "run" starts strace, which then runs "confine". The tracer is therefore
// outside the Landlock domain and writes its log to a directory the agent is
// not allowed to touch, so an agent cannot read or rewrite its own record.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/landlock-lsm/go-landlock/landlock"

	"github.com/omerfaizan10/tripline/internal/events"
	"github.com/omerfaizan10/tripline/internal/policy"
)

const (
	outDir   = "/tripline/out"
	selfPath = "/tripline/bin/tripline-shim"
)

func main() {
	if len(os.Args) < 2 {
		fatal("usage: tripline-shim run|confine --policy FILE -- cmd...")
	}
	pol, cmd, err := parseArgs(os.Args[2:])
	if err != nil {
		fatal(err.Error())
	}
	switch os.Args[1] {
	case "run":
		os.Exit(run(pol, cmd))
	case "confine":
		confine(pol, cmd)
	default:
		fatal("unknown stage " + os.Args[1])
	}
}

func parseArgs(a []string) (string, []string, error) {
	if len(a) < 4 || a[0] != "--policy" || a[2] != "--" {
		return "", nil, errors.New("usage: tripline-shim run|confine --policy FILE -- cmd...")
	}
	return a[1], a[3:], nil
}

// Result is what "run" leaves behind for the host.
type Result struct {
	Start    float64 `json:"start"`
	End      float64 `json:"end"`
	ExitCode int     `json:"exit_code"`
	Landlock string  `json:"landlock"` // what the kernel granted, from confine
}

func run(pol string, cmd []string) int {
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		fatal(err.Error())
	}
	args := append(append([]string{}, events.StraceArgs...), "-o", outDir+"/trace.log", "--", selfPath, "confine", "--policy", pol, "--")
	args = append(args, cmd...)
	c := exec.Command("strace", args...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	res := Result{Start: now()}
	err := c.Run()
	res.End = now()
	res.ExitCode = exitCode(err)
	if b, e := os.ReadFile(outDir + "/landlock.txt"); e == nil {
		res.Landlock = string(b)
	}
	b, _ := json.MarshalIndent(res, "", "  ")
	_ = os.WriteFile(outDir+"/result.json", b, 0o600)
	return res.ExitCode
}

func confine(polFile string, cmd []string) {
	b, err := os.ReadFile(polFile)
	if err != nil {
		fatal(err.Error())
	}
	var p policy.Policy
	if err := json.Unmarshal(b, &p); err != nil {
		fatal("policy: " + err.Error())
	}
	status := "not applied (audit mode)"
	if p.Mode != policy.Audit {
		status, err = applyLandlock(&p)
		if err != nil {
			fatal("landlock: " + err.Error())
		}
	}
	if p.Mode == policy.Audit {
		_ = os.WriteFile(outDir+"/landlock.txt", []byte(status), 0o600)
	}
	bin, err := exec.LookPath(cmd[0])
	if err != nil {
		fatal(err.Error())
	}
	if err := syscall.Exec(bin, cmd, os.Environ()); err != nil {
		fatal(err.Error())
	}
}

// applyLandlock turns the expanded policy into kernel rules. Missing paths are
// skipped because Landlock refuses rules for paths that do not exist.
func applyLandlock(p *policy.Policy) (string, error) {
	var rules []landlock.Rule
	var ro, rw, skipped int
	for _, path := range p.Filesystem.Write {
		st, err := os.Stat(path)
		if err != nil {
			skipped++
			continue
		}
		if st.IsDir() {
			rules = append(rules, landlock.RWDirs(path))
		} else {
			rules = append(rules, landlock.RWFiles(path))
		}
		rw++
	}
	for _, path := range p.Filesystem.Read {
		if p.AllowsWrite(path) {
			continue // already covered read-write
		}
		st, err := os.Stat(path)
		if err != nil {
			skipped++
			continue
		}
		if st.IsDir() {
			rules = append(rules, landlock.RODirs(path))
		} else {
			rules = append(rules, landlock.ROFiles(path))
		}
		ro++
	}
	// Only the proxy ports may be dialled; the private network has no other
	// way out anyway, this is a second, kernel-level layer.
	rules = append(rules, landlock.ConnectTCP(3128), landlock.ConnectTCP(8081))
	summary := fmt.Sprintf("applied (%d read-only, %d read-write, %d missing skipped, TCP connect limited to proxy ports)", ro, rw, skipped)
	// The log directory is outside the agent's rules, so record the summary
	// now: after Restrict this process can no longer write there.
	_ = os.WriteFile(outDir+"/landlock.txt", []byte(summary), 0o600)
	if err := landlock.V11.BestEffort().Restrict(rules...); err != nil {
		_ = os.WriteFile(outDir+"/landlock.txt", []byte("failed: "+err.Error()), 0o600)
		return "", err
	}
	return summary, nil
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return 127
}

func now() float64 { return float64(time.Now().UnixMicro()) / 1e6 }

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "tripline-shim:", msg)
	os.Exit(126)
}
