// Package events is the common record of what happened in a sandbox run.
// Every source (syscall trace, egress proxy, policy checks, decoy secrets)
// produces Events; a run's timeline is all of them merged by time.
package events

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"sort"
)

// Source says which part of the sandbox observed an event.
type Source string

const (
	SrcTrace  Source = "trace"  // syscall trace inside the sandbox
	SrcProxy  Source = "proxy"  // egress proxy
	SrcPolicy Source = "policy" // policy evaluation after the run
	SrcRun    Source = "run"    // run lifecycle (start, exit)
)

// Op is what the agent tried to do.
type Op string

const (
	OpRead    Op = "read"
	OpWrite   Op = "write"
	OpDelete  Op = "delete"
	OpRename  Op = "rename"
	OpMkdir   Op = "mkdir"
	OpExec    Op = "exec"
	OpConnect Op = "connect" // raw socket connect seen in the trace
	OpHTTP    Op = "http"    // request through the egress proxy
	OpStart   Op = "start"
	OpExit    Op = "exit"
)

// Result is the outcome as observed.
type Result string

const (
	OK      Result = "ok"
	Denied  Result = "denied"  // blocked by Landlock, the network or the proxy
	Failed  Result = "failed"  // failed for an ordinary reason (e.g. file not found)
	Pending Result = "pending" // waiting for a human decision (ask mode)
)

// Flag marks an event as notable in a report.
type Flag string

const (
	FlagCanary        Flag = "canary"          // touched a decoy secret
	FlagOutsidePolicy Flag = "outside_policy"  // the policy did not allow this
	FlagExecFlagged   Flag = "exec_flagged"    // ran a program the policy flags
	FlagNewHost       Flag = "new_host"        // network host not on the allowlist
	FlagDirectNet     Flag = "direct_net"      // tried to bypass the proxy
	FlagExfilRisk     Flag = "exfil_risk"      // contacted the network after reading a decoy
	FlagSecretToModel Flag = "secret_to_model" // a decoy secret appeared in a model request
	FlagModel         Flag = "model"           // traffic to the model API through the gateway
)

// Event is one observed action.
type Event struct {
	T      float64  `json:"t"` // seconds since the Unix epoch
	Src    Source   `json:"src"`
	PID    int      `json:"pid,omitempty"`
	Op     Op       `json:"op"`
	Path   string   `json:"path,omitempty"`
	Path2  string   `json:"path2,omitempty"` // rename target
	Argv   []string `json:"argv,omitempty"`
	Host   string   `json:"host,omitempty"`
	Port   int      `json:"port,omitempty"`
	Method string   `json:"method,omitempty"`
	Result Result   `json:"result"`
	Errno  string   `json:"errno,omitempty"`
	Detail string   `json:"detail,omitempty"`
	Flags  []Flag   `json:"flags,omitempty"`

	// Model gateway accounting (OpHTTP events to the model API).
	Model        string `json:"model,omitempty"`
	TokensIn     int    `json:"tokens_in,omitempty"`
	TokensCached int    `json:"tokens_cached,omitempty"`
	TokensOut    int    `json:"tokens_out,omitempty"`
	BytesUp      int64  `json:"bytes_up,omitempty"`
	BytesDown    int64  `json:"bytes_down,omitempty"`
}

// HasFlag reports whether e carries f.
func (e *Event) HasFlag(f Flag) bool {
	for _, x := range e.Flags {
		if x == f {
			return true
		}
	}
	return false
}

// AddFlag adds f once.
func (e *Event) AddFlag(f Flag) {
	if !e.HasFlag(f) {
		e.Flags = append(e.Flags, f)
	}
}

// Sort orders events by time, keeping the original order for ties.
func Sort(evs []Event) {
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].T < evs[j].T })
}

// WriteJSONL writes one event per line.
func WriteJSONL(w io.Writer, evs []Event) error {
	enc := json.NewEncoder(w)
	for i := range evs {
		if err := enc.Encode(&evs[i]); err != nil {
			return err
		}
	}
	return nil
}

// ReadJSONL reads events written by WriteJSONL. Blank lines are skipped.
func ReadJSONL(r io.Reader) ([]Event, error) {
	var out []Event
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Event
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

// ReadFile reads a JSONL event file; a missing file yields no events.
func ReadFile(file string) ([]Event, error) {
	f, err := os.Open(file)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ReadJSONL(f)
}
