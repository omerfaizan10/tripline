// Package policy defines Blast Radius policies: what a coding agent may read,
// write and reach over the network, and how strictly that is applied.
//
// Policies are deny-by-default allowlists. In enforce and ask modes the file
// rules become Linux Landlock rules (applied by the kernel inside the sandbox)
// and the host rules are applied by the egress proxy, which is the sandbox's
// only route off its private network.
package policy

import (
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Mode controls what happens when the agent steps outside the policy.
type Mode string

const (
	// Audit records everything and blocks nothing.
	Audit Mode = "audit"
	// Enforce blocks anything outside the policy.
	Enforce Mode = "enforce"
	// Ask blocks file access outside the policy and pauses unknown network
	// hosts until a human approves or denies them.
	Ask Mode = "ask"
)

// Policy is the on-disk YAML document.
type Policy struct {
	Version    int        `yaml:"version" json:"version"`
	Name       string     `yaml:"name,omitempty" json:"name,omitempty"`
	Mode       Mode       `yaml:"mode" json:"mode"`
	Filesystem Filesystem `yaml:"filesystem" json:"filesystem"`
	Network    Network    `yaml:"network" json:"network"`
	Exec       Exec       `yaml:"exec,omitempty" json:"exec,omitempty"`
}

// Filesystem lists directories and files the agent may use. Entries may use
// ${WORKSPACE} and ${HOME}. A directory entry covers everything below it.
type Filesystem struct {
	Read  []string `yaml:"read" json:"read"`
	Write []string `yaml:"write" json:"write"`
}

// Network lists hosts the proxy lets through. "*.example.com" matches any
// subdomain (not example.com itself).
type Network struct {
	AllowHosts []string `yaml:"allow_hosts" json:"allow_hosts"`
}

// Exec lists programs that are flagged when run. Landlock cannot forbid one
// binary inside an allowed directory, so these are reported, not blocked.
type Exec struct {
	Flag []string `yaml:"flag,omitempty" json:"flag,omitempty"`
}

// Load reads and validates a policy file.
func Load(file string) (*Policy, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse decodes and validates YAML. Unknown keys are rejected so a typo cannot
// silently weaken a policy.
func Parse(b []byte) (*Policy, error) {
	var p Policy
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Validate checks the policy is well formed.
func (p *Policy) Validate() error {
	var errs []error
	if p.Version != 1 {
		errs = append(errs, fmt.Errorf("policy: version must be 1, got %d", p.Version))
	}
	switch p.Mode {
	case Audit, Enforce, Ask:
	default:
		errs = append(errs, fmt.Errorf("policy: mode must be audit, enforce or ask, got %q", p.Mode))
	}
	for _, e := range append(append([]string{}, p.Filesystem.Read...), p.Filesystem.Write...) {
		if e == "" {
			errs = append(errs, errors.New("policy: empty filesystem entry"))
			continue
		}
		if !strings.HasPrefix(e, "/") && !strings.HasPrefix(e, "${") {
			errs = append(errs, fmt.Errorf("policy: filesystem entry %q must be absolute or start with ${WORKSPACE} or ${HOME}", e))
		}
	}
	for _, h := range p.Network.AllowHosts {
		if err := validHostPattern(h); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func validHostPattern(h string) error {
	if h == "" {
		return errors.New("policy: empty host")
	}
	rest := strings.TrimPrefix(h, "*.")
	if strings.ContainsAny(rest, "*/:@ ") || rest == "" {
		return fmt.Errorf("policy: host %q must be a hostname or *.domain", h)
	}
	return nil
}

// Expand returns a copy with ${WORKSPACE} and ${HOME} substituted and paths
// cleaned, so rules can be compared with what the agent actually touched.
func (p *Policy) Expand(workspace, home string) *Policy {
	sub := func(in []string) []string {
		out := make([]string, 0, len(in))
		for _, e := range in {
			e = strings.ReplaceAll(e, "${WORKSPACE}", workspace)
			e = strings.ReplaceAll(e, "${HOME}", home)
			out = append(out, path.Clean(e))
		}
		return dedupe(out)
	}
	c := *p
	c.Filesystem.Read = sub(p.Filesystem.Read)
	c.Filesystem.Write = sub(p.Filesystem.Write)
	c.Network.AllowHosts = dedupe(lower(p.Network.AllowHosts))
	return &c
}

// AllowsHost reports whether the proxy should let a connection to host through.
func (p *Policy) AllowsHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, pat := range p.Network.AllowHosts {
		if pat == host {
			return true
		}
		if strings.HasPrefix(pat, "*.") && strings.HasSuffix(host, pat[1:]) {
			return true
		}
	}
	return false
}

// AllowsRead reports whether an expanded policy permits reading path.
// Writable paths are readable too.
func (p *Policy) AllowsRead(file string) bool {
	return covered(file, p.Filesystem.Read) || covered(file, p.Filesystem.Write)
}

// AllowsWrite reports whether an expanded policy permits writing path.
func (p *Policy) AllowsWrite(file string) bool {
	return covered(file, p.Filesystem.Write)
}

// Flagged reports whether running prog should be flagged.
func (p *Policy) Flagged(prog string) bool {
	base := path.Base(prog)
	for _, f := range p.Exec.Flag {
		if f == base || f == prog {
			return true
		}
	}
	return false
}

func covered(file string, roots []string) bool {
	file = path.Clean(file)
	for _, r := range roots {
		if file == r || r == "/" || strings.HasPrefix(file, r+"/") {
			return true
		}
	}
	return false
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func lower(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(s)
	}
	return out
}

// Marshal renders a policy as YAML.
func (p *Policy) Marshal() ([]byte, error) {
	return yaml.Marshal(p)
}
