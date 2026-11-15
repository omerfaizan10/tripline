package policy

import (
	"fmt"
	"path"
	"sort"
	"strings"
)

// Access is one successful file or network use observed in a run.
type Access struct {
	Path  string
	Write bool
	Host  string // set for network accesses instead of Path
}

// SynthInput is the evidence for a least-privilege policy.
type SynthInput struct {
	Accesses  []Access
	Workspace string   // e.g. /work
	Home      string   // e.g. /home/agent
	Exclude   []string // paths that must never be granted (decoy secrets)
	Name      string
}

// SynthResult is a policy plus how it was derived.
type SynthResult struct {
	Policy   *Policy
	Excluded []string // accesses seen but deliberately not granted
	Evidence map[string]int
}

// systemRoots are granted as whole directories when anything below them was
// read: listing individual library files would be brittle and no safer.
var systemRoots = []string{"/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/proc", "/sys", "/opt", "/dev", "/run", "/var/lib"}

// Synthesize builds the tightest policy that still allows every observed
// access, generalising paths to stable roots. The result is in enforce mode.
func Synthesize(in SynthInput) SynthResult {
	reads, writes, hosts := map[string]bool{}, map[string]bool{}, map[string]bool{}
	res := SynthResult{Evidence: map[string]int{}}
	excluded := map[string]bool{}

	for _, a := range in.Accesses {
		if a.Host != "" {
			hosts[strings.ToLower(a.Host)] = true
			res.Evidence["hosts"]++
			continue
		}
		p := path.Clean(a.Path)
		if blocked(p, in.Exclude) {
			excluded[p] = true
			continue
		}
		root := generalise(p, a.Write, in.Workspace, in.Home)
		if root == "" {
			continue
		}
		if a.Write {
			writes[root] = true
			res.Evidence["writes"]++
		} else {
			reads[root] = true
			res.Evidence["reads"]++
		}
	}
	// A writable root already grants reading.
	for r := range reads {
		if coveredBy(r, writes) {
			delete(reads, r)
		}
	}
	// Drop entries nested under another entry of the same kind.
	p := &Policy{
		Version: 1,
		Name:    in.Name,
		Mode:    Enforce,
		Filesystem: Filesystem{
			Read:  templated(prune(reads), in.Workspace, in.Home),
			Write: templated(prune(writes), in.Workspace, in.Home),
		},
		Network: Network{AllowHosts: sorted(hosts)},
	}
	res.Policy = p
	res.Excluded = sorted(excluded)
	return res
}

func blocked(p string, exclude []string) bool {
	for _, e := range exclude {
		if p == e || strings.HasPrefix(e, p+"/") || strings.HasPrefix(p, e+"/") {
			return true
		}
	}
	return false
}

// generalise maps a concrete path to the root a policy should name.
func generalise(p string, write bool, work, home string) string {
	switch {
	case work != "" && (p == work || strings.HasPrefix(p, work+"/")):
		return work
	case p == "/tmp" || strings.HasPrefix(p, "/tmp/"):
		return "/tmp"
	case home != "" && (p == home || strings.HasPrefix(p, home+"/")):
		rel := strings.TrimPrefix(strings.TrimPrefix(p, home), "/")
		if rel == "" {
			return "" // listing the home directory itself is not worth granting
		}
		parts := strings.Split(rel, "/")
		// Keep dot-config files exact (e.g. ~/.gitconfig) and one level for
		// directories (~/.cache, ~/.npm), two for ~/.config/<tool>.
		if len(parts) == 1 {
			return home + "/" + parts[0]
		}
		if parts[0] == ".config" || parts[0] == ".local" {
			return home + "/" + parts[0] + "/" + parts[1]
		}
		return home + "/" + parts[0]
	}
	for _, r := range systemRoots {
		if p == r || strings.HasPrefix(p, r+"/") {
			return r
		}
	}
	// Anything else: its first two levels (e.g. /var/cache).
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	if len(parts) >= 2 {
		return "/" + parts[0] + "/" + parts[1]
	}
	return p
}

func coveredBy(p string, roots map[string]bool) bool {
	for r := range roots {
		if p == r || strings.HasPrefix(p, r+"/") {
			return true
		}
	}
	return false
}

func prune(set map[string]bool) []string {
	var out []string
	for p := range set {
		nested := false
		for q := range set {
			if q != p && strings.HasPrefix(p, q+"/") {
				nested = true
				break
			}
		}
		if !nested {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

func templated(paths []string, work, home string) []string {
	out := make([]string, len(paths))
	for i, p := range paths {
		switch {
		case work != "" && (p == work || strings.HasPrefix(p, work+"/")):
			p = "${WORKSPACE}" + strings.TrimPrefix(p, work)
		case home != "" && (p == home || strings.HasPrefix(p, home+"/")):
			p = "${HOME}" + strings.TrimPrefix(p, home)
		}
		out[i] = p
	}
	sort.Strings(out)
	return out
}

func sorted(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Header is a YAML comment block explaining a synthesised policy.
func (r SynthResult) Header(runs int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Synthesised by blast from %d run(s): the tightest policy that still\n", runs)
	fmt.Fprintf(&b, "# allows every access those runs made (%d reads, %d writes, %d host uses).\n", r.Evidence["reads"], r.Evidence["writes"], r.Evidence["hosts"])
	if len(r.Excluded) > 0 {
		b.WriteString("# Not granted, although the runs touched them (decoy credentials):\n")
		for _, e := range r.Excluded {
			fmt.Fprintf(&b, "#   %s\n", e)
		}
	}
	return b.String()
}
