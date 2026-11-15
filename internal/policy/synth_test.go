package policy

import (
	"reflect"
	"testing"
)

func TestSynthesize(t *testing.T) {
	r := Synthesize(SynthInput{
		Workspace: "/work",
		Home:      "/home/agent",
		Exclude:   []string{"/home/agent/.ssh/id_ed25519"},
		Accesses: []Access{
			{Path: "/usr/lib/python3.11/os.py"},
			{Path: "/usr/bin/git"},
			{Path: "/etc/ssl/certs/ca-certificates.crt"},
			{Path: "/work/src/app.py"},
			{Path: "/work/src/app.py", Write: true},
			{Path: "/tmp/pytest-of-agent/x", Write: true},
			{Path: "/home/agent/.cache/pip/http/a", Write: true},
			{Path: "/home/agent/.gitconfig"},
			{Path: "/home/agent/.config/gh/hosts.yml"},
			{Path: "/home/agent/.ssh/id_ed25519"}, // read in an audit run: must not be granted
			{Path: "/home/agent/.ssh"},
			{Host: "PyPI.org"},
			{Host: "files.pythonhosted.org"},
		},
	})
	p := r.Policy
	if p.Mode != Enforce {
		t.Fatal("synthesised policies enforce")
	}
	if want := []string{"${HOME}/.cache", "${WORKSPACE}", "/tmp"}; !reflect.DeepEqual(p.Filesystem.Write, want) {
		t.Errorf("write = %v, want %v", p.Filesystem.Write, want)
	}
	// /work is writable so it is not repeated under read.
	if want := []string{"${HOME}/.config/gh", "${HOME}/.gitconfig", "/etc", "/usr"}; !reflect.DeepEqual(p.Filesystem.Read, want) {
		t.Errorf("read = %v, want %v", p.Filesystem.Read, want)
	}
	if want := []string{"files.pythonhosted.org", "pypi.org"}; !reflect.DeepEqual(p.Network.AllowHosts, want) {
		t.Errorf("hosts = %v, want %v", p.Network.AllowHosts, want)
	}
	if len(r.Excluded) != 2 {
		t.Errorf("both the key and its directory should be listed as excluded, got %v", r.Excluded)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("synthesised policy must validate: %v", err)
	}
	b, _ := p.Marshal()
	if _, err := Parse(b); err != nil {
		t.Fatalf("synthesised policy must round-trip: %v", err)
	}
}
