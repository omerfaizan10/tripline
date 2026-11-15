package policy

import (
	"strings"
	"testing"
)

const sample = `
version: 1
name: test
mode: enforce
filesystem:
  read: ["/usr", "${HOME}/.gitconfig"]
  write: ["${WORKSPACE}", "/tmp"]
network:
  allow_hosts: ["registry.npmjs.org", "*.github.com", "PyPI.org"]
exec:
  flag: ["curl"]
`

func load(t *testing.T) *Policy {
	t.Helper()
	p, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	return p.Expand("/work", "/home/agent")
}

func TestParseRejectsUnknownKeys(t *testing.T) {
	_, err := Parse([]byte(strings.Replace(sample, "allow_hosts", "allow_host", 1)))
	if err == nil {
		t.Fatal("a misspelled key must be rejected, not silently ignored")
	}
}

func TestValidate(t *testing.T) {
	cases := map[string]string{
		"bad mode":      strings.Replace(sample, "mode: enforce", "mode: lax", 1),
		"bad version":   strings.Replace(sample, "version: 1", "version: 2", 1),
		"relative path": strings.Replace(sample, `"/tmp"`, `"tmp"`, 1),
		"url as host":   strings.Replace(sample, `"registry.npmjs.org"`, `"https://registry.npmjs.org"`, 1),
		"bare wildcard": strings.Replace(sample, `"*.github.com"`, `"*"`, 1),
	}
	for name, doc := range cases {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}

func TestHosts(t *testing.T) {
	p := load(t)
	for host, want := range map[string]bool{
		"registry.npmjs.org":      true,
		"REGISTRY.npmjs.org.":     true, // case and trailing dot are normalised
		"api.github.com":          true,
		"github.com":              false, // *.github.com does not cover the apex
		"evil-github.com":         false,
		"github.com.evil.io":      false,
		"pypi.org":                true, // patterns are lower-cased
		"registry.npmjs.org.evil": false,
	} {
		if got := p.AllowsHost(host); got != want {
			t.Errorf("AllowsHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestPaths(t *testing.T) {
	p := load(t)
	checks := []struct {
		path        string
		read, write bool
	}{
		{"/work/src/main.py", true, true},
		{"/work", true, true},
		{"/work2/secret", false, false}, // prefix of a name is not containment
		{"/usr/bin/python3", true, false},
		{"/home/agent/.gitconfig", true, false},
		{"/home/agent/.ssh/id_ed25519", false, false},
		{"/tmp/../home/agent/.ssh/id_ed25519", false, false}, // cleaned before matching
	}
	for _, c := range checks {
		if got := p.AllowsRead(c.path); got != c.read {
			t.Errorf("AllowsRead(%q) = %v, want %v", c.path, got, c.read)
		}
		if got := p.AllowsWrite(c.path); got != c.write {
			t.Errorf("AllowsWrite(%q) = %v, want %v", c.path, got, c.write)
		}
	}
}

func TestFlagged(t *testing.T) {
	p := load(t)
	if !p.Flagged("/usr/bin/curl") || p.Flagged("/usr/bin/git") {
		t.Fatal("exec flags should match by program name")
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	p, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(b); err != nil {
		t.Fatalf("marshalled policy does not parse back: %v", err)
	}
}
