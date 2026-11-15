package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A task without its own git repo still gets a recorded diff, and the
// baseline repo stays outside the workspace the agent can see.
func TestBaselineWithoutTaskRepo(t *testing.T) {
	dir := t.TempDir()
	work := filepath.Join(dir, "work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "app.py"), []byte("x = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := baseline(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(work, ".git")); err == nil {
		t.Fatal("baseline must not create .git inside the workspace")
	}
	if err := os.WriteFile(filepath.Join(work, "app.py"), []byte("x = 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "new.py"), []byte("y = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	d := gitDiff(dir)
	if !strings.Contains(d, "+x = 2") || !strings.Contains(d, "new.py") {
		t.Fatalf("diff misses changes:\n%s", d)
	}
	got := strings.Join(changedFiles(dir), ",")
	if !strings.Contains(got, "app.py") || !strings.Contains(got, "new.py") {
		t.Fatalf("changed files: %s", got)
	}
}

func TestNoTaskNoDiff(t *testing.T) {
	if d := gitDiff(t.TempDir()); d != "" {
		t.Fatalf("expected no diff, got %q", d)
	}
}
