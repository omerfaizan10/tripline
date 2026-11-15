package events

import (
	"bufio"
	"io"
	"path"
	"regexp"
	"strconv"
	"strings"
)

// StraceArgs are the flags the sandbox passes to strace. The parser below
// expects exactly this output shape: -f (pid prefix), -ttt (epoch times),
// -y (fd paths), -s 4096 (long strings).
var StraceArgs = []string{
	"-f", "-qq", "-ttt", "-y", "-s", "4096",
	"-e", "trace=execve,open,openat,creat,unlink,unlinkat,rename,renameat,renameat2,mkdir,mkdirat,chdir,fchdir,connect,clone,clone3,fork,vfork",
	"-e", "signal=none",
}

// line: "<pid> <epoch.us> <rest>"
var lineRE = regexp.MustCompile(`^(\d+)\s+(\d+\.\d+)\s+(.*)$`)

// ParseStrace turns strace output into events. cwd is the working directory
// of the first traced process; children inherit their parent's directory.
func ParseStrace(r io.Reader, cwd string) ([]Event, error) {
	p := &straceParser{cwd: map[int]string{}, pending: map[int]string{}, root: cwd}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		p.line(sc.Text())
	}
	return p.out, sc.Err()
}

type straceParser struct {
	cwd     map[int]string
	pending map[int]string // unfinished call text per pid
	root    string
	out     []Event
}

func (p *straceParser) dir(pid int) string {
	if d, ok := p.cwd[pid]; ok {
		return d
	}
	return p.root
}

func (p *straceParser) line(s string) {
	m := lineRE.FindStringSubmatch(s)
	if m == nil {
		return
	}
	pid, _ := strconv.Atoi(m[1])
	t, _ := strconv.ParseFloat(m[2], 64)
	rest := m[3]

	// Join "<unfinished ...>" with its later "<... name resumed>".
	if strings.HasSuffix(rest, "<unfinished ...>") {
		p.pending[pid] = strings.TrimSpace(strings.TrimSuffix(rest, "<unfinished ...>"))
		return
	}
	if strings.HasPrefix(rest, "<... ") {
		i := strings.Index(rest, " resumed>")
		if i < 0 {
			return
		}
		head, ok := p.pending[pid]
		if !ok {
			return
		}
		delete(p.pending, pid)
		rest = head + rest[i+len(" resumed>"):]
	}
	if strings.HasPrefix(rest, "+++") || strings.HasPrefix(rest, "---") {
		return // exit and signal notices
	}

	name, args, ret, ok := splitCall(rest)
	if !ok {
		return
	}
	retVal, errno, retPath := parseReturn(ret)
	a := splitArgs(args)

	ev := Event{T: t, Src: SrcTrace, PID: pid, Result: OK}
	if errno != "" {
		ev.Errno = errno
		ev.Result = classify(errno)
	}

	switch name {
	case "clone", "clone3", "fork", "vfork":
		if errno == "" && retVal > 0 {
			p.cwd[int(retVal)] = p.dir(pid)
		}
		return
	case "chdir":
		if errno == "" && len(a) > 0 {
			p.cwd[pid] = p.resolve(pid, "", unquote(a[0]))
		}
		return
	case "fchdir":
		if errno == "" && len(a) > 0 {
			if d := fdPath(a[0]); d != "" {
				p.cwd[pid] = d
			}
		}
		return
	case "execve":
		if errno == "ENOENT" {
			return // PATH lookups that miss are noise
		}
		if len(a) < 2 {
			return
		}
		ev.Op = OpExec
		ev.Path = p.resolve(pid, "", unquote(a[0]))
		ev.Argv = parseArgv(a[1])
	case "open", "creat":
		if len(a) < 1 {
			return
		}
		ev.Path = p.pick(pid, "", unquote(a[0]), retPath)
		ev.Op = OpRead
		if name == "creat" || (len(a) > 1 && isWriteFlags(a[1])) {
			ev.Op = OpWrite
		}
	case "openat":
		if len(a) < 3 {
			return
		}
		ev.Path = p.pick(pid, a[0], unquote(a[1]), retPath)
		ev.Op = OpRead
		if isWriteFlags(a[2]) {
			ev.Op = OpWrite
		}
	case "unlink":
		if len(a) < 1 {
			return
		}
		ev.Op, ev.Path = OpDelete, p.resolve(pid, "", unquote(a[0]))
	case "unlinkat":
		if len(a) < 2 {
			return
		}
		ev.Op, ev.Path = OpDelete, p.resolve(pid, a[0], unquote(a[1]))
	case "rename":
		if len(a) < 2 {
			return
		}
		ev.Op = OpRename
		ev.Path, ev.Path2 = p.resolve(pid, "", unquote(a[0])), p.resolve(pid, "", unquote(a[1]))
	case "renameat", "renameat2":
		if len(a) < 4 {
			return
		}
		ev.Op = OpRename
		ev.Path, ev.Path2 = p.resolve(pid, a[0], unquote(a[1])), p.resolve(pid, a[2], unquote(a[3]))
	case "mkdir":
		if len(a) < 1 {
			return
		}
		ev.Op, ev.Path = OpMkdir, p.resolve(pid, "", unquote(a[0]))
	case "mkdirat":
		if len(a) < 2 {
			return
		}
		ev.Op, ev.Path = OpMkdir, p.resolve(pid, a[0], unquote(a[1]))
	case "connect":
		if len(a) < 2 {
			return
		}
		host, port, ok := parseSockaddr(a[1])
		if !ok {
			return // unix sockets and other families are not network egress
		}
		if errno == "EINPROGRESS" {
			ev.Result, ev.Errno = OK, "" // non-blocking connect that is under way
		}
		ev.Op, ev.Host, ev.Port = OpConnect, host, port
	default:
		return
	}
	// fds opened through /proc/self/fd can resolve to pipes, sockets or
	// anonymous inodes ("pipe:[123]"); those are not files.
	if ev.Op != OpConnect && ev.Op != OpExec && !strings.HasPrefix(ev.Path, "/") {
		return
	}
	p.out = append(p.out, ev)
}

// pick prefers the kernel-resolved path strace prints after the returned fd.
func (p *straceParser) pick(pid int, dirfd, name, retPath string) string {
	if retPath != "" {
		return retPath
	}
	return p.resolve(pid, dirfd, name)
}

// resolve makes name absolute using the dirfd decoration or the tracked cwd.
func (p *straceParser) resolve(pid int, dirfd, name string) string {
	if name == "" {
		return ""
	}
	if strings.HasPrefix(name, "/") {
		return path.Clean(name)
	}
	base := p.dir(pid)
	if d := fdPath(dirfd); d != "" {
		base = d
	}
	return path.Clean(path.Join(base, name))
}

// classify separates "the sandbox said no" from ordinary failures.
func classify(errno string) Result {
	switch errno {
	case "EACCES", "EPERM", "ENETUNREACH", "EHOSTUNREACH", "EROFS":
		return Denied
	default:
		return Failed
	}
}

func isWriteFlags(f string) bool {
	for _, w := range []string{"O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND"} {
		if strings.Contains(f, w) {
			return true
		}
	}
	return false
}

// splitCall splits `name(args) = ret` at the parenthesis that closes the
// argument list, respecting quotes and nesting.
func splitCall(s string) (name, args, ret string, ok bool) {
	open := strings.IndexByte(s, '(')
	if open <= 0 {
		return "", "", "", false
	}
	name = s[:open]
	depth, inStr, esc := 0, false, false
	for i := open; i < len(s); i++ {
		c := s[i]
		switch {
		case esc:
			esc = false
		case inStr && c == '\\':
			esc = true
		case c == '"':
			inStr = !inStr
		case inStr:
		case c == '(' || c == '[' || c == '{':
			depth++
		case c == ')' || c == ']' || c == '}':
			depth--
			if depth == 0 && c == ')' {
				rest := strings.TrimSpace(s[i+1:])
				if !strings.HasPrefix(rest, "=") {
					return "", "", "", false
				}
				return name, s[open+1 : i], strings.TrimSpace(rest[1:]), true
			}
		}
	}
	return "", "", "", false
}

// splitArgs splits a top-level comma-separated argument list.
func splitArgs(s string) []string {
	var out []string
	depth, inStr, esc, start := 0, false, false, 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case esc:
			esc = false
		case inStr && c == '\\':
			esc = true
		case c == '"':
			inStr = !inStr
		case inStr:
		case c == '(' || c == '[' || c == '{' || c == '<':
			depth++
		case c == ')' || c == ']' || c == '}' || c == '>':
			depth--
		case c == ',' && depth == 0:
			out = append(out, strings.TrimSpace(s[start:i]))
			start = i + 1
		}
	}
	if tail := strings.TrimSpace(s[start:]); tail != "" {
		out = append(out, tail)
	}
	return out
}

var retRE = regexp.MustCompile(`^(-?\d+|0x[0-9a-f]+|\?)(?:<([^>]*)>)?(?:\s+([A-Z][A-Z0-9_]+)(?:\s+\(.*\))?)?`)

// parseReturn reads "3</path>", "0" or "-1 EACCES (Permission denied)".
func parseReturn(s string) (val int64, errno, fdpath string) {
	m := retRE.FindStringSubmatch(s)
	if m == nil {
		return 0, "", ""
	}
	val, _ = strconv.ParseInt(m[1], 0, 64)
	return val, m[3], m[2]
}

// fdPath extracts the path decoration from "3</a/b>" or "AT_FDCWD</a>".
func fdPath(arg string) string {
	i := strings.IndexByte(arg, '<')
	if i < 0 || !strings.HasSuffix(arg, ">") {
		return ""
	}
	return arg[i+1 : len(arg)-1]
}

var (
	inetRE  = regexp.MustCompile(`sa_family=AF_INET,\s*sin_port=htons\((\d+)\),\s*sin_addr=inet_addr\("([^"]+)"\)`)
	inet6RE = regexp.MustCompile(`sa_family=AF_INET6,\s*sin6_port=htons\((\d+)\).*?inet_pton\(AF_INET6,\s*"([^"]+)"`)
)

func parseSockaddr(s string) (host string, port int, ok bool) {
	if m := inetRE.FindStringSubmatch(s); m != nil {
		port, _ = strconv.Atoi(m[1])
		return m[2], port, true
	}
	if m := inet6RE.FindStringSubmatch(s); m != nil {
		port, _ = strconv.Atoi(m[1])
		return m[2], port, true
	}
	return "", 0, false
}

func parseArgv(s string) []string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	var out []string
	for _, a := range splitArgs(s) {
		if strings.HasPrefix(a, "\"") {
			out = append(out, unquote(a))
		} else if a == "..." {
			out = append(out, "...")
		}
	}
	return out
}

// unquote decodes a C-style quoted string as strace prints it. A trailing
// "..." (truncation marker) is dropped.
func unquote(s string) string {
	s = strings.TrimSuffix(strings.TrimSpace(s), "...")
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return s
	}
	s = s[1 : len(s)-1]
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			b.WriteByte(c)
			continue
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case '"', '\\':
			b.WriteByte(s[i])
		case 'x':
			if i+2 < len(s) {
				if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
					b.WriteByte(byte(v))
					i += 2
					continue
				}
			}
			b.WriteByte('x')
		default:
			if s[i] >= '0' && s[i] <= '7' {
				j := i
				for j < len(s) && j < i+3 && s[j] >= '0' && s[j] <= '7' {
					j++
				}
				v, _ := strconv.ParseUint(s[i:j], 8, 8)
				b.WriteByte(byte(v))
				i = j - 1
				continue
			}
			b.WriteByte(s[i])
		}
	}
	return b.String()
}
