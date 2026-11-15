package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/omerfaizan10/blast-radius/internal/events"
	"github.com/omerfaizan10/blast-radius/internal/policy"
)

type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) { l.mu.Lock(); defer l.mu.Unlock(); return l.b.Write(p) }

// waitEvents polls until at least n events are logged; the proxy writes an
// event after it finishes relaying, which can be just after the client is done.
func (l *logBuf) waitEvents(t *testing.T, n int) []events.Event {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		evs := l.events(t)
		if len(evs) >= n || time.Now().After(deadline) {
			return evs
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (l *logBuf) events(t *testing.T) []events.Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	evs, err := events.ReadJSONL(bytes.NewReader(l.b.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

func pol(mode policy.Mode, hosts ...string) *policy.Policy {
	return &policy.Policy{Version: 1, Mode: mode, Network: policy.Network{AllowHosts: hosts}}
}

// echoServer answers every line with "echo: <line>".
func echoServer(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				sc := bufio.NewScanner(c)
				for sc.Scan() {
					fmt.Fprintf(c, "echo: %s\n", sc.Text())
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func startProxy(t *testing.T, cfg Config) (*Proxy, string) {
	echo := echoServer(t)
	cfg.Dial = func(network, addr string) (net.Conn, error) { return net.Dial("tcp", echo) }
	p := New(cfg)
	srv := httptest.NewServer(p.EgressHandler())
	t.Cleanup(srv.Close)
	return p, strings.TrimPrefix(srv.URL, "http://")
}

func tunnel(t *testing.T, proxyAddr, target string) (int, *bufio.Reader, net.Conn) {
	c, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, br, c
}

func TestConnectAllowedRelaysBytes(t *testing.T) {
	log := &logBuf{}
	_, addr := startProxy(t, Config{Policy: pol(policy.Enforce, "registry.npmjs.org"), Log: log})
	code, br, c := tunnel(t, addr, "registry.npmjs.org:443")
	if code != 200 {
		t.Fatalf("allowed host got %d", code)
	}
	fmt.Fprint(c, "hello\n")
	line, _ := br.ReadString('\n')
	if line != "echo: hello\n" {
		t.Fatalf("tunnel did not relay: %q", line)
	}
	c.Close()
	evs := log.waitEvents(t, 1)
	if len(evs) != 1 || evs[0].Result != events.OK || evs[0].BytesUp == 0 || evs[0].BytesDown == 0 {
		t.Fatalf("expected one ok event with byte counts, got %+v", evs)
	}
}

func TestConnectDeniedHost(t *testing.T) {
	log := &logBuf{}
	_, addr := startProxy(t, Config{Policy: pol(policy.Enforce, "registry.npmjs.org"), Log: log})
	code, _, c := tunnel(t, addr, "evil.example:443")
	c.Close()
	if code != http.StatusForbidden {
		t.Fatalf("unlisted host got %d, want 403", code)
	}
	evs := log.events(t)
	if len(evs) != 1 || evs[0].Result != events.Denied || !evs[0].HasFlag(events.FlagNewHost) {
		t.Fatalf("expected a denied new_host event, got %+v", evs)
	}
}

func TestAuditModeAllowsButFlags(t *testing.T) {
	log := &logBuf{}
	_, addr := startProxy(t, Config{Policy: pol(policy.Audit), Log: log})
	code, _, c := tunnel(t, addr, "anything.example:443")
	c.Close()
	if code != 200 {
		t.Fatalf("audit mode should let traffic through, got %d", code)
	}
	if evs := log.waitEvents(t, 1); len(evs) != 1 || !evs[0].HasFlag(events.FlagNewHost) {
		t.Fatalf("audit mode must still flag unlisted hosts: %+v", evs)
	}
}

func TestAskModeWaitsForHuman(t *testing.T) {
	log := &logBuf{}
	p, addr := startProxy(t, Config{Policy: pol(policy.Ask), Log: log, AskTimeout: 5 * time.Second})
	ctl := httptest.NewServer(p.ControlHandler())
	defer ctl.Close()

	got := make(chan int, 1)
	go func() {
		code, _, c := tunnel(t, addr, "new.example:443")
		c.Close()
		got <- code
	}()
	var holds []map[string]any
	for i := 0; i < 50 && len(holds) == 0; i++ {
		time.Sleep(20 * time.Millisecond)
		resp, err := http.Get(ctl.URL + "/pending")
		if err != nil {
			t.Fatal(err)
		}
		_ = json.NewDecoder(resp.Body).Decode(&holds)
		resp.Body.Close()
	}
	if len(holds) != 1 || holds[0]["host"] != "new.example" {
		t.Fatalf("expected one hold for new.example, got %v", holds)
	}
	body := fmt.Sprintf(`{"id":%q,"allow":true}`, holds[0]["id"])
	if _, err := http.Post(ctl.URL+"/decide", "application/json", strings.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	if code := <-got; code != 200 {
		t.Fatalf("approved host got %d", code)
	}
	// The answer is remembered for the rest of the run.
	code, _, c := tunnel(t, addr, "new.example:443")
	c.Close()
	if code != 200 {
		t.Fatalf("second request to an approved host got %d", code)
	}
}

func TestGatewayInjectsKeyMetersTokensAndFlagsDecoys(t *testing.T) {
	var sawAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"hi\"}\n\n")
		fmt.Fprint(w, "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"model\":\"test-model\",\"usage\":{\"input_tokens\":1200,\"output_tokens\":85}}}\n\n")
	}))
	defer upstream.Close()

	log := &logBuf{}
	decoy := "ghp_DECOYDECOYDECOYDECOYDECOYDECOY1234"
	p := New(Config{Policy: pol(policy.Enforce), Log: log, ModelUpstream: upstream.URL, ModelKey: "sk-real", Decoys: []string{decoy}})
	gw := httptest.NewServer(p.GatewayHandler())
	defer gw.Close()

	req, _ := http.NewRequest("POST", gw.URL+"/v1/responses", strings.NewReader(`{"model":"test-model","input":"my token is `+decoy+`"}`))
	req.Header.Set("Authorization", "Bearer sk-agent-tried-its-own")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(b), "response.completed") {
		t.Fatal("stream not passed through to the agent")
	}
	if sawAuth != "Bearer sk-real" {
		t.Fatalf("upstream saw %q; the agent's credential must be replaced by the real key", sawAuth)
	}
	evs := log.waitEvents(t, 1)
	if len(evs) != 1 {
		t.Fatalf("want 1 event, got %d", len(evs))
	}
	e := evs[0]
	if e.TokensIn != 1200 || e.TokensOut != 85 || e.Model != "test-model" {
		t.Fatalf("usage not metered: %+v", e)
	}
	if !e.HasFlag(events.FlagSecretToModel) || strings.Contains(e.Detail, decoy) {
		t.Fatalf("decoy in prompt must be flagged without logging the full secret: %+v", e)
	}
}

func TestParseUsageChatCompletions(t *testing.T) {
	m, in, out := ParseUsage([]byte(`{"model":"gpt-x","usage":{"prompt_tokens":10,"completion_tokens":3}}`))
	if m != "gpt-x" || in != 10 || out != 3 {
		t.Fatalf("got %s %d %d", m, in, out)
	}
}
