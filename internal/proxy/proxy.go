// Package proxy is the sandbox's only route off its private network.
//
// It serves three listeners:
//
//   - an HTTP proxy (CONNECT tunnels and plain HTTP) that lets through only
//     hosts on the policy's allowlist, and in ask mode holds unknown hosts
//     until a human decides;
//   - a model gateway: the agent talks plain HTTP to it, the gateway drops any
//     credential the agent sends, adds the real API key (which never enters the
//     sandbox), forwards over TLS, meters tokens and scans requests for decoys;
//   - a small control API the host CLI uses to list and answer ask-mode holds.
package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/omerfaizan10/tripline/internal/events"
	"github.com/omerfaizan10/tripline/internal/policy"
)

// Config wires the proxy to a run.
type Config struct {
	Policy        *policy.Policy
	Decoys        []string      // decoy secret values to look for
	ModelUpstream string        // e.g. https://api.openai.com
	ModelKey      string        // injected as Authorization: Bearer
	AskTimeout    time.Duration // ask mode: deny after this long
	Log           io.Writer     // JSONL events
	Dial          func(network, addr string) (net.Conn, error)
	Client        *http.Client // for plain HTTP and the gateway; nil = default
}

// Proxy holds run state.
type Proxy struct {
	cfg     Config
	mu      sync.Mutex
	enc     *json.Encoder
	pending map[string]*hold
	decided map[string]bool // ask mode: hosts already answered for this run
	nextID  atomic.Int64
}

type hold struct {
	ID     string    `json:"id"`
	Host   string    `json:"host"`
	Port   int       `json:"port"`
	Since  time.Time `json:"since"`
	answer chan bool
}

// New builds a proxy.
func New(cfg Config) *Proxy {
	if cfg.AskTimeout == 0 {
		cfg.AskTimeout = 2 * time.Minute
	}
	if cfg.Dial == nil {
		d := &net.Dialer{Timeout: 15 * time.Second}
		cfg.Dial = d.Dial
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 10 * time.Minute}
	}
	if cfg.Log == nil {
		cfg.Log = io.Discard
	}
	return &Proxy{cfg: cfg, enc: json.NewEncoder(cfg.Log), pending: map[string]*hold{}, decided: map[string]bool{}}
}

func (p *Proxy) emit(e events.Event) {
	e.Src = events.SrcProxy
	if e.T == 0 {
		e.T = float64(time.Now().UnixMicro()) / 1e6
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	_ = p.enc.Encode(&e)
}

// ---------- egress proxy ----------

// EgressHandler serves CONNECT and absolute-form HTTP requests.
func (p *Proxy) EgressHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			p.connect(w, r)
			return
		}
		p.plain(w, r)
	})
}

// decide applies the policy, consulting a human in ask mode.
func (p *Proxy) decide(host string, port int) (bool, string) {
	if p.cfg.Policy.AllowsHost(host) {
		return true, "allowlist"
	}
	if p.cfg.Policy.Mode == policy.Audit {
		return true, "audit mode"
	}
	if p.cfg.Policy.Mode != policy.Ask {
		return false, "not on allowlist"
	}
	p.mu.Lock()
	if v, ok := p.decided[host]; ok {
		p.mu.Unlock()
		if v {
			return true, "approved earlier in this run"
		}
		return false, "denied earlier in this run"
	}
	h := &hold{ID: strconv.FormatInt(p.nextID.Add(1), 10), Host: host, Port: port, Since: time.Now(), answer: make(chan bool, 1)}
	p.pending[h.ID] = h
	p.mu.Unlock()
	p.emit(events.Event{Op: events.OpHTTP, Method: "CONNECT", Host: host, Port: port, Result: events.Pending, Flags: []events.Flag{events.FlagNewHost}, Detail: "waiting for approval"})

	var ok bool
	var why string
	select {
	case ok = <-h.answer:
		why = map[bool]string{true: "approved by human", false: "denied by human"}[ok]
	case <-time.After(p.cfg.AskTimeout):
		why = "no answer, denied"
	}
	p.mu.Lock()
	delete(p.pending, h.ID)
	p.decided[host] = ok
	p.mu.Unlock()
	return ok, why
}

func (p *Proxy) connect(w http.ResponseWriter, r *http.Request) {
	host, portStr, err := net.SplitHostPort(r.Host)
	if err != nil {
		host, portStr = r.Host, "443"
	}
	port, _ := strconv.Atoi(portStr)
	ev := events.Event{Op: events.OpHTTP, Method: "CONNECT", Host: host, Port: port}
	if !p.cfg.Policy.AllowsHost(host) {
		ev.AddFlag(events.FlagNewHost)
	}
	if hits := p.findDecoys(host); len(hits) > 0 {
		ev.AddFlag(events.FlagCanary)
		ev.Detail = "decoy secret in hostname: " + strings.Join(hits, ",")
	}
	ok, why := p.decide(host, port)
	if !ok {
		ev.Result, ev.Detail = events.Denied, joinDetail(ev.Detail, why)
		p.emit(ev)
		http.Error(w, "blocked by tripline policy: "+why, http.StatusForbidden)
		return
	}
	up, err := p.cfg.Dial("tcp", net.JoinHostPort(host, portStr))
	if err != nil {
		ev.Result, ev.Detail = events.Failed, joinDetail(ev.Detail, err.Error())
		p.emit(ev)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	hj, okHJ := w.(http.Hijacker)
	if !okHJ {
		up.Close()
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	client, buf, err := hj.Hijack()
	if err != nil {
		up.Close()
		return
	}
	_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	ev.Result, ev.Detail = events.OK, joinDetail(ev.Detail, why)
	start := time.Now()
	var upN, downN int64
	done := make(chan struct{}, 2)
	go func() {
		// bytes the client already sent past the CONNECT line
		if n := buf.Reader.Buffered(); n > 0 {
			b, _ := buf.Reader.Peek(n)
			m, _ := up.Write(b)
			atomic.AddInt64(&upN, int64(m))
		}
		n, _ := io.Copy(up, client)
		atomic.AddInt64(&upN, n)
		closeWrite(up)
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(client, up)
		atomic.AddInt64(&downN, n)
		closeWrite(client)
		done <- struct{}{}
	}()
	<-done
	<-done
	client.Close()
	up.Close()
	ev.T = float64(start.UnixMicro()) / 1e6
	ev.BytesUp, ev.BytesDown = atomic.LoadInt64(&upN), atomic.LoadInt64(&downN)
	p.emit(ev)
}

func closeWrite(c net.Conn) {
	if tc, ok := c.(interface{ CloseWrite() error }); ok {
		_ = tc.CloseWrite()
	}
}

func (p *Proxy) plain(w http.ResponseWriter, r *http.Request) {
	if r.URL.Host == "" {
		http.Error(w, "this is a proxy; send absolute-form requests", http.StatusBadRequest)
		return
	}
	host := r.URL.Hostname()
	port, _ := strconv.Atoi(r.URL.Port())
	if port == 0 {
		port = 80
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	ev := events.Event{Op: events.OpHTTP, Method: r.Method, Host: host, Port: port, Path: r.URL.Path}
	if !p.cfg.Policy.AllowsHost(host) {
		ev.AddFlag(events.FlagNewHost)
	}
	if hits := p.findDecoys(r.URL.String() + "\n" + headerText(r.Header) + "\n" + string(body)); len(hits) > 0 {
		ev.AddFlag(events.FlagCanary)
		ev.Detail = "decoy secret in request: " + strings.Join(hits, ",")
	}
	ok, why := p.decide(host, port)
	if !ok {
		ev.Result, ev.Detail = events.Denied, joinDetail(ev.Detail, why)
		p.emit(ev)
		http.Error(w, "blocked by tripline policy: "+why, http.StatusForbidden)
		return
	}
	out, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), bytes.NewReader(body))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	copyHeaders(out.Header, r.Header)
	out.Header.Del("Proxy-Connection")
	out.Header.Del("Proxy-Authorization")
	resp, err := p.cfg.Client.Do(out)
	if err != nil {
		ev.Result, ev.Detail = events.Failed, joinDetail(ev.Detail, err.Error())
		p.emit(ev)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	n, _ := io.Copy(w, resp.Body)
	ev.Result, ev.Detail = events.OK, joinDetail(ev.Detail, why)
	ev.BytesUp, ev.BytesDown = int64(len(body)), n
	p.emit(ev)
}

// ---------- model gateway ----------

// GatewayHandler forwards /v1/... to the model API with the real key.
func (p *Proxy) GatewayHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up, err := url.Parse(p.cfg.ModelUpstream)
		if err != nil || p.cfg.ModelUpstream == "" {
			http.Error(w, "model gateway not configured", http.StatusServiceUnavailable)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<20))
		ev := events.Event{Op: events.OpHTTP, Method: r.Method, Host: up.Hostname(), Port: 443, Path: r.URL.Path, Flags: []events.Flag{events.FlagModel}}
		if hits := p.findDecoys(string(body) + "\n" + r.URL.RawQuery); len(hits) > 0 {
			ev.AddFlag(events.FlagSecretToModel)
			ev.AddFlag(events.FlagCanary)
			ev.Detail = "decoy secret sent to the model: " + strings.Join(hits, ",")
		}
		target := strings.TrimSuffix(p.cfg.ModelUpstream, "/") + r.URL.Path
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}
		out, err := http.NewRequestWithContext(r.Context(), r.Method, target, bytes.NewReader(body))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		copyHeaders(out.Header, r.Header)
		out.Header.Del("Authorization") // whatever the agent sent is never forwarded
		out.Header.Del("Openai-Organization")
		out.Header.Del("Openai-Project")
		if p.cfg.ModelKey != "" {
			out.Header.Set("Authorization", "Bearer "+p.cfg.ModelKey)
		}
		resp, err := p.cfg.Client.Do(out)
		if err != nil {
			ev.Result, ev.Detail = events.Failed, joinDetail(ev.Detail, err.Error())
			p.emit(ev)
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		copyHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		// Stream through while keeping a capped copy for usage accounting.
		var tap cappedBuffer
		tap.max = 32 << 20
		fl, _ := w.(http.Flusher)
		n, _ := io.Copy(flushWriter{w, fl}, io.TeeReader(resp.Body, &tap))
		ev.BytesUp, ev.BytesDown = int64(len(body)), n
		ev.Result = events.OK
		if resp.StatusCode >= 400 {
			ev.Result = events.Failed
			ev.Detail = joinDetail(ev.Detail, "upstream status "+strconv.Itoa(resp.StatusCode))
		}
		u := ParseUsageFull(tap.Bytes())
		ev.Model, ev.TokensIn, ev.TokensCached, ev.TokensOut = u.Model, u.In, u.Cached, u.Out
		if ev.Model == "" {
			ev.Model = requestModel(body)
		}
		p.emit(ev)
	})
}

type flushWriter struct {
	w http.ResponseWriter
	f http.Flusher
}

func (fw flushWriter) Write(b []byte) (int, error) {
	n, err := fw.w.Write(b)
	if fw.f != nil {
		fw.f.Flush()
	}
	return n, err
}

type cappedBuffer struct {
	bytes.Buffer
	max int
}

func (c *cappedBuffer) Write(b []byte) (int, error) {
	if room := c.max - c.Len(); room > 0 {
		if len(b) > room {
			c.Buffer.Write(b[:room])
		} else {
			c.Buffer.Write(b)
		}
	}
	return len(b), nil
}

type usageDoc struct {
	Model string `json:"model"`
	Usage *struct {
		InputTokens      int `json:"input_tokens"`
		OutputTokens     int `json:"output_tokens"`
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		InputDetails     *struct {
			CachedTokens int `json:"cached_tokens"`
		} `json:"input_tokens_details"`
		PromptDetails *struct {
			CachedTokens int `json:"cached_tokens"`
		} `json:"prompt_tokens_details"`
	} `json:"usage"`
	Response *usageDoc `json:"response"`
}

// Usage is what one model response cost in tokens.
type Usage struct {
	Model  string
	In     int // all input tokens, cached included
	Cached int // the cached part of In
	Out    int
}

// ParseUsage reads token counts from a JSON body or an SSE stream (Responses
// API "response.completed" or Chat Completions with usage). The last usage
// block wins, which is the final total in a stream.
func ParseUsage(b []byte) (model string, in, out int) {
	u := ParseUsageFull(b)
	return u.Model, u.In, u.Out
}

// ParseUsageFull is ParseUsage including cached input tokens.
func ParseUsageFull(b []byte) Usage {
	model, in, out, cached := "", 0, 0, 0
	try := func(raw []byte) {
		var d usageDoc
		if json.Unmarshal(raw, &d) != nil {
			return
		}
		if d.Response != nil {
			d = *d.Response
		}
		if d.Model != "" {
			model = d.Model
		}
		if d.Usage != nil {
			in = d.Usage.InputTokens + d.Usage.PromptTokens
			out = d.Usage.OutputTokens + d.Usage.CompletionTokens
			cached = 0
			if d.Usage.InputDetails != nil {
				cached += d.Usage.InputDetails.CachedTokens
			}
			if d.Usage.PromptDetails != nil {
				cached += d.Usage.PromptDetails.CachedTokens
			}
		}
	}
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		try(trimmed)
		return Usage{model, in, cached, out}
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 1<<20), 1<<26)
	for sc.Scan() {
		line := sc.Bytes()
		if bytes.HasPrefix(line, []byte("data:")) {
			payload := bytes.TrimSpace(line[5:])
			if bytes.Contains(payload, []byte(`"usage"`)) || bytes.Contains(payload, []byte(`"model"`)) {
				try(payload)
			}
		}
	}
	return Usage{model, in, cached, out}
}

func requestModel(body []byte) string {
	var d struct {
		Model string `json:"model"`
	}
	_ = json.Unmarshal(body, &d)
	return d.Model
}

// ---------- control API (ask mode) ----------

// ControlHandler lets the host list and answer holds.
func (p *Proxy) ControlHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /pending", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		list := make([]*hold, 0, len(p.pending))
		for _, h := range p.pending {
			list = append(list, h)
		}
		p.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(list)
	})
	mux.HandleFunc("POST /decide", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID    string `json:"id"`
			Allow bool   `json:"allow"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		p.mu.Lock()
		h, ok := p.pending[req.ID]
		p.mu.Unlock()
		if !ok {
			http.Error(w, "no such hold", http.StatusNotFound)
			return
		}
		h.answer <- req.Allow
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	return mux
}

// ---------- helpers ----------

func (p *Proxy) findDecoys(text string) []string {
	var hits []string
	for _, d := range p.cfg.Decoys {
		if d != "" && strings.Contains(text, d) {
			hits = append(hits, d[:min(6, len(d))]+"…")
		}
	}
	return hits
}

func headerText(h http.Header) string {
	var b strings.Builder
	for k, vs := range h {
		for _, v := range vs {
			fmt.Fprintf(&b, "%s: %s\n", k, v)
		}
	}
	return b.String()
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

func joinDetail(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	default:
		return a + "; " + b
	}
}

// LoadDecoys reads the token list the host wrote for this run.
func LoadDecoys(file string) ([]string, error) {
	b, err := os.ReadFile(file)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var toks []string
	return toks, json.Unmarshal(b, &toks)
}
