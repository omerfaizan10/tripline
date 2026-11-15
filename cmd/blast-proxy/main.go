// blast-proxy runs in its own container, on both the sandbox's private
// network and a network with internet access. It is the only way out.
//
// The model API key is read from this container's environment; the sandbox
// container never receives it.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/omerfaizan10/blast-radius/internal/policy"
	"github.com/omerfaizan10/blast-radius/internal/proxy"
)

func main() {
	polFile := flag.String("policy", "/blast/policy.json", "expanded policy (JSON)")
	decoyFile := flag.String("decoys", "/blast/decoys.json", "decoy secret values (JSON list)")
	logFile := flag.String("log", "/blast/out/proxy.jsonl", "event log")
	askTimeout := flag.Duration("ask-timeout", 2*time.Minute, "ask mode: deny after this long")
	flag.Parse()

	b, err := os.ReadFile(*polFile)
	if err != nil {
		log.Fatal(err)
	}
	var pol policy.Policy
	if err := json.Unmarshal(b, &pol); err != nil {
		log.Fatal(err)
	}
	decoys, err := proxy.LoadDecoys(*decoyFile)
	if err != nil {
		log.Fatal(err)
	}
	out, err := os.OpenFile(*logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		log.Fatal(err)
	}
	defer out.Close()

	upstream := os.Getenv("BLAST_MODEL_UPSTREAM")
	if upstream == "" {
		upstream = "https://api.openai.com"
	}
	p := proxy.New(proxy.Config{
		Policy:        &pol,
		Decoys:        decoys,
		ModelUpstream: upstream,
		ModelKey:      os.Getenv("OPENAI_API_KEY"),
		AskTimeout:    *askTimeout,
		Log:           out,
	})

	servers := []*http.Server{
		{Addr: ":3128", Handler: p.EgressHandler(), ReadHeaderTimeout: 30 * time.Second},
		{Addr: ":8081", Handler: p.GatewayHandler(), ReadHeaderTimeout: 30 * time.Second},
		{Addr: ":8090", Handler: p.ControlHandler(), ReadHeaderTimeout: 10 * time.Second},
	}
	for _, s := range servers {
		go func(s *http.Server) {
			if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("%s: %v", s.Addr, err)
			}
		}(s)
	}
	log.Printf("blast-proxy: mode=%s hosts=%d decoys=%d gateway=%v", pol.Mode, len(pol.Network.AllowHosts), len(decoys), os.Getenv("OPENAI_API_KEY") != "")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(ctx)
	}
	_ = out.Sync()
}
