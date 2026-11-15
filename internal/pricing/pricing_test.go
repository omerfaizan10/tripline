package pricing

import (
	"math"
	"testing"
)

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestCost(t *testing.T) {
	// 100K input of which 80K cached, 5K output on Astra:
	// 20K*10 + 80K*1 + 5K*50 = 200000+80000+250000 = 530000 per 1M => $0.53
	if c, ok := Cost("gpt-6-astra", 100_000, 80_000, 5_000); !ok || !near(c, 0.53) {
		t.Fatalf("astra cost = %v", c)
	}
	// Snapshot names resolve to their family.
	if _, ok := Lookup("gpt-6.1-sol-2026-09-29"); !ok {
		t.Fatal("dated snapshot should resolve")
	}
	// gpt-6-sol must not be confused with gpt-6.1-sol and vice versa.
	r, _ := Lookup("gpt-6-sol")
	if r.Cached != 0.20 {
		t.Fatalf("gpt-6-sol matched the wrong family: %+v", r)
	}
	// Over 272K input the whole request uses long-context rates.
	short, _ := Cost("gpt-6.1-sol", 272_000, 0, 0)
	long, _ := Cost("gpt-6.1-sol", 272_001, 0, 0)
	if !(long > short*1.9) {
		t.Fatalf("long-context surcharge not applied: %v vs %v", short, long)
	}
	if _, ok := Cost("unknown-model", 1, 0, 1); ok {
		t.Fatal("unknown models must report no price rather than $0")
	}
}
