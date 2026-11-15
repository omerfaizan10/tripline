// Package pricing turns metered tokens into dollars.
//
// Rates are OpenAI's standard API prices per 1M tokens as published on
// https://developers.openai.com/api/docs/pricing (read 2026-11-15). Requests
// with more than 272K input tokens are billed at the long-context rates for
// the whole request.
package pricing

import "strings"

// Rate is dollars per 1M tokens.
type Rate struct {
	In, Cached, Out             float64 // short context (<= 272K input tokens)
	LongIn, LongCached, LongOut float64
}

// Source is cited wherever costs are shown.
const Source = "OpenAI API standard pricing, developers.openai.com/api/docs/pricing, read 2026-11-15"

const longContext = 272_000

var rates = map[string]Rate{
	"gpt-6-astra":   {10, 1, 50, 20, 2, 75},
	"gpt-6.1-sol":   {2, 0.10, 10, 4, 0.20, 15},
	"gpt-6.1-terra": {1, 0.05, 5, 2, 0.10, 7.5},
	"gpt-6-sol":     {2, 0.20, 10, 4, 0.40, 15},
	"gpt-6-luna":    {0.10, 0.01, 0.50, 0.20, 0.02, 0.75},
	"gpt-5.3-codex": {1.75, 0.175, 14, 1.75, 0.175, 14},
}

// Lookup finds the rate for a model, accepting dated snapshot names such as
// gpt-6-astra-2026-08-14. The longest matching prefix wins.
func Lookup(model string) (Rate, bool) {
	best, found := "", false
	for name := range rates {
		if (model == name || strings.HasPrefix(model, name+"-")) && len(name) > len(best) {
			best, found = name, true
		}
	}
	return rates[best], found
}

// Cost prices one request. in includes the cached tokens.
func Cost(model string, in, cached, out int) (float64, bool) {
	r, ok := Lookup(model)
	if !ok {
		return 0, false
	}
	if cached > in {
		cached = in
	}
	pin, pc, pout := r.In, r.Cached, r.Out
	if in > longContext {
		pin, pc, pout = r.LongIn, r.LongCached, r.LongOut
	}
	return (float64(in-cached)*pin + float64(cached)*pc + float64(out)*pout) / 1e6, true
}
