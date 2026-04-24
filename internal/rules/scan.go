package rules

import (
	"context"
	"net/http"

	"github.com/Shasheen8/Spekto/internal/auth"
	"github.com/Shasheen8/Spekto/internal/executor"
	"github.com/Shasheen8/Spekto/internal/inventory"
)

// ScanOptions configures rule-based scanning.
type ScanOptions struct {
	// MaxProbesPerSeed caps the number of probe requests sent per seed result
	// across all rules. Zero uses the default of 50.
	MaxProbesPerSeed int
}

// Scan runs each rule against every successful REST seed result and returns
// all confirmed findings. Probe requests are executed via the same HTTP
// execution layer used for seeding, respecting the supplied policy limits.
func Scan(ctx context.Context, seeds []executor.Result, registry auth.Registry, rules []Rule, policy executor.HTTPPolicy, opts ScanOptions) ([]Finding, error) {
	if len(rules) == 0 || len(seeds) == 0 {
		return nil, nil
	}
	maxProbes := opts.MaxProbesPerSeed
	if maxProbes <= 0 {
		maxProbes = 100
	}

	client := &http.Client{
		Timeout: policy.Timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var allFindings []Finding

	for _, seed := range seeds {
		if seed.Status != "succeeded" {
			continue
		}
		// Apply rules to REST and GraphQL — both use HTTP transport.
		// gRPC has a distinct execution model and is handled separately.
		if seed.Protocol != inventory.ProtocolREST && seed.Protocol != inventory.ProtocolGraphQL {
			continue
		}

		// Resolve auth context so rules can inspect the actual token values.
		authCtx := auth.Context{}
		if seed.AuthContextName != "" {
			if v, ok := registry.Get(seed.AuthContextName); ok {
				authCtx = v
			}
		}

		// Collect immediate findings and probes from all rules.
		var pendingProbes []Probe
		for _, rule := range rules {
			probes, findings := rule.Check(seed, authCtx)
			allFindings = append(allFindings, findings...)
			pendingProbes = append(pendingProbes, probes...)
		}

		if len(pendingProbes) == 0 {
			continue
		}
		if len(pendingProbes) > maxProbes {
			pendingProbes = pendingProbes[:maxProbes]
		}

		requests := make([]executor.HTTPRequest, len(pendingProbes))
		for i, p := range pendingProbes {
			requests[i] = p.Request
		}

		results, err := executor.ExecuteHTTP(ctx, client, requests, registry, policy)
		if err != nil {
			return nil, err
		}

		for i, result := range results {
			if i < len(pendingProbes) {
				allFindings = append(allFindings, pendingProbes[i].Evaluate(result)...)
			}
		}
	}

	return allFindings, nil
}
