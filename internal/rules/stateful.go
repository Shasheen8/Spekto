package rules

import (
	"context"
	"net/http"
	"strings"

	"github.com/Shasheen8/Spekto/internal/auth"
	"github.com/Shasheen8/Spekto/internal/executor"
	"github.com/Shasheen8/Spekto/internal/inventory"
)

// StatefulOptions configures stateful authorization scanning.
type StatefulOptions struct {
	// AllowWriteChecks enables BFLA probes on mutating methods (POST, PUT, PATCH, DELETE).
	// Disabled by default to prevent unintended data modification on scan targets.
	AllowWriteChecks bool
	// MaxProbes caps the total number of cross-context probe requests across all operations.
	// Zero uses the default of 100.
	MaxProbes int
}

// StatefulScan runs cross-auth-context authorization checks against successful REST seeds.
// It is opt-in and requires at least two distinct auth contexts in the registry.
//
// Rules applied:
//
//	BOLA001 – broken object-level authorization: alternative auth context reads the same resource
//	BFLA001 – broken function-level authorization: alternative auth context executes a privileged write
//
// Confidence is Medium for both rules because the scanner cannot determine whether two
// auth contexts are intended to have different access rights — that judgement is the operator's.
// Configure distinct named auth contexts (e.g. admin + user) to produce actionable findings.
func StatefulScan(ctx context.Context, seeds []executor.Result, registry auth.Registry, policy executor.HTTPPolicy, opts StatefulOptions) ([]Finding, error) {
	if len(registry.Contexts) < 2 {
		return nil, nil
	}

	maxProbes := opts.MaxProbes
	if maxProbes <= 0 {
		maxProbes = 100
	}

	type probeSpec struct {
		seed     executor.Result
		altName  string
		readOnly bool
	}

	var specs []probeSpec
	probed := map[string]bool{}
	budget := maxProbes

outer:
	for _, seed := range seeds {
		if seed.Status != "succeeded" || seed.Protocol != inventory.ProtocolREST {
			continue
		}
		if seed.AuthContextName == "" {
			// Seed was not authenticated — cross-context comparison is meaningless.
			continue
		}

		method := strings.ToUpper(seed.Evidence.Request.Method)
		readOnly := method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions

		if !readOnly && !opts.AllowWriteChecks {
			// Write probes are explicitly opt-in.
			continue
		}

		for _, altCtx := range registry.Contexts {
			if budget <= 0 {
				break outer
			}
			if altCtx.Name == seed.AuthContextName {
				continue
			}
			key := seed.OperationID + ":" + seed.AuthContextName + ":" + altCtx.Name + ":" + seed.Evidence.Request.URL
			if probed[key] {
				continue
			}
			probed[key] = true
			budget--
			specs = append(specs, probeSpec{seed: seed, altName: altCtx.Name, readOnly: readOnly})
		}
	}

	if len(specs) == 0 {
		return nil, nil
	}

	// Build all probe requests and execute in one batch under the existing policy.
	requests := make([]executor.HTTPRequest, len(specs))
	for i, spec := range specs {
		s := spec.seed
		requests[i] = executor.HTTPRequest{
			ID:              s.OperationID + ":stateful:" + spec.altName,
			OperationID:     s.OperationID,
			Method:          s.Evidence.Request.Method,
			URL:             s.Evidence.Request.URL,
			Body:            s.Evidence.Request.Body,
			ContentType:     s.Evidence.Request.ContentType,
			AuthContextName: spec.altName,
		}
	}

	results, err := executor.ExecuteHTTP(ctx, nil, requests, registry, policy)
	if err != nil {
		return nil, err
	}

	var allFindings []Finding
	for i, result := range results {
		if i >= len(specs) {
			break
		}
		spec := specs[i]
		seed := spec.seed

		if !probeSucceeded(result) {
			continue
		}

		if spec.readOnly {
			allFindings = append(allFindings, newFinding(
				"BOLA001", SeverityHigh, ConfidenceMedium,
				"Broken Object Level Authorization",
				"Auth context '"+spec.altName+"' can access the same resource as '"+seed.AuthContextName+"' at '"+seed.Locator+"'. Verify that these contexts should have different object-level access rights.",
				seed,
				FindingEvidence{Seed: seed.Evidence, Probe: probeEvidence(result)},
				"API1:2023 Broken Object Level Authorization", 285,
				"Enforce object-level authorization on every request. Verify the requesting identity owns or is explicitly permitted to access the specific resource instance, not just the resource type.",
			))
		} else {
			allFindings = append(allFindings, newFinding(
				"BFLA001", SeverityHigh, ConfidenceMedium,
				"Broken Function Level Authorization",
				"Auth context '"+spec.altName+"' can execute the "+seed.Evidence.Request.Method+" operation at '"+seed.Locator+"' that was seeded with '"+seed.AuthContextName+"'.",
				seed,
				FindingEvidence{Seed: seed.Evidence, Probe: probeEvidence(result)},
				"API5:2023 Broken Function Level Authorization", 285,
				"Enforce role-based authorization on every operation. Restrict mutating and administrative operations to identities that are explicitly authorized for that function.",
			))
		}
	}

	return allFindings, nil
}
