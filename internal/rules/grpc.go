package rules

import (
	"context"
	"fmt"
	"strings"

	"github.com/Shasheen8/Spekto/internal/auth"
	"github.com/Shasheen8/Spekto/internal/config"
	"github.com/Shasheen8/Spekto/internal/executor"
	"github.com/Shasheen8/Spekto/internal/inventory"
)

// GRPCScan runs gRPC-specific security checks against the scan bundle results.
// It is called separately from Scan because gRPC probes require a distinct
// execution path (dynamic gRPC invocation rather than HTTP).
//
// Rules applied:
//
//	GRPC001 – unauthenticated method access
//	GRPC002 – invalid auth metadata accepted
//	GRPC003 – server reflection accessible without authentication
//	GRPC004 – error response contains internal implementation details
func GRPCScan(ctx context.Context, seeds []executor.Result, targets []config.Target, registry auth.Registry, policy executor.HTTPPolicy) ([]Finding, error) {
	if len(seeds) == 0 {
		return nil, nil
	}

	targetByName := make(map[string]config.Target, len(targets))
	for _, t := range targets {
		targetByName[t.Name] = t
	}

	// GRPC003 is probed once per unique endpoint, not once per seed.
	reflectionChecked := map[string]bool{}

	var allFindings []Finding

	for _, seed := range seeds {
		if seed.Protocol != inventory.ProtocolGRPC {
			continue
		}
		target, ok := targetByName[seed.Target]
		if !ok {
			continue
		}

		// GRPC004: static analysis — applies to all results including failures.
		allFindings = append(allFindings, grpcErrorLeakage(seed)...)

		if seed.Status != "succeeded" {
			continue
		}

		// GRPC003: once per endpoint.
		endpoint := strings.TrimSpace(target.Endpoint)
		if !reflectionChecked[endpoint] {
			reflectionChecked[endpoint] = true
			allFindings = append(allFindings, grpcReflectionExposed(ctx, seed, target)...)
		}

		if seed.AuthContextName == "" {
			continue
		}

		// GRPC001 and GRPC002 require auth to have been used on the seed.
		allFindings = append(allFindings, grpcUnauthAccess(ctx, seed, target, policy)...)
		allFindings = append(allFindings, grpcInvalidAuth(ctx, seed, target, policy)...)
	}

	return allFindings, nil
}

// grpcUnauthAccess (GRPC001) tries the same method without any credentials.
func grpcUnauthAccess(ctx context.Context, seed executor.Result, target config.Target, policy executor.HTTPPolicy) []Finding {
	svc, method, ok := splitGRPCLocator(seed.Evidence.Request.GRPCMethod)
	if !ok {
		return nil
	}
	code, _, _ := executor.ProbeGRPCMethod(ctx, target, svc, method, nil, policy)
	if code != "OK" {
		return nil
	}
	return []Finding{newFinding(
		"GRPC001", SeverityHigh, ConfidenceHigh,
		"gRPC method accessible without authentication",
		fmt.Sprintf("The gRPC method %s/%s returned OK with no authentication credentials.", svc, method),
		seed,
		FindingEvidence{Seed: seed.Evidence},
		"API2:2023 Broken Authentication", 287,
		"Require authentication on all gRPC methods. Apply a server-side auth interceptor rather than checking credentials per-handler.",
	)}
}

// grpcInvalidAuth (GRPC002) sends an obviously invalid bearer token.
func grpcInvalidAuth(ctx context.Context, seed executor.Result, target config.Target, policy executor.HTTPPolicy) []Finding {
	svc, method, ok := splitGRPCLocator(seed.Evidence.Request.GRPCMethod)
	if !ok {
		return nil
	}
	invalidMeta := map[string]string{"authorization": "Bearer INVALID.GRPC.TOKEN"}
	code, _, _ := executor.ProbeGRPCMethod(ctx, target, svc, method, invalidMeta, policy)
	if code != "OK" {
		return nil
	}
	return []Finding{newFinding(
		"GRPC002", SeverityHigh, ConfidenceHigh,
		"gRPC method accepts invalid authentication",
		fmt.Sprintf("The gRPC method %s/%s returned OK with an invalid bearer token.", svc, method),
		seed,
		FindingEvidence{Seed: seed.Evidence},
		"API2:2023 Broken Authentication", 287,
		"Validate authentication tokens on every gRPC call. Reject malformed or unrecognised credentials.",
	)}
}

// grpcReflectionExposed (GRPC003) tests whether reflection is accessible without auth.
func grpcReflectionExposed(ctx context.Context, seed executor.Result, target config.Target) []Finding {
	services, err := executor.ProbeGRPCReflection(ctx, target)
	if err != nil || len(services) == 0 {
		return nil
	}
	return []Finding{newFinding(
		"GRPC003", SeverityMedium, ConfidenceHigh,
		"gRPC server reflection accessible without authentication",
		fmt.Sprintf("gRPC server reflection returned %d service(s) without authentication, exposing the full service schema.", len(services)),
		seed,
		FindingEvidence{Seed: seed.Evidence},
		"API7:2023 Security Misconfiguration", 200,
		"Disable gRPC server reflection in production or restrict it to authenticated callers.",
	)}
}

// leakageSignals are patterns that suggest internal implementation details in
// gRPC error messages or response bodies. Conservative set to limit false positives.
var leakageSignals = []string{
	"goroutine ", ".go:", "panic:", "runtime error:",
	"stack trace", "/home/", "/root/", "/var/app/", "/tmp/",
}

// grpcErrorLeakage (GRPC004) checks whether the error or response body contains
// patterns that suggest internal implementation details.
func grpcErrorLeakage(seed executor.Result) []Finding {
	combined := strings.ToLower(seed.Error + " " + string(seed.Evidence.Response.Body))
	for _, signal := range leakageSignals {
		if strings.Contains(combined, signal) {
			return []Finding{newFinding(
				"GRPC004", SeverityMedium, ConfidenceMedium,
				"gRPC response leaks internal implementation details",
				"The gRPC response contains a pattern suggesting internal details: '"+signal+"'. This may disclose stack traces, file paths, or infrastructure information.",
				seed,
				FindingEvidence{Seed: seed.Evidence},
				"API7:2023 Security Misconfiguration", 209,
				"Return only generic error messages in production. Use gRPC status codes and strip internal detail from error descriptions.",
			)}
		}
	}
	return nil
}

// splitGRPCLocator parses a gRPC method locator of the form
// "package.ServiceName/MethodName" or "ServiceName/MethodName".
func splitGRPCLocator(locator string) (service, method string, ok bool) {
	parts := strings.SplitN(strings.TrimSpace(locator), "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}
