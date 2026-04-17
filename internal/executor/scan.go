package executor

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Shasheen8/Spekto/internal/auth"
	"github.com/Shasheen8/Spekto/internal/config"
	"github.com/Shasheen8/Spekto/internal/inventory"
)

type ScanOptions struct {
	IncludeTargets []string
	ExcludeTargets []string
	AuthContexts   []string
	ResourceHints  config.ResourceHints
	// Registry is a pre-resolved auth registry. When non-nil it is used directly,
	// skipping internal registry construction and login-flow resolution so callers
	// that also need the registry (e.g. for rule scanning) only pay that cost once.
	Registry *auth.Registry
	// IncludeOperations scopes the scan to operations whose ID or locator matches
	// any of the given strings (substring match on locator). Empty = all operations.
	IncludeOperations []string
	// IncludeTags scopes the scan to operations carrying at least one of the given
	// tags (case-insensitive OR logic). Empty = all operations.
	IncludeTags []string
}

func Scan(ctx context.Context, cfg config.Config, inv inventory.Inventory, options ScanOptions) (Bundle, error) {
	startedAt := time.Now().UTC()
	targets, err := cfg.SelectTargetsFiltered(options.IncludeTargets, options.ExcludeTargets)
	if err != nil {
		return Bundle{}, err
	}
	if len(targets) == 0 {
		return Bundle{}, errors.New("scan requires at least one selected target")
	}

	var registry auth.Registry
	if options.Registry != nil {
		registry = *options.Registry
	} else {
		var err2 error
		registry, err2 = auth.NewRegistry(cfg)
		if err2 != nil {
			return Bundle{}, err2
		}
		loginClient := &http.Client{
			Timeout: cfg.Scan.Timeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		registry, err2 = registry.ResolveLoginFlows(ctx, loginClient)
		if err2 != nil {
			return Bundle{}, err2
		}
	}

	policy := NewHTTPPolicy(cfg.Scan)
	bundle := Bundle{StartedAt: startedAt}

	for _, target := range targets {
		operations := selectTargetOperations(inv.Operations, target, options.IncludeOperations, options.IncludeTags)
		switch target.Protocol {
		case "rest":
			results, err := scanRESTTarget(ctx, target, operations, registry, policy, options.AuthContexts, options.ResourceHints)
			if err != nil {
				return Bundle{}, err
			}
			bundle.Results = append(bundle.Results, results...)
		case "graphql":
			results, err := scanGraphQLTarget(ctx, target, operations, registry, policy, options.AuthContexts)
			if err != nil {
				return Bundle{}, err
			}
			bundle.Results = append(bundle.Results, results...)
		case "grpc":
			results, err := ExecuteGRPC(ctx, target, operations, registry, policy, options.AuthContexts)
			if err != nil {
				return Bundle{}, err
			}
			bundle.Results = append(bundle.Results, results...)
		default:
			return Bundle{}, fmt.Errorf("unsupported target protocol %q", target.Protocol)
		}
	}

	bundle.FinishedAt = time.Now().UTC()
	bundle.Finalize()
	return bundle, nil
}

func scanRESTTarget(ctx context.Context, target config.Target, operations []inventory.Operation, registry auth.Registry, policy HTTPPolicy, selectedAuthContexts []string, hints config.ResourceHints) ([]Result, error) {
	requests := make([]HTTPRequest, 0)
	requestMeta := map[string]inventory.Operation{}
	requestGaps := map[string][]string{}
	results := make([]Result, 0)

	for _, operation := range operations {
		authContextNames, skipResult, err := resolveAuthAssignments(operation, target, registry, selectedAuthContexts)
		if err != nil {
			return nil, err
		}
		if skipResult != nil {
			results = append(results, *skipResult)
			continue
		}
		built, err := buildRESTRequests(target.BaseURL, operation, authContextNames, hints)
		if err != nil {
			return nil, err
		}
		for _, request := range built {
			requests = append(requests, request)
			requestMeta[request.ID] = operation
			if len(request.SchemaGaps) > 0 {
				requestGaps[request.ID] = request.SchemaGaps
			}
		}
	}

	httpResults, err := ExecuteHTTP(ctx, &http.Client{Timeout: policy.Timeout}, requests, registry, policy)
	if err != nil {
		return nil, err
	}
	results = append(results, convertHTTPResults(target, requestMeta, requestGaps, httpResults)...)
	return results, nil
}

func scanGraphQLTarget(ctx context.Context, target config.Target, operations []inventory.Operation, registry auth.Registry, policy HTTPPolicy, selectedAuthContexts []string) ([]Result, error) {
	endpoint := target.Endpoint
	if strings.TrimSpace(endpoint) == "" {
		endpoint = target.BaseURL
	}
	requests := make([]HTTPRequest, 0)
	requestMeta := map[string]inventory.Operation{}
	results := make([]Result, 0)

	for _, operation := range operations {
		authContextNames, skipResult, err := resolveAuthAssignments(operation, target, registry, selectedAuthContexts)
		if err != nil {
			return nil, err
		}
		if skipResult != nil {
			results = append(results, *skipResult)
			continue
		}
		built, err := buildGraphQLRequests(endpoint, operation, authContextNames)
		if err != nil {
			results = append(results, failedProtocolResult(target, operation, "", endpoint, err))
			continue
		}
		for _, request := range built {
			requests = append(requests, request)
			requestMeta[request.ID] = operation
		}
	}

	httpResults, err := ExecuteHTTP(ctx, &http.Client{Timeout: policy.Timeout}, requests, registry, policy)
	if err != nil {
		return nil, err
	}
	results = append(results, convertHTTPResults(target, requestMeta, nil, httpResults)...)
	return results, nil
}

func convertHTTPResults(target config.Target, operations map[string]inventory.Operation, gaps map[string][]string, httpResults []HTTPResult) []Result {
	results := make([]Result, 0, len(httpResults))
	for _, httpResult := range httpResults {
		operation := operations[httpResult.RequestID]
		status := "failed"
		switch {
		case strings.HasPrefix(httpResult.Error, "skipped:"):
			status = "skipped"
		case httpResult.Error == "" && httpResult.StatusCode >= 200 && httpResult.StatusCode < 400:
			status = "succeeded"
		}
		r := Result{
			Protocol:        operation.Protocol,
			Target:          target.Name,
			OperationID:     httpResult.OperationID,
			Locator:         operation.Locator,
			DisplayName:     operation.DisplayName,
			AuthContextName: httpResult.AuthContextName,
			Status:          status,
			Error:           httpResult.Error,
			StartedAt:       httpResult.StartedAt,
			Duration:        httpResult.Duration,
			Evidence: Evidence{
				Request: RequestEvidence{
					Method:      httpResult.Method,
					URL:         httpResult.URL,
					Headers:     httpResult.RequestHeaders,
					ContentType: httpResult.RequestContentType,
					Body:        httpResult.RequestBody,
				},
				Response: ResponseEvidence{
					StatusCode: httpResult.StatusCode,
					Headers:    httpResult.ResponseHeaders,
					Body:       httpResult.ResponseBody,
					Truncated:  httpResult.Truncated,
				},
			},
		}
		if gaps != nil {
			r.SchemaGaps = gaps[httpResult.RequestID]
		}
		results = append(results, r)
	}
	return results
}

func selectTargetOperations(operations []inventory.Operation, target config.Target, includeOps, includeTags []string) []inventory.Operation {
	selected := make([]inventory.Operation, 0, len(operations))
	for _, operation := range operations {
		if string(operation.Protocol) != target.Protocol {
			continue
		}
		if len(operation.Targets) > 0 && !containsString(operation.Targets, target.Name) {
			continue
		}
		if len(includeOps) > 0 && !operationMatchesAny(operation, includeOps) {
			continue
		}
		if len(includeTags) > 0 && !operationHasAnyTag(operation, includeTags) {
			continue
		}
		selected = append(selected, operation)
	}
	return selected
}

// operationMatchesAny returns true when the operation ID equals any pattern,
// or the locator contains any pattern as a substring.
func operationMatchesAny(op inventory.Operation, patterns []string) bool {
	for _, p := range patterns {
		if op.ID == p || strings.Contains(op.Locator, p) {
			return true
		}
	}
	return false
}

// operationHasAnyTag returns true when the operation carries at least one of
// the given tags (case-insensitive).
func operationHasAnyTag(op inventory.Operation, tags []string) bool {
	for _, want := range tags {
		for _, have := range op.Tags {
			if strings.EqualFold(have, want) {
				return true
			}
		}
	}
	return false
}

func resolveAuthAssignments(operation inventory.Operation, target config.Target, registry auth.Registry, selectedAuthContexts []string) ([]string, *Result, error) {
	authContextNames, err := registry.CandidatesForTarget(operation.AuthHints, target, selectedAuthContexts)
	if err != nil {
		return nil, nil, err
	}
	if operation.AuthHints.RequiresAuth == inventory.AuthRequirementYes && len(authContextNames) == 0 {
		result := skippedProtocolResult(target, operation, "", "skipped: no matching auth context")
		return nil, &result, nil
	}
	return authContextNames, nil, nil
}

func skippedProtocolResult(target config.Target, operation inventory.Operation, authContextName string, message string) Result {
	return Result{
		Protocol:        operation.Protocol,
		Target:          target.Name,
		OperationID:     operation.ID,
		Locator:         operation.Locator,
		DisplayName:     operation.DisplayName,
		AuthContextName: authContextName,
		Status:          "skipped",
		Error:           message,
		StartedAt:       time.Now().UTC(),
	}
}

func failedProtocolResult(target config.Target, operation inventory.Operation, authContextName string, requestURL string, err error) Result {
	return Result{
		Protocol:        operation.Protocol,
		Target:          target.Name,
		OperationID:     operation.ID,
		Locator:         operation.Locator,
		DisplayName:     operation.DisplayName,
		AuthContextName: authContextName,
		Status:          "failed",
		Error:           err.Error(),
		StartedAt:       time.Now().UTC(),
		Evidence: Evidence{
			Request: RequestEvidence{
				URL: requestURL,
			},
		},
	}
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}
