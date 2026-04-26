package executor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
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
	Budget      *RequestBudget
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
	if err := validateTargetAllowlist(cfg.Scan.TargetAllowlist, targets); err != nil {
		return Bundle{}, err
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
	if options.Budget != nil {
		policy.Budget = options.Budget
	}
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
			results, err := scanGraphQLTarget(ctx, target, operations, registry, policy, options.AuthContexts, options.ResourceHints)
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
		if !policy.AllowWrite && operation.REST != nil && !isReadOnlyHTTPMethod(operation.REST.Method) {
			results = append(results, skippedProtocolResult(target, operation, "", "skipped: mutating operation requires explicit write opt-in"))
			continue
		}
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

func scanGraphQLTarget(ctx context.Context, target config.Target, operations []inventory.Operation, registry auth.Registry, policy HTTPPolicy, selectedAuthContexts []string, hints config.ResourceHints) ([]Result, error) {
	endpoint := target.Endpoint
	if strings.TrimSpace(endpoint) == "" {
		endpoint = target.BaseURL
	}
	requests := make([]HTTPRequest, 0)
	requestMeta := map[string]inventory.Operation{}
	results := make([]Result, 0)

	for _, operation := range operations {
		if !policy.AllowWrite && operation.GraphQL != nil && strings.EqualFold(operation.GraphQL.RootKind, "mutation") {
			results = append(results, skippedProtocolResult(target, operation, "", "skipped: mutating operation requires explicit write opt-in"))
			continue
		}
		authContextNames, skipResult, err := resolveAuthAssignments(operation, target, registry, selectedAuthContexts)
		if err != nil {
			return nil, err
		}
		if skipResult != nil {
			results = append(results, *skipResult)
			continue
		}
		built, err := buildGraphQLRequests(endpoint, operation, authContextNames, hints)
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
		if len(operation.Targets) > 0 && !targetValuesMatch(operation.Targets, target) {
			continue
		}
		if !operation.Provenance.Specified && len(operation.Origins) > 0 && !targetValuesMatch(operation.Origins, target) {
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

func targetValuesMatch(values []string, target config.Target) bool {
	targetValues := []string{target.Name}
	if raw := strings.TrimSpace(target.BaseURL); raw != "" {
		targetValues = append(targetValues, raw)
	}
	if raw := strings.TrimSpace(target.Endpoint); raw != "" {
		targetValues = append(targetValues, raw)
	}
	if origin := targetOrigin(target); origin != "" {
		targetValues = append(targetValues, origin)
	}
	for _, operationTarget := range values {
		for _, targetValue := range targetValues {
			if strings.EqualFold(strings.TrimRight(operationTarget, "/"), strings.TrimRight(targetValue, "/")) {
				return true
			}
		}
	}
	return false
}

func targetOrigin(target config.Target) string {
	rawURL := strings.TrimSpace(target.BaseURL)
	if rawURL == "" {
		rawURL = strings.TrimSpace(target.Endpoint)
	}
	if rawURL == "" {
		return ""
	}
	if !strings.Contains(rawURL, "://") {
		return ""
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
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

func isReadOnlyHTTPMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

// validateTargetAllowlist rejects any target whose host is not covered by the
// allowlist. An empty allowlist permits all targets.
func validateTargetAllowlist(allowlist []string, targets []config.Target) error {
	if len(allowlist) == 0 {
		return nil
	}
	for _, t := range targets {
		host := targetHost(t)
		if host == "" {
			continue
		}
		if !hostAllowed(host, allowlist) {
			return fmt.Errorf("target %q host %q is not in scan.target_allowlist", t.Name, host)
		}
	}
	return nil
}

// targetHost extracts the hostname from a target's base_url or endpoint.
func targetHost(t config.Target) string {
	if ep := strings.TrimSpace(t.Endpoint); ep != "" {
		if strings.Contains(ep, "://") {
			if parsed, err := url.Parse(ep); err == nil {
				return parsed.Hostname()
			}
		}
		if host, _, err := net.SplitHostPort(ep); err == nil {
			return host
		}
		return ep
	}
	if base := strings.TrimSpace(t.BaseURL); base != "" {
		if parsed, err := url.Parse(base); err == nil {
			return parsed.Hostname()
		}
	}
	return ""
}

// hostAllowed returns true when host matches any allowlist pattern.
// Patterns may be exact hostnames or wildcard prefixes (*.example.com).
func hostAllowed(host string, allowlist []string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	for _, pattern := range allowlist {
		p := strings.ToLower(strings.TrimSpace(pattern))
		if p == "" {
			continue
		}
		if strings.HasPrefix(p, "*.") {
			suffix := p[1:] // e.g. ".example.com"
			if strings.HasSuffix(host, suffix) || host == p[2:] {
				return true
			}
		} else if host == p {
			return true
		}
	}
	return false
}
