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

	registry, err := auth.NewRegistry(cfg)
	if err != nil {
		return Bundle{}, err
	}
	loginClient := &http.Client{
		Timeout: cfg.Scan.Timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	registry, err = registry.ResolveLoginFlows(ctx, loginClient)
	if err != nil {
		return Bundle{}, err
	}

	policy := NewHTTPPolicy(cfg.Scan)
	bundle := Bundle{StartedAt: startedAt}

	for _, target := range targets {
		operations := selectTargetOperations(inv.Operations, target)
		switch target.Protocol {
		case "rest":
			results, err := scanRESTTarget(ctx, target, operations, registry, policy, options.AuthContexts)
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

func scanRESTTarget(ctx context.Context, target config.Target, operations []inventory.Operation, registry auth.Registry, policy HTTPPolicy, selectedAuthContexts []string) ([]Result, error) {
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
		built, err := buildRESTRequests(target.BaseURL, operation, authContextNames)
		if err != nil {
			return nil, err
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
	results = append(results, convertHTTPResults(target, requestMeta, httpResults)...)
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
	results = append(results, convertHTTPResults(target, requestMeta, httpResults)...)
	return results, nil
}

func convertHTTPResults(target config.Target, operations map[string]inventory.Operation, httpResults []HTTPResult) []Result {
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
		results = append(results, Result{
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
					ContentType: httpResult.RequestHeaders["Content-Type"],
				},
				Response: ResponseEvidence{
					StatusCode: httpResult.StatusCode,
					Headers:    httpResult.ResponseHeaders,
					Body:       httpResult.ResponseBody,
					Truncated:  httpResult.Truncated,
				},
			},
		})
	}
	return results
}

func selectTargetOperations(operations []inventory.Operation, target config.Target) []inventory.Operation {
	selected := make([]inventory.Operation, 0, len(operations))
	for _, operation := range operations {
		if string(operation.Protocol) != target.Protocol {
			continue
		}
		if len(operation.Targets) > 0 && !containsString(operation.Targets, target.Name) {
			continue
		}
		selected = append(selected, operation)
	}
	return selected
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
