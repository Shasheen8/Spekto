package executor

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/Shasheen8/Spekto/internal/config"
	"github.com/Shasheen8/Spekto/internal/inventory"
	"github.com/Shasheen8/Spekto/internal/seed"
)

func buildRESTRequests(targetBaseURL string, operation inventory.Operation, authContextNames []string, hints config.ResourceHints) ([]HTTPRequest, error) {
	if operation.REST == nil {
		return nil, fmt.Errorf("rest operation %q is missing rest details", operation.ID)
	}
	candidate := seed.GenerateRESTCandidate(operation, hints)
	requestURL, err := resolveRESTURL(targetBaseURL, operation.REST.NormalizedPath, candidate.PathValues, candidate.QueryValues)
	if err != nil {
		return nil, err
	}
	method := strings.ToUpper(strings.TrimSpace(operation.REST.Method))
	if method == "" {
		method = http.MethodGet
	}
	assignments := authAssignments(authContextNames)
	requests := make([]HTTPRequest, 0, len(assignments))
	for _, authContextName := range assignments {
		requests = append(requests, HTTPRequest{
			ID:              requestExecutionID(operation.ID, authContextName),
			OperationID:     operation.ID,
			Method:          method,
			URL:             requestURL,
			Body:            candidate.Body,
			ContentType:     candidate.ContentType,
			AuthContextName: authContextName,
			SchemaGaps:      candidate.SchemaGaps,
		})
	}
	return requests, nil
}

func buildGraphQLRequests(endpoint string, operation inventory.Operation, authContextNames []string) ([]HTTPRequest, error) {
	if operation.GraphQL == nil {
		return nil, fmt.Errorf("graphql operation %q is missing graphql details", operation.ID)
	}
	if operation.GraphQL.RootKind == "subscription" {
		return nil, fmt.Errorf("subscriptions are not supported by the phase 2 graphql adapter")
	}
	query := graphqlQuery(operation)
	body, err := json.Marshal(map[string]string{"query": query})
	if err != nil {
		return nil, err
	}
	assignments := authAssignments(authContextNames)
	requests := make([]HTTPRequest, 0, len(assignments))
	for _, authContextName := range assignments {
		requests = append(requests, HTTPRequest{
			ID:              requestExecutionID(operation.ID, authContextName),
			OperationID:     operation.ID,
			Method:          http.MethodPost,
			URL:             endpoint,
			Body:            body,
			ContentType:     "application/json",
			AuthContextName: authContextName,
		})
	}
	return requests, nil
}

// resolveRESTURL constructs the full request URL from a base URL, path template,
// and resolved path/query parameter maps.
func resolveRESTURL(baseURL, normalizedPath string, pathValues, queryValues map[string]string) (string, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	joined := normalizedPath
	if joined == "" {
		joined = "/"
	}
	replaced := joined
	for name, value := range pathValues {
		replaced = strings.ReplaceAll(replaced, "{"+name+"}", url.PathEscape(value))
	}
	parsed.Path = path.Join(strings.TrimSuffix(parsed.Path, "/"), strings.TrimPrefix(replaced, "/"))
	if strings.HasSuffix(replaced, "/") && !strings.HasSuffix(parsed.Path, "/") {
		parsed.Path += "/"
	}
	if len(queryValues) > 0 {
		q := parsed.Query()
		for name, value := range queryValues {
			q.Set(name, value)
		}
		parsed.RawQuery = q.Encode()
	}
	return parsed.String(), nil
}

func graphqlQuery(operation inventory.Operation) string {
	rootKind := operation.GraphQL.RootKind
	name := operation.GraphQL.OperationName
	if name == "" {
		name = operation.DisplayName
	}
	args := make([]string, 0, len(operation.GraphQL.ArgumentMap))
	for _, arg := range operation.GraphQL.ArgumentMap {
		parts := strings.SplitN(arg, ":", 2)
		if len(parts) != 2 {
			continue
		}
		args = append(args, fmt.Sprintf("%s: %s", parts[0], graphqlLiteral(parts[1])))
	}
	argString := ""
	if len(args) > 0 {
		argString = "(" + strings.Join(args, ", ") + ")"
	}
	selectionHints := operation.GraphQL.SelectionHints
	if len(selectionHints) == 0 {
		return fmt.Sprintf("%s { %s%s }", rootKind, name, argString)
	}
	selection := strings.Join(selectionHints, " ")
	return fmt.Sprintf("%s { %s%s { %s } }", rootKind, name, argString, selection)
}

func graphqlLiteral(typeName string) string {
	normalized := strings.TrimSpace(typeName)
	normalized = strings.TrimSuffix(normalized, "!")
	normalized = strings.TrimPrefix(normalized, "[")
	normalized = strings.TrimSuffix(normalized, "]")
	switch normalized {
	case "Int":
		return "1"
	case "Float":
		return "1.0"
	case "Boolean":
		return "true"
	case "ID", "String":
		return `"sample"`
	default:
		return `"sample"`
	}
}

func requestExecutionID(operationID string, authContextName string) string {
	if authContextName == "" {
		return operationID
	}
	return operationID + ":" + authContextName
}

func authAssignments(names []string) []string {
	if len(names) == 0 {
		return []string{""}
	}
	return append([]string(nil), names...)
}

