package executor

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/Shasheen8/Spekto/internal/inventory"
)

func buildRESTRequests(targetBaseURL string, operation inventory.Operation, authContextNames []string) ([]HTTPRequest, error) {
	if operation.REST == nil {
		return nil, fmt.Errorf("rest operation %q is missing rest details", operation.ID)
	}

	requestURL, err := resolveRESTURL(targetBaseURL, operation.REST.NormalizedPath, operation.REST.PathParams, operation.REST.QueryParams, operation.Examples)
	if err != nil {
		return nil, err
	}
	method := strings.ToUpper(strings.TrimSpace(operation.REST.Method))
	if method == "" {
		method = http.MethodGet
	}
	body, contentType := restBody(operation)

	assignments := authAssignments(authContextNames)
	requests := make([]HTTPRequest, 0, len(assignments))
	for _, authContextName := range assignments {
		requests = append(requests, HTTPRequest{
			ID:              requestExecutionID(operation.ID, authContextName),
			OperationID:     operation.ID,
			Method:          method,
			URL:             requestURL,
			Body:            body,
			ContentType:     contentType,
			AuthContextName: authContextName,
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

func resolveRESTURL(baseURL string, normalizedPath string, pathParams []inventory.ParameterMeta, queryParams []inventory.ParameterMeta, examples inventory.Examples) (string, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	joinedPath := normalizedPath
	if joinedPath == "" {
		joinedPath = "/"
	}
	replacedPath := joinedPath
	for _, param := range pathParams {
		replacedPath = strings.ReplaceAll(replacedPath, "{"+param.Name+"}", url.PathEscape(restParameterValue(param, examples)))
	}
	parsed.Path = path.Join(strings.TrimSuffix(parsed.Path, "/"), strings.TrimPrefix(replacedPath, "/"))
	if strings.HasSuffix(replacedPath, "/") && !strings.HasSuffix(parsed.Path, "/") {
		parsed.Path += "/"
	}

	query := parsed.Query()
	for _, param := range queryParams {
		query.Set(param.Name, restParameterValue(param, examples))
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func restParameterValue(param inventory.ParameterMeta, examples inventory.Examples) string {
	for _, example := range examples.Parameters {
		if example.Name != param.Name || !strings.EqualFold(example.In, param.In) {
			continue
		}
		switch {
		case strings.TrimSpace(example.Example) != "":
			return example.Example
		case strings.TrimSpace(example.Default) != "":
			return example.Default
		}
	}
	if strings.TrimSpace(param.Default) != "" {
		return param.Default
	}
	switch strings.ToLower(param.Type) {
	case "int", "integer":
		return "1"
	case "number", "float", "double":
		return "1.0"
	case "boolean":
		return "true"
	default:
		return "sample"
	}
}

func restBody(operation inventory.Operation) ([]byte, string) {
	if len(operation.Examples.RequestBodies) > 0 {
		example := operation.Examples.RequestBodies[0]
		return []byte(example.Value), defaultString(example.MediaType, "application/json")
	}
	if operation.REST == nil || operation.REST.RequestBody == nil || len(operation.REST.RequestBody.Content) == 0 {
		return nil, ""
	}
	content := operation.REST.RequestBody.Content[0]
	if strings.Contains(strings.ToLower(content.MediaType), "json") {
		return []byte("{}"), defaultString(content.MediaType, "application/json")
	}
	return nil, content.MediaType
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

func defaultString(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
