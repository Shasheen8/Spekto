package active

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/Shasheen8/Spekto/internal/inventory"
	graphqldiscovery "github.com/Shasheen8/Spekto/internal/protocol/graphql"
	restdiscovery "github.com/Shasheen8/Spekto/internal/protocol/rest"
)

var specPaths = []string{
	"/openapi.json",
	"/openapi.yaml",
	"/swagger.json",
	"/swagger.yaml",
	"/swagger/v1/swagger.json",
	"/api/openapi.json",
}

var graphQLPaths = []string{
	"/graphql",
	"/query",
	"/api/graphql",
}

var introspectionBody = []byte(`{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { kind name fields(includeDeprecated: true) { name args { name type { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } type { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }"}`)

type HTTPDocument struct {
	Operations []inventory.Operation
	Warnings   []string
}

func DiscoverHTTPTarget(ctx context.Context, client *http.Client, baseURL string) (*HTTPDocument, error) {
	normalized, err := normalizeBaseURL(baseURL)
	if err != nil {
		return nil, err
	}

	var operationSets [][]inventory.Operation
	var warnings []string

	for _, candidate := range specPaths {
		discoveredURL, data, ok, err := fetchSpecCandidate(ctx, client, normalized, candidate)
		if err != nil {
			warnings = append(warnings, err.Error())
			continue
		}
		if !ok {
			continue
		}
		doc, err := restdiscovery.ParseData(ctx, data, discoveredURL)
		if err != nil {
			continue
		}
		operationSets = append(operationSets, markActiveOperations(doc.Operations, discoveredURL, doc.SourceRef.ParserFamily, doc.SourceRef.SupportLevel, doc.SourceRef.Warnings))
		break
	}

	for _, candidate := range graphQLPaths {
		discoveredURL, data, ok, err := fetchGraphQLCandidate(ctx, client, normalized, candidate)
		if err != nil {
			warnings = append(warnings, err.Error())
			continue
		}
		if !ok {
			continue
		}
		doc, err := graphqldiscovery.ParseData(data, discoveredURL)
		if err != nil {
			continue
		}
		operationSets = append(operationSets, markActiveOperations(doc.Operations, discoveredURL, doc.SourceRef.ParserFamily, doc.SourceRef.SupportLevel, doc.SourceRef.Warnings))
		break
	}

	merged := inventory.Merge(operationSets...)
	return &HTTPDocument{
		Operations: merged.Operations,
		Warnings:   warnings,
	}, nil
}

func fetchSpecCandidate(ctx context.Context, client *http.Client, base *url.URL, path string) (string, []byte, bool, error) {
	targetURL := resolveProbeURL(base, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return "", nil, false, err
	}
	req.Header.Set("Accept", "application/json, application/yaml, text/yaml, application/x-yaml")
	resp, err := client.Do(req)
	if err != nil {
		return targetURL, nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return targetURL, nil, false, nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return targetURL, nil, false, err
	}
	return targetURL, data, true, nil
}

func fetchGraphQLCandidate(ctx context.Context, client *http.Client, base *url.URL, path string) (string, []byte, bool, error) {
	targetURL := resolveProbeURL(base, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(introspectionBody))
	if err != nil {
		return "", nil, false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return targetURL, nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return targetURL, nil, false, nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return targetURL, nil, false, err
	}
	return targetURL, data, true, nil
}

func markActiveOperations(ops []inventory.Operation, location, parserFamily string, supportLevel inventory.SupportLevel, warnings []string) []inventory.Operation {
	out := make([]inventory.Operation, 0, len(ops))
	for _, op := range ops {
		op.SourceRefs = []inventory.SourceRef{{
			Type:         inventory.SourceActive,
			Location:     location,
			ParserFamily: parserFamily,
			SupportLevel: supportLevel,
			Warnings:     append([]string(nil), warnings...),
		}}
		op.Provenance.ActivelyDiscovered = true
		if op.Confidence < 0.8 {
			op.Confidence = 0.8
		}
		out = append(out, op)
	}
	return out
}

func normalizeBaseURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	if parsed.Scheme == "" {
		parsed.Scheme = "https"
	}
	return parsed, nil
}

func resolveProbeURL(base *url.URL, path string) string {
	probe := &url.URL{Path: path}
	return base.ResolveReference(probe).String()
}
