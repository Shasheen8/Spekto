package rules

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Shasheen8/Spekto/internal/auth"
	"github.com/Shasheen8/Spekto/internal/executor"
	"github.com/Shasheen8/Spekto/internal/inventory"
)

// gqlResponseDataIsNull returns true when a GraphQL response carries a null
// or absent data field alongside errors — the canonical pattern for an auth
// rejection returned at the GraphQL application layer rather than HTTP.
func gqlResponseDataIsNull(body []byte) bool {
	var resp struct {
		Data   json.RawMessage `json:"data"`
		Errors []any           `json:"errors"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return false
	}
	return len(resp.Errors) > 0 && (resp.Data == nil || string(resp.Data) == "null")
}

// GraphQLIntrospectionEnabled checks whether the GraphQL introspection API is
// accessible without authentication. Introspection exposes the full schema —
// every type, field, argument, and directive — making it significantly easier
// to map an attack surface without authorisation.
type GraphQLIntrospectionEnabled struct{}

func (r *GraphQLIntrospectionEnabled) ID() string { return "GQL001" }

const minimalIntrospectionQuery = `{"query":"{__schema{queryType{name}}}"}`

func (r *GraphQLIntrospectionEnabled) Check(seed executor.Result, _ auth.Context) ([]Probe, []Finding) {
	if seed.Protocol != inventory.ProtocolGraphQL {
		return nil, nil
	}
	req := executor.HTTPRequest{
		ID:          probeID(seed, r.ID()),
		OperationID: seed.OperationID,
		Method:      "POST",
		URL:         seed.Evidence.Request.URL,
		Body:        []byte(minimalIntrospectionQuery),
		ContentType: "application/json",
		// No AuthContextName — testing unauthenticated access.
	}
	return []Probe{{
		RuleID:  r.ID(),
		Request: req,
		Evaluate: func(result executor.HTTPResult) []Finding {
			if !probeSucceeded(result) {
				return nil
			}
			body := strings.ToLower(string(result.ResponseBody))
			if !strings.Contains(body, `"__schema"`) {
				return nil
			}
			return []Finding{newFinding(
				r.ID(), SeverityMedium, ConfidenceHigh,
				"GraphQL introspection accessible without authentication",
				"The GraphQL introspection API returned schema data without authentication credentials, exposing the full API schema to unauthenticated callers.",
				seed,
				FindingEvidence{Seed: seed.Evidence, Probe: probeEvidence(result)},
				"API7:2023 Security Misconfiguration", 200,
				"Disable GraphQL introspection in production. If required for tooling, gate it behind authentication or restrict it to internal networks.",
			)}
		},
	}}, nil
}

// GraphQLAuthBypass checks whether a GraphQL operation that required
// authentication still returns data when credentials are stripped.
// This is the GraphQL equivalent of REST AUTH001, with one additional check:
// a response containing only a GraphQL errors array (no data field) is treated
// as a proper rejection, not a bypass.
type GraphQLAuthBypass struct{}

func (r *GraphQLAuthBypass) ID() string { return "GQL002" }

func (r *GraphQLAuthBypass) Check(seed executor.Result, _ auth.Context) ([]Probe, []Finding) {
	if seed.Protocol != inventory.ProtocolGraphQL {
		return nil, nil
	}
	if seed.AuthContextName == "" {
		return nil, nil
	}

	req := seedBaseRequest(seed)
	req.ID = probeID(seed, r.ID())
	req.Headers = cloneNonRedactedHeaders(seed.Evidence.Request.Headers)
	// No AuthContextName → executor applies no auth.

	return []Probe{{
		RuleID:  r.ID(),
		Request: req,
		Evaluate: func(result executor.HTTPResult) []Finding {
			if !probeSucceeded(result) {
				return nil
			}
			// Treat {"data": null, "errors": [...]} as a proper auth rejection.
			// Many GraphQL servers return this pattern instead of a 4xx HTTP status.
			if gqlResponseDataIsNull(result.ResponseBody) {
				return nil
			}
			return []Finding{newFinding(
				r.ID(), SeverityHigh, ConfidenceHigh,
				"GraphQL authentication bypass",
				"The GraphQL operation returned data without authentication credentials.",
				seed,
				FindingEvidence{Seed: seed.Evidence, Probe: probeEvidence(result)},
				"API2:2023 Broken Authentication", 287,
				"Require authentication for all GraphQL operations that access protected data. Apply auth checks at the transport or gateway level rather than per-resolver.",
			)}
		},
	}}, nil
}

// GraphQLBatchAbuse checks whether the server accepts and processes a batch of
// repeated GraphQL operations in a single request. Servers that do not apply
// per-operation limits to batched requests may be vulnerable to request
// amplification, rate-limit bypass, or query complexity budget circumvention.
type GraphQLBatchAbuse struct{}

func (r *GraphQLBatchAbuse) ID() string { return "GQL003" }

const graphqlBatchSize = 10

func (r *GraphQLBatchAbuse) Check(seed executor.Result, _ auth.Context) ([]Probe, []Finding) {
	if seed.Protocol != inventory.ProtocolGraphQL {
		return nil, nil
	}

	var singleOp any
	if err := json.Unmarshal(seed.Evidence.Request.Body, &singleOp); err != nil {
		return nil, nil
	}

	batch := make([]any, graphqlBatchSize)
	for i := range batch {
		batch[i] = singleOp
	}
	batchBody, err := json.Marshal(batch)
	if err != nil {
		return nil, nil
	}

	req := seedBaseRequest(seed)
	req.ID = probeID(seed, r.ID())
	req.AuthContextName = seed.AuthContextName
	req.Body = batchBody
	req.Headers = cloneNonRedactedHeaders(seed.Evidence.Request.Headers)

	return []Probe{{
		RuleID:  r.ID(),
		Request: req,
		Evaluate: func(result executor.HTTPResult) []Finding {
			if !probeSucceeded(result) {
				return nil
			}
			// Only flag if the response is a JSON array — confirming the server
			// processed the batch rather than rejecting or ignoring it.
			body := strings.TrimSpace(string(result.ResponseBody))
			if !strings.HasPrefix(body, "[") {
				return nil
			}
			return []Finding{newFinding(
				r.ID(), SeverityMedium, ConfidenceMedium,
				"GraphQL batch query accepted",
				fmt.Sprintf("The server accepted and processed a batch of %d repeated GraphQL operations in a single request. This may allow bypassing per-request rate limits or query complexity budgets.", graphqlBatchSize),
				seed,
				FindingEvidence{Seed: seed.Evidence, Probe: probeEvidence(result)},
				"API4:2023 Unrestricted Resource Consumption", 770,
				"Disable GraphQL batching or enforce per-operation limits independently of the HTTP request count.",
			)}
		},
	}}, nil
}
