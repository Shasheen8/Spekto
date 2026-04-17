package rules

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Shasheen8/Spekto/internal/auth"
	"github.com/Shasheen8/Spekto/internal/executor"
)

// MassAssignment checks whether the server silently accepts privilege-related
// fields injected into a JSON request body and reflects them in the response.
// APIs that bind request bodies directly to internal models without an explicit
// field allowlist are vulnerable: an attacker can set role, admin, or permission
// fields that should never be user-controlled.
type MassAssignment struct{}

func (r *MassAssignment) ID() string { return "BODY001" }

// massAssignmentFields are injected into the request body alongside normal fields.
// They are chosen to cover the most common patterns for privilege escalation via
// model binding in REST APIs.
var massAssignmentFields = map[string]any{
	"role":        "admin",
	"is_admin":    true,
	"admin":       true,
	"superuser":   true,
	"permissions": []string{"admin", "write"},
}

func (r *MassAssignment) Check(seed executor.Result, _ auth.Context) ([]Probe, []Finding) {
	// Only meaningful on methods that carry a request body.
	method := strings.ToUpper(seed.Evidence.Request.Method)
	if method != http.MethodPost && method != http.MethodPut && method != http.MethodPatch {
		return nil, nil
	}

	// Seed body must be valid JSON — skip otherwise.
	bodyMap, err := parseJSONBody(seed.Evidence.Request.Body)
	if err != nil {
		return nil, nil
	}

	// Merge privilege fields into a copy of the seed body.
	mutated := make(map[string]any, len(bodyMap)+len(massAssignmentFields))
	for k, v := range bodyMap {
		mutated[k] = v
	}
	for k, v := range massAssignmentFields {
		if _, exists := mutated[k]; !exists {
			mutated[k] = v
		}
	}

	mutatedBody, err := json.Marshal(mutated)
	if err != nil {
		return nil, nil
	}

	req := seedBaseRequest(seed)
	req.ID = probeID(seed, r.ID())
	req.AuthContextName = seed.AuthContextName // keep original auth
	req.Body = mutatedBody
	req.ContentType = "application/json"
	req.Headers = cloneNonRedactedHeaders(seed.Evidence.Request.Headers)

	return []Probe{{
		RuleID:  r.ID(),
		Request: req,
		Evaluate: func(result executor.HTTPResult) []Finding {
			if !probeSucceeded(result) {
				return nil
			}
			// Flag when any injected privilege field is reflected in the response body,
			// indicating the server accepted and stored the value.
			responseBody := strings.ToLower(string(result.ResponseBody))
			for field := range massAssignmentFields {
				// Look for the field name as a JSON key in the response.
				if strings.Contains(responseBody, `"`+field+`"`) {
					return []Finding{newFinding(
						r.ID(), SeverityHigh, ConfidenceMedium,
						"Mass assignment: privilege field '"+field+"' accepted and reflected",
						"The server accepted and reflected the privilege field '"+field+"' that was injected into the request body, indicating a mass assignment vulnerability.",
						seed,
						FindingEvidence{Seed: seed.Evidence, Probe: probeEvidence(result)},
						"API3:2023 Broken Object Property Level Authorization", 915,
						"Use an explicit field allowlist for all model binding. Never expose or accept internal properties directly from client input.",
					)}
				}
			}
			return nil
		},
	}}, nil
}

// parseJSONBody unmarshals a JSON body into a generic map.
// Returns an empty map for a nil or empty body, and an error for non-JSON content.
func parseJSONBody(body []byte) (map[string]any, error) {
	if len(body) == 0 {
		return map[string]any{}, nil
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, err
	}
	return m, nil
}
