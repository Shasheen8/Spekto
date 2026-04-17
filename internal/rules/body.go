package rules

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Shasheen8/Spekto/internal/auth"
	"github.com/Shasheen8/Spekto/internal/executor"
)

// MassAssignment checks whether the server silently accepts privilege-related
// fields injected into a JSON request body and reflects them back in the response.
// APIs that bind request bodies directly to internal models without a field
// allowlist are vulnerable: an attacker can set role, admin, or permission
// fields that should never be user-controlled.
type MassAssignment struct{}

func (r *MassAssignment) ID() string { return "BODY001" }

// massAssignmentChecks is an ordered list of (field, injected-value) pairs.
// A deterministic slice is used so finding reports are reproducible across runs.
var massAssignmentChecks = []struct {
	field string
	value any
}{
	{"role", "admin"},
	{"is_admin", true},
	{"admin", true},
	{"superuser", true},
}

func (r *MassAssignment) Check(seed executor.Result, _ auth.Context) ([]Probe, []Finding) {
	// Only applicable to request methods that carry a body.
	method := strings.ToUpper(seed.Evidence.Request.Method)
	if method != http.MethodPost && method != http.MethodPut && method != http.MethodPatch {
		return nil, nil
	}

	// Seed body must be valid JSON — skip non-JSON content types.
	bodyMap, err := parseJSONBody(seed.Evidence.Request.Body)
	if err != nil {
		return nil, nil
	}

	// Merge injected fields into a copy of the seed body without overwriting
	// fields that are already present (we want to add, not clobber).
	mutated := make(map[string]any, len(bodyMap)+len(massAssignmentChecks))
	for k, v := range bodyMap {
		mutated[k] = v
	}
	for _, check := range massAssignmentChecks {
		if _, exists := mutated[check.field]; !exists {
			mutated[check.field] = check.value
		}
	}

	mutatedBody, err := json.Marshal(mutated)
	if err != nil {
		return nil, nil
	}

	// Parse seed response once here so the closure can compare against it,
	// avoiding false positives from fields that were already in the response.
	seedRespMap, _ := parseJSONBody(seed.Evidence.Response.Body)

	req := seedBaseRequest(seed)
	req.ID = probeID(seed, r.ID())
	req.AuthContextName = seed.AuthContextName
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
			probeRespMap, err := parseJSONBody(result.ResponseBody)
			if err != nil {
				return nil
			}
			for _, check := range massAssignmentChecks {
				probeVal, probeHas := probeRespMap[check.field]
				if !probeHas {
					continue
				}
				// Marshal both the probe value and our injected value to compare them
				// structurally, regardless of JSON whitespace or type differences.
				probeJSON, _ := json.Marshal(probeVal)
				injectJSON, _ := json.Marshal(check.value)
				if string(probeJSON) != string(injectJSON) {
					continue // server returned a different value, not our injection
				}
				// Our injected value is reflected. Only flag if it wasn't already
				// in the seed response with the same value (avoids pre-existing fields).
				seedVal, seedHas := seedRespMap[check.field]
				if seedHas {
					seedJSON, _ := json.Marshal(seedVal)
					if string(seedJSON) == string(injectJSON) {
						continue // field was already there with same value before injection
					}
				}
				return []Finding{newFinding(
					r.ID(), SeverityHigh, ConfidenceMedium,
					"Mass assignment: privilege field '"+check.field+"' accepted and reflected",
					"The server accepted and reflected the privilege field '"+check.field+"' injected into the request body with value "+string(injectJSON)+", indicating a mass assignment vulnerability.",
					seed,
					FindingEvidence{Seed: seed.Evidence, Probe: probeEvidence(result)},
					"API3:2023 Broken Object Property Level Authorization", 915,
					"Use an explicit field allowlist for all model binding. Never expose or accept internal properties directly from client input.",
				)}
			}
			return nil
		},
	}}, nil
}

// parseJSONBody unmarshals a JSON body into a generic map.
// Returns an empty map for nil/empty input and an error for non-JSON content.
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
