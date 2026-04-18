package rules

import (
	"net/url"
	"strings"

	"github.com/Shasheen8/Spekto/internal/auth"
	"github.com/Shasheen8/Spekto/internal/executor"
	"github.com/Shasheen8/Spekto/internal/inventory"
)

// PrivilegeEscalationParams checks whether adding privilege-related query
// parameters to an unauthenticated request bypasses access controls.
// Some APIs retain debug or backdoor parameters that grant elevated access
// regardless of the bearer token.
type PrivilegeEscalationParams struct{}

func (r *PrivilegeEscalationParams) ID() string { return "PARAM001" }

var privilegeQueryParams = []struct{ name, value string }{
	{"admin", "true"},
	{"role", "admin"},
	{"debug", "true"},
	{"superuser", "true"},
	{"is_admin", "true"},
	{"elevated", "true"},
}

func (r *PrivilegeEscalationParams) Check(seed executor.Result, _ auth.Context) ([]Probe, []Finding) {
	// GraphQL operations don't use URL query parameters for auth or privilege control.
	if seed.Protocol != inventory.ProtocolREST {
		return nil, nil
	}
	if seed.AuthContextName == "" {
		return nil, nil
	}
	probes := make([]Probe, 0, len(privilegeQueryParams))
	for _, param := range privilegeQueryParams {
		capturedParam := param
		req := seedBaseRequest(seed)
		req.ID = probeID(seed, r.ID()+"-"+param.name)
		// No auth context — testing whether the parameter alone bypasses auth.
		req.URL = appendQueryParam(seed.Evidence.Request.URL, capturedParam.name, capturedParam.value)

		probes = append(probes, Probe{
			RuleID:  r.ID(),
			Request: req,
			Evaluate: func(result executor.HTTPResult) []Finding {
				if !probeSucceeded(result) {
					return nil
				}
				return []Finding{newFinding(
					r.ID(), SeverityHigh, ConfidenceMedium,
					"Privilege escalation via query parameter: "+capturedParam.name+"="+capturedParam.value,
					"The endpoint returned a successful response with no authentication when "+capturedParam.name+"="+capturedParam.value+" was added to the query string.",
					seed,
					FindingEvidence{Seed: seed.Evidence, Probe: probeEvidence(result)},
					"API1:2023 Broken Object Level Authorization", 285,
					"Never use query parameters as an authentication or authorization mechanism. Enforce server-side authorization based on verified identity only.",
				)}
			},
		})
	}
	return probes, nil
}

// appendQueryParam appends a single key=value pair to a URL's query string.
func appendQueryParam(rawURL, name, value string) string {
	sep := "?"
	if strings.Contains(rawURL, "?") {
		sep = "&"
	}
	return rawURL + sep + url.QueryEscape(name) + "=" + url.QueryEscape(value)
}
