package rules

import (
	"github.com/Shasheen8/Spekto/internal/auth"
	"github.com/Shasheen8/Spekto/internal/executor"
)

// AuthBypass checks whether a protected endpoint is reachable without credentials.
// A finding is raised when removing all auth still yields a 2xx/3xx response.
type AuthBypass struct{}

func (r *AuthBypass) ID() string { return "AUTH001" }

func (r *AuthBypass) Check(seed executor.Result, _ auth.Context) ([]Probe, []Finding) {
	if seed.AuthContextName == "" {
		// Seed used no auth — nothing to strip.
		return nil, nil
	}

	req := seedBaseRequest(seed)
	req.ID = probeID(seed, r.ID())
	// AuthContextName left empty → executor applies no auth.

	return []Probe{{
		RuleID:  r.ID(),
		Request: req,
		Evaluate: func(result executor.HTTPResult) []Finding {
			if !probeSucceeded(result) {
				return nil
			}
			return []Finding{newFinding(
				r.ID(), SeverityHigh, ConfidenceHigh,
				"Authentication bypass",
				"The endpoint returned a successful response with no authentication credentials present.",
				seed,
				FindingEvidence{Seed: seed.Evidence, Probe: probeEvidence(result)},
				"API2:2023 Broken Authentication", 287,
				"Require valid authentication on all protected endpoints. Enforce auth at the framework or gateway layer rather than per-handler.",
			)}
		},
	}}, nil
}

// InvalidAuthAccepted checks whether the server accepts a structurally invalid bearer token.
// A finding is raised when an obviously garbage token still yields a 2xx/3xx response.
type InvalidAuthAccepted struct{}

func (r *InvalidAuthAccepted) ID() string { return "AUTH002" }

func (r *InvalidAuthAccepted) Check(seed executor.Result, authCtx auth.Context) ([]Probe, []Finding) {
	if seed.AuthContextName == "" || authCtx.BearerToken == "" {
		return nil, nil
	}

	req := seedBaseRequest(seed)
	req.ID = probeID(seed, r.ID())
	req.Headers = cloneNonRedactedHeaders(seed.Evidence.Request.Headers)
	req.Headers["Authorization"] = "Bearer INVALID.TOKEN.SPEKTO"
	// AuthContextName empty → executor will not overwrite our header.

	return []Probe{{
		RuleID:  r.ID(),
		Request: req,
		Evaluate: func(result executor.HTTPResult) []Finding {
			if !probeSucceeded(result) {
				return nil
			}
			return []Finding{newFinding(
				r.ID(), SeverityHigh, ConfidenceHigh,
				"Invalid authentication accepted",
				"The endpoint accepted an invalid bearer token and returned a successful response, indicating token validation may not be enforced.",
				seed,
				FindingEvidence{Seed: seed.Evidence, Probe: probeEvidence(result)},
				"API2:2023 Broken Authentication", 287,
				"Validate every authentication token on every request. Reject malformed, expired, or unrecognised tokens with 401.",
			)}
		},
	}}, nil
}
