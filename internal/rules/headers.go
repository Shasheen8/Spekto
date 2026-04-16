package rules

import (
	"net/http"
	"strings"

	"github.com/Shasheen8/Spekto/internal/auth"
	"github.com/Shasheen8/Spekto/internal/executor"
)

// SecurityHeaders checks for missing HTTP security response headers by analysing
// the seed response directly. No probe request is sent.
type SecurityHeaders struct{}

func (r *SecurityHeaders) ID() string { return "HDR001" }

func (r *SecurityHeaders) Check(seed executor.Result, _ auth.Context) ([]Probe, []Finding) {
	hdrs := seed.Evidence.Response.Headers
	url := seed.Evidence.Request.URL
	var findings []Finding

	// HSTS — only meaningful on HTTPS endpoints.
	if strings.HasPrefix(url, "https://") {
		if !headerPresent(hdrs, "Strict-Transport-Security") {
			findings = append(findings, newFinding(
				r.ID()+"-HSTS", SeverityMedium, ConfidenceMedium,
				"HSTS header missing",
				"The response does not include Strict-Transport-Security, leaving it vulnerable to protocol downgrade attacks.",
				seed,
				FindingEvidence{Seed: seed.Evidence},
				"API7:2023 Security Misconfiguration", 319,
				"Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to all HTTPS responses.",
			))
		}
	}

	// Frame protection — check both X-Frame-Options and CSP frame-ancestors.
	hasFO := headerPresent(hdrs, "X-Frame-Options")
	hasCSP := headerPresent(hdrs, "Content-Security-Policy")
	if !hasFO && !hasCSP {
		findings = append(findings, newFinding(
			r.ID()+"-FRAME", SeverityLow, ConfidenceLow,
			"Clickjacking protection missing",
			"The response lacks both X-Frame-Options and a Content-Security-Policy frame-ancestors directive.",
			seed,
			FindingEvidence{Seed: seed.Evidence},
			"API7:2023 Security Misconfiguration", 1021,
			"Add 'X-Frame-Options: DENY' or use 'Content-Security-Policy: frame-ancestors none'.",
		))
	}

	// CSP — checked independently of frame protection.
	if !hasCSP {
		findings = append(findings, newFinding(
			r.ID()+"-CSP", SeverityLow, ConfidenceLow,
			"Content-Security-Policy header missing",
			"The response does not include a Content-Security-Policy header.",
			seed,
			FindingEvidence{Seed: seed.Evidence},
			"API7:2023 Security Misconfiguration", 693,
			"Define a Content-Security-Policy that restricts resource loading to trusted sources.",
		))
	}

	return nil, findings
}

// CORSMisconfiguration probes whether the endpoint reflects arbitrary origins in
// Access-Control-Allow-Origin, indicating a permissive CORS policy.
type CORSMisconfiguration struct{}

func (r *CORSMisconfiguration) ID() string { return "HDR002" }

const corsProbeOrigin = "https://evil.spekto.example.com"

func (r *CORSMisconfiguration) Check(seed executor.Result, _ auth.Context) ([]Probe, []Finding) {
	req := seedBaseRequest(seed)
	req.ID = probeID(seed, r.ID())
	req.AuthContextName = seed.AuthContextName
	req.Headers = cloneNonRedactedHeaders(seed.Evidence.Request.Headers)
	req.Headers["Origin"] = corsProbeOrigin

	return []Probe{{
		RuleID:  r.ID(),
		Request: req,
		Evaluate: func(result executor.HTTPResult) []Finding {
			acao := result.ResponseHeaders["Access-Control-Allow-Origin"]
			if acao == "" {
				return nil
			}
			// Only flag if the probe origin or wildcard is reflected.
			reflected := acao == "*" || strings.EqualFold(acao, corsProbeOrigin)
			if !reflected {
				return nil
			}

			severity := SeverityMedium
			description := "The endpoint reflects the request Origin in Access-Control-Allow-Origin, allowing cross-origin reads."
			if acao == "*" {
				description = "The endpoint uses a wildcard Access-Control-Allow-Origin header, permitting any origin to read responses."
			}
			acac := result.ResponseHeaders["Access-Control-Allow-Credentials"]
			if strings.EqualFold(acac, "true") {
				severity = SeverityCritical
				description += " Combined with Access-Control-Allow-Credentials: true, authenticated cross-origin requests are possible."
			}

			return []Finding{newFinding(
				r.ID(), severity, ConfidenceHigh,
				"CORS misconfiguration",
				description,
				seed,
				FindingEvidence{Seed: seed.Evidence, Probe: probeEvidence(result)},
				"API7:2023 Security Misconfiguration", 942,
				"Restrict Access-Control-Allow-Origin to a specific allowlist of trusted domains. Never combine wildcard origins with Allow-Credentials: true.",
			)}
		},
	}}, nil
}

// TRACEEnabled checks whether the HTTP TRACE method is accepted by the endpoint.
type TRACEEnabled struct{}

func (r *TRACEEnabled) ID() string { return "HDR003" }

func (r *TRACEEnabled) Check(seed executor.Result, _ auth.Context) ([]Probe, []Finding) {
	req := seedBaseRequest(seed)
	req.ID = probeID(seed, r.ID())
	req.Method = http.MethodTrace
	req.Body = nil
	req.ContentType = ""
	// No auth — exposure is significant regardless of auth state.

	return []Probe{{
		RuleID:  r.ID(),
		Request: req,
		Evaluate: func(result executor.HTTPResult) []Finding {
			if result.StatusCode != http.StatusOK {
				return nil
			}
			ct := strings.ToLower(result.ResponseHeaders["Content-Type"])
			// A genuine TRACE response echoes request headers with message/http content type.
			if !strings.Contains(ct, "message") && !strings.Contains(ct, "http") {
				return nil
			}
			return []Finding{newFinding(
				r.ID(), SeverityLow, ConfidenceMedium,
				"HTTP TRACE method enabled",
				"The server responded to an HTTP TRACE request. TRACE can be used in cross-site tracing (XST) attacks to steal HTTP-only cookies.",
				seed,
				FindingEvidence{Seed: seed.Evidence, Probe: probeEvidence(result)},
				"API7:2023 Security Misconfiguration", 16,
				"Disable HTTP TRACE and TRACK methods at the server or reverse proxy level.",
			)}
		},
	}}, nil
}

// MethodOverride checks whether the server honours method override headers, which
// can allow bypassing method-based access controls by disguising DELETE/PUT as GET/POST.
type MethodOverride struct{}

func (r *MethodOverride) ID() string { return "HDR004" }

// overrideHeaders are the common headers servers use to accept method overrides.
var overrideHeaders = []string{
	"X-HTTP-Method-Override",
	"X-Method-Override",
	"X-HTTP-Method",
}

func (r *MethodOverride) Check(seed executor.Result, _ auth.Context) ([]Probe, []Finding) {
	// Only probe GET and POST — those are the methods typically overridden.
	m := strings.ToUpper(seed.Evidence.Request.Method)
	if m != http.MethodGet && m != http.MethodPost {
		return nil, nil
	}

	probes := make([]Probe, 0, len(overrideHeaders))
	for _, hdrName := range overrideHeaders {
		capturedHdr := hdrName
		req := seedBaseRequest(seed)
		req.ID = probeID(seed, r.ID()+"-"+hdrName)
		req.AuthContextName = seed.AuthContextName
		req.Headers = cloneNonRedactedHeaders(seed.Evidence.Request.Headers)
		req.Headers[capturedHdr] = http.MethodDelete
		seedStatus := seed.Evidence.Response.StatusCode

		probes = append(probes, Probe{
			RuleID:  r.ID(),
			Request: req,
			Evaluate: func(result executor.HTTPResult) []Finding {
				if result.Error != "" {
					return nil
				}
				// The server processed the override if the status differs from the
				// seed — a 405 or successful response on the overridden method both
				// indicate the header was interpreted.
				if result.StatusCode == seedStatus {
					return nil
				}
				// A 404 is ambiguous; 405 or 2xx strongly suggest override was processed.
				if result.StatusCode == http.StatusNotFound {
					return nil
				}
				return []Finding{newFinding(
					r.ID(), SeverityMedium, ConfidenceMedium,
					"HTTP method override accepted ("+capturedHdr+")",
					"The server changed its response when the "+capturedHdr+" header was set to DELETE, indicating it may honour method overrides. This can allow bypass of method-based access controls.",
					seed,
					FindingEvidence{Seed: seed.Evidence, Probe: probeEvidence(result)},
					"API7:2023 Security Misconfiguration", 650,
					"Disable HTTP method override headers unless explicitly required. Enforce method-based access control at the transport layer.",
				)}
			},
		})
	}
	return probes, nil
}

// headerPresent checks whether a named header exists in the map with a non-empty value.
func headerPresent(headers map[string]string, name string) bool {
	for k, v := range headers {
		if strings.EqualFold(k, name) && strings.TrimSpace(v) != "" {
			return true
		}
	}
	return false
}
