package rules

import (
	"net/http"
	"strings"

	"github.com/Shasheen8/Spekto/internal/auth"
	"github.com/Shasheen8/Spekto/internal/executor"
	"github.com/Shasheen8/Spekto/internal/inventory"
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
	// Probe both TRACE and TRACK — both echo request headers and are exploitable
	// in cross-site tracing (XST) attacks. No auth sent; exposure is significant
	// regardless of authentication state.
	probes := make([]Probe, 0, 2)
	for _, method := range []string{http.MethodTrace, "TRACK"} {
		capturedMethod := method
		req := seedBaseRequest(seed)
		req.ID = probeID(seed, r.ID()+"-"+method)
		req.Method = capturedMethod
		req.Body = nil
		req.ContentType = ""

		probes = append(probes, Probe{
			RuleID:  r.ID(),
			Request: req,
			Evaluate: func(result executor.HTTPResult) []Finding {
				if result.StatusCode != http.StatusOK {
					return nil
				}
				ct := strings.ToLower(result.ResponseHeaders["Content-Type"])
				if !strings.Contains(ct, "message") && !strings.Contains(ct, "http") {
					return nil
				}
				return []Finding{newFinding(
					r.ID(), SeverityLow, ConfidenceMedium,
					"HTTP "+capturedMethod+" method enabled",
					"The server responded to an HTTP "+capturedMethod+" request. "+capturedMethod+" can be used in cross-site tracing (XST) attacks to steal HTTP-only cookies.",
					seed,
					FindingEvidence{Seed: seed.Evidence, Probe: probeEvidence(result)},
					"API7:2023 Security Misconfiguration", 16,
					"Disable HTTP TRACE and TRACK methods at the server or reverse proxy level.",
				)}
			},
		})
	}
	return probes, nil
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
	// Method override doesn't apply to GraphQL — GraphQL always uses POST and
	// operation semantics are defined in the query body, not the HTTP method.
	if seed.Protocol != inventory.ProtocolREST {
		return nil, nil
	}
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

// IPSourceBypass checks whether adding a loopback source-IP header to an
// unauthenticated request yields a successful response. Some services grant
// implicit trust to requests appearing to originate from localhost or internal
// networks, making these headers a bypass vector when not properly sanitised.
type IPSourceBypass struct{}

func (r *IPSourceBypass) ID() string { return "HDR005" }

var ipBypassHeaders = []string{
	"X-Forwarded-For",
	"X-Real-IP",
	"X-Originating-IP",
	"X-Client-IP",
	"True-Client-IP",
}

func (r *IPSourceBypass) Check(seed executor.Result, _ auth.Context) ([]Probe, []Finding) {
	if seed.AuthContextName == "" {
		return nil, nil
	}
	probes := make([]Probe, 0, len(ipBypassHeaders))
	for _, hdrName := range ipBypassHeaders {
		capturedHdr := hdrName
		req := seedBaseRequest(seed)
		req.ID = probeID(seed, r.ID()+"-"+hdrName)
		// No auth context — only the IP spoof header is sent.
		req.Headers = map[string]string{capturedHdr: "127.0.0.1"}

		probes = append(probes, Probe{
			RuleID:  r.ID(),
			Request: req,
			Evaluate: func(result executor.HTTPResult) []Finding {
				if !probeSucceeded(result) {
					return nil
				}
				return []Finding{newFinding(
					r.ID(), SeverityHigh, ConfidenceMedium,
					"IP-based authentication bypass via "+capturedHdr,
					"The endpoint returned a successful response with no authentication credentials when "+capturedHdr+": 127.0.0.1 was added, indicating IP-based access control may be bypassable.",
					seed,
					FindingEvidence{Seed: seed.Evidence, Probe: probeEvidence(result)},
					"API2:2023 Broken Authentication", 287,
					"Do not use source IP as an authentication mechanism. Enforce token-based authentication on every request regardless of apparent source address.",
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
