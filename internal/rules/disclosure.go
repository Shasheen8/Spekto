package rules

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Shasheen8/Spekto/internal/auth"
	"github.com/Shasheen8/Spekto/internal/executor"
	"github.com/Shasheen8/Spekto/internal/inventory"
)

// ── SEC001: Default Credentials ───────────────────────────────────────────

// commonBasicCredentials are (username, password) pairs tried against HTTP
// Basic-authenticated endpoints.
var commonBasicCredentials = [][2]string{
	{"admin", "admin"},
	{"admin", "password"},
	{"admin", ""},
	{"test", "test"},
	{"user", "user"},
	{"guest", "guest"},
	{"root", "root"},
	{"admin", "1234"},
}

// DefaultCredentials tries common username/password pairs against endpoints
// that used HTTP Basic authentication in the seed. A finding is raised when
// the server accepts a well-known credential.
type DefaultCredentials struct{}

func (r *DefaultCredentials) ID() string { return "SEC001" }

func (r *DefaultCredentials) Check(seed executor.Result, authCtx auth.Context) ([]Probe, []Finding) {
	if seed.Protocol != inventory.ProtocolREST {
		return nil, nil
	}
	if authCtx.BasicUsername == "" && authCtx.BasicPassword == "" {
		return nil, nil
	}

	var probes []Probe
	for _, cred := range commonBasicCredentials {
		username, password := cred[0], cred[1]
		if username == authCtx.BasicUsername && password == authCtx.BasicPassword {
			continue // skip the already-configured credential
		}
		// Build a minimal auth context just to get the correct Authorization header.
		credCtx := auth.Context{BasicUsername: username, BasicPassword: password}

		req := seedBaseRequest(seed)
		req.ID = probeID(seed, r.ID()+"-"+username)
		req.Headers = cloneNonRedactedHeaders(seed.Evidence.Request.Headers)
		// Apply basic auth header directly so we don't need registry lookup.
		for k, vals := range credCtx.HTTPHeaders() {
			req.Headers[k] = strings.Join(vals, ",")
		}
		// AuthContextName empty → executor does not overwrite our header.
		capturedUser := username

		probes = append(probes, Probe{
			RuleID:  r.ID(),
			Request: req,
			Evaluate: func(result executor.HTTPResult) []Finding {
				if !probeSucceeded(result) {
					return nil
				}
				return []Finding{newFinding(
					r.ID(), SeverityCritical, ConfidenceHigh,
					"Default credentials accepted",
					"The endpoint accepted the well-known credential '"+capturedUser+":***', indicating default or weak credentials are in use.",
					seed,
					FindingEvidence{Seed: seed.Evidence, Probe: probeEvidence(result)},
					"API2:2023 Broken Authentication", 1392,
					"Change all default credentials before deployment. Enforce strong password policies and consider mandatory credential rotation.",
				)}
			},
		})
	}
	return probes, nil
}

// ── SEC002: Server Crash ───────────────────────────────────────────────────

// buildNestedJSON returns a JSON object nested depth levels deep.
func buildNestedJSON(depth int) []byte {
	open := strings.Repeat(`{"a":`, depth)
	return []byte(open + `"z"` + strings.Repeat("}", depth))
}

var crashBodyProbes = []struct {
	desc string
	body []byte
}{
	{"deeply nested JSON (50 levels)", buildNestedJSON(50)},
	{"oversized string field (8 KB)", []byte(`{"input":"` + strings.Repeat("A", 8192) + `"}`)},
	{"truncated JSON", []byte(`{"key": `)},
}

var crashResponseIndicators = []string{
	"goroutine ", ".go:", "panic:", "runtime error:",
	"segmentation fault", "null pointer", "out of memory",
}

// ServerCrash probes write endpoints with crash-inducing payloads. A finding
// is raised when the server returns 5xx or stack trace content.
type ServerCrash struct{}

func (r *ServerCrash) ID() string { return "SEC002" }

func (r *ServerCrash) Check(seed executor.Result, _ auth.Context) ([]Probe, []Finding) {
	if seed.Protocol != inventory.ProtocolREST {
		return nil, nil
	}
	method := strings.ToUpper(seed.Evidence.Request.Method)
	if method != "POST" && method != "PUT" && method != "PATCH" {
		return nil, nil
	}

	var probes []Probe
	for i, cp := range crashBodyProbes {
		capturedDesc := cp.desc
		req := seedBaseRequest(seed)
		req.ID = probeID(seed, fmt.Sprintf("%s-%d", r.ID(), i))
		req.Body = cp.body
		req.ContentType = "application/json"
		req.AuthContextName = seed.AuthContextName
		req.Headers = cloneNonRedactedHeaders(seed.Evidence.Request.Headers)

		probes = append(probes, Probe{
			RuleID:  r.ID(),
			Request: req,
			Evaluate: func(result executor.HTTPResult) []Finding {
				body := strings.ToLower(string(result.ResponseBody))
				crashContent := false
				for _, ind := range crashResponseIndicators {
					if strings.Contains(body, ind) {
						crashContent = true
						break
					}
				}
				if result.StatusCode < 500 && !crashContent {
					return nil
				}
				desc := "The server returned a 5xx error"
				if crashContent {
					desc = "The response contains crash or stack trace indicators"
				}
				return []Finding{newFinding(
					r.ID(), SeverityMedium, ConfidenceMedium,
					"Server crash on malformed input ("+capturedDesc+")",
					desc+" when sent a crash-inducing payload ("+capturedDesc+").",
					seed,
					FindingEvidence{Seed: seed.Evidence, Probe: probeEvidence(result)},
					"API7:2023 Security Misconfiguration", 755,
					"Handle all malformed input gracefully. Recover from panics in every request handler. Never expose internal error details to clients.",
				)}
			},
		})
	}
	return probes, nil
}

// ── SEC003: PII / Sensitive Data Disclosure ────────────────────────────────

// piiPatterns are compiled once at startup. The scanner stops at the first
// match per seed to avoid flooding the findings list.
var piiPatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"credit card (Visa)", regexp.MustCompile(`\b4[0-9]{12}(?:[0-9]{3})?\b`)},
	{"credit card (Mastercard)", regexp.MustCompile(`\b5[1-5][0-9]{14}\b`)},
	{"credit card (Amex)", regexp.MustCompile(`\b3[47][0-9]{13}\b`)},
	{"US Social Security Number", regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)},
	{"private key header", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`)},
	{"embedded JWT", regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}`)},
	{"AWS access key", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
}

// PIIDisclosure scans successful seed responses for PII and sensitive data
// patterns. No probe request is sent — this is a static analysis of the seed.
type PIIDisclosure struct{}

func (r *PIIDisclosure) ID() string { return "SEC003" }

func (r *PIIDisclosure) Check(seed executor.Result, _ auth.Context) ([]Probe, []Finding) {
	if seed.Protocol != inventory.ProtocolREST && seed.Protocol != inventory.ProtocolGraphQL {
		return nil, nil
	}
	body := string(seed.Evidence.Response.Body)
	if len(body) == 0 {
		return nil, nil
	}
	for _, p := range piiPatterns {
		if p.re.MatchString(body) {
			return nil, []Finding{newFinding(
				r.ID(), SeverityHigh, ConfidenceHigh,
				"PII / sensitive data disclosure: "+p.name,
				"The response body contains a pattern matching '"+p.name+"'. Sensitive data must not be returned to API consumers.",
				seed,
				FindingEvidence{Seed: seed.Evidence},
				"API3:2023 Broken Object Property Level Authorization", 359,
				"Remove sensitive fields from API responses. Apply field-level access controls and audit all data returned to clients.",
			)}
		}
	}
	return nil, nil
}

// ── SEC004: Resource Exhaustion ────────────────────────────────────────────

const exhaustionThresholdFactor = 5 // flag when probe takes >5× seed baseline

// ResourceExhaustion probes write endpoints with a deeply nested JSON payload.
// A finding is raised when response time exceeds the seed baseline by a
// significant multiple, indicating algorithmic complexity vulnerability.
type ResourceExhaustion struct{}

func (r *ResourceExhaustion) ID() string { return "SEC004" }

func (r *ResourceExhaustion) Check(seed executor.Result, _ auth.Context) ([]Probe, []Finding) {
	if seed.Protocol != inventory.ProtocolREST {
		return nil, nil
	}
	method := strings.ToUpper(seed.Evidence.Request.Method)
	if method != "POST" && method != "PUT" && method != "PATCH" {
		return nil, nil
	}
	if seed.Duration <= 0 {
		return nil, nil
	}

	threshold := time.Duration(exhaustionThresholdFactor) * seed.Duration

	req := seedBaseRequest(seed)
	req.ID = probeID(seed, r.ID())
	req.Body = buildNestedJSON(100)
	req.ContentType = "application/json"
	req.AuthContextName = seed.AuthContextName
	req.Headers = cloneNonRedactedHeaders(seed.Evidence.Request.Headers)

	return []Probe{{
		RuleID:  r.ID(),
		Request: req,
		Evaluate: func(result executor.HTTPResult) []Finding {
			if result.Duration <= threshold {
				return nil
			}
			return []Finding{newFinding(
				r.ID(), SeverityMedium, ConfidenceMedium,
				"Resource exhaustion / algorithmic complexity",
				fmt.Sprintf("A deeply nested JSON payload caused a response time of %v — more than %d× the %.0fms baseline — suggesting vulnerability to resource exhaustion.", result.Duration.Round(time.Millisecond), exhaustionThresholdFactor, float64(seed.Duration.Milliseconds())),
				seed,
				FindingEvidence{Seed: seed.Evidence, Probe: probeEvidence(result)},
				"API4:2023 Unrestricted Resource Consumption", 770,
				"Enforce JSON nesting depth limits and maximum request sizes. Apply per-request timeouts.",
			)}
		},
	}}, nil
}
