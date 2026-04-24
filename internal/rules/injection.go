package rules

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/Shasheen8/Spekto/internal/auth"
	"github.com/Shasheen8/Spekto/internal/executor"
	"github.com/Shasheen8/Spekto/internal/inventory"
)

// ── Injection helpers ──────────────────────────────────────────────────────

// pathInjectedURL replaces every {param} segment in the URL with payload by
// comparing the seed locator's path template against the actual request path.
// Returns the original URL unchanged when there are no template params.
func pathInjectedURL(locator, rawURL, payload string) string {
	parts := strings.SplitN(locator, ":", 2)
	if len(parts) < 2 || !strings.Contains(parts[1], "{") {
		return rawURL
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	patternSegs := strings.Split(parts[1], "/")
	actualSegs := strings.Split(parsed.Path, "/")
	if len(patternSegs) != len(actualSegs) {
		return rawURL
	}
	mutated := false
	for i, seg := range patternSegs {
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			actualSegs[i] = url.PathEscape(payload)
			mutated = true
		}
	}
	if !mutated {
		return rawURL
	}
	cp := *parsed
	cp.Path = strings.Join(actualSegs, "/")
	return cp.String()
}

// queryInjectedURL replaces every query param value with payload.
// Returns the original URL unchanged when there are no query params.
func queryInjectedURL(rawURL, payload string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := parsed.Query()
	if len(q) == 0 {
		return rawURL
	}
	for k := range q {
		q.Set(k, payload)
	}
	cp := *parsed
	cp.RawQuery = q.Encode()
	return cp.String()
}

// bodyInjected replaces every top-level string field value in a JSON body with
// payload. Returns nil when the body is not a JSON object or has no string fields.
func bodyInjected(body []byte, payload string) []byte {
	if len(body) == 0 {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return nil
	}
	mutated := false
	for k, v := range m {
		if _, ok := v.(string); ok {
			m[k] = payload
			mutated = true
		}
	}
	if !mutated {
		return nil
	}
	data, _ := json.Marshal(m)
	return data
}

// injectionProbes builds up to three probes (path, query, body) for a given
// payload and shared evaluator. Skips any injection point that has nothing to
// inject into (no template params, no query params, non-JSON body, etc.).
func injectionProbes(ruleID string, seed executor.Result, payload string, eval func(executor.HTTPResult) []Finding) []Probe {
	method := strings.ToUpper(seed.Evidence.Request.Method)
	isWrite := method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch

	var probes []Probe

	if injURL := pathInjectedURL(seed.Locator, seed.Evidence.Request.URL, payload); injURL != seed.Evidence.Request.URL {
		req := seedBaseRequest(seed)
		req.ID = probeID(seed, ruleID+"-path")
		req.URL = injURL
		req.AuthContextName = seed.AuthContextName
		req.Headers = cloneNonRedactedHeaders(seed.Evidence.Request.Headers)
		probes = append(probes, Probe{RuleID: ruleID, Request: req, Evaluate: eval})
	}

	if injURL := queryInjectedURL(seed.Evidence.Request.URL, payload); injURL != seed.Evidence.Request.URL {
		req := seedBaseRequest(seed)
		req.ID = probeID(seed, ruleID+"-query")
		req.URL = injURL
		req.AuthContextName = seed.AuthContextName
		req.Headers = cloneNonRedactedHeaders(seed.Evidence.Request.Headers)
		probes = append(probes, Probe{RuleID: ruleID, Request: req, Evaluate: eval})
	}

	if isWrite {
		if injBody := bodyInjected(seed.Evidence.Request.Body, payload); injBody != nil {
			req := seedBaseRequest(seed)
			req.ID = probeID(seed, ruleID+"-body")
			req.Body = injBody
			req.ContentType = "application/json"
			req.AuthContextName = seed.AuthContextName
			req.Headers = cloneNonRedactedHeaders(seed.Evidence.Request.Headers)
			probes = append(probes, Probe{RuleID: ruleID, Request: req, Evaluate: eval})
		}
	}

	return probes
}

// ── INJ001: Server Error on Invalid Input ─────────────────────────────────

// ServerErrorOnInput sends a null body to write endpoints. A 5xx response
// indicates the server does not validate input before processing it.
type ServerErrorOnInput struct{}

func (r *ServerErrorOnInput) ID() string { return "INJ001" }

func (r *ServerErrorOnInput) Check(seed executor.Result, _ auth.Context) ([]Probe, []Finding) {
	if seed.Protocol != inventory.ProtocolREST {
		return nil, nil
	}
	method := strings.ToUpper(seed.Evidence.Request.Method)
	if method != http.MethodPost && method != http.MethodPut && method != http.MethodPatch {
		return nil, nil
	}
	req := seedBaseRequest(seed)
	req.ID = probeID(seed, r.ID())
	req.Body = []byte("null")
	req.ContentType = "application/json"
	req.AuthContextName = seed.AuthContextName
	req.Headers = cloneNonRedactedHeaders(seed.Evidence.Request.Headers)
	return []Probe{{
		RuleID:  r.ID(),
		Request: req,
		Evaluate: func(result executor.HTTPResult) []Finding {
			if result.StatusCode < 500 {
				return nil
			}
			return []Finding{newFinding(
				r.ID(), SeverityMedium, ConfidenceMedium,
				"Internal server error on null input",
				"The endpoint returned a 5xx response when sent a null request body, indicating insufficient input validation.",
				seed,
				FindingEvidence{Seed: seed.Evidence, Probe: probeEvidence(result)},
				"API7:2023 Security Misconfiguration", 755,
				"Validate all input before processing. Return 400 Bad Request for invalid payloads rather than allowing unhandled exceptions to reach the client.",
			)}
		},
	}}, nil
}

// ── INJ002: SQL Injection ──────────────────────────────────────────────────

var sqlErrorIndicators = []string{
	"sql syntax", "mysql_", "ora-0", "ora-1", "postgresql", "sqlite_",
	"sqlstate", "odbc driver", "jdbc", "unterminated quoted string",
	"you have an error in your sql", "warning: mysql", "pg_query",
	"microsoft ole db", "invalid query",
}

// SQLInjection injects a SQL payload into path params, query params, and body
// fields. A finding is raised when the response contains SQL error strings.
type SQLInjection struct{}

func (r *SQLInjection) ID() string { return "INJ002" }

func (r *SQLInjection) Check(seed executor.Result, _ auth.Context) ([]Probe, []Finding) {
	if seed.Protocol != inventory.ProtocolREST {
		return nil, nil
	}
	eval := func(result executor.HTTPResult) []Finding {
		body := strings.ToLower(string(result.ResponseBody))
		for _, ind := range sqlErrorIndicators {
			if strings.Contains(body, ind) {
				return []Finding{newFinding(
					r.ID(), SeverityHigh, ConfidenceMedium,
					"SQL injection",
					"The response contains SQL error strings after a SQL payload was injected, indicating the application may be vulnerable to SQL injection.",
					seed,
					FindingEvidence{Seed: seed.Evidence, Probe: probeEvidence(result)},
					"API8:2023 Injection", 89,
					"Use parameterised queries or prepared statements. Never interpolate user input directly into SQL strings.",
				)}
			}
		}
		return nil
	}
	return injectionProbes(r.ID(), seed, `' OR '1'='1`, eval), nil
}

// ── INJ003: NoSQL Injection ────────────────────────────────────────────────

// NoSQLInjection injects MongoDB operator payloads into body fields.
// A finding is raised when the server returns unexpected data or a 2xx response
// that differs from the baseline, suggesting operator injection was processed.
type NoSQLInjection struct{}

func (r *NoSQLInjection) ID() string { return "INJ003" }

func (r *NoSQLInjection) Check(seed executor.Result, _ auth.Context) ([]Probe, []Finding) {
	if seed.Protocol != inventory.ProtocolREST {
		return nil, nil
	}
	method := strings.ToUpper(seed.Evidence.Request.Method)
	if method != http.MethodPost && method != http.MethodPut && method != http.MethodPatch {
		return nil, nil
	}
	// Parse the existing body and replace one string field with a NoSQL operator object.
	var m map[string]any
	if err := json.Unmarshal(seed.Evidence.Request.Body, &m); err != nil || len(m) == 0 {
		return nil, nil
	}
	injected := make(map[string]any, len(m))
	for k, v := range m {
		injected[k] = v
	}
	for k, v := range m {
		if _, isStr := v.(string); isStr {
			injected[k] = map[string]any{"$gt": ""}
			break
		}
	}
	body, err := json.Marshal(injected)
	if err != nil {
		return nil, nil
	}
	req := seedBaseRequest(seed)
	req.ID = probeID(seed, r.ID())
	req.Body = body
	req.ContentType = "application/json"
	req.AuthContextName = seed.AuthContextName
	req.Headers = cloneNonRedactedHeaders(seed.Evidence.Request.Headers)
	return []Probe{{
		RuleID:  r.ID(),
		Request: req,
		Evaluate: func(result executor.HTTPResult) []Finding {
			if !probeSucceeded(result) {
				return nil
			}
			// Flag if the probe returned more data than the seed response (operator bypassed a filter).
			if len(result.ResponseBody) > len(seed.Evidence.Response.Body)+64 {
				return []Finding{newFinding(
					r.ID(), SeverityHigh, ConfidenceMedium,
					"NoSQL injection",
					"Injecting a NoSQL comparison operator produced a larger response than the baseline, suggesting the operator was interpreted by the database and bypassed a filter.",
					seed,
					FindingEvidence{Seed: seed.Evidence, Probe: probeEvidence(result)},
					"API8:2023 Injection", 943,
					"Sanitise and validate all input before passing it to database queries. Reject inputs that contain operator-looking values.",
				)}
			}
			return nil
		},
	}}, nil
}

// ── INJ004: Command Injection ──────────────────────────────────────────────

var cmdOutputIndicators = []string{
	"uid=", "gid=", "root:", "/bin/sh", "/bin/bash",
	"command not found", "sh: ", "bash: ",
	"windows ip configuration", "volume serial number",
}

// CommandInjection injects shell command separators into path and query params.
// A finding is raised when the response contains command output indicators.
type CommandInjection struct{}

func (r *CommandInjection) ID() string { return "INJ004" }

func (r *CommandInjection) Check(seed executor.Result, _ auth.Context) ([]Probe, []Finding) {
	if seed.Protocol != inventory.ProtocolREST {
		return nil, nil
	}
	eval := func(result executor.HTTPResult) []Finding {
		body := strings.ToLower(string(result.ResponseBody))
		for _, ind := range cmdOutputIndicators {
			if strings.Contains(body, ind) {
				return []Finding{newFinding(
					r.ID(), SeverityCritical, ConfidenceMedium,
					"Command injection",
					"The response contains command output after a shell injection payload was injected, indicating the application may be executing user-supplied input as a system command.",
					seed,
					FindingEvidence{Seed: seed.Evidence, Probe: probeEvidence(result)},
					"API8:2023 Injection", 78,
					"Never pass user input to system calls or shell commands. Use allowlisted arguments and avoid shell=true execution patterns.",
				)}
			}
		}
		return nil
	}
	return injectionProbes(r.ID(), seed, `; echo spekto_cmd_test`, eval), nil
}

// ── INJ005: Path Traversal ─────────────────────────────────────────────────

var pathTraversalIndicators = []string{
	"root:x:0:0", "daemon:", "/bin/bash", "/bin/sh",
	"[boot loader]", "[operating systems]", // windows boot.ini
	"[fonts]", "[extensions]",              // windows system.ini
	"<html", "<!doctype",                  // serving static files unexpectedly
}

// PathTraversal injects directory traversal sequences into path and query params.
// A finding is raised when the response contains file content indicators.
type PathTraversal struct{}

func (r *PathTraversal) ID() string { return "INJ005" }

func (r *PathTraversal) Check(seed executor.Result, _ auth.Context) ([]Probe, []Finding) {
	if seed.Protocol != inventory.ProtocolREST {
		return nil, nil
	}
	eval := func(result executor.HTTPResult) []Finding {
		body := strings.ToLower(string(result.ResponseBody))
		for _, ind := range pathTraversalIndicators {
			if strings.Contains(body, ind) {
				return []Finding{newFinding(
					r.ID(), SeverityCritical, ConfidenceHigh,
					"Path traversal",
					"The response contains file system content after a directory traversal payload was injected, indicating the application resolves user-supplied paths without sanitisation.",
					seed,
					FindingEvidence{Seed: seed.Evidence, Probe: probeEvidence(result)},
					"API8:2023 Injection", 22,
					"Resolve file paths against a fixed base directory and reject any path that escapes it. Use os.FileSystem or similar abstractions with path-safe APIs.",
				)}
			}
		}
		return nil
	}
	return injectionProbes(r.ID(), seed, `../../etc/passwd`, eval), nil
}

// ── INJ006: Server-Side Request Forgery (SSRF) ────────────────────────────

var ssrfIndicators = []string{
	"ami-id", "instance-type", "local-ipv4", "placement", // AWS metadata
	"compute", "project-id", "zone", "service-accounts",  // GCP metadata
	"windows azure", "api-version",                        // Azure metadata
	"169.254.169.254",                                     // metadata IP echoed back
}

// SSRFProbe injects cloud metadata service URLs into path and query params.
// A finding is raised when the response contains metadata content, indicating
// the server fetched the injected URL on behalf of the client.
type SSRFProbe struct{}

func (r *SSRFProbe) ID() string { return "INJ006" }

func (r *SSRFProbe) Check(seed executor.Result, _ auth.Context) ([]Probe, []Finding) {
	if seed.Protocol != inventory.ProtocolREST {
		return nil, nil
	}
	eval := func(result executor.HTTPResult) []Finding {
		body := strings.ToLower(string(result.ResponseBody))
		for _, ind := range ssrfIndicators {
			if strings.Contains(body, ind) {
				return []Finding{newFinding(
					r.ID(), SeverityCritical, ConfidenceHigh,
					"Server-Side Request Forgery (SSRF)",
					"The response contains cloud instance metadata content after an internal URL was injected as a parameter value, indicating the server fetched the URL on the client's behalf.",
					seed,
					FindingEvidence{Seed: seed.Evidence, Probe: probeEvidence(result)},
					"API7:2023 Security Misconfiguration", 918,
					"Validate and allowlist URLs before fetching them. Block requests to link-local (169.254.x.x), loopback, and RFC-1918 addresses.",
				)}
			}
		}
		return nil
	}
	return injectionProbes(r.ID(), seed, `http://169.254.169.254/latest/meta-data/`, eval), nil
}
