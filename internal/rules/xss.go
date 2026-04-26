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

const xssMarker = "spekto_xss_marker"

type ReflectedXSS struct{}

func (r *ReflectedXSS) ID() string { return "XSS001" }

func (r *ReflectedXSS) Check(seed executor.Result, _ auth.Context) ([]Probe, []Finding) {
	if seed.Protocol != inventory.ProtocolREST {
		return nil, nil
	}
	method := strings.ToUpper(seed.Evidence.Request.Method)
	readOnly := method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
	bodyMethod := method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch
	if !readOnly && !bodyMethod {
		return nil, nil
	}

	probes := make([]Probe, 0, 3)
	if readOnly {
		req := seedBaseRequest(seed)
		req.ID = probeID(seed, r.ID()+"-query")
		req.AuthContextName = seed.AuthContextName
		req.Headers = cloneNonRedactedHeaders(seed.Evidence.Request.Headers)
		req.URL = appendQueryParam(seed.Evidence.Request.URL, "spekto_xss_probe", xssMarker)
		probes = append(probes, reflectedXSSProbe(r.ID(), seed, req))

		pathReq := req
		pathReq.ID = probeID(seed, r.ID()+"-path")
		pathReq.URL = replaceFirstPathSegment(seed.Evidence.Request.URL)
		if pathReq.URL != seed.Evidence.Request.URL {
			probes = append(probes, reflectedXSSProbe(r.ID(), seed, pathReq))
		}
	}
	if bodyMethod {
		if body, ok := appendMarkerToJSONBody(seed.Evidence.Request.Body); ok {
			req := seedBaseRequest(seed)
			req.ID = probeID(seed, r.ID()+"-body")
			req.AuthContextName = seed.AuthContextName
			req.Headers = cloneNonRedactedHeaders(seed.Evidence.Request.Headers)
			req.Body = body
			req.ContentType = "application/json"
			probes = append(probes, reflectedXSSProbe(r.ID(), seed, req))
		}
	}
	return probes, nil
}

type StoredXSS struct{}

func (r *StoredXSS) ID() string { return "XSS002" }

func (r *StoredXSS) Check(seed executor.Result, _ auth.Context) ([]Probe, []Finding) {
	if seed.Protocol != inventory.ProtocolREST {
		return nil, nil
	}
	if !responseReflectsMarker(seed.Evidence.Response.Headers, seed.Evidence.Response.Body) {
		return nil, nil
	}
	severity, title := reflectedXSSSeverity(seed.Evidence.Response.Headers)
	return nil, []Finding{newFinding(
		r.ID(), severity, ConfidenceMedium,
		title,
		"The seed response already contained Spekto's inert XSS marker, indicating a previously submitted marker may be stored or reflected in later responses.",
		seed,
		FindingEvidence{Seed: seed.Evidence},
		"API8:2023 Security Misconfiguration", 79,
		"Encode stored user-controlled data before rendering it and remove unsafe stored marker values from persisted content.",
	)}
}

func reflectedXSSProbe(ruleID string, seed executor.Result, req executor.HTTPRequest) Probe {
	return Probe{
		RuleID:  ruleID,
		Request: req,
		Evaluate: func(result executor.HTTPResult) []Finding {
			if !probeSucceeded(result) && result.StatusCode < 400 {
				return nil
			}
			if !responseReflectsMarker(result.ResponseHeaders, result.ResponseBody) {
				return nil
			}
			severity, title := reflectedXSSSeverity(result.ResponseHeaders)
			return []Finding{newFinding(
				ruleID, severity, ConfidenceMedium,
				title,
				"The response reflected Spekto's inert XSS marker from the request. HTML/script contexts are stronger indicators of exploitable XSS; JSON/text reflection still indicates unsafe response reflection that should be encoded or rejected.",
				seed,
				FindingEvidence{Seed: seed.Evidence, Probe: probeEvidence(result)},
				"API8:2023 Security Misconfiguration", 79,
				"Encode untrusted data for the response context, reject unsafe input where possible, and keep JSON string values escaped rather than embedding raw HTML/script content.",
			)}
		},
	}
}

func responseReflectsMarker(headers map[string]string, body []byte) bool {
	if len(body) == 0 || !reflectionMediaType(headers) {
		return false
	}
	return strings.Contains(string(body), xssMarker)
}

func reflectionMediaType(headers map[string]string) bool {
	contentType := ""
	for key, value := range headers {
		if strings.EqualFold(key, "content-type") {
			contentType = value
			break
		}
	}
	contentType = strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	return contentType == "text/html" ||
		contentType == "application/json" ||
		contentType == "text/plain" ||
		strings.HasSuffix(contentType, "+json")
}

func reflectedXSSSeverity(headers map[string]string) (Severity, string) {
	for key, value := range headers {
		if strings.EqualFold(key, "content-type") {
			base := strings.ToLower(strings.TrimSpace(strings.Split(value, ";")[0]))
			if base == "text/html" {
				return SeverityHigh, "Potential executable XSS reflection in HTML response"
			}
			return SeverityMedium, "Unsafe marker reflection in API response"
		}
	}
	return SeverityMedium, "Unsafe marker reflection in API response"
}

func appendMarkerToJSONBody(body []byte) ([]byte, bool) {
	if len(body) == 0 {
		return nil, false
	}
	var object map[string]any
	if err := json.Unmarshal(body, &object); err != nil {
		return nil, false
	}
	object["spekto_xss_probe"] = xssMarker
	mutated, err := json.Marshal(object)
	if err != nil {
		return nil, false
	}
	return mutated, true
}

func replaceFirstPathSegment(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	segments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	for i, segment := range segments {
		if segment != "" {
			segments[i] = url.PathEscape(xssMarker)
			parsed.Path = "/" + strings.Join(segments, "/")
			return parsed.String()
		}
	}
	return rawURL
}
