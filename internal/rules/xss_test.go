package rules

import (
	"net/http"
	"strings"
	"testing"

	"github.com/Shasheen8/Spekto/internal/auth"
	"github.com/Shasheen8/Spekto/internal/executor"
	"github.com/Shasheen8/Spekto/internal/inventory"
)

func TestReflectedXSSBuildsInertQueryProbeAndFlagsHTMLReflection(t *testing.T) {
	seed := xssSeed("https://api.example.com/search?q=sample", "application/json", `{"ok":true}`)
	rule := &ReflectedXSS{}

	probes, immediate := rule.Check(seed, auth.Context{})
	if len(immediate) != 0 {
		t.Fatalf("expected no immediate findings, got %#v", immediate)
	}
	if len(probes) == 0 {
		t.Fatalf("expected reflected XSS probe")
	}
	if !strings.Contains(probes[0].Request.URL, "spekto_xss_marker") {
		t.Fatalf("expected inert marker in probe URL, got %s", probes[0].Request.URL)
	}

	result := executor.HTTPResult{
		StatusCode:      http.StatusOK,
		ResponseHeaders: map[string]string{"Content-Type": "text/html"},
		ResponseBody:    []byte(`<html><script>const x="spekto_xss_marker";</script></html>`),
		Method:          http.MethodGet,
		URL:             probes[0].Request.URL,
	}
	findings := probes[0].Evaluate(result)
	if len(findings) != 1 || findings[0].RuleID != "XSS001" {
		t.Fatalf("expected XSS001, got %#v", findings)
	}
}

func TestStoredXSSFlagsMarkerAlreadyPresentInSeedEvidence(t *testing.T) {
	seed := xssSeed("https://api.example.com/profile", "text/html", `<div>spekto_xss_marker</div>`)
	rule := &StoredXSS{}

	probes, findings := rule.Check(seed, auth.Context{})
	if len(probes) != 0 {
		t.Fatalf("expected no probes, got %#v", probes)
	}
	if len(findings) != 1 || findings[0].RuleID != "XSS002" {
		t.Fatalf("expected XSS002, got %#v", findings)
	}
}

func TestReflectedXSSBuildsJSONBodyProbe(t *testing.T) {
	seed := xssSeed("https://api.example.com/comments", "application/json", `{"ok":true}`)
	seed.Evidence.Request.Method = http.MethodPost
	seed.Evidence.Request.Headers = map[string]string{"X-Trace": "trace-1"}
	seed.Evidence.Request.Body = []byte(`{"comment":"hello"}`)
	seed.AuthContextName = "user"
	rule := &ReflectedXSS{}

	probes, immediate := rule.Check(seed, auth.Context{})
	if len(immediate) != 0 {
		t.Fatalf("expected no immediate findings, got %#v", immediate)
	}
	if len(probes) != 1 {
		t.Fatalf("expected one body probe, got %#v", probes)
	}
	if probes[0].Request.AuthContextName != "user" || probes[0].Request.Headers["X-Trace"] != "trace-1" {
		t.Fatalf("expected auth context and headers preserved, got %#v", probes[0].Request)
	}
	if got := string(probes[0].Request.Body); !strings.Contains(got, `"spekto_xss_probe":"spekto_xss_marker"`) {
		t.Fatalf("expected JSON body marker, got %s", got)
	}

	findings := probes[0].Evaluate(executor.HTTPResult{
		StatusCode:      http.StatusOK,
		ResponseHeaders: map[string]string{"Content-Type": "application/json"},
		ResponseBody:    []byte(`{"echo":"spekto_xss_marker"}`),
		Method:          http.MethodPost,
		URL:             probes[0].Request.URL,
	})
	if len(findings) != 1 || findings[0].RuleID != "XSS001" {
		t.Fatalf("expected XSS001 from body reflection, got %#v", findings)
	}
}

func TestReflectedXSSSkipsEmptyOrNonJSONBodies(t *testing.T) {
	rule := &ReflectedXSS{}
	for _, body := range [][]byte{nil, []byte(`not-json`), []byte(`[{"comment":"hello"}]`)} {
		seed := xssSeed("https://api.example.com/comments", "application/json", `{"ok":true}`)
		seed.Evidence.Request.Method = http.MethodPost
		seed.Evidence.Request.Body = body

		probes, findings := rule.Check(seed, auth.Context{})
		if len(probes) != 0 || len(findings) != 0 {
			t.Fatalf("expected no probes/findings for body %q, got probes=%#v findings=%#v", body, probes, findings)
		}
	}
}

func xssSeed(rawURL, contentType, responseBody string) executor.Result {
	op := inventory.NewRESTOperation("GET", "/search")
	return executor.Result{
		Protocol:    inventory.ProtocolREST,
		Target:      "rest-api",
		OperationID: op.ID,
		Locator:     op.Locator,
		Status:      "succeeded",
		Evidence: executor.Evidence{
			Request: executor.RequestEvidence{
				Method: http.MethodGet,
				URL:    rawURL,
			},
			Response: executor.ResponseEvidence{
				StatusCode: http.StatusOK,
				Headers:    map[string]string{"Content-Type": contentType},
				Body:       []byte(responseBody),
			},
		},
	}
}
