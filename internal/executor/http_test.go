package executor

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Shasheen8/Spekto/internal/auth"
	"github.com/Shasheen8/Spekto/internal/config"
)

func TestExecuteHTTPAppliesAuthAndCapturesResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token-1" {
			t.Fatalf("unexpected authorization header: %s", r.Header.Get("Authorization"))
		}
		if r.Header.Get("X-Spekto-Request-ID") == "" {
			t.Fatalf("missing correlation header")
		}
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc"})
		w.Header().Set("X-Trace", "trace-1")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	registry, err := auth.NewRegistry(config.Config{
		AuthContexts: []config.AuthContext{
			{Name: "bearer", BearerToken: "token-1"},
		},
	})
	if err != nil {
		t.Fatalf("auth.NewRegistry returned error: %v", err)
	}

	results, err := ExecuteHTTP(context.Background(), server.Client(), []HTTPRequest{{
		OperationID:     "op-1",
		Method:          http.MethodGet,
		URL:             server.URL,
		AuthContextName: "bearer",
	}}, registry, HTTPPolicy{Concurrency: 1, RequestBudget: 1, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("ExecuteHTTP returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].StatusCode != http.StatusOK {
		t.Fatalf("unexpected status code: %d", results[0].StatusCode)
	}
	if string(results[0].ResponseBody) != `{"ok":true}` {
		t.Fatalf("unexpected response body: %s", string(results[0].ResponseBody))
	}
	if results[0].RequestHeaders["Authorization"] != "[redacted]" {
		t.Fatalf("expected redacted authorization header: %#v", results[0].RequestHeaders)
	}
	if results[0].ResponseHeaders["Set-Cookie"] != "[redacted]" {
		t.Fatalf("expected redacted set-cookie header: %#v", results[0].ResponseHeaders)
	}
}

func TestExecuteHTTPMarksBudgetExceededRequestsSkipped(t *testing.T) {
	results, err := ExecuteHTTP(context.Background(), nil, []HTTPRequest{
		{ID: "a", Method: http.MethodGet, URL: "https://a.example.com"},
		{ID: "b", Method: http.MethodGet, URL: "https://b.example.com"},
	}, auth.Registry{}, HTTPPolicy{Concurrency: 1, RequestBudget: 1, Timeout: time.Second})
	if err != nil {
		t.Fatalf("ExecuteHTTP returned error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if results[1].Error != "skipped: request budget exceeded" {
		t.Fatalf("unexpected skip error: %s", results[1].Error)
	}
}

func TestExecuteHTTPTruncatesLargeResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("0123456789"))
	}))
	defer server.Close()

	results, err := ExecuteHTTP(context.Background(), server.Client(), []HTTPRequest{{
		Method: http.MethodGet,
		URL:    server.URL,
	}}, auth.Registry{}, HTTPPolicy{Concurrency: 1, RequestBudget: 1, Timeout: time.Second, MaxResponseBytes: 4})
	if err != nil {
		t.Fatalf("ExecuteHTTP returned error: %v", err)
	}
	if len(results[0].ResponseBody) != 4 {
		t.Fatalf("unexpected response body length: %d", len(results[0].ResponseBody))
	}
	if !results[0].Truncated {
		t.Fatalf("expected truncated response")
	}
}

func TestExecuteHTTPRejectsUnknownAuthContext(t *testing.T) {
	results, err := ExecuteHTTP(context.Background(), nil, []HTTPRequest{{
		Method:          http.MethodGet,
		URL:             "https://api.example.com",
		AuthContextName: "missing",
	}}, auth.Registry{}, HTTPPolicy{Concurrency: 1, RequestBudget: 1, Timeout: time.Second})
	if err != nil {
		t.Fatalf("ExecuteHTTP returned error: %v", err)
	}
	if results[0].Error == "" {
		t.Fatalf("expected auth context error")
	}
}

func TestExecuteHTTPDoesNotRetryUnsafeMethods(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	results, err := ExecuteHTTP(context.Background(), server.Client(), []HTTPRequest{{
		Method: http.MethodPost,
		URL:    server.URL,
	}}, auth.Registry{}, HTTPPolicy{Concurrency: 1, RequestBudget: 3, Timeout: time.Second, Retries: 2})
	if err != nil {
		t.Fatalf("ExecuteHTTP returned error: %v", err)
	}
	if attempts != 1 {
		t.Fatalf("expected one attempt for unsafe method, got %d", attempts)
	}
	if results[0].StatusCode != http.StatusInternalServerError {
		t.Fatalf("unexpected status code: %d", results[0].StatusCode)
	}
}

func TestExecuteHTTPRetriesSafeMethods(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	results, err := ExecuteHTTP(context.Background(), server.Client(), []HTTPRequest{{
		Method: http.MethodGet,
		URL:    server.URL,
	}}, auth.Registry{}, HTTPPolicy{Concurrency: 1, RequestBudget: 3, Timeout: time.Second, Retries: 2})
	if err != nil {
		t.Fatalf("ExecuteHTTP returned error: %v", err)
	}
	if attempts != 3 {
		t.Fatalf("expected three attempts for safe method, got %d", attempts)
	}
	if results[0].StatusCode != http.StatusTooManyRequests {
		t.Fatalf("unexpected status code: %d", results[0].StatusCode)
	}
}

func TestExecuteHTTPRetriesNetworkErrorsOnlyForSafeMethods(t *testing.T) {
	attempts := 0
	client := &http.Client{
		Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			attempts++
			return nil, errors.New("network down")
		}),
	}

	_, err := ExecuteHTTP(context.Background(), client, []HTTPRequest{{
		Method: http.MethodGet,
		URL:    "https://api.example.com",
	}}, auth.Registry{}, HTTPPolicy{Concurrency: 1, RequestBudget: 2, Timeout: time.Second, Retries: 1})
	if err != nil {
		t.Fatalf("ExecuteHTTP returned error: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("expected two attempts for safe method network failure, got %d", attempts)
	}

	attempts = 0
	_, err = ExecuteHTTP(context.Background(), client, []HTTPRequest{{
		Method: http.MethodPost,
		URL:    "https://api.example.com",
	}}, auth.Registry{}, HTTPPolicy{Concurrency: 1, RequestBudget: 1, Timeout: time.Second, Retries: 1})
	if err != nil {
		t.Fatalf("ExecuteHTTP returned error: %v", err)
	}
	if attempts != 1 {
		t.Fatalf("expected one attempt for unsafe method network failure, got %d", attempts)
	}
}

func TestExecuteHTTPRejectsRedirectOutsideAllowlist(t *testing.T) {
	redirected := false
	blocked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected = true
		w.WriteHeader(http.StatusOK)
	}))
	defer blocked.Close()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, blocked.URL, http.StatusFound)
	}))
	defer server.Close()

	results, err := ExecuteHTTP(context.Background(), server.Client(), []HTTPRequest{{
		Method: http.MethodGet,
		URL:    server.URL,
	}}, auth.Registry{}, HTTPPolicy{
		Concurrency:     1,
		RequestBudget:   2,
		Timeout:         time.Second,
		FollowRedirects: true,
		TargetAllowlist: []string{"127.0.0.2"},
	})
	if err != nil {
		t.Fatalf("ExecuteHTTP returned error: %v", err)
	}
	if redirected {
		t.Fatalf("redirect outside allowlist should not be followed")
	}
	if results[0].Error == "" {
		t.Fatalf("expected redirect allowlist error")
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
