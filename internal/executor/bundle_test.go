package executor

import "testing"

func TestCoverageClassifiesBlockReasons(t *testing.T) {
	results := []Result{
		{Target: "t", OperationID: "auth", Locator: "GET:/auth", Status: "skipped", Error: "skipped: no matching auth context"},
		{Target: "t", OperationID: "budget", Locator: "GET:/budget", Status: "skipped", Error: "skipped: request budget exceeded"},
		{Target: "t", OperationID: "stream", Locator: "Svc/Stream", Status: "skipped", Error: "skipped: streaming gRPC methods are not supported"},
		{Target: "t", OperationID: "schema", Locator: "GET:/schema", Status: "failed", SchemaGaps: []string{"query:id"}, Evidence: Evidence{Response: ResponseEvidence{StatusCode: 400}}},
		{Target: "t", OperationID: "status", Locator: "GET:/status", Status: "failed", Evidence: Evidence{Response: ResponseEvidence{StatusCode: 500}}},
		{Target: "t", OperationID: "grpc", Locator: "Svc/Get", Status: "failed", Evidence: Evidence{Response: ResponseEvidence{GRPCCode: "UNAUTHENTICATED"}}},
		{Target: "t", OperationID: "net", Locator: "GET:/net", Status: "failed", Error: "dial tcp timeout"},
	}
	bundle := Bundle{Results: results}
	bundle.Finalize()

	want := []string{
		"auth_missing",
		"budget_exceeded",
		"streaming_unsupported",
		"schema_gap",
		"bad_status",
		"bad_status",
		"network_error",
	}
	for i, reason := range want {
		if got := bundle.Coverage.Entries[i].BlockReason; got != reason {
			t.Fatalf("entry %d expected %s, got %s", i, reason, got)
		}
	}
	if bundle.Coverage.ByReason["bad_status"] != 2 {
		t.Fatalf("expected two bad_status entries, got %#v", bundle.Coverage.ByReason)
	}
}

func TestEvidenceRedactedScrubsSensitiveHeadersURLsAndJSON(t *testing.T) {
	evidence := Evidence{
		Request: RequestEvidence{
			URL: "https://user:pass@example.com/v1/users?api_key=secret&cursor=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig&safe=1",
			Headers: map[string]string{
				"X-Auth-Token":        "secret-token",
				"X-Spekto-Request-ID": "req-1",
			},
			Metadata: map[string]string{
				"authorization": "Bearer secret",
			},
			Body: []byte(`{"email":"user@example.com","password":"p","nested":{"access_token":"tok"},"jwt":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"}`),
		},
		Response: ResponseEvidence{
			Headers: map[string]string{
				"Set-Cookie": "session=abc",
				"X-Trace":    "trace-1",
			},
			Body: []byte(`{"ok":true,"session_id":"abc"}`),
		},
	}

	redacted := evidence.Redacted()
	if redacted.Request.Headers["X-Auth-Token"] != "[redacted]" {
		t.Fatalf("expected sensitive request header redacted: %#v", redacted.Request.Headers)
	}
	if redacted.Request.Headers["X-Spekto-Request-ID"] != "req-1" {
		t.Fatalf("expected non-sensitive request header preserved: %#v", redacted.Request.Headers)
	}
	if redacted.Request.Metadata["authorization"] != "[redacted]" {
		t.Fatalf("expected sensitive metadata redacted: %#v", redacted.Request.Metadata)
	}
	if got := redacted.Request.URL; got != "https://%5Bredacted%5D@example.com/v1/users?api_key=%5Bredacted%5D&cursor=%5Bredacted%5D&safe=1" {
		t.Fatalf("unexpected redacted URL: %s", got)
	}
	if got := string(redacted.Request.Body); got != `{"email":"user@example.com","jwt":"[redacted]","nested":{"access_token":"[redacted]"},"password":"[redacted]"}` {
		t.Fatalf("unexpected redacted request body: %s", got)
	}
	if redacted.Response.Headers["Set-Cookie"] != "[redacted]" {
		t.Fatalf("expected set-cookie redacted: %#v", redacted.Response.Headers)
	}
	if got := string(redacted.Response.Body); got != `{"ok":true,"session_id":"[redacted]"}` {
		t.Fatalf("unexpected redacted response body: %s", got)
	}
}
