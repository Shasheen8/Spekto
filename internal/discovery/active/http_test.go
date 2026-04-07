package active

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDiscoverHTTPTargetFindsOpenAPISpec(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/openapi.json" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
		  "openapi":"3.1.0",
		  "info":{"title":"Test","version":"1.0.0"},
		  "paths":{"/v1/models":{"get":{"responses":{"200":{"description":"ok"}}}}}
		}`))
	}))
	defer server.Close()

	doc, err := DiscoverHTTPTarget(context.Background(), server.Client(), server.URL)
	if err != nil {
		t.Fatalf("DiscoverHTTPTarget returned error: %v", err)
	}
	if len(doc.Operations) != 1 {
		t.Fatalf("expected 1 operation, got %d", len(doc.Operations))
	}
	if !doc.Operations[0].Provenance.ActivelyDiscovered {
		t.Fatalf("expected active provenance")
	}
}

func TestDiscoverHTTPTargetFindsGraphQLIntrospection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/graphql" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
		  "data":{
		    "__schema":{
		      "queryType":{"name":"Query"},
		      "mutationType":null,
		      "subscriptionType":null,
		      "types":[
		        {"kind":"OBJECT","name":"Query","fields":[{"name":"model","args":[{"name":"id","type":{"kind":"SCALAR","name":"ID","ofType":null},"defaultValue":null}],"type":{"kind":"OBJECT","name":"Model","ofType":null}}]},
		        {"kind":"OBJECT","name":"Model","fields":[]}
		      ]
		    }
		  }
		}`))
	}))
	defer server.Close()

	doc, err := DiscoverHTTPTarget(context.Background(), server.Client(), server.URL)
	if err != nil {
		t.Fatalf("DiscoverHTTPTarget returned error: %v", err)
	}
	if len(doc.Operations) != 1 {
		t.Fatalf("expected 1 operation, got %d", len(doc.Operations))
	}
	if doc.Operations[0].Protocol != "graphql" {
		t.Fatalf("unexpected protocol: %s", doc.Operations[0].Protocol)
	}
}
