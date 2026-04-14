package seed

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStoreAddAndLookup(t *testing.T) {
	s := &Store{}
	rec := Record{
		OperationID:     "op1",
		Locator:         "GET:/v1/models",
		Protocol:        "rest",
		AuthContextName: "prod",
		Method:          "GET",
		URL:             "https://api.example.com/v1/models",
		ResponseStatus:  200,
		CapturedAt:      time.Now().UTC(),
		Source:          "scan",
	}
	s.Add(rec)

	got, ok := s.Lookup("op1", "prod")
	if !ok {
		t.Fatal("expected record to be found")
	}
	if got.URL != rec.URL {
		t.Fatalf("expected URL %q, got %q", rec.URL, got.URL)
	}
}

func TestStoreReplaceExisting(t *testing.T) {
	s := &Store{}
	s.Add(Record{OperationID: "op1", AuthContextName: "prod", URL: "old-url", Source: "scan"})
	s.Add(Record{OperationID: "op1", AuthContextName: "prod", URL: "new-url", Source: "scan"})

	if len(s.Records) != 1 {
		t.Fatalf("expected 1 record after replace, got %d", len(s.Records))
	}
	got, _ := s.Lookup("op1", "prod")
	if got.URL != "new-url" {
		t.Fatalf("expected replaced URL, got %q", got.URL)
	}
}

func TestStoreDistinctAuthContexts(t *testing.T) {
	s := &Store{}
	s.Add(Record{OperationID: "op1", AuthContextName: "user-a", Source: "scan"})
	s.Add(Record{OperationID: "op1", AuthContextName: "user-b", Source: "scan"})

	if len(s.Records) != 2 {
		t.Fatalf("expected 2 records for different auth contexts, got %d", len(s.Records))
	}
	_, okA := s.Lookup("op1", "user-a")
	_, okB := s.Lookup("op1", "user-b")
	if !okA || !okB {
		t.Fatal("expected both auth context records to be found")
	}
}

func TestStoreForOperation(t *testing.T) {
	s := &Store{}
	s.Add(Record{OperationID: "op1", AuthContextName: "a", Source: "scan"})
	s.Add(Record{OperationID: "op1", AuthContextName: "b", Source: "scan"})
	s.Add(Record{OperationID: "op2", AuthContextName: "a", Source: "scan"})

	records := s.ForOperation("op1")
	if len(records) != 2 {
		t.Fatalf("expected 2 records for op1, got %d", len(records))
	}
	for _, r := range records {
		if r.OperationID != "op1" {
			t.Fatalf("expected only op1 records, got %q", r.OperationID)
		}
	}
}

func TestStoreNotFound(t *testing.T) {
	s := &Store{}
	_, ok := s.Lookup("missing", "ctx")
	if ok {
		t.Fatal("expected not found for missing record")
	}
}

func TestLoadStoreFileNotExist(t *testing.T) {
	s, err := LoadStoreFile(filepath.Join(t.TempDir(), "nonexistent.json"))
	if err != nil {
		t.Fatalf("expected no error for missing file, got %v", err)
	}
	if s == nil || len(s.Records) != 0 {
		t.Fatal("expected empty store for missing file")
	}
}

func TestStoreSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "seeds.json")

	s := &Store{}
	s.Add(Record{
		OperationID:     "op1",
		Locator:         "GET:/v1/items",
		Protocol:        "rest",
		AuthContextName: "ctx",
		Method:          "GET",
		URL:             "https://api.example.com/v1/items",
		ResponseStatus:  200,
		CapturedAt:      time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		Source:          "scan",
	})
	if err := s.Save(path); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}

	loaded, err := LoadStoreFile(path)
	if err != nil {
		t.Fatalf("LoadStoreFile returned error: %v", err)
	}
	if len(loaded.Records) != 1 {
		t.Fatalf("expected 1 record after load, got %d", len(loaded.Records))
	}
	got := loaded.Records[0]
	if got.OperationID != "op1" || got.URL != "https://api.example.com/v1/items" {
		t.Fatalf("unexpected record after load: %+v", got)
	}
}

func TestStoreSaveFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seeds.json")
	s := &Store{}
	if err := s.Save(path); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat returned error: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600 permissions, got %o", info.Mode().Perm())
	}
}
