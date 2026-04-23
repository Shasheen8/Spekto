package seed

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Record is a captured successful request that serves as a seed for future scans.
// It stores the full request evidence and provenance so it can be replayed or
// used by later phases to generate mutations.
type Record struct {
	OperationID     string            `json:"operation_id"`
	Locator         string            `json:"locator"`
	Protocol        string            `json:"protocol"`
	Target          string            `json:"target,omitempty"`
	AuthContextName string            `json:"auth_context_name,omitempty"`
	Method          string            `json:"method,omitempty"`
	URL             string            `json:"url,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	Body            []byte            `json:"body,omitempty"`
	ContentType     string            `json:"content_type,omitempty"`
	GRPCMethod      string            `json:"grpc_method,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
	ResponseStatus  int               `json:"response_status,omitempty"`
	GRPCCode        string            `json:"grpc_code,omitempty"`
	CapturedAt      time.Time         `json:"captured_at"`
	Source          string            `json:"source"` // "scan"
}

// Store holds captured seed records. Records are keyed by operation ID and
// auth context name — one record per (operation, auth) pair is retained.
type Store struct {
	Records []Record `json:"records"`
}

// LoadStoreFile loads a seed store from a JSON file.
// Returns an empty store when the file does not exist.
func LoadStoreFile(path string) (*Store, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Store{}, nil
		}
		return nil, fmt.Errorf("read seed store %s: %w", path, err)
	}
	var s Store
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse seed store %s: %w", path, err)
	}
	return &s, nil
}

// Save writes the store to a JSON file with 0600 permissions.
// Any existing file is removed first to ensure permissions are always applied.
func (s *Store) Save(path string) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	_ = os.Remove(path)
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

// Add inserts or replaces the record for the given (operation, auth context) pair.
func (s *Store) Add(record Record) {
	for i, existing := range s.Records {
		if existing.OperationID == record.OperationID && existing.AuthContextName == record.AuthContextName {
			s.Records[i] = record
			return
		}
	}
	s.Records = append(s.Records, record)
}

// Lookup returns the seed for the given operation and auth context.
func (s *Store) Lookup(operationID, authContextName string) (Record, bool) {
	for _, r := range s.Records {
		if r.OperationID == operationID && r.AuthContextName == authContextName {
			return r, true
		}
	}
	return Record{}, false
}

// ForOperation returns all seeds for the given operation ID across all auth contexts.
func (s *Store) ForOperation(operationID string) []Record {
	var out []Record
	for _, r := range s.Records {
		if r.OperationID == operationID {
			out = append(out, r)
		}
	}
	return out
}
