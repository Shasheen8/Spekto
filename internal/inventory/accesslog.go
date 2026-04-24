package inventory

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
)

const maxAccessLogBytes = 20 * 1024 * 1024
const maxAccessLogRecords = 100000

type accessLogRecord struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	URL    string `json:"url"`
	Host   string `json:"host"`
	Scheme string `json:"scheme"`
	Status int    `json:"status"`
	Target string `json:"target"`
}

type AccessLogDocument struct {
	Operations []Operation
	SourceRef  SourceRef
}

func ParseAccessLogFile(path string) (*AccessLogDocument, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > maxAccessLogBytes {
		return nil, fmt.Errorf("access log %s exceeds %d byte limit", path, maxAccessLogBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseAccessLog(data, path)
}

func ParseAccessLog(data []byte, source string) (*AccessLogDocument, error) {
	records, err := parseAccessLogRecords(data)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, errors.New("access log extract contains no records")
	}

	sourceRef := SourceRef{
		Type:         SourceTraffic,
		Location:     source,
		ParserFamily: "access_log",
		SupportLevel: SupportLevelFull,
	}

	opsByID := map[string]Operation{}
	for _, record := range records {
		op, ok, err := accessLogOperation(record, sourceRef)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		if existing, found := opsByID[op.ID]; found {
			opsByID[op.ID] = mergeOperation(existing, op)
			continue
		}
		opsByID[op.ID] = op
	}

	ops := make([]Operation, 0, len(opsByID))
	for _, op := range opsByID {
		ops = append(ops, op)
	}
	sort.Slice(ops, func(i, j int) bool {
		if ops[i].Locator == ops[j].Locator {
			return ops[i].ID < ops[j].ID
		}
		return ops[i].Locator < ops[j].Locator
	})

	return &AccessLogDocument{
		Operations: ops,
		SourceRef:  sourceRef,
	}, nil
}

func parseAccessLogRecords(data []byte) ([]accessLogRecord, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, errors.New("access log extract is empty")
	}
	if strings.HasPrefix(trimmed, "[") {
		var records []accessLogRecord
		if err := json.Unmarshal(data, &records); err != nil {
			return nil, err
		}
		if len(records) > maxAccessLogRecords {
			return nil, fmt.Errorf("access log has %d records, limit is %d", len(records), maxAccessLogRecords)
		}
		return records, nil
	}
	var records []accessLogRecord
	scanner := bufio.NewScanner(strings.NewReader(trimmed))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var record accessLogRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			return nil, err
		}
		records = append(records, record)
		if len(records) > maxAccessLogRecords {
			return nil, fmt.Errorf("access log has more than %d records", maxAccessLogRecords)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

func accessLogOperation(record accessLogRecord, sourceRef SourceRef) (Operation, bool, error) {
	method := strings.ToUpper(strings.TrimSpace(record.Method))
	if method == "" {
		return Operation{}, false, nil
	}
	targetURL, err := recordURL(record)
	if err != nil {
		return Operation{}, false, err
	}
	if targetURL == nil {
		return Operation{}, false, nil
	}

	normalizedPath, dynParams, dynExamples := NormalizeTrafficPath(targetURL.Path)
	op := NewRESTOperation(method, normalizedPath)
	op.SourceRefs = []SourceRef{sourceRef}
	op.Provenance = Provenance{Observed: true}
	op.Confidence = 0.7
	op.Status = StatusNormalized
	op.Origins = uniqueStrings([]string{originURL(targetURL)})
	op.DisplayName = op.Locator
	op.REST = &RESTDetails{
		Method:           method,
		NormalizedPath:   normalizedPath,
		OriginalPath:     targetURL.Path,
		PathParams:       dynParams,
		ServerCandidates: uniqueStrings([]string{originURL(targetURL)}),
	}
	op.Examples.Parameters = append(op.Examples.Parameters, dynExamples...)
	if record.Status != 0 {
		op.REST.ResponseMap = append(op.REST.ResponseMap, ResponseMeta{
			StatusCode: fmt.Sprintf("%d", record.Status),
		})
	}
	return op, true, nil
}

func recordURL(record accessLogRecord) (*url.URL, error) {
	if strings.TrimSpace(record.URL) != "" {
		parsed, err := url.Parse(strings.TrimSpace(record.URL))
		if err != nil {
			return nil, fmt.Errorf("invalid access log url %q: %w", record.URL, err)
		}
		return parsed, nil
	}
	if strings.TrimSpace(record.Path) == "" {
		return nil, nil
	}
	path := normalizePath(record.Path)
	target := strings.TrimSpace(record.Target)
	if target != "" {
		parsed, err := url.Parse(target)
		if err != nil {
			return nil, fmt.Errorf("invalid access log target %q: %w", record.Target, err)
		}
		parsed.Path = path
		return parsed, nil
	}
	host := strings.TrimSpace(record.Host)
	if host == "" {
		return &url.URL{Path: path}, nil
	}
	scheme := strings.TrimSpace(record.Scheme)
	if scheme == "" {
		scheme = "https"
	}
	return &url.URL{
		Scheme: scheme,
		Host:   host,
		Path:   path,
	}, nil
}
