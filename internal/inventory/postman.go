package inventory

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

type postmanCollection struct {
	Item []postmanItem `json:"item"`
}

type postmanItem struct {
	Name    string          `json:"name"`
	Item    []postmanItem   `json:"item"`
	Request *postmanRequest `json:"request"`
}

type postmanRequest struct {
	Method string              `json:"method"`
	Header []postmanNameValue  `json:"header"`
	URL    postmanURL          `json:"url"`
	Body   *postmanRequestBody `json:"body"`
}

type postmanNameValue struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type postmanRequestBody struct {
	Mode string `json:"mode"`
	Raw  string `json:"raw"`
}

type postmanURL struct {
	Raw   string             `json:"raw"`
	Host  []string           `json:"host"`
	Path  []string           `json:"path"`
	Query []postmanNameValue `json:"query"`
}

type PostmanDocument struct {
	Operations []Operation
	SourceRef  SourceRef
}

func ParsePostman(data []byte, source string) (*PostmanDocument, error) {
	var collection postmanCollection
	if err := json.Unmarshal(data, &collection); err != nil {
		return nil, err
	}

	sourceRef := SourceRef{
		Type:         SourceTraffic,
		Location:     source,
		ParserFamily: "postman",
		SupportLevel: SupportLevelFull,
	}

	opsByID := map[string]Operation{}
	for _, item := range collection.Item {
		walkPostmanItem(item, sourceRef, opsByID)
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

	return &PostmanDocument{
		Operations: ops,
		SourceRef:  sourceRef,
	}, nil
}

func walkPostmanItem(item postmanItem, sourceRef SourceRef, opsByID map[string]Operation) {
	if item.Request != nil {
		if op, ok, err := postmanRequestOperation(*item.Request, item.Name, sourceRef); err == nil && ok {
			if existing, found := opsByID[op.ID]; found {
				opsByID[op.ID] = mergeOperation(existing, op)
			} else {
				opsByID[op.ID] = op
			}
		}
	}
	for _, child := range item.Item {
		walkPostmanItem(child, sourceRef, opsByID)
	}
}

func postmanRequestOperation(req postmanRequest, itemName string, sourceRef SourceRef) (Operation, bool, error) {
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		return Operation{}, false, nil
	}
	targetURL, err := parsePostmanURL(req.URL)
	if err != nil {
		return Operation{}, false, err
	}
	if targetURL == nil {
		return Operation{}, false, nil
	}

	op := NewRESTOperation(method, targetURL.Path)
	op.SourceRefs = []SourceRef{sourceRef}
	op.Provenance = Provenance{Observed: true}
	op.Confidence = 0.8
	op.Status = StatusNormalized
	op.Targets = uniqueStrings([]string{originURL(targetURL)})
	op.DisplayName = itemName
	if strings.TrimSpace(op.DisplayName) == "" {
		op.DisplayName = op.Locator
	}
	op.REST = &RESTDetails{
		Method:           method,
		NormalizedPath:   normalizePath(targetURL.Path),
		OriginalPath:     targetURL.Path,
		ServerCandidates: uniqueStrings([]string{originURL(targetURL)}),
	}

	for _, header := range req.Header {
		if strings.TrimSpace(header.Key) == "" {
			continue
		}
		op.REST.HeaderParams = append(op.REST.HeaderParams, ParameterMeta{Name: header.Key, In: "header"})
		op.Examples.Parameters = append(op.Examples.Parameters, ParameterValue{
			Name:    header.Key,
			In:      "header",
			Example: header.Value,
		})
	}

	for _, query := range req.URL.Query {
		if strings.TrimSpace(query.Key) == "" {
			continue
		}
		op.REST.QueryParams = append(op.REST.QueryParams, ParameterMeta{Name: query.Key, In: "query"})
		op.Examples.Parameters = append(op.Examples.Parameters, ParameterValue{
			Name:    query.Key,
			In:      "query",
			Example: query.Value,
		})
	}

	if req.Body != nil && req.Body.Mode == "raw" {
		op.REST.RequestBody = &RequestBodyMeta{
			Content: []MediaTypeMeta{{
				MediaType: "application/json",
			}},
		}
		op.Examples.RequestBodies = append(op.Examples.RequestBodies, ExampleValue{
			MediaType: "application/json",
			Value:     req.Body.Raw,
		})
	}

	return op, true, nil
}

func parsePostmanURL(raw postmanURL) (*url.URL, error) {
	if strings.TrimSpace(raw.Raw) != "" {
		parsed, err := url.Parse(strings.TrimSpace(raw.Raw))
		if err != nil {
			return nil, fmt.Errorf("invalid Postman raw URL %q: %w", raw.Raw, err)
		}
		return parsed, nil
	}
	if len(raw.Host) == 0 {
		return nil, nil
	}
	host := strings.Join(raw.Host, ".")
	path := "/" + strings.Join(raw.Path, "/")
	u := &url.URL{
		Scheme: "https",
		Host:   host,
		Path:   normalizePath(path),
	}
	if len(raw.Query) > 0 {
		values := url.Values{}
		for _, q := range raw.Query {
			values.Set(q.Key, q.Value)
		}
		u.RawQuery = values.Encode()
	}
	return u, nil
}
