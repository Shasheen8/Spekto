package inventory

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

type harEnvelope struct {
	Log harLog `json:"log"`
}

type harLog struct {
	Entries []harEntry `json:"entries"`
}

type harEntry struct {
	Request  harRequest  `json:"request"`
	Response harResponse `json:"response"`
}

type harRequest struct {
	Method      string         `json:"method"`
	URL         string         `json:"url"`
	Headers     []harNameValue `json:"headers"`
	QueryString []harNameValue `json:"queryString"`
	Cookies     []harNameValue `json:"cookies"`
	PostData    *harPostData   `json:"postData"`
}

type harResponse struct {
	Status  int        `json:"status"`
	Content harContent `json:"content"`
}

type harContent struct {
	MimeType string `json:"mimeType"`
}

type harPostData struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

type harNameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type HARDocument struct {
	Operations []Operation
	SourceRef  SourceRef
}

func ParseHAR(data []byte, source string) (*HARDocument, error) {
	var envelope harEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, err
	}

	sourceRef := SourceRef{
		Type:         SourceTraffic,
		Location:     source,
		ParserFamily: "har",
		SupportLevel: SupportLevelFull,
	}

	opsByID := map[string]Operation{}
	for _, entry := range envelope.Log.Entries {
		op, ok, err := harEntryOperation(entry, sourceRef)
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

	return &HARDocument{
		Operations: ops,
		SourceRef:  sourceRef,
	}, nil
}

func harEntryOperation(entry harEntry, sourceRef SourceRef) (Operation, bool, error) {
	method := strings.ToUpper(strings.TrimSpace(entry.Request.Method))
	if method == "" {
		return Operation{}, false, nil
	}
	parsedURL, err := url.Parse(strings.TrimSpace(entry.Request.URL))
	if err != nil {
		return Operation{}, false, fmt.Errorf("invalid HAR request URL %q: %w", entry.Request.URL, err)
	}
	normalizedPath, dynParams, dynExamples := NormalizeTrafficPath(parsedURL.Path)
	op := NewRESTOperation(method, normalizedPath)
	op.SourceRefs = []SourceRef{sourceRef}
	op.Provenance = Provenance{Observed: true}
	op.Confidence = 0.8
	op.Status = StatusNormalized
	op.Origins = uniqueStrings([]string{originURL(parsedURL)})
	op.DisplayName = op.Locator
	op.REST = &RESTDetails{
		Method:           method,
		NormalizedPath:   normalizedPath,
		OriginalPath:     parsedURL.Path,
		PathParams:       dynParams,
		ServerCandidates: uniqueStrings([]string{originURL(parsedURL)}),
	}
	op.Examples.Parameters = append(op.Examples.Parameters, dynExamples...)

	for _, header := range entry.Request.Headers {
		meta := ParameterMeta{Name: header.Name, In: "header"}
		op.REST.HeaderParams = append(op.REST.HeaderParams, meta)
		op.Examples.Parameters = append(op.Examples.Parameters, ParameterValue{
			Name:    header.Name,
			In:      "header",
			Example: RedactExample(header.Name, "header", header.Value),
		})
	}
	for _, query := range entry.Request.QueryString {
		meta := ParameterMeta{Name: query.Name, In: "query"}
		op.REST.QueryParams = append(op.REST.QueryParams, meta)
		op.Examples.Parameters = append(op.Examples.Parameters, ParameterValue{
			Name:    query.Name,
			In:      "query",
			Example: RedactExample(query.Name, "query", query.Value),
		})
	}
	for _, cookie := range entry.Request.Cookies {
		meta := ParameterMeta{Name: cookie.Name, In: "cookie"}
		op.REST.CookieParams = append(op.REST.CookieParams, meta)
		op.Examples.Parameters = append(op.Examples.Parameters, ParameterValue{
			Name:    cookie.Name,
			In:      "cookie",
			Example: RedactExample(cookie.Name, "cookie", cookie.Value),
		})
	}

	if entry.Request.PostData != nil {
		op.REST.RequestBody = &RequestBodyMeta{
			Content: []MediaTypeMeta{{
				MediaType: entry.Request.PostData.MimeType,
			}},
		}
		op.Examples.RequestBodies = append(op.Examples.RequestBodies, ExampleValue{
			MediaType: entry.Request.PostData.MimeType,
			Value:     RedactBodyExample(entry.Request.PostData.Text),
		})
	}

	if entry.Response.Status != 0 {
		statusCode := fmt.Sprintf("%d", entry.Response.Status)
		op.REST.ResponseMap = append(op.REST.ResponseMap, ResponseMeta{
			StatusCode: statusCode,
			Content: []MediaTypeMeta{{
				MediaType: entry.Response.Content.MimeType,
			}},
		})
	}

	return op, true, nil
}

func originURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	if u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}
