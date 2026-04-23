package executor

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Shasheen8/Spekto/internal/auth"
	"github.com/Shasheen8/Spekto/internal/config"
)

const defaultMaxResponseBytes = 64 * 1024
const correlationHeader = "X-Spekto-Request-ID"

type HTTPRequest struct {
	ID              string
	OperationID     string
	Method          string
	URL             string
	Headers         map[string]string
	Body            []byte
	ContentType     string
	AuthContextName string
	SchemaGaps      []string
}

type HTTPResult struct {
	RequestID          string
	OperationID        string
	AuthContextName    string
	Method             string
	URL                string
	StatusCode         int
	Duration           time.Duration
	StartedAt          time.Time
	Truncated          bool
	Error              string

	RequestBody        []byte
	RequestContentType string
	RequestHeaders     map[string]string
	ResponseHeaders    map[string]string
	ResponseBody       []byte
}

type HTTPPolicy struct {
	Concurrency      int
	RequestBudget    int
	Timeout          time.Duration
	MaxResponseBytes int64
	Retries          int
	RateLimit        float64
	FollowRedirects  bool
}

type httpExecutorState struct {
	registry    auth.Registry
	policy      HTTPPolicy
	limiter     *rateLimiter
	clientCache map[string]*http.Client
	clientMu    sync.Mutex
}

func NewHTTPPolicy(scan config.ScanPolicy) HTTPPolicy {
	policy := HTTPPolicy{
		Concurrency:      scan.Concurrency,
		RequestBudget:    scan.RequestBudget,
		Timeout:          scan.Timeout,
		MaxResponseBytes: scan.MaxResponseBytes,
		Retries:          scan.Retries,
		RateLimit:        scan.RateLimit,
		FollowRedirects:  scan.FollowRedirects,
	}
	if policy.Concurrency <= 0 {
		policy.Concurrency = 1
	}
	if policy.RequestBudget <= 0 {
		policy.RequestBudget = 1
	}
	if policy.Timeout <= 0 {
		policy.Timeout = 5 * time.Second
	}
	if policy.MaxResponseBytes <= 0 {
		policy.MaxResponseBytes = defaultMaxResponseBytes
	}
	return policy
}

func ExecuteHTTP(ctx context.Context, client *http.Client, requests []HTTPRequest, registry auth.Registry, policy HTTPPolicy) ([]HTTPResult, error) {
	if client == nil {
		client = &http.Client{}
	}
	if policy.Concurrency <= 0 {
		policy.Concurrency = 1
	}
	if policy.RequestBudget <= 0 {
		policy.RequestBudget = len(requests)
	}
	if policy.Timeout <= 0 {
		policy.Timeout = 5 * time.Second
	}
	if policy.MaxResponseBytes <= 0 {
		policy.MaxResponseBytes = defaultMaxResponseBytes
	}

	results := make([]HTTPResult, len(requests))
	limit := len(requests)
	if policy.RequestBudget < limit {
		limit = policy.RequestBudget
	}
	for i := limit; i < len(requests); i++ {
		results[i] = skippedResult(requests[i], i)
	}
	if limit == 0 {
		return results, nil
	}

	state := &httpExecutorState{
		registry:    registry,
		policy:      policy,
		limiter:     newRateLimiter(policy.RateLimit),
		clientCache: map[string]*http.Client{"": cloneHTTPClient(client, nil, policy.FollowRedirects)},
	}

	type job struct {
		index int
		req   HTTPRequest
	}
	jobs := make(chan job, limit)

	var wg sync.WaitGroup
	workerCount := minInt(policy.Concurrency, limit)
	for range workerCount {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				results[item.index] = state.executeOneHTTP(ctx, client, item.req, item.index)
			}
		}()
	}

	for i := 0; i < limit; i++ {
		jobs <- job{index: i, req: requests[i]}
	}
	close(jobs)
	wg.Wait()

	return results, nil
}

func (s *httpExecutorState) executeOneHTTP(ctx context.Context, baseClient *http.Client, request HTTPRequest, index int) HTTPResult {
	requestID := request.ID
	if strings.TrimSpace(requestID) == "" {
		requestID = fmt.Sprintf("req-%06d", index+1)
	}

	result := HTTPResult{
		RequestID:       requestID,
		OperationID:     request.OperationID,
		AuthContextName: request.AuthContextName,
		Method:          strings.ToUpper(strings.TrimSpace(request.Method)),
		URL:             request.URL,
		StartedAt:       time.Now().UTC(),
	}
	if result.Method == "" {
		result.Error = "request method must not be empty"
		return result
	}
	if strings.TrimSpace(result.URL) == "" {
		result.Error = "request url must not be empty"
		return result
	}

	authContext := auth.Context{}
	hasAuthContext := false
	if strings.TrimSpace(request.AuthContextName) != "" {
		value, ok := s.registry.Get(request.AuthContextName)
		if !ok {
			result.Error = fmt.Sprintf("unknown auth context %q", request.AuthContextName)
			return result
		}
		authContext = value
		hasAuthContext = true
		result.URL = auth.RedactURL(result.URL, authContext)
	}

	client, err := s.clientForContext(baseClient, authContext, hasAuthContext)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	start := time.Now()
	for attempt := 0; attempt <= s.policy.Retries; attempt++ {
		if err := s.limiter.Wait(ctx); err != nil {
			result.Error = err.Error()
			return result
		}
		attemptResult, retryable := s.doHTTPAttempt(ctx, client, request, requestID, authContext, hasAuthContext)
		result = attemptResult
		result.Duration = time.Since(start)
		if !retryable || !isRetrySafeMethod(result.Method) || attempt == s.policy.Retries {
			return result
		}
	}
	return result
}

func (s *httpExecutorState) doHTTPAttempt(ctx context.Context, client *http.Client, request HTTPRequest, requestID string, authContext auth.Context, hasAuthContext bool) (HTTPResult, bool) {
	result := HTTPResult{
		RequestID:          requestID,
		OperationID:        request.OperationID,
		AuthContextName:    request.AuthContextName,
		Method:             strings.ToUpper(strings.TrimSpace(request.Method)),
		URL:                request.URL,
		StartedAt:          time.Now().UTC(),
		RequestBody:        request.Body,
		RequestContentType: request.ContentType,
	}
	if hasAuthContext {
		result.URL = auth.RedactURL(result.URL, authContext)
	}

	reqCtx, cancel := context.WithTimeout(ctx, s.policy.Timeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(reqCtx, result.Method, request.URL, bytes.NewReader(request.Body))
	if err != nil {
		result.Error = err.Error()
		return result, false
	}
	for key, value := range request.Headers {
		httpReq.Header.Set(key, value)
	}
	if request.ContentType != "" && httpReq.Header.Get("Content-Type") == "" {
		httpReq.Header.Set("Content-Type", request.ContentType)
	}
	httpReq.Header.Set(correlationHeader, requestID)

	if hasAuthContext {
		if err := authContext.ApplyHTTPRequest(httpReq); err != nil {
			result.Error = err.Error()
			result.RequestHeaders = redactHeaderMap(httpReq.Header)
			return result, false
		}
	}

	result.RequestHeaders = redactHeaderMap(httpReq.Header)
	start := time.Now()
	resp, err := client.Do(httpReq)
	result.Duration = time.Since(start)
	if err != nil {
		result.Error = err.Error()
		return result, true
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.ResponseHeaders = redactHeaderMap(resp.Header)
	body, truncated, readErr := readLimitedBody(resp.Body, s.policy.MaxResponseBytes)
	if readErr != nil {
		result.Error = readErr.Error()
		return result, false
	}
	result.ResponseBody = body
	result.Truncated = truncated
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= http.StatusInternalServerError {
		return result, true
	}
	return result, false
}

func (s *httpExecutorState) clientForContext(baseClient *http.Client, authContext auth.Context, hasAuthContext bool) (*http.Client, error) {
	cacheKey := ""
	if hasAuthContext {
		cacheKey = authContext.Name
	}

	s.clientMu.Lock()
	existing, ok := s.clientCache[cacheKey]
	s.clientMu.Unlock()
	if ok {
		return existing, nil
	}

	var tlsConfig *tls.Config
	if hasAuthContext {
		value, err := authContext.TLSConfig()
		if err != nil {
			return nil, err
		}
		tlsConfig = value
	}

	client := cloneHTTPClient(baseClient, tlsConfig, s.policy.FollowRedirects)

	s.clientMu.Lock()
	s.clientCache[cacheKey] = client
	s.clientMu.Unlock()
	return client, nil
}

func cloneHTTPClient(base *http.Client, tlsConfig *tls.Config, followRedirects bool) *http.Client {
	if base == nil {
		base = &http.Client{}
	}
	cloned := *base
	cloned.Transport = cloneTransport(base.Transport, tlsConfig)
	if !followRedirects {
		cloned.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return &cloned
}

func cloneTransport(base http.RoundTripper, tlsConfig *tls.Config) http.RoundTripper {
	switch transport := base.(type) {
	case *http.Transport:
		cloned := transport.Clone()
		if tlsConfig != nil {
			cloned.TLSClientConfig = tlsConfig
		}
		return cloned
	case nil:
		cloned := http.DefaultTransport.(*http.Transport).Clone()
		if tlsConfig != nil {
			cloned.TLSClientConfig = tlsConfig
		}
		return cloned
	default:
		return base
	}
}

func skippedResult(req HTTPRequest, index int) HTTPResult {
	requestID := req.ID
	if strings.TrimSpace(requestID) == "" {
		requestID = fmt.Sprintf("req-%06d", index+1)
	}
	return HTTPResult{
		RequestID:       requestID,
		OperationID:     req.OperationID,
		AuthContextName: req.AuthContextName,
		Method:          strings.ToUpper(strings.TrimSpace(req.Method)),
		URL:             req.URL,
		Error:           "skipped: request budget exceeded",
	}
}

func readLimitedBody(body io.Reader, maxBytes int64) ([]byte, bool, error) {
	limited := &io.LimitedReader{R: body, N: maxBytes + 1}
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > maxBytes {
		return data[:maxBytes], true, nil
	}
	return data, false, nil
}

func redactHeaderMap(headers http.Header) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	out := make(map[string]string, len(headers))
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		values := headers.Values(key)
		if isSensitiveHeader(key) {
			out[key] = "[redacted]"
			continue
		}
		out[key] = strings.Join(values, ",")
	}
	return out
}

func isSensitiveHeader(key string) bool {
	switch strings.ToLower(key) {
	case "authorization", "cookie", "set-cookie", "x-api-key", "proxy-authorization":
		return true
	default:
		return false
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func isRetrySafeMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}
