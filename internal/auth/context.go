package auth

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/Shasheen8/Spekto/internal/config"
	"github.com/Shasheen8/Spekto/internal/inventory"
)

type Context struct {
	Name             string
	Roles            []string
	Headers          map[string]string
	QueryParams      map[string]string
	Cookies          map[string]string
	BearerToken      string
	BasicUsername    string
	BasicPassword    string
	APIKeyHeaderName string
	APIKeyQueryName  string
	APIKeyValue      string
	MTLS             *MTLSConfig
	Login            *LoginFlow
}

type MTLSConfig struct {
	CertFile           string
	KeyFile            string
	CAFile             string
	InsecureSkipVerify bool
}

type LoginFlow struct {
	Method      string
	URL         string
	Headers     map[string]string
	Body        string
	ContentType string
	Capture     LoginCapture
}

type LoginCapture struct {
	BearerJSONPointer string
	Header            string
	Cookie            string
}

type Registry struct {
	Contexts []Context
	byName   map[string]Context
}

func NewRegistry(cfg config.Config) (Registry, error) {
	contexts := make([]Context, 0, len(cfg.AuthContexts))
	index := make(map[string]Context, len(cfg.AuthContexts))

	for _, value := range cfg.AuthContexts {
		ctx := Context{
			Name:             value.Name,
			Roles:            append([]string(nil), value.Roles...),
			Headers:          cloneMap(value.Headers),
			Cookies:          cloneMap(value.Cookies),
			BearerToken:      strings.TrimSpace(value.BearerToken),
			BasicUsername:    value.BasicUsername,
			BasicPassword:    value.BasicPassword,
			APIKeyHeaderName: strings.TrimSpace(value.APIKeyHeaderName),
			APIKeyQueryName:  strings.TrimSpace(value.APIKeyQueryName),
			APIKeyValue:      strings.TrimSpace(value.APIKeyValue),
			MTLS:             cloneMTLS(value.MTLS),
			Login:            cloneLoginFlow(value.Login),
		}
		if ctx.APIKeyHeaderName != "" && ctx.APIKeyValue != "" {
			if ctx.Headers == nil {
				ctx.Headers = map[string]string{}
			}
			if _, exists := ctx.Headers[ctx.APIKeyHeaderName]; !exists {
				ctx.Headers[ctx.APIKeyHeaderName] = ctx.APIKeyValue
			}
		}
		if ctx.APIKeyQueryName != "" && ctx.APIKeyValue != "" {
			ctx.QueryParams = map[string]string{
				ctx.APIKeyQueryName: ctx.APIKeyValue,
			}
		}
		if _, exists := index[ctx.Name]; exists {
			return Registry{}, fmt.Errorf("duplicate auth context %q", ctx.Name)
		}
		contexts = append(contexts, ctx)
		index[ctx.Name] = ctx
	}

	sort.Slice(contexts, func(i, j int) bool { return contexts[i].Name < contexts[j].Name })
	return Registry{
		Contexts: contexts,
		byName:   index,
	}, nil
}

func (r Registry) ResolveLoginFlows(ctx context.Context, client *http.Client) (Registry, error) {
	if client == nil {
		client = &http.Client{}
	}
	resolved := make([]Context, 0, len(r.Contexts))
	index := make(map[string]Context, len(r.Contexts))
	for _, candidate := range r.Contexts {
		current := candidate
		if current.Login != nil {
			updated, err := current.executeLoginFlow(ctx, client)
			if err != nil {
				return Registry{}, fmt.Errorf("login flow for %q: %w", current.Name, err)
			}
			current = updated
		}
		resolved = append(resolved, current)
		index[current.Name] = current
	}
	return Registry{Contexts: resolved, byName: index}, nil
}

func (r Registry) Get(name string) (Context, bool) {
	value, ok := r.byName[name]
	return value, ok
}

func (r Registry) Select(names []string) ([]Context, error) {
	if len(names) == 0 {
		return append([]Context(nil), r.Contexts...), nil
	}

	selected := make([]Context, 0, len(names))
	for _, name := range names {
		value, ok := r.Get(name)
		if !ok {
			return nil, fmt.Errorf("unknown auth context %q", name)
		}
		selected = append(selected, value)
	}
	return selected, nil
}

func (r Registry) Candidates(hints inventory.AuthHints) []string {
	if len(hints.AuthContextCandidates) > 0 {
		out := make([]string, 0, len(hints.AuthContextCandidates))
		for _, name := range hints.AuthContextCandidates {
			if _, ok := r.byName[name]; ok {
				out = append(out, name)
			}
		}
		return inventory.SortStringsStable(out)
	}

	if hints.RequiresAuth == inventory.AuthRequirementNo {
		return nil
	}

	if len(hints.AuthSchemes) == 0 || containsUnknownScheme(hints.AuthSchemes) {
		names := make([]string, 0, len(r.Contexts))
		for _, ctx := range r.Contexts {
			names = append(names, ctx.Name)
		}
		return inventory.SortStringsStable(names)
	}

	names := make([]string, 0, len(r.Contexts))
	for _, ctx := range r.Contexts {
		if ctx.SupportsAny(hints.AuthSchemes) {
			names = append(names, ctx.Name)
		}
	}
	return inventory.SortStringsStable(names)
}

func (r Registry) CandidatesForTarget(hints inventory.AuthHints, target config.Target, selected []string) ([]string, error) {
	targetAllowed, err := validateAllowedContexts(r.byName, target.AuthContexts)
	if err != nil {
		return nil, err
	}
	selectedAllowed, err := validateAllowedContexts(r.byName, selected)
	if err != nil {
		return nil, err
	}

	candidates := r.Candidates(hints)
	if len(targetAllowed) == 0 && len(selectedAllowed) == 0 {
		return candidates, nil
	}

	allowed := targetAllowed
	if len(allowed) == 0 {
		allowed = selectedAllowed
	} else if len(selectedAllowed) > 0 {
		allowed = intersectAllowedContexts(allowed, selectedAllowed)
	}

	filtered := make([]string, 0, len(candidates))
	for _, name := range candidates {
		if _, ok := allowed[name]; ok {
			filtered = append(filtered, name)
		}
	}
	return inventory.SortStringsStable(filtered), nil
}

func (c Context) SupportsAny(schemes []inventory.AuthScheme) bool {
	supported := c.SupportedSchemes()
	for _, scheme := range schemes {
		if slices.Contains(supported, scheme) {
			return true
		}
	}
	return false
}

func (c Context) SupportedSchemes() []inventory.AuthScheme {
	schemes := make([]inventory.AuthScheme, 0, 6)
	if c.BearerToken != "" {
		schemes = append(schemes, inventory.AuthSchemeBearer)
	}
	if c.BasicUsername != "" || c.BasicPassword != "" {
		schemes = append(schemes, inventory.AuthSchemeBasic)
	}
	if len(c.Cookies) > 0 {
		schemes = append(schemes, inventory.AuthSchemeCookie)
	}
	if c.APIKeyHeaderName != "" && c.APIKeyValue != "" {
		schemes = append(schemes, inventory.AuthSchemeAPIKeyHeader)
	}
	if c.APIKeyQueryName != "" && c.APIKeyValue != "" {
		schemes = append(schemes, inventory.AuthSchemeAPIKeyQuery)
	}
	if c.MTLS != nil {
		schemes = append(schemes, inventory.AuthSchemeMTLS)
	}
	return uniqueSchemes(schemes)
}

func (c Context) HTTPHeaders() http.Header {
	headers := make(http.Header, len(c.Headers)+1)
	for key, value := range c.Headers {
		headers.Set(key, value)
	}
	if _, exists := headers["Authorization"]; !exists {
		switch {
		case c.BearerToken != "":
			headers.Set("Authorization", "Bearer "+c.BearerToken)
		case c.BasicUsername != "" || c.BasicPassword != "":
			token := base64.StdEncoding.EncodeToString([]byte(c.BasicUsername + ":" + c.BasicPassword))
			headers.Set("Authorization", "Basic "+token)
		}
	}
	if c.APIKeyHeaderName != "" && c.APIKeyValue != "" && headers.Get(c.APIKeyHeaderName) == "" {
		headers.Set(c.APIKeyHeaderName, c.APIKeyValue)
	}
	return headers
}

func (c Context) ApplyHTTPRequest(req *http.Request) error {
	if req == nil {
		return fmt.Errorf("request must not be nil")
	}
	for key, values := range c.HTTPHeaders() {
		for _, value := range values {
			req.Header.Set(key, value)
		}
	}
	query := req.URL.Query()
	for name, value := range c.QueryParams {
		query.Set(name, value)
	}
	if c.APIKeyQueryName != "" && c.APIKeyValue != "" {
		query.Set(c.APIKeyQueryName, c.APIKeyValue)
	}
	req.URL.RawQuery = query.Encode()
	for name, value := range c.Cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	return nil
}

func (c Context) ApplyGRPCMetadata(headers map[string]string) map[string]string {
	metadata := make(map[string]string, len(headers)+len(c.Headers)+2)
	for key, value := range headers {
		metadata[strings.ToLower(key)] = value
	}
	for key, values := range c.HTTPHeaders() {
		metadata[strings.ToLower(key)] = strings.Join(values, ",")
	}
	if len(c.Cookies) > 0 {
		pairs := make([]string, 0, len(c.Cookies))
		for name, value := range c.Cookies {
			pairs = append(pairs, name+"="+value)
		}
		sort.Strings(pairs)
		metadata["cookie"] = strings.Join(pairs, "; ")
	}
	return metadata
}

func (c Context) TLSConfig() (*tls.Config, error) {
	if c.MTLS == nil {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(c.MTLS.CertFile, c.MTLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load mtls key pair: %w", err)
	}
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: c.MTLS.InsecureSkipVerify,
	}
	if strings.TrimSpace(c.MTLS.CAFile) != "" {
		caPEM, err := os.ReadFile(c.MTLS.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read mtls ca file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("parse mtls ca file")
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

func (c Context) executeLoginFlow(ctx context.Context, client *http.Client) (Context, error) {
	login := c.Login
	if login == nil {
		return c, nil
	}

	req, err := http.NewRequestWithContext(ctx, login.Method, login.URL, bytes.NewBufferString(login.Body))
	if err != nil {
		return c, err
	}
	for key, value := range login.Headers {
		req.Header.Set(key, value)
	}
	if login.ContentType != "" {
		req.Header.Set("Content-Type", login.ContentType)
	}
	for key, value := range c.Headers {
		if req.Header.Get(key) == "" {
			req.Header.Set(key, value)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return c, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return c, fmt.Errorf("unexpected login status %d", resp.StatusCode)
	}

	out := c
	if header := strings.TrimSpace(login.Capture.Header); header != "" {
		value := strings.TrimSpace(resp.Header.Get(header))
		if value == "" {
			return c, fmt.Errorf("login capture header %q missing", header)
		}
		out.Headers = cloneMap(out.Headers)
		out.Headers[header] = value
		if parsed, ok := parseBearerHeader(value); ok {
			out.BearerToken = parsed
		}
	}
	if cookieName := strings.TrimSpace(login.Capture.Cookie); cookieName != "" {
		cookieFound := false
		out.Cookies = cloneMap(out.Cookies)
		for _, cookie := range resp.Cookies() {
			if cookie.Name == cookieName {
				out.Cookies[cookie.Name] = cookie.Value
				cookieFound = true
				break
			}
		}
		if !cookieFound {
			return c, fmt.Errorf("login capture cookie %q missing", cookieName)
		}
	}
	if pointer := strings.TrimSpace(login.Capture.BearerJSONPointer); pointer != "" {
		var payload any
		if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
			return c, fmt.Errorf("decode login response: %w", err)
		}
		token, err := lookupJSONPointerString(payload, pointer)
		if err != nil {
			return c, err
		}
		out.BearerToken = token
	}
	out.Login = nil
	return out, nil
}

func parseBearerHeader(value string) (string, bool) {
	prefix := "bearer "
	if !strings.HasPrefix(strings.ToLower(value), prefix) {
		return "", false
	}
	return strings.TrimSpace(value[len(prefix):]), true
}

func lookupJSONPointerString(root any, pointer string) (string, error) {
	if !strings.HasPrefix(pointer, "/") {
		return "", fmt.Errorf("login capture pointer must start with /")
	}
	current := root
	for _, rawPart := range strings.Split(pointer, "/")[1:] {
		part := strings.ReplaceAll(strings.ReplaceAll(rawPart, "~1", "/"), "~0", "~")
		object, ok := current.(map[string]any)
		if !ok {
			return "", fmt.Errorf("json pointer %q does not resolve to an object", pointer)
		}
		value, exists := object[part]
		if !exists {
			return "", fmt.Errorf("json pointer %q missing key %q", pointer, part)
		}
		current = value
	}
	token, ok := current.(string)
	if !ok || strings.TrimSpace(token) == "" {
		return "", fmt.Errorf("json pointer %q did not resolve to a non-empty string", pointer)
	}
	return token, nil
}

func cloneMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func cloneMTLS(value *config.MTLSConfig) *MTLSConfig {
	if value == nil {
		return nil
	}
	return &MTLSConfig{
		CertFile:           value.CertFile,
		KeyFile:            value.KeyFile,
		CAFile:             value.CAFile,
		InsecureSkipVerify: value.InsecureSkipVerify,
	}
}

func cloneLoginFlow(value *config.LoginFlow) *LoginFlow {
	if value == nil {
		return nil
	}
	return &LoginFlow{
		Method:      value.Method,
		URL:         value.URL,
		Headers:     cloneMap(value.Headers),
		Body:        value.Body,
		ContentType: value.ContentType,
		Capture: LoginCapture{
			BearerJSONPointer: value.Capture.BearerJSONPointer,
			Header:            value.Capture.Header,
			Cookie:            value.Capture.Cookie,
		},
	}
}

func validateAllowedContexts(index map[string]Context, names []string) (map[string]struct{}, error) {
	if len(names) == 0 {
		return nil, nil
	}
	allowed := make(map[string]struct{}, len(names))
	for _, name := range names {
		if _, ok := index[name]; !ok {
			return nil, fmt.Errorf("unknown auth context %q", name)
		}
		allowed[name] = struct{}{}
	}
	return allowed, nil
}

func intersectAllowedContexts(a, b map[string]struct{}) map[string]struct{} {
	out := map[string]struct{}{}
	for key := range a {
		if _, ok := b[key]; ok {
			out[key] = struct{}{}
		}
	}
	return out
}

func containsUnknownScheme(schemes []inventory.AuthScheme) bool {
	for _, scheme := range schemes {
		if scheme == inventory.AuthSchemeUnknown {
			return true
		}
	}
	return false
}

func uniqueSchemes(values []inventory.AuthScheme) []inventory.AuthScheme {
	if len(values) == 0 {
		return nil
	}
	seen := map[inventory.AuthScheme]struct{}{}
	out := make([]inventory.AuthScheme, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func RedactURL(rawURL string, ctx Context) string {
	if strings.TrimSpace(rawURL) == "" || ctx.APIKeyQueryName == "" {
		return rawURL
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	query := parsed.Query()
	if _, exists := query[ctx.APIKeyQueryName]; !exists {
		return rawURL
	}
	query.Set(ctx.APIKeyQueryName, "[redacted]")
	parsed.RawQuery = query.Encode()
	return parsed.String()
}
