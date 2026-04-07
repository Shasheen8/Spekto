package auth

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"

	"github.com/Shasheen8/Spekto/internal/config"
	"github.com/Shasheen8/Spekto/internal/inventory"
)

type Context struct {
	Name          string
	Headers       map[string]string
	Cookies       map[string]string
	BearerToken   string
	BasicUsername string
	BasicPassword string
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
			Name:          value.Name,
			Headers:       cloneMap(value.Headers),
			Cookies:       cloneMap(value.Cookies),
			BearerToken:   strings.TrimSpace(value.BearerToken),
			BasicUsername: value.BasicUsername,
			BasicPassword: value.BasicPassword,
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
		return names
	}

	names := make([]string, 0, len(r.Contexts))
	for _, ctx := range r.Contexts {
		if ctx.SupportsAny(hints.AuthSchemes) {
			names = append(names, ctx.Name)
		}
	}
	return inventory.SortStringsStable(names)
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
	schemes := make([]inventory.AuthScheme, 0, 4)
	if c.BearerToken != "" {
		schemes = append(schemes, inventory.AuthSchemeBearer)
	}
	if c.BasicUsername != "" || c.BasicPassword != "" {
		schemes = append(schemes, inventory.AuthSchemeBasic)
	}
	if len(c.Cookies) > 0 {
		schemes = append(schemes, inventory.AuthSchemeCookie)
	}
	for key := range c.Headers {
		switch strings.ToLower(key) {
		case "authorization":
			continue
		default:
			schemes = append(schemes, inventory.AuthSchemeAPIKeyHeader)
		}
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
	for name, value := range c.Cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	return nil
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
