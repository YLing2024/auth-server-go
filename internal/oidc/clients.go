package oidc

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// ClientRecord is one OIDC client registration.
type ClientRecord struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret"`
	RedirectURIs            []string `json:"redirect_uris"`
	PostLogoutRedirectURIs  []string `json:"post_logout_redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	Scopes                  []string `json:"scopes"`
	FirstParty              bool     `json:"first_party"`
	CookieDomain            string   `json:"cookie_domain"`
}

var defaultGrants = []string{"authorization_code"}

// ClientRegistry loads <DATA_DIR>/clients.json. Invalid entries are skipped and
// recorded as warnings; a malformed file degrades to an empty registry rather
// than crashing the auth centre.
type ClientRegistry struct {
	path     string
	clients  map[string]*ClientRecord
	warnings []string
}

// NewClientRegistry loads the registry from file (missing file is an empty
// registry). The file is chmod 0600 because it holds client secrets.
func NewClientRegistry(file string) *ClientRegistry {
	r := &ClientRegistry{path: file, clients: map[string]*ClientRecord{}}
	r.load()
	return r
}

// Warnings returns load-time diagnostics (skipped clients, parse errors).
func (r *ClientRegistry) Warnings() []string { return r.warnings }

func (r *ClientRegistry) load() {
	if r.path == "" {
		return
	}
	raw, err := os.ReadFile(r.path)
	if err != nil {
		return
	}
	_ = os.Chmod(r.path, 0o600)

	var data any
	if err := json.Unmarshal(raw, &data); err != nil {
		r.warnings = append(r.warnings, "clients.json 解析失败，按空注册表处理: "+err.Error())
		return
	}
	list := clientList(data)
	if list == nil {
		r.warnings = append(r.warnings, "clients.json 结构非法（应为数组或 {clients: []}），按空注册表处理")
		return
	}
	for _, item := range list {
		client, errs := validateClient(item)
		if len(errs) > 0 {
			id := ""
			if m, ok := item.(map[string]any); ok {
				id, _ = m["client_id"].(string)
			}
			if id == "" {
				id = "(无 id)"
			}
			r.warnings = append(r.warnings, fmt.Sprintf("跳过非法客户端 %s: %s", id, strings.Join(errs, "; ")))
			continue
		}
		r.clients[client.ClientID] = client
	}
}

func clientList(data any) []any {
	switch v := data.(type) {
	case []any:
		return v
	case map[string]any:
		if arr, ok := v["clients"].([]any); ok {
			return arr
		}
	}
	return nil
}

// Get returns the client for id, or nil.
func (r *ClientRegistry) Get(id string) *ClientRecord {
	return r.clients[id]
}

// Clients returns every registered client (used by /auth redirect whitelisting).
func (r *ClientRegistry) Clients() []*ClientRecord {
	out := make([]*ClientRecord, 0, len(r.clients))
	for _, c := range r.clients {
		out = append(out, c)
	}
	return out
}

// IsConfidential reports whether the client has a non-empty secret.
func (r *ClientRegistry) IsConfidential(c *ClientRecord) bool {
	return c != nil && c.ClientSecret != ""
}

// CheckSecret validates a client secret: public clients always pass, a
// confidential client requires a constant-time match.
func (r *ClientRegistry) CheckSecret(c *ClientRecord, provided string) bool {
	if !r.IsConfidential(c) {
		return true
	}
	if provided == "" {
		return false
	}
	return TimingEqual(c.ClientSecret, provided)
}

// MatchRedirect does exact string matching against the registered URIs — no
// prefix or wildcard matching is ever allowed.
func (r *ClientRegistry) MatchRedirect(c *ClientRecord, uri string) bool {
	if c == nil || uri == "" {
		return false
	}
	for _, u := range c.RedirectURIs {
		if u == uri {
			return true
		}
	}
	return false
}

// MatchPostLogout is the exact-match check for post_logout_redirect_uri.
func (r *ClientRegistry) MatchPostLogout(c *ClientRecord, uri string) bool {
	if c == nil || uri == "" {
		return false
	}
	for _, u := range c.PostLogoutRedirectURIs {
		if u == uri {
			return true
		}
	}
	return false
}

// AllowsGrant reports whether the client permits a grant_type.
func (r *ClientRegistry) AllowsGrant(c *ClientRecord, grant string) bool {
	if c == nil {
		return false
	}
	for _, g := range c.GrantTypes {
		if g == grant {
			return true
		}
	}
	return false
}

// redirectURIError validates one registered redirect URI. It returns an error
// description or "" when the URI is acceptable.
func redirectURIError(uri any) string {
	s, ok := uri.(string)
	if !ok || s == "" {
		return "redirect_uri 必须是非空字符串"
	}
	if strings.Contains(s, "*") {
		return "redirect_uri 不允许通配符 *"
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" {
		return "redirect_uri 不是合法 URL: " + s
	}
	if u.Fragment != "" {
		return "redirect_uri 不允许携带 fragment"
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "redirect_uri 协议不允许: " + u.Scheme
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		return "http 协议仅允许 localhost 调试: " + s
	}
	return ""
}

func isLoopbackHost(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1", "[::1]":
		return true
	}
	return false
}

func validateClient(raw any) (*ClientRecord, []string) {
	m, ok := raw.(map[string]any)
	if !ok {
		return nil, []string{"客户端必须是对象"}
	}
	var errs []string

	clientID, _ := m["client_id"].(string)
	if strings.TrimSpace(clientID) == "" {
		errs = append(errs, "client_id 必填")
	}

	redirects, _ := m["redirect_uris"].([]any)
	if len(redirects) == 0 {
		errs = append(errs, "redirect_uris 必填且非空")
	} else {
		for _, u := range redirects {
			if e := redirectURIError(u); e != "" {
				errs = append(errs, e)
			}
		}
	}

	var postLogout []string
	if v, present := m["post_logout_redirect_uris"]; present {
		arr, ok := v.([]any)
		if !ok {
			errs = append(errs, "post_logout_redirect_uris 必须是数组")
		} else {
			for _, u := range arr {
				if e := redirectURIError(u); e != "" {
					errs = append(errs, "post_logout_redirect_uris: "+e)
					continue
				}
				postLogout = append(postLogout, u.(string))
			}
		}
	}

	if v, present := m["client_secret"]; present {
		if _, ok := v.(string); !ok {
			errs = append(errs, "client_secret 必须是字符串")
		}
	}
	if v, present := m["first_party"]; present {
		if _, ok := v.(bool); !ok {
			errs = append(errs, "first_party 必须是布尔")
		}
	}
	if v, present := m["cookie_domain"]; present {
		if _, ok := v.(string); !ok {
			errs = append(errs, "cookie_domain 必须是字符串")
		}
	}
	if v, present := m["grant_types"]; present {
		if _, ok := v.([]any); !ok {
			errs = append(errs, "grant_types 必须是数组")
		}
	}
	if v, present := m["scopes"]; present {
		if _, ok := v.([]any); !ok {
			errs = append(errs, "scopes 必须是数组")
		}
	}

	if len(errs) > 0 {
		return nil, errs
	}

	secret, _ := m["client_secret"].(string)
	firstParty, _ := m["first_party"].(bool)
	cookieDomain, _ := m["cookie_domain"].(string)
	grants := stringSlice(m["grant_types"])
	if grants == nil {
		grants = append([]string(nil), defaultGrants...)
	}
	return &ClientRecord{
		ClientID:               clientID,
		ClientSecret:           secret,
		RedirectURIs:           stringSlice(redirects),
		PostLogoutRedirectURIs: postLogout,
		GrantTypes:             grants,
		Scopes:                 stringSlice(m["scopes"]),
		FirstParty:             firstParty,
		CookieDomain:           cookieDomain,
	}, nil
}

func stringSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
