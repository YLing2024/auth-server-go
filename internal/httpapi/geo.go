package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"auth-server-go/internal/redis"
)

// isPrivateIP decides whether an address is local/private. Private addresses are
// marked isLocal on the session record and never sent to the GeoIP provider.
func isPrivateIP(ip string) bool {
	if ip == "" {
		return true
	}
	if ip == "::1" || strings.HasPrefix(ip, "fe80:") {
		return true
	}
	if ip == "unknown" {
		return true
	}
	if strings.Contains(ip, ":") {
		return false // 其他 IPv6 视作公网，尽力解析
	}
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	nums := make([]int, 4)
	for i, p := range parts {
		n, err := atoiStrict(p)
		if err != nil {
			return false
		}
		nums[i] = n
	}
	a, b := nums[0], nums[1]
	switch {
	case a == 127 || a == 10:
		return true
	case a == 172 && b >= 16 && b <= 31:
		return true
	case a == 192 && b == 168:
		return true
	case a == 169 && b == 254:
		return true
	case a == 100 && b >= 64 && b <= 127:
		return true
	case a == 0:
		return true
	case a >= 224:
		return true
	}
	return false
}

func atoiStrict(s string) (int, error) {
	if s == "" {
		return 0, errEmpty
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, errEmpty
		}
		n = n*10 + int(s[i]-'0')
	}
	return n, nil
}

type geoEntry struct {
	location string
	ts       int64
}

// geoResolver resolves login locations in the background with the same 24h cache
// and eviction policy as the legacy implementation. Failures stay silent.
type geoResolver struct {
	url    string
	store  *redis.Store
	client *http.Client

	mu    sync.Mutex
	cache map[string]geoEntry
}

func newGeoResolver(rawURL string, store *redis.Store) *geoResolver {
	return &geoResolver{
		url:    rawURL,
		store:  store,
		client: &http.Client{Timeout: 2500 * time.Millisecond},
		cache:  map[string]geoEntry{},
	}
}

const geoCacheTTLMillis = 24 * 3600 * 1000

func (g *geoResolver) cacheGet(ip string) (string, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	rec, ok := g.cache[ip]
	if !ok {
		return "", false
	}
	if time.Now().UnixMilli()-rec.ts > geoCacheTTLMillis {
		delete(g.cache, ip)
		return "", false
	}
	return rec.location, true
}

func (g *geoResolver) cacheSet(ip, location string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.cache) > 5000 {
		n := 0
		for k := range g.cache {
			delete(g.cache, k)
			n++
			if n >= 2500 {
				break
			}
		}
	}
	g.cache[ip] = geoEntry{location: location, ts: time.Now().UnixMilli()}
}

type geoData struct {
	Status     string `json:"status"`
	Success    bool   `json:"success"`
	Country    string `json:"country"`
	RegionName string `json:"regionName"`
	Region     string `json:"region"`
	City       string `json:"city"`
}

// resolveLocation is deliberately fire-and-forget: it uses a background context
// so a returning HTTP handler cannot cancel the lookup, mirroring the legacy
// "async, not awaited" call.
func (g *geoResolver) resolveLocation(hashKey, ip string) {
	go g.lookup(hashKey, ip)
}

func (g *geoResolver) lookup(hashKey, ip string) {
	if ip == "" || isPrivateIP(ip) {
		return
	}
	if cached, ok := g.cacheGet(ip); ok {
		if cached != "" {
			_ = g.store.Client().HSet(context.Background(), hashKey, "location", cached).Err()
		}
		return
	}
	location := ""
	if data := g.fetch(ip); data != nil && (data.Status == "success" || data.Success) {
		parts := []string{}
		for _, p := range []string{data.Country, firstNonEmpty(data.RegionName, data.Region), data.City} {
			if p != "" {
				parts = append(parts, p)
			}
		}
		location = strings.TrimSpace(strings.Join(parts, ", "))
	}
	g.cacheSet(ip, location)
	if location != "" {
		_ = g.store.Client().HSet(context.Background(), hashKey, "location", location).Err()
	}
}

func (g *geoResolver) fetch(ip string) *geoData {
	endpoint := strings.ReplaceAll(g.url, "{ip}", url.QueryEscape(ip))
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/json")
	resp, err := g.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil
	}
	var data geoData
	if json.Unmarshal(raw, &data) != nil {
		return nil
	}
	return &data
}

// remoteIP is the direct peer address, used by the legacy module login limiter
// which never trusted proxy headers.
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return host
}

// clientIP resolves the real client address the way the legacy app did: prefer
// the first X-Forwarded-For hop, then X-Real-IP, then the peer address.
func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		first := strings.TrimSpace(strings.Split(fwd, ",")[0])
		if first != "" {
			return first
		}
	}
	if real := r.Header.Get("X-Real-IP"); real != "" {
		return strings.TrimSpace(real)
	}
	return remoteIP(r)
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
