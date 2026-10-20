// Package config loads the auth-server runtime configuration from environment
// variables.
//
// Variable names and defaults mirror the legacy Node implementation so a
// deployment can be swapped without touching any key file. Two defaults are
// deliberately different, both because this process must never collide with the
// running legacy service: PORT defaults to 19260 (not 3200) and HOST defaults to
// the loopback address (not 0.0.0.0). See docs/COMPAT.md.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// legacySubjectLabels are historical identity tags written by older versions.
// They are normalised to the configured subject on read so both identity
// channels (session token and OIDC) agree.
var legacySubjectLabels = []string{"HomeAuth"}

// Config is the fully resolved runtime configuration.
type Config struct {
	Host      string
	Port      int
	RedisHost string
	RedisPort int
	RedisDB   int

	// DataDir holds the key files and the client registry. It is never written
	// to by Load except when a key file is missing.
	DataDir string
	Issuer  string

	Subject     string
	DisplayName string

	SessionDays int
	// SessionTTL is the sliding session lifetime in seconds (remember me).
	SessionTTL int
	// SessionShortTTL is the absolute lifetime in seconds for sessions created
	// without "remember me". Those sessions are never renewed.
	SessionShortTTL int

	JWTSecret     string
	InternalToken string
	// InternalTokenFile is where the shared internal token is persisted (0600).
	InternalTokenFile string

	GeoIPURL string
	// AllowedRedirectRoots is the parsed cross-origin login redirect whitelist.
	// Empty means same-origin only, never a wildcard.
	AllowedRedirectRoots []string

	GatewayBackchannelURL string

	// AccessTTL is the access_token / id_token lifetime in seconds.
	AccessTTL int

	// Login rate-limit thresholds. The IP dimension keeps the legacy ladder;
	// the device dimension is deliberately wider because one device may be
	// shared by several people. The global counter only alerts.
	RateLimitIPMax     int
	RateLimitDeviceMax int
	RateLimitGlobalMax int
}

// LegacySubjects returns the historical identity labels to normalise on read.
func LegacySubjects() []string {
	out := make([]string, len(legacySubjectLabels))
	copy(out, legacySubjectLabels)
	return out
}

// Load resolves the configuration from the environment, loading or creating the
// JWT secret and the internal token as a side effect (file modes 0600).
func Load() (*Config, error) {
	dataDir, err := resolveDataDir()
	if err != nil {
		return nil, err
	}

	c := &Config{
		Host:                  envStr("HOST", "127.0.0.1"),
		RedisHost:             envStr("REDIS_HOST", "127.0.0.1"),
		DataDir:               dataDir,
		Issuer:                strings.TrimRight(envStr("ISSUER", "http://127.0.0.1:19260"), "/"),
		Subject:               envStr("SSO_SUBJECT", "linden"),
		GeoIPURL:              envStr("AUTH_GEOIP_URL", "https://ip-api.com/json/{ip}?fields=status,country,regionName,city"),
		GatewayBackchannelURL: envStr("GATEWAY_BACKCHANNEL_URL", "http://127.0.0.1:18920/_auth/backchannel-logout"),
	}
	c.DisplayName = envStr("SSO_DISPLAY_NAME", c.Subject)

	if c.Port, err = envInt("PORT", 19260); err != nil {
		return nil, err
	}
	if c.RedisPort, err = envInt("REDIS_PORT", 6379); err != nil {
		return nil, err
	}
	if c.RedisDB, err = envInt("REDIS_DB", 0); err != nil {
		return nil, err
	}
	if c.RateLimitIPMax, err = envInt("SSO_RL_IP_MAX", 5); err != nil {
		return nil, err
	}
	if c.RateLimitDeviceMax, err = envInt("SSO_RL_DEVICE_MAX", 10); err != nil {
		return nil, err
	}
	if c.RateLimitGlobalMax, err = envInt("SSO_RL_GLOBAL_MAX", 60); err != nil {
		return nil, err
	}
	if c.RateLimitIPMax <= 0 || c.RateLimitDeviceMax <= 0 || c.RateLimitGlobalMax <= 0 {
		return nil, fmt.Errorf("config: SSO_RL_IP_MAX/SSO_RL_DEVICE_MAX/SSO_RL_GLOBAL_MAX 必须为正整数")
	}
	if c.SessionDays, err = envInt("SESSION_DAYS", 7); err != nil {
		return nil, err
	}
	if c.SessionDays <= 0 {
		return nil, fmt.Errorf("config: SESSION_DAYS 必须为正整数，当前 %d", c.SessionDays)
	}
	c.SessionTTL = c.SessionDays * 86400
	if c.SessionShortTTL, err = envInt("SESSION_SHORT_TTL", 900); err != nil {
		return nil, err
	}
	if c.SessionShortTTL <= 0 {
		return nil, fmt.Errorf("config: SESSION_SHORT_TTL 必须为正整数，当前 %d", c.SessionShortTTL)
	}

	c.AccessTTL = 900
	if v := os.Getenv("ACCESS_TTL_SEC"); v != "" {
		n, convErr := strconv.Atoi(strings.TrimSpace(v))
		if convErr != nil {
			return nil, fmt.Errorf("config: ACCESS_TTL_SEC 非法: %q", v)
		}
		if n >= 60 {
			c.AccessTTL = n
		}
	}

	if c.Port < 0 || c.Port > 65535 {
		return nil, fmt.Errorf("config: PORT 越界: %d", c.Port)
	}
	if c.RedisDB < 0 || c.RedisDB > 15 {
		return nil, fmt.Errorf("config: REDIS_DB 越界: %d", c.RedisDB)
	}
	if !strings.HasPrefix(c.Issuer, "http://") && !strings.HasPrefix(c.Issuer, "https://") {
		return nil, fmt.Errorf("config: ISSUER 必须是 http(s) 绝对 URL")
	}

	c.AllowedRedirectRoots = ParseAllowedRedirectRoots(os.Getenv("ALLOWED_REDIRECT_ROOTS"))

	if c.JWTSecret, err = loadOrCreateJWTSecret(c.DataDir); err != nil {
		return nil, err
	}

	c.InternalTokenFile = envStr("INTERNAL_TOKEN_FILE", filepath.Join(c.DataDir, "internal-token"))
	if c.InternalToken, err = loadOrCreateInternalToken(c.InternalTokenFile); err != nil {
		return nil, err
	}

	return c, nil
}

// SecureCookies reports whether SSO cookies must carry the Secure attribute.
// The legacy implementation keys this purely off the issuer scheme.
func (c *Config) SecureCookies() bool {
	return strings.HasPrefix(c.Issuer, "https://")
}

func resolveDataDir() (string, error) {
	if v := strings.TrimSpace(os.Getenv("DATA_DIR")); v != "" {
		return v, nil
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("config: 无法确定工作目录作为 DATA_DIR: %w", err)
	}
	return wd, nil
}

// ParseAllowedRedirectRoots normalises the comma-separated whitelist. It
// tolerates a `*.` prefix and leading dots, drops anything that is not a bare
// domain form, and de-duplicates while preserving order. An empty result means
// "same origin only" — it never degrades into "allow anything".
func ParseAllowedRedirectRoots(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		root := strings.ToLower(strings.TrimSpace(part))
		root = strings.TrimPrefix(root, "*.")
		root = strings.TrimLeft(root, ".")
		if root == "" || !isBareDomain(root) {
			continue
		}
		if !contains(out, root) {
			out = append(out, root)
		}
	}
	return out
}

// isBareDomain accepts only lowercase alnum/dot/hyphen domain shapes. It rejects
// protocol, path, port and wildcard remnants so a misconfiguration cannot widen
// the whitelist.
func isBareDomain(s string) bool {
	if strings.HasPrefix(s, "-") || strings.HasSuffix(s, "-") || strings.HasSuffix(s, ".") {
		return false
	}
	if strings.Contains(s, "..") {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '.' || r == '-':
		default:
			return false
		}
	}
	return true
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func loadOrCreateJWTSecret(dataDir string) (string, error) {
	if v := os.Getenv("JWT_SECRET"); v != "" {
		return v, nil
	}
	path := filepath.Join(dataDir, "jwt-secret")
	if raw, err := os.ReadFile(path); err == nil {
		if s := strings.TrimSpace(string(raw)); s != "" {
			return s, nil
		}
	}
	secret, err := randomHex(32)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("config: 创建 JWT 密钥目录失败: %w", err)
	}
	if err := os.WriteFile(path, []byte(secret), 0o600); err != nil {
		return "", fmt.Errorf("config: 写入 JWT 密钥失败: %w", err)
	}
	return secret, nil
}

func loadOrCreateInternalToken(path string) (string, error) {
	if v := os.Getenv("INTERNAL_TOKEN"); v != "" {
		return v, nil
	}
	if raw, err := os.ReadFile(path); err == nil {
		if s := strings.TrimSpace(string(raw)); s != "" {
			return s, nil
		}
	}
	token, err := randomHex(32)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("config: 创建内部令牌目录失败: %w", err)
	}
	if err := os.WriteFile(path, []byte(token), 0o600); err != nil {
		return "", fmt.Errorf("config: 写入内部令牌失败: %w", err)
	}
	return token, nil
}

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("config: 生成随机数失败: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

func envStr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) (int, error) {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0, fmt.Errorf("config: %s 非法: %q", key, v)
	}
	return n, nil
}
