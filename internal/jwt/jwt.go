// Package jwt implements the minimal JWS/JWK layer the auth centre needs.
//
// Signing and verification of id_token / access_token use ES256 (ECDSA P-256)
// with the key material shared through <DATA_DIR>/oidc-keys.json, matching the
// legacy implementation byte for byte (the `kid` is the RFC 7638 JWK
// thumbprint, and the serialized compact JWS uses raw r||s signatures, not
// ASN.1). A separate HS256 path exists only for the legacy /api/totp module
// routes. No third-party JWT library is used.
package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"auth-server-go/internal/jsonx"
)

var b64 = base64.RawURLEncoding

// JWK is an elliptic-curve JSON Web Key. D is present only for private keys.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	D   string `json:"d,omitempty"`
}

// KeyEntry is one entry of oidc-keys.json. Field order matches the legacy file
// so round-tripping does not reorder keys.
type KeyEntry struct {
	Kid        string `json:"kid"`
	CreatedAt  int64  `json:"createdAt"`
	PrivateJWK JWK    `json:"privateJwk"`
	PublicJWK  JWK    `json:"publicJwk"`
}

type keyFile struct {
	Keys []KeyEntry `json:"keys"`
}

// KeyStore holds the ES256 keys. The first entry is the active signing key;
// JWKS publishes every public key so rotation keeps old tokens verifiable.
type KeyStore struct {
	path string
	keys []KeyEntry
	priv []*ecdsa.PrivateKey
	pub  []*ecdsa.PublicKey
}

// Thumbprint computes the RFC 7638 SHA-256 thumbprint of a public EC JWK,
// base64url encoded without padding. It is the canonical `kid`.
func Thumbprint(pub JWK) string {
	canonical := `{"crv":"` + pub.Crv + `","kty":"` + pub.Kty + `","x":"` + pub.X + `","y":"` + pub.Y + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return b64.EncodeToString(sum[:])
}

// LoadKeyStore reads oidc-keys.json. When the file is absent it generates a
// fresh key and persists it (0600) exactly like the legacy first-start path.
// It never rotates or replaces existing keys.
func LoadKeyStore(path string) (*KeyStore, error) {
	ks := &KeyStore{path: path}
	raw, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("jwt: 读取密钥文件失败 %s: %w", path, err)
		}
		entry, genErr := generateEntry()
		if genErr != nil {
			return nil, genErr
		}
		ks.keys = []KeyEntry{entry}
		if err := ks.persist(); err != nil {
			return nil, err
		}
		if err := ks.compile(); err != nil {
			return nil, err
		}
		return ks, nil
	}

	var kf keyFile
	if err := json.Unmarshal(raw, &kf); err != nil {
		return nil, fmt.Errorf("jwt: 解析密钥文件失败 %s: %w", path, err)
	}
	if len(kf.Keys) == 0 {
		return nil, fmt.Errorf("jwt: 密钥文件 %s 中没有可用密钥", path)
	}
	for i := range kf.Keys {
		k := &kf.Keys[i]
		if k.PrivateJWK.Kty == "" || k.PublicJWK.Kty == "" {
			return nil, fmt.Errorf("jwt: 密钥文件 %s 第 %d 项缺少 JWK", path, i)
		}
		if k.Kid == "" {
			k.Kid = Thumbprint(k.PublicJWK)
		}
		// 旧文件可能只存了 publicJwk / privateJwk 之一，缺哪补哪，避免整库不可用。
		if k.PrivateJWK.X == "" {
			k.PrivateJWK = k.PublicJWK
		}
		if k.PublicJWK.X == "" {
			k.PublicJWK = JWK{Kty: k.PrivateJWK.Kty, Crv: k.PrivateJWK.Crv, X: k.PrivateJWK.X, Y: k.PrivateJWK.Y}
		}
	}
	ks.keys = kf.Keys
	if err := ks.compile(); err != nil {
		return nil, err
	}
	return ks, nil
}

func (ks *KeyStore) compile() error {
	ks.priv = make([]*ecdsa.PrivateKey, 0, len(ks.keys))
	ks.pub = make([]*ecdsa.PublicKey, 0, len(ks.keys))
	for i := range ks.keys {
		priv, err := privateFromJWK(ks.keys[i].PrivateJWK)
		if err != nil {
			return fmt.Errorf("jwt: 第 %d 把私钥无效: %w", i, err)
		}
		pub, err := publicFromJWK(ks.keys[i].PublicJWK)
		if err != nil {
			return fmt.Errorf("jwt: 第 %d 把公钥无效: %w", i, err)
		}
		ks.priv = append(ks.priv, priv)
		ks.pub = append(ks.pub, pub)
	}
	return nil
}

// ActiveKid returns the kid used for new signatures.
func (ks *KeyStore) ActiveKid() string {
	if len(ks.keys) == 0 {
		return ""
	}
	return ks.keys[0].Kid
}

func (ks *KeyStore) indexOf(kid string) int {
	for i := range ks.keys {
		if ks.keys[i].Kid == kid {
			return i
		}
	}
	return -1
}

// JwkOut is one entry of the published JWKS document.
type JwkOut struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

type jwksDoc struct {
	Keys []JwkOut `json:"keys"`
}

// JWKS renders the public key set. Byte layout matches the legacy response so
// the two services produce identical documents for the same key file.
func (ks *KeyStore) JWKS() ([]byte, error) {
	doc := jwksDoc{Keys: make([]JwkOut, 0, len(ks.keys))}
	for i := range ks.keys {
		p := ks.keys[i].PublicJWK
		doc.Keys = append(doc.Keys, JwkOut{
			Kty: p.Kty, Crv: p.Crv, X: p.X, Y: p.Y,
			Kid: ks.keys[i].Kid, Use: "sig", Alg: "ES256",
		})
	}
	return jsonx.Marshal(doc)
}

type jwsHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// SignJWT signs payload (already shaped as ordered claims) with the active key
// and returns a compact ES256 JWS.
func (ks *KeyStore) SignJWT(payload any) (string, error) {
	if len(ks.keys) == 0 {
		return "", errors.New("jwt: 没有签名密钥")
	}
	header := jwsHeader{Alg: "ES256", Typ: "JWT", Kid: ks.keys[0].Kid}
	hb, err := jsonx.Marshal(header)
	if err != nil {
		return "", err
	}
	pb, err := jsonx.Marshal(payload)
	if err != nil {
		return "", err
	}
	signingInput := b64.EncodeToString(hb) + "." + b64.EncodeToString(pb)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, ks.priv[0], digest[:])
	if err != nil {
		return "", fmt.Errorf("jwt: 签名失败: %w", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signingInput + "." + b64.EncodeToString(sig), nil
}

// VerifyOpts constrains verification beyond the signature.
type VerifyOpts struct {
	Issuer   string
	Audience string
}

// Verify checks the ES256 signature and the exp/iss/aud claims, returning the
// decoded payload as a raw JSON map. Only ES256 is accepted.
func (ks *KeyStore) Verify(token string, opts VerifyOpts) (map[string]any, error) {
	parts := splitToken(token)
	if parts == nil {
		return nil, errors.New("jwt: 结构非法")
	}
	hb, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("jwt: 头部解码失败")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hb, &header); err != nil {
		return nil, errors.New("jwt: 头部非法")
	}
	if header.Alg != "ES256" {
		return nil, errors.New("jwt: 算法不允许")
	}
	idx := ks.indexOf(header.Kid)
	if idx < 0 {
		return nil, errors.New("jwt: 未知 kid")
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return nil, errors.New("jwt: 签名解码失败")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(ks.pub[idx], digest[:], r, s) {
		return nil, errors.New("jwt: 签名校验失败")
	}
	pb, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("jwt: 载荷解码失败")
	}
	var payload map[string]any
	if err := json.Unmarshal(pb, &payload); err != nil {
		return nil, errors.New("jwt: 载荷非法")
	}
	exp, ok := numClaim(payload, "exp")
	if !ok {
		return nil, errors.New("jwt: 缺少 exp")
	}
	if exp < float64(time.Now().Unix()) {
		return nil, errors.New("jwt: 已过期")
	}
	if opts.Issuer != "" && strClaim(payload, "iss") != opts.Issuer {
		return nil, errors.New("jwt: iss 不符")
	}
	if opts.Audience != "" && strClaim(payload, "aud") != opts.Audience {
		return nil, errors.New("jwt: aud 不符")
	}
	return payload, nil
}

// ── HS256（仅旧 /api/totp 模块路由复用，行为与旧 lib/jwt.js 一致）────────────

// SignHS256 signs a payload as an HS256 JWT with the given lifetime. The claims
// body keeps the legacy lib/totp-auth/lib/jwt.js field order: the caller's
// fields first (so pass a struct, not a map), then iat and exp appended last.
// This keeps module tokens byte-identical for the same payload and clock.
func SignHS256(payload any, secret string, ttl time.Duration) (string, error) {
	now := time.Now().Unix()
	pb, err := jsonx.Marshal(payload)
	if err != nil {
		return "", err
	}
	if len(pb) < 2 || pb[0] != '{' || pb[len(pb)-1] != '}' {
		return "", errors.New("jwt: HS256 payload 必须是 JSON 对象")
	}
	claims := make([]byte, 0, len(pb)+32)
	claims = append(claims, pb[:len(pb)-1]...)
	claims = append(claims, fmt.Sprintf(`,"iat":%d,"exp":%d}`, now, now+int64(ttl.Seconds()))...)

	header, err := jsonx.Marshal(struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}{Alg: "HS256", Typ: "JWT"})
	if err != nil {
		return "", err
	}
	input := b64.EncodeToString(header) + "." + b64.EncodeToString(claims)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(input))
	return input + "." + b64.EncodeToString(mac.Sum(nil)), nil
}

// VerifyHS256 validates an HS256 JWT and returns its claims. It rejects
// non-HS256 algorithms and expired tokens.
func VerifyHS256(token, secret string) (map[string]any, error) {
	parts := splitToken(token)
	if parts == nil {
		return nil, errors.New("jwt: 结构非法")
	}
	hb, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("jwt: 头部解码失败")
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(hb, &header); err != nil {
		return nil, errors.New("jwt: 头部非法")
	}
	if header.Alg != "HS256" {
		return nil, errors.New("jwt: 算法不允许")
	}
	expected := hmac.New(sha256.New, []byte(secret))
	expected.Write([]byte(parts[0] + "." + parts[1]))
	want := expected.Sum(nil)
	got, err := b64.DecodeString(parts[2])
	if err != nil || !hmac.Equal(want, got) {
		return nil, errors.New("jwt: 签名校验失败")
	}
	pb, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("jwt: 载荷解码失败")
	}
	var payload map[string]any
	if err := json.Unmarshal(pb, &payload); err != nil {
		return nil, errors.New("jwt: 载荷非法")
	}
	exp, ok := numClaim(payload, "exp")
	if !ok {
		return nil, errors.New("jwt: 缺少 exp")
	}
	if exp < float64(time.Now().Unix()) {
		return nil, errors.New("jwt: 已过期")
	}
	return payload, nil
}

func splitToken(token string) []string {
	parts := make([]string, 0, 3)
	start := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
		}
	}
	parts = append(parts, token[start:])
	if len(parts) != 3 {
		return nil
	}
	return parts
}

func numClaim(m map[string]any, key string) (float64, bool) {
	v, ok := m[key].(float64)
	return v, ok
}

func strClaim(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}

func generateEntry() (KeyEntry, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return KeyEntry{}, fmt.Errorf("jwt: 生成 P-256 密钥失败: %w", err)
	}
	x := make([]byte, 32)
	y := make([]byte, 32)
	d := make([]byte, 32)
	priv.X.FillBytes(x)
	priv.Y.FillBytes(y)
	priv.D.FillBytes(d)
	pub := JWK{Kty: "EC", Crv: "P-256", X: b64.EncodeToString(x), Y: b64.EncodeToString(y)}
	entry := KeyEntry{
		Kid:        Thumbprint(pub),
		CreatedAt:  time.Now().UnixMilli(),
		PrivateJWK: JWK{Kty: "EC", Crv: "P-256", X: pub.X, Y: pub.Y, D: b64.EncodeToString(d)},
		PublicJWK:  pub,
	}
	return entry, nil
}

func (ks *KeyStore) persist() error {
	if err := os.MkdirAll(filepath.Dir(ks.path), 0o700); err != nil {
		return fmt.Errorf("jwt: 创建密钥目录失败: %w", err)
	}
	data, err := jsonx.MarshalIndent(keyFile{Keys: ks.keys}, 2)
	if err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.%d.tmp", ks.path, os.Getpid())
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("jwt: 写入临时密钥文件失败: %w", err)
	}
	if err := os.Rename(tmp, ks.path); err != nil {
		return fmt.Errorf("jwt: 替换密钥文件失败: %w", err)
	}
	// 目标文件系统可能不支持 chmod，忽略失败。
	_ = os.Chmod(ks.path, 0o600)
	return nil
}

func privateFromJWK(k JWK) (*ecdsa.PrivateKey, error) {
	if k.Crv != "P-256" || k.Kty != "EC" {
		return nil, fmt.Errorf("不支持的曲线/类型: %s/%s", k.Kty, k.Crv)
	}
	x, err := decodeCoord(k.X)
	if err != nil {
		return nil, err
	}
	y, err := decodeCoord(k.Y)
	if err != nil {
		return nil, err
	}
	d, err := decodeCoord(k.D)
	if err != nil {
		return nil, err
	}
	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y},
		D:         d,
	}
	if priv.D.Sign() <= 0 || priv.D.Cmp(elliptic.P256().Params().N) >= 0 {
		return nil, errors.New("私钥标量越界")
	}
	return priv, nil
}

func publicFromJWK(k JWK) (*ecdsa.PublicKey, error) {
	if k.Crv != "P-256" || k.Kty != "EC" {
		return nil, fmt.Errorf("不支持的曲线/类型: %s/%s", k.Kty, k.Crv)
	}
	x, err := decodeCoord(k.X)
	if err != nil {
		return nil, err
	}
	y, err := decodeCoord(k.Y)
	if err != nil {
		return nil, err
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

func decodeCoord(s string) (*big.Int, error) {
	b, err := b64.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

// SHA256Hex is exported for callers that need the same key-derivation the OIDC
// provider uses for its Redis records.
func SHA256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
