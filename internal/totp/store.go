package totp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// PendingTTL is how long a two-phase reset stays confirmable.
const PendingTTL = 5 * time.Minute

func defaultNowMillis() int64 { return time.Now().UnixMilli() }

// SecretStore persists the formal TOTP secret as <dir>/totp-secret.json. The
// format ({ "secret": "..." }) is shared with the legacy service, so the file
// must never be rewritten with a different shape.
type SecretStore struct {
	path string
}

// NewSecretStore returns a store rooted at path (the totp-secret.json file).
func NewSecretStore(path string) *SecretStore { return &SecretStore{path: path} }

// Load returns the secret, or ok=false when the file is missing or invalid.
func (s *SecretStore) Load() (string, bool) {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return "", false
	}
	var data struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(raw, &data); err != nil || data.Secret == "" {
		return "", false
	}
	return data.Secret, true
}

// Save atomically writes the formal secret (0600). Callers must only do this
// after a confirmed pending code — see the two-phase reset contract.
func (s *SecretStore) Save(secret string) error {
	return writeJSONAtomic(s.path, map[string]string{"secret": secret})
}

// PendingRecord is the on-disk shape of an in-flight reset.
type PendingRecord struct {
	Secret    string `json:"secret"`
	ExpiresAt int64  `json:"expiresAt"`
}

// PendingStore persists the pending TOTP secret as <dir>/totp-pending.json.
type PendingStore struct {
	path string
}

// NewPendingStore returns a store rooted at path (the totp-pending.json file).
func NewPendingStore(path string) *PendingStore { return &PendingStore{path: path} }

// Load returns a live pending record. Expired or malformed records are removed
// and reported as absent so a stale pending never blocks a fresh reset.
func (p *PendingStore) Load() (*PendingRecord, bool) {
	raw, err := os.ReadFile(p.path)
	if err != nil {
		return nil, false
	}
	var rec PendingRecord
	if err := json.Unmarshal(raw, &rec); err != nil || rec.Secret == "" || rec.ExpiresAt == 0 {
		return nil, false
	}
	if time.Now().UnixMilli() > rec.ExpiresAt {
		p.Delete()
		return nil, false
	}
	return &rec, true
}

// Save writes a pending record with the standard 5-minute TTL. It never touches
// the formal secret.
func (p *PendingStore) Save(secret string) error {
	rec := PendingRecord{Secret: secret, ExpiresAt: time.Now().UnixMilli() + PendingTTL.Milliseconds()}
	return writeJSONAtomic(p.path, rec)
}

// Delete removes the pending record; a missing file is not an error.
func (p *PendingStore) Delete() {
	_ = os.Remove(p.path)
}

func writeJSONAtomic(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("totp: 创建目录失败: %w", err)
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.%d.tmp", path, os.Getpid())
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("totp: 写入临时文件失败: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("totp: 替换文件失败: %w", err)
	}
	return nil
}
