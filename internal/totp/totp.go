// Package totp implements RFC 6238 TOTP and the tiered login rate limiter.
//
// Parameter set matches lib/totp-auth exactly: HMAC-SHA1, 6 digits, 30 second
// step, ±1 step tolerance. The base32 codec is RFC 4648 without padding.
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"strings"
	"time"
)

// Step is the TOTP time step in seconds.
const Step = 30

// Digits is the number of output digits.
const Digits = 6

const base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

// DefaultWindow is the tolerated step offset (±1 step) used on login.
const DefaultWindow = 1

// Base32Encode encodes raw bytes as uppercase RFC 4648 base32 without padding.
func Base32Encode(input []byte) string {
	var sb strings.Builder
	bits := 0
	var value uint32
	for _, b := range input {
		value = (value << 8) | uint32(b)
		bits += 8
		for bits >= 5 {
			sb.WriteByte(base32Alphabet[(value>>uint(bits-5))&0x1f])
			bits -= 5
		}
	}
	if bits > 0 {
		sb.WriteByte(base32Alphabet[(value<<uint(5-bits))&0x1f])
	}
	return sb.String()
}

// Base32Decode decodes an RFC 4648 base32 string (padding optional, spaces
// ignored, case-insensitive) into bytes.
func Base32Decode(input string) ([]byte, error) {
	cleaned := strings.ToUpper(strings.Join(strings.Fields(input), ""))
	cleaned = strings.TrimRight(cleaned, "=")
	if cleaned == "" {
		return nil, errors.New("base32: 空 secret")
	}
	var out []byte
	bits := 0
	var value uint32
	for _, ch := range cleaned {
		idx := strings.IndexRune(base32Alphabet, ch)
		if idx < 0 {
			return nil, errors.New("base32: 非法字符 " + string(ch))
		}
		value = (value << 5) | uint32(idx)
		bits += 5
		if bits >= 8 {
			out = append(out, byte((value>>uint(bits-8))&0xff))
			bits -= 8
		}
	}
	return out, nil
}

// Generate computes the TOTP code for a base32 secret at the given Unix second.
// time <= 0 means "now".
func Generate(secret string, at int64) (string, error) {
	key, err := Base32Decode(secret)
	if err != nil {
		return "", err
	}
	if at <= 0 {
		at = time.Now().Unix()
	}
	return generateWithKey(key, at), nil
}

func generateWithKey(key []byte, at int64) string {
	counter := uint64(at / Step)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])
	code := bin % 1_000_000
	digits := [6]byte{}
	for i := 5; i >= 0; i-- {
		digits[i] = byte('0' + code%10)
		code /= 10
	}
	return string(digits[:])
}

// Verify checks a candidate code against the given window (±steps). Spaces in
// the candidate are ignored, matching the legacy verifier.
func Verify(secret, code string, window int) bool {
	expected := strings.Join(strings.Fields(code), "")
	if expected == "" {
		return false
	}
	key, err := Base32Decode(secret)
	if err != nil {
		return false
	}
	now := time.Now().Unix()
	for step := -window; step <= window; step++ {
		if generateWithKey(key, now+int64(step)*Step) == expected {
			return true
		}
	}
	return false
}

// GenerateSecret returns a fresh 160-bit secret as base32, matching the legacy
// 20-byte random secret.
func GenerateSecret() (string, error) {
	buf := make([]byte, 20)
	if _, err := cryptoRead(buf); err != nil {
		return "", err
	}
	return Base32Encode(buf), nil
}
