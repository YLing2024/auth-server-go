package totp

import "crypto/rand"

// cryptoRead is split out so GenerateSecret stays readable and the randomness
// source is obvious (crypto/rand, never math/rand).
func cryptoRead(buf []byte) (int, error) {
	return rand.Read(buf)
}
