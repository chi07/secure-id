// Package secureid generates sortable, unguessable string IDs:
// a fixed-width base62 timestamp prefix followed by a crypto-random
// base62 suffix that scales with the requested length.
package secureid

import (
	"crypto/rand"
	"errors"
	"time"
)

// Layout: [ timePartLen base62 chars of UnixMilli ][ random base62 chars ].
// base62 (vs base36) packs ~15% more entropy per character.
const (
	timePartLen = 8 // covers ~89 years of milliseconds after the Unix epoch
	charset     = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

// maxRandByte is the cutoff for rejection sampling: bytes below it map to
// base62 digits without modulo bias (248 = 4*62).
const maxRandByte = 62 * (256 / 62)

// ErrTooShort is returned when length cannot hold the timestamp prefix plus
// at least one random character.
var ErrTooShort = errors.New("secureid: length must be at least 9")

// NewSID generates a sortable secure ID of the given length. The first 8
// characters encode the current time in base62; the remaining length-8
// characters are crypto-random base62 (rejection-sampled, no modulo bias),
// so longer IDs are proportionally harder to guess.
//
// Uniqueness is statistical: the random part has 62^(length-8) possible
// values, so callers relying on uniqueness should either use a large enough
// length or keep a unique constraint at the storage layer.
func NewSID(length int) (string, error) {
	if length < timePartLen+1 {
		return "", ErrTooShort
	}

	buf := make([]byte, length)

	// Timestamp prefix, fixed-width base62, big-endian, '0'-padded.
	encodeBase62(buf[:timePartLen], uint64(time.Now().UnixMilli()))

	// Crypto-random suffix.
	if err := fillRand(buf[timePartLen:]); err != nil {
		return "", err
	}
	return string(buf), nil
}

// encodeBase62 writes value into dst as fixed-width big-endian base62.
func encodeBase62(dst []byte, value uint64) {
	for i := len(dst) - 1; i >= 0; i-- {
		dst[i] = charset[value%62]
		value /= 62
	}
}

// fillRand writes rejection-sampled random base62 chars into dst.
// crypto/rand is already safe for concurrent use; no mutex is needed.
func fillRand(dst []byte) error {
	var chunk [64]byte
	for len(dst) > 0 {
		if _, err := rand.Read(chunk[:]); err != nil {
			return err
		}
		n := 0
		for _, b := range chunk {
			if b >= maxRandByte {
				continue
			}
			dst[n] = charset[int(b)%62]
			if n++; n == len(dst) {
				return nil
			}
		}
		dst = dst[n:]
	}
	return nil
}

// IsSecureID reports whether id is a well-formed secure ID: exactly length
// characters, all in the base62 alphabet (both cases accepted).
func IsSecureID(id string, length int) bool {
	if length < 1 || len(id) != length {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}
