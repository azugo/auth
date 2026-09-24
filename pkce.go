package auth

import (
	"crypto/sha256"
	"encoding/base64"
)

// s256 is BASE64URL(SHA256(value)), the RFC 7636 S256 transform.
func s256(value string) string {
	sum := sha256.Sum256([]byte(value))

	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// validPKCEValue reports whether v is a valid RFC 7636 code_verifier or code_challenge:
// 43-128 unreserved characters.
func validPKCEValue(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}

	for _, c := range []byte(v) {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '.', c == '_', c == '~':
		default:
			return false
		}
	}

	return true
}
