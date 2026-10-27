// Package dpoptest mints DPoP proofs for tests.
package dpoptest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/go-quicktest/qt"
	"github.com/golang-jwt/jwt/v5"
)

// Key is a client's DPoP key pair.
type Key struct {
	priv *ecdsa.PrivateKey
	// JWK is the public key as a JWK.
	JWK map[string]any
	// JKT is the thumbprint of JWK.
	JKT string
}

// NewKey generates a P-256 DPoP key.
func NewKey(t *testing.T) *Key {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))

	pub, err := priv.PublicKey.Bytes()
	qt.Assert(t, qt.IsNil(err))

	x := base64.RawURLEncoding.EncodeToString(pub[1:33])
	y := base64.RawURLEncoding.EncodeToString(pub[33:])

	// The RFC 7638 thumbprint input, computed independently of the dpop package.
	sum := sha256.Sum256([]byte(`{"crv":"P-256","kty":"EC","x":"` + x + `","y":"` + y + `"}`))

	return &Key{
		priv: priv,
		JWK:  map[string]any{"kty": "EC", "crv": "P-256", "x": x, "y": y},
		JKT:  base64.RawURLEncoding.EncodeToString(sum[:]),
	}
}

// Proof mints a proof for method and uri; claims add to or override the defaults.
func (k *Key) Proof(t *testing.T, method, uri string, claims map[string]any) string {
	t.Helper()

	id := make([]byte, 16)
	_, _ = rand.Read(id)

	c := jwt.MapClaims{
		"jti": base64.RawURLEncoding.EncodeToString(id),
		"htm": method,
		"htu": uri,
		"iat": time.Now().Unix(),
	}

	for name, v := range claims {
		c[name] = v
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, c)
	tok.Header["typ"] = "dpop+jwt"
	tok.Header["jwk"] = k.JWK

	s, err := tok.SignedString(k.priv)
	qt.Assert(t, qt.IsNil(err))

	return s
}

// AccessProof mints a proof for method and uri presenting the access token tok.
func (k *Key) AccessProof(t *testing.T, method, uri, tok string) string {
	t.Helper()

	sum := sha256.Sum256([]byte(tok))

	return k.Proof(t, method, uri, map[string]any{"ath": base64.RawURLEncoding.EncodeToString(sum[:])})
}
