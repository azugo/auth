package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"

	"azugo.io/core/http"
)

// jwksKey is one parsed JWKS verification key.
type jwksKey struct {
	kid    string
	public crypto.PublicKey
}

// jwksDocument is the RFC 7517 key set document.
type jwksDocument struct {
	Keys []jwkEntry `json:"keys"`
}

// jwkEntry is one RFC 7517 JWK.
type jwkEntry struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// fetchJWKS downloads and parses the provider JWKS, skipping non-signature and unsupported
// keys.
func fetchJWKS(ctx context.Context, client http.Client, uri string) ([]jwksKey, error) {
	doc := jwksDocument{}
	if err := client.WithContext(ctx).GetJSON(uri, &doc); err != nil {
		return nil, fmt.Errorf("oidc: JWKS fetch failed: %w", err)
	}

	keys := make([]jwksKey, 0, len(doc.Keys))

	for _, k := range doc.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}

		pub, err := k.publicKey()
		if err != nil {
			continue
		}

		keys = append(keys, jwksKey{kid: k.Kid, public: pub})
	}

	return keys, nil
}

// publicKey converts the JWK to its crypto.PublicKey.
func (k jwkEntry) publicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, err
		}

		e, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, err
		}

		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
	case "EC":
		var curve elliptic.Curve

		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported curve %q", k.Crv)
		}

		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, err
		}

		y, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, err
		}

		// Build an uncompressed point (0x04 || x || y)
		coordSize := (curve.Params().BitSize + 7) / 8
		point := make([]byte, 1+2*coordSize)
		point[0] = 0x04
		copy(point[1+coordSize-len(x):1+coordSize], x)
		copy(point[1+2*coordSize-len(y):], y)

		return ecdsa.ParseUncompressedPublicKey(curve, point)
	default:
		return nil, fmt.Errorf("unsupported key type %q", k.Kty)
	}
}
