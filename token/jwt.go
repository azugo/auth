package token

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"math/big"
	"unsafe"

	"github.com/golang-jwt/jwt/v5"
)

func s2b(s string) []byte {
	return unsafe.Slice(unsafe.StringData(s), len(s)) //nolint:gosec
}

// IDTokenClaims are the standard OIDC ID Token claims.
type IDTokenClaims struct {
	Issuer    string
	Subject   string
	Audience  string
	IssuedAt  int64
	ExpiresAt int64
}

// SignIDToken mints a signed ID Token using signingKey.
func SignIDToken(signingKey SigningKey, claims IDTokenClaims) (string, error) {
	return sign(signingKey, jwt.MapClaims{
		"iss": claims.Issuer,
		"sub": claims.Subject,
		"aud": claims.Audience,
		"iat": claims.IssuedAt,
		"exp": claims.ExpiresAt,
	})
}

func sign(signingKey SigningKey, claims jwt.MapClaims) (string, error) {
	method, err := signerMethodFor(signingKey.Algorithm)
	if err != nil {
		return "", err
	}

	tok := jwt.NewWithClaims(method, claims)

	if signingKey.ID != "" {
		tok.Header["kid"] = signingKey.ID
	}

	return tok.SignedString(signingKey.Private)
}

// signerMethod adapts a crypto.Signer (RSA or ECDSA) to jwt.SigningMethod.
type signerMethod struct {
	alg           string
	hash          crypto.Hash
	ecdsaKeyBytes int // 0 for RSA
}

func signerMethodFor(alg string) (*signerMethod, error) {
	switch alg {
	case AlgRS256:
		return &signerMethod{alg: alg, hash: crypto.SHA256}, nil
	case AlgRS384:
		return &signerMethod{alg: alg, hash: crypto.SHA384}, nil
	case AlgRS512:
		return &signerMethod{alg: alg, hash: crypto.SHA512}, nil
	case AlgES256:
		return &signerMethod{alg: alg, hash: crypto.SHA256, ecdsaKeyBytes: 32}, nil
	case AlgES384:
		return &signerMethod{alg: alg, hash: crypto.SHA384, ecdsaKeyBytes: 48}, nil
	case AlgES512:
		return &signerMethod{alg: alg, hash: crypto.SHA512, ecdsaKeyBytes: 66}, nil
	default:
		return nil, fmt.Errorf("unsupported signing algorithm %q", alg)
	}
}

func (m *signerMethod) Alg() string {
	return m.alg
}

// Sign implements jwt.SigningMethod: key must be a crypto.Signer.
func (m *signerMethod) Sign(signingString string, key any) ([]byte, error) {
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, jwt.ErrInvalidKeyType
	}

	if !m.hash.Available() {
		return nil, jwt.ErrHashUnavailable
	}

	h := m.hash.New()
	h.Write(s2b(signingString))

	sig, err := signer.Sign(rand.Reader, h.Sum(nil), m.hash)
	if err != nil {
		return nil, err
	}

	if m.ecdsaKeyBytes == 0 {
		return sig, nil
	}

	// crypto.Signer.Sign on an ECDSA key returns an ASN.1 DER-encoded (r, s) pair; JWS needs
	// the fixed-width raw r||s encoding instead.
	var parsed struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(sig, &parsed); err != nil {
		return nil, err
	}

	out := make([]byte, 2*m.ecdsaKeyBytes)
	parsed.R.FillBytes(out[:m.ecdsaKeyBytes])
	parsed.S.FillBytes(out[m.ecdsaKeyBytes:])

	return out, nil
}

// Verify implements jwt.SigningMethod: key must be *rsa.PublicKey (RS*) or *ecdsa.PublicKey
// (ES*).
func (m *signerMethod) Verify(signingString string, sig []byte, key any) error {
	if !m.hash.Available() {
		return jwt.ErrHashUnavailable
	}

	h := m.hash.New()
	h.Write(s2b(signingString))
	digest := h.Sum(nil)

	if m.ecdsaKeyBytes == 0 {
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return jwt.ErrInvalidKeyType
		}

		return rsa.VerifyPKCS1v15(pub, m.hash, digest, sig)
	}

	pub, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return jwt.ErrInvalidKeyType
	}

	if len(sig) != 2*m.ecdsaKeyBytes {
		return jwt.ErrECDSAVerification
	}

	r := new(big.Int).SetBytes(sig[:m.ecdsaKeyBytes])
	s := new(big.Int).SetBytes(sig[m.ecdsaKeyBytes:])

	if !ecdsa.Verify(pub, digest, r, s) {
		return jwt.ErrECDSAVerification
	}

	return nil
}
