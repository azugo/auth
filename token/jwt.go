package token

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"unsafe"

	"github.com/goccy/go-json"
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
	// Nonce is echoed from the authorization request; omitted when empty.
	Nonce string
	// AuthTime is when the user originally authenticated; omitted when zero.
	AuthTime int64
	// ACR and AMR are the satisfied authentication context and methods.
	ACR string
	AMR []string
}

// accessTokenType is the RFC 9068 typ header value marking a JWT as an access token.
const accessTokenType = "at+jwt"

// SignIDToken mints a signed ID Token using signingKey.
func SignIDToken(signingKey SigningKey, claims IDTokenClaims) (string, error) {
	m := jwt.MapClaims{
		"iss": claims.Issuer,
		"sub": claims.Subject,
		"aud": claims.Audience,
		"iat": claims.IssuedAt,
		"exp": claims.ExpiresAt,
	}

	if claims.Nonce != "" {
		m["nonce"] = claims.Nonce
	}

	if claims.AuthTime != 0 {
		m["auth_time"] = claims.AuthTime
	}

	if claims.ACR != "" {
		m["acr"] = claims.ACR
	}

	if len(claims.AMR) > 0 {
		m["amr"] = claims.AMR
	}

	return sign(signingKey, "", m)
}

// AccessTokenClaims are the claims of a signed JWT access token.
type AccessTokenClaims struct {
	Issuer    string
	Subject   string
	ClientID  string // aud
	Scope     string
	TokenID   string // jti, checked against the revocation deny-list
	IssuedAt  int64
	ExpiresAt int64
	// ACR and AMR are the session's authentication context (RFC 9068 §2.2.1).
	ACR string
	AMR []string
}

// SignAccessToken mints a signed JWT access token using signingKey.
func SignAccessToken(signingKey SigningKey, claims AccessTokenClaims) (string, error) {
	m := jwt.MapClaims{
		"iss":   claims.Issuer,
		"sub":   claims.Subject,
		"aud":   claims.ClientID,
		"scope": claims.Scope,
		"jti":   claims.TokenID,
		"iat":   claims.IssuedAt,
		"exp":   claims.ExpiresAt,
	}

	if claims.ACR != "" {
		m["acr"] = claims.ACR
	}

	if len(claims.AMR) > 0 {
		m["amr"] = claims.AMR
	}

	return sign(signingKey, accessTokenType, m)
}

// allAlgorithms are the JWS algorithms accepted when verifying inbound JWTs.
var allAlgorithms = []string{AlgRS256, AlgRS384, AlgRS512, AlgES256, AlgES384, AlgES512}

// VerifyAccessToken verifies a signed JWT access token against set - the key matching the
// kid header when the header names a known key, otherwise primary, signing and secondary
// keys in order.
func VerifyAccessToken(set *KeySet, tok string) (AccessTokenClaims, error) {
	claims := jwt.MapClaims{}
	err := ErrInvalidToken

	for _, pub := range verificationKeys(set, tok) {
		if _, err = jwt.ParseWithClaims(tok, claims,
			func(t *jwt.Token) (any, error) {
				// Only RFC 9068 access tokens are accepted
				if typ, _ := t.Header["typ"].(string); !strings.EqualFold(typ, accessTokenType) &&
					!strings.EqualFold(typ, "application/"+accessTokenType) {
					return nil, ErrInvalidToken
				}

				return pub, nil
			},
			jwt.WithValidMethods(allAlgorithms),
			jwt.WithExpirationRequired(),
		); err == nil {
			break
		}
	}

	if err != nil {
		return AccessTokenClaims{}, err
	}

	out := AccessTokenClaims{}
	out.Issuer, _ = claims["iss"].(string)
	out.Subject, _ = claims["sub"].(string)
	out.ClientID, _ = claims["aud"].(string)
	out.Scope, _ = claims["scope"].(string)
	out.ACR, _ = claims["acr"].(string)

	if amr, ok := claims["amr"].([]any); ok {
		for _, v := range amr {
			if s, ok := v.(string); ok {
				out.AMR = append(out.AMR, s)
			}
		}
	}

	out.TokenID, _ = claims["jti"].(string)
	if out.TokenID == "" {
		return AccessTokenClaims{}, ErrInvalidToken
	}

	if v, err := claims.GetIssuedAt(); err == nil && v != nil {
		out.IssuedAt = v.Unix()
	}

	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		return AccessTokenClaims{}, ErrInvalidToken
	}

	out.ExpiresAt = exp.Unix()

	return out, nil
}

// VerifyIDToken verifies an id_token this server issued and returns its claims. Expiry is
// deliberately not enforced: an id_token_hint identifies a past session rather than authorizing
// a request (OpenID Connect RP-Initiated Logout).
func VerifyIDToken(set *KeySet, tok string) (IDTokenClaims, error) {
	claims := jwt.MapClaims{}
	err := ErrInvalidToken

	for _, pub := range verificationKeys(set, tok) {
		if _, err = jwt.ParseWithClaims(tok, claims,
			func(*jwt.Token) (any, error) { return pub, nil },
			jwt.WithValidMethods(allAlgorithms),
			jwt.WithoutClaimsValidation(),
		); err == nil {
			break
		}
	}

	if err != nil {
		return IDTokenClaims{}, err
	}

	out := IDTokenClaims{}
	out.Issuer, _ = claims["iss"].(string)
	out.Subject, _ = claims["sub"].(string)
	out.Audience, _ = claims["aud"].(string)

	if out.Subject == "" {
		return IDTokenClaims{}, ErrInvalidToken
	}

	return out, nil
}

// verificationKeys returns the public keys to try for tok, narrowed to the single key a known
// kid names.
func verificationKeys(set *KeySet, tok string) []crypto.PublicKey {
	type candidate struct {
		id  string
		pub crypto.PublicKey
	}

	candidates := make([]candidate, 0, 1+len(set.Signing)+len(set.Secondary))
	candidates = append(candidates, candidate{set.Primary.ID, set.Primary.Public})

	for _, k := range set.Signing {
		candidates = append(candidates, candidate{k.ID, k.Public})
	}

	for _, k := range set.Secondary {
		candidates = append(candidates, candidate{k.ID, k.Public})
	}

	if kid := jwtKID(tok); kid != "" {
		if i := slices.IndexFunc(candidates,
			func(c candidate) bool {
				return c.id == kid
			},
		); i >= 0 {
			candidates = candidates[i : i+1]
		}
	}

	out := make([]crypto.PublicKey, 0, len(candidates))
	for _, c := range candidates {
		out = append(out, c.pub)
	}

	return out
}

// jwtKID extracts the kid header from a serialized JWT without verifying it.
func jwtKID(tok string) string {
	head, _, ok := strings.Cut(tok, ".")
	if !ok {
		return ""
	}

	raw, err := base64.RawURLEncoding.DecodeString(head)
	if err != nil {
		return ""
	}

	var header struct {
		KID string `json:"kid"`
	}

	if err := json.Unmarshal(raw, &header); err != nil {
		return ""
	}

	return header.KID
}

func sign(signingKey SigningKey, typ string, claims jwt.MapClaims) (string, error) {
	method, err := signerMethodFor(signingKey.Algorithm)
	if err != nil {
		return "", err
	}

	tok := jwt.NewWithClaims(method, claims)

	if typ != "" {
		tok.Header["typ"] = typ
	}

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
