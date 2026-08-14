package token

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"slices"

	"azugo.io/auth/contract"

	"github.com/goccy/go-json"
)

// Signing algorithms accepted for a SigningKey/VerificationKey.
const (
	AlgRS256 = "RS256"
	AlgRS384 = "RS384"
	AlgRS512 = "RS512"
	AlgES256 = "ES256"
	AlgES384 = "ES384"
	AlgES512 = "ES512"
)

// ecdsaCurveBits maps a JWT ECDSA algorithm to its expected curve bit size.
var ecdsaCurveBits = map[string]int{
	AlgES256: 256,
	AlgES384: 384,
	AlgES512: 521,
}

// ecdsaAlgorithmForCurve returns the JWS algorithm RFC 7518 §3.4 mandates for curve's bit
// size, or "" if unsupported. Unlike RSA (RS256/384/512 is a free choice of hash independent
// of the key), each ECDSA curve has exactly one valid algorithm.
func ecdsaAlgorithmForCurve(curve elliptic.Curve) string {
	switch curve.Params().BitSize {
	case 256:
		return AlgES256
	case 384:
		return AlgES384
	case 521:
		return AlgES512
	default:
		return ""
	}
}

// KeySet is the resolved key set used for signing and verification.
type KeySet struct {
	// Primary is the default signing key for new tokens.
	Primary SigningKey
	// Signing keys provide alternative algorithms for clients that register a different
	// id_token_signed_response_alg; at most one key per algorithm.
	Signing []SigningKey
	// Secondary keys are tried for verification when the primary's kid does not match, in
	// order.
	Secondary []VerificationKey
}

// SigningKey holds one asymmetric signing key.
type SigningKey struct {
	// ID is the kid included in the JWT header and JWKS.
	ID string
	// Algorithm is RS256, RS384, RS512, ES256, ES384 or ES512.
	Algorithm string
	// Private signs new tokens.
	Private crypto.Signer
	// Public is included in JWKS.
	Public crypto.PublicKey
}

// VerificationKey holds a public key used only for verification.
type VerificationKey struct {
	ID string
	// Algorithm is RS256, RS384, RS512, ES256, ES384 or ES512, or "" for an RSA key with no
	// algorithm configured.
	Algorithm string
	Public    crypto.PublicKey
}

// SigningAlgorithms returns the distinct algorithms this set can sign with, primary first.
func (s *KeySet) SigningAlgorithms() []string {
	algs := make([]string, 0, 1+len(s.Signing))
	algs = append(algs, s.Primary.Algorithm)

	for _, k := range s.Signing {
		if !slices.Contains(algs, k.Algorithm) {
			algs = append(algs, k.Algorithm)
		}
	}

	return algs
}

// SignerFor returns the signing key for alg - the primary when alg is "" or matches it,
// otherwise the Signing entry with that algorithm.
func (s *KeySet) SignerFor(alg string) (SigningKey, bool) {
	if alg == "" || alg == s.Primary.Algorithm {
		return s.Primary, true
	}

	for _, k := range s.Signing {
		if k.Algorithm == alg {
			return k, true
		}
	}

	return SigningKey{}, false
}

// KeyProvider supplies the current key set. Called on each signing and verification
// operation.
type KeyProvider interface {
	KeySet(ctx context.Context) (*KeySet, error)
}

// KeySet returns the key set itself, making a static *KeySet its own KeyProvider.
func (s *KeySet) KeySet(_ context.Context) (*KeySet, error) {
	return s, nil
}

// NewConfigKeyProvider parses the PEM-encoded keys in cfg into a static KeyProvider.
func NewConfigKeyProvider(cfg *contract.KeySetConfig) (KeyProvider, error) {
	if cfg == nil {
		return nil, errors.New("key set configuration is required")
	}

	primary, err := parseSigningKey(cfg.Primary)
	if err != nil {
		return nil, fmt.Errorf("primary key %q: %w", cfg.Primary.ID, err)
	}

	signing := make([]SigningKey, 0, len(cfg.Signing))
	algs := map[string]struct{}{primary.Algorithm: {}}

	for _, kc := range cfg.Signing {
		sk, err := parseSigningKey(kc)
		if err != nil {
			return nil, fmt.Errorf("signing key %q: %w", kc.ID, err)
		}

		if _, ok := algs[sk.Algorithm]; ok {
			return nil, fmt.Errorf("signing key %q: duplicate algorithm %s", sk.ID, sk.Algorithm)
		}

		algs[sk.Algorithm] = struct{}{}

		signing = append(signing, sk)
	}

	secondary := make([]VerificationKey, 0, len(cfg.Secondary))

	for _, kc := range cfg.Secondary {
		vk, err := parseVerificationKey(kc)
		if err != nil {
			return nil, fmt.Errorf("secondary key %q: %w", kc.ID, err)
		}

		secondary = append(secondary, vk)
	}

	return &KeySet{Primary: primary, Signing: signing, Secondary: secondary}, nil
}

func parseSigningKey(kc contract.KeyConfig) (SigningKey, error) {
	priv, err := parsePrivateKey(kc.PrivateKey)
	if err != nil {
		return SigningKey{}, err
	}

	pub := priv.Public()

	if kc.PublicKey != "" {
		if pub, err = ParsePublicKeyPEM(kc.PublicKey); err != nil {
			return SigningKey{}, err
		}
	}

	id, alg, err := resolveIDAndAlgorithm(kc, pub, true)
	if err != nil {
		return SigningKey{}, err
	}

	return SigningKey{ID: id, Algorithm: alg, Private: priv, Public: pub}, nil
}

func parseVerificationKey(kc contract.KeyConfig) (VerificationKey, error) {
	if kc.PublicKey == "" {
		return VerificationKey{}, errors.New("public key is required for a secondary key")
	}

	pub, err := ParsePublicKeyPEM(kc.PublicKey)
	if err != nil {
		return VerificationKey{}, err
	}

	id, alg, err := resolveIDAndAlgorithm(kc, pub, false)
	if err != nil {
		return VerificationKey{}, err
	}

	return VerificationKey{ID: id, Algorithm: alg, Public: pub}, nil
}

func resolveIDAndAlgorithm(kc contract.KeyConfig, pub crypto.PublicKey, forSigning bool) (string, string, error) {
	alg := kc.Algorithm

	switch {
	case alg != "":
		if err := validateAlgorithmKey(alg, pub); err != nil {
			return "", "", err
		}
	default:
		switch k := pub.(type) {
		case *ecdsa.PublicKey:
			if alg = ecdsaAlgorithmForCurve(k.Curve); alg == "" {
				return "", "", errors.New("unsupported ECDSA curve")
			}
		case *rsa.PublicKey:
			if forSigning {
				alg = AlgRS256
			}
		default:
			return "", "", fmt.Errorf("unsupported public key type %T", pub)
		}
	}

	id := kc.ID
	if id == "" {
		thumbprint, err := jwkThumbprint(pub)
		if err != nil {
			return "", "", err
		}

		id = thumbprint
	}

	return id, alg, nil
}

func parsePrivateKey(pemStr string) (crypto.Signer, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("invalid PEM block")
	}

	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, errors.New("key does not support signing")
		}

		return signer, nil
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	return nil, errors.New("unsupported private key format")
}

// ParsePublicKeyPEM decodes a PEM-encoded PKIX public key, PKCS#1 (RSA) public key, or
// certificate (using its public key).
func ParsePublicKeyPEM(pemStr string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("invalid PEM block")
	}

	if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		return key, nil
	}

	if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
		return cert.PublicKey, nil
	}

	if key, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return key, nil
	}

	return nil, errors.New("unsupported public key format")
}

func validateAlgorithmKey(alg string, pub crypto.PublicKey) error {
	switch alg {
	case AlgRS256, AlgRS384, AlgRS512:
		if _, ok := pub.(*rsa.PublicKey); !ok {
			return fmt.Errorf("algorithm %s requires an RSA key", alg)
		}
	case AlgES256, AlgES384, AlgES512:
		ecKey, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("algorithm %s requires an ECDSA key", alg)
		}

		if want := ecdsaCurveBits[alg]; ecKey.Curve.Params().BitSize != want {
			return fmt.Errorf("algorithm %s requires a P-%d curve key", alg, want)
		}
	default:
		return fmt.Errorf("unsupported algorithm %q", alg)
	}

	return nil
}

// JWK is one entry in a JSON Web Key Set (RFC 7517).
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// JWKS is a JSON Web Key Set document.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWKSFrom renders set's public keys as a JWKS document.
func JWKSFrom(set *KeySet) JWKS {
	keys := make([]JWK, 0, 1+len(set.Signing)+len(set.Secondary))
	keys = append(keys, jwkFor(set.Primary.ID, set.Primary.Algorithm, set.Primary.Public))

	for _, sk := range set.Signing {
		keys = append(keys, jwkFor(sk.ID, sk.Algorithm, sk.Public))
	}

	for _, vk := range set.Secondary {
		keys = append(keys, jwkFor(vk.ID, vk.Algorithm, vk.Public))
	}

	return JWKS{Keys: keys}
}

func jwkFor(kid, alg string, pub crypto.PublicKey) JWK {
	fields, err := publicKeyFields(pub)
	if err != nil {
		return JWK{}
	}

	return JWK{
		Kty: fields.Kty, Use: "sig", Kid: kid, Alg: alg,
		N: fields.N, E: fields.E,
		Crv: fields.Crv, X: fields.X, Y: fields.Y,
	}
}

type jwkPublicFields struct {
	Kty       string
	N, E      string
	Crv, X, Y string
}

func publicKeyFields(pub crypto.PublicKey) (jwkPublicFields, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return jwkPublicFields{
			Kty: "RSA",
			N:   base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
		}, nil
	case *ecdsa.PublicKey:
		alg := ecdsaAlgorithmForCurve(k.Curve)
		if alg == "" {
			return jwkPublicFields{}, errors.New("unsupported ECDSA curve")
		}

		ek, err := k.ECDH()
		if err != nil {
			return jwkPublicFields{}, err
		}

		// Uncompressed point: 0x04 || X || Y.
		raw := ek.Bytes()
		size := (len(raw) - 1) / 2
		x := raw[1 : 1+size]
		y := raw[1+size:]

		return jwkPublicFields{
			Kty: "EC",
			Crv: ecdsaCurveName(alg),
			X:   base64.RawURLEncoding.EncodeToString(x),
			Y:   base64.RawURLEncoding.EncodeToString(y),
		}, nil
	default:
		return jwkPublicFields{}, fmt.Errorf("unsupported public key type %T", pub)
	}
}

func jwkThumbprint(pub crypto.PublicKey) (string, error) {
	fields, err := publicKeyFields(pub)
	if err != nil {
		return "", err
	}

	m := map[string]string{"kty": fields.Kty}

	switch fields.Kty {
	case "RSA":
		m["e"] = fields.E
		m["n"] = fields.N
	case "EC":
		m["crv"] = fields.Crv
		m["x"] = fields.X
		m["y"] = fields.Y
	}

	canonical, err := json.Marshal(m)
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256(canonical)

	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func ecdsaCurveName(alg string) string {
	switch alg {
	case AlgES256:
		return "P-256"
	case AlgES384:
		return "P-384"
	case AlgES512:
		return "P-521"
	default:
		return ""
	}
}
