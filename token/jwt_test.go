package token

import (
	"strings"
	"testing"

	"azugo.io/auth/contract"

	"github.com/go-quicktest/qt"
	"github.com/golang-jwt/jwt/v5"
)

func keySetConfigFor(id, alg, priv, pub string) *contract.KeySetConfig {
	return &contract.KeySetConfig{
		Primary: contract.KeyConfig{ID: id, Algorithm: alg, PrivateKey: priv, PublicKey: pub},
	}
}

func TestSignIDTokenRSAVerifiesWithStdlib(t *testing.T) {
	key, priv, pub := genRSA(t)

	kp, err := NewConfigKeyProvider(keySetConfigFor("k1", "RS256", priv, pub))
	qt.Assert(t, qt.IsNil(err))

	set, err := kp.KeySet(t.Context())
	qt.Assert(t, qt.IsNil(err))

	raw, err := SignIDToken(set.Primary, IDTokenClaims{
		Issuer: "https://issuer.example", Subject: "u1", Audience: "client1",
		IssuedAt: 1000, ExpiresAt: 2000,
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(len(strings.Split(raw, ".")), 3))

	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(raw, claims, func(_ *jwt.Token) (any, error) {
		return &key.PublicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithoutClaimsValidation())
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(parsed.Valid))
	qt.Check(t, qt.Equals(claims["iss"], "https://issuer.example"))
	qt.Check(t, qt.Equals(claims["sub"], "u1"))
	qt.Check(t, qt.Equals(claims["aud"], "client1"))
	qt.Check(t, qt.Equals(parsed.Header["kid"], "k1"))
}

func TestSignIDTokenECDSAVerifiesWithStdlib(t *testing.T) {
	key, priv, pub := genECDSA(t)

	kp, err := NewConfigKeyProvider(keySetConfigFor("k1", "ES256", priv, pub))
	qt.Assert(t, qt.IsNil(err))

	set, err := kp.KeySet(t.Context())
	qt.Assert(t, qt.IsNil(err))

	raw, err := SignIDToken(set.Primary, IDTokenClaims{
		Issuer: "https://issuer.example", Subject: "u1", Audience: "client1",
		IssuedAt: 1000, ExpiresAt: 2000,
	})
	qt.Assert(t, qt.IsNil(err))

	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(raw, claims, func(_ *jwt.Token) (any, error) {
		return &key.PublicKey, nil
	}, jwt.WithValidMethods([]string{"ES256"}), jwt.WithoutClaimsValidation())
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(parsed.Valid))
	qt.Check(t, qt.Equals(claims["sub"], "u1"))
}

func TestSignIDTokenOmitsKidWhenSigningKeyIDEmpty(t *testing.T) {
	key, priv, pub := genRSA(t)

	// Built directly (not via NewConfigKeyProvider, which now always derives ID for the
	// primary key) to exercise sign()'s own empty-ID handling in isolation - e.g. a custom
	// KeyProvider that returns a SigningKey with no ID.
	signer, err := parsePrivateKey(priv)
	qt.Assert(t, qt.IsNil(err))

	pubKey, err := parsePublicKey(pub)
	qt.Assert(t, qt.IsNil(err))

	signingKey := SigningKey{Algorithm: "RS256", Private: signer, Public: pubKey}

	raw, err := SignIDToken(signingKey, IDTokenClaims{Issuer: "iss", Subject: "u1", Audience: "c1"})
	qt.Assert(t, qt.IsNil(err))

	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(raw, claims, func(_ *jwt.Token) (any, error) {
		return &key.PublicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithoutClaimsValidation())
	qt.Assert(t, qt.IsNil(err))

	_, hasKid := parsed.Header["kid"]
	qt.Check(t, qt.IsFalse(hasKid))
}

func TestSignIDTokenTamperedSignatureFailsVerification(t *testing.T) {
	_, priv, pub := genRSA(t)

	kp, err := NewConfigKeyProvider(keySetConfigFor("k1", "RS256", priv, pub))
	qt.Assert(t, qt.IsNil(err))

	set, err := kp.KeySet(t.Context())
	qt.Assert(t, qt.IsNil(err))

	raw, err := SignIDToken(set.Primary, IDTokenClaims{Issuer: "iss", Subject: "u1", Audience: "c1"})
	qt.Assert(t, qt.IsNil(err))

	parts := strings.Split(raw, ".")
	qt.Assert(t, qt.Equals(len(parts), 3))
	// Flip the payload without re-signing.
	tampered := parts[0] + "." + parts[1] + "x" + "." + parts[2]

	otherKey, _, _ := genRSA(t)

	_, err = jwt.Parse(tampered, func(_ *jwt.Token) (any, error) {
		return &otherKey.PublicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithoutClaimsValidation())
	qt.Check(t, qt.IsNotNil(err))
}

func TestSignerMethodUnsupportedAlgorithm(t *testing.T) {
	_, err := signerMethodFor("HS256")
	qt.Check(t, qt.IsNotNil(err))
}
