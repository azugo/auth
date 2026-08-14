package token

import (
	"strings"
	"testing"
	"time"

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

	pubKey, err := ParsePublicKeyPEM(pub)
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

func TestSignVerifyAccessTokenRoundTrip(t *testing.T) {
	_, priv, pub := genRSA(t)

	kp, err := NewConfigKeyProvider(keySetConfigFor("k1", "RS256", priv, pub))
	qt.Assert(t, qt.IsNil(err))

	set, err := kp.KeySet(t.Context())
	qt.Assert(t, qt.IsNil(err))

	now := time.Now()

	raw, err := SignAccessToken(set.Primary, AccessTokenClaims{
		Issuer: "https://issuer.example", Subject: "u1", ClientID: "svc",
		Scope: "items:read", TokenID: "jti1",
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(),
	})
	qt.Assert(t, qt.IsNil(err))

	claims, err := VerifyAccessToken(set, raw)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(claims.Issuer, "https://issuer.example"))
	qt.Check(t, qt.Equals(claims.Subject, "u1"))
	qt.Check(t, qt.Equals(claims.ClientID, "svc"))
	qt.Check(t, qt.Equals(claims.Scope, "items:read"))
	qt.Check(t, qt.Equals(claims.TokenID, "jti1"))
	qt.Check(t, qt.Equals(claims.ExpiresAt, now.Add(time.Minute).Unix()))
}

func TestVerifyAccessTokenRejectsExpired(t *testing.T) {
	_, priv, pub := genRSA(t)

	kp, err := NewConfigKeyProvider(keySetConfigFor("k1", "RS256", priv, pub))
	qt.Assert(t, qt.IsNil(err))

	set, err := kp.KeySet(t.Context())
	qt.Assert(t, qt.IsNil(err))

	raw, err := SignAccessToken(set.Primary, AccessTokenClaims{
		Subject: "u1", ClientID: "svc", TokenID: "jti1",
		IssuedAt: time.Now().Add(-2 * time.Minute).Unix(), ExpiresAt: time.Now().Add(-time.Minute).Unix(),
	})
	qt.Assert(t, qt.IsNil(err))

	_, err = VerifyAccessToken(set, raw)
	qt.Check(t, qt.IsNotNil(err))
}

func TestVerifyAccessTokenSelectsSigningKeyByKid(t *testing.T) {
	_, rsaPriv, rsaPub := genRSA(t)
	_, ecPriv, ecPub := genECDSA(t)

	kp, err := NewConfigKeyProvider(&contract.KeySetConfig{
		Primary: contract.KeyConfig{ID: "k1", Algorithm: "RS256", PrivateKey: rsaPriv, PublicKey: rsaPub},
		Signing: []contract.KeyConfig{{ID: "k2", Algorithm: "ES256", PrivateKey: ecPriv, PublicKey: ecPub}},
	})
	qt.Assert(t, qt.IsNil(err))

	set, err := kp.KeySet(t.Context())
	qt.Assert(t, qt.IsNil(err))

	now := time.Now()

	raw, err := SignAccessToken(set.Signing[0], AccessTokenClaims{
		Subject: "u1", ClientID: "svc", TokenID: "jti1",
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(),
	})
	qt.Assert(t, qt.IsNil(err))

	claims, err := VerifyAccessToken(set, raw)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(claims.Subject, "u1"))
}

func TestVerifyAccessTokenRejectsForeignKey(t *testing.T) {
	_, priv, pub := genRSA(t)
	_, otherPriv, otherPub := genRSA(t)

	kp, err := NewConfigKeyProvider(keySetConfigFor("k1", "RS256", priv, pub))
	qt.Assert(t, qt.IsNil(err))

	set, err := kp.KeySet(t.Context())
	qt.Assert(t, qt.IsNil(err))

	foreign, err := NewConfigKeyProvider(keySetConfigFor("k1", "RS256", otherPriv, otherPub))
	qt.Assert(t, qt.IsNil(err))

	foreignSet, err := foreign.KeySet(t.Context())
	qt.Assert(t, qt.IsNil(err))

	now := time.Now()

	raw, err := SignAccessToken(foreignSet.Primary, AccessTokenClaims{
		Subject: "u1", ClientID: "svc", TokenID: "jti1",
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(),
	})
	qt.Assert(t, qt.IsNil(err))

	_, err = VerifyAccessToken(set, raw)
	qt.Check(t, qt.IsNotNil(err))
}

func TestVerifyAccessTokenRejectsIDToken(t *testing.T) {
	_, priv, pub := genRSA(t)

	kp, err := NewConfigKeyProvider(keySetConfigFor("k1", "RS256", priv, pub))
	qt.Assert(t, qt.IsNil(err))

	set, err := kp.KeySet(t.Context())
	qt.Assert(t, qt.IsNil(err))

	now := time.Now()

	// An id_token signed with the same key must not pass as an access token.
	raw, err := SignIDToken(set.Primary, IDTokenClaims{
		Issuer: "https://issuer.example", Subject: "u1", Audience: "client1",
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(),
	})
	qt.Assert(t, qt.IsNil(err))

	_, err = VerifyAccessToken(set, raw)
	qt.Check(t, qt.IsNotNil(err))
}

func TestVerifyAccessTokenRejectsMissingJTI(t *testing.T) {
	_, priv, pub := genRSA(t)

	kp, err := NewConfigKeyProvider(keySetConfigFor("k1", "RS256", priv, pub))
	qt.Assert(t, qt.IsNil(err))

	set, err := kp.KeySet(t.Context())
	qt.Assert(t, qt.IsNil(err))

	now := time.Now()

	raw, err := SignAccessToken(set.Primary, AccessTokenClaims{
		Subject: "u1", ClientID: "svc",
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(),
	})
	qt.Assert(t, qt.IsNil(err))

	_, err = VerifyAccessToken(set, raw)
	qt.Check(t, qt.IsNotNil(err))
}
