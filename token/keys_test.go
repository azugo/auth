package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"

	"azugo.io/auth/contract"

	"github.com/go-quicktest/qt"
	"github.com/goccy/go-json"
)

func pemEncode(blockType string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}))
}

// genRSA generates an RSA test key pair PEM-encoded as PKCS#8 (private) / PKIX (public).
func genRSA(t *testing.T) (*rsa.PrivateKey, string, string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	qt.Assert(t, qt.IsNil(err))

	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	qt.Assert(t, qt.IsNil(err))

	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	qt.Assert(t, qt.IsNil(err))

	return key, pemEncode("PRIVATE KEY", privDER), pemEncode("PUBLIC KEY", pubDER)
}

// genECDSA generates an ECDSA P-256 test key pair PEM-encoded as PKCS#8 (private) / PKIX
// (public).
func genECDSA(t *testing.T) (*ecdsa.PrivateKey, string, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))

	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	qt.Assert(t, qt.IsNil(err))

	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	qt.Assert(t, qt.IsNil(err))

	return key, pemEncode("PRIVATE KEY", privDER), pemEncode("EC PUBLIC KEY", pubDER)
}

func TestConfigKeyProviderParsesRSAPrimary(t *testing.T) {
	_, priv, pub := genRSA(t)

	kp, err := NewConfigKeyProvider(&contract.KeySetConfig{
		Primary: contract.KeyConfig{ID: "k1", Algorithm: "RS256", PrivateKey: priv, PublicKey: pub},
	})
	qt.Assert(t, qt.IsNil(err))

	set, err := kp.KeySet(t.Context())
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(set.Primary.ID, "k1"))
	qt.Check(t, qt.Equals(set.Primary.Algorithm, "RS256"))
	qt.Check(t, qt.IsNotNil(set.Primary.Private))
	qt.Check(t, qt.HasLen(set.Secondary, 0))
}

func TestConfigKeyProviderParsesECDSAPrimaryAndSecondary(t *testing.T) {
	_, priv1, pub1 := genECDSA(t)
	_, _, pub2 := genECDSA(t)

	kp, err := NewConfigKeyProvider(&contract.KeySetConfig{
		Primary:   contract.KeyConfig{ID: "k1", Algorithm: "ES256", PrivateKey: priv1, PublicKey: pub1},
		Secondary: []contract.KeyConfig{{ID: "k0", Algorithm: "ES256", PublicKey: pub2}},
	})
	qt.Assert(t, qt.IsNil(err))

	set, err := kp.KeySet(t.Context())
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(set.Primary.ID, "k1"))
	qt.Assert(t, qt.HasLen(set.Secondary, 1))
	qt.Check(t, qt.Equals(set.Secondary[0].ID, "k0"))
	qt.Check(t, qt.Equals(set.Secondary[0].Algorithm, "ES256"))
}

func TestConfigKeyProviderParsesSigningKeys(t *testing.T) {
	_, rsaPriv, rsaPub := genRSA(t)
	_, ecPriv, ecPub := genECDSA(t)

	kp, err := NewConfigKeyProvider(&contract.KeySetConfig{
		Primary: contract.KeyConfig{ID: "k1", Algorithm: "RS256", PrivateKey: rsaPriv, PublicKey: rsaPub},
		Signing: []contract.KeyConfig{{ID: "k2", Algorithm: "ES256", PrivateKey: ecPriv, PublicKey: ecPub}},
	})
	qt.Assert(t, qt.IsNil(err))

	set, err := kp.KeySet(t.Context())
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(set.Signing, 1))
	qt.Check(t, qt.Equals(set.Signing[0].ID, "k2"))
	qt.Check(t, qt.Equals(set.Signing[0].Algorithm, "ES256"))
	qt.Check(t, qt.IsNotNil(set.Signing[0].Private))

	qt.Check(t, qt.DeepEquals(set.SigningAlgorithms(), []string{"RS256", "ES256"}))

	jwks := JWKSFrom(set)
	qt.Assert(t, qt.HasLen(jwks.Keys, 2))
	qt.Check(t, qt.Equals(jwks.Keys[1].Kid, "k2"))
	qt.Check(t, qt.Equals(jwks.Keys[1].Alg, "ES256"))
}

func TestConfigKeyProviderRejectsDuplicateSigningAlgorithm(t *testing.T) {
	_, priv1, pub1 := genRSA(t)
	_, priv2, pub2 := genRSA(t)

	_, err := NewConfigKeyProvider(&contract.KeySetConfig{
		Primary: contract.KeyConfig{ID: "k1", Algorithm: "RS256", PrivateKey: priv1, PublicKey: pub1},
		Signing: []contract.KeyConfig{{ID: "k2", Algorithm: "RS256", PrivateKey: priv2, PublicKey: pub2}},
	})
	qt.Check(t, qt.ErrorMatches(err, `.*duplicate algorithm RS256.*`))
}

func TestConfigKeyProviderRejectsAlgorithmKeyMismatch(t *testing.T) {
	_, priv, pub := genRSA(t)

	_, err := NewConfigKeyProvider(&contract.KeySetConfig{
		// RSA key but declared as an EC algorithm.
		Primary: contract.KeyConfig{ID: "k1", Algorithm: "ES256", PrivateKey: priv, PublicKey: pub},
	})
	qt.Check(t, qt.IsNotNil(err))
}

func TestConfigKeyProviderRejectsInvalidPEM(t *testing.T) {
	_, err := NewConfigKeyProvider(&contract.KeySetConfig{
		Primary: contract.KeyConfig{ID: "k1", Algorithm: "RS256", PrivateKey: "not pem", PublicKey: "not pem"},
	})
	qt.Check(t, qt.IsNotNil(err))
}

func TestKeySetSigningAlgorithmsDeduplicates(t *testing.T) {
	set := &KeySet{
		Primary: SigningKey{Algorithm: "RS256"},
		Signing: []SigningKey{
			{Algorithm: "RS256"},
			{Algorithm: "ES256"},
		},
		Secondary: []VerificationKey{
			{Algorithm: "ES384"},
		},
	}

	// Secondary keys verify only - they are not advertised as signing algorithms.
	qt.Check(t, qt.DeepEquals(set.SigningAlgorithms(), []string{"RS256", "ES256"}))
}

func TestKeySetSignerFor(t *testing.T) {
	set := &KeySet{
		Primary: SigningKey{ID: "p", Algorithm: "RS256"},
		Signing: []SigningKey{{ID: "s", Algorithm: "ES256"}},
	}

	sk, ok := set.SignerFor("")
	qt.Assert(t, qt.IsTrue(ok))
	qt.Check(t, qt.Equals(sk.ID, "p"))

	sk, ok = set.SignerFor("RS256")
	qt.Assert(t, qt.IsTrue(ok))
	qt.Check(t, qt.Equals(sk.ID, "p"))

	sk, ok = set.SignerFor("ES256")
	qt.Assert(t, qt.IsTrue(ok))
	qt.Check(t, qt.Equals(sk.ID, "s"))

	_, ok = set.SignerFor("ES384")
	qt.Check(t, qt.IsFalse(ok))
}

func TestJWKSFromRSA(t *testing.T) {
	key, priv, pub := genRSA(t)

	kp, err := NewConfigKeyProvider(&contract.KeySetConfig{
		Primary: contract.KeyConfig{ID: "k1", Algorithm: "RS256", PrivateKey: priv, PublicKey: pub},
	})
	qt.Assert(t, qt.IsNil(err))

	set, err := kp.KeySet(t.Context())
	qt.Assert(t, qt.IsNil(err))

	jwks := JWKSFrom(set)
	qt.Assert(t, qt.HasLen(jwks.Keys, 1))

	jwk := jwks.Keys[0]
	qt.Check(t, qt.Equals(jwk.Kty, "RSA"))
	qt.Check(t, qt.Equals(jwk.Kid, "k1"))
	qt.Check(t, qt.Equals(jwk.Alg, "RS256"))
	qt.Check(t, qt.Equals(jwk.Use, "sig"))

	n, err := base64.RawURLEncoding.DecodeString(jwk.N)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(new(big.Int).SetBytes(n).Cmp(key.N), 0))

	e, err := base64.RawURLEncoding.DecodeString(jwk.E)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(int(new(big.Int).SetBytes(e).Int64()), key.E))
}

func TestJWKSFromECDSA(t *testing.T) {
	key, priv, pub := genECDSA(t)

	kp, err := NewConfigKeyProvider(&contract.KeySetConfig{
		Primary: contract.KeyConfig{ID: "k1", Algorithm: "ES256", PrivateKey: priv, PublicKey: pub},
	})
	qt.Assert(t, qt.IsNil(err))

	set, err := kp.KeySet(t.Context())
	qt.Assert(t, qt.IsNil(err))

	jwks := JWKSFrom(set)
	qt.Assert(t, qt.HasLen(jwks.Keys, 1))

	jwk := jwks.Keys[0]
	qt.Check(t, qt.Equals(jwk.Kty, "EC"))
	qt.Check(t, qt.Equals(jwk.Crv, "P-256"))

	x, err := base64.RawURLEncoding.DecodeString(jwk.X)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(new(big.Int).SetBytes(x).Cmp(key.X), 0))

	y, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(new(big.Int).SetBytes(y).Cmp(key.Y), 0))
}

// TestJWKThumbprintMatchesRFC7638Vector verifies jwkThumbprint against RFC 7638 Appendix A's
// own worked example, the strongest available proof of canonicalization correctness.
func TestJWKThumbprintMatchesRFC7638Vector(t *testing.T) {
	const n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tS" +
		"oc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_F" +
		"DW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQF" +
		"h6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
	const e = "AQAB"
	const wantThumbprint = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

	nBytes, err := base64.RawURLEncoding.DecodeString(n)
	qt.Assert(t, qt.IsNil(err))

	eBytes, err := base64.RawURLEncoding.DecodeString(e)
	qt.Assert(t, qt.IsNil(err))

	pub := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}

	got, err := jwkThumbprint(pub)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(got, wantThumbprint))
}

func TestConfigKeyProviderDerivesIDFromThumbprintWhenOmitted(t *testing.T) {
	_, priv, pub := genRSA(t)

	kp, err := NewConfigKeyProvider(&contract.KeySetConfig{
		Primary: contract.KeyConfig{Algorithm: "RS256", PrivateKey: priv, PublicKey: pub},
	})
	qt.Assert(t, qt.IsNil(err))

	set, err := kp.KeySet(t.Context())
	qt.Assert(t, qt.IsNil(err))

	want, err := jwkThumbprint(set.Primary.Public)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(set.Primary.ID, want))
	qt.Check(t, qt.IsTrue(set.Primary.ID != ""))
}

func TestConfigKeyProviderDerivesAlgorithmForECWhenOmitted(t *testing.T) {
	_, priv, pub := genECDSA(t)

	kp, err := NewConfigKeyProvider(&contract.KeySetConfig{
		Primary: contract.KeyConfig{PrivateKey: priv, PublicKey: pub},
	})
	qt.Assert(t, qt.IsNil(err))

	set, err := kp.KeySet(t.Context())
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(set.Primary.Algorithm, "ES256"))
}

func TestConfigKeyProviderDefaultsRSAAlgorithmToRS256WhenOmitted(t *testing.T) {
	_, priv, pub := genRSA(t)

	kp, err := NewConfigKeyProvider(&contract.KeySetConfig{
		Primary: contract.KeyConfig{PrivateKey: priv, PublicKey: pub},
	})
	qt.Assert(t, qt.IsNil(err))

	set, err := kp.KeySet(t.Context())
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(set.Primary.Algorithm, "RS256"))
}

func TestConfigKeyProviderSecondaryOnlyNeedsPublicKey(t *testing.T) {
	_, priv, pub := genRSA(t)
	_, _, secondaryRSAPub := genRSA(t)
	_, _, secondaryECPub := genECDSA(t)

	kp, err := NewConfigKeyProvider(&contract.KeySetConfig{
		Primary: contract.KeyConfig{ID: "k1", Algorithm: "RS256", PrivateKey: priv, PublicKey: pub},
		Secondary: []contract.KeyConfig{
			{PublicKey: secondaryRSAPub},
			{PublicKey: secondaryECPub},
		},
	})
	qt.Assert(t, qt.IsNil(err))

	set, err := kp.KeySet(t.Context())
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(set.Secondary, 2))

	// RSA: no algorithm is guessed - which hash a rotated-out key was actually signed with is
	// a historical fact this package cannot know.
	rsaVK := set.Secondary[0]
	qt.Check(t, qt.Equals(rsaVK.Algorithm, ""))
	qt.Check(t, qt.IsTrue(rsaVK.ID != ""))

	wantRSAID, err := jwkThumbprint(rsaVK.Public)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(rsaVK.ID, wantRSAID))

	ecVK := set.Secondary[1]
	qt.Check(t, qt.Equals(ecVK.Algorithm, "ES256"))
	qt.Check(t, qt.IsTrue(ecVK.ID != ""))

	// JWKS omits "alg" for the RSA entry (RFC 7517: alg is optional) rather than asserting a
	// guessed value.
	jwks := JWKSFrom(set)
	qt.Assert(t, qt.HasLen(jwks.Keys, 3))
	qt.Check(t, qt.Equals(jwks.Keys[1].Alg, ""))
	qt.Check(t, qt.Equals(jwks.Keys[2].Alg, "ES256"))

	body, err := json.Marshal(jwks.Keys[1])
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Not(qt.StringContains(string(body), `"alg"`)))

	// Verification-only keys never contribute to the advertised signing algorithms.
	qt.Check(t, qt.DeepEquals(set.SigningAlgorithms(), []string{"RS256"}))
}

func TestConfigKeyProviderDerivesPrimaryPublicKeyFromPrivateWhenOmitted(t *testing.T) {
	key, priv, pub := genRSA(t)

	kp, err := NewConfigKeyProvider(&contract.KeySetConfig{
		Primary: contract.KeyConfig{PrivateKey: priv},
	})
	qt.Assert(t, qt.IsNil(err))

	set, err := kp.KeySet(t.Context())
	qt.Assert(t, qt.IsNil(err))

	rsaPub, ok := set.Primary.Public.(*rsa.PublicKey)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Check(t, qt.Equals(rsaPub.N.Cmp(key.N), 0))
	qt.Check(t, qt.Equals(rsaPub.E, key.E))

	// The explicitly-supplied PublicKey (if any) would parse to the same value - confirms the
	// derived key is actually usable, not just structurally present.
	explicitPub, err := ParsePublicKeyPEM(pub)
	qt.Assert(t, qt.IsNil(err))
	explicitRSAPub, ok := explicitPub.(*rsa.PublicKey)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Check(t, qt.Equals(rsaPub.N.Cmp(explicitRSAPub.N), 0))
}

func TestConfigKeyProviderSecondaryRequiresPublicKey(t *testing.T) {
	_, priv, pub := genRSA(t)

	_, err := NewConfigKeyProvider(&contract.KeySetConfig{
		Primary:   contract.KeyConfig{ID: "k1", Algorithm: "RS256", PrivateKey: priv, PublicKey: pub},
		Secondary: []contract.KeyConfig{{}},
	})
	qt.Check(t, qt.IsNotNil(err))
}
