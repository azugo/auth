package token

import (
	"testing"
	"time"

	"azugo.io/auth/contract"
)

func benchCodec(b *testing.B) (*Codec, string) {
	b.Helper()

	c := NewCodec(&contract.Configuration{Secret: "0123456789abcdef0123456789abcdef"})

	tok, err := c.Encrypt(AccessClaims{
		Type: TypeAccessToken, SessionID: "s1", TokenID: "jti1",
		IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		b.Fatal(err)
	}

	return c, tok
}

func BenchmarkCodecEncrypt(b *testing.B) {
	c, _ := benchCodec(b)
	claims := AccessClaims{
		Type: TypeAccessToken, SessionID: "s1", TokenID: "jti1",
		IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}

	b.ReportAllocs()

	for b.Loop() {
		if _, err := c.Encrypt(claims); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCodecDecodeAccess(b *testing.B) {
	c, tok := benchCodec(b)

	b.ReportAllocs()

	for b.Loop() {
		if _, err := c.DecodeAccess(tok); err != nil {
			b.Fatal(err)
		}
	}
}

func benchKeySet(b *testing.B, alg string) *KeySet {
	b.Helper()

	var cfg *contract.KeySetConfig

	if alg == "ES256" {
		key := `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg0Q7bde4zmyxCbz7c
r6HGW2mZ2646h6ojx0y7Ejq6/2ahRANCAAQ3ZWEG5jvGYzKJqCcRUsTiOd5AY5xw
Nb0lFRXQyMEwv3nWtIT+X40MOUJXCa1FyEy/aa9zTgnkPTsSTaSaqTkK
-----END PRIVATE KEY-----`
		cfg = &contract.KeySetConfig{Primary: contract.KeyConfig{ID: "k1", PrivateKey: key}}
	} else {
		b.Fatal("unsupported bench alg")
	}

	kp, err := NewConfigKeyProvider(cfg)
	if err != nil {
		b.Fatal(err)
	}

	set, err := kp.KeySet(b.Context())
	if err != nil {
		b.Fatal(err)
	}

	return set
}

func BenchmarkSignAccessTokenES256(b *testing.B) {
	set := benchKeySet(b, "ES256")
	claims := AccessTokenClaims{
		Issuer: "https://issuer.example", Subject: "u1", ClientID: "svc",
		Scope: "items:read", TokenID: "jti1",
		IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}

	b.ReportAllocs()

	for b.Loop() {
		if _, err := SignAccessToken(set.Primary, claims); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyAccessTokenES256(b *testing.B) {
	set := benchKeySet(b, "ES256")

	tok, err := SignAccessToken(set.Primary, AccessTokenClaims{
		Issuer: "https://issuer.example", Subject: "u1", ClientID: "svc",
		Scope: "items:read", TokenID: "jti1",
		IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for b.Loop() {
		if _, err := VerifyAccessToken(set, tok); err != nil {
			b.Fatal(err)
		}
	}
}
