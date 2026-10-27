package dpop

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"azugo.io/auth/internal/dpoptest"
	"azugo.io/auth/jti"

	"azugo.io/azugo"
	"azugo.io/core/cache"
	"github.com/go-quicktest/qt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/valyala/fasthttp"
)

const tokenURL = "https://issuer.example/auth/token"

func newReplay(t *testing.T) jti.DenyList {
	t.Helper()

	c := cache.New(cache.MemoryCache)
	qt.Assert(t, qt.IsNil(c.Start(context.Background())))
	t.Cleanup(c.Close)

	list, err := jti.NewCacheDenyList(c, "test:dpop")
	qt.Assert(t, qt.IsNil(err))

	return list
}

func TestValidateProofReturnsThumbprint(t *testing.T) {
	key := dpoptest.NewKey(t)

	jkt, err := ValidateProof(context.Background(), key.Proof(t, "POST", tokenURL, nil), "POST", tokenURL, newReplay(t))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(jkt, key.JKT))
}

func TestValidateProofRejectsReplay(t *testing.T) {
	key := dpoptest.NewKey(t)
	replay := newReplay(t)
	proof := key.Proof(t, "POST", tokenURL, nil)

	_, err := ValidateProof(context.Background(), proof, "POST", tokenURL, replay)
	qt.Assert(t, qt.IsNil(err))

	_, err = ValidateProof(context.Background(), proof, "POST", tokenURL, replay)
	qt.Check(t, qt.ErrorIs(err, ErrInvalidProof))
}

func TestValidateProofMatchesRequest(t *testing.T) {
	key := dpoptest.NewKey(t)

	for _, tc := range []struct {
		name   string
		method string
		htu    string
		ok     bool
	}{
		{"same", "POST", tokenURL, true},
		{"query and fragment ignored", "POST", tokenURL + "?a=b#c", true},
		{"default port", "POST", "https://issuer.example:443/auth/token", true},
		{"host case", "POST", "https://ISSUER.example/auth/token", true},
		{"other method", "GET", tokenURL, false},
		{"other path", "POST", "https://issuer.example/auth/userinfo", false},
		{"other host", "POST", "https://evil.example/auth/token", false},
		{"other scheme", "POST", "http://issuer.example/auth/token", false},
		{"other port", "POST", "https://issuer.example:8443/auth/token", false},
		{"relative", "POST", "/auth/token", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ValidateProof(context.Background(), key.Proof(t, tc.method, tc.htu, nil), "POST", tokenURL, newReplay(t))
			if tc.ok {
				qt.Check(t, qt.IsNil(err))
			} else {
				qt.Check(t, qt.ErrorIs(err, ErrInvalidProof))
			}
		})
	}
}

func TestValidateProofChecksClaims(t *testing.T) {
	key := dpoptest.NewKey(t)

	for name, claims := range map[string]map[string]any{
		"stale iat":  {"iat": time.Now().Add(-time.Minute - 2*time.Second).Unix()},
		"future iat": {"iat": time.Now().Add(time.Minute + 2*time.Second).Unix()},
		"no iat":     {"iat": nil},
		"no jti":     {"jti": ""},
		"expired":    {"exp": time.Now().Add(-time.Minute).Unix()},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ValidateProof(context.Background(), key.Proof(t, "POST", tokenURL, claims), "POST", tokenURL, newReplay(t), ClockSkew(time.Minute))
			qt.Check(t, qt.ErrorIs(err, ErrInvalidProof))
		})
	}
}

func TestValidateProofATH(t *testing.T) {
	key := dpoptest.NewKey(t)

	_, err := ValidateProof(context.Background(), key.AccessProof(t, "GET", tokenURL, "tok"), "GET", tokenURL, newReplay(t), ATH("tok"))
	qt.Check(t, qt.IsNil(err))

	_, err = ValidateProof(context.Background(), key.AccessProof(t, "GET", tokenURL, "other"), "GET", tokenURL, newReplay(t), ATH("tok"))
	qt.Check(t, qt.ErrorIs(err, ErrInvalidProof))

	_, err = ValidateProof(context.Background(), key.Proof(t, "GET", tokenURL, nil), "GET", tokenURL, newReplay(t), ATH("tok"))
	qt.Check(t, qt.ErrorIs(err, ErrInvalidProof))
}

func TestValidateProofNonce(t *testing.T) {
	key := dpoptest.NewKey(t)
	nonces := Nonces{Key: []byte("0123456789abcdef0123456789abcdef"), Window: time.Minute}

	_, err := ValidateProof(context.Background(), key.Proof(t, "POST", tokenURL, nil), "POST", tokenURL, newReplay(t), nonces)
	qt.Check(t, qt.ErrorIs(err, ErrUseNonce))

	other := Nonces{Key: []byte("other")}.New()

	_, err = ValidateProof(context.Background(), key.Proof(t, "POST", tokenURL, map[string]any{"nonce": other}), "POST", tokenURL, newReplay(t), nonces)
	qt.Check(t, qt.ErrorIs(err, ErrUseNonce))

	_, err = ValidateProof(context.Background(), key.Proof(t, "POST", tokenURL, map[string]any{"nonce": nonces.New()}), "POST", tokenURL, newReplay(t), nonces)
	qt.Check(t, qt.IsNil(err))
}

func TestValidateProofNonceReplacesIATWindow(t *testing.T) {
	key := dpoptest.NewKey(t)
	nonces := Nonces{Key: []byte("0123456789abcdef0123456789abcdef"), Window: time.Hour}

	// A client clock an hour late still passes with a current nonce.
	proof := key.Proof(t, "POST", tokenURL, map[string]any{"nonce": nonces.New(), "iat": time.Now().Add(-time.Hour).Unix()})

	_, err := ValidateProof(context.Background(), proof, "POST", tokenURL, newReplay(t), nonces, ClockSkew(time.Second))
	qt.Check(t, qt.IsNil(err))

	// An iat beyond the skew in the future is refused all the same.
	proof = key.Proof(t, "POST", tokenURL, map[string]any{"nonce": nonces.New(), "iat": time.Now().Add(time.Minute).Unix()})

	_, err = ValidateProof(context.Background(), proof, "POST", tokenURL, newReplay(t), nonces, ClockSkew(10*time.Second))
	qt.Check(t, qt.ErrorIs(err, ErrInvalidProof))
}

func TestNoncesWithoutWindowFailClosed(t *testing.T) {
	nonces := Nonces{Key: []byte("k")}
	qt.Check(t, qt.Equals(nonces.New(), ""))

	_, err := ValidateProof(context.Background(), dpoptest.NewKey(t).Proof(t, "POST", tokenURL, map[string]any{"nonce": ""}), "POST", tokenURL, newReplay(t), nonces)
	qt.Check(t, qt.ErrorIs(err, ErrUseNonce))
}

func TestNoncesWindow(t *testing.T) {
	nonces := Nonces{Key: []byte("k"), Window: 50 * time.Millisecond}
	nonce := nonces.New()

	exp, ok := nonces.expiry(nonce)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Check(t, qt.IsTrue(time.Until(exp) <= 2*nonces.Window))

	// A nonce is accepted for its own window and the next, then refused.
	time.Sleep(time.Until(exp) + 5*time.Millisecond)

	_, ok = nonces.expiry(nonce)
	qt.Check(t, qt.IsFalse(ok))
}

func TestValidateProofRejectsBadHeaders(t *testing.T) {
	key := dpoptest.NewKey(t)
	claims := jwt.MapClaims{"jti": "x", "htm": "POST", "htu": tokenURL, "iat": time.Now().Unix()}

	t.Run("typ", func(t *testing.T) {
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tok.Header["typ"] = "JWT"
		tok.Header["jwk"] = key.JWK
		s, err := tok.SignedString([]byte("secret"))
		qt.Assert(t, qt.IsNil(err))

		_, err = ValidateProof(context.Background(), s, "POST", tokenURL, newReplay(t))
		qt.Check(t, qt.ErrorIs(err, ErrInvalidProof))
	})

	t.Run("symmetric", func(t *testing.T) {
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tok.Header["typ"] = "dpop+jwt"
		tok.Header["jwk"] = map[string]any{"kty": "oct", "k": base64.RawURLEncoding.EncodeToString([]byte("secret"))}
		s, err := tok.SignedString([]byte("secret"))
		qt.Assert(t, qt.IsNil(err))

		_, err = ValidateProof(context.Background(), s, "POST", tokenURL, newReplay(t))
		qt.Check(t, qt.ErrorIs(err, ErrInvalidProof))
	})

	t.Run("private key", func(t *testing.T) {
		jwk := map[string]any{"d": "AAAA"}
		for k, v := range key.JWK {
			jwk[k] = v
		}

		_, _, err := parseJWK(jwk)
		qt.Check(t, qt.ErrorIs(err, ErrInvalidProof))
	})

	t.Run("no jwk", func(t *testing.T) {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		qt.Assert(t, qt.IsNil(err))

		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["typ"] = "dpop+jwt"
		s, err := tok.SignedString(priv)
		qt.Assert(t, qt.IsNil(err))

		_, err = ValidateProof(context.Background(), s, "POST", tokenURL, newReplay(t))
		qt.Check(t, qt.ErrorIs(err, ErrInvalidProof))
	})
}

func TestValidateProofRSAAndEd25519(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	qt.Assert(t, qt.IsNil(err))

	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	qt.Assert(t, qt.IsNil(err))

	for _, tc := range []struct {
		name   string
		method jwt.SigningMethod
		jwk    map[string]any
		priv   any
	}{
		{"PS256", jwt.SigningMethodPS256, map[string]any{
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaKey.E)).Bytes()),
		}, rsaKey},
		{"EdDSA", jwt.SigningMethodEdDSA, map[string]any{
			"kty": "OKP",
			"crv": "Ed25519",
			"x":   base64.RawURLEncoding.EncodeToString(edPub),
		}, edPriv},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tok := jwt.NewWithClaims(tc.method, jwt.MapClaims{"jti": "x", "htm": "POST", "htu": tokenURL, "iat": time.Now().Unix()})
			tok.Header["typ"] = "dpop+jwt"
			tok.Header["jwk"] = tc.jwk
			s, err := tok.SignedString(tc.priv)
			qt.Assert(t, qt.IsNil(err))

			_, want, err := parseJWK(tc.jwk)
			qt.Assert(t, qt.IsNil(err))

			jkt, err := ValidateProof(context.Background(), s, "POST", tokenURL, newReplay(t))
			qt.Assert(t, qt.IsNil(err))
			qt.Check(t, qt.Equals(jkt, want))
		})
	}
}

func TestThumbprintRFC7638Example(t *testing.T) {
	_, jkt, err := parseJWK(map[string]any{
		"kty": "RSA",
		"n":   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		"e":   "AQAB",
		"alg": "RS256",
		"kid": "2011-04-29",
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(jkt, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"))
}

func TestCredential(t *testing.T) {
	for header, want := range map[string]struct {
		tok   string
		bound bool
	}{
		"Bearer tok": {"tok", false},
		"bearer tok": {"tok", false},
		"DPoP tok":   {"tok", true},
		"dpop tok":   {"tok", true},
		"Basic tok":  {"", false},
		"Bearer":     {"", false},
		"":           {"", false},
	} {
		tok, bound := Credential(header)
		qt.Check(t, qt.Equals(tok, want.tok), qt.Commentf("%q", header))
		qt.Check(t, qt.Equals(bound, want.bound), qt.Commentf("%q", header))
	}
}

func TestRequestURLWithBasePath(t *testing.T) {
	app := azugo.NewTestApp()
	app.Start(t)
	t.Cleanup(app.Stop)

	app.RouterOptions().BasePath = "/api"

	app.Get("/auth/token", func(ctx *azugo.Context) {
		ctx.Text(RequestURL(ctx, "") + " " + RequestURL(ctx, "https://issuer.example/api/"))
	})

	// Whether or not a proxy stripped the base path, the public URL carries it once.
	for _, path := range []string{"/api/auth/token", "/auth/token"} {
		resp, err := app.TestClient().Get(path + "?q=1")
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.Equals(string(resp.Body()), "http://test/api/auth/token https://issuer.example/api/auth/token"))
		fasthttp.ReleaseResponse(resp)
	}
}

func TestRequestURLKeepsEscapedPath(t *testing.T) {
	app := azugo.NewTestApp()
	app.Start(t)
	t.Cleanup(app.Stop)

	app.Get("/{path:*}", func(ctx *azugo.Context) {
		ctx.Text(RequestURL(ctx, ""))
	})

	// The proof names the path as sent, so a percent-encoded segment is kept, not decoded; the
	// client must send it verbatim too, as fasthttp re-quotes the decoded path by default.
	tc := app.TestClient()
	tc.Client().DisablePathNormalizing = true

	for path, want := range map[string]string{
		"/auth/apikeys/a%2Fb?q=1": "http://test/auth/apikeys/a%2Fb",
		"/auth/x%3Fy%23z":         "http://test/auth/x%3Fy%23z",
		"/auth/caf%C3%A9":         "http://test/auth/caf%C3%A9",
	} {
		resp, err := tc.Get(path)
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.Equals(string(resp.Body()), want), qt.Commentf(path))
		qt.Check(t, qt.IsTrue(sameURI(want, string(resp.Body()))), qt.Commentf(path))
		fasthttp.ReleaseResponse(resp)
	}
}

func TestRequestURLStripsBasePathOnlyAtBoundary(t *testing.T) {
	app := azugo.NewTestApp()
	app.Start(t)
	t.Cleanup(app.Stop)

	app.RouterOptions().BasePath = "/api"

	app.Get("/{path:*}", func(ctx *azugo.Context) {
		ctx.Text(RequestURL(ctx, "https://issuer.example"))
	})

	// A path merely starting with the base path's text keeps it.
	for path, want := range map[string]string{
		"/api":            "https://issuer.example",
		"/api/auth/token": "https://issuer.example/auth/token",
		"/apix/token":     "https://issuer.example/apix/token",
	} {
		resp, err := app.TestClient().Get(path)
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.Equals(string(resp.Body()), want), qt.Commentf(path))
		fasthttp.ReleaseResponse(resp)
	}
}

func TestValidateProofClockSkew(t *testing.T) {
	key := dpoptest.NewKey(t)

	for _, tc := range []struct {
		name string
		iat  time.Duration
		ok   bool
	}{
		{"now", 0, true},
		{"within past", -20 * time.Second, true},
		{"within future", 20 * time.Second, true},
		{"past", -40 * time.Second, false},
		{"future", 40 * time.Second, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proof := key.Proof(t, "POST", tokenURL, map[string]any{"iat": time.Now().Add(tc.iat).Unix()})

			_, err := ValidateProof(context.Background(), proof, "POST", tokenURL, newReplay(t), ClockSkew(30*time.Second))
			if tc.ok {
				qt.Check(t, qt.IsNil(err))
			} else {
				qt.Check(t, qt.ErrorIs(err, ErrInvalidProof))
			}
		})
	}

	// A strict skew still accepts a just-signed proof.
	_, err := ValidateProof(context.Background(), key.Proof(t, "POST", tokenURL, nil), "POST", tokenURL, newReplay(t), ClockSkew(0))
	qt.Check(t, qt.IsNil(err))
}
