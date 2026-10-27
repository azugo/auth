package middleware

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"azugo.io/auth"
	"azugo.io/auth/client"
	"azugo.io/auth/contract"
	"azugo.io/auth/internal/dpoptest"
	"azugo.io/auth/token"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

const testURL = "http://test/"

// dpopLoginFor signs alice in with a proof by key, so the result's tokens are bound to it.
func dpopLoginFor(t *testing.T, a *auth.Auth, key *dpoptest.Key) auth.LoginResult {
	t.Helper()

	const tokenURL = "https://issuer.example/token"

	res, err := a.Login(context.Background(), auth.LoginRequest{
		Credentials: auth.ClientCredentials{ClientID: "spa"}, Username: "alice", Password: "irrelevant",
		DPoP: &auth.DPoPProof{Proof: key.Proof(t, "GET", tokenURL, nil), Method: "GET", URL: tokenURL},
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(res.TokenType, "DPoP"))

	return res
}

// jwtKeys returns a fresh RS256 signing key set.
func jwtKeys(t *testing.T) token.KeyProvider {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	qt.Assert(t, qt.IsNil(err))

	priv, err := x509.MarshalPKCS8PrivateKey(key)
	qt.Assert(t, qt.IsNil(err))

	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	qt.Assert(t, qt.IsNil(err))

	keys, err := token.NewConfigKeyProvider(&contract.KeySetConfig{Primary: contract.KeyConfig{
		ID: "k1", Algorithm: "RS256",
		PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv})),
		PublicKey:  string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub})),
	}})
	qt.Assert(t, qt.IsNil(err))

	return keys
}

func TestAuthMiddlewareRefusesBoundTokenCookie(t *testing.T) {
	for name, tt := range map[string]struct {
		tokenType client.AccessTokenType
		opts      []auth.Option
	}{
		"paseto": {client.AccessTokenTypeIntrospect, nil},
		"jwt":    {client.AccessTokenTypeJWT, []auth.Option{auth.KeyProvider(jwtKeys(t))}},
	} {
		t.Run(name, func(t *testing.T) {
			a := newTestAuth(t, &client.Client{
				ID: "spa", GrantTypes: []string{client.GrantTypePassword},
				AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeJSON,
				AccessTokenType: tt.tokenType,
			}, tt.opts...)
			key := dpoptest.NewKey(t)
			login := dpopLoginFor(t, a, key)

			app := newTestApp(t)
			app.Use(Auth(a, Cookie()))
			app.Get("/", func(ctx *azugo.Context) {
				if ctx.User().Authorized() {
					ctx.Text(ctx.User().ID())

					return
				}

				ctx.Text("anonymous")
			})

			tc := app.TestClient()

			// The cookie slot carries the session cookie only; a bound token there has no proof.
			for name, tt := range map[string]struct {
				opts []azugo.TestClientOption
				want string
			}{
				"dpop":           {[]azugo.TestClientOption{tc.WithHeader("Authorization", "DPoP "+login.AccessToken), tc.WithHeader("DPoP", key.AccessProof(t, "GET", testURL, login.AccessToken))}, "u1"},
				"session cookie": {[]azugo.TestClientOption{tc.WithCookie(a.Config().CookieName, login.Cookie.Value)}, "u1"},
				"bound cookie":   {[]azugo.TestClientOption{tc.WithCookie(a.Config().CookieName, login.AccessToken)}, "anonymous"},
			} {
				resp, err := tc.Get("/", tt.opts...)
				qt.Assert(t, qt.IsNil(err))
				qt.Check(t, qt.Equals(string(resp.Body()), tt.want), qt.Commentf(name))
				fasthttp.ReleaseResponse(resp)
			}
		})
	}
}

func TestAuthMiddlewareDPoP(t *testing.T) {
	a := newTestAuth(t, &client.Client{
		ID: "spa", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeJSON,
	})
	key := dpoptest.NewKey(t)
	tok := dpopLoginFor(t, a, key).AccessToken

	app := newTestApp(t)
	app.Use(Auth(a))
	app.Get("/", func(ctx *azugo.Context) {
		// A second read within the request reuses the verified proof.
		if ctx.User().Authorized() && a.ReadSessionToken(ctx) == tok {
			ctx.Text(ctx.User().ID())

			return
		}

		ctx.Text("anonymous")
	})

	tc := app.TestClient()

	for _, tt := range []struct {
		name   string
		opts   []azugo.TestClientOption
		status int
		code   string
	}{
		{"dpop", []azugo.TestClientOption{tc.WithHeader("Authorization", "DPoP "+tok), tc.WithHeader("DPoP", key.AccessProof(t, "GET", testURL, tok))}, 200, ""},
		{"bearer", []azugo.TestClientOption{tc.WithHeader("Authorization", "Bearer "+tok)}, 401, "invalid_token"},
		{"no proof", []azugo.TestClientOption{tc.WithHeader("Authorization", "DPoP "+tok)}, 401, "invalid_dpop_proof"},
		{"other token", []azugo.TestClientOption{tc.WithHeader("Authorization", "DPoP "+tok), tc.WithHeader("DPoP", key.AccessProof(t, "GET", testURL, "other"))}, 401, "invalid_dpop_proof"},
		{"other url", []azugo.TestClientOption{tc.WithHeader("Authorization", "DPoP "+tok), tc.WithHeader("DPoP", key.AccessProof(t, "GET", testURL+"other", tok))}, 401, "invalid_dpop_proof"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := tc.Get("/", tt.opts...)
			defer fasthttp.ReleaseResponse(resp)
			qt.Assert(t, qt.IsNil(err))
			qt.Assert(t, qt.Equals(resp.StatusCode(), tt.status))

			if tt.code == "" {
				qt.Check(t, qt.Equals(string(resp.Body()), "u1"))

				return
			}

			// A failed binding is answered with the DPoP challenge, not an anonymous pass.
			challenge := string(resp.Header.Peek("WWW-Authenticate"))
			qt.Check(t, qt.IsTrue(strings.HasPrefix(challenge, "DPoP ")))
			qt.Check(t, qt.StringContains(challenge, `error="`+tt.code+`"`))
		})
	}
}

func TestAuthMiddlewareRefusesMultipleProofs(t *testing.T) {
	a := newTestAuth(t, &client.Client{
		ID: "spa", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeJSON,
	})
	key := dpoptest.NewKey(t)
	tok := dpopLoginFor(t, a, key).AccessToken

	app := newTestApp(t)
	app.Use(Auth(a))
	app.Get("/", func(ctx *azugo.Context) {
		ctx.StatusCode(204)
	})

	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	req.SetRequestURI(testURL)
	req.Header.Set("Authorization", "DPoP "+tok)
	req.Header.Add("DPoP", key.AccessProof(t, "GET", testURL, tok))
	req.Header.Add("DPoP", key.AccessProof(t, "GET", testURL, tok))

	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	qt.Assert(t, qt.IsNil(app.TestClient().Client().Do(req, resp)))
	qt.Check(t, qt.Equals(resp.StatusCode(), 401))

	// The reason is passed through, not collapsed into a missing proof.
	challenge := string(resp.Header.Peek("WWW-Authenticate"))
	qt.Check(t, qt.IsTrue(strings.HasPrefix(challenge, "DPoP ")))
	qt.Check(t, qt.StringContains(challenge, `error_description="multiple DPoP proofs"`))
}

func TestDPoPMiddlewareChallenges(t *testing.T) {
	a := newTestAuth(t, &client.Client{
		ID: "spa", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeJSON,
	})
	key := dpoptest.NewKey(t)
	tok := dpopLoginFor(t, a, key).AccessToken

	app := newTestApp(t)
	app.Use(DPoP(a))
	app.Get("/", func(ctx *azugo.Context) {
		// The middleware verified the single-use proof; the handler reads the token as often as it likes.
		ctx.Text(a.ReadSessionToken(ctx) + " " + a.ReadSessionToken(ctx))
	})

	tc := app.TestClient()

	resp, err := tc.Get("/", tc.WithHeader("Authorization", "DPoP "+tok), tc.WithHeader("DPoP", key.AccessProof(t, "GET", testURL, tok)))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 200))
	qt.Check(t, qt.Equals(string(resp.Body()), tok+" "+tok))
	fasthttp.ReleaseResponse(resp)

	resp, err = tc.Get("/", tc.WithHeader("Authorization", "Bearer "+tok))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 401))
	qt.Check(t, qt.IsTrue(strings.HasPrefix(string(resp.Header.Peek("WWW-Authenticate")), "DPoP ")))
}

func TestReadAccessTokenChallengesWithDPoP(t *testing.T) {
	a := newTestAuth(t, &client.Client{
		ID: "spa", GrantTypes: []string{client.GrantTypePassword},
		AllowedAuthMethods: []string{client.AuthMethodPassword}, ResponseMode: client.ResponseModeJSON,
	})
	tok := dpopLoginFor(t, a, dpoptest.NewKey(t)).AccessToken

	app := newTestApp(t)
	app.Get("/", func(ctx *azugo.Context) {
		if _, err := a.ReadAccessToken(ctx); err != nil {
			ctx.Error(err)

			return
		}

		ctx.StatusCode(204)
	})

	tc := app.TestClient()

	resp, err := tc.Get("/", tc.WithHeader("Authorization", "Bearer "+tok))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), 401))

	challenge := string(resp.Header.Peek("WWW-Authenticate"))
	qt.Check(t, qt.IsTrue(strings.HasPrefix(challenge, `DPoP `)))
	qt.Check(t, qt.StringContains(challenge, `error="invalid_token"`))
	qt.Check(t, qt.StringContains(challenge, `algs="ES256`))
}
